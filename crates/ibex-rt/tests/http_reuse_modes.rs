// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-reuse` and `pool-max-conn` against the real binary (T135).
//!
//! Every expected sequence was measured on HAProxy 3.5-dev8-885761-29 (`nbthread 1`, one
//! `listen` with `http-reuse <mode>` and `server ... [pool-max-conn N]`, a backend that
//! numbers the connections it accepts in arrival order, clients that connect one after
//! the other, 100 ms apart, and send `reqs` requests each on their own connection). Each
//! row of a table is a client; each number is the backend connection that carried the
//! request.
//!
//! What the numbers say, in the sources' terms (`be_reuse_connection`, `srv_add_to_idle_list`):
//! - `never`: the connection belongs to its client connection.
//! - a connection that has carried one request waits in the server's idle list, one that
//!   has carried two or more in its safe list; the server keeps a connection only if its
//!   safe list is empty and (it is safe or its idle list is empty), and `pool-max-conn`
//!   bounds the two lists together (`0`: nothing is kept, not even for the next request
//!   of the same client);
//! - the first request of a client connection takes: nothing (`safe`), a safe connection
//!   (`aggressive`), a safe one, then an idle one (`always`); the following requests take
//!   an idle one, then a safe one.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// A backend whose answers say which of its accepted connections carried the request.
fn backend() -> SocketAddr {
    backend_closing(None)
}

/// The same, closing each connection `close_after` after its first answer when given.
fn backend_closing(close_after: Option<Duration>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    let count = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let id = count.fetch_add(1, Ordering::SeqCst) + 1;
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let rsp = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Conn: {id}\r\n\r\n");
                    if s.write_all(rsp.as_bytes()).is_err() {
                        break;
                    }
                    if let Some(d) = close_after {
                        thread::sleep(d);
                        break;
                    }
                }
            });
        }
    });
    addr
}

struct Ibex(Child, NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(cfg: &str, fe: SocketAddr) -> Ibex {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
        thread::sleep(Duration::from_millis(20));
    }
    Ibex(child, f)
}

/// `clients` sequential client connections of `reqs` requests each; the backend connection
/// that carried each request.
fn sequences(mode: &str, pool_max_conn: Option<&str>, clients: usize, reqs: usize) -> Vec<Vec<usize>> {
    let be = backend();
    let fe = common::reserve_addr();
    let pmc = pool_max_conn.map(|n| format!(" pool-max-conn {n}")).unwrap_or_default();
    let _ibex = start(
        &format!(
            "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
             listen sender\n  bind {fe}\n  http-reuse {mode}\n  server srv {be}{pmc}\n"
        ),
        fe,
    );
    let mut out = Vec::new();
    for _ in 0..clients {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut seq = Vec::new();
        for _ in 0..reqs {
            c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
            let mut resp = Vec::new();
            let mut buf = [0u8; 4096];
            while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => resp.extend_from_slice(&buf[..n]),
                }
            }
            let resp = String::from_utf8_lossy(&resp).to_ascii_lowercase();
            let id = resp
                .split("x-conn: ")
                .nth(1)
                .and_then(|r| r.split("\r\n").next())
                .and_then(|n| n.trim().parse().ok())
                .unwrap_or_else(|| panic!("no answer: {resp:?}"));
            seq.push(id);
        }
        drop(c);
        thread::sleep(Duration::from_millis(100));
        out.push(seq);
    }
    out
}

/// `rounds` bursts of six client connections open together, each sending two requests;
/// the highest backend connection number seen, i.e. how many connections the backend saw.
fn burst(mode: &str, rounds: usize) -> usize {
    let be = backend();
    let fe = common::reserve_addr();
    let _ibex = start(
        &format!(
            "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
             listen sender\n  bind {fe}\n  http-reuse {mode}\n  server srv {be}\n"
        ),
        fe,
    );
    let mut highest = 0;
    for _ in 0..rounds {
        let mut cs: Vec<TcpStream> = (0..6).map(|_| TcpStream::connect(fe).expect("connect")).collect();
        for _ in 0..2 {
            for c in &mut cs {
                c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
            }
            for c in &mut cs {
                let mut resp = Vec::new();
                let mut buf = [0u8; 4096];
                while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => resp.extend_from_slice(&buf[..n]),
                    }
                }
                let resp = String::from_utf8_lossy(&resp).to_ascii_lowercase();
                let id: usize = resp.split("x-conn: ").nth(1).and_then(|r| r.split("\r\n").next()).and_then(|n| n.trim().parse().ok()).expect("answer");
                highest = highest.max(id);
            }
        }
        drop(cs);
        thread::sleep(Duration::from_millis(200));
    }
    highest
}

/// HAProxy keeps as many idle connections as the server was seen to use at once
/// (`est_need_conns`): after a burst of six, the next burst of six finds them. Under `safe`
/// a first request never takes one, so every burst opens six new ones.
#[test]
fn a_burst_leaves_as_many_idle_connections_as_it_used() {
    assert_eq!(burst("always", 3), 6);
    assert_eq!(burst("aggressive", 3), 6);
    assert_eq!(burst("safe", 3), 18);
}

/// An idle connection the server has closed is not taken: the request opens a new one.
#[test]
fn an_idle_connection_closed_by_the_server_is_not_reused() {
    let be = backend_closing(Some(Duration::from_millis(50)));
    let fe = common::reserve_addr();
    let _ibex = start(
        &format!(
            "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
             listen sender\n  bind {fe}\n  http-reuse always\n  server srv {be}\n"
        ),
        fe,
    );
    let mut ids = Vec::new();
    for _ in 0..2 {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut resp = Vec::new();
        let mut buf = [0u8; 4096];
        while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => resp.extend_from_slice(&buf[..n]),
            }
        }
        let resp = String::from_utf8_lossy(&resp).to_ascii_lowercase();
        ids.push(resp.split("x-conn: ").nth(1).and_then(|r| r.split("\r\n").next()).and_then(|n| n.trim().parse::<usize>().ok()).expect("answer"));
        drop(c);
        thread::sleep(Duration::from_millis(300));
    }
    assert_eq!(ids, [1, 2]);
}

#[test]
fn never_keeps_the_connection_for_its_client_only() {
    assert_eq!(sequences("never", None, 3, 3), [[1, 1, 1], [2, 2, 2], [3, 3, 3]]);
}

#[test]
fn safe_opens_a_connection_for_a_first_request_and_reuses_a_safe_one_after() {
    let want = [[1, 1, 1], [2, 1, 1], [3, 1, 1], [4, 1, 1]];
    assert_eq!(sequences("safe", None, 4, 3), want);
    // pool-max-conn 1 changes nothing here: the second list is never wanted.
    assert_eq!(sequences("safe", Some("1"), 4, 3), want);
}

#[test]
fn safe_one_request_per_client_never_reuses() {
    assert_eq!(sequences("safe", None, 4, 1), [[1], [2], [3], [4]]);
    assert_eq!(sequences("safe", None, 4, 2), [[1, 1], [2, 1], [3, 1], [4, 1]]);
}

#[test]
fn aggressive_first_requests_take_only_connections_that_were_reused() {
    assert_eq!(sequences("aggressive", None, 4, 3), [[1, 1, 1], [1, 1, 1], [1, 1, 1], [1, 1, 1]]);
    // One request per client leaves every connection with a single use: never "safe".
    assert_eq!(sequences("aggressive", None, 4, 1), [[1], [2], [3], [4]]);
    assert_eq!(sequences("aggressive", None, 4, 2), [[1, 1], [1, 1], [1, 1], [1, 1]]);
}

#[test]
fn always_first_requests_take_an_idle_connection() {
    assert_eq!(sequences("always", None, 4, 1), [[1], [1], [1], [1]]);
}

#[test]
fn pool_max_conn_zero_keeps_no_idle_connection_even_for_the_next_request() {
    assert_eq!(sequences("always", Some("0"), 3, 2), [[1, 2], [3, 4], [5, 6]]);
    assert_eq!(sequences("safe", Some("0"), 3, 2), [[1, 2], [3, 4], [5, 6]]);
}

#[test]
fn pool_max_conn_one_or_two_keeps_one_connection_here() {
    assert_eq!(sequences("always", Some("1"), 3, 2), [[1, 1], [1, 1], [1, 1]]);
    assert_eq!(sequences("always", Some("2"), 3, 2), [[1, 1], [1, 1], [1, 1]]);
}

/// `ibex -c` on a `server` line carrying `kw`: its status and everything it printed.
fn check(kw: &str, default_server: bool) -> (bool, String) {
    let line = if default_server {
        format!("  default-server {kw}\n  server s 127.0.0.1:2\n")
    } else {
        format!("  server s 127.0.0.1:2 {kw}\n")
    };
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(format!("listen l\n  bind 127.0.0.1:1\n  mode http\n  timeout client 1s\n  timeout server 1s\n  timeout connect 1s\n{line}").as_bytes())
        .expect("write cfg");
    let o = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run ibex");
    let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    (o.status.success(), text)
}

#[test]
fn pool_max_conn_is_checked_at_load_and_no_longer_called_ignored() {
    for ok in ["pool-max-conn -1", "pool-max-conn 0", "pool-max-conn 5", "pool-max-conn abc", "pool-max-conn +3"] {
        for default_server in [false, true] {
            let (success, text) = check(ok, default_server);
            assert!(success, "{ok} (default-server: {default_server}) refused: {text}");
            assert!(!text.contains("is ignored"), "{ok}: {text}");
        }
    }
    for (bad, why) in [("pool-max-conn -2", "'pool-max-conn' must be >= -1"), ("pool-max-conn", "'pool-max-conn' expects <value> as argument")] {
        let (success, text) = check(bad, false);
        assert!(!success, "{bad} accepted: {text}");
        assert!(text.contains(why), "{bad}: {text}");
    }
}

// T159 part A: the pools are per server, `pool-purge-delay` and `pool-low-conn`.
// Measured on HAProxy 3.5-dev8-885761-29 as above (`nbthread 1`, clients 100 ms apart).

/// A backend that numbers its connections, answers `/slow` after 400 ms, and records which
/// connections were closed by their peer.
struct Tracked {
    addr: SocketAddr,
    closed: Arc<std::sync::Mutex<Vec<usize>>>,
}

fn tracked_backend() -> Tracked {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    let count = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let closed2 = Arc::clone(&closed);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let id = count.fetch_add(1, Ordering::SeqCst) + 1;
            let closed = Arc::clone(&closed2);
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let mut pending = Vec::new();
                'conn: loop {
                    let n = match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    pending.extend_from_slice(&buf[..n]);
                    while let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head: Vec<u8> = pending.drain(..end + 4).collect();
                        if head.starts_with(b"GET /slow") {
                            thread::sleep(Duration::from_millis(400));
                        }
                        let rsp = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Conn: {id}\r\n\r\n");
                        if s.write_all(rsp.as_bytes()).is_err() {
                            break 'conn;
                        }
                    }
                }
                closed.lock().unwrap().push(id);
            });
        }
    });
    Tracked { addr, closed }
}

impl Tracked {
    fn closed(&self) -> Vec<usize> {
        let mut v = self.closed.lock().unwrap().clone();
        v.sort_unstable();
        v
    }
}

/// One request of `path` on `c`: the backend connection that carried it.
fn request(c: &mut TcpStream, path: &str) -> usize {
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).unwrap();
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
        }
    }
    let resp = String::from_utf8_lossy(&resp).to_ascii_lowercase();
    resp.split("x-conn: ")
        .nth(1)
        .and_then(|r| r.split("\r\n").next())
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or_else(|| panic!("no answer: {resp:?}"))
}

/// `n` client connections one after the other, `reqs` requests of `path` each.
fn clients(fe: SocketAddr, n: usize, reqs: usize, path: &str) -> Vec<Vec<usize>> {
    (0..n)
        .map(|_| {
            let mut c = TcpStream::connect(fe).expect("connect");
            c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let seq = (0..reqs).map(|_| request(&mut c, path)).collect();
            drop(c);
            thread::sleep(Duration::from_millis(100));
            seq
        })
        .collect()
}

fn start_with(body: &str) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n{}",
        body.replace("{fe}", &fe.to_string())
    );
    (start(&cfg, fe), fe)
}

/// HAProxy keeps idle connections per server (`srv->per_thr[].idle_conns`), and the
/// connection hash names the server: two backends whose servers share an address do not
/// take each other's connections.
#[test]
fn idle_connections_belong_to_their_server_not_to_its_address() {
    let be = tracked_backend();
    let (_ibex, fe) = start_with(&format!(
        "frontend f\n  bind {{fe}}\n  use_backend b2 if {{ path_beg /b2 }}\n  default_backend b1\n\
         backend b1\n  http-reuse always\n  server s {a}\nbackend b2\n  http-reuse always\n  server s {a}\n",
        a = be.addr
    ));
    let got: Vec<_> = ["/b1", "/b2", "/b1", "/b2"].iter().map(|p| clients(fe, 1, 1, p)[0][0]).collect();
    assert_eq!(got, [1, 2, 1, 2]);
}

/// `pool-purge-delay 0` keeps no idle connection (`srv_add_to_idle_list`), not even for the
/// next request of the same client; under `never` the connection is the client's alone.
#[test]
fn pool_purge_delay_zero_keeps_no_idle_connection() {
    for (mode, want) in [("always", [[1, 2], [3, 4], [5, 6]]), ("safe", [[1, 2], [3, 4], [5, 6]]), ("never", [[1, 1], [2, 2], [3, 3]])] {
        let be = tracked_backend();
        let (_ibex, fe) = start_with(&format!("listen l\n  bind {{fe}}\n  http-reuse {mode}\n  server s {} pool-purge-delay 0\n", be.addr));
        assert_eq!(clients(fe, 3, 2, "/"), want, "http-reuse {mode}");
    }
}

/// Every `pool-purge-delay` the server's estimate of what it needs decays
/// (`srv_cleanup_idle_conns`: halfway down to the peak since the last purge) and half the
/// idle connections beyond it, plus one, are closed, oldest first. HAProxy, eight
/// connections idle after a burst of eight, 500 ms purges: nothing closed at the first two
/// purges, then 3, 3 and 2. Here with 600 ms purges, sampled between them.
#[test]
fn pool_purge_delay_closes_idle_connections_beyond_the_estimate() {
    let be = tracked_backend();
    let (_ibex, fe) = start_with(&format!("listen l\n  bind {{fe}}\n  http-reuse always\n  server s {} pool-purge-delay 600\n", be.addr));
    let burst: Vec<_> = (0..8)
        .map(|_| {
            thread::spawn(move || {
                let mut c = TcpStream::connect(fe).expect("connect");
                c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                request(&mut c, "/slow")
            })
        })
        .collect();
    let mut ids: Vec<usize> = burst.into_iter().map(|t| t.join().unwrap()).collect();
    ids.sort_unstable();
    assert_eq!(ids, [1, 2, 3, 4, 5, 6, 7, 8]);
    let t0 = Instant::now();
    let at = |ms: u64| thread::sleep(Duration::from_millis(ms).saturating_sub(t0.elapsed()));
    // Purges at about 0.6 s (estimate 8: none), 1.2 s (4: none), 1.8 s (3), 2.4 s (3), 3.0 s (2).
    at(1500);
    assert_eq!(be.closed(), Vec::<usize>::new(), "before the third purge");
    at(2100);
    // The oldest idle go first: the order the burst's responses ended in, not their numbers.
    assert_eq!(be.closed().len(), 3, "after the third purge: {:?}", be.closed());
    at(2700);
    assert_eq!(be.closed().len(), 6, "after the fourth purge: {:?}", be.closed());
    at(3500);
    assert_eq!(be.closed(), [1, 2, 3, 4, 5, 6, 7, 8]);
    // Nothing is left to reuse.
    assert_eq!(clients(fe, 1, 1, "/"), [[9]]);
}

/// `pool-low-conn` lets a server keep that many idle connections beyond what it was seen to
/// need (`srv_add_to_idle_list`), and a request takes the oldest idle connection first.
/// Under `safe`, four clients of one request each open four connections; a fifth client of
/// four requests then shows what was kept.
#[test]
fn pool_low_conn_keeps_idle_connections_beyond_the_estimate() {
    for (low, closed, last) in [
        ("", vec![2, 3, 4], [5, 1, 1, 1]),
        (" pool-low-conn 1", vec![3, 4], [5, 1, 2, 1]),
        (" pool-low-conn 3", vec![], [5, 1, 2, 3]),
    ] {
        let be = tracked_backend();
        let (_ibex, fe) = start_with(&format!("listen l\n  bind {{fe}}\n  http-reuse safe\n  server s {}{low}\n", be.addr));
        assert_eq!(clients(fe, 4, 1, "/"), [[1], [2], [3], [4]], "{low}");
        thread::sleep(Duration::from_millis(300));
        assert_eq!(be.closed(), closed, "{low}");
        assert_eq!(clients(fe, 1, 4, "/"), [last], "{low}");
    }
}

#[test]
fn pool_purge_delay_and_pool_low_conn_are_checked_at_load_and_not_called_ignored() {
    for ok in ["pool-purge-delay 0", "pool-purge-delay 500", "pool-purge-delay 2s", "pool-low-conn 4", "pool-low-conn +2", "pool-low-conn abc", "pool-low-conn -3"] {
        for default_server in [false, true] {
            let (success, text) = check(ok, default_server);
            assert!(success, "{ok} (default-server: {default_server}) refused: {text}");
            assert!(!text.contains("is ignored"), "{ok}: {text}");
        }
    }
    for (bad, why) in [
        ("pool-purge-delay abc", "unexpected character 'a' in argument to <pool-purge-delay>."),
        ("pool-purge-delay 10x", "unexpected character 'x' in argument to <pool-purge-delay>."),
        ("pool-purge-delay -1", "unexpected character '-' in argument to <pool-purge-delay>."),
        ("pool-purge-delay", "'pool-purge-delay' expects <value> as argument."),
        (
            "pool-purge-delay 99999999999",
            "timer overflow in argument '99999999999' to 'pool-purge-delay' (maximum value is 2147483647 ms or ~24.8 days)",
        ),
        ("pool-low-conn", "'pool-low-conn' expects <value> as argument."),
    ] {
        for default_server in [false, true] {
            let (success, text) = check(bad, default_server);
            assert!(!success, "{bad} accepted: {text}");
            assert!(text.contains(why), "{bad}: {text}");
        }
    }
}

/// `n` client connections one after the other, each sending one request and then staying
/// open and idle; then a second request on the first of them. Returns the backend
/// connections still open while the clients idle, and the backend connection that carried
/// each request.
fn idle_clients(nbthread: usize, n: usize) -> (usize, Vec<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let be = listener.local_addr().expect("addr");
    let open = Arc::new(AtomicUsize::new(0));
    let open2 = Arc::clone(&open);
    thread::spawn(move || {
        let count = AtomicUsize::new(0);
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let id = count.fetch_add(1, Ordering::SeqCst) + 1;
            let open = Arc::clone(&open2);
            open.fetch_add(1, Ordering::SeqCst);
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let rsp = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Conn: {id}\r\n\r\n");
                    if s.write_all(rsp.as_bytes()).is_err() {
                        break;
                    }
                }
                open.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    let fe = common::reserve_addr();
    let _ibex = start(
        &format!(
            "global\n  nbthread {nbthread}\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n\
             listen sender\n  bind {fe}\n  server srv {be}\n"
        ),
        fe,
    );
    let ask = |c: &mut TcpStream| -> usize {
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut resp = Vec::new();
        let mut buf = [0u8; 4096];
        while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => resp.extend_from_slice(&buf[..n]),
            }
        }
        let resp = String::from_utf8_lossy(&resp).to_ascii_lowercase();
        resp.split("x-conn: ").nth(1).and_then(|r| r.split("\r\n").next()).and_then(|n| n.trim().parse().ok()).expect("answer")
    };
    let mut clients = Vec::new();
    let mut ids = Vec::new();
    for _ in 0..n {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        ids.push(ask(&mut c));
        clients.push(c);
        thread::sleep(Duration::from_millis(20));
    }
    thread::sleep(Duration::from_millis(300));
    let still_open = open.load(Ordering::SeqCst);
    ids.push(ask(&mut clients[0]));
    (still_open, ids)
}

/// T187, measured on HAProxy (`http-reuse safe`, 10 sequential clients, each one request
/// then idle): every first request opens its own connection, but after its response the
/// connection goes back to the server's lists, which keep one per thread
/// (`srv_add_to_idle_list`) and close the rest: 1 backend connection left at `nbthread 1`
/// (the first, which the first client's next request takes), at most 4 at `nbthread 4`.
/// A client that idles does not hold a server connection.
#[test]
fn an_idle_client_does_not_hold_a_server_connection() {
    let (open, ids) = idle_clients(1, 10);
    assert_eq!(ids, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1]);
    assert_eq!(open, 1);
    let (open, ids) = idle_clients(4, 10);
    assert_eq!(&ids[..10], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    assert!(open <= 4, "{open} backend connections held by 10 idle clients");
}
