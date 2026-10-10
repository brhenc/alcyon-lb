// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! No socket is kept open after its peer is gone (T217).
//!
//! Measured on HAProxy 3.5-dev8-885761-29 (`nbthread 1`, 10 keep-alive clients one request
//! each, a backend that closes its connection 200 ms after answering, by FIN or by RST): 1.5 s
//! later the process holds the listener and the 10 client sockets and no server socket
//! (`/proc/<pid>/fd`); it subscribes its idle server connections for reads and closes one that
//! reads EOF, an error or data (`conn_idle_*`, `srv_cleanup_*`). Ibex kept the dead ones in the
//! pool until a request took them (283 left open in T187's soak run).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// A backend that answers one request per connection and closes the connection 200 ms later:
/// with a FIN, or with an RST (`SO_LINGER` 0).
fn closing_backend(rst: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                if s.read(&mut buf).unwrap_or(0) == 0 {
                    return;
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                thread::sleep(Duration::from_millis(200));
                if rst {
                    let _ = rustix::net::sockopt::set_socket_linger(&s, Some(Duration::ZERO));
                }
            });
        }
    });
    addr
}

struct Ibex(Child, #[allow(dead_code)] NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(cfg: &str, fe: SocketAddr) -> Ibex {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    // stdin too: inherited, it is whatever ran the test (a socket under an agent's shell),
    // and `sockets` would count it as one ibex left open.
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never started listening on {fe}");
    Ibex(child, f)
}

/// Sockets `pid` holds, from `/proc/<pid>/fd`.
fn sockets(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .expect("fd dir")
        .filter_map(Result::ok)
        .filter(|e| std::fs::read_link(e.path()).is_ok_and(|l| l.to_string_lossy().starts_with("socket:")))
        .count()
}

fn ask(c: &mut TcpStream) -> String {
    let _ = c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    while !resp.ends_with(b"ok") {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&resp).lines().next().unwrap_or("").to_string()
}

/// `n` keep-alive clients each send a request, the server closes every server connection;
/// returns the sockets the proxy holds beyond its listener and the clients one second
/// later, and the answers to a second request on each client.
fn closed_by_server(rst: bool, n: usize) -> (usize, Vec<String>) {
    let be = closing_backend(rst);
    let fe = common::reserve_addr();
    let ibex = start(
        &format!(
            "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n\
             listen l\n  bind {fe}\n  server s {be}\n"
        ),
        fe,
    );
    let pid = ibex.0.id();
    let mut clients = Vec::new();
    for _ in 0..n {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        assert!(ask(&mut c).starts_with("HTTP/1.1 200"));
        clients.push(c);
        thread::sleep(Duration::from_millis(10));
    }
    let deadline = Instant::now() + Duration::from_secs(6);
    // the listener and the clients are the sockets that belong there
    let want = n + 1;
    thread::sleep(Duration::from_millis(500));
    while Instant::now() < deadline && sockets(pid) > want {
        thread::sleep(Duration::from_millis(50));
    }
    let extra = sockets(pid).saturating_sub(want);
    let answers = clients.iter_mut().map(ask).collect();
    (extra, answers)
}

/// An idle pooled server connection whose server closed it is closed within a poll: by FIN
/// and by RST.
#[test]
fn an_idle_server_connection_the_server_closed_is_closed() {
    for rst in [false, true] {
        let (extra, answers) = closed_by_server(rst, 10);
        assert_eq!(extra, 0, "rst={rst}: {extra} server sockets open after the server closed them");
        assert!(answers.iter().all(|a| a.starts_with("HTTP/1.1 200")), "rst={rst}: {answers:?}");
    }
}

// ---- T217 churn: a few thousand mixed operations, then the descriptors are back ----

use std::collections::BTreeMap;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// A keep-alive backend on a fixed port that can be stopped (every connection it holds is
/// closed) and started again: the soak's server restart. `/slow` is answered after 3 s,
/// `/big` with 20 MB.
struct Restartable {
    port: u16,
    run: Arc<AtomicBool>,
    held: Arc<Mutex<Vec<TcpStream>>>,
}

impl Restartable {
    fn new(port: u16) -> Self {
        let mut b = Self { port, run: Arc::new(AtomicBool::new(false)), held: Arc::default() };
        b.start();
        b
    }

    fn start(&mut self) {
        let listener = TcpListener::bind(("127.0.0.1", self.port)).expect("bind backend");
        listener.set_nonblocking(true).expect("nonblocking");
        let run = Arc::new(AtomicBool::new(true));
        self.run = Arc::clone(&run);
        let held = Arc::clone(&self.held);
        thread::spawn(move || {
            while run.load(Ordering::Relaxed) {
                let Ok((s, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                };
                s.set_nonblocking(false).expect("blocking");
                if let Ok(c) = s.try_clone() {
                    held.lock().expect("held").push(c);
                }
                thread::spawn(move || backend_conn(s));
            }
        });
    }

    fn stop(&mut self) {
        self.run.store(false, Ordering::Relaxed);
        thread::sleep(Duration::from_millis(20));
        for c in self.held.lock().expect("held").drain(..) {
            let _ = c.shutdown(Shutdown::Both);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn backend_conn(mut s: TcpStream) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 65536];
    loop {
        let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
            match s.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
            continue;
        };
        let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
        let len: usize = head.split("content-length:").nth(1).and_then(|r| r.lines().next()).and_then(|n| n.trim().parse().ok()).unwrap_or(0);
        while buf.len() < end + 4 + len {
            match s.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        buf.drain(..end + 4 + len);
        if head.contains("/slow") {
            thread::sleep(Duration::from_secs(3));
        }
        if head.contains("/big") {
            if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 20000000\r\n\r\n").is_err() {
                return;
            }
            for _ in 0..305 {
                if s.write_all(&[b'x'; 65536]).is_err() {
                    return;
                }
            }
        } else if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
            return;
        }
    }
}

/// The process's descriptors by kind (`/proc/<pid>/fd`).
fn fd_breakdown(pid: u32) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for e in std::fs::read_dir(format!("/proc/{pid}/fd")).expect("fd dir").filter_map(Result::ok) {
        let Ok(l) = std::fs::read_link(e.path()) else { continue };
        let l = l.to_string_lossy().to_string();
        let kind = if l.starts_with('/') { "file" } else { l.split(':').next().unwrap_or("?") };
        *m.entry(kind.to_string()).or_default() += 1;
    }
    m
}

/// A command on the stats socket: the whole answer.
fn cli(path: &std::path::Path, cmd: &str) -> String {
    let mut s = UnixStream::connect(path).expect("stats socket");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    s.read_to_string(&mut out).expect("answer");
    out
}

fn curr_conns(path: &std::path::Path) -> usize {
    cli(path, "show info").lines().find_map(|l| l.strip_prefix("CurrConns: ")).and_then(|n| n.trim().parse().ok()).expect("CurrConns")
}

/// What a client of the soak does to the proxy, one way or another.
fn churn_op(kind: usize, fe: SocketAddr, tls: SocketAddr) {
    let get = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    let connect = |a: SocketAddr| {
        let c = TcpStream::connect(a).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        c
    };
    match kind % 10 {
        0 => {
            let mut c = connect(fe);
            for _ in 0..2 {
                let _ = ask(&mut c);
            }
        }
        1 => {
            // aborts in the middle of the request head
            let mut c = connect(fe);
            let _ = c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nX-Part: ");
        }
        2 => {
            // resets in the middle of the response
            let mut c = connect(fe);
            let _ = c.write_all(b"GET /big HTTP/1.1\r\nHost: x\r\n\r\n");
            let mut b = [0u8; 1000];
            let _ = c.read(&mut b);
            let _ = rustix::net::sockopt::set_socket_linger(&c, Some(Duration::ZERO));
        }
        3 => {
            // aborts a slow upload
            let mut c = connect(fe);
            let _ = c.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n");
            let _ = c.write_all(&[b'a'; 5000]);
        }
        4 => {
            // half-closed: FIN after the request, still reading
            let mut c = connect(fe);
            let _ = c.write_all(get.as_bytes());
            let _ = c.shutdown(Shutdown::Write);
            let mut r = Vec::new();
            let _ = c.read_to_end(&mut r);
        }
        5 => {
            // half-closed before the answer to a slow request
            let mut c = connect(fe);
            let _ = c.write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n");
            let _ = c.shutdown(Shutdown::Write);
        }
        6 => {
            // aborts during the TLS handshake
            let mut c = connect(tls);
            let _ = c.write_all(&[0x16, 3, 1, 0, 0xc8, 1, 0, 0]);
        }
        7 => {
            // clear text on a TLS port
            let mut c = connect(tls);
            let _ = c.write_all(b"GET / HTTP/1.0\r\n\r\n");
            let mut r = Vec::new();
            let _ = c.read_to_end(&mut r);
        }
        8 => {
            // `timeout server`: the answer comes later than the proxy waits
            let mut c = connect(fe);
            let _ = c.write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n");
            let mut r = Vec::new();
            let _ = c.read_to_end(&mut r);
        }
        _ => {
            // `timeout http-keep-alive` / `timeout client`: idles after an answer, or sends nothing
            let mut c = connect(fe);
            if kind % 20 == 9 {
                let _ = ask(&mut c);
            }
            let mut r = Vec::new();
            let _ = c.read_to_end(&mut r);
        }
    }
}

/// A few thousand mixed operations (clients that abort or reset at every stage, half-closed
/// clients, every timeout, TLS handshakes cut short, a health check against a dead server, the
/// backend restarted every so often with keep-alive clients holding connections), then the
/// descriptors of the process, by kind, are what they were before, and so are its connections
/// (`show info` `CurrConns`). Measured on HAProxy with the same operations: back to baseline
/// after the idle period, sockets 4 -> 4 (three listeners and the stats socket).
#[test]
fn descriptors_are_back_to_baseline_after_a_churn() {
    let be_port = common::reserve_addr().port();
    let fe = common::reserve_addr();
    let tls = common::reserve_addr();
    let dead = common::reserve_addr();
    let dead_fe = common::reserve_addr();
    let dir = tempfile::tempdir().expect("dir");
    let stats = dir.path().join("stats.sock");
    let cert = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/certs/localhost.pem");
    let mut backend = Restartable::new(be_port);
    let ibex = start(
        &format!(
            "global\n  nbthread 1\n  stats socket {stats}\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 500ms\n  \
             timeout server 500ms\n  timeout http-keep-alive 500ms\n  timeout http-request 500ms\n\
             listen l\n  bind {fe}\n  server s 127.0.0.1:{be_port}\n\
             listen t\n  bind {tls} ssl crt {cert}\n  server s 127.0.0.1:{be_port}\n\
             listen d\n  bind {dead_fe}\n  server d {dead} check inter 100ms\n",
            stats = stats.display()
        ),
        fe,
    );
    let pid = ibex.0.id();
    // the probe that waited for the listener has been timed out by then
    thread::sleep(Duration::from_millis(1500));
    let base = fd_breakdown(pid);
    let base_conns = curr_conns(&stats);
    // 100 clients of 20 operations each: 2000 in all, while the backend is restarted every
    // second under keep-alive clients that idle between answers. (40 of 50 took 30 s, most
    // of it waiting out timeouts one after the other; this split has the same mix of
    // operations to within six of 2000, T259.)
    let n = 100 * 20;
    let workers: Vec<_> = (0..100usize).map(|w| thread::spawn(move || (0..20usize).for_each(|i| churn_op(w * 7 + i * 3 + w * i, fe, tls)))).collect();
    let mut held: Vec<TcpStream> = Vec::new();
    while !workers.iter().all(thread::JoinHandle::is_finished) {
        for _ in 0..2 {
            let mut c = TcpStream::connect(fe).expect("connect");
            c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
            let _ = ask(&mut c);
            held.push(c);
        }
        thread::sleep(Duration::from_millis(500));
        backend.stop();
        backend.start();
        for c in held.iter_mut().take(2) {
            let _ = ask(c);
        }
        if held.len() > 6 {
            held.drain(..2);
        }
    }
    for w in workers {
        w.join().expect("worker");
    }
    drop(held);
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut now = fd_breakdown(pid);
    while Instant::now() < deadline && (now != base || curr_conns(&stats) != base_conns) {
        thread::sleep(Duration::from_millis(200));
        now = fd_breakdown(pid);
    }
    assert_eq!(now, base, "descriptors by kind after {n} operations and an idle period");
    assert_eq!(curr_conns(&stats), base_conns, "CurrConns after the churn");
}
