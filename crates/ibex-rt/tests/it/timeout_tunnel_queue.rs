// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `timeout tunnel` and `timeout queue` (and `http-request set-timeout tunnel|queue`) run as
//! timers on the data path (T178).
//!
//! Every value below was measured on the reference `HAProxy` (3.5-dev8-885761-29), with
//! `timeout connect 2s`, `timeout client 2s`, `timeout server 2s` unless said otherwise:
//!
//! * a WebSocket (`101`), a `CONNECT` (`200`) and a `mode tcp` connection, idle in both
//!   directions, are closed after `timeout tunnel` (0.7 s for 700 ms), not after the
//!   client/server timeout (2.0 s without it); the log says `cD`; traffic resets it
//!   (a byte every 400 ms keeps the tunnel open for 6 s);
//! * `http-request set-timeout tunnel 500` over `timeout tunnel 5s` closes at 0.5 s;
//! * `maxconn 1` server with one request in flight, a second request waits in the queue:
//!   `503` after `timeout queue` (0.7 s), else after `timeout connect` (1.5 s for 1500 ms),
//!   logged `sQ` with `Tw` equal to the wait and `0/1` queue positions; the backend row of
//!   `show stat` shows `qcur 1` while it waits, and `econ 1` once it gave up.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::NamedTempFile;

#[derive(Clone, Copy, PartialEq)]
enum Be {
    WebSocket,
    Connect,
    Raw,
    /// Answers after two seconds.
    Slow,
}

fn backend(kind: Be) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                if kind != Be::Raw {
                    let mut head = Vec::new();
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match c.read(&mut buf) {
                            Ok(n) if n > 0 => head.extend_from_slice(&buf[..n]),
                            _ => return,
                        }
                    }
                    let reply: &[u8] = match kind {
                        Be::WebSocket => b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n",
                        Be::Connect => b"HTTP/1.1 200 Connection established\r\n\r\n",
                        _ => {
                            thread::sleep(Duration::from_secs(2));
                            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                            thread::sleep(Duration::from_millis(300));
                            return;
                        }
                    };
                    let _ = c.write_all(reply);
                }
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 || c.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// A UDP syslog sink.
fn log_sink() -> (u16, Arc<Mutex<Vec<String>>>) {
    let u = UdpSocket::bind("127.0.0.1:0").expect("udp");
    let port = u.local_addr().expect("addr").port();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let l2 = lines.clone();
    thread::spawn(move || {
        let mut b = [0u8; 4096];
        while let Ok(n) = u.recv(&mut b) {
            l2.lock().expect("lock").push(String::from_utf8_lossy(&b[..n]).into_owned());
        }
    });
    (port, lines)
}

/// Starts ibex on `listen_body`, `{fe}`/`{be}`/`{log}` replaced, runs `f`, stops it.
fn with_ibex<T>(timeouts: &str, mode: &str, listen_body: &str, be: SocketAddr, f: impl FnOnce(SocketAddr, &Arc<Mutex<Vec<String>>>) -> T) -> T {
    let fe = common::reserve_addr();
    let (lp, lines) = log_sink();
    let cfg = format!(
        "global\n  log 127.0.0.1:{lp} local0\n\
         defaults\n  mode {mode}\n  log global\n  option {}\n{timeouts}\
         listen l\n  bind {fe}\n{listen_body}  server s {be}{}\n",
        if mode == "tcp" { "tcplog" } else { "httplog" },
        if mode == "tcp" { "" } else { " maxconn 1" }
    );
    let mut file = NamedTempFile::new().expect("tmp");
    file.write_all(cfg.as_bytes()).expect("write");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(file.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Ibex).expect("spawn");
    assert!(common::wait_listening(fe), "never listened:\n{cfg}");
    let out = f(fe, &lines);
    common::stop(&mut child);
    out
}

const TIMEOUTS: &str = "  timeout connect 2s\n  timeout client 2s\n  timeout server 2s\n";

/// How long until the peer closes `s`; `ping` sends a byte that often meanwhile.
fn until_eof(s: &mut TcpStream, limit: Duration, ping: Option<Duration>) -> (Duration, bool) {
    let start = Instant::now();
    s.set_read_timeout(Some(Duration::from_millis(20))).expect("rt");
    let mut next = Duration::ZERO;
    let mut b = [0u8; 256];
    while start.elapsed() < limit {
        if ping.is_some_and(|_| start.elapsed() >= next) {
            if s.write_all(b"x").is_err() {
                return (start.elapsed(), true);
            }
            next += ping.unwrap_or_default();
        }
        match s.read(&mut b) {
            Ok(0) => return (start.elapsed(), true),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => return (start.elapsed(), true),
            Ok(_) => {}
        }
    }
    (start.elapsed(), false)
}

fn open_tunnel(fe: SocketAddr, kind: Be) -> TcpStream {
    let mut s = TcpStream::connect(fe).expect("connect");
    let req: &[u8] = match kind {
        Be::WebSocket => b"GET /ws HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        _ => b"CONNECT a:1 HTTP/1.1\r\nHost: a:1\r\n\r\n",
    };
    s.write_all(req).expect("send");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("rt");
    let mut head = Vec::new();
    let mut b = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut b).expect("head");
        assert!(n > 0, "no head");
        head.extend_from_slice(&b[..n]);
    }
    s
}

fn near(got: Duration, want_ms: u64) -> bool {
    let g = got.as_millis() as u64;
    g + 150 >= want_ms && g <= want_ms + 250
}

/// `Tw`, the milliseconds a request waited in the queue, from the `Tq/Tw/Tc/Tr/Ta` field of an
/// `httplog` line.
fn queue_wait_ms(log: &str) -> Option<u64> {
    log.split(' ').find(|f| f.split('/').count() == 5 && f.split('/').all(|n| !n.is_empty() && n.trim_start_matches(['-', '+']).bytes().all(|b| b.is_ascii_digit()))).and_then(|f| f.split('/').nth(1)?.parse().ok())
}

fn logged(lines: &Arc<Mutex<Vec<String>>>, needle: &str) -> bool {
    for _ in 0..30 {
        if lines.lock().expect("lock").iter().any(|l| l.contains(needle)) {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

fn tunnel_idle(kind: Be, timeouts: &str, body: &str) {
    let be = backend(kind);
    let (d, eof, lines) = with_ibex(timeouts, "http", body, be, |fe, lines| {
        let mut s = open_tunnel(fe, kind);
        let (d, eof) = until_eof(&mut s, Duration::from_secs(4), None);
        assert!(logged(lines, " cD"), "log: {:?}", lines.lock().expect("lock"));
        (d, eof, lines.lock().expect("lock").clone())
    });
    assert!(eof && near(d, 700), "closed after {d:?} ({eof}); log {lines:?}");
}

#[test]
fn websocket_idle_is_closed_after_timeout_tunnel() {
    tunnel_idle(Be::WebSocket, &format!("{TIMEOUTS}  timeout tunnel 700ms\n"), "");
}

#[test]
fn connect_tunnel_idle_is_closed_after_timeout_tunnel() {
    tunnel_idle(Be::Connect, &format!("{TIMEOUTS}  timeout tunnel 700ms\n"), "");
}

#[test]
fn traffic_resets_timeout_tunnel() {
    let be = backend(Be::WebSocket);
    let (d, eof) = with_ibex(&format!("{TIMEOUTS}  timeout tunnel 700ms\n"), "http", "", be, |fe, _| {
        let mut s = open_tunnel(fe, Be::WebSocket);
        until_eof(&mut s, Duration::from_millis(3500), Some(Duration::from_millis(400)))
    });
    assert!(!eof, "closed after {d:?} with traffic every 400 ms");
}

#[test]
fn tcp_mode_idle_is_closed_after_timeout_tunnel() {
    let be = backend(Be::Raw);
    let (d, eof) = with_ibex(&format!("{TIMEOUTS}  timeout tunnel 700ms\n"), "tcp", "", be, |fe, lines| {
        let mut s = TcpStream::connect(fe).expect("connect");
        let r = until_eof(&mut s, Duration::from_secs(4), None);
        assert!(logged(lines, " cD"), "log: {:?}", lines.lock().expect("lock"));
        r
    });
    // Never sooner than the timer; the upper bound only has to tell 700 ms from `timeout
    // client` (2 s), the host's delay in waking this thread is not what is tested.
    assert!(eof && d + Duration::from_millis(150) >= Duration::from_millis(700) && d <= Duration::from_millis(1500), "closed after {d:?} ({eof})");
}

#[test]
fn set_timeout_tunnel_changes_the_timer() {
    let be = backend(Be::WebSocket);
    let (d, eof) = with_ibex(&format!("{TIMEOUTS}  timeout tunnel 5s\n"), "http", "  http-request set-timeout tunnel 500\n", be, |fe, _| {
        let mut s = open_tunnel(fe, Be::WebSocket);
        until_eof(&mut s, Duration::from_secs(4), None)
    });
    assert!(eof && near(d, 500), "closed after {d:?} ({eof})");
}

/// One request in flight on the `maxconn 1` server, a second one queued: how long its
/// answer takes, its status line, the backend's `qcur` while it waits, and its log line.
fn queued(timeouts: &str, body: &str) -> (Duration, String, String, String, String) {
    let be = backend(Be::Slow);
    let body = format!("  stats enable\n  stats uri /st\n{body}");
    with_ibex(timeouts, "http", &body, be, |fe, lines| {
        let mut a = TcpStream::connect(fe).expect("a");
        a.write_all(b"GET /a HTTP/1.1\r\nHost: t\r\n\r\n").expect("a");
        // /b only once /a holds the server's one slot: sent together (a late accept, a loaded
        // host) /b could take the slot and /a be the queued one.
        let deadline = Instant::now() + Duration::from_secs(5);
        while server_scur(fe) != "1" {
            assert!(Instant::now() < deadline, "/a never took the slot");
            thread::sleep(Duration::from_millis(20));
        }
        let mut b = TcpStream::connect(fe).expect("b");
        let t0 = Instant::now();
        b.write_all(b"GET /b HTTP/1.1\r\nHost: t\r\n\r\n").expect("b");
        // /b is queued: wait for the row to say so (it stays queued for the timeout).
        let deadline = Instant::now() + Duration::from_millis(600);
        let mut mid = backend_row(fe);
        while !mid.starts_with("qcur=1") && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
            mid = backend_row(fe);
        }
        b.set_read_timeout(Some(Duration::from_secs(6))).expect("rt");
        let mut r = Vec::new();
        let mut buf = [0u8; 1024];
        while !r.windows(4).any(|w| w == b"\r\n\r\n") {
            match b.read(&mut buf) {
                Ok(n) if n > 0 => r.extend_from_slice(&buf[..n]),
                _ => break,
            }
        }
        let d = t0.elapsed();
        let first = String::from_utf8_lossy(&r).lines().next().unwrap_or("").to_string();
        logged(lines, "GET /b");
        let log = lines.lock().expect("lock").iter().find(|l| l.contains("GET /b")).cloned().unwrap_or_default();
        thread::sleep(Duration::from_millis(2300));
        drop(a);
        drop(b);
        let end = backend_row(fe);
        (d, first, mid, end, log)
    })
}

/// The `scur` of server `s`, as the text of the CSV field.
fn server_scur(fe: SocketAddr) -> String {
    let mut c = TcpStream::connect(fe).expect("stats");
    c.write_all(b"GET /st;csv HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").expect("send");
    c.set_read_timeout(Some(Duration::from_secs(2))).expect("rt");
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    let hdr: Vec<&str> = out.lines().find(|l| l.starts_with("# ")).expect("header")[2..].split(',').collect();
    let row: Vec<&str> = out.lines().find(|l| l.starts_with("l,s,")).expect("row").split(',').collect();
    row[hdr.iter().position(|h| *h == "scur").expect("column")].to_string()
}

/// The `qcur` and `econ` of the backend row, as `qcur=<n> econ=<n>`.
fn backend_row(fe: SocketAddr) -> String {
    let mut c = TcpStream::connect(fe).expect("stats");
    c.write_all(b"GET /st;csv HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").expect("send");
    c.set_read_timeout(Some(Duration::from_secs(2))).expect("rt");
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    let hdr: Vec<&str> = out.lines().find(|l| l.starts_with("# ")).expect("header")[2..].split(',').collect();
    let row: Vec<&str> = out.lines().find(|l| l.starts_with("l,BACKEND,")).expect("row").split(',').collect();
    let col = |n: &str| row[hdr.iter().position(|h| *h == n).expect("column")];
    format!("qcur={} econ={}", col("qcur"), col("econ"))
}

#[test]
fn queued_request_gets_503_after_timeout_queue() {
    let t = format!("  timeout connect 1500ms\n  timeout client 10s\n  timeout server 10s\n  timeout queue 700ms\n");
    let (d, status, mid, end, log) = queued(&t, "");
    let tw = queue_wait_ms(&log);
    assert!(tw.is_some_and(|tw| near(Duration::from_millis(tw), 700)), "Tw {tw:?} ms; answered after {d:?}: {status}; log {log}");
    assert_eq!(status, "HTTP/1.1 503 Service Unavailable", "{log}");
    assert!(log.contains(" sQ-- "), "{log}");
    assert!(log.contains(" 0/1 \"GET /b"), "queue positions: {log}");
    assert_eq!(mid, "qcur=1 econ=0");
    assert_eq!(end, "qcur=0 econ=1");
}

#[test]
fn queued_request_waits_timeout_connect_when_no_timeout_queue() {
    let t = "  timeout connect 1500ms\n  timeout client 10s\n  timeout server 10s\n";
    let (d, status, _, _, log) = queued(t, "");
    // Never sooner than the timer, by the test's clock. How long the request waited is the
    // proxy's own `Tw`: the test's clock also holds the time this thread took to write and to
    // wake up, which a loaded host stretches.
    assert!(d + Duration::from_millis(150) >= Duration::from_millis(1500), "answered after {d:?}: {status}; log {log}");
    let tw = queue_wait_ms(&log);
    assert!(tw.is_some_and(|tw| near(Duration::from_millis(tw), 1500)), "Tw {tw:?} ms; answered after {d:?}: {status}; log {log}");
    assert_eq!(status, "HTTP/1.1 503 Service Unavailable", "{log}");
    assert!(log.contains(" sQ-- "), "{log}");
}

#[test]
fn set_timeout_queue_changes_the_timer() {
    let t = "  timeout connect 1500ms\n  timeout client 10s\n  timeout server 10s\n  timeout queue 5s\n";
    let (d, status, _, _, log) = queued(t, "  http-request set-timeout queue 400\n");
    let tw = queue_wait_ms(&log);
    assert!(tw.is_some_and(|tw| near(Duration::from_millis(tw), 400)), "Tw {tw:?} ms; answered after {d:?}: {status}; log {log}");
    assert!(log.contains(" sQ-- "), "{log}");
}

#[test]
fn queued_request_is_served_when_the_slot_frees() {
    // The first request answers after 2 s; the queued one then goes through, well before
    // a 5 s `timeout queue`.
    let be = backend(Be::Slow);
    let t = "  timeout connect 1500ms\n  timeout client 10s\n  timeout server 10s\n  timeout queue 5s\n";
    let (gap, status, a_status) = with_ibex(t, "http", "", be, |fe, _| {
        let mut a = TcpStream::connect(fe).expect("a");
        a.write_all(b"GET /a HTTP/1.1\r\nHost: t\r\n\r\n").expect("a");
        // When the first answer reaches us: the slot frees then. Both instants are taken in
        // this test, so a slow start or a late wake-up on a loaded host moves them together.
        let a_done = {
            let mut a = a.try_clone().expect("clone");
            thread::spawn(move || {
                let mut r = Vec::new();
                let mut buf = [0u8; 1024];
                while !r.windows(4).any(|w| w == b"\r\n\r\n") {
                    match a.read(&mut buf) {
                        Ok(n) if n > 0 => r.extend_from_slice(&buf[..n]),
                        _ => break,
                    }
                }
                (Instant::now(), String::from_utf8_lossy(&r).lines().next().unwrap_or("").to_string())
            })
        };
        thread::sleep(Duration::from_millis(200));
        let mut b = TcpStream::connect(fe).expect("b");
        b.write_all(b"GET /b HTTP/1.1\r\nHost: t\r\n\r\n").expect("b");
        b.set_read_timeout(Some(Duration::from_secs(8))).expect("rt");
        let mut r = Vec::new();
        let mut buf = [0u8; 1024];
        while !r.windows(4).any(|w| w == b"\r\n\r\n") {
            match b.read(&mut buf) {
                Ok(n) if n > 0 => r.extend_from_slice(&buf[..n]),
                _ => break,
            }
        }
        let b_done = Instant::now();
        let (a_done, a_status) = a_done.join().expect("a reader");
        let _ = a.shutdown(std::net::Shutdown::Both);
        // Which of the two took the slot is the proxy's order of work, not the test's: the
        // requests are 200 ms apart, and a loaded host can hand ibex both in one pass, `/b` first
        // (T614: a gap of 0 ns, B answered before A). Whichever came second waited behind the
        // other, so the distance between the two answers is what is measured.
        let gap = if b_done > a_done { b_done - a_done } else { a_done - b_done };
        (gap, String::from_utf8_lossy(&r).lines().next().unwrap_or("").to_string(), a_status)
    });
    assert_eq!((status.as_str(), a_status.as_str()), ("HTTP/1.1 200 OK", "HTTP/1.1 200 OK"));
    // The second request only goes to the server once the first one's answer has left, and
    // then the backend takes its own 2 s: it cannot be answered sooner than that after the
    // first, and a request that waited out the 5 s `timeout queue` would have been a 503.
    assert!(gap >= Duration::from_millis(1900) && gap < Duration::from_millis(3500), "{gap:?}");
}

#[test]
fn two_queued_requests_are_both_served_in_turn() {
    let be = backend(Be::Slow);
    let t = "  timeout connect 1500ms\n  timeout client 10s\n  timeout server 10s\n  timeout queue 9s\n";
    let out = with_ibex(t, "http", "", be, |fe, _| {
        let hs: Vec<_> = (0..3)
            .map(|i| {
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(150 * i));
                    let mut s = TcpStream::connect(fe).expect("c");
                    s.write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").expect("w");
                    s.set_read_timeout(Some(Duration::from_secs(10))).expect("rt");
                    let mut r = String::new();
                    let _ = s.read_to_string(&mut r);
                    r.lines().next().unwrap_or("").to_string()
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().expect("join")).collect::<Vec<_>>()
    });
    assert_eq!(out, vec!["HTTP/1.1 200 OK"; 3]);
}

/// The 101 comes late (1 s, `timeout client`/`server` 5 s): the tunnel runs on
/// `timeout tunnel` from the 101, so it closes about 0.7 s after it (5 s would be `timeout client`).
#[test]
fn timeout_tunnel_starts_at_a_late_101() {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let be = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut b = [0u8; 4096];
                let _ = c.read(&mut b);
                thread::sleep(Duration::from_secs(1));
                let _ = c.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n");
                while c.read(&mut b).is_ok_and(|n| n > 0) {}
            });
        }
    });
    let t = "  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n  timeout tunnel 700ms\n";
    let (d, eof) = with_ibex(t, "http", "", be, |fe, _| {
        let mut s = TcpStream::connect(fe).expect("c");
        s.write_all(b"GET /ws HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").expect("w");
        let mut b = [0u8; 1024];
        s.set_read_timeout(Some(Duration::from_secs(30))).expect("rt");
        let _ = s.read(&mut b);
        // Timed from the 101 reaching the client, not from the request: how late the 101 is
        // depends on the host, the tunnel timeout runs from it.
        let t0 = Instant::now();
        let (d, eof) = until_eof(&mut s, Duration::from_secs(4), None);
        { let _ = d; (t0.elapsed(), eof) }
    });
    assert!(eof && d >= Duration::from_millis(550) && d <= Duration::from_millis(1500), "closed at {d:?}");
}
