// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The buffer wait queue (memory slice S6, `docs/design/memory-q3-2026-10-25.md`): a connection
//! that cannot have a buffer past `tune.buffers.limit` waits for one, as on `HAProxy`, instead of
//! being reset.
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29 (`nbthread 1` and 2, `tune.buffers.limit 8`, slow
//! readers holding the buffers): no stream ever fails for want of a buffer; a new connection
//! waits and is served `200` once buffers are given back (drain shape, Q3 doc 1.2); a connection
//! still waiting when `timeout client` fires is answered `408` and logged
//! `fe/<NOSRV> -1/-1/-1/-1/<timeout> 408 0 - - cR-- ... "<BADREQ>"`. `HAProxy`'s cap is the limit
//! plus `nbthread` x `tune.buffers.reserve` (4); Ibex has no reserve yet, its cap is the limit, so
//! the number of holders here is Ibex's.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::common;

/// Body length of `GET /big`.
const BIG: usize = 2 << 20;

/// A server answering every head `200` with `ok` (`GET /big`: [`BIG`] bytes), then closing.
fn backend() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = l.local_addr().expect("addr").port();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut tmp) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                if buf.starts_with(b"GET /big") {
                    let _ = c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {BIG}\r\nConnection: close\r\n\r\n").as_bytes());
                    let chunk = vec![b'x'; 65536];
                    for _ in 0..BIG / chunk.len() {
                        if c.write_all(&chunk).is_err() {
                            return;
                        }
                    }
                } else {
                    let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                }
            });
        }
    });
    port
}

struct Proxy {
    child: Child,
    port: u16,
    /// Frontend `fe2`, with `timeout client 2s`: same pool, its own timeout.
    port2: u16,
    /// `fe`'s TLS bind (S6b), and the certificate it serves.
    tls_port: u16,
    cert: Option<rustls::pki_types::CertificateDer<'static>>,
    log: Arc<Mutex<String>>,
    dir: tempfile::TempDir,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

impl Proxy {
    fn log(&self) -> String {
        self.log.lock().expect("log").clone()
    }

    /// One CLI command's answer.
    fn cli(&self, cmd: &str) -> String {
        let mut s = UnixStream::connect(self.dir.path().join("s.sock")).expect("cli connect");
        s.set_read_timeout(Some(Duration::from_secs(3))).ok();
        s.write_all(format!("{cmd}\n").as_bytes()).expect("cli write");
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    /// `show pools`' standard buffer line: refused takes.
    fn buffer_failures(&self) -> usize {
        let out = self.cli("show pools");
        let line = out.lines().find(|l| l.contains("Pool buffer ")).unwrap_or_else(|| panic!("no buffer pool line in {out}"));
        line.split(" failures").next().and_then(|h| h.rsplit(' ').next()).and_then(|n| n.parse().ok()).unwrap_or_else(|| panic!("{line}"))
    }

    /// `show pools`' standard buffer line: (used, of them in thread caches).
    fn buffers(&self) -> (usize, usize) {
        let out = self.cli("show pools");
        let line = out.lines().find(|l| l.contains("Pool buffer ")).unwrap_or_else(|| panic!("no buffer pool line in {out}"));
        let num = |after: &str| -> usize {
            let rest = &line[line.find(after).map_or(0, |i| i + after.len())..];
            rest.trim_start().split(|c: char| !c.is_ascii_digit()).next().unwrap_or("").parse().unwrap_or_else(|_| panic!("{line}"))
        };
        (num("bytes), "), num("used (~"))
    }
}

/// The proxy, `nbthread 1`, with `tune.buffers.limit 3` and this `timeout client` (frontend
/// `fe2`: 2 s). `fe` answers `GET /r` itself (`hello`) and has a TLS bind too.
fn start(timeout_client: &str) -> Proxy {
    start_with(timeout_client, "")
}

/// [`start`] with more `global` lines.
fn start_with(timeout_client: &str, global: &str) -> Proxy {
    let be = backend();
    let dir = tempfile::TempDir::new().expect("dir");
    let cfg = dir.path().join("c.cfg");
    let sock = dir.path().join("s.sock");
    let port = common::reserve_port();
    let port2 = common::reserve_port();
    let tls_port = common::reserve_port();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let pem = dir.path().join("c.pem");
    std::fs::write(&pem, format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem())).expect("write pem");
    std::fs::write(
        &cfg,
        format!(
            "global\n\tnbthread 1\n\ttune.buffers.limit 3\n{global}\tstats socket {} level admin\n\
             defaults\n\tmode http\n\tlog stderr format raw local0\n\toption httplog\n\
             \ttimeout connect 3s\n\ttimeout client {timeout_client}\n\ttimeout server 5s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tbind 127.0.0.1:{tls_port} ssl crt {}\n\
             \thttp-request return status 200 content-type text/plain string hello if {{ path /r }}\n\tdefault_backend be\n\n\
             frontend fe2\n\tbind 127.0.0.1:{port2}\n\ttimeout client 2s\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{be}\n",
            sock.display(),
            pem.display()
        ),
    )
    .expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).arg("-db").stdout(Stdio::null()).stderr(Stdio::piped()).spawn().expect("spawn");
    let log = Arc::new(Mutex::new(String::new()));
    let (mut err, sink) = (child.stderr.take().expect("stderr"), Arc::clone(&log));
    thread::spawn(move || {
        let mut tmp = [0u8; 4096];
        while let Ok(n) = err.read(&mut tmp) {
            if n == 0 {
                break;
            }
            sink.lock().expect("log").push_str(&String::from_utf8_lossy(&tmp[..n]));
        }
    });
    assert!(common::wait_listening(([127, 0, 0, 1], port).into()), "the proxy never listened on {port}");
    assert!(common::wait_listening(([127, 0, 0, 1], port2).into()), "the proxy never listened on {port2}");
    Proxy { child, port, port2, tls_port, cert: Some(ck.cert.der().clone()), log, dir }
}

/// Three connections each holding a buffer for a partial request head: the limit.
fn hold(port: u16) -> Vec<TcpStream> {
    hold_n(port, 3)
}

/// `n` connections each holding a buffer for a partial request head.
fn hold_n(port: u16, n: usize) -> Vec<TcpStream> {
    let held = (0..n)
        .map(|_| {
            let mut c = TcpStream::connect(("127.0.0.1", port)).expect("connect");
            c.write_all(b"GET /held HTTP/1.1\r\nHost: x\r\n").expect("partial head");
            c
        })
        .collect();
    thread::sleep(Duration::from_millis(300));
    held
}

/// A `GET` on a new connection, in a thread: what it read (empty when reset or closed with
/// nothing) and how long it took.
fn get_in_thread(port: u16) -> thread::JoinHandle<(String, Duration)> {
    thread::spawn(move || {
        let t = Instant::now();
        let mut c = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let _ = c.write_all(b"GET /waiter HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        let mut got = Vec::new();
        let _ = c.read_to_end(&mut got);
        (String::from_utf8_lossy(&got).into_owned(), t.elapsed())
    })
}

/// Past the limit, the connection waits (it is neither reset nor answered `500`) and is
/// served `200` once a holder leaves and gives its buffer back.
#[test]
fn past_the_limit_a_connection_waits_and_is_served_when_a_buffer_frees() {
    let p = start("10s");
    let mut held = hold(p.port);
    let waiter = get_in_thread(p.port);
    thread::sleep(Duration::from_millis(700));
    assert!(!waiter.is_finished(), "the connection past the limit did not wait: {:?}\n{}", waiter.join().ok(), p.log());
    drop(held.remove(0));
    let (got, _) = waiter.join().expect("waiter");
    assert!(got.starts_with("HTTP/1.1 200"), "not served once a buffer was free: {got:?}\n{}", p.log());
    assert!(!p.log().contains("IR--"), "a stream failed for want of a buffer:\n{}", p.log());
}

/// Still waiting when `timeout client` fires: `408`, logged as `HAProxy` does
/// (`fe/<NOSRV> -1/-1/-1/-1/<timeout> 408 0 - - cR-- ... "<BADREQ>"`). The holders are on a
/// frontend with a longer timeout, so they keep the buffers past the waiter's.
#[test]
fn a_connection_waiting_for_a_buffer_times_out_with_408_cr() {
    let p = start("10s");
    let _held = hold(p.port);
    let waiter = get_in_thread(p.port2);
    thread::sleep(Duration::from_millis(700));
    assert!(!waiter.is_finished(), "the connection past the limit did not wait: {:?}\n{}", waiter.join().ok(), p.log());
    let (got, took) = waiter.join().expect("waiter");
    assert!(got.starts_with("HTTP/1.1 408"), "not a 408 at the client timeout: {got:?}\n{}", p.log());
    assert!(took >= Duration::from_millis(1800), "answered before the timeout: {took:?}");
    thread::sleep(Duration::from_millis(200));
    let log = p.log();
    assert!(
        log.lines().any(|l| l.contains(" fe2 fe2/<NOSRV> -1/-1/-1/-1/") && l.contains(" 408 0 - - cR-- ") && l.ends_with("\"<BADREQ>\"")),
        "no 408 cR-- line for the waiter:\n{log}"
    );
}

/// A waiter whose client leaves is not kept: once the holders are gone too, every buffer is
/// back in the thread cache (`show pools` used = cached) and the next request is served.
#[test]
fn a_waiter_that_disconnects_leaves_the_queue() {
    let p = start("10s");
    let held = hold(p.port);
    let mut c = TcpStream::connect(("127.0.0.1", p.port)).expect("connect");
    c.write_all(b"GET /gone HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("request");
    thread::sleep(Duration::from_millis(300));
    drop(c);
    thread::sleep(Duration::from_millis(300));
    drop(held);
    thread::sleep(Duration::from_millis(500));
    let (got, _) = get_in_thread(p.port).join().expect("get");
    assert!(got.starts_with("HTTP/1.1 200"), "{got:?}\n{}", p.log());
    thread::sleep(Duration::from_millis(300));
    let (used, cached) = p.buffers();
    assert_eq!(used, cached, "buffers still in use after every connection left:\n{}", p.cli("show pools"));
    assert!(!p.log().contains("IR--"), "a stream failed for want of a buffer:\n{}", p.log());
}

/// Slow readers of a large response past the limit: every one gets its whole body. A stream
/// already answering waits for its next buffer (`HAProxy` never cut a response in the Q3 runs:
/// no `ID--`), where Ibex cut them (`ID--`, 200 with part of the body).
#[test]
fn slow_readers_past_the_limit_each_get_the_whole_body() {
    let p = start("10s");
    let readers: Vec<TcpStream> = (0..6)
        .map(|_| {
            let mut c = TcpStream::connect(("127.0.0.1", p.port)).expect("connect");
            rustix::net::sockopt::set_socket_recv_buffer_size(&c, 4096).expect("SO_RCVBUF");
            c.write_all(b"GET /big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("request");
            c
        })
        .collect();
    thread::sleep(Duration::from_millis(500));
    let got: Vec<usize> = readers
        .into_iter()
        .map(|mut c| {
            thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(8))).ok();
                // Reading at last: a window of 4 KiB would make this slow, not the proxy.
                rustix::net::sockopt::set_socket_recv_buffer_size(&c, 1 << 20).expect("SO_RCVBUF");
                let mut all = Vec::new();
                let _ = c.read_to_end(&mut all);
                all.windows(4).position(|w| w == b"\r\n\r\n").map_or(0, |h| all.len() - h - 4)
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|t| t.join().expect("reader"))
        .collect();
    assert!(got.iter().all(|&n| n == BIG), "bodies {got:?} of {BIG}:\n{}", p.log());
    assert!(!p.log().contains(" ID-- ") && !p.log().contains("IR--"), "a stream failed for want of a buffer:\n{}", p.log());
}

/// A waiting connection does not spin: its client socket, with its request unread, is not
/// polled until a buffer is given back (the poller is level-triggered). Before, the stream ran
/// on every loop and was refused each time: ~300000 refused takes a second, 150 % CPU.
#[test]
fn a_waiting_connection_is_not_run_again_until_a_buffer_frees() {
    let p = start("10s");
    let _held = hold(p.port);
    let _waiter = get_in_thread(p.port);
    thread::sleep(Duration::from_millis(300));
    let before = p.buffer_failures();
    thread::sleep(Duration::from_secs(1));
    let after = p.buffer_failures();
    assert!(after - before < 50, "refused takes in one second of waiting: {}", after - before);
}

// -----------------------------------------------------------------------------
// S6b §4: buffers another thread's cache holds
// -----------------------------------------------------------------------------

/// `nbthread 2`, `tune.buffers.limit 8`, no `tune.memory.prealloc`; `GET /t` answers
/// `%[thread]` (Ibex has no `bind ... thread N`: each worker has its own `SO_REUSEPORT` socket,
/// so a test finds which thread serves a connection by asking it, as `memory_prealloc.rs`).
fn start_two_threads() -> Proxy {
    let be = backend();
    let dir = tempfile::TempDir::new().expect("dir");
    let cfg = dir.path().join("c.cfg");
    let sock = dir.path().join("s.sock");
    let port = common::reserve_port();
    let port2 = common::reserve_port();
    std::fs::write(
        &cfg,
        format!(
            "global\n\tnbthread 2\n\ttune.buffers.limit 8\n\tstats socket {} level admin\n\
             defaults\n\tmode http\n\tlog stderr format raw local0\n\toption httplog\n\
             \ttimeout connect 3s\n\ttimeout client 4s\n\ttimeout server 5s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\
             \thttp-request return status 200 content-type text/plain lf-string \"%[thread]\" if {{ path /t }}\n\
             \tdefault_backend be\n\n\
             frontend fe2\n\tbind 127.0.0.1:{port2}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{be}\n",
            sock.display()
        ),
    )
    .expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).arg("-db").stdout(Stdio::null()).stderr(Stdio::piped()).spawn().expect("spawn");
    let log = Arc::new(Mutex::new(String::new()));
    let (mut err, sink) = (child.stderr.take().expect("stderr"), Arc::clone(&log));
    thread::spawn(move || {
        let mut tmp = [0u8; 4096];
        while let Ok(n) = err.read(&mut tmp) {
            if n == 0 {
                break;
            }
            sink.lock().expect("log").push_str(&String::from_utf8_lossy(&tmp[..n]));
        }
    });
    assert!(common::wait_listening(([127, 0, 0, 1], port).into()), "the proxy never listened on {port}");
    Proxy { child, port, port2, tls_port: 0, cert: None, log, dir }
}

/// The worker thread serving `c`, asked with `GET /t` (the connection stays open).
fn thread_of(c: &mut TcpStream) -> String {
    c.set_read_timeout(Some(Duration::from_secs(5))).ok();
    c.write_all(b"GET /t HTTP/1.1\r\nHost: a\r\n\r\n").expect("GET /t");
    let mut got = Vec::new();
    let mut b = [0u8; 512];
    loop {
        let n = c.read(&mut b).expect("read /t");
        assert!(n > 0, "closed before answering /t: {:?}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&b[..n]);
        let text = String::from_utf8_lossy(&got).into_owned();
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let len: usize = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0))).expect("content-length");
            if body.len() >= len {
                return body[..len].to_string();
            }
        }
    }
}

/// Idle keep-alive connections: eight on one thread ("A") and one on the other ("B").
fn split_threads(p: &Proxy) -> (Vec<TcpStream>, TcpStream) {
    let mut by: std::collections::BTreeMap<String, Vec<TcpStream>> = std::collections::BTreeMap::new();
    for _ in 0..400 {
        let mut c = TcpStream::connect(("127.0.0.1", p.port)).expect("connect");
        let t = thread_of(&mut c);
        by.entry(t).or_default().push(c);
        if by.len() == 2 && by.values().all(|v| v.len() >= 8) {
            break;
        }
    }
    let mut it = by.into_values();
    let (a, mut b) = (it.next().expect("thread A"), it.next().expect("thread B: one thread accepts everything"));
    (a.into_iter().take(8).collect(), b.remove(0))
}

/// Each of `held` sends a partial request head: it holds a buffer on its thread, all eight of
/// the limit between them. Before, the buffers thread B's cache kept from its `GET /t` counted
/// against the limit and three of A's holders waited (`8 used (~3 by thread caches)`).
fn hold_on(p: &Proxy, held: &mut [TcpStream]) {
    for c in held.iter_mut() {
        c.write_all(b"GET /held HTTP/1.1\r\nHost: x\r\n").expect("partial head");
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        thread::sleep(Duration::from_millis(100));
        let (used, cached) = p.buffers();
        if used - cached == held.len() {
            return;
        }
        assert!(Instant::now() < deadline, "{} holders on one thread hold {} buffers:\n{}", held.len(), used - cached, p.cli("show pools"));
    }
}

/// A `GET` on `c` in a thread: what it read and how long it took.
fn get_on(mut c: TcpStream) -> thread::JoinHandle<(String, Duration)> {
    thread::spawn(move || {
        let t = Instant::now();
        c.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let _ = c.write_all(b"GET /b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        let mut got = Vec::new();
        let _ = c.read_to_end(&mut got);
        (String::from_utf8_lossy(&got).into_owned(), t.elapsed())
    })
}

/// Thread A held the eight buffers of the limit and gave them back: thread B's next request is
/// served at once. Before, A's cache kept the eight (they count against the limit) and B waited
/// for `timeout client` (408).
#[test]
fn buffers_another_thread_gave_back_serve_this_thread() {
    let p = start_two_threads();
    let (mut a, b) = split_threads(&p);
    hold_on(&p, &mut a);
    drop(a);
    thread::sleep(Duration::from_millis(300));
    let (got, took) = get_on(b).join().expect("B");
    assert!(got.starts_with("HTTP/1.1 200") && took < Duration::from_secs(2), "B after A gave its buffers back, {took:?}: {got:?}\n{}", p.cli("show pools"));
}

/// Thread B waits while thread A holds the limit; A's holders leave: B is woken and served,
/// not left waiting for its timeout while A's cache holds the buffers.
#[test]
fn a_waiter_is_woken_by_buffers_another_thread_gives_back() {
    let p = start_two_threads();
    let (mut a, b) = split_threads(&p);
    hold_on(&p, &mut a);
    let waiter = get_on(b);
    thread::sleep(Duration::from_millis(700));
    assert!(!waiter.is_finished(), "B did not wait: {:?}", waiter.join().ok());
    drop(a);
    let (got, took) = waiter.join().expect("B");
    assert!(got.starts_with("HTTP/1.1 200") && took < Duration::from_secs(3), "B after A's holders left, {took:?}: {got:?}\n{}", p.log());
}

// -----------------------------------------------------------------------------
// S6b §2: a local reply and a TLS read past the limit wait too
// -----------------------------------------------------------------------------

/// Two holders and a `GET /r` the frontend answers itself: its request has the third buffer
/// and the reply none. Measured on `HAProxy` 3.5-dev8 (`limit 3`, `reserve 0`): the request
/// waits and is answered `200` once a holder leaves (0.7 s, when it left). Ibex closed the
/// connection without an answer (`write_reply_with`: no buffer for the reply). Now the reply
/// waits for a buffer, and gets the one its request, consumed, gave back: it is answered while
/// the holders stay (Ibex's request and reply do not need two buffers at once, `HAProxy`'s do).
#[test]
fn a_local_reply_past_the_limit_waits_for_a_buffer() {
    let p = start("10s");
    let _held = hold_n(p.port, 2);
    let t = Instant::now();
    let mut c = TcpStream::connect(("127.0.0.1", p.port)).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let _ = c.write_all(b"GET /r HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    let got = String::from_utf8_lossy(&got);
    assert!(got.starts_with("HTTP/1.1 200") && got.ends_with("hello"), "the local reply at the limit: {got:?}\n{}", p.log());
    assert!(t.elapsed() < Duration::from_secs(2), "answered after {:?}", t.elapsed());
}

/// The same with the start of a second request behind the first: the request buffer is not
/// empty after the first, so the reply has no buffer until a holder leaves; it waits for one
/// (it was closed unanswered), and is answered then, as on `HAProxy`.
#[test]
fn a_local_reply_with_a_pipelined_request_waits_for_a_holder_to_leave() {
    let p = start("10s");
    let mut held = hold_n(p.port, 2);
    let port = p.port;
    let waiter = thread::spawn(move || {
        let mut c = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let _ = c.write_all(b"GET /r HTTP/1.1\r\nHost: x\r\n\r\nGET /r HTTP/1.1\r\n");
        let mut got = Vec::new();
        let mut b = [0u8; 4096];
        while !got.ends_with(b"hello") {
            match c.read(&mut b) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&b[..n]),
            }
        }
        String::from_utf8_lossy(&got).into_owned()
    });
    thread::sleep(Duration::from_millis(700));
    assert!(!waiter.is_finished(), "the local reply did not wait: {:?}\n{}", waiter.join().ok(), p.log());
    drop(held.remove(0));
    let got = waiter.join().expect("waiter");
    assert!(got.starts_with("HTTP/1.1 200") && got.ends_with("hello"), "not answered once a buffer was free: {got:?}\n{}", p.log());
}

/// A TLS connection past the limit: Ibex reads the handshake into a standard buffer (`HAProxy`'s
/// OpenSSL reads into its own memory: measured, its handshake completes at once and the request
/// waits). The connection waits for the buffer, and is served `200` once the holders leave,
/// where it failed (S5) with the handshake refused.
#[test]
fn a_tls_connection_past_the_limit_waits_for_a_buffer() {
    let p = start("10s");
    let held = hold(p.port);
    let cert = p.cert.clone().expect("cert");
    let addr: std::net::SocketAddr = ([127, 0, 0, 1], p.tls_port).into();
    let waiter = thread::spawn(move || {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).expect("root");
        let cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
        let conn = rustls::ClientConnection::new(Arc::new(cfg), name).expect("client");
        let tcp = TcpStream::connect(addr).expect("connect");
        tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        let _ = tls.write_all(b"GET /r HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        let mut got = Vec::new();
        let mut b = [0u8; 4096];
        loop {
            match tls.read(&mut b) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&b[..n]),
                Err(e) => {
                    got.extend_from_slice(format!(" <{e}>").as_bytes());
                    break;
                }
            }
        }
        String::from_utf8_lossy(&got).into_owned()
    });
    thread::sleep(Duration::from_millis(700));
    assert!(!waiter.is_finished(), "the TLS connection did not wait: {:?}\n{}", waiter.join().ok(), p.log());
    // One buffer free: the TLS read's, the request's still wanting. The waiter holds the one it
    // has and waits for the other without spinning (it took the request buffer, was refused
    // the read buffer, gave the first back and was offered it again, in a loop).
    let mut held = held;
    drop(held.remove(0));
    thread::sleep(Duration::from_millis(300));
    let before = p.buffer_failures();
    thread::sleep(Duration::from_secs(1));
    let refused = p.buffer_failures() - before;
    assert!(refused < 50, "refused takes in one second of waiting with one buffer free: {refused}");
    drop(held);
    let got = waiter.join().expect("waiter");
    assert!(got.starts_with("HTTP/1.1 200") && got.contains("hello"), "not served once buffers were free: {got:?}\n{}", p.log());
}

// -----------------------------------------------------------------------------
// S6b §1: tune.buffers.reserve
// -----------------------------------------------------------------------------

/// `tune.buffers.limit 3`, `tune.buffers.reserve 2`, `nbthread 1`: the thread's two emergency
/// buffers are made at start and raise the limit by two (`dynbuf.c`
/// `alloc_emergency_buffers_per_thread`). Measured on `HAProxy` 3.5-dev8 with five holders of a
/// partial head: `5 allocated (81920 bytes), 5 used` (the limit plus the reserve; with
/// `tune.buffers.limit 8`, `nbthread 2`: 8 / 12 / 40 allocated at reserve 0 / 2 / 16, Q3 doc
/// 1.1). Holders past the limit wait as before and are served once the others leave.
#[test]
fn the_reserve_raises_the_limit_by_its_emergency_buffers() {
    let p = start_with("10s", "\ttune.buffers.reserve 2\n");
    let allocated = |p: &Proxy| -> usize {
        let out = p.cli("show pools");
        let line = out.lines().find(|l| l.contains("Pool buffer ")).unwrap_or_else(|| panic!("{out}"));
        line.split(" : ").nth(1).and_then(|r| r.split_whitespace().next()).and_then(|n| n.parse().ok()).unwrap_or_else(|| panic!("{line}"))
    };
    let (used, cached) = p.buffers();
    assert_eq!(used - cached, 2, "the reserve, made at start:\n{}", p.cli("show pools"));
    // Partial heads of requests the frontend answers itself: completed, each is a local reply
    // (`DB_MUX_TX`, which may take the reserve's last buffer; a server's response, `DB_SE_RX`,
    // may not take past two thirds of it).
    let mut held: Vec<TcpStream> = (0..6)
        .map(|_| {
            let mut c = TcpStream::connect(("127.0.0.1", p.port)).expect("connect");
            c.write_all(b"GET /r HTTP/1.1\r\nHost: x\r\n").expect("partial head");
            c
        })
        .collect();
    thread::sleep(Duration::from_millis(300));
    assert_eq!(allocated(&p), 5, "the limit and the reserve:\n{}", p.cli("show pools"));
    let (used, cached) = p.buffers();
    // Three from the pool and one from the reserve (a client's first buffer only while the
    // reserve is full), one left in it; the fifth and sixth wait.
    assert_eq!(used - cached, 5, "four holders and one emergency buffer:\n{}", p.cli("show pools"));
    // Each holder completes its request in turn and is answered: the waiters too.
    for c in &mut held {
        c.set_read_timeout(Some(Duration::from_secs(5))).ok();
        c.write_all(b"Connection: close\r\n\r\n").expect("rest of the head");
        let mut got = Vec::new();
        let _ = c.read_to_end(&mut got);
        assert!(got.starts_with(b"HTTP/1.1 200") && got.ends_with(b"hello"), "{:?}\n{}", String::from_utf8_lossy(&got), p.log());
    }
}
