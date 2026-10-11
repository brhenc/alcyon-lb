// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A TCP-mode frontend routing to a backend (`default_backend`), as the reference
//! `HAProxy` (3.5-dev8-885761-29) ran it, measured 2026-10-03: the connection reaches
//! the backend's server, and its log line names them --
//! `dip=127.0.0.1 ts=-- b=be_app s=app1 B=0 Tc=0 Tt=500` for a server that read the
//! request, waited 500 ms and closed.

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::Engine;

#[test]
fn a_tcp_frontend_reaches_its_default_backend_and_logs_it() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv = listener.local_addr().expect("addr");
    thread::spawn(move || {
        if let Ok((mut c, _)) = listener.accept() {
            let mut buf = [0u8; 100];
            let n = c.read(&mut buf).unwrap_or(0);
            let _ = c.write_all(&buf[..n].to_ascii_uppercase());
            thread::sleep(Duration::from_millis(100));
        }
    });
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_nonblocking(true).expect("nonblocking");
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  timeout connect 5s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe1\n  bind {fe}\n  mode tcp\n  log {} local0\n  \
         log-format \"dip=%fi ts=%ts b=%b s=%s B=%B Tc=%Tc\"\n  default_backend be_app\n\
         backend be_app\n  mode tcp\n  server app1 {srv}\n",
        collector.local_addr().expect("addr")
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let client = thread::spawn(move || {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        c.write_all(b"ping").expect("send");
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
        out
    });
    let mut line = None;
    let mut buf = [0u8; 1024];
    let deadline = Instant::now() + Duration::from_secs(10);
    while line.is_none() && Instant::now() < deadline {
        let _ = engine.run_once();
        if let Ok(n) = collector.recv(&mut buf) {
            line = Some(String::from_utf8_lossy(&buf[..n]).into_owned());
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(client.join().expect("client"), b"PING", "relayed through the backend's server");
    let line = line.expect("a log line");
    let body = line.split_once("]: ").map_or("", |(_, b)| b.trim_end());
    // `%Tc` is however long this machine took to connect (HAProxy: 0); bounded, the rest
    // compared exactly.
    let (rest, tc) = body.rsplit_once(" Tc=").expect("Tc");
    assert!(tc.parse::<i64>().is_ok_and(|t| (0..50).contains(&t)), "{body}");
    assert_eq!(rest, "dip=127.0.0.1 ts=-- b=be_app s=app1 B=4");
}

/// TCP mode: a server sends as much as its socket takes to a client that reads nothing
/// (4 KB receive buffer), then resets its connection; the client writes, then reads what
/// came. The proxy learns of the reset sending the client's bytes, its buffer still full for
/// the client: the client's side is shut for reading and what the proxy holds is delivered,
/// then the close. Measured on `HAProxy` 3.5-dev8-885761-29 (`T280_ORACLE=/path/to/haproxy`):
/// the client gets every byte the log counts (1810432 of the 4434432 sent; the rest died
/// with the reset), then EOF, and its next writes fail (`EPIPE`).
#[test]
fn a_server_reset_behind_a_full_buffer_delivers_what_the_proxy_holds() {
    use rustix::net::{AddressFamily, SocketType};
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let be = l.local_addr().expect("addr");
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let go_rx = std::sync::Arc::new(std::sync::Mutex::new(go_rx));
    let (sent_tx, sent_rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let (go_rx, sent_tx) = (std::sync::Arc::clone(&go_rx), sent_tx.clone());
            thread::spawn(move || {
                c.set_nonblocking(true).ok();
                let chunk = vec![b'z'; 65536];
                let (mut sent, mut idle) = (0usize, Instant::now());
                while idle.elapsed() < Duration::from_millis(300) {
                    match c.write(&chunk) {
                        Ok(n) => {
                            sent += n;
                            idle = Instant::now();
                        }
                        Err(_) => thread::sleep(Duration::from_millis(5)),
                    }
                }
                let _ = sent_tx.send(sent);
                let _ = go_rx.lock().expect("go").recv_timeout(Duration::from_secs(5));
                let _ = rustix::net::sockopt::set_socket_linger(&c, Some(Duration::ZERO));
            });
        }
    });
    let fe = common::reserve_addr();
    let dir = tempfile::TempDir::new().expect("dir");
    let cfg = dir.path().join("c.cfg");
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode tcp\n\tlog stderr format raw local0\n\toption tcplog\n\
             \ttimeout connect 2s\n\ttimeout client 5s\n\ttimeout server 5s\n\n\
             frontend fe\n\tbind {fe}\n\tdefault_backend be\n\nbackend be\n\tserver s1 {be}\n"
        ),
    )
    .expect("write config");
    let bin = std::env::var("T280_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let mut child = std::process::Command::new(bin)
        .arg("-f")
        .arg(&cfg)
        .arg("-db")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut err = child.stderr.take().expect("stderr");
    let log = thread::spawn(move || {
        let mut out = String::new();
        let _ = err.read_to_string(&mut out);
        out
    });
    assert!(common::wait_listening(fe), "never listened on {fe}");
    // The readiness probe's server connection waits too: let it go first.
    let _ = sent_rx.recv_timeout(Duration::from_secs(5));
    go_tx.send(()).ok();
    let fd = rustix::net::socket(AddressFamily::INET, SocketType::STREAM, None).expect("socket");
    rustix::net::sockopt::set_socket_recv_buffer_size(&fd, 4096).expect("SO_RCVBUF");
    let std::net::SocketAddr::V4(v4) = fe else { panic!("v4") };
    rustix::net::connect_v4(&fd, &v4).expect("connect");
    let mut s = TcpStream::from(fd);
    sent_rx.recv_timeout(Duration::from_secs(5)).expect("the server filled the buffers");
    go_tx.send(()).ok();
    thread::sleep(Duration::from_millis(200));
    s.write_all(b"hello").expect("write");
    thread::sleep(Duration::from_millis(300));
    s.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let (mut got, mut buf) = (0usize, vec![0u8; 4096]);
    let end = loop {
        match s.read(&mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => got += n,
            Err(e) => break Err(e.kind()),
        }
    };
    let late = s.write_all(b"after").and_then(|()| {
        thread::sleep(Duration::from_millis(100));
        s.write_all(b"again")
    });
    common::stop(&mut child);
    let log = log.join().expect("log");
    let line = log.lines().rev().find(|l| l.contains(" be/s1 ")).unwrap_or_else(|| panic!("no log line: {log}"));
    let logged: usize = line.split_whitespace().nth(5).and_then(|b| b.parse().ok()).unwrap_or_else(|| panic!("bytes in {line}"));
    assert_eq!(end, Ok(()), "the client sees the close after {got} bytes");
    assert!(got > 0 && got == logged, "the client gets every byte the proxy took: {got} vs {line}");
    assert!(late.is_err(), "writes after the close fail");
}

/// TCP mode, a server that speaks first: the client connects, half-closes at once (sends
/// nothing) and reads. Measured on `HAProxy` 3.5-dev8-885761-29 (`T280_ORACLE=/path/to/haproxy`)
/// with `default_backend`, with and without a `tcp-request inspect-delay`: the server
/// connection is made all the same, the client's close reaches the server (it reads EOF),
/// and the server's reply reaches the client. Ibex dropped it (`fe/<NOSRV> -1/-1/0`): the
/// server side of a connect deferred to routing gave up on a client that had shut, so the
/// readiness probe of the test above never reached its server, which waited 5 s for it.
#[test]
fn a_client_that_half_closes_at_once_still_reaches_a_server_that_speaks_first() {
    for extra in ["", "\ttcp-request inspect-delay 1s\n\ttcp-request content accept if { req.len gt 0 }\n"] {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
        let be = l.local_addr().expect("addr");
        let server = thread::spawn(move || {
            l.set_nonblocking(true).expect("nonblocking");
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                if let Ok((mut c, _)) = l.accept() {
                    c.set_nonblocking(false).ok();
                    c.set_read_timeout(Some(Duration::from_secs(2))).ok();
                    let mut buf = [0u8; 16];
                    let eof = matches!(c.read(&mut buf), Ok(0));
                    let _ = c.write_all(b"220 hello\r\n");
                    return Some(eof);
                }
                thread::sleep(Duration::from_millis(5));
            }
            None
        });
        let fe = common::reserve_addr();
        let dir = tempfile::TempDir::new().expect("dir");
        let cfg = dir.path().join("c.cfg");
        std::fs::write(
            &cfg,
            format!(
                "defaults\n\tmode tcp\n\ttimeout connect 2s\n\ttimeout client 5s\n\ttimeout server 5s\n\n\
                 frontend fe\n\tbind {fe}\n{extra}\tdefault_backend be\n\nbackend be\n\tserver s1 {be}\n"
            ),
        )
        .expect("write config");
        let bin = std::env::var("T280_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
        let mut child = std::process::Command::new(bin)
            .arg("-f")
            .arg(&cfg)
            .arg("-db")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn");
        let mut c = (0..250)
            .find_map(|_| TcpStream::connect(fe).ok().or_else(|| {
                thread::sleep(Duration::from_millis(20));
                None
            }))
            .expect("never listened");
        c.shutdown(std::net::Shutdown::Write).expect("shutdown");
        c.set_read_timeout(Some(Duration::from_secs(3))).ok();
        let mut got = Vec::new();
        let _ = c.read_to_end(&mut got);
        let eof = server.join().expect("server");
        common::stop(&mut child);
        assert_eq!(eof, Some(true), "the server is connected and reads the client's close ({extra:?})");
        assert_eq!(got, b"220 hello\r\n", "the server's reply reaches the client ({extra:?})");
    }
}
