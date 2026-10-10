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
