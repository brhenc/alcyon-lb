// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `no log` cancels the `log` lines a section inherited from `defaults`. Measured on the
//! reference `HAProxy` (3.5-dev8-885761-29) with `log global` in defaults: the frontend with
//! `no log` logged nothing, the plain one logged, and one with `no log` then its own `log`
//! logged once (its own line only).

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::Engine;

#[test]
fn no_log_cancels_the_inherited_log_lines() {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_nonblocking(true).expect("nonblocking");
    let (a, b, c) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 2s\n  timeout server 2s\n  log {} local0\n  \
         log-format \"%f\"\n\
         frontend nof\n  bind {a}\n  http-request return status 200\n  no log\n\
         frontend yesf\n  bind {b}\n  http-request return status 200\n\
         frontend nof2\n  bind {c}\n  http-request return status 200\n  no log\n  log {} local0\n",
        collector.local_addr().expect("addr"),
        collector.local_addr().expect("addr"),
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let client = thread::spawn(move || {
        for addr in [a, b, c] {
            let mut s = TcpStream::connect(addr).expect("connect");
            s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
            s.write_all(b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n").expect("send");
            let mut out = Vec::new();
            let _ = s.read_to_end(&mut out);
        }
    });
    let mut lines = Vec::new();
    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_millis(2500);
    while Instant::now() < deadline {
        let _ = engine.run_once();
        if let Ok(n) = collector.recv(&mut buf) {
            let l = String::from_utf8_lossy(&buf[..n]).into_owned();
            lines.push(l.split_once("]: ").map_or(l.clone(), |(_, b)| b.trim_end().to_string()));
        }
        thread::sleep(Duration::from_millis(1));
    }
    client.join().expect("client");
    lines.sort();
    assert_eq!(lines, ["nof2", "yesf"]);
}
