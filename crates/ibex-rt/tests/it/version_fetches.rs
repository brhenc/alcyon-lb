// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `req.ver` and `res.ver`: the version without its `HTTP/`, as `HAProxy`
//! (3.5-dev8-885761-29) printed them for this configuration, measured 2026-10-03:
//! `[1.1] [1.1]` for an HTTP/1.1 exchange, `[1.0] [1.0]` for an HTTP/1.0 one
//! (`smp_fetch_rqver`, `smp_fetch_stver` in `src/http_fetch.c`).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::Engine;

fn server(ver: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf);
            let _ = write!(c, "HTTP/{ver} 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    addr
}

#[test]
fn versions_are_reported_without_the_protocol_name() {
    let (s11, s10, fe) = (server("1.1"), server("1.0"), common::reserve_addr());
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n  http-response set-header x-v \"[%[res.ver]] [%[req.ver]]\"\n  \
         use_backend b10 if {{ path /10 }}\n  default_backend b11\n\
         backend b11\n  server s {s11}\nbackend b10\n  server s {s10}\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let client = thread::spawn(move || {
        ["GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", "GET /10 HTTP/1.0\r\nHost: x\r\n\r\n"]
            .iter()
            .map(|r| {
                let mut c = TcpStream::connect(fe).expect("connect");
                c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
                c.write_all(r.as_bytes()).expect("send");
                let mut out = String::new();
                let _ = c.read_to_string(&mut out);
                out.lines().find(|l| l.to_ascii_lowercase().starts_with("x-v:")).unwrap_or("").trim().to_string()
            })
            .collect::<Vec<_>>()
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let got = client.join().expect("client");
    assert_eq!(got, ["x-v: [1.1] [1.1]", "x-v: [1.0] [1.0]"]);
}
