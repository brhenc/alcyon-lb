// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Per-transaction log lines on the wire, as the reference `HAProxy` (3.5-dev8-885761-29)
//! sent them for the same configuration and requests, measured 2026-10-03 with a UDP
//! collector:
//!
//! ```text
//! /ret ST=200 B=0 U=85 ts=LR Tw=-1 Tc=-1 Tr=-1 s=<NOSRV> b=fe
//! /deny ST=403 B=0 U=86 ts=PR Tw=-1 Tc=-1 Tr=-1 s=<NOSRV> b=fe
//! /red ST=302 B=0 U=85 ts=LR Tw=-1 Tc=-1 Tr=-1 s=<NOSRV> b=fe
//! /ok ST=201 B=77 U=84 ts=-- Tw=0 Tc=0 Tr=1 s=s1 b=be
//! /dead ST=503 B=0 U=86 ts=SC Tw=0 Tc=-1 Tr=-1 s=s2 b=dead
//! <BADREQ> ST=400 B=0 U=0 ts=PR Tw=-1 Tc=-1 Tr=-1 s=<NOSRV> b=fe
//! ```
//!
//! `%B` is what the server sent (0 for a response the proxy made), `%U` what the client
//! sent for a request that parsed (curl's requests were 84 to 86 bytes; here they are
//! whatever these requests are). The syslog header carries the tag and pid, and no host
//! name: `<134>Oct  3 17:11:54 haproxy[1605231]: ...`.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::Engine;

const RESPONSE: &[u8] = b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\nSet-Cookie: s=1\r\nX-R: rv\r\n\r\nhello";

fn server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut chunk) {
                    Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                    _ => break,
                }
            }
            let _ = c.write_all(RESPONSE);
        }
    });
    addr
}

fn request(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
}

#[test]
fn each_transaction_logs_one_line_as_haproxy_does() {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_nonblocking(true).expect("nonblocking");
    let (srv, dead, fe) = (server(), common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 100ms\n  timeout client 2s\n  timeout server 2s\n\
         frontend fe\n  bind {fe}\n  log {} local0\n  \
         log-format \"%HU ST=%ST B=%B U=%U ts=%ts Tw=%Tw Tc=%Tc Tr=%Tr s=%s b=%b\"\n  \
         http-request return status 200 content-type text/plain string hello if {{ path /ret }}\n  \
         http-request deny if {{ path /deny }}\n  \
         http-request redirect location /x if {{ path /red }}\n  \
         use_backend dead if {{ path /dead }}\n  default_backend be\n\
         backend be\n  server s1 {srv}\n\
         backend dead\n  server s2 {dead}\n",
        collector.local_addr().expect("addr")
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let reqs = ["/ret", "/deny", "/red", "/ok", "/dead"].map(request);
    let lens: Vec<usize> = reqs.iter().map(String::len).collect();
    let client = thread::spawn(move || {
        for r in reqs.iter().map(String::as_str).chain(["GARBAGE\r\n\r\n"]) {
            let mut c = TcpStream::connect(fe).expect("connect");
            c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
            c.write_all(r.as_bytes()).expect("send");
            let mut out = Vec::new();
            let _ = c.read_to_end(&mut out);
        }
    });
    let mut lines = Vec::new();
    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(15);
    while lines.len() < 6 && Instant::now() < deadline {
        let _ = engine.run_once();
        if let Ok(n) = collector.recv(&mut buf) {
            lines.push(String::from_utf8_lossy(&buf[..n]).into_owned());
        }
        thread::sleep(Duration::from_millis(1));
    }
    client.join().expect("client");
    let pid = std::process::id();
    for l in &lines {
        assert!(l.starts_with("<134>") && l.contains(&format!(" haproxy[{pid}]: ")), "header: {l:?}");
        let time_then_tag = l.split(" haproxy[").next().unwrap_or("");
        assert_eq!(time_then_tag.len(), "<134>Oct  3 17:11:54".len(), "no host name in the header: {l:?}");
    }
    let mut bodies: Vec<String> = lines.iter().map(|l| l.split_once("]: ").map_or("", |(_, b)| b.trim_end()).to_string()).collect();
    // The connect and response times of `/ok` are whatever this machine took (HAProxy:
    // 0 and 1); they are bounded here, the rest compared exactly.
    if let Some(ok) = bodies.get_mut(3) {
        let fields: Vec<String> = ok
            .split(' ')
            .map(|f| match f.split_once('=') {
                Some((k @ ("Tc" | "Tr"), v)) => {
                    let ms: i64 = v.parse().unwrap_or(-1);
                    assert!((0..50).contains(&ms), "{k}={v} in {ok}");
                    format!("{k}=n")
                }
                _ => f.to_string(),
            })
            .collect();
        *ok = fields.join(" ");
    }
    assert_eq!(
        bodies,
        [
            format!("/ret ST=200 B=0 U={} ts=LR Tw=-1 Tc=-1 Tr=-1 s=<NOSRV> b=fe", lens[0]),
            format!("/deny ST=403 B=0 U={} ts=PR Tw=-1 Tc=-1 Tr=-1 s=<NOSRV> b=fe", lens[1]),
            format!("/red ST=302 B=0 U={} ts=LR Tw=-1 Tc=-1 Tr=-1 s=<NOSRV> b=fe", lens[2]),
            format!("/ok ST=201 B={} U={} ts=-- Tw=0 Tc=n Tr=n s=s1 b=be", RESPONSE.len(), lens[3]),
            format!("/dead ST=503 B=0 U={} ts=SC Tw=0 Tc=-1 Tr=-1 s=s2 b=dead", lens[4]),
            "<BADREQ> ST=400 B=0 U=0 ts=PR Tw=-1 Tc=-1 Tr=-1 s=<NOSRV> b=fe".to_string(),
        ]
    );
}
