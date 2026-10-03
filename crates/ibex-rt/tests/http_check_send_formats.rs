// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `http-check send`: `hdr` values, `uri-lf` and `body-lf` are log-formats, rendered per
//! check for the server being checked; `uri` and `body` are literal; and `send-state`
//! reports the checked server's real name, state and weights.
//!
//! Before this Ibex sent every value literally (`x-id: %[unique-id]`), and `send-state`
//! wrote `UP 1/1; name=srv; qcur=0; srv_port=<port>` for every server, up or down.
//!
//! Expected requests are `HAProxy`'s, measured on 2026-10-03 against `HAProxy`
//! 3.5-dev8-885761-29 running this configuration with capture servers (the last request
//! each server received, once the checks had settled; `\r\n` line ends):
//!
//! ```text
//! be1/s1  GET /plain%[be_name] HTTP/1.1 | host: localhost | x-id: U-be1-down-1 |
//!         x-lit: literal | x-srv: s1 | x-haproxy-server-state: UP; address=127.0.0.1;
//!         port=<s1>; name=be1/s1; node=<hostname>; weight=1/1; scur=0/0; qcur=0 |
//!         content-length: 11 | connection: close || b%[be_name]
//! be2/t1  POST /lfbe2/t1 HTTP/1.1 | content-length: 3 | connection: close || Bt1
//! be3/d1  (answers 503, so DOWN) GET / HTTP/1.1 | x-haproxy-server-state: DOWN;
//!         address=127.0.0.1; port=<d1>; name=be3/d1; node=<hostname>; weight=1/7;
//!         scur=0/0; qcur=0 | connection: close
//! be3/d2  (backup, weight 7) ... x-haproxy-server-state: UP; ...; name=be3/d2; ...;
//!         weight=7/7; ...
//! ```
//!
//! So: the header whose value renders empty (`x-empty %[str()]`) is not sent; `srv_is_up`
//! and `nbsrv` in the backend's `unique-id-format` see s2 DOWN; `weight=<server>/<backend
//! total>`, where the total is the usable active servers' weights, or the first usable
//! backup's when there are none (d1 is DOWN, so be3's total is d2's 7); `node` is the host
//! name when no `node` is configured. Before the checks settle `HAProxy` reports transitional
//! states (`UP 0/1`) that this does not assert on.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::Engine;

type Seen = Arc<Mutex<Vec<String>>>;

/// A server that records every complete request it receives and answers with `status`.
fn capture(status: &'static str) -> (SocketAddr, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let seen: Seen = Arc::default();
    let rec = Arc::clone(&seen);
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let _ = c.set_read_timeout(Some(Duration::from_millis(300)));
            let mut data = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n) = c.read(&mut buf) {
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&data);
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let len = head
                        .lines()
                        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                        .unwrap_or(0);
                    if body.len() >= len {
                        break;
                    }
                }
            }
            if !data.is_empty() {
                rec.lock().expect("lock").push(String::from_utf8_lossy(&data).into_owned());
            }
            let _ = c.write_all(format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").as_bytes());
        }
    });
    (addr, seen)
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname").expect("hostname").trim().to_string()
}

/// The last request in `seen` containing `marker`.
fn last_with(seen: &Seen, marker: &str) -> Option<String> {
    seen.lock().expect("lock").iter().rev().find(|r| r.contains(marker)).cloned()
}

#[test]
fn http_check_send_renders_its_formats_and_reports_the_real_server_state() {
    let (p1, seen1) = capture("200 OK");
    let (p2, seen2) = capture("200 OK");
    let (p3, seen3) = capture("503 Service Unavailable");
    let dead = common::reserve_addr();
    let fe = common::reserve_addr();
    let ck = "check inter 100 rise 1 fall 1";
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe}\n  default_backend be1\n\
         backend be1\n  option httpchk\n  http-check send-state\n  \
         unique-id-format U-%[be_name]-%[srv_is_up(s2),iif(up,down)]-%[nbsrv]\n  \
         http-check send meth GET uri /plain%[be_name] ver HTTP/1.1 hdr host localhost hdr x-id %[unique-id] \
         hdr x-empty %[str()] hdr x-lit literal hdr x-srv %[srv_name] body \"b%[be_name]\"\n  \
         server s1 {p1} {ck}\n  server s2 {dead} {ck} weight 3\n\
         backend be2\n  option httpchk\n  \
         http-check send meth POST uri-lf /lf%[be_name]/%[srv_name] ver HTTP/1.1 body-lf \"B%[srv_name]\"\n  \
         server t1 {p2} {ck}\n\
         backend be3\n  option httpchk\n  http-check send-state\n  http-check send meth GET uri / ver HTTP/1.1\n  \
         server d1 {p3} {ck}\n  server d2 {p1} {ck} backup weight 7\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let until = Instant::now() + Duration::from_millis(1200);
    while Instant::now() < until {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let node = hostname();
    let (a1, a3) = (p1.port(), p3.port());

    assert_eq!(
        last_with(&seen1, "/plain").as_deref(),
        Some(format!(
            "GET /plain%[be_name] HTTP/1.1\r\nhost: localhost\r\nx-id: U-be1-down-1\r\nx-lit: literal\r\nx-srv: s1\r\n\
             x-haproxy-server-state: UP; address=127.0.0.1; port={a1}; name=be1/s1; node={node}; weight=1/1; scur=0/0; qcur=0\r\n\
             content-length: 11\r\nconnection: close\r\n\r\nb%[be_name]"
        ).as_str()),
        "be1/s1's check request: the hdr values must be rendered for be1 and s1 (the unique ID from be1's \
         unique-id-format, with s2 DOWN), uri and body are literal, the empty header is dropped"
    );
    assert_eq!(
        last_with(&seen2, "POST").as_deref(),
        Some("POST /lfbe2/t1 HTTP/1.1\r\ncontent-length: 3\r\nconnection: close\r\n\r\nBt1"),
        "uri-lf and body-lf are log-formats"
    );
    assert_eq!(
        last_with(&seen3, "name=be3/d1").as_deref(),
        Some(format!(
            "GET / HTTP/1.1\r\nx-haproxy-server-state: DOWN; address=127.0.0.1; port={a3}; name=be3/d1; node={node}; \
             weight=1/7; scur=0/0; qcur=0\r\nconnection: close\r\n\r\n"
        ).as_str()),
        "send-state for a server its check found DOWN"
    );
    assert_eq!(
        last_with(&seen1, "name=be3/d2").as_deref(),
        Some(format!(
            "GET / HTTP/1.1\r\nx-haproxy-server-state: UP; address=127.0.0.1; port={a1}; name=be3/d2; node={node}; \
             weight=7/7; scur=0/0; qcur=0\r\nconnection: close\r\n\r\n"
        ).as_str()),
        "send-state for the backup that took over"
    );
}
