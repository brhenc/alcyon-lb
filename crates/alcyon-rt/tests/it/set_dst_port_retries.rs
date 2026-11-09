// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `http-request set-dst-port` and `http-request set-retries` on the data path, as the
//! reference `HAProxy` (3.5-dev8-885761-29) behaved with the same configurations,
//! measured 2026-10-03 (curl, and `wretr` from `show stat` for the retries):
//!
//! * `dst` / `dst_port` in HTTP rules are the frontend connection's destination, and
//!   `set-dst-port` rewrites that port: the value is cast to an integer and truncated to 16
//!   bits (`tcp_action_req_set_dst_port`, `src/tcp_act.c`).
//! * A server without a port (or with port 0) connects to the destination port, and one
//!   with no address to the destination address (`SRV_F_MAPPORTS`, `alloc_dst_address`
//!   in `src/backend.c`).
//! * `set-retries` replaces the stream's retry budget; a value outside 0..=100 is ignored;
//!   switching to another backend resets it to that backend's `retries`
//!   (`stream_set_backend`).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use alcyon_rt::Engine;

/// A backend answering every request with `name`, then closing.
fn named_backend(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{name}", name.len());
        }
    });
    addr
}

/// Starts an engine on `cfg` (`@FE@` replaced by the frontend address) and sends it each
/// request in `reqs` (path, extra header lines) on its own connection, returning each
/// response body (or the status line if there is no body).
fn exchange(cfg: &str, reqs: &[(&str, &str)]) -> (Engine, Vec<String>) {
    let fe = common::reserve_addr();
    let config = alcyon_config::parse_str(&cfg.replace("@FE@", &fe.to_string())).expect("parse");
    let mut engine = Engine::new(&config, 64).expect("Engine::new");
    let reqs: Vec<(String, String)> = reqs.iter().map(|&(p, h)| (p.to_string(), h.to_string())).collect();
    let client = thread::spawn(move || {
        reqs.iter()
            .map(|(path, hdrs)| {
                let mut s = TcpStream::connect(fe).expect("connect");
                s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
                write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{hdrs}\r\n").expect("send");
                let mut out = Vec::new();
                let _ = s.read_to_end(&mut out);
                let text = String::from_utf8_lossy(&out).into_owned();
                match text.split_once("\r\n\r\n") {
                    Some((_, body)) if !body.is_empty() => body.trim_end().to_string(),
                    _ => text.lines().next().unwrap_or("").to_string(),
                }
            })
            .collect::<Vec<_>>()
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    (engine, client.join().expect("client"))
}

fn retries(engine: &Engine, proxy: &str) -> u64 {
    let p = engine.proxies.iter().find(|p| p.name.as_str() == proxy).expect("proxy");
    p.stats.iter().map(|s| s.retries_count.load(Ordering::Relaxed)).sum()
}

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 50ms\n  timeout client 5s\n  timeout server 5s\n";

#[test]
fn dst_in_http_rules_is_the_frontend_destination() {
    let cfg = format!(
        "{DEFAULTS}frontend fe\n  bind @FE@\n  \
         http-request return status 200 content-type text/plain lf-string \"%[dst]:%[dst_port]\"\n"
    );
    let fe = cfg.clone();
    let (_, got) = exchange(&fe, &[("/", "")]);
    // The address is only known once bound; compare its shape.
    assert!(got[0].starts_with("127.0.0.1:") && got[0].len() > "127.0.0.1:".len(), "{got:?}");
}

#[test]
fn set_dst_port_rewrites_the_port_as_haproxy_casts_it() {
    let cfg = format!(
        "{DEFAULTS}frontend fe\n  bind @FE@\n  \
         http-request set-dst-port hdr(x-port)\n  \
         http-request return status 200 content-type text/plain lf-string \"%[dst]:%[dst_port] %[fc_dst_port]\"\n"
    );
    let (_, got) = exchange(
        &cfg,
        &[("/", "x-port: 29102\r\n"), ("/", "x-port: 70000\r\n"), ("/", "x-port: -1\r\n"), ("/", "")],
    );
    // `fc_dst_port` is the connection's own and does not move.
    let fc = got[3].split(' ').nth(1).expect("fc_dst_port").to_string();
    assert_eq!(
        got,
        [
            format!("127.0.0.1:29102 {fc}"),
            format!("127.0.0.1:4464 {fc}"),
            format!("127.0.0.1:65535 {fc}"),
            // No header, no value: the destination is left as it was.
            format!("127.0.0.1:{fc} {fc}"),
        ]
    );
}

#[test]
fn a_server_without_a_port_connects_to_the_rewritten_destination() {
    let a = named_backend("a");
    let b = named_backend("b");
    let fixed = named_backend("fixed");
    let cfg = format!(
        "{DEFAULTS}frontend fe\n  bind @FE@\n  \
         http-request set-dst-port hdr(x-port)\n  \
         use_backend any if {{ path /any }}\n  \
         use_backend zero if {{ path /zero }}\n  \
         use_backend noport if {{ path /noport }}\n  \
         default_backend fixed\n\
         backend any\n  server s 0.0.0.0:0\n\
         backend zero\n  server s 127.0.0.1:0\n\
         backend noport\n  server s 127.0.0.1\n\
         backend fixed\n  server s {fixed}\n"
    );
    let (_, got) = exchange(
        &cfg,
        &[
            ("/any", &format!("x-port: {}\r\n", a.port())),
            ("/zero", &format!("x-port: {}\r\n", b.port())),
            ("/noport", &format!("x-port: {}\r\n", a.port())),
            ("/", &format!("x-port: {}\r\n", a.port())),
        ],
    );
    assert_eq!(got, ["a", "b", "a", "fixed"]);
}

#[test]
fn set_retries_replaces_the_retry_budget() {
    let dead = common::reserve_addr();
    let cfg = format!(
        "{DEFAULTS}listen l\n  bind @FE@\n  retries 0\n  \
         http-request set-var(txn.r) req.hdr(x-r)\n  \
         http-request set-retries var(txn.r) if {{ var(txn.r) -m found }}\n  \
         http-request set-retries 2 if {{ path /two }}\n  \
         http-request return status 200 content-type text/plain lf-string \"cur=%[cur_max_retries] be=%[be_max_retries]\" if {{ path /show }}\n  \
         server s {dead}\n"
    );
    let (e, got) = exchange(&cfg, &[("/show", ""), ("/show", "x-r: 7\r\n"), ("/show", "x-r: 101\r\n")]);
    assert_eq!(got, ["cur=0 be=0", "cur=7 be=0", "cur=0 be=0"]);
    assert_eq!(retries(&e, "l"), 0);

    let (e, _) = exchange(&cfg, &[("/two", "")]);
    assert_eq!(retries(&e, "l"), 2, "set-retries 2 over retries 0");
    let (e, _) = exchange(&cfg, &[("/", "x-r: 3\r\n")]);
    assert_eq!(retries(&e, "l"), 3, "set-retries from a variable");
    let (e, _) = exchange(&cfg, &[("/", "x-r: 200\r\n")]);
    assert_eq!(retries(&e, "l"), 0, "a value above 100 is ignored");
}

#[test]
fn switching_backend_resets_the_retry_budget_to_the_new_backend_s() {
    let dead = common::reserve_addr();
    let cfg = format!(
        "{DEFAULTS}listen l\n  bind @FE@\n  retries 0\n  \
         http-request set-retries 1\n  \
         use_backend other if {{ path /other }}\n  \
         server s {dead}\n\
         backend other\n  retries 5\n  server s {dead}\n"
    );
    let (e, _) = exchange(&cfg, &[("/other", ""), ("/", "")]);
    assert_eq!((retries(&e, "l"), retries(&e, "other")), (1, 5));
}

/// Reads one response with a `Content-Length` body from `s`; returns its status line.
fn read_response(s: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            let len = head
                .lines()
                .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("content-length")))
                .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                return head.lines().next().unwrap_or("").to_string();
            }
        }
        match s.read(&mut chunk) {
            Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => return String::from_utf8_lossy(&buf).into_owned(),
        }
    }
}

#[test]
fn each_request_on_a_connection_starts_with_the_full_retry_budget() {
    // HAProxy: two requests on one connection to a dead server, `retries 3`: wretr=6.
    let dead = common::reserve_addr();
    let fe = common::reserve_addr();
    let cfg = format!("{DEFAULTS}listen l\n  bind {fe}\n  retries 3\n  server s {dead}\n");
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let client = thread::spawn(move || {
        let mut s = TcpStream::connect(fe).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        (0..2)
            .map(|_| {
                s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
                read_response(&mut s)
            })
            .collect::<Vec<_>>()
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let got = client.join().expect("client");
    assert!(got.iter().all(|l| l.starts_with("HTTP/1.1 503")), "{got:?}");
    assert_eq!(retries(&engine, "l"), 6);
}
