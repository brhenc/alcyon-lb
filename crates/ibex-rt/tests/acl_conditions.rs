// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! How a rule's condition combines its ACLs, as `HAProxy` (3.5-dev8-885761-29) answered
//! the same configuration, measured 2026-10-03 with curl: terms side by side must all hold,
//! `||` or `or` separates alternatives, and `!` negates the term after it, attached or
//! not (`build_acl_cond`, `acl_exec_cond` in `src/acl.c`).

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::Engine;

const CFG: &str = "defaults
  mode http
  timeout connect 1s
  timeout client 5s
  timeout server 5s
frontend fe
  bind @FE@
  acl is_n path_beg /n
  http-request return status 201 if { path /a } || { path /b }
  http-request return status 202 if ! { path /nc } is_n
  http-request return status 203 if { path /x } or { path /y }
  http-request return status 205 unless { path_beg /z } || ! is_n
  http-request return status 204
";

#[test]
fn conditions_combine_their_acls_as_haproxy_does() {
    let fe = common::reserve_addr();
    let config = ibex_config::parse_str(&CFG.replace("@FE@", &fe.to_string())).expect("parse");
    let mut engine = Engine::new(&config, 64).expect("Engine::new");
    let paths = ["a", "b", "n", "nc", "x", "y", "c"];
    let client = thread::spawn(move || {
        paths
            .iter()
            .map(|p| {
                let mut s = TcpStream::connect(fe).expect("connect");
                s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
                write!(s, "GET /{p} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
                let mut out = String::new();
                let _ = s.read_to_string(&mut out);
                format!("{p}={}", out.get(9..12).unwrap_or("---"))
            })
            .collect::<Vec<_>>()
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let got = client.join().expect("client");
    assert_eq!(got, ["a=201", "b=201", "n=202", "nc=205", "x=203", "y=203", "c=204"]);
}

/// `HAProxy`'s predefined ACLs (`default_acl_list`, `src/acl.c`), as it answered this
/// configuration (measured 2026-10-03, 3.5-dev8-885761-29).
#[test]
fn the_predefined_acls_mean_what_haproxy_defines() {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n  \
         http-request return status 201 if {{ path /t }} TRUE\n  \
         http-request return status 202 if {{ path /f }} FALSE\n  \
         http-request return status 205 if {{ path /g }} METH_GET LOCALHOST HTTP_1.1 HTTP_URL_SLASH\n  \
         http-request return status 206 if {{ path /p }} METH_POST\n  \
         http-request return status 207 if {{ path /c }} HTTP_CONTENT\n  \
         http-request return status 204\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let reqs = [
        ("t", "GET /t HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
        ("f", "GET /f HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
        ("g", "GET /g HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
        ("p", "GET /p HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
        ("postp", "POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx"),
        ("c", "POST /c HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\nxy"),
    ];
    let client = thread::spawn(move || {
        reqs.iter()
            .map(|(k, r)| {
                let mut s = TcpStream::connect(fe).expect("connect");
                s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
                s.write_all(r.as_bytes()).expect("send");
                let mut out = String::new();
                let _ = s.read_to_string(&mut out);
                format!("{k}={}", out.get(9..12).unwrap_or("---"))
            })
            .collect::<Vec<_>>()
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let got = client.join().expect("client");
    assert_eq!(got, ["t=201", "f=204", "g=205", "p=204", "postp=206", "c=207"]);
}
