// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Converter edge cases (T136). Every expected value was measured on `HAProxy`
//! 3.5-dev8-885761-29 with the same rules (`http-request return` with one header per
//! converter), requests as given.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::Engine;

/// Run `rules` in a frontend and send each raw request; return the `x-*` header lines of
/// each response, in order, as `name: value`.
fn run(rules: &str, requests: &[&str]) -> Vec<Vec<String>> {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n{rules}\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let reqs: Vec<String> = requests.iter().map(|r| (*r).to_string()).collect();
    let client = thread::spawn(move || {
        reqs.iter()
            .map(|r| {
                let mut c = TcpStream::connect(fe).expect("connect");
                c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
                c.write_all(r.as_bytes()).expect("send");
                let mut out = String::new();
                let _ = c.read_to_string(&mut out);
                out.lines()
                    .filter(|l| l.to_ascii_lowercase().starts_with("x-"))
                    .map(|l| l.trim_end().to_string())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    client.join().expect("client")
}

fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
}

#[test]
fn field_and_word_past_the_end_are_not_found() {
    let rules = "  http-request set-var(txn.uri) path\n\
  http-request set-var(txn.f) var(txn.uri),field(3,/)\n\
  http-request set-var(txn.w) var(txn.uri),word(3,/)\n\
  http-request return status 200 hdr x-f \"[%[var(txn.f)]]\" hdr x-w \"[%[var(txn.w)]]\" if { var(txn.f) -m found } { var(txn.w) -m found }\n\
  http-request return status 200 hdr x-f \"[%[var(txn.f)]]\" if { var(txn.f) -m found }\n\
  http-request return status 200 hdr x-w \"[%[var(txn.w)]]\" if { var(txn.w) -m found }\n\
  http-request return status 200 hdr x-none y\n";
    let reqs: Vec<String> = ["/foo/bar/baz", "/foo//bar/baz", "/foo", "/a/b/", "/a///"].iter().map(|p| get(p)).collect();
    let reqs: Vec<&str> = reqs.iter().map(String::as_str).collect();
    let got = run(rules, &reqs);
    assert_eq!(
        got,
        vec![
            vec!["x-f: [bar]", "x-w: [baz]"],
            vec!["x-f: []", "x-w: [baz]"],
            vec!["x-none: y"],
            vec!["x-f: [b]"],
            vec!["x-f: []"],
        ]
    );
}

#[test]
fn set_var_with_a_failing_converter_leaves_the_variable_alone() {
    let rules = "  http-request set-var(txn.a) str(one)\n\
  http-request set-var(txn.a) str(x),field(3,/)\n\
  http-request set-var(sess.b) str(one)\n\
  http-request set-var(sess.b) str(x),field(3,/)\n\
  http-request return status 200 hdr x-a \"[%[var(txn.a)]]\" hdr x-b \"[%[var(sess.b)]]\"\n";
    assert_eq!(run(rules, &[&get("/")]), vec![vec!["x-a: [one]", "x-b: [one]"]]);
}
