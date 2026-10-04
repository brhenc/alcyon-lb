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
fn hmac_takes_a_base64_literal_or_a_variable_as_key() {
    let rules = "  http-request set-var(txn.hash) req.hdr(hash)\n\
  http-request set-var(txn.key) str(my_super_secret_long_key),base64\n\
  http-request return status 200 hdr x-s1s \"%[var(txn.hash),hmac(sha1,a2V5),hex,lower]\" \
hdr x-s1l \"%[var(txn.hash),hmac(sha1,txn.key),hex,lower]\" \
hdr x-s2s \"%[var(txn.hash),hmac(sha256,a2V5),hex,lower]\" \
hdr x-s2l \"%[var(txn.hash),hmac(sha256,txn.key),hex,lower]\" \
hdr x-m5 \"%[var(txn.hash),hmac(md5,a2V5),hex,lower]\" \
hdr x-s5 \"%[var(txn.hash),hmac(sha512,a2V5),hex,lower]\" \
hdr x-s3 \"%[var(txn.hash),hmac(sha384,txn.key),hex,lower]\" \
hdr x-s224 \"%[var(txn.hash),hmac(sha224,a2V5),hex,lower]\" \
hdr x-un \"[%[var(txn.hash),hmac(sha1,txn.nokey),hex,lower]]\"\n";
    let req = "GET / HTTP/1.1\r\nHost: x\r\nHash: 1\r\nConnection: close\r\n\r\n";
    assert_eq!(
        run(rules, &[req]),
        vec![vec![
            "x-s1s: e23feb105f9622241bf23db1638cd2b4208b1f53",
            "x-s1l: 87b10ddcf39e26f6bd7c3b0e38e0125997b255be",
            "x-s2s: 6da91fb91517be1f5cdcf3af91d7d40c717dd638a306157606fb2e584f7ae926",
            "x-s2l: 2fb3de6a462c54d1803f946b52202f3a8cd46548ffb3f789b4ac11a4361ffef2",
            "x-m5: 4af35dc1cd7f387546377a4f2b548d0c",
            "x-s5: 54816905e95d0a740369d5fb40cc37ce13761d9f56e897508590faf2306152093147409290592b6aeddc694b2de4a816526be399e7bf50a971a1537df831ca4a",
            "x-s3: 405a393d4c05b3cbcded664ffa0cd6c069469188bac89d1ae9d33460554f95a6384c6b19e32fc940f3cf722351e93ccb",
            "x-s224: 2951c9326afebb8a223109f8e6d55ba654e52109c335170395b7c97d",
            "x-un: []",
        ]]
    );
}

#[test]
fn param_finds_a_name_anywhere_in_the_query_with_a_char_or_hex_separator() {
    let rules = "  http-request set-var(txn.query) query\n\
  http-request set-var(txn.a) var(txn.query),param(test)\n\
  http-request set-var(txn.b) var(txn.query),param(test,0x26)\n\
  http-request set-var(txn.c) var(txn.query),param(test,;)\n\
  http-request set-var(txn.d) var(txn.query),param(test,0x3b)\n\
  http-request return status 200 hdr x-q \"[%[var(txn.query)]]\" hdr x-a \"[%[var(txn.a)]]\" if { var(txn.a) -m found }\n\
  http-request return status 200 hdr x-q \"[%[var(txn.query)]]\" hdr x-na y hdr x-b \"[%[var(txn.b)]]\" hdr x-c \"[%[var(txn.c)]]\" hdr x-d \"[%[var(txn.d)]]\"\n";
    let reqs: Vec<String> = [
        "/foo/?test=1&b=4&d",
        "/?a=1&b=4&test=34",
        "/?a=b&c=d",
        "/?a=b&test&c=d",
        "/?test=",
        "/?testing=123&test=4",
        "/?a=1;test=5&b=2",
        "/?a=1;test=5&test=7",
    ]
    .iter()
    .map(|p| get(p))
    .collect();
    let reqs: Vec<&str> = reqs.iter().map(String::as_str).collect();
    assert_eq!(
        run(rules, &reqs),
        vec![
            vec!["x-q: [test=1&b=4&d]", "x-a: [1]"],
            vec!["x-q: [a=1&b=4&test=34]", "x-a: [34]"],
            vec!["x-q: [a=b&c=d]", "x-na: y", "x-b: []", "x-c: []", "x-d: []"],
            vec!["x-q: [a=b&test&c=d]", "x-a: []"],
            vec!["x-q: [test=]", "x-a: []"],
            vec!["x-q: [testing=123&test=4]", "x-a: [4]"],
            vec!["x-q: [a=1;test=5&b=2]", "x-na: y", "x-b: []", "x-c: [5&b=2]", "x-d: [5&b=2]"],
            vec!["x-q: [a=1;test=5&test=7]", "x-a: [7]"],
        ]
    );
}

/// `reg-tests/converter/reverse_dom.vtc`, expectations as `HAProxy` meets them.
#[test]
fn reverse_dom_route_is_unset_when_the_host_has_no_reverse() {
    let map = std::env::temp_dir().join(format!("ibex-reverse-dom-{}.map", std::process::id()));
    std::fs::write(&map, "com.example. example\ncom.example.mail. mail\n").expect("map");
    let rules = format!(
        "  http-request set-var(txn.rev_const) str(MaIl.EXAMPLE.com),reverse_dom\n\
  http-request set-var(txn.rev_host) req.hdr(Host),host_only,reverse_dom if {{ req.hdr(Host) -m found }}\n\
  http-request set-var(txn.rev_host_dot) var(txn.rev_host),concat(.) if {{ var(txn.rev_host) -m found }}\n\
  http-request set-var(txn.route) var(txn.rev_host_dot),map_beg({},miss) if {{ var(txn.rev_host_dot) -m found }}\n\
  http-request set-var(txn.sub_only) str(no)\n\
  http-request set-var(txn.sub_only) str(yes) if {{ var(txn.rev_host) -m beg com.example. }}\n\
  http-request return status 200 hdr X-Rev-Const \"%[var(txn.rev_const)]\" hdr X-Rev-Host \"%[var(txn.rev_host)]\" hdr X-Route \"%[var(txn.route)]\" hdr X-Sub-Only \"%[var(txn.sub_only)]\"\n",
        map.display()
    );
    let reqs: Vec<String> = ["example.com", "mail.example.com", "example.com.", "localhost", "badexample.com", "foo..bar", ".example.com", "."]
        .iter()
        .map(|h| format!("GET / HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n\r\n"))
        .collect();
    let reqs: Vec<&str> = reqs.iter().map(String::as_str).collect();
    let got = run(&rules, &reqs);
    let _ = std::fs::remove_file(&map);
    let cst = "X-Rev-Const: com.EXAMPLE.MaIl";
    assert_eq!(
        got,
        vec![
            vec![cst, "X-Rev-Host: com.example", "X-Route: example", "X-Sub-Only: no"],
            vec![cst, "X-Rev-Host: com.example.mail", "X-Route: mail", "X-Sub-Only: yes"],
            vec![cst, "X-Rev-Host: com.example", "X-Route: example", "X-Sub-Only: no"],
            vec![cst, "X-Rev-Host: localhost", "X-Route: miss", "X-Sub-Only: no"],
            vec![cst, "X-Rev-Host: com.badexample", "X-Route: miss", "X-Sub-Only: no"],
            vec![cst, "X-Sub-Only: no"],
            vec![cst, "X-Sub-Only: no"],
            vec![cst, "X-Sub-Only: no"],
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
