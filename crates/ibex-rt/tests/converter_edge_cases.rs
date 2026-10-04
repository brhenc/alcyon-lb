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

/// `reg-tests/converter/secure_memcmp.vtc`, the text form (frontend `fe`). The binary form
/// (`fe2`, a `b64dec` value kept in a variable) needs variables that hold bytes; they hold
/// `String`s (T136 report).
#[test]
fn secure_memcmp_compares_against_a_variable() {
    let pair = |raw: &str, hash: &str| format!("GET / HTTP/1.1\r\nHost: x\r\nRaw: {raw}\r\nHash: {hash}\r\nConnection: close\r\n\r\n");
    let text = "  http-request set-var(txn.hash) req.hdr(hash)\n\
  http-request set-var(txn.raw) req.hdr(raw)\n\
  acl is_match var(txn.raw),sha1,base64,secure_memcmp(txn.hash)\n\
  http-request return status 200 hdr x-match true if is_match\n\
  http-request return status 200 hdr x-match false\n";
    let t = [("1", "NWoZK3kTsExUV00Ywo1G5jlUKKs="), ("2", "2kuSN7rMzfGcB2DKt67EqDWQELA="), ("2", "2kuSN7rMzfGcB2DKt67EqDWQELX="), ("3", "2kuSN7rMzfGcB2DKt67EqDWQELA=")];
    let reqs: Vec<String> = t.iter().map(|(r, h)| pair(r, h)).collect();
    let reqs: Vec<&str> = reqs.iter().map(String::as_str).collect();
    assert_eq!(run(text, &reqs), ["true", "true", "false", "false"].map(|v| vec![format!("x-match: {v}")]));
}

/// `reg-tests/converter/time.vtc`: utime/ltime in s, ms and us, offsets in the input unit,
/// `%N`, `%3N`, `%6N`, and http_date's ms/us units.
#[test]
fn date_converters_handle_units_offsets_and_fractions() {
    let h = |name: &str, expr: &str| format!("  http-after-response set-header x-{name} \"%[{expr}]\"\n");
    let mut rules = String::from("  http-request return status 200\n");
    for (n, e) in [
        ("utime", "int(1000000000),utime(%Y-%m-%dT%H:%M:%S)"),
        ("utime-p", "int(1000000000),utime(%Y-%m-%dT%H:%M:%S,60)"),
        ("utime-n", "int(1000000000),utime(%Y-%m-%dT%H:%M:%S,-100)"),
        ("msu", "int(1234567890123),ms_utime(%Y-%m-%dT%H:%M:%S.%3N)"),
        ("msu-6", "int(1234567890123),ms_utime(%6N)"),
        ("msu-9", "int(1234567890123),ms_utime(%N)"),
        ("msu-p", "int(1234567890123),ms_utime(%H:%M:%S.%3N,877)"),
        ("usu", "int(1234567890123456),us_utime(%Y-%m-%dT%H:%M:%S.%6N)"),
        ("usu-3", "int(1234567890123456),us_utime(%3N)"),
        ("usu-9", "int(1234567890123456),us_utime(%N)"),
        ("usu-n", "int(1234567890123456),us_utime(%H:%M:%S.%6N,-123456)"),
        ("msl", "int(1234567890123),ms_ltime(%S.%3N)"),
        ("usl", "int(1234567890123456),us_ltime(%S.%6N)"),
        ("hdate", "int(1000000000),http_date"),
        ("hdate-o", "int(1000000000),http_date(3600)"),
        ("hdate-ms", "int(1000000000123),http_date(0,ms)"),
        ("hdate-us", "int(1000000000123456),http_date(0,us)"),
        ("hdate-mo", "int(1000000000123),http_date(-1000,ms)"),
        ("hdate-pd", "int(1000000000023),http_date(0,ms)"),
        ("hdate-pu", "int(1000000000000023),http_date(0,us)"),
        ("acc-s", "accept_date"),
        ("acc-ms", "accept_date(ms),div(1000)"),
        ("acc-us", "accept_date(us),div(1000000)"),
        ("date-s", "date"),
        ("date-ms", "date(0,ms),div(1000)"),
        ("date-us", "date(0,us),div(1000000)"),
    ] {
        rules.push_str(&h(n, e));
    }
    let got = run(&rules, &[&get("/")]);
    let hdrs: std::collections::HashMap<String, String> = got[0]
        .iter()
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_ascii_lowercase().trim_start_matches("x-").to_string(), v.to_string()))
        .collect();
    let want = [
        ("utime", "2001-09-09T01:46:40"),
        ("utime-p", "2001-09-09T01:47:40"),
        ("utime-n", "2001-09-09T01:45:00"),
        ("msu", "2009-02-13T23:31:30.123"),
        ("msu-6", "123000"),
        ("msu-9", "123000000"),
        ("msu-p", "23:31:31.000"),
        ("usu", "2009-02-13T23:31:30.123456"),
        ("usu-3", "123"),
        ("usu-9", "123456000"),
        ("usu-n", "23:31:30.000000"),
        ("msl", "30.123"),
        ("usl", "30.123456"),
        ("hdate", "Sun, 09 Sep 2001 01:46:40 GMT"),
        ("hdate-o", "Sun, 09 Sep 2001 02:46:40 GMT"),
        ("hdate-ms", "Sun, 09 Sep 2001 01:46:40.123 GMT"),
        ("hdate-us", "Sun, 09 Sep 2001 01:46:40.123456 GMT"),
        ("hdate-mo", "Sun, 09 Sep 2001 01:46:39.123 GMT"),
        ("hdate-pd", "Sun, 09 Sep 2001 01:46:40.023 GMT"),
        ("hdate-pu", "Sun, 09 Sep 2001 01:46:40.000023 GMT"),
    ];
    for (k, v) in want {
        assert_eq!(hdrs.get(k).map(String::as_str), Some(v), "header {k}");
    }
    assert_eq!(hdrs.get("acc-ms"), hdrs.get("acc-s"));
    assert_eq!(hdrs.get("acc-us"), hdrs.get("acc-s"));
    assert_eq!(hdrs.get("date-ms"), hdrs.get("date-s"));
    assert_eq!(hdrs.get("date-us"), hdrs.get("date-s"));
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
