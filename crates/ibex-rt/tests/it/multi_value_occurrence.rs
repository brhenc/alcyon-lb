// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T337: which occurrence `hdr()`, `fhdr()`, `cook()`, `url_param()` and their `_val` forms
//! give, as a sample and in an ACL.
//!
//! As a sample (`SMP_OPT_ITERATE` unset) `smp_fetch_hdr`/`smp_fetch_fhdr` give the **last**
//! comma value / line unless an occurrence is given (counted in values for `hdr`, in lines for
//! `fhdr`, from the end when negative), `smp_fetch_cookie` the **last** cookie of that name
//! (the first cookie when no name is given), `smp_fetch_url_param` the **first** parameter.
//! In an ACL (`acl_exec_cond` sets `SMP_OPT_ITERATE` and loops while `SMP_F_NOT_LAST`) every
//! value is tried, except for `hdr`/`fhdr` with an explicit occurrence.
//!
//! `url_param(<name>,<delim>,<i>)`: the parameters start after the first `<delim>` (default
//! `?`) in the URI, `&`, `;` and `<delim>` end a parameter, `i` compares the name without case,
//! and no name takes the value after the first `=`. Cookie values keep their quotes and end at
//! a `;` or `,` outside them; a Set-Cookie value holds one cookie.
//!
//! Every row measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-17 with this file's config.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

const REQ_SAMPLES: &[&str] = &[
    "[%[hdr(x)]|%[hdr(x,1)]|%[hdr(x,2)]|%[hdr(x,-1)]|%[hdr(x,-2)]|%[hdr(x,0)]|%[req.hdr(x)]|%[req.fhdr(x)]|%[req.fhdr(x,1)]|%[req.fhdr(x,-1)]|%[hdr_cnt(x)]|%[req.fhdr_cnt(x)]|%[hdr_val(x)]]",
    "[%[cook(a)]|%[cook(b)]|%[cook()]|%[cook_val(a)]|%[req.cook(a)]|%[cook_cnt(a)]|%[req.cook_names]]",
    "[%[url_param(x)]|%[url_param(x,&)]|%[url_param(x,&,i)]|%[url_param(X,,i)]|%[url_param(X)]|%[url_param()]|%[urlp(x,;)]|%[urlp_val(x)]|%[urlp(y)]]",
];
const REQ_ACLS: &[&str] = &[
    "hdr(x) -m str 1",
    "hdr(x) -m str 2",
    "hdr(x) -m str 3",
    "hdr(x) -m str \"1, 2\"",
    "hdr(x) -m sub 2",
    "hdr(x) -m found",
    "hdr(x,1) -m str 2",
    "hdr(x),lower -m str 2",
    "hdr(x) -m int 1",
    "req.fhdr(x) -m str \"1, 2\"",
    "hdr_val(x) -m int 1",
    "cook(a) -m str 1",
    "cook(a) -m int 1",
    "cook(a) -m found",
    "cook_val(a) -m int 1",
    "url_param(x) -m str 2",
    "urlp(x) -m int 2",
    "urlp_val(x) -m int 2",
    "url_param(x,&,i) -m str 1",
];
const RES_SAMPLES: &[&str] = &[
    "[%[res.hdr(x)]|%[res.hdr(x,1)]|%[res.hdr(x,2)]|%[res.hdr(x,-1)]|%[shdr(x)]|%[res.fhdr(x)]|%[res.fhdr(x,1)]|%[res.hdr_cnt(x)]]",
    "[%[res.cook(a)]|%[res.cook(b)]|%[res.cook()]|%[res.cook_val(a)]|%[scook(a)]|%[res.cook_cnt(a)]|%[res.cook_names]]",
];
const RES_ACLS: &[&str] = &[
    "res.hdr(x) -m str 2",
    "res.hdr(x) -m str 3",
    "res.hdr(x) -m found",
    "res.hdr(x,1) -m str 2",
    "res.fhdr(x) -m str \"1, 2\"",
    "shdr(x) -m sub 1",
    "res.cook(a) -m str 1",
    "res.cook(a) -m str 3",
    "res.cook(a) -m int 1",
    "res.cook_val(a) -m int 1",
    "res.cook(a) -m found",
    "res.cook(b) -m found",
    "res.cook() -m str /",
];

/// Each row: the request, and the body the oracle answers (the three sample groups, then one
/// digit per `REQ_ACLS` line).
const REQ_ROWS: &[(&str, &str)] = &[
    (
        "GET /p?x=1&y=5&x=2 HTTP/1.1\r\nHost: h\r\nx: 1, 2\r\nx: 3\r\nCookie: a=1; b=2\r\nCookie: a=3\r\nConnection: close\r\n\r\n",
        "[3|1|2|3|2|3|3|3|1, 2|3|3|2|3][3|2|1|3|3|2|a,b,a][1|2|2|1||1||1|5][1110110111111111110]",
    ),
    // A quoted comma does not split; an empty line is the last (empty) value; a quoted cookie
    // value keeps its quotes and its `;`; a `,` ends a request cookie.
    (
        "GET /p?X=1;x=2&x=3 HTTP/1.1\r\nHost: h\r\nx: \"a,b\", c\r\nx:\r\nCookie: a=\"x;y\"; b=2, a=4\r\nConnection: close\r\n\r\n",
        r#"[|"a,b"|c||c||||"a,b", c||3|2|0][4|2|"x;y"|4|4|2|a,b,a][2|3|3|1|1|1|2|2|][0000010000000101110]"#,
    ),
    (
        "GET /p HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
        "[||||||||||0|0|][|||||0|][||||||||][0000000000000000000]",
    ),
    // Empty values are values; `$a` is skipped.
    (
        "GET /p?&x=&x=1;y HTTP/1.1\r\nHost: h\r\nx: 2\r\nCookie: b=; a=\r\nCookie: $a=9; a=5\r\nConnection: close\r\n\r\n",
        "[2|2||2||2|2|2|2|2|1|1|2][5|||5|5|2|b,a,a][|||||||0|][0100111100000100001]",
    ),
    (
        "GET /p?y=7&x=8 HTTP/1.1\r\nHost: h\r\nx:  2 ,3  \r\nCookie: a = 7 ; b=\"q\\\"r;s\"\r\nConnection: close\r\n\r\n",
        r#"[3|2|3|3|2|3|3|2 ,3|2 ,3|2 ,3|2|1|3][7|"q\"r;s"|7|7|7|1|a,b][8|8|8|8||7||8|7][0110111100000100000]"#,
    ),
    // `?` (the default delimiter) also ends a parameter.
    (
        "GET /p?y&z=9?x=8&x=7 HTTP/1.1\r\nHost: h\r\nx: 1\r\nx: 1\r\nCookie: a=1\r\nCookie: a=1\r\nConnection: close\r\n\r\n",
        "[1|1|1|1|1|1|1|1|1|1|2|2|1][1||1|1|1|2|a,a][8|7|7|8||9||8|][1000010010111110000]",
    ),
];

/// Each row: the headers the server answers with, and the `x-out` the oracle sets.
const RES_ROWS: &[(&str, &str)] = &[
    (
        "x: 1, 2\r\nx: 3\r\nSet-Cookie: a=1; Path=/\r\nSet-Cookie: b=2\r\nSet-Cookie: a=3\r\n",
        "[3|1|2|3|3|3|1, 2|3][3|2|1|3|3|2|a,b,a][1110111111111]",
    ),
    // T341: a quoted Set-Cookie value is one value, `;` inside it included.
    (
        "Set-Cookie: a=\"x\\\"y;z\"; b=2\r\nx: \"a,b\", c\r\n",
        r#"[c|"a,b"|c|c|c|"a,b", c|"a,b", c|2]["x\"y;z"||"x\"y;z"|0|"x\"y;z"|1|a][0010000000100]"#,
    ),
    // A comma splits a Set-Cookie; only the first non-`$` attribute is the cookie.
    (
        "Set-Cookie: a=1, a=2\r\nSet-Cookie: $v=1; a=4; b=5\r\n",
        "[|||||||0][4||1|4|4|3|a,a][0000001011100]",
    ),
    ("", "[|||||||0][|||||0|][0000000000000]"),
    (
        "Set-Cookie: a=5; Expires=Wed, 21 Oct 2026 07:28:00 GMT\r\nSet-Cookie: c=\r\nx: 1\r\nx: 1\r\n",
        "[1|1|1|1|1|1|1|2][5||5|5|5|1|a,c][0010010000100]",
    ),
    // A Set-Cookie value is searched again after the cookie found, so `a=2` is found too, and
    // with no name `Path=/` gives `/` to the ACL.
    ("Set-Cookie: a=1; a=2\r\nSet-Cookie: s=1; Path=/\r\n", "[|||||||0][2||1|2|2|1|a,s][0000001011101]"),
];

fn config(fq: SocketAddr, fr: SocketAddr, be: SocketAddr) -> String {
    use std::fmt::Write as _;
    let mut c = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\nfrontend fq\n  bind {fq}\n"
    );
    let mut bits = String::new();
    for (i, a) in REQ_ACLS.iter().enumerate() {
        let _ = write!(c, "  http-request set-var(txn.a{i}) str(0)\n  http-request set-var(txn.a{i}) str(1) if {{ {a} }}\n");
        let _ = write!(bits, "%[var(txn.a{i})]");
    }
    let _ = writeln!(c, "  http-request return status 200 content-type text/plain lf-string \"{}[{bits}]\"", REQ_SAMPLES.concat());
    let _ = write!(c, "frontend fr\n  bind {fr}\n  default_backend b\n");
    bits.clear();
    for (i, a) in RES_ACLS.iter().enumerate() {
        let _ = write!(c, "  http-response set-var(txn.r{i}) str(0)\n  http-response set-var(txn.r{i}) str(1) if {{ {a} }}\n");
        let _ = write!(bits, "%[var(txn.r{i})]");
    }
    let _ = write!(c, "  http-response set-header x-out \"{}[{bits}]\"\nbackend b\n  server s {be}\n", RES_SAMPLES.concat());
    c
}

/// A server that answers `GET /<i>` with `RES_ROWS[i]`'s headers, then closes.
fn backend() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
            let (mut head, mut b) = (Vec::new(), [0u8; 4096]);
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&b[..n]),
                }
            }
            let head = String::from_utf8_lossy(&head);
            let i: usize = head.split(' ').nth(1).and_then(|p| p.trim_start_matches('/').parse().ok()).unwrap_or(0);
            let hdrs = RES_ROWS.get(i).map_or("", |r| r.0);
            let _ = c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n{hdrs}\r\nok").as_bytes());
        }
    });
    addr
}

fn get(addr: SocketAddr, req: &str) -> String {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn occurrence_as_sample_and_every_value_in_acls() {
    let (fq, fr, be) = (common::reserve_addr(), common::reserve_addr(), backend());
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    f.write_all(config(fq, fr, be).as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    assert!(common::wait_listening(fq) && common::wait_listening(fr), "ibex did not listen");

    let mut bad = Vec::new();
    for (req, want) in REQ_ROWS {
        let out = get(fq, req);
        let body = out.split_once("\r\n\r\n").map_or("", |(_, b)| b);
        if body != *want {
            bad.push(format!("{req:?}\n   got  {body}\n   want {want}"));
        }
    }
    for (i, (hdrs, want)) in RES_ROWS.iter().enumerate() {
        let out = get(fr, &format!("GET /{i} HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n"));
        let head = out.split("\r\n\r\n").next().unwrap_or("");
        let got = head
            .lines()
            .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("x-out")).map(|(_, v)| v.trim()))
            .unwrap_or("<none>");
        if got != *want {
            bad.push(format!("{hdrs:?}\n   got  {got}\n   want {want}"));
        }
    }
    common::stop(&mut child);
    assert!(bad.is_empty(), "{} rows differ from the oracle:\n{}", bad.len(), bad.join("\n"));
}
