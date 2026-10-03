// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The string-to-integer cast on the data path: an arithmetic converter, integer matching,
//! `set-dst-port` and `set-retries`, each given a header value that is not a clean
//! integer.
//!
//! `HAProxy` casts with `c_str2int` (`src/sample.c`), which reads an optional sign and the
//! leading digits and ignores the rest (`read_int64`, `src/tools.c`), saturating out of
//! range; only an empty string fails the cast. So `abc` is 0 and `12abc` is 12.
//!
//! Every expected value below was measured against `HAProxy` 3.5-dev8-885761-29,
//! 2026-10-03, with this same configuration (curl, one request per value; `EMPTY` is a
//! header with an empty value, `NONE` no header at all):
//!
//! ```text
//! /add  abc 1 | 12abc 13 | EMPTY - | +5 6 | -3x -2 | - 1 | 7 8 | 0x10 1 | NONE -
//!       99999999999999999999 9223372036854775807 | -99999999999999999999 -9223372036854775807
//! /eq0  (-m int 0)    matches abc, -, 0x10; not 12abc, EMPTY, +5, -3x, 7, NONE, ±999..
//! /gt5  (-m int gt 5) matches 12abc, 7, 999..; not abc, EMPTY, +5, -3x, -, 0x10, NONE
//! /port (set-dst-port, then %[dst_port]) abc (port 0: dst_port fails) | 12abc 12 |
//!       EMPTY unchanged | +5 5 | -3x 65533 | - (0) | 7 7 | 999.. 65535 | -999.. (0) |
//!       0x10 (0) | NONE unchanged
//! /retr (retries 3, set-retries) abc 0 | 12abc 12 | EMPTY 3 | +5 5 | -3x 3 | - 0 | 7 7 |
//!       ±999.. 3 | 0x10 0 | NONE 3
//! /noport (server without a port) <origin port>abc -> origin | abc -> 503
//! ```

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::Engine;

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

/// Starts an engine on `cfg` (`@FE@` replaced by the frontend address), sends each
/// `(path, header lines)` on its own connection and returns `(status line, body)` for each.
fn exchange(cfg: &str, reqs: &[(String, String)]) -> Vec<(String, String)> {
    let fe = common::reserve_addr();
    let config = ibex_config::parse_str(&cfg.replace("@FE@", &fe.to_string())).expect("parse");
    let mut engine = Engine::new(&config, 64).expect("Engine::new");
    let reqs = reqs.to_vec();
    let client = thread::spawn(move || {
        reqs.iter()
            .map(|(path, hdrs)| {
                let mut s = TcpStream::connect(fe).expect("connect");
                s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
                write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{hdrs}\r\n").expect("send");
                let mut out = Vec::new();
                let _ = s.read_to_end(&mut out);
                let text = String::from_utf8_lossy(&out).into_owned();
                let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
                (head.lines().next().unwrap_or("").to_string(), body.trim_end().to_string())
            })
            .collect::<Vec<_>>()
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    client.join().expect("client")
}

const CFG: &str = "defaults\n  mode http\n  timeout connect 50ms\n  timeout client 5s\n  timeout server 5s\n\
frontend fe\n  bind @FE@\n  \
http-request return status 200 content-type text/plain lf-string \"add=[%[req.hdr(x-n),add(1)]]\" if { path /add }\n  \
http-request return status 200 content-type text/plain string \"eq0\" if { path /eq0 } { req.hdr(x-n) -m int 0 }\n  \
http-request return status 200 content-type text/plain string \"no\" if { path /eq0 }\n  \
http-request return status 200 content-type text/plain string \"gt5\" if { path /gt5 } { req.hdr(x-n) -m int gt 5 }\n  \
http-request return status 200 content-type text/plain string \"no\" if { path /gt5 }\n  \
http-request set-dst-port hdr(x-n) if { path /port }\n  \
http-request set-dst-port hdr(x-n) if { path /noport }\n  \
http-request return status 200 content-type text/plain lf-string \"port=%[dst_port]\" if { path /port }\n  \
use_backend noport if { path /noport }\n  \
default_backend be\n\
backend be\n  retries 3\n  \
http-request set-retries req.hdr(x-n)\n  \
http-request return status 200 content-type text/plain lf-string \"cur=%[cur_max_retries]\"\n  \
server s @DEAD@\n\
backend noport\n  server s 127.0.0.1\n";

/// The header line for a probe value: `EMPTY` is an empty value, `NONE` no header.
fn header(v: &str) -> String {
    match v {
        "NONE" => String::new(),
        "EMPTY" => "x-n:\r\n".to_string(),
        v => format!("x-n: {v}\r\n"),
    }
}

const BIG: &str = "99999999999999999999";
const NEG_BIG: &str = "-99999999999999999999";

/// Runs `path` once per value and lists every body that differs from `HAProxy`'s.
fn mismatches(path: &str, cases: &[(&str, &str)]) -> Vec<String> {
    let cfg = CFG.replace("@DEAD@", &common::reserve_addr().to_string());
    let reqs: Vec<(String, String)> = cases.iter().map(|&(v, _)| (path.to_string(), header(v))).collect();
    let got = exchange(&cfg, &reqs);
    // `@NONE@` stands for whatever this run answered with no header at all.
    let none = cases.iter().zip(&got).find(|((v, _), _)| *v == "NONE").map(|(_, (_, b))| b.clone());
    cases
        .iter()
        .map(|&(v, want)| (v, if want == "@NONE@" { none.clone().expect("a NONE case") } else { want.to_string() }))
        .zip(&got)
        .filter(|((_, want), (_, body))| body != want)
        .map(|((v, want), (status, body))| format!("{path} x-n={v:?}: HAProxy {want:?}, Ibex {body:?} ({status})"))
        .collect()
}

#[test]
fn an_arithmetic_converter_casts_a_string_as_haproxy_does() {
    let wrong = mismatches(
        "/add",
        &[
            ("abc", "add=[1]"),
            ("12abc", "add=[13]"),
            ("EMPTY", "add=[]"),
            ("+5", "add=[6]"),
            ("-3x", "add=[-2]"),
            ("-", "add=[1]"),
            ("7", "add=[8]"),
            ("0x10", "add=[1]"),
            (BIG, "add=[9223372036854775807]"),
            (NEG_BIG, "add=[-9223372036854775807]"),
            ("NONE", "add=[]"),
        ],
    );
    assert!(wrong.is_empty(), "`add` over a string header:\n{}", wrong.join("\n"));
}

#[test]
fn integer_matching_casts_a_string_as_haproxy_does() {
    let mut wrong = mismatches(
        "/eq0",
        &[
            ("abc", "eq0"),
            ("-", "eq0"),
            ("0x10", "eq0"),
            ("12abc", "no"),
            ("EMPTY", "no"),
            ("+5", "no"),
            ("-3x", "no"),
            ("7", "no"),
            (BIG, "no"),
            (NEG_BIG, "no"),
            ("NONE", "no"),
        ],
    );
    wrong.extend(mismatches(
        "/gt5",
        &[
            ("12abc", "gt5"),
            ("7", "gt5"),
            (BIG, "gt5"),
            ("abc", "no"),
            ("EMPTY", "no"),
            ("+5", "no"),
            ("-3x", "no"),
            ("-", "no"),
            (NEG_BIG, "no"),
            ("0x10", "no"),
            ("NONE", "no"),
        ],
    ));
    assert!(wrong.is_empty(), "`-m int` over a string header:\n{}", wrong.join("\n"));
}

#[test]
fn set_dst_port_casts_a_string_as_haproxy_does() {
    let wrong = mismatches(
        "/port",
        &[
            // Port 0: HAProxy's `dst_port` fails on it (`smp_fetch_dport`), so it prints
            // nothing.
            ("abc", "port="),
            ("12abc", "port=12"),
            ("+5", "port=5"),
            ("-3x", "port=65533"),
            ("-", "port="),
            ("7", "port=7"),
            (BIG, "port=65535"),
            (NEG_BIG, "port="),
            ("0x10", "port="),
            // No value: the action does nothing, and the destination is the frontend's.
            ("EMPTY", "@NONE@"),
            ("NONE", "@NONE@"),
        ],
    );
    assert!(wrong.is_empty(), "`set-dst-port hdr(x-n)`:\n{}", wrong.join("\n"));
    // And `@NONE@` itself is a port, not an empty fetch.
    let cfg = CFG.replace("@DEAD@", &common::reserve_addr().to_string());
    let own = exchange(&cfg, &[("/port".to_string(), String::new())]);
    assert!(own[0].1.len() > "port=".len(), "the frontend's own port: {own:?}");
}

#[test]
fn a_port_with_trailing_text_reaches_the_server() {
    let origin = named_backend("origin");
    let cfg = CFG.replace("@DEAD@", &common::reserve_addr().to_string());
    let got = exchange(
        &cfg,
        &[
            ("/noport".to_string(), header(&format!("{}abc", origin.port()))),
            ("/noport".to_string(), header(&origin.port().to_string())),
            ("/noport".to_string(), header("abc")),
        ],
    );
    assert!(
        got[2].0.starts_with("HTTP/1.1 503"),
        "`abc` is port 0, which HAProxy cannot connect to (503); got {:?}",
        got[2]
    );
    assert_eq!(
        got[..2].iter().map(|(_, b)| b.as_str()).collect::<Vec<_>>(),
        ["origin", "origin"],
        "a server without a port should connect to the port `set-dst-port` read from \
         \"{}abc\" as HAProxy does; got {got:?}",
        origin.port()
    );
}

#[test]
fn set_retries_casts_a_string_as_haproxy_does() {
    let wrong = mismatches(
        "/retr",
        &[
            ("abc", "cur=0"),
            ("12abc", "cur=12"),
            ("EMPTY", "cur=3"),
            ("+5", "cur=5"),
            // Out of 0..=100: ignored, the backend's `retries 3` stands.
            ("-3x", "cur=3"),
            ("-", "cur=0"),
            ("7", "cur=7"),
            (BIG, "cur=3"),
            (NEG_BIG, "cur=3"),
            ("0x10", "cur=0"),
            ("NONE", "cur=3"),
        ],
    );
    assert!(wrong.is_empty(), "`set-retries req.hdr(x-n)`:\n{}", wrong.join("\n"));
}
