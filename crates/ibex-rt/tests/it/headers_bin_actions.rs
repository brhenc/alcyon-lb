// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T382: `add-headers-bin`, `set-headers-bin` and `del-headers-bin` in `http-request`,
//! `http-response` and `http-after-response`. Every expected value was measured on
//! `HAProxy 3.5-dev8-885761-29` on 2026-10-18 (`src/http_act.c`), including what a truncated
//! or unterminated list does: a list cut inside an entry fails the rewrite (a 500, or nothing
//! done with `strict-mode off`), a list that ends with no terminator is a 500 whatever the
//! mode, and a list whose first length is 0 ends there (`del`) or needs a second 0 (`set`/`add`).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Ibex(Child, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> Ibex {
    let dir = std::env::temp_dir().join(format!("qh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg.replace("{sock}", &sock)).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let ibex = Ibex(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "ibex did not listen on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while UnixStream::connect(&sock).is_err() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    ibex
}

fn get(addr: SocketAddr, req: &[u8]) -> String {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// A server that answers every request with a fixed response carrying four `x-` headers.
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
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nx-a: 1\r\nx-b: 2\r\nX-C: 3\r\nx-a: 4\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody");
        }
    });
    addr
}

fn hex(entries: &[&str], terminated: bool) -> String {
    let mut s = String::new();
    for e in entries {
        s.push_str(&format!("{:02x}", e.len()));
        for b in e.bytes() {
            s.push_str(&format!("{b:02x}"));
        }
    }
    if terminated {
        s.push_str("0000");
    }
    s
}

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n";

fn rules_extra(rules: &mut String) {
    for (path, expr) in [("strlist", "str(abc)"), ("intlist", "int(5)"), ("nofetch", "req.hdr(x-absent)")] {
        rules.push_str(&format!("  http-request set-headers-bin {expr} if {{ path_end /{path} }}\n"));
    }
}

/// The rule lines the request side is tested with: each is selected by the path.
fn req_cfg(addr: SocketAddr) -> String {
    let h = |e: &[&str], t| hex(e, t);
    let mut rules = String::new();
    let mut rule = |path: &str, act: &str, bin: String, tail: &str| {
        rules.push_str(&format!("  http-request {act} bin({bin}){tail} if {{ path_end /{path} }}\n"));
    };
    rule("set", "set-headers-bin", h(&["x-a", "x"], true), "");
    rule("setup", "set-headers-bin", h(&["X-A", "v"], true), "");
    rule("add", "add-headers-bin", h(&["x-a", "x"], true), "");
    rule("nomatch", "set-headers-bin", h(&["x-a", "x"], true), " prefix zz");
    rule("pfxcase", "set-headers-bin", h(&["x-a", "x"], true), " prefix X-");
    rule("pfxmatch", "add-headers-bin", h(&["x-a", "x", "y-a", "y"], true), " prefix x-");
    rule("imm", "set-headers-bin", h(&["Connection", "x", "host-other", "y", "Content-Length", "5", "x-ok", "1", "Expect", "z"], true), "");
    rule("trunc", "set-headers-bin", "03782d6105".into(), "");
    rule("noterm", "set-headers-bin", "03782d610178".into(), "");
    rule("zero", "set-headers-bin", "00".into(), "");
    rule("zero2", "set-headers-bin", "000000".into(), "");
    rule("zero3", "set-headers-bin", "00000001".into(), "");
    rule("goodthentrunc", "set-headers-bin", "03782d6101780378".into(), "");
    rule("del", "del-headers-bin", h(&["X-A"], false) + "00", "");
    rule("delbeg", "del-headers-bin", h(&["x-"], false) + "00", " -m beg");
    rule("delbegcase", "del-headers-bin", h(&["X-"], false) + "00", " -m beg");
    rule("delend", "del-headers-bin", h(&["b"], false) + "00", " -m end");
    rule("delsub", "del-headers-bin", h(&["-"], false) + "00", " -m sub");
    rule("delimm", "del-headers-bin", h(&["Connection", "Content-Length", "x-ok"], false) + "00", "");
    rule("delzero", "del-headers-bin", "00".into(), "");
    rule("deltrunc", "del-headers-bin", "09782d61".into(), "");
    rule("delnoterm", "del-headers-bin", "03782d61".into(), "");
    rule("delendnoterm", "del-headers-bin", "0161".into(), " -m end");
    // Lists that are not `bin(...)`: a string (cut inside its first entry), an integer, and a
    // fetch that gives nothing (the rule changes nothing). Measured on the same oracle.
    rules_extra(&mut rules);
    format!(
        "global\n  stats socket {{sock}} level admin\n{DEFAULTS}frontend fe\n  bind {addr}\n  http-request strict-mode off if {{ path_beg /soft }}\n{rules}  http-request return status 200 content-type text/plain lf-string \"%[req.hdrs]\"\n"
    )
}

/// The headers the request carried when the rules were done, less `host` and `connection`.
fn seen(addr: SocketAddr, path: &str) -> Result<Vec<String>, String> {
    let r = get(addr, format!("GET {path} HTTP/1.1\r\nHost: a\r\nx-a: 1\r\nX-a: 9\r\nx-b: 2\r\nExpect: z\r\nConnection: close\r\n\r\n").as_bytes());
    let (head, body) = r.split_once("\r\n\r\n").unwrap_or_else(|| panic!("no answer: {r:?}"));
    if !head.starts_with("HTTP/1.1 200") {
        return Err(head.lines().next().unwrap_or("").to_string());
    }
    Ok(body.lines().filter(|l| !l.is_empty() && !l.starts_with("host: ") && !l.starts_with("connection: ")).map(str::to_string).collect())
}

fn ok(addr: SocketAddr, path: &str, want: &[&str]) {
    assert_eq!(seen(addr, path), Ok(want.iter().map(|s| (*s).to_string()).collect()), "{path}");
}

fn err500(addr: SocketAddr, path: &str) {
    assert_eq!(seen(addr, path), Err("HTTP/1.1 500 Internal Server Error".to_string()), "{path}");
}

const ALL: [&str; 4] = ["x-a: 1", "x-a: 9", "x-b: 2", "expect: z"];

#[test]
fn request_side_headers_bin() {
    let addr = common::reserve_addr();
    let _ibex = start("hdrsbin_req", &req_cfg(addr), &[addr]);

    // set: every occurrence goes, the new one is last; the name is the one the list gives.
    ok(addr, "/set", &["x-b: 2", "expect: z", "x-a: x"]);
    ok(addr, "/setup", &["x-b: 2", "expect: z", "x-a: v"]);
    ok(addr, "/add", &["x-a: 1", "x-a: 9", "x-b: 2", "expect: z", "x-a: x"]);
    // prefix: a case-sensitive prefix of the name in the list.
    ok(addr, "/nomatch", &ALL);
    ok(addr, "/pfxcase", &ALL);
    ok(addr, "/pfxmatch", &["x-a: 1", "x-a: 9", "x-b: 2", "expect: z", "x-a: x"]);
    // connection, content-length and expect are left alone.
    ok(addr, "/imm", &["x-a: 1", "x-a: 9", "x-b: 2", "expect: z", "host-other: y", "x-ok: 1"]);
    // del: exact, case-insensitive; beg|end|sub; the immutable names are skipped.
    ok(addr, "/del", &["x-b: 2", "expect: z"]);
    ok(addr, "/delbeg", &["expect: z"]);
    ok(addr, "/delbegcase", &["expect: z"]);
    ok(addr, "/delend", &["x-a: 1", "x-a: 9", "expect: z"]);
    ok(addr, "/delsub", &["expect: z"]);
    ok(addr, "/delimm", &ALL);
    // a list that starts with an empty name: del stops there, set needs the second 0.
    ok(addr, "/delzero", &ALL);
    ok(addr, "/zero2", &ALL);
    ok(addr, "/zero3", &ALL);
    // A list that is a string, an integer or not there at all.
    err500(addr, "/strlist");
    ok(addr, "/intlist", &ALL);
    ok(addr, "/nofetch", &ALL);
}

#[test]
fn request_side_headers_bin_malformed_lists() {
    let addr = common::reserve_addr();
    let _ibex = start("hdrsbin_bad", &req_cfg(addr), &[addr]);
    // Cut inside an entry: the rewrite fails, strict mode makes it a 500.
    for p in ["/trunc", "/deltrunc", "/zero"] {
        err500(addr, p);
    }
    // No terminator: a 500 in both modes.
    for p in ["/noterm", "/delnoterm", "/delendnoterm", "/soft/noterm", "/soft/delnoterm"] {
        err500(addr, p);
    }
}

#[test]
fn request_side_headers_bin_soft_rewrite() {
    let addr = common::reserve_addr();
    let _ibex = start("hdrsbin_soft", &req_cfg(addr), &[addr]);
    // strict-mode off: the cut list stops the rule (what came before stays done).
    ok(addr, "/soft/trunc", &ALL);
    ok(addr, "/soft/deltrunc", &ALL);
    ok(addr, "/soft/zero", &ALL);
    ok(addr, "/soft/strlist", &ALL);
    ok(addr, "/soft/goodthentrunc", &["x-b: 2", "expect: z", "x-a: x"]);
    err500(addr, "/soft/noterm");
    err500(addr, "/soft/delnoterm");
}

fn res_cfg(addr: SocketAddr, be: SocketAddr) -> String {
    let h = |e: &[&str], t| hex(e, t);
    let mut rules = String::new();
    for (list, p) in [("http-response", ""), ("http-after-response", "a")] {
        let mut rule = |t: &str, act: &str, bin: String, tail: &str| {
            rules.push_str(&format!("  {list} {act} bin({bin}){tail} if {{ var(txn.t) -m str {p}{t} }}\n"));
        };
        rule("set", "set-headers-bin", h(&["x-a", "x"], true), "");
        rule("trunc", "set-headers-bin", "03782d6105".into(), "");
        rule("add", "add-headers-bin", h(&["x-a", "x"], true), " prefix x-");
        rule("pfx", "add-headers-bin", h(&["x-a", "x"], true), " prefix y-");
        rule("delbeg", "del-headers-bin", h(&["x-"], false) + "00", " -m beg");
        rule("del", "del-headers-bin", h(&["X-C"], false) + "00", "");
        rule("deltrunc", "del-headers-bin", "03782d61".into(), "");
    }
    format!(
        "global\n  stats socket {{sock}} level admin\n{DEFAULTS}frontend fe\n  bind {addr}\n  http-request set-var(txn.t) req.hdr(x-t)\n  default_backend be\nbackend be\n  server s1 {be}\n{rules}"
    )
}

fn res_seen(addr: SocketAddr, t: &str) -> Result<Vec<String>, String> {
    let r = get(addr, format!("GET / HTTP/1.1\r\nHost: a\r\nx-t: {t}\r\nConnection: close\r\n\r\n").as_bytes());
    let (head, _) = r.split_once("\r\n\r\n").unwrap_or_else(|| panic!("no answer: {r:?}"));
    if !head.starts_with("HTTP/1.1 200") {
        return Err(head.lines().next().unwrap_or("").to_string());
    }
    Ok(head.lines().filter(|l| l.starts_with("x-")).map(str::to_string).collect())
}

#[test]
fn response_side_headers_bin() {
    let addr = common::reserve_addr();
    let _ibex = start("hdrsbin_res", &res_cfg(addr, backend()), &[addr]);
    let all = vec!["x-a: 1", "x-b: 2", "x-c: 3", "x-a: 4"];
    for p in ["", "a"] {
        let w = |t: &str| format!("{p}{t}");
        let want = |v: &[&str]| Ok(v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        assert_eq!(res_seen(addr, &w("set")), want(&["x-b: 2", "x-c: 3", "x-a: x"]), "{p}set");
        assert_eq!(res_seen(addr, &w("add")), want(&["x-a: 1", "x-b: 2", "x-c: 3", "x-a: 4", "x-a: x"]), "{p}add");
        assert_eq!(res_seen(addr, &w("pfx")), want(&all), "{p}pfx");
        assert_eq!(res_seen(addr, &w("delbeg")), want(&[]), "{p}delbeg");
        assert_eq!(res_seen(addr, &w("del")), want(&["x-a: 1", "x-b: 2", "x-a: 4"]), "{p}del");
        for t in ["trunc", "deltrunc"] {
            assert_eq!(res_seen(addr, &w(t)), Err("HTTP/1.1 500 Internal Server Error".to_string()), "{p}{t}");
        }
    }
}

fn check(rule: &str) -> (bool, String) {
    let dir = std::env::temp_dir().join(format!("qh-hdrsbin-cfg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{}.cfg", rule.len()));
    let cfg = format!("{DEFAULTS}frontend f\n  bind 127.0.0.1:1\n  {rule}\n  default_backend b\nbackend b\n  server s 127.0.0.1:1\n");
    std::fs::write(&path, cfg).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("ibex -c");
    let _ = std::fs::remove_dir_all(&dir);
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn headers_bin_config_errors() {
    let fetch = |n: &str, part: &str| format!("fetch method '{n}' extracts information from '{part}', none of which is available here.");
    let cases: Vec<(&str, String)> = vec![
        ("http-request add-headers-bin bin(00) prefix", "error detected in frontend 'f' while parsing 'http-request add-headers-bin' rule : expects 1 argument: <headers>; or 3 arguments: <headers> prefix <pfx>.".into()),
        ("http-request add-headers-bin", "while parsing 'http-request add-headers-bin' rule : expects exactly one argument or three arguments <headers> prefix <pfx>.".into()),
        ("http-request set-headers-bin", "while parsing 'http-request set-headers-bin' rule : expects exactly one argument or three arguments <headers> prefix <pfx>.".into()),
        ("http-request del-headers-bin", "while parsing 'http-request del-headers-bin' rule : expects at least 1 argument.".into()),
        ("http-request del-headers-bin bin(00) -m reg", "while parsing 'http-request del-headers-bin' rule : -m reg is unsupported with del-headers-bin due to performance reasons.".into()),
        ("http-response del-headers-bin bin(00) -m reg", "while parsing 'http-response del-headers-bin' rule : -m reg is unsupported with del-headers-bin due to performance reasons.".into()),
        ("http-request del-headers-bin bin(00) -m foo", "while parsing 'http-request del-headers-bin' rule : -m with unsupported matching method 'foo'.".into()),
        ("http-request del-headers-bin bin(00) -m", "while parsing 'http-request del-headers-bin' rule : -m flag expects exactly 1 argument.".into()),
        ("http-request add-headers-bin bin(00) bar", "'http-request add-headers-bin' expects either 'if' or 'unless' followed by a condition but found 'bar'".into()),
        ("http-request del-headers-bin bin(00) -m beg extra", "'http-request del-headers-bin' expects either 'if' or 'unless' followed by a condition but found 'extra'".into()),
        ("http-request set-headers-bin res.hdrs_bin", format!("while parsing 'http-request set-headers-bin' rule : {}", fetch("res.hdrs_bin", "HTTP response headers"))),
        ("http-response set-headers-bin req.hdrs_bin", format!("while parsing 'http-response set-headers-bin' rule : {}", fetch("req.hdrs_bin", "HTTP request headers"))),
        ("http-after-response del-headers-bin req.hdrs_bin", format!("while parsing 'http-after-response del-headers-bin' rule : {}", fetch("req.hdrs_bin", "HTTP request headers"))),
    ];
    let mut wrong = Vec::new();
    for (rule, why) in &cases {
        let (ok, err) = check(rule);
        if ok || !err.contains(why.as_str()) {
            wrong.push(format!("{rule}: loaded={ok}, stderr={err:?}, wanted {why:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    for rule in ["http-request del-headers-bin bin(00) -m beg", "http-after-response set-headers-bin res.hdrs_bin prefix x", "http-response add-headers-bin res.hdrs_bin prefix x if { status 200 }"] {
        let (ok, err) = check(rule);
        assert!(ok, "{rule}: {err}");
    }
}

/// `n` copies of `add-headers-bin` of a 900-byte header on the response, with `tune.bufsize
/// 4096`. Measured on the same oracle: two fit (200, two `x-big`), six do not (500).
fn big_cfg(addr: SocketAddr, be: SocketAddr, n: usize) -> String {
    let mut list = vec![5u8];
    list.extend_from_slice(b"x-big");
    // `encode_varint` of 900: (900 | 240) & 255, then (900 - 240) >> 4 = 41.
    list.extend_from_slice(&[(900u32 | 240) as u8, 41]);
    list.extend(std::iter::repeat_n(b'A', 900));
    list.extend_from_slice(&[0, 0]);
    let bin: String = list.iter().map(|b| format!("{b:02x}")).collect();
    let rules = format!("  http-response add-headers-bin bin({bin}) if {{ var(txn.t) -m str many }}\n").repeat(n);
    format!(
        "global\n  stats socket {{sock}} level admin\n  tune.bufsize 4096\n{DEFAULTS}frontend fe\n  bind {addr}\n  http-request set-var(txn.t) req.hdr(x-t)\n  default_backend be\nbackend be\n  server s1 {be}\n{rules}"
    )
}

#[test]
fn response_headers_bin_that_do_not_fit_the_buffer_are_a_500() {
    let be = backend();
    let ok_addr = common::reserve_addr();
    let _fits = start("hdrsbin_fit", &big_cfg(ok_addr, be, 2), &[ok_addr]);
    let r = get(ok_addr, b"GET / HTTP/1.1\r\nHost: a\r\nx-t: many\r\nConnection: close\r\n\r\n");
    assert!(r.starts_with("HTTP/1.1 200"), "{r:.60}");
    assert_eq!(r.matches("x-big: ").count(), 2);
    let full_addr = common::reserve_addr();
    let _full = start("hdrsbin_full", &big_cfg(full_addr, be, 6), &[full_addr]);
    let r = get(full_addr, b"GET / HTTP/1.1\r\nHost: a\r\nx-t: many\r\nConnection: close\r\n\r\n");
    assert!(r.starts_with("HTTP/1.1 500"), "{r:.60}");
}
