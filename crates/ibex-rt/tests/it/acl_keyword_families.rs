// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! ACL keyword shorthands (`url_beg`, `base_dom`, `cook_len`, `hdr_cnt`, `shdr_beg`, ...)
//! must match what they match in `HAProxy` (T132). They used to load and never match, so
//! `http-request deny if { url_beg /admin }` let `/admin/x` through.
//!
//! Every row is `{ <acl> }` guarding `http-request set-var(txn.mN) int(1)` (requests) or
//! `http-response set-var(txn.rN) int(1)`, read back from an `x-hits` response header, for
//! two requests. The two booleans are what `HAProxy` 3.5-dev8-885761-29 answered for the
//! same configuration, 2026-10-04:
//!
//! * A: `GET /dom/x.html?a=5&b=zz`, `Host: abc.example.com`, `Cookie: c1=hello; n=7`,
//!   `X-N: 12`, `X-S: /dom/x.y`, `X-Ip: 10.1.2.3`;
//! * B: `POST /other`, `Host: zzz.test`, `Cookie: c1=world`, `X-N: 3`, `X-S: nope`;
//! * the server answers `X-R: abc`, `X-N: 12`, `Set-Cookie: sc=val`, `Set-Cookie: sn=9`.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};

const REQ_CASES: &[(&str, bool, bool)] = &[
    ("url /dom/x.html?a=5&b=zz", true, false),
    ("url_beg /dom", true, false),
    ("url_end .html?a=5&b=zz", true, false),
    ("url_sub dom/x", true, false),
    ("url_dir dom", true, false),
    ("url_dom dom", true, false),
    ("url_reg ^/d.m/", true, false),
    ("url_len 20", true, false),
    ("path /dom/x.html", true, false),
    ("path_beg /dom", true, false),
    ("path_end .html", true, false),
    ("path_sub dom/x", true, false),
    ("path_dir dom", true, false),
    ("path_dom dom", true, false),
    ("path_reg ^/d.m/", true, false),
    ("path_len 11", true, false),
    ("base abc.example.com/dom/x.html", true, false),
    ("base_beg abc", true, false),
    ("base_end x.html", true, false),
    ("base_sub example", true, false),
    ("base_dir dom", true, false),
    ("base_dom example", true, false),
    ("base_reg ^abc\\.", true, false),
    ("base_len 26", true, false),
    ("cook(c1) hello", true, false),
    ("cook_beg(c1) he", true, false),
    ("cook_end(c1) llo", true, false),
    ("cook_sub(c1) ell", true, false),
    ("cook_dir(c1) hello", true, false),
    ("cook_dom(c1) hello", true, false),
    ("cook_reg(c1) ^h.l", true, false),
    ("cook_len(c1) 5", true, true),
    ("hdr(x-s) /dom/x.y", true, false),
    ("hdr_beg(x-s) /dom", true, false),
    ("hdr_end(x-s) x.y", true, false),
    ("hdr_sub(x-s) om/x", true, false),
    ("hdr_dir(x-s) dom", true, false),
    ("hdr_dom(x-s) dom", true, false),
    ("hdr_reg(x-s) ^/d.m", true, false),
    ("hdr_len(x-s) 8", true, false),
    ("urlp(a) 5", true, false),
    ("urlp_beg(a) 5", true, false),
    ("urlp_end(a) 5", true, false),
    ("urlp_sub(a) 5", true, false),
    ("urlp_dir(a) 5", true, false),
    ("urlp_dom(a) 5", true, false),
    ("urlp_reg(a) ^5$", true, false),
    ("urlp_len(a) 1", true, false),
    ("hdr_cnt(x-s) 1", true, true),
    ("hdr_cnt(x-s) ge 2", false, false),
    ("hdr_val(x-n) gt 5", true, false),
    ("hdr_val(x-n) 12", true, false),
    ("hdr_val(x-n) lt 5", false, true),
    ("cook_cnt(c1) 1", true, true),
    ("cook_cnt(c1) ge 2", false, false),
    ("cook_val(n) ge 7", true, false),
    ("cook_val(n) lt 7", false, false),
    ("urlp_val(a) 5", true, false),
    ("urlp_val(a) gt 5", false, false),
    ("hdr_ip(x-ip) 10.0.0.0/8", true, false),
    ("method GET", true, false),
    ("method POST", false, true),
    ("req_ver 1.1", true, true),
    ("hdr_len(host) 15", true, false),
    ("hdr_len(host) 3", false, false),
    ("path_len 11", true, false),
    ("path_len 5", false, false),
    ("url_len 20", true, false),
    ("url_len 3", false, false),
];

const RES_CASES: &[(&str, bool, bool)] = &[
    ("shdr(x-r) abc", true, true),
    ("shdr_beg(x-r) ab", true, true),
    ("shdr_end(x-r) bc", true, true),
    ("shdr_sub(x-r) b", true, true),
    ("shdr_reg(x-r) ^a.c", true, true),
    ("shdr_dir(x-r) abc", true, true),
    ("shdr_dom(x-r) abc", true, true),
    ("shdr_len(x-r) 3", true, true),
    ("shdr_cnt(x-r) 1", true, true),
    ("shdr_val(x-n) gt 5", true, true),
    ("scook(sc) val", true, true),
    ("scook_beg(sc) va", true, true),
    ("scook_end(sc) al", true, true),
    ("scook_sub(sc) a", true, true),
    ("scook_reg(sc) ^v.l", true, true),
    ("scook_len(sc) 3", true, true),
    ("scook_dir(sc) val", true, true),
    ("scook_dom(sc) val", true, true),
    ("scook_cnt(sc) 1", true, true),
    ("scook_val(sn) gt 5", true, true),
    ("resp_ver 1.1", true, true),
];

const REQ_A: &str = "GET /dom/x.html?a=5&b=zz HTTP/1.1\r\nHost: abc.example.com\r\nCookie: c1=hello; n=7\r\nX-N: 12\r\nX-S: /dom/x.y\r\nX-Ip: 10.1.2.3\r\nConnection: close\r\n\r\n";
const REQ_B: &str = "POST /other HTTP/1.1\r\nHost: zzz.test\r\nCookie: c1=world\r\nX-N: 3\r\nX-S: nope\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

fn backend() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-R: abc\r\nX-N: 12\r\nSet-Cookie: sc=val; Path=/\r\nSet-Cookie: sn=9\r\nConnection: close\r\n\r\n");
        }
    });
    addr
}

fn config(fe: SocketAddr, be: SocketAddr) -> String {
    let mut c = format!(
        "defaults\n mode http\n timeout client 5s\n timeout server 5s\n timeout connect 5s\nfrontend fe\n bind {fe}\n"
    );
    for (i, (acl, _, _)) in REQ_CASES.iter().enumerate() {
        c += &format!(" http-request set-var(txn.m{i}) int(1) if {{ {acl} }}\n");
    }
    for (i, (acl, _, _)) in RES_CASES.iter().enumerate() {
        c += &format!(" http-response set-var(txn.r{i}) int(1) if {{ {acl} }}\n");
    }
    let m: Vec<String> = (0..REQ_CASES.len()).map(|i| format!("%[var(txn.m{i})]")).collect();
    let r: Vec<String> = (0..RES_CASES.len()).map(|i| format!("%[var(txn.r{i})]")).collect();
    c += &format!(" http-response set-header x-hits \"{}|{}\"\n", m.join(","), r.join(","));
    c += &format!(" default_backend be\nbackend be\n server s {be}\n");
    c
}

fn hits(fe: SocketAddr, req: &str) -> (Vec<bool>, Vec<bool>) {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.write_all(req.as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let line = out
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("x-hits:"))
        .unwrap_or_else(|| panic!("no x-hits in {out:?}"));
    let (m, r) = line["x-hits:".len()..].trim().split_once('|').expect("separator");
    let flags = |s: &str| s.split(',').map(|v| v == "1").collect::<Vec<_>>();
    (flags(m), flags(r))
}

#[test]
fn acl_keyword_shorthands_match_as_haproxy() {
    let be = backend();
    let fe = common::reserve_addr();
    let path = std::env::temp_dir().join(format!("ibex_aclfam_{}.cfg", std::process::id()));
    std::fs::write(&path, config(fe, be)).expect("write config");
    let check = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("ibex -c");
    assert!(
        check.status.success(),
        "ibex -c refused a keyword HAProxy accepts: {}{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Ibex)
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex did not listen");
    let (a_req, a_res) = hits(fe, REQ_A);
    let (b_req, b_res) = hits(fe, REQ_B);
    common::stop(&mut child);
    let _ = std::fs::remove_file(&path);
    let mut wrong = Vec::new();
    for (i, (acl, a, b)) in REQ_CASES.iter().enumerate() {
        if (a_req[i], b_req[i]) != (*a, *b) {
            wrong.push(format!("{{ {acl} }}: want A={a} B={b}, got A={} B={}", a_req[i], b_req[i]));
        }
    }
    for (i, (acl, a, b)) in RES_CASES.iter().enumerate() {
        if (a_res[i], b_res[i]) != (*a, *b) {
            wrong.push(format!("{{ {acl} }} (response): want A={a} B={b}, got A={} B={}", a_res[i], b_res[i]));
        }
    }
    assert!(wrong.is_empty(), "{} ACLs differ from HAProxy:\n{}", wrong.len(), wrong.join("\n"));
}

/// What `ibex -c` says about `acl a <keyword>`: (exit code, output).
fn check_acl(keyword: &str) -> (Option<i32>, String) {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n mode http\n timeout client 5s\n timeout server 5s\n timeout connect 5s\n\
         frontend fe\n bind {fe}\n acl a {keyword}\n http-request deny if a\n default_backend be\n\
         backend be\n server s 127.0.0.1:1\n"
    );
    let path = std::env::temp_dir().join(format!("ibex_aclfam_c_{}_{}.cfg", std::process::id(), keyword.len()));
    std::fs::write(&path, cfg).expect("write config");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("ibex -c");
    let _ = std::fs::remove_file(&path);
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

/// A keyword Ibex has no fetch behind used to load and never match. `HAProxy` refuses a
/// keyword it does not know ("unknown fetch method 'nosuch' in ACL expression 'nosuch'",
/// measured, exit 1); Ibex refuses the ones it does not implement the same way. (`url_ip`
/// and `url_port`, which `HAProxy` accepts and this test used for the case, are fetches
/// now: `tests/url_ip_port.rs`.)
#[test]
fn an_acl_keyword_without_a_fetch_is_refused() {
    for kw in ["nosuch", "nosuch_beg /a"] {
        let (code, text) = check_acl(kw);
        assert_eq!(code, Some(1), "{kw}: {text}");
        assert!(text.contains("unknown fetch method"), "{kw}: {text}");
    }
    for kw in ["url_beg /a", "hdr_val(x-n) gt 5", "shdr_len(x-r) 3", "url_ip 1.2.3.4", "url_port 80"] {
        let (code, text) = check_acl(kw);
        assert_eq!(code, Some(0), "{kw}: {text}");
    }
}
