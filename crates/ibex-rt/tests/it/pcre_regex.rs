// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Regular expressions only a PCRE has: look-around, back-references, possessive
//! quantifiers, atomic groups, named groups and inline flags, in an ACL `-m reg`, in
//! `replace-header` and in `regsub`; a catastrophic pattern; and the PCRE features Ibex
//! refuses.
//!
//! Every expected value was measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-04 with
//! the same configuration (`x-m` lists, by letter, which ACLs matched each path).
//! Two measured differences are not tested because they are known gaps (see
//! docs/differences.md): an ACL compiles with PCRE2_NO_AUTO_CAPTURE, so `(a)b\1` is a
//! load error on `HAProxy` and a match on Ibex; and `\Q..\E` is refused by Ibex.
//! Ordinary patterns still compile with `regex`; only a pattern it refuses goes to
//! `fancy-regex`, which gives up after a bounded number of backtracking steps and calls
//! that no match (as PCRE2's match limit does).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n";

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// Starts ibex on `cfg`, `{fe}` replaced by the listening address.
fn start(cfg: &str) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let text = cfg.replace("{fe}", &fe.to_string());
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, _cfg: f };
    assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}");
    (ibex, fe)
}

/// `ibex -c -f` on `cfg`: whether it was accepted, and what it said.
fn check(cfg: &str) -> (bool, String) {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run ibex -c");
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

/// One request, and the response head (the answers here have no body).
fn get(fe: SocketAddr, path: &str) -> String {
    send(fe, &format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n"))
}

/// `request` as is, and the response head.
fn send(fe: SocketAddr, request: &str) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(request.as_bytes()).expect("send");
    let mut got = Vec::new();
    let mut buf = [0u8; 65536];
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&got).into_owned()
}

fn hdr(resp: &str, name: &str) -> Option<String> {
    resp.split("\r\n").find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

const ACLS: &str = r#"
defaults
  mode http
  timeout connect 1s
  timeout client 5s
  timeout server 5s
frontend f
  bind {fe}
  http-request set-var(txn.m) str(:)
  http-request set-var-fmt(txn.m) "%[var(txn.m)]A" if { path_reg -- ^/(?=ab) }
  http-request set-var-fmt(txn.m) "%[var(txn.m)]B" if { path_reg -- (?<=/)ab }
  http-request set-var-fmt(txn.m) "%[var(txn.m)]C" if { path_reg -- (?<n>a)b\1 }
  http-request set-var-fmt(txn.m) "%[var(txn.m)]D" if { path_reg -- ^/a++b }
  http-request set-var-fmt(txn.m) "%[var(txn.m)]E" if { path_reg -- ^/(?>a+)ab }
  http-request set-var-fmt(txn.m) "%[var(txn.m)]F" if { path_reg -- (?<n>b)c }
  http-request set-var-fmt(txn.m) "%[var(txn.m)]G" if { path_reg -- (?i)^/AB }
  http-request set-var-fmt(txn.m) "%[var(txn.m)]H" if { path_reg -- ^/(a+)+$ }
  http-request set-var-fmt(txn.m) "%[var(txn.m)]I" if { path_reg -- (?<!x)b }
  http-request set-var-fmt(txn.m) "%[var(txn.m)]J" if { path_reg -- ^/(?!ab)a }
  http-request set-var-fmt(txn.m) "%[var(txn.m)]K" if { path_reg -- (?<n>a)\k<n> }
  http-request set-var-fmt(txn.m) "%[var(txn.m)]L" if { path_reg -- (?P<n>a)(?P=n) }
  http-request set-var-fmt(txn.m) "%[var(txn.m)]N" if { path_reg -- ^/(a+)+(?=$) }
  http-request return status 200 hdr x-m "%[var(txn.m)]"
"#;

/// Which of the ACLs above matched each path (A look-ahead, B look-behind, C numbered
/// back-reference to a named group, D possessive, E atomic group, F named group, G inline
/// `(?i)`, H plain nested repetition, I negative look-behind, J negative look-ahead, K and
/// L named back-references, N a catastrophic pattern with a look-ahead).
#[test]
fn acl_reg_takes_pcre_only_syntax() {
    let (_ibex, fe) = start(ACLS);
    let measured = [
        ("/ab", ":ABDGI"),
        ("/abab", ":ABCDGI"),
        ("/aab", ":DIJKL"),
        ("/aaaa", ":HJKLN"),
        ("/AB", ":G"),
        ("/abc", ":ABDFGI"),
    ];
    for (path, want) in measured {
        let r = get(fe, path);
        assert_eq!(hdr(&r, "x-m").as_deref(), Some(want), "{path}: {r}");
    }
}

/// `(a+)+(?=$)` against 28, 48 and 3000 `a` and a `b`: `HAProxy`'s PCRE2 gives up at its
/// match limit and answers "no match" (`N` absent) at once; so must Ibex, in well under
/// the time an unbounded backtrack would take.
#[test]
fn a_catastrophic_pattern_is_no_match_and_prompt() {
    let (_ibex, fe) = start(ACLS);
    for n in [28, 48, 3000] {
        let t = Instant::now();
        let r = get(fe, &format!("/{}b", "a".repeat(n)));
        assert_eq!(hdr(&r, "x-m").as_deref(), Some(":DIJKL"), "{n}: {r}");
        assert!(t.elapsed() < Duration::from_secs(3), "{n} took {:?}", t.elapsed());
    }
}

const REWRITE: &str = r#"
defaults
  mode http
  timeout connect 1s
  timeout client 5s
  timeout server 5s
frontend f
  bind {fe}
  http-request set-header x-in "abab"
  http-request set-header x-bk "foo-foo-bar"
  http-request set-header x-pos "aaab"
  http-request set-header x-look "ac"
  http-request set-header x-ci "HELLO"
  http-request replace-header x-in (a)(b)\1\2 "<\2\1>"
  http-request replace-header x-bk (?<n>foo)-\1 "[\1]"
  http-request replace-header x-pos a++b X
  http-request replace-value x-look a(?=c) Y
  http-request replace-header x-ci (?i)hel y
  http-request return status 200 hdr x-in "%[req.hdr(x-in)]" hdr x-bk "%[req.hdr(x-bk)]" hdr x-pos "%[req.hdr(x-pos)]" hdr x-look "%[req.hdr(x-look)]" hdr x-ci "%[req.hdr(x-ci)]"
"#;

/// `replace-header`/`replace-value` with a back-reference to a group of the pattern, a
/// possessive quantifier, a look-ahead and an inline flag.
#[test]
fn replace_header_takes_pcre_only_syntax() {
    let (_ibex, fe) = start(REWRITE);
    let r = get(fe, "/");
    for (name, want) in [("x-in", "<ba>"), ("x-bk", "[foo]"), ("x-pos", "X"), ("x-look", "Y"), ("x-ci", "y")] {
        assert_eq!(hdr(&r, name).as_deref(), Some(want), "{name}: {r}");
    }
}

const REGSUB: &str = r#"
defaults
  mode http
  timeout connect 1s
  timeout client 5s
  timeout server 5s
frontend f
  bind {fe}
  http-request set-var(txn.rs) 'str(abab),regsub("(a)b\1","X")'
  http-request set-var(txn.rs2) 'str(foo-foo),regsub("(?<n>foo)-\1","[\1]")'
  http-request set-var(txn.rs3) 'str(HELLO),regsub("(?i)hel","y")'
  http-request set-var(txn.rs4) 'str(ab),regsub("(?<=a)b","X")'
  http-request set-var(txn.rs5) 'str(aaab),regsub("a++","X")'
  http-request set-var(txn.rs6) 'str(aaab),regsub("(?>a+)b","X")'
  http-request set-var(txn.rs7) 'str(aaab),regsub("(?=a)a","X")'
  http-request return status 200 hdr x-rs "%[var(txn.rs)]" hdr x-rs2 "%[var(txn.rs2)]" hdr x-rs3 "%[var(txn.rs3)]" hdr x-rs4 "%[var(txn.rs4)]" hdr x-rs5 "%[var(txn.rs5)]" hdr x-rs6 "%[var(txn.rs6)]" hdr x-rs7 "%[var(txn.rs7)]"
"#;

/// `regsub` with each PCRE-only feature (first match only: no `g` flag).
#[test]
fn regsub_takes_pcre_only_syntax() {
    let (_ibex, fe) = start(REGSUB);
    let r = get(fe, "/");
    for (name, want) in [("x-rs", "Xb"), ("x-rs2", "[foo]"), ("x-rs3", "yLO"), ("x-rs4", "aX"), ("x-rs5", "Xb"), ("x-rs6", "X"), ("x-rs7", "Xaab")] {
        assert_eq!(hdr(&r, name).as_deref(), Some(want), "{name}: {r}");
    }
}

/// What `fancy-regex` lacks is refused at load, naming the feature, where `HAProxy`
/// (PCRE2) takes it: recursion, subroutine calls, callouts, `\X`, branch reset groups.
#[test]
fn pcre_features_ibex_lacks_are_refused_with_a_reason() {
    for re in ["(?R)", "(a)(?1)", "(?C)a", "\\X", "(?|(a)|(b))"] {
        let cfg = format!("{DEFAULTS}listen l\n  bind 127.0.0.1:1\n  http-request replace-header x '{re}' y\n");
        let (ok, text) = check(&cfg);
        assert!(!ok, "{re} was loaded");
        assert!(text.contains("not supported") && text.contains("docs/differences.md"), "{re}: {text}");
        let cfg = format!("{DEFAULTS}listen l\n  bind 127.0.0.1:1\n  http-request deny if {{ path_reg -- {re} }}\n");
        let (ok, text) = check(&cfg);
        assert!(!ok, "path_reg {re} was loaded");
        assert!(text.contains("not supported"), "path_reg {re}: {text}");
    }
}

const REQ: &str = "GET /ab?x=1 HTTP/1.1\r\nHost: x\r\nx-del: 1\r\nx-keep: 2\r\n\r\n";

fn one_rule(rule: &str, hdrs: &str) -> String {
    format!("{DEFAULTS}frontend f\n  bind {{fe}}\n  http-request {rule}\n  http-request return status 200 {hdrs}\n")
}

/// `replace-path` and `replace-pathq` with a look-ahead and a named group, and `del-header
/// -m reg` with a negative look-ahead. (HAProxy replaces the whole path or path and query
/// with the format, so the patterns here match all of it.)
#[test]
fn path_rewrites_and_header_names_take_pcre_only_syntax() {
    let show = r#"hdr x-p "%[path]" hdr x-q "%[query]" hdr x-hd "%[req.hdr(x-del)]" hdr x-hk "%[req.hdr(x-keep)]""#;
    let (_a, fe) = start(&one_rule(r"replace-pathq ^(?=/)/ab\?x=1$ /Q?y=2", show));
    let r = send(fe, REQ);
    assert_eq!((hdr(&r, "x-p").as_deref(), hdr(&r, "x-q").as_deref()), (Some("/Q"), Some("y=2")), "{r}");
    let (_b, fe) = start(&one_rule(r"replace-path ^/(?<a>a+)(?=b)b$ /[\1]", show));
    let r = send(fe, REQ);
    assert_eq!((hdr(&r, "x-p").as_deref(), hdr(&r, "x-q").as_deref()), (Some("/[a]"), Some("x=1")), "{r}");
    let (_c, fe) = start(&one_rule("del-header ^x-(?!keep) -m reg", show));
    let r = send(fe, REQ);
    assert_eq!((hdr(&r, "x-hd"), hdr(&r, "x-hk").as_deref()), (None, Some("2")), "{r}");
}

/// `map_regm` with a look-ahead key and a `\1` in the value.
#[test]
fn map_regm_takes_pcre_only_syntax() {
    let mut map = NamedTempFile::new().expect("tmp");
    map.write_all(b"^/(a)(?=b) <\\1>\n").expect("write map");
    let cfg = one_rule(&format!("set-var(txn.mm) path,map_regm({})", map.path().display()), r#"hdr x-mm "%[var(txn.mm)]""#);
    let (_ibex, fe) = start(&cfg);
    let r = send(fe, REQ);
    assert_eq!(hdr(&r, "x-mm").as_deref(), Some("<a>"), "{r}");
}
