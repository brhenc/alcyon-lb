// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `HAProxy` compiles the regexes of ACLs, of `map_reg` and of health-check `rstring` /
//! `rstatus` with PCRE2_NO_AUTO_CAPTURE: an unnamed group does not capture, so it has no
//! number (T274 J2). `(a)\1` is a load error, `(?<n>a)\1` is a back-reference to `n`,
//! `(a)(?<n>b)\1` refers to `n`. `map_regm`, `replace-*` and `regsub` keep numbering every
//! group.
//!
//! Measured against `HAProxy` 3.5-dev8-885761-29, 2026-10-11 (`haproxy -c` and the CLI):
//!
//! * refused, exit 1, `regex '(a)\1' is invalid (error=reference to non-existent
//!   subpattern, erroffset=5).`: `acl a path_reg`, `acl a path -m reg`, `hdr(x) -m reg`,
//!   inline `{ path_reg .. }`, `-f` pattern file, `map_reg` and `map_reg_key` files,
//!   `http-check expect rstring`/`rstatus`, `tcp-check expect rstring`; also `((a))\2`,
//!   `(?:a)\1`, `(a)(?<n>b)\2`, `(a)(?(1)b|c)`, `(?<n>b)(?<m>b)\3`.
//! * accepted: `(?<n>a)\1`, `(a)b`, `(?<n>b)(?<m>b)\2`, `(a)(?<n>b)\1`; `map_regm` with
//!   `(a)\1`; `replace-header`, `replace-value`, `replace-path`, `replace-uri` with `(a)\1`.
//! * CLI: `add acl <acl> (a)\\1` and `add map <map_reg file> (a)\\1 v` (sent with the backslash doubled) answer the same
//!   refusal and add nothing; the same on a `map_regm` file, and `(?<n>q)\\1`, are added.

use crate::common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const NONEXISTENT: &str = "reference to non-existent subpattern";

fn tmp(tag: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("ibex_t274j2_{}_{n}_{tag}", std::process::id()))
}

/// `-c` on a configuration with `fe_line` in the frontend and `be_lines` in a backend.
/// `file` is written first, and its path replaces `FILE` in the lines.
fn check(fe_line: &str, be_lines: &str, file: Option<&str>) -> (Option<i32>, String) {
    let f = tmp("pat");
    if let Some(content) = file {
        std::fs::write(&f, content).expect("write pattern file");
    }
    let fe_line = fe_line.replace("FILE", &f.display().to_string());
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind 127.0.0.1:18080\n  {fe_line}\n  default_backend be\n\
         backend be\n{be_lines}  server s1 127.0.0.1:1 check\n"
    );
    let path = tmp("cfg");
    std::fs::write(&path, &cfg).expect("write config");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("run -c");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&f);
    (out.status.code(), format!("{cfg}\n---\n{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

/// Patterns HAProxy refuses where no group captures unless it is named.
const REFUSED: &[&str] = &[r"(a)\1", r"((a))\2", r"(?:a)\1", r"(a)(?<n>b)\2", "(a)(?(1)b|c)", r"(?<n>b)(?<m>b)\3", r"[(](a)\1"];
/// Patterns it accepts.
const ACCEPTED: &[&str] = &[r"(?<n>a)\1", "(a)b", r"(?<n>b)(?<m>b)\2", r"(a)(?<n>b)\1", r"\(a\1(?<n>a)", r"[(]a(?<n>b)\1"];

#[test]
fn acl_regexes_do_not_number_unnamed_groups() {
    for pat in REFUSED {
        for line in [
            format!("acl a path_reg -- {pat}"),
            format!("acl a path -m reg -- {pat}"),
            format!("acl a hdr(x) -m reg -- {pat}"),
            format!("http-request deny if {{ path_reg -- {pat} }}"),
            format!("http-request deny if {{ path -i -m reg -- {pat} }}"),
        ] {
            let (code, out) = check(&line, "", None);
            assert_eq!(code, Some(1), "`{line}` must be refused:\n{out}");
            assert!(out.contains(NONEXISTENT), "`{line}`: expected {NONEXISTENT:?}:\n{out}");
        }
        let (code, out) = check("http-request deny if { path_reg -f FILE }", "", Some(&format!("{pat}\n")));
        assert_eq!(code, Some(1), "pattern file with `{pat}` must be refused:\n{out}");
        assert!(out.contains(NONEXISTENT), "pattern file with `{pat}`:\n{out}");
    }
    for pat in ACCEPTED {
        for line in [format!("acl a path_reg -- {pat}"), format!("http-request deny if {{ path_reg -- {pat} }}")] {
            let (code, out) = check(&line, "", None);
            assert_eq!(code, Some(0), "`{line}` must load:\n{out}");
        }
    }
}

#[test]
fn map_reg_does_not_number_unnamed_groups_and_map_regm_does() {
    for pat in REFUSED {
        for conv in ["map_reg", "map_reg_key"] {
            let line = format!("http-request set-var(txn.x) path,{conv}(FILE)");
            let (code, out) = check(&line, "", Some(&format!("{pat} v\n")));
            assert_eq!(code, Some(1), "`{conv}` with `{pat}` must be refused:\n{out}");
            assert!(out.contains(NONEXISTENT), "`{conv}` with `{pat}`:\n{out}");
        }
    }
    for pat in ACCEPTED {
        let (code, out) = check("http-request set-var(txn.x) path,map_reg(FILE)", "", Some(&format!("{pat} v\n")));
        assert_eq!(code, Some(0), "map_reg with `{pat}` must load:\n{out}");
    }
    // map_regm compiles with captures: every group counts.
    for pat in [r"(a)\1", r"((a))\2"] {
        let (code, out) = check("http-request set-var(txn.x) path,map_regm(FILE)", "", Some(&format!("{pat} v\n")));
        assert_eq!(code, Some(0), "map_regm with `{pat}` must load:\n{out}");
    }
}

#[test]
fn health_check_regexes_do_not_number_unnamed_groups() {
    for pat in REFUSED {
        for be in [
            format!("  option httpchk\n  http-check expect rstring {pat}\n"),
            format!("  option httpchk\n  http-check expect rstatus {pat}\n"),
            format!("  option tcp-check\n  tcp-check expect rstring {pat}\n"),
        ] {
            let (code, out) = check("", &be, None);
            assert_eq!(code, Some(1), "{be:?} must be refused:\n{out}");
            assert!(out.contains(NONEXISTENT), "{be:?}:\n{out}");
        }
    }
    for pat in ACCEPTED {
        let be = format!("  option httpchk\n  http-check expect rstring {pat}\n");
        let (code, out) = check("", &be, None);
        assert_eq!(code, Some(0), "{be:?} must load:\n{out}");
    }
}

#[test]
fn rewrites_and_regsub_still_number_every_group() {
    for line in [
        r"http-request replace-header X (a)\1 z",
        r"http-request replace-value X (a)\1 z",
        r"http-request replace-path (a)\1 z",
        r"http-request replace-uri (a)\1 z",
        r"http-response replace-header X (a)\1 z",
        r"http-request replace-path (a)(?(1)x) y",
    ] {
        let (code, out) = check(line, "", None);
        assert_eq!(code, Some(0), "`{line}` must load:\n{out}");
    }
}

struct Ibex {
    child: Child,
    sock: PathBuf,
    files: Vec<PathBuf>,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        for p in &self.files {
            let _ = std::fs::remove_file(p);
        }
    }
}

fn cli(sock: &PathBuf, input: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let _ = s.write_all(input.as_bytes());
    let _ = s.shutdown(std::net::Shutdown::Write);
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn get(fe: std::net::SocketAddr, path: &str) -> String {
    let mut s = std::net::TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let _ = s.write_all(format!("GET {path} HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n").as_bytes());
    let mut resp = String::new();
    let _ = s.read_to_string(&mut resp);
    resp
}

/// The pattern on the wire. `HAProxy`'s CLI reads a backslash as an escape and wants `\\1`,
/// and so does Ibex's (T287).
const WIRE: &str = r"\\1";

#[test]
fn the_cli_refuses_an_unnamed_group_reference_in_an_acl_and_a_map_reg_but_not_a_map_regm() {
    let (sock, cfg, acl, mreg, mregm) = (tmp("sock"), tmp("cfg"), tmp("acl"), tmp("mreg"), tmp("mregm"));
    std::fs::write(&acl, "^/y\n").expect("acl");
    std::fs::write(&mreg, "^/x v\n").expect("map");
    std::fs::write(&mregm, "^/x v\n").expect("map");
    let fe = common::reserve_addr();
    let text = format!(
        "global\n  stats socket {} mode 600 level admin\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
         frontend f\n  bind {fe}\n  http-request deny if {{ path_reg -f {} }}\n\
         http-request return status 200 hdr x-reg %[path,map_reg({},none)] hdr x-regm %[path,map_regm({},none)]\n",
        sock.display(),
        acl.display(),
        mreg.display(),
        mregm.display()
    );
    std::fs::write(&cfg, &text).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let ibex = Ibex { child, sock: sock.clone(), files: vec![cfg, acl.clone(), mreg.clone(), mregm.clone(), sock] };
    assert!(common::wait_listening(fe), "ibex never listened with:\n{text}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ibex.sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let want = format!("regex '(a)\\1' is invalid (error={NONEXISTENT}");
    let out = cli(&ibex.sock, &format!("add acl {} (a){WIRE}\n", acl.display()));
    assert!(out.contains(&want), "add acl: {out:?}");
    let out = cli(&ibex.sock, &format!("add map {} (a){WIRE} v\n", mreg.display()));
    assert!(out.contains(&want), "add map (map_reg): {out:?}");
    assert!(!cli(&ibex.sock, &format!("show map {}\n", mreg.display())).contains("(a)"), "nothing added to the map_reg map");
    assert!(!cli(&ibex.sock, &format!("show acl {}\n", acl.display())).contains("(a)"), "nothing added to the acl");
    // map_regm keeps numbering every group; a named group is a back-reference target.
    let out = cli(&ibex.sock, &format!("add map {} (a){WIRE} R\n", mregm.display()));
    assert!(!out.contains("invalid"), "add map (map_regm): {out:?}");
    let out = cli(&ibex.sock, &format!("add map {} (?<n>q){WIRE} M\n", mreg.display()));
    assert!(!out.contains("invalid"), "add map (map_reg, named): {out:?}");
    let out = cli(&ibex.sock, &format!("add acl {} (?<n>z){WIRE}\n", acl.display()));
    assert!(!out.contains("invalid"), "add acl (named): {out:?}");
    // And they do what they say.
    let r = get(fe, "/aa");
    assert!(r.contains("x-regm: R"), "map_regm (a)\\1 on /aa: {r:?}");
    let r = get(fe, "/qq");
    assert!(r.contains("x-reg: M"), "map_reg (?<n>q)\\1 on /qq: {r:?}");
    assert!(get(fe, "/zz").starts_with("HTTP/1.1 403"), "acl (?<n>z)\\1 on /zz");
    assert!(get(fe, "/zy").starts_with("HTTP/1.1 200"), "acl (?<n>z)\\1 on /zy");
}

#[test]
fn an_unnamed_group_is_not_counted_in_a_back_reference() {
    // `(a)(?<n>b)\1` refers to `n`, so it matches `abb` and not `aba`.
    let fe = common::reserve_addr();
    let cfg = tmp("cfg");
    let text = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
         frontend f\n  bind {fe}\n  http-request deny if {{ path_reg -- ^/(a)(?<n>b)\\1$ }}\n\
         http-request return status 200\n"
    );
    std::fs::write(&cfg, &text).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let _ibex = Ibex { child, sock: tmp("none"), files: vec![cfg] };
    assert!(common::wait_listening(fe), "ibex never listened with:\n{text}");
    assert!(get(fe, "/abb").starts_with("HTTP/1.1 403"), "/abb must match");
    assert!(get(fe, "/aba").starts_with("HTTP/1.1 200"), "/aba must not match");
}
