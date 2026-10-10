// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `stats socket` address forms (T222), measured on 3.5-dev8-885761-29 with `haproxy -c`.
//!
//! Before: `127.0.0.1:N`, `ipv4@...`, `abns@x`, `fd@N` and `./x.sock` were accepted and Ibex
//! bound a unix socket *file* with that literal name (AGENTS.md section 5). HAProxy answers:
//!
//! ```text
//! './x.sock'        'stats socket' : missing port specification in './x.sock'
//! 'ipv4@/x'         'stats socket' : missing port specification in 'ipv4@/x'
//! path > 97 bytes   'stats socket' : socket path '<arg>' too long (max 97)   (limit counts after unix@)
//! 'abns@' > 107     'stats socket' : socket path '<arg>' too long (max 107)
//! 'unix@s.sock'     accepted, binds `s.sock` (relative allowed with the prefix)
//! ```
//! `fd@` stats sockets are not implemented in Ibex: the parser refuses them. TCP and abstract
//! sockets are served since T246.

mod common;

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::{NamedTempFile, TempDir};

fn cfg(arg: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tmp");
    write!(f, "global\n\tstats socket {arg}\n").expect("write");
    f
}

/// (exit ok, stderr) of `ibex -c` on a config with one `stats socket <arg>`.
fn check(arg: &str) -> (bool, String) {
    let f = cfg(arg);
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn refused(arg: &str, text: &str) {
    let (ok, err) = check(arg);
    assert!(!ok, "`stats socket {arg}` must be refused, stderr: {err}");
    assert!(err.contains(text), "`stats socket {arg}`: expected {text:?} in: {err}");
}

#[test]
fn a_path_without_a_leading_slash_is_host_port_and_needs_a_port() {
    for a in ["./x.sock", "x.sock", "ipv4@/x", "127.0.0.1"] {
        refused(a, &format!("'stats socket' : missing port specification in '{a}'"));
    }
}

#[test]
fn a_path_over_97_bytes_is_refused_and_97_is_accepted() {
    for pre in ["", "unix@"] {
        let ok = format!("{pre}/{}", "a".repeat(96));
        assert!(check(&ok).0, "97 byte path with prefix {pre:?} must be accepted: {}", check(&ok).1);
        let long = format!("{pre}/{}", "a".repeat(97));
        refused(&long, &format!("'stats socket' : socket path '{long}' too long (max 97)"));
    }
    let long = format!("abns@{}", "a".repeat(108));
    refused(&long, &format!("'stats socket' : socket path '{long}' too long (max 107)"));
}

#[test]
fn forms_ibex_does_not_implement_are_refused_not_bound_as_files() {
    // TCP and abstract sockets are served since T246 (tests/stats_socket_tcp_abns.rs).
    for a in ["fd@3", "sockpair@3"] {
        refused(a, "'stats socket' :");
        let (_, err) = check(a);
        assert!(err.contains("not supported"), "`{a}` should say it is not supported: {err}");
    }
}

#[test]
fn unix_prefix_binds_the_path_without_the_prefix() {
    let dir = TempDir::new().expect("dir");
    let f = cfg("unix@s.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .current_dir(dir.path())
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let end = Instant::now() + Duration::from_secs(10);
    let sock = dir.path().join("s.sock");
    while UnixStream::connect(&sock).is_err() {
        assert!(Instant::now() < end, "s.sock never accepted");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!dir.path().join("unix@s.sock").exists(), "the prefix is not part of the file name");
    common::stop(&mut child);
}

/// T222 item 4 had `typed` and `json` refused; T245 had `typed` and `json` refused; T245 implemented them (populated output is
/// checked against HAProxy in `cli_show_typed_json.rs`). With no proxy at all, HAProxy
/// 3.5 answers `typed` with an empty line and `json` with an empty array (measured).
#[test]
fn show_stat_typed_and_json_with_no_proxy_answer_as_haproxy() {
    use std::io::{Read, Write};
    let dir = TempDir::new().expect("dir");
    let sock = dir.path().join("s.sock");
    let f = cfg(&sock.display().to_string());
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let end = Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(&sock).is_err() {
        assert!(Instant::now() < end, "socket never accepted");
        std::thread::sleep(Duration::from_millis(50));
    }
    let ask = |c: &str| {
        let mut s = UnixStream::connect(&sock).expect("connect");
        s.write_all(format!("{c}\n").as_bytes()).expect("write");
        let mut out = String::new();
        s.read_to_string(&mut out).expect("read");
        out
    };
    for (c, want) in [
        ("show stat typed", "\n"),
        ("show stat -1 1 -1 typed", "\n"),
        ("show stat json", "[]\n\n"),
        ("show stat -1 4 -1 json", "[]\n\n"),
    ] {
        assert_eq!(ask(c), want, "`{c}`");
    }
    assert!(ask("show stat").starts_with("# pxname"), "plain show stat is still CSV");
    common::stop(&mut child);
}
