// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A regex that refers to a capture group it does not have is refused when the
//! configuration loads, and on the CLI, wherever the configuration can hold a regex (T277,
//! V&V VV-3). Before this, `(?(2))` passed `ibex -c` and the first request or health check
//! that evaluated it aborted the whole process (a panic inside `fancy-regex`).
//!
//! Measured against `HAProxy` 3.5-dev8-885761-29, 2026-10-11:
//!
//! * `haproxy -c` refuses `(?(2))` in every context below, exit 1, with
//!   `regex '(?(2))' is invalid (error=reference to non-existent subpattern, erroffset=2).`
//!   (`path_reg`, `-m reg`, `hdr_reg`, `-f` pattern file, `map_reg` file, `replace-path`,
//!   `replace-uri`, `replace-header`, `replace-value`, `http-response replace-header`,
//!   `http-check expect rstring`/`rstatus`, `tcp-check expect rstring`).
//! * The CLI answers `add map <m> (?(2)) v` and `add acl <a> (?(2))` with the same
//!   `regex '(?(2))' is invalid (error=reference to non-existent subpattern, erroffset=2).`
//!   and adds nothing.
//! * Accepted where groups capture: `replace-path (a)(?(1)x) y`, `replace-path (?(1)a)(b) y`.
//!
//! `T277_ORACLE=<haproxy binary>` runs the load assertions against that binary instead.

use crate::common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const NONEXISTENT: &str = "reference to non-existent subpattern";

fn binary() -> String {
    std::env::var("T277_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string())
}

fn tmp(tag: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("ibex_t277_{}_{n}_{tag}", std::process::id()))
}

/// `-c` on a configuration with `fe_line` in the frontend and `be_lines` in a backend that
/// health-checks. `file` is written first, and its path replaces `FILE` in the lines.
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
    let out = Command::new(binary()).arg("-c").arg("-f").arg(&path).output().expect("run -c");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&f);
    (out.status.code(), format!("{cfg}\n---\n{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

const MISSING: &[&str] = &["(?(2))", "(?(2)a|b)", "(?(1)a|b)", "(a)(?(2)x)"];

#[test]
fn a_conditional_on_a_missing_group_is_refused_in_every_rule() {
    let fe: &[&str] = &[
        "http-request deny if { path_reg P }",
        "http-request deny if { path -m reg P }",
        "http-request deny if { hdr_reg(host) P }",
        "http-request redirect location /x if { hdr_reg(host) P }",
        "http-request replace-path P x",
        "http-request replace-uri P x",
        "http-request replace-header h P x",
        "http-request replace-value h P x",
        "http-response replace-header h P x",
    ];
    for pat in MISSING {
        for line in fe {
            let (code, out) = check(&line.replace('P', pat), "", None);
            assert_eq!(code, Some(1), "`{line}` with `{pat}` must be refused:\n{out}");
            assert!(out.contains(NONEXISTENT), "`{line}` with `{pat}`: expected {NONEXISTENT:?}:\n{out}");
        }
    }
}

#[test]
fn a_conditional_on_a_missing_group_is_refused_in_health_checks() {
    for pat in MISSING {
        for be in [
            format!("  option httpchk\n  http-check expect rstring {pat}\n"),
            format!("  option httpchk\n  http-check expect rstatus {pat}\n"),
            format!("  option tcp-check\n  tcp-check connect\n  tcp-check expect rstring {pat}\n"),
        ] {
            let (code, out) = check("http-request set-var(txn.a) str(a)", &be, None);
            assert_eq!(code, Some(1), "`{be}` must be refused:\n{out}");
            assert!(out.contains(NONEXISTENT), "`{be}`: expected {NONEXISTENT:?}:\n{out}");
        }
    }
}

#[test]
fn a_conditional_on_a_missing_group_is_refused_in_pattern_and_map_files() {
    for pat in MISSING {
        for (line, content) in [
            ("http-request deny if { path_reg -f FILE }", format!("{pat}\n")),
            ("http-request set-var(txn.x) path,map_reg(FILE)", format!("{pat} v\n")),
        ] {
            let (code, out) = check(line, "", Some(&content));
            assert_eq!(code, Some(1), "`{line}` with `{pat}` must be refused:\n{out}");
            assert!(out.contains(NONEXISTENT), "`{line}` with `{pat}`: expected {NONEXISTENT:?}:\n{out}");
        }
    }
}

#[test]
fn a_conditional_on_a_group_that_exists_loads() {
    for line in ["http-request replace-path (a)(?(1)x) y", "http-request replace-path (?(1)a)(b) y"] {
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

#[test]
fn the_cli_refuses_a_conditional_on_a_missing_group_and_the_process_lives() {
    let (sock, cfg, map, acl) = (tmp("sock"), tmp("cfg"), tmp("map"), tmp("acl"));
    std::fs::write(&map, "^/x v\n").expect("map");
    std::fs::write(&acl, "^/y\n").expect("acl");
    let fe = common::reserve_addr();
    let text = format!(
        "global\n  stats socket {} mode 600 level admin\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
         frontend f\n  bind {fe}\n  http-request deny if {{ path_reg -f {} }}\n\
         http-request return status 200 hdr x-m %[path,map_reg({},none)]\n",
        sock.display(),
        acl.display(),
        map.display()
    );
    std::fs::write(&cfg, &text).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let mut ibex = Ibex { child, sock: sock.clone(), files: vec![cfg, map.clone(), acl.clone(), sock] };
    assert!(common::wait_listening(fe), "ibex never listened with:\n{text}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ibex.sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let want = format!("regex '(?(2))' is invalid (error={NONEXISTENT}");
    let out = cli(&ibex.sock, &format!("add map {} (?(2)) v\n", map.display()));
    assert!(out.contains(&want), "add map: {out:?}");
    let out = cli(&ibex.sock, &format!("add acl {} (?(2))\n", acl.display()));
    assert!(out.contains(&want), "add acl: {out:?}");
    let out = cli(&ibex.sock, &format!("show map {}\n", map.display()));
    assert!(!out.contains("(?(2))"), "nothing added to the map: {out:?}");
    let out = cli(&ibex.sock, &format!("show acl {}\n", acl.display()));
    assert!(!out.contains("(?(2))"), "nothing added to the acl: {out:?}");

    // Requests through both lists: the process is alive and answers.
    for path in ["/x", "/abc", "/y"] {
        let mut s = std::net::TcpStream::connect(fe).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        let _ = s.write_all(format!("GET {path} HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n").as_bytes());
        let mut resp = String::new();
        let _ = s.read_to_string(&mut resp);
        assert!(resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.1 403"), "{path}: {resp:?}");
    }
    assert!(ibex.child.try_wait().expect("try_wait").is_none(), "ibex exited");
}
