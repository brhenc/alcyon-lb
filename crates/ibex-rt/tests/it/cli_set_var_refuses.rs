// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The CLI's `set var proc.<name> expr <expression>` refuses an expression that does not parse
//! and leaves the variable alone; it used to store the text of the expression as a string.
//! Measured on HAProxy 3.5-dev8 (`experimental-mode on;set var ...` on the stats socket): an
//! unknown fetch answers `unknown fetch method 'nosuchfetch'`, an unknown converter `unknown
//! converter 'nosuchconv'`, `1 +` answers `unknown fetch method '1'`; `get var` then says
//! `Variable not found.`

use crate::common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::Duration;

fn ask(sock: &std::path::Path, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect cli");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn set_var_with_an_expression_that_does_not_parse_is_refused() {
    let dir = tempfile::tempdir().expect("tmp dir");
    let sock = dir.path().join("cli.sock");
    let fe = common::reserve_addr();
    let cfg = dir.path().join("ibex.cfg");
    std::fs::write(
        &cfg,
        format!(
            "global\n  stats socket {} level admin\n\
             defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 1s\n\
             frontend f\n  bind {fe}\n  http-request return status 200\n",
            sock.display()
        ),
    )
    .expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Ibex)
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened on {fe}");

    for (cmd, want) in [
        ("set var proc.x expr nosuchfetch", "unknown fetch method 'nosuchfetch'"),
        ("set var proc.x expr str(a),nosuchconv", "unknown converter 'nosuchconv'"),
        ("set var proc.x nosuchfetch", "unknown fetch method 'nosuchfetch'"),
    ] {
        let got = ask(&sock, &format!("experimental-mode on;{cmd}"));
        assert!(got.contains(want), "{cmd}: expected `{want}` in {got:?}");
        assert_eq!(ask(&sock, "get var proc.x"), "Variable not found.\n\n", "{cmd}: nothing was stored");
    }
    common::stop(&mut child);
}

/// The same in the global section: `set-var proc.x nosuchfetch` is refused when the configuration
/// loads (HAProxy: `parsing [g.cfg:2] : unknown fetch method 'nosuchfetch'`, exit 1); Ibex
/// started and stored the text of the expression.
#[test]
fn global_set_var_with_an_unknown_fetch_or_converter_is_refused_at_load() {
    let dir = tempfile::tempdir().expect("tmp dir");
    for (expr, want) in [("nosuchfetch", "unknown fetch method 'nosuchfetch'"), ("str(a),nosuchconv", "unknown converter 'nosuchconv'")] {
        let cfg = dir.path().join("ibex.cfg");
        std::fs::write(&cfg, format!("global\n  set-var proc.x {expr}\nfrontend f\n  mode http\n  bind 127.0.0.1:1\n")).expect("write cfg");
        let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&cfg).output().expect("run ibex -c");
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(!out.status.success(), "{expr}: accepted: {text}");
        assert!(text.contains(want), "{expr}: expected `{want}` in {text}");
    }
}
