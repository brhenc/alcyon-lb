// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! CLI `get var` reads the process-wide variables only (T156).
//!
//! `vars_parse_cli_get_var` (src/vars.c) looks the name up in the `proc` scope and nowhere
//! else: the CLI has no stream, so a `txn.`, `sess.` or `req.` name is never found. Ibex
//! read those from the thread's `CURRENT_VARS`, the variables of whatever stream was
//! running. Measured on `HAProxy` 3.5-dev8-885761-29, one command per connection, after a
//! request that set `txn.x` and `sess.y`:
//!
//! ```text
//! get var proc.a   proc.a: type=str value=<hello>\n\n
//! get var txn.x    Variable not found.\n\n           (sess.y, req.z, foo: the same)
//! get var          Missing process-wide variable identifier.\n\n
//! ```
//!
//! Ibex 8392fff answered each without the closing empty line, and `get var` alone with
//! "Unknown command".

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
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
fn get_var_answers_from_the_process_scope_only() {
    let dir = tempfile::tempdir().expect("tmp dir");
    let sock = dir.path().join("cli.sock");
    let fe = common::reserve_addr();
    let cfg = dir.path().join("ibex.cfg");
    std::fs::write(
        &cfg,
        format!(
            "global\n  stats socket {} level admin\n  set-var proc.a str(hello)\n\
             defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 1s\n\
             frontend f\n  bind {fe}\n  http-request set-var(txn.x) str(1)\n  http-request set-var(sess.y) str(2)\n\
             \x20 http-request return status 200\n",
            sock.display()
        ),
    )
    .expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Ibex)
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened on {fe}");
    // A stream that set txn.x and sess.y, kept open while the CLI is asked.
    let mut c = TcpStream::connect(fe).expect("connect");
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    let mut buf = [0u8; 256];
    let _ = c.read(&mut buf);

    let got: Vec<(&str, String)> = ["get var proc.a", "get var txn.x", "get var sess.y", "get var req.z", "get var foo", "get var"]
        .into_iter()
        .map(|cmd| (cmd, ask(&sock, cmd)))
        .collect();
    common::stop(&mut child);
    let want = [
        "proc.a: type=str value=<hello>\n\n",
        "Variable not found.\n\n",
        "Variable not found.\n\n",
        "Variable not found.\n\n",
        "Variable not found.\n\n",
        "Missing process-wide variable identifier.\n\n",
    ];
    for ((cmd, got), want) in got.iter().zip(want) {
        assert_eq!(got, want, "{cmd}");
    }
}
