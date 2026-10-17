// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T329: the `dump_all_vars([<scope>][,<prefix>][,<delimiter>])` sample fetch. Every column except the
//! first is what `HAProxy` 3.5-dev8 answers to the same configuration. The first one (no <scope>) follows
//! configuration.txt, "all these scopes are visited" in the order sess, txn, req, res, proc: the binary
//! dumps only the context's scope there (`txn.a="x", txn.b="z"`), a discrepancy reported upstream.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

const CFG: &str = r#"
defaults
  mode http
  timeout connect 1s
  timeout client 5s
  timeout server 5s
frontend fe
  bind {A}
  http-request set-var(txn.a) str(x)
  http-request set-var(txn.b) str(z)
  http-request set-var(req.n) int(3)
  http-request set-var(sess.s) str(y)
  http-request return status 200 content-type text/plain lf-string "[%[dump_all_vars]|%[dump_all_vars(txn)]|%[dump_all_vars(sess)]|%[dump_all_vars(req)]|%[dump_all_vars(txn,b)]|%[dump_all_vars(txn,,;)]|%[dump_all_vars(res)]]"
"#;

#[test]
fn dump_all_vars_scopes_prefix_and_delimiter() {
    let a = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("ibex-dump-all-vars-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(&path, CFG.replace("{A}", &a.to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _ibex = common::Ibex(child);
    assert!(common::wait_listening(a), "ibex did not listen on {a}");

    let mut s = TcpStream::connect_timeout(&a, Duration::from_secs(2)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").unwrap();
    let mut answer = String::new();
    let _ = s.read_to_string(&mut answer);
    let _ = std::fs::remove_dir_all(&dir);
    let body = answer.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    assert_eq!(
        body,
        r#"[sess.s="y", txn.a="x", txn.b="z", req.n=3|txn.a="x", txn.b="z"|sess.s="y"|req.n=3|txn.b="z"|txn.a="x";txn.b="z"|]"#
    );
}

/// An unknown <scope> is refused when the configuration loads, with `HAProxy`'s words (measured on 3.5-dev8):
/// accepting it would make the fetch answer nothing at run time. T329
#[test]
fn dump_all_vars_unknown_scope_is_refused() {
    let dir = std::env::temp_dir().join(format!("ibex-dump-all-vars-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    let cfg = "defaults\n  mode http\nfrontend fe\n  bind 127.0.0.1:18999\n  http-request return status 200 content-type text/plain lf-string \"%[dump_all_vars(foo)]\"\n";
    std::fs::write(&path, cfg).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(!out.status.success(), "ibex -c accepted dump_all_vars(foo): {text}");
    assert!(
        text.contains("invalid args in fetch method 'dump_all_vars' : invalid scope 'foo', must be one of: sess, txn, req, res, proc."),
        "{text}"
    );
}
