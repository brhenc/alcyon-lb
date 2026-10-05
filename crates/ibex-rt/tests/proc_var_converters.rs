// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The `set-var` and `unset-var` converters on a `proc.` variable change the process's
//! variable, seen by every later stream (T156).
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29, each request on a new connection, `proc.u`
//! set to `start` in `global`:
//!
//! ```text
//!                                       HAProxy        Ibex 8392fff
//! /set   (str(conv),set-var(proc.x))    x=conv u=start x=conv u=start
//! /                                     x=conv u=start x=conv u=start
//! /unset (str(a),unset-var(proc.u))     x=conv u=-     x=conv u=start
//! /                                     x=conv u=-     x=conv u=start
//! ```
//!
//! `unset-var` removed the name from the thread's map of the running stream's variables
//! only, where a `proc.` variable never is.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

/// The `x` and `u` headers of the answer to `GET <path>` on a new connection.
fn get(fe: SocketAddr, path: &str) -> (Option<String>, Option<String>) {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let hdr = |n: &str| {
        out.split("\r\n")
            .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.trim().to_string()))
    };
    (hdr("x"), hdr("u"))
}

#[test]
fn the_var_converters_change_the_process_variable() {
    let dir = tempfile::tempdir().expect("tmp dir");
    let fe = common::reserve_addr();
    let cfg = dir.path().join("ibex.cfg");
    std::fs::write(
        &cfg,
        format!(
            "global\n  nbthread 1\n  set-var proc.u str(start)\n\
             defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 1s\n\
             frontend f\n  bind {fe}\n\
             \x20 http-request set-header x1 %[str(conv),set-var(proc.x)] if {{ path /set }}\n\
             \x20 http-request set-header x2 %[str(a),unset-var(proc.u)] if {{ path /unset }}\n\
             \x20 http-request return status 200 hdr x %[var(proc.x)] hdr u %[var(proc.u)]\n"
        ),
    )
    .expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened on {fe}");
    let got: Vec<_> = ["/set", "/", "/unset", "/"].into_iter().map(|p| (p, get(fe, p))).collect();
    common::stop(&mut child);
    let s = |v: &str| Some(v.to_string());
    let want = [(s("conv"), s("start")), (s("conv"), s("start")), (s("conv"), None), (s("conv"), None)];
    for ((path, got), want) in got.iter().zip(want) {
        assert_eq!(*got, want, "{path}");
    }
}
