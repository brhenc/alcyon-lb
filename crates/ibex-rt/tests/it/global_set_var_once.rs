// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `set-var` / `set-var-fmt` lines of `global` run once per process, before any thread
//! serves. Ibex ran them again in every worker as it was built, at the same time: a
//! `set-var-fmt` reading the variable it sets then saw what another worker had already
//! appended (`sample_fetches/vars.vtc` failed 1 run in 10 with `str=this is a string a
//! string`).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29`: `global` with `nbthread 4` and
//! `set-var-fmt proc.s "%[var(proc.s)]x"` (no earlier `proc.s`), then
//! `http-request return ... hdr x-s "%[var(proc.s)]"`: `x-s: x`. Ibex answered `xx`.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};

fn x_s(nbthread: usize) -> String {
    let fe = common::reserve_addr();
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    write!(
        f,
        "global\n  nbthread {nbthread}\n  set-var-fmt proc.s \"%[var(proc.s)]x\"\n\
         defaults\n  mode http\n  timeout client 5s\n  timeout connect 1s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  http-request return status 200 hdr x-s \"%[var(proc.s)]\"\n"
    )
    .expect("cfg");
    let _ibex = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Ibex)
        .expect("spawn");
    assert!(common::wait_listening(fe));
    let mut s = TcpStream::connect(fe).expect("connect");
    s.write_all(b"GET / HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n").expect("send");
    let mut resp = String::new();
    s.read_to_string(&mut resp).expect("read");
    resp.split("\r\n")
        .find_map(|l| l.split_once(": ").filter(|(n, _)| n.eq_ignore_ascii_case("x-s")).map(|(_, v)| v.to_string()))
        .unwrap_or_else(|| resp.lines().next().unwrap_or("<nothing>").to_string())
}

#[test]
fn global_set_var_fmt_runs_once_whatever_the_thread_count() {
    for nbthread in [1, 4, 16] {
        assert_eq!(x_s(nbthread), "x", "nbthread {nbthread}");
    }
}
