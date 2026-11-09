// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T363i: a `log-format` keeps its trailing blanks, as `HAProxy` 3.5-dev8 does (measured with
//! `log stdout format raw` and `log-format "%ci x "`: the line is `127.0.0.1 x ` with the space;
//! reg-test `log/log_filtering.vtc`). Alcyon dropped them.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn a_log_format_keeps_its_trailing_blank() {
    let addr = common::reserve_addr();
    let cfg = format!(
        "global\n  log stdout format raw local0\ndefaults\n  mode http\n  log global\n  timeout client 2s\n  timeout server 2s\n  timeout connect 2s\n\
         frontend f\n  bind {addr}\n  log-format \"%ci x \"\n  http-request return status 200 content-type text/plain lf-string ok\n"
    );
    let path = std::env::temp_dir().join(format!("alcyon-t363i-{}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write cfg");
    let mut alcyon = common::Alcyon(
        Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-db").arg("-f").arg(&path).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn alcyon"),
    );
    assert!(common::wait_listening(addr), "alcyon did not listen");
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").expect("send");
    let mut d = Vec::new();
    let _ = s.read_to_end(&mut d);
    std::thread::sleep(Duration::from_millis(300));
    common::stop(&mut alcyon);
    let mut out = String::new();
    let _ = alcyon.0.stdout.take().expect("stdout").read_to_string(&mut out);
    let _ = std::fs::remove_file(&path);
    assert!(out.lines().any(|l| l == "127.0.0.1 x "), "{out:?}");
}
