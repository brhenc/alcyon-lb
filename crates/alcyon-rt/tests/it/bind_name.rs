// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `bind ... name <n>` names the listener: `so_name` reads it back on connections it
//! accepted, and a bind without a name has none (HAProxy 3.5-dev8: the `so-name` header is
//! left out for the unnamed bind).

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

fn get(addr: std::net::SocketAddr) -> String {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn so_name_reads_the_bind_name() {
    let (a, b, c) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {a} name foo\n  bind {b}\n  bind {c} name bar\n\
         \x20 http-request return status 200 hdr so-name %[so_name]\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Alcyon)
        .expect("spawn");
    assert!(common::wait_listening(a));
    let (ra, rb, rc) = (get(a), get(b), get(c));
    common::stop(&mut child);
    assert!(ra.to_ascii_lowercase().contains("so-name: foo\r\n"), "{ra}");
    assert!(!rb.to_ascii_lowercase().contains("so-name:"), "{rb}");
    assert!(rc.to_ascii_lowercase().contains("so-name: bar\r\n"), "{rc}");
}
