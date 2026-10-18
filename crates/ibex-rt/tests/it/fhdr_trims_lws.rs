// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T363n: `res.fhdr` gives a header line without its leading and trailing spaces
//! (`__http_find_header` skips LWS both sides, full or not), even when `set-header` stored them.
//! The wire keeps them: `http_after_response.vtc` hashes `%[res.fhdr(sl1)]`.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn res_fhdr_trims_lws_but_wire_keeps_it() {
    let be = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let be_addr = be.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in be.incoming() {
            let Ok(mut c) = c else { continue };
            let mut b = [0u8; 4096];
            let _ = c.read(&mut b);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
    });
    let a = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("t363n-fhdr-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    // Measured on HAProxy 3.5-dev8: b on the wire is " e f " (spaces kept); x-out is
    // "[e f|e f|3]"; y-out "[e f]"; the line set by after-response is trimmed the same way.
    std::fs::write(
        &path,
        format!(
            "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind {a}\n  default_backend b\n  \
             http-response set-header b \" e f \"\n  \
             http-response set-header x-out \"[%[res.fhdr(b)]|%[res.hdr(b)]|%[res.fhdr(b),length]]\"\n  \
             http-after-response set-header c \" g \"\n  \
             http-after-response set-header y-out \"[%[res.fhdr(c)]]\"\n\
             backend b\n  server s {be_addr}\n"
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    assert!(common::wait_listening(a));
    let mut s = TcpStream::connect(a).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    common::stop(&mut child);
    let _ = std::fs::remove_dir_all(&dir);
    let out = String::from_utf8_lossy(&out);
    assert!(out.contains("\r\nb:  e f \r\n"), "wire keeps the spaces: {out:?}");
    assert!(out.contains("\r\nx-out: [e f|e f|3]\r\n"), "{out:?}");
    assert!(out.contains("\r\ny-out: [g]\r\n"), "{out:?}");
}
