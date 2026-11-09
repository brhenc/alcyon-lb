// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The `duress_target` binary serves HTTP/3 through the engine's frontend (T463): a request
//! to it reaches the backend given as its second argument.
//!
//! SIGUSR1 (what `common::stop` sends first) makes it leave its loop and exit normally, so the
//! process writes its coverage profile; the test checks it exits by itself with status 0.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[test]
fn duress_target_proxies_an_h3_request_to_its_backend() {
    let have_h3 = Command::new("curl")
        .arg("--version")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("HTTP3"));
    assert!(have_h3, "this test needs a curl with HTTP/3; it fails rather than skips");

    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let backend = l.local_addr().expect("addr");
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut c) = s else { continue };
            let mut buf = [0u8; 4096];
            let _ = c.set_read_timeout(Some(Duration::from_millis(500)));
            let _ = c.read(&mut buf);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nfrom-be-T463");
        }
    });

    let port = common::reserve_addr().port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_duress_target"))
        .arg(port.to_string())
        .arg(backend.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn duress_target");
    // It prints the port once the engine is built.
    let mut out = child.stdout.take().expect("stdout");
    let mut line = [0u8; 16];
    let n = out.read(&mut line).expect("read port line");
    assert_eq!(String::from_utf8_lossy(&line[..n]).trim(), port.to_string());

    let res = Command::new("curl")
        .args(["-sS", "--http3-only", "-k", "--max-time", "10", "--resolve"])
        .arg(format!("localhost:{port}:127.0.0.1"))
        .arg(format!("https://localhost:{port}/x"))
        .output()
        .expect("curl");
    common::stop(&mut child);
    let status = child.wait().expect("wait");
    assert!(status.success(), "SIGUSR1 must end duress_target normally, got {status:?}");
    let body = String::from_utf8_lossy(&res.stdout);
    assert!(
        body.contains("from-be-T463"),
        "the backend's answer must arrive.\nstdout: {body}\nstderr: {}",
        String::from_utf8_lossy(&res.stderr)
    );
}
