// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A condition with no term in it (T144b 12). `HAProxy 3.5-dev8-885761-29` accepts
//! `http-request deny if` and answered `GET /x` with:
//!
//! ```text
//! deny if                    200      deny unless                403
//! deny if ||                 200      deny if !                  200
//! deny unless !              403      deny if { path /x } ||     403
//! deny unless { path /y } || 403      deny unless { path /x } || 200
//! deny if || { path /x }     403
//! capture ... len 5 if / capture ... len 4 unless, with x: abcdefghij and y: wxyz123,
//!                            hr={|wxyz}   (the `if` one is not applied, the `unless` one is)
//! ```
//!
//! An empty condition has no alternative that holds: `if` is false and `unless` true, and an
//! empty alternative next to a real one (`{ ... } ||`) counts for nothing. Ibex had it the
//! other way round: `deny if` denied every request.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Ibex(Child, NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                if c.read(&mut buf).is_ok() {
                    let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                }
                thread::sleep(Duration::from_millis(200));
            });
        }
    });
    addr
}

fn start(rules: &str, log: Option<&UdpSocket>) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let logging = log.map_or(String::new(), |l| format!("  log {} local0\n  log-format \"hr=%hr\"\n", l.local_addr().expect("addr")));
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n{logging}{rules}  default_backend be\nbackend be\n  server s {}\n",
        server()
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex(child, f);
    assert!(common::wait_listening(fe), "ibex never listened with:\n{cfg}");
    (ibex, fe)
}

fn get(fe: SocketAddr, headers: &str) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).ok();
    write!(c, "GET /x HTTP/1.1\r\nHost: a\r\n{headers}Connection: close\r\n\r\n").expect("send");
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn a_condition_without_a_term_has_no_alternative_that_holds() {
    let cases = [
        ("deny if", "200"),
        ("deny unless", "403"),
        ("deny if ||", "200"),
        ("deny if !", "200"),
        ("deny unless !", "403"),
        ("deny if { path /x } ||", "403"),
        ("deny unless { path /y } ||", "403"),
        ("deny unless { path /x } ||", "200"),
        ("deny if || { path /x }", "403"),
    ];
    for (rule, status) in cases {
        let (_ibex, fe) = start(&format!("  http-request {rule}\n"), None);
        let got = get(fe, "");
        assert!(got.starts_with(&format!("HTTP/1.1 {status}")), "http-request {rule}: wanted {status}, got {got:?}");
    }
}

#[test]
fn a_capture_with_an_empty_if_is_not_applied_and_with_an_empty_unless_is_() {
    let logs = UdpSocket::bind("127.0.0.1:0").expect("log socket");
    logs.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let rules = "  http-request capture req.hdr(x) len 5 if\n  http-request capture req.hdr(y) len 4 unless\n";
    let (_ibex, fe) = start(rules, Some(&logs));
    let got = get(fe, "x: abcdefghij\r\ny: wxyz123\r\n");
    assert!(got.starts_with("HTTP/1.1 200"), "{got:?}");
    let mut buf = [0u8; 2048];
    loop {
        let n = logs.recv(&mut buf).expect("a log line");
        let line = String::from_utf8_lossy(&buf[..n]).into_owned();
        // The line of the harness's probe connection has no captures.
        if let Some(at) = line.find("hr=") {
            if line[at..].trim_end() == "hr=" {
                continue;
            }
            assert_eq!(line[at..].trim_end(), "hr={|wxyz}");
            return;
        }
    }
}
