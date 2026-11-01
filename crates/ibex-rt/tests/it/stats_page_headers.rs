// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The response headers of the stats page (T571), names, values and order, as measured on
//! HAProxy 3.5-dev8-885761-29 with `stats refresh 7`: `cache-control: no-cache`, then
//! `content-type` (`text/html`, `text/plain` for CSV, `application/json` for JSON), `refresh`,
//! then the framing. All names are lower case. `/s/api/data` is not special in HAProxy (HTML).
//! The admin POST answers (303) are `cache-control`, `content-type: text/plain`,
//! `content-length: 0`, `location`, `connection: close`.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn head_of(fe: std::net::SocketAddr, req: &str) -> Vec<String> {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.write_all(req.as_bytes()).expect("send");
    c.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    let (mut got, mut tmp) = (Vec::new(), [0u8; 8192]);
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        match c.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(k) => got.extend_from_slice(&tmp[..k]),
        }
    }
    let at = got.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(got.len());
    String::from_utf8_lossy(&got[..at]).split("\r\n").map(str::to_string).collect()
}

#[test]
fn stats_page_headers_as_haproxy() {
    let fe = common::reserve_addr();
    let cfg = format!("global\n\nfrontend f\n    mode http\n    bind {fe}\n    timeout client 5s\n    stats enable\n    stats uri /s\n    stats admin if TRUE\n    stats refresh 7\n");
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Ibex).expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
        thread::sleep(Duration::from_millis(20));
    }
    let page = |ct: &str, tail: &[&str]| -> Vec<String> {
        let mut v = vec!["HTTP/1.1 200 OK".to_string(), "cache-control: no-cache".to_string(), format!("content-type: {ct}"), "refresh: 7".to_string()];
        v.extend(tail.iter().map(|s| s.to_string()));
        v
    };
    let chunked = ["transfer-encoding: chunked", "connection: close"];
    let redir = |st: &str| -> Vec<String> {
        ["HTTP/1.1 303 See Other", "cache-control: no-cache", "content-type: text/plain", "content-length: 0"].iter().map(|s| s.to_string()).chain([format!("location: /s;st={st}"), "connection: close".to_string()]).collect()
    };
    let close11 = "HTTP/1.1\r\nHost: x\r\nConnection: close\r\n";
    let cases: Vec<(&str, String, Vec<String>)> = vec![
        ("html", format!("GET /s {close11}\r\n"), page("text/html", &chunked)),
        ("csv", format!("GET /s;csv {close11}\r\n"), page("text/plain", &chunked)),
        // Not measured as HAProxy: `;json` (its JSON stats format) is not implemented here and
        // answers the HTML page; `/api/data` is the Ibex dashboard's own endpoint (HAProxy
        // answers HTML), kept, with the same header style.
        ("api/data", format!("GET /s/api/data {close11}\r\n"), page("application/json", &chunked)),
        ("csv 1.0", "GET /s;csv HTTP/1.0\r\n\r\n".to_string(), page("text/plain", &["connection: close"])),
        ("post noop", format!("POST /s {close11}Content-Length: 3\r\n\r\nx=y"), redir("NONE")),
        ("post empty", format!("POST /s {close11}\r\n"), redir("NONE")),
    ];
    let mut bad = Vec::new();
    for (name, req, want) in &cases {
        let got = head_of(fe, req);
        if &got != want {
            bad.push(format!("{name}: got {got:?}\n      want {want:?}"));
        }
    }
    common::stop(&mut child);
    assert!(bad.is_empty(), "{} cases differ from HAProxy:\n{}", bad.len(), bad.join("\n"));
}
