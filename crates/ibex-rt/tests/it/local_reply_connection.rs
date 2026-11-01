// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The `Connection` header of a locally generated response, and whether the connection stays
//! open (T563). Measured on HAProxy 3.5-dev8-885761-29 (`tasks/T563-progress.md`): an HTTP/1.0
//! client sending `Connection: Keep-Alive` is answered `connection: keep-alive` (`ab -k` waits
//! for it, or for the close) by `http-request return`, `deny` and `redirect`; without it `close`;
//! an HTTP/1.1 client gets nothing, or `close` when it asked for it; `option httpclose` closes
//! all; an `errorfile` page that says `HTTP/1.0` carries no `Connection` and closes.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// `(client version, client Connection token)`, the connection headers the client gets, and
/// whether the connection is still open.
type Want = (&'static str, Option<&'static str>, &'static [&'static str], bool);

const KEEP: &[Want] = &[
    ("1.0", None, &["connection: close"], false),
    ("1.0", Some("Keep-Alive"), &["connection: keep-alive"], true),
    ("1.0", Some("close"), &["connection: close"], false),
    ("1.1", None, &[], true),
    ("1.1", Some("close"), &["connection: close"], false),
];
const CLOSE: &[Want] = &[
    ("1.0", None, &["connection: close"], false),
    ("1.0", Some("Keep-Alive"), &["connection: close"], false),
    ("1.0", Some("close"), &["connection: close"], false),
    ("1.1", None, &["connection: close"], false),
    ("1.1", Some("close"), &["connection: close"], false),
];
const ERRORFILE: &[Want] = &[
    ("1.0", None, &[], false),
    ("1.0", Some("Keep-Alive"), &[], false),
    ("1.1", None, &[], false),
    ("1.1", Some("close"), &[], false),
];

fn get(fe: SocketAddr, ver: &str, token: Option<&str>) -> (Vec<String>, bool) {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    let host = if ver == "1.1" { "Host: x\r\n" } else { "" };
    let conn = token.map_or(String::new(), |t| format!("Connection: {t}\r\n"));
    write!(c, "GET / HTTP/{ver}\r\n{host}{conn}\r\n").expect("send");
    let mut got = Vec::new();
    let mut tmp = [0u8; 2048];
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        match c.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(k) => got.extend_from_slice(&tmp[..k]),
        }
    }
    // The bodies are small and arrive with the head; what comes later is the close, or nothing.
    c.set_read_timeout(Some(Duration::from_millis(600))).expect("timeout");
    let open = loop {
        match c.read(&mut tmp) {
            Ok(0) => break false,
            Ok(_) => {}
            Err(e) => break matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
        }
    };
    let lines = String::from_utf8_lossy(&got).to_ascii_lowercase().split("\r\n").skip(1).take_while(|l| !l.is_empty()).filter(|l| l.starts_with("connection:")).map(str::to_string).collect();
    (lines, open)
}

#[test]
fn local_responses_say_connection_as_haproxy_does() {
    let mut page = NamedTempFile::new().expect("tmp");
    page.write_all(b"HTTP/1.0 503 Service Unavailable\r\nCache-Control: no-cache\r\nContent-Type: text/plain\r\n\r\nerr503\n").expect("write page");
    // (listener name, rules, expected rows)
    let cases: Vec<(&str, String, &[Want])> = vec![
        ("return", "http-request return status 200 content-type text/plain string hello".into(), KEEP),
        ("deny", "http-request deny".into(), KEEP),
        ("redirect", "http-request redirect location /x".into(), KEEP),
        ("return_httpclose", "option httpclose\n    http-request return status 200 content-type text/plain string hello".into(), CLOSE),
        ("return_server_close", "option http-server-close\n    http-request return status 200 content-type text/plain string hello".into(), KEEP),
        ("errorfile", format!("http-request return status 503 errorfile {}", page.path().display()), ERRORFILE),
    ];
    let mut cfg = String::from("global\n\n");
    let fes: Vec<SocketAddr> = cases.iter().map(|_| common::reserve_addr()).collect();
    for ((name, rules, _), fe) in cases.iter().zip(&fes) {
        cfg += &format!("frontend {name}\n    mode http\n    bind {fe}\n    timeout client 5s\n    {rules}\n\n");
    }
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Ibex).expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    for fe in &fes {
        while TcpStream::connect(fe).is_err() {
            assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
            thread::sleep(Duration::from_millis(20));
        }
    }
    let mut bad = Vec::new();
    thread::scope(|sc| {
        let jobs: Vec<_> = cases
            .iter()
            .zip(&fes)
            .flat_map(|((name, _, rows), fe)| rows.iter().map(move |r| (*name, *fe, *r)))
            .map(|(name, fe, (ver, tok, want, want_open))| sc.spawn(move || (name, ver, tok, want, want_open, get(fe, ver, tok))))
            .collect();
        for j in jobs {
            let (name, ver, tok, want, want_open, (lines, open)) = j.join().expect("client");
            if lines != want || open != want_open {
                bad.push(format!("{name}: HTTP/{ver} {tok:?}: got {lines:?} open {open}, want {want:?} open {want_open}"));
            }
        }
    });
    common::stop(&mut child);
    assert!(bad.is_empty(), "{} cases differ from HAProxy:\n{}", bad.len(), bad.join("\n"));
}
