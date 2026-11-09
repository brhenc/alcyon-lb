// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `%U` of a request whose head `HAProxy` changes while it parses it (T522): an `Upgrade`
//! header loses its `h2c` and `h2` words (and goes when none is left), and a `Host` header or
//! an absolute URI loses the port of its scheme's default (`:80`; `:443` for CONNECT).
//! Each expected value, and the head the server gets, was measured on `HAProxy` 3.5-dev8.

use crate::common;

use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Sends `req` through a proxy that logs `%U`; returns the `%U` and the head the server got.
fn exchange(req: &[u8], resp: &'static [u8]) -> (String, String) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let be = l.local_addr().unwrap();
    let (got_tx, got_rx) = mpsc::channel();
    thread::spawn(move || {
        let Ok((mut s, _)) = l.accept() else { return };
        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
        let mut got = Vec::new();
        let mut b = [0u8; 4096];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            match s.read(&mut b) {
                Ok(n) if n > 0 => got.extend_from_slice(&b[..n]),
                _ => return,
            }
        }
        let _ = s.write_all(resp);
        let _ = got_tx.send(String::from_utf8_lossy(&got).into_owned());
        thread::sleep(Duration::from_millis(300));
    });
    let port = common::reserve_port();
    let dir = tempfile::tempdir().expect("dir");
    let cfg = dir.path().join("alcyon.cfg");
    std::fs::write(
        &cfg,
        format!(
            "global\n  tune.alcyon.h1-lowercase-headers on\n\tlog stdout format raw local0\n\
             defaults\n\tmode http\n\tlog global\n\ttimeout connect 3s\n\ttimeout client 5s\n\ttimeout server 5s\n\ttimeout tunnel 5s\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tlog-format \"ST=%ST U=%U\"\n\tdefault_backend be\n\
             backend be\n\tserver s1 {be}\n"
        ),
    )
    .expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&cfg).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn");
    let out = child.stdout.take().expect("stdout");
    let (tx, logs) = mpsc::channel();
    thread::spawn(move || {
        for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    assert!(common::wait_listening(([127, 0, 0, 1], port).into()), "never listened");
    let mut c = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    c.write_all(req).unwrap();
    let wire = got_rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    let _ = c.set_read_timeout(Some(Duration::from_millis(500)));
    let mut b = [0u8; 4096];
    let _ = c.read(&mut b);
    drop(c);
    // The probe of `wait_listening` read no request: `U=0`.
    let line = std::iter::from_fn(|| logs.recv_timeout(Duration::from_secs(3)).ok()).find(|l| !l.ends_with(" U=0")).expect("the stream is logged");
    common::stop(&mut child);
    (line, wire)
}

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
const OK_TUNNEL: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n";

fn get(upgrade_lines: &str, connection: &str) -> Vec<u8> {
    format!("GET / HTTP/1.1\r\nHost: x\r\n{upgrade_lines}{connection}\r\n").into_bytes()
}

#[track_caller]
fn expect(req: &[u8], resp: &'static [u8], line: &str, wire: &str) {
    let (got_line, got_wire) = exchange(req, resp);
    assert_eq!(got_line, line, "log of {:?}", String::from_utf8_lossy(req));
    assert_eq!(got_wire, wire, "head the server got for {:?}", String::from_utf8_lossy(req));
}

#[test]
fn an_h2c_only_upgrade_is_not_counted() {
    expect(&get("Upgrade: h2c\r\n", "Connection: upgrade\r\n"), OK, "ST=200 U=38", "GET / HTTP/1.1\r\nhost: x\r\n\r\n");
    expect(&get("Upgrade: h2c\r\n", "Connection: upgrade, keep-alive\r\n"), OK, "ST=200 U=38", "GET / HTTP/1.1\r\nhost: x\r\n\r\n");
    expect(&get("Upgrade: h2c, h2\r\n", "Connection: upgrade\r\n"), OK, "ST=200 U=38", "GET / HTTP/1.1\r\nhost: x\r\n\r\n");
}

#[test]
fn an_upgrade_loses_its_h2_words_and_keeps_the_rest() {
    let wire = "GET / HTTP/1.1\r\nhost: x\r\nupgrade: foo\r\nconnection: upgrade\r\n\r\n";
    expect(&get("Upgrade: foo, h2c\r\n", "Connection: upgrade\r\n"), OK, "ST=200 U=65", wire);
    expect(&get("Upgrade: h2c,foo\r\n", "Connection: upgrade\r\n"), OK, "ST=200 U=65", wire);
    expect(&get("Upgrade: h2c\r\nUpgrade: foo\r\n", "Connection: upgrade\r\n"), OK, "ST=200 U=65", wire);
    // The blank after the first word stays, as in HAProxy's rewrite in place.
    expect(&get("Upgrade: foo , h2c , bar\r\n", "Connection: upgrade\r\n"), OK, "ST=200 U=70", "GET / HTTP/1.1\r\nhost: x\r\nupgrade: foo ,bar\r\nconnection: upgrade\r\n\r\n");
}

#[test]
fn an_empty_upgrade_goes_with_the_connection_token() {
    expect(&get("Upgrade:\r\n", "Connection: upgrade\r\n"), OK, "ST=200 U=38", "GET / HTTP/1.1\r\nhost: x\r\n\r\n");
}

#[test]
fn the_http2_settings_of_an_h2c_upgrade_stay() {
    let req = get("Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n", "Connection: Upgrade, HTTP2-Settings\r\n");
    expect(&req, OK, "ST=200 U=92", "GET / HTTP/1.1\r\nhost: x\r\nhttp2-settings: AAMAAABkAAQAAP__\r\nconnection: HTTP2-Settings\r\n\r\n");
}

#[test]
fn a_connect_authority_and_host_lose_the_default_port() {
    let w = |h: &str| format!("CONNECT {h} HTTP/1.1\r\nhost: {}\r\n\r\n", h.split(':').next().unwrap());
    let req = |h: &str| format!("CONNECT {h} HTTP/1.1\r\nHost: {h}\r\n\r\n").into_bytes();
    expect(&req("example.com:443"), OK_TUNNEL, "ST=200 U=66", &w("example.com:443"));
    expect(&req("example.com:80"), OK_TUNNEL, "ST=200 U=65", &w("example.com:80"));
    expect(&req("a.b:443"), OK_TUNNEL, "ST=200 U=50", &w("a.b:443"));
    expect(&req("[::1]:443"), OK_TUNNEL, "ST=200 U=54", "CONNECT [::1]:443 HTTP/1.1\r\nhost: [::1]\r\n\r\n");
    // Another port is kept.
    expect(&req("example.com:8080"), OK_TUNNEL, "ST=200 U=72", "CONNECT example.com:8080 HTTP/1.1\r\nhost: example.com:8080\r\n\r\n");
}

#[test]
fn an_absolute_uri_and_host_lose_the_port_80() {
    expect(
        b"GET http://example.com:80/ HTTP/1.1\r\nHost: example.com:80\r\n\r\n",
        OK,
        "ST=200 U=66",
        "GET http://example.com/ HTTP/1.1\r\nhost: example.com\r\n\r\n",
    );
    expect(
        b"GET https://example.com:443/ HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        OK_TUNNEL,
        "ST=200 U=67",
        "GET https://example.com/ HTTP/1.1\r\nhost: example.com\r\n\r\n",
    );
}

#[test]
fn a_repeated_host_an_empty_path_and_a_content_length_beside_chunked_are_counted_as_parsed() {
    // Before: U=43, U=65 and U=79 (the head as received).
    expect(b"GET / HTTP/1.1\r\nHost: x\r\nHost: x\r\n\r\n", OK, "ST=200 U=38", "GET / HTTP/1.1\r\nhost: x\r\n\r\n");
    expect(b"GET http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n", OK, "ST=200 U=66", "GET http://example.com/ HTTP/1.1\r\nhost: example.com\r\n\r\n");
    expect(
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        OK,
        "ST=200 U=64",
        "POST / HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n",
    );
}
