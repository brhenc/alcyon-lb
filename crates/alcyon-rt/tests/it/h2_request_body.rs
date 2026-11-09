// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The request body of an HTTP/2 client that follows its head (T144b 5). Measured on
//! `HAProxy 3.5-dev8-885761-29` (2026-10-04) with `curl --http2-prior-knowledge -T -` fed
//! from a pipe (`abc`, a pause, `def`) and a raw-socket server:
//!
//! ```text
//! no Content-Length   the server hears transfer-encoding: chunked and the DATA frames as
//!                     chunks (3 abc, 3 def, 0), at +0.4 s
//! Content-Length: 6   the server hears content-length: 6 and abcdef
//! wait-for-body time 1s at-least 6, return x-body=%[req.body]:
//!                     pause 0 s: abcdef (6)   pause 0.5 s: abcdef (6)   pause 2.5 s: 408
//! wait-for-body time 1s at-least 3:
//!                     pause 0 s: abcdef (6)   pause 0.5 s: abc (3)      pause 2.5 s: abc (3)
//! option http-buffer-request, timeout http-request 1s:
//!                     pause 0 s: abcdef (6)   pause 0.5 s: abcdef (6)   pause 2.5 s: 408
//! ```
//!
//! Alcyon answered with what had arrived with the head and sent the server a request with no
//! body at all when the rest came later.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Alcyon(Child, NamedTempFile);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// A server that reads one request to its end (the blank line and then what the framing
/// says, or until it has been quiet for 1.5 s) and sends what it heard to the test.
fn server() -> (SocketAddr, Receiver<Vec<u8>>) {
    let (tx, rx) = channel();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let tx = tx.clone();
            thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_millis(1500))).ok();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match c.read(&mut chunk) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => break,
                    }
                    let text = String::from_utf8_lossy(&buf).to_ascii_lowercase();
                    let Some((head, body)) = text.split_once("\r\n\r\n") else { continue };
                    if body.ends_with("0\r\n\r\n") && head.contains("transfer-encoding: chunked") {
                        break;
                    }
                    if head.contains("content-length: 6") && body.len() >= 6 {
                        break;
                    }
                }
                let _ = tx.send(buf);
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                thread::sleep(Duration::from_millis(200));
            });
        }
    });
    (addr, rx)
}

fn start(rules: &str) -> (Alcyon, SocketAddr, Receiver<Vec<u8>>) {
    let fe = common::reserve_addr();
    let (srv, heard) = server();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe} proto h2\n{rules}  default_backend be\nbackend be\n  server s {srv}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    let alcyon = Alcyon(child, f);
    assert!(common::wait_listening(fe), "alcyon never listened with:\n{cfg}");
    (alcyon, fe, heard)
}

/// `curl -T -` over HTTP/2 with `abc`, a pause and `def` on its standard input: the head
/// goes out at once, the DATA frames when the pipe has them. The response as text, head
/// and body.
fn upload(fe: SocketAddr, pause_ms: u64, content_length: bool) -> String {
    let mut cmd = Command::new("curl");
    cmd.args(["-s", "-i", "--http2-prior-knowledge", "-m", "6", "-T", "-"]);
    if content_length {
        cmd.args(["-H", "Content-Length: 6"]);
    }
    let mut curl = cmd.arg(format!("http://{fe}/p")).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("curl");
    let mut stdin = curl.stdin.take().expect("stdin");
    stdin.write_all(b"abc").expect("abc");
    stdin.flush().ok();
    thread::sleep(Duration::from_millis(pause_ms));
    stdin.write_all(b"def").expect("def");
    drop(stdin);
    let out = curl.wait_with_output().expect("curl output");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(at) = body.windows(2).position(|w| w == b"\r\n") {
        let size = usize::from_str_radix(std::str::from_utf8(&body[..at]).unwrap_or("0").trim(), 16).unwrap_or(0);
        if size == 0 {
            break;
        }
        out.extend_from_slice(&body[at + 2..at + 2 + size]);
        body = &body[at + 2 + size + 2..];
    }
    out
}

#[test]
fn a_body_that_follows_the_head_reaches_the_server_chunked_when_it_has_no_length() {
    let (_alcyon, fe, heard) = start("");
    let resp = upload(fe, 400, false);
    assert!(resp.contains(" 200"), "{resp:?}");
    let raw = heard.recv_timeout(Duration::from_secs(5)).expect("the server heard a request");
    let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    let (head, body) = text.split_once("\r\n\r\n").expect("a head");
    assert!(head.starts_with("put /p http/1.1"), "{text:?}");
    assert!(head.contains("transfer-encoding: chunked"), "{text:?}");
    assert!(!head.contains("content-length"), "{text:?}");
    assert_eq!(dechunk(body.as_bytes()), b"abcdef", "{text:?}");
}

#[test]
fn a_body_that_follows_the_head_reaches_the_server_whole_when_it_has_a_length() {
    let (_alcyon, fe, heard) = start("");
    let resp = upload(fe, 400, true);
    assert!(resp.contains(" 200"), "{resp:?}");
    let raw = heard.recv_timeout(Duration::from_secs(5)).expect("the server heard a request");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").expect("a head");
    assert!(head.to_ascii_lowercase().contains("content-length: 6"), "{text:?}");
    assert_eq!(body, "abcdef", "{text:?}");
}

fn x_headers(resp: &str) -> (String, String) {
    let get = |n: &str| resp.lines().find_map(|l| l.strip_prefix(n)).unwrap_or("").trim().to_string();
    (get("x-body:"), get("x-len:"))
}

const RETURN_BODY: &str = "  http-request return status 200 hdr x-body \"%[req.body]\" hdr x-len \"%[req.body_len]\"\n";

#[test]
fn wait_for_body_at_least_waits_for_an_http2_body() {
    let (_alcyon, fe, _heard) = start(&format!("  http-request wait-for-body time 1s at-least 6\n{RETURN_BODY}"));
    for pause in [0, 500] {
        let resp = upload(fe, pause, true);
        assert!(resp.contains(" 200"), "pause {pause}: {resp:?}");
        assert_eq!(x_headers(&resp), ("abcdef".to_string(), "6".to_string()), "pause {pause}: {resp:?}");
    }
    let resp = upload(fe, 2500, true);
    assert!(resp.contains(" 408"), "pause 2500: {resp:?}");
}

#[test]
fn wait_for_body_at_least_stops_at_the_bytes_it_asked_for() {
    let (_alcyon, fe, _heard) = start(&format!("  http-request wait-for-body time 1s at-least 3\n{RETURN_BODY}"));
    for (pause, want) in [(500, ("abc", "3")), (2500, ("abc", "3"))] {
        let resp = upload(fe, pause, true);
        assert!(resp.contains(" 200"), "pause {pause}: {resp:?}");
        assert_eq!(x_headers(&resp), (want.0.to_string(), want.1.to_string()), "pause {pause}: {resp:?}");
    }
}

#[test]
fn http_buffer_request_waits_for_the_whole_http2_body() {
    let (_alcyon, fe, _heard) = start(&format!("  option http-buffer-request\n  timeout http-request 1s\n{RETURN_BODY}"));
    for pause in [0, 500] {
        let resp = upload(fe, pause, true);
        assert!(resp.contains(" 200"), "pause {pause}: {resp:?}");
        assert_eq!(x_headers(&resp), ("abcdef".to_string(), "6".to_string()), "pause {pause}: {resp:?}");
    }
    let resp = upload(fe, 2500, true);
    assert!(resp.contains(" 408"), "pause 2500: {resp:?}");
}
