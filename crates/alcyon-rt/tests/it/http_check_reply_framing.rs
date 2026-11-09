// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! How `http-check` reads the body of a server's reply when its `Transfer-Encoding` or
//! `Content-Length` lines are split, repeated or disagree (tasks/T281 item 2). The check
//! used to read the first `Transfer-Encoding` line alone and search it for "chunked", and
//! the first `Content-Length` alone, so every case below passed.
//!
//! A fake server reads the check's request, answers the bytes below and closes. Expected
//! lines measured on `HAProxy` 3.5-dev8-885761-29 (2026-10-11), `option log-health-checks`,
//! `option httpchk GET /`, `http-check expect string hello`; the body is `5\r\nhello\r\n0\r\n\r\n`
//! after a `Transfer-Encoding`, `hello` otherwise:
//!
//! ```text
//! TE: chunked                         Layer7 check passed, code: 200
//! TE: chunked + CL: 3                 Layer7 check passed, code: 200
//! TE: gzip / TE: chunked              Layer7 invalid response, info: "TCPCHK did not match content 'hello' at step 1"
//! TE: chunked / TE: gzip              (same)
//! TE: chunked, gzip                   (same)
//! TE: xchunkedx                       (same)
//! TE: chunked / TE: chunked           Socket error
//! CL: 5 / CL: 3                       Socket error
//! CL: +5                              Socket error
//! CL: 5 / CL: 5                       Layer7 check passed, code: 200
//! CL: 5, 5                            Layer7 check passed, code: 200
//! CL: 3                               Layer7 invalid response, info: "HTTP content check did not match"
//! ```
//!
//! A response `HAProxy`'s HTTP/1 parser marks as a parsing error (a coding other than a
//! lone `chunked`) fails the first `expect` with the generic message of its kind and the
//! rule's step (`tcpcheck_expect_onerror_message`); one it cannot parse at all is a socket
//! error. The step is the rule's index among the `http-check` lines plus one; the expect
//! added when there is none is step 2.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Alcyon(Child);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// A server that reads the check's request, sends `reply` and closes.
fn fake(reply: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { break };
            let reply = reply.clone();
            thread::spawn(move || {
                s.set_read_timeout(Some(Duration::from_secs(1))).ok();
                let mut b = [0u8; 4096];
                let _ = s.read(&mut b);
                let _ = s.write_all(&reply);
            });
        }
    });
    addr
}

/// The reason of the first health-check log line for b/s: what follows `reason: `, up to
/// `, check duration`.
fn reason(check_lines: &str, reply: Vec<u8>) -> String {
    let server = fake(reply);
    let dir = tempfile::TempDir::new().expect("tmp");
    let syslog = UdpSocket::bind("127.0.0.1:0").expect("udp");
    syslog.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let front = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  log 127.0.0.1:{} local0\n  option log-health-checks\n  timeout connect 1s\n  \
         timeout client 2s\n  timeout server 2s\n  timeout check 1s\nfrontend f\n  bind {front}\n  default_backend b\n\
         backend b\n{check_lines}\n  server s {server} check inter 200ms fall 1 rise 1\n",
        syslog.local_addr().unwrap().port()
    );
    let path = dir.path().join("alcyon.cfg");
    std::fs::write(&path, &cfg).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    let mut alcyon = Alcyon(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        if let Ok((n, _)) = syslog.recv_from(&mut buf) {
            let line = String::from_utf8_lossy(&buf[..n]).into_owned();
            if line.contains("Health check for server b/s") {
                let r = line.split_once("reason: ").map_or(line.as_str(), |(_, r)| r);
                return r.split(", check duration").next().unwrap_or(r).to_string();
            }
        }
        if let Ok(Some(st)) = alcyon.0.try_wait() {
            panic!("alcyon exited ({st}) before logging a check, for:\n{cfg}");
        }
    }
    panic!("no health-check log line within 5s for:\n{cfg}");
}

const EXPECT_HELLO: &str = "  option httpchk GET /\n  http-check expect string hello";
const CHUNKED: &str = "5\r\nhello\r\n0\r\n\r\n";
const PASSED: &str = "Layer7 check passed, code: 200";
const SOCKERR: &str = "Socket error";
const BAD_TE: &str = "Layer7 invalid response, info: \"TCPCHK did not match content 'hello' at step 1\"";

fn reply(fields: &str, body: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\n{fields}\r\n\r\n{body}").into_bytes()
}

fn assert_all(cases: &[(&str, &str, Vec<u8>, &str)]) {
    let wrong: Vec<String> = cases
        .iter()
        .filter_map(|(name, lines, r, want)| {
            let got = reason(lines, r.clone());
            (got != *want).then(|| format!("{name}: got `{got}`, expected `{want}`"))
        })
        .collect();
    assert!(wrong.is_empty(), "{} of {} cases wrong:\n{}", wrong.len(), cases.len(), wrong.join("\n"));
}

#[test]
fn every_transfer_encoding_line_frames_the_reply() {
    assert_all(&[
        ("te chunked", EXPECT_HELLO, reply("Transfer-Encoding: chunked", CHUNKED), PASSED),
        ("te chunked + cl", EXPECT_HELLO, reply("Transfer-Encoding: chunked\r\nContent-Length: 3", CHUNKED), PASSED),
        ("te gzip / chunked", EXPECT_HELLO, reply("Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked", CHUNKED), BAD_TE),
        ("te chunked / gzip", EXPECT_HELLO, reply("Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip", CHUNKED), BAD_TE),
        ("te chunked, gzip", EXPECT_HELLO, reply("Transfer-Encoding: chunked, gzip", CHUNKED), BAD_TE),
        ("te xchunkedx", EXPECT_HELLO, reply("Transfer-Encoding: xchunkedx", CHUNKED), BAD_TE),
        ("te chunked twice", EXPECT_HELLO, reply("Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked", CHUNKED), SOCKERR),
    ]);
}

#[test]
fn every_content_length_line_frames_the_reply() {
    assert_all(&[
        ("cl 5 / 3", EXPECT_HELLO, reply("Content-Length: 5\r\nContent-Length: 3", "hello"), SOCKERR),
        ("cl +5", EXPECT_HELLO, reply("Content-Length: +5", "hello"), SOCKERR),
        ("cl 5 / 5", EXPECT_HELLO, reply("Content-Length: 5\r\nContent-Length: 5", "hello"), PASSED),
        ("cl 5, 5", EXPECT_HELLO, reply("Content-Length: 5, 5", "hello"), PASSED),
        ("cl 3", EXPECT_HELLO, reply("Content-Length: 3", "hello"), "Layer7 invalid response, info: \"HTTP content check did not match\""),
    ]);
}

/// The message of a reply with a coding other than `chunked` names the first expect's kind
/// and step, as `HAProxy` numbers them.
#[test]
fn a_bad_coding_fails_the_first_expect_with_its_step() {
    let r = || reply("Transfer-Encoding: chunked, gzip", CHUNKED);
    assert_all(&[
        ("default expect", "  option httpchk GET /", r(), "Layer7 invalid response, info: \"TCPCHK did not match content(status codes) at step 2\""),
        ("expect status", "  option httpchk GET /\n  http-check expect status 200", r(), "Layer7 invalid response, info: \"TCPCHK did not match content(status codes) at step 1\""),
        (
            "send then expects",
            "  option httpchk\n  http-check send meth GET uri /x\n  http-check expect status 200\n  http-check expect string hello",
            r(),
            "Layer7 invalid response, info: \"TCPCHK did not match content(status codes) at step 2\"",
        ),
        ("expect rstring", "  option httpchk GET /\n  http-check expect rstring hel+o", r(), "Layer7 invalid response, info: \"TCPCHK did not match content (regex) at step 1\""),
        ("expect string-lf", "  option httpchk GET /\n  http-check expect string-lf hello", r(), "Layer7 invalid response, info: \"TCPCHK did not match content (log-format string) at step 1\""),
        ("expect hdr", "  option httpchk GET /\n  http-check expect hdr name x", r(), "Layer7 invalid response, info: \"TCPCHK did not match content (header pattern) at step 1\""),
        (
            "set-var then expect",
            "  option httpchk GET /\n  http-check set-var(check.x) str(a)\n  http-check expect string hello",
            r(),
            "Layer7 invalid response, info: \"TCPCHK did not match content 'hello' at step 2\"",
        ),
        (
            "set-var then the added expect",
            "  option httpchk GET /\n  http-check set-var(check.x) str(a)",
            r(),
            "Layer7 invalid response, info: \"TCPCHK did not match content(status codes) at step 2\"",
        ),
    ]);
}
