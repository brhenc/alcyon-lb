// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A server that streams a check reply without ever ending it (T271). `HAProxy` reads one
//! buffer (`tune.bufsize`, 16 KB) and judges what it holds; Ibex used to keep reading into
//! an unbounded buffer until `timeout check`, so a hostile or broken server grew its memory
//! for as long as that timeout.
//!
//! Each fake server sends 40 000 bytes with no CRLF and keeps the connection open. Lines
//! measured on `HAProxy` 3.5-dev8-885761-29 (2026-10-10), `option log-health-checks`,
//! `timeout check 2s`, all within 1 ms:
//!
//! ```text
//! redis  "+" A*40000                Layer7 wrong status, code: 0, info: "+AAA..." (127 chars)
//! smtp   "220 " A*40000             Layer7 wrong status, code: 0, info: "AAA..."  (127 chars)
//! smtp   "220 ok\r\n", then after EHLO "250 " A*40000
//!                                   Layer7 wrong status, code: 0, info: "AAA..."  (127 chars)
//! ```
//!
//! The SMTP greeting case: the first 16 KB ("220 AAA...") pass both greeting rules, the EHLO
//! is sent, and the next 16 KB, all `A`, fail the EHLO rule with code 0. The info is cut to
//! 127 bytes (`HCHK_DESC_LEN` - 1, src/check.c).

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Ibex(Child);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

#[derive(Clone, Copy)]
enum Mode {
    /// Reads the PING, then streams.
    Redis,
    /// Streams the greeting.
    SmtpGreeting,
    /// Sends a good greeting, reads the EHLO, then streams the EHLO reply.
    SmtpEhlo,
}

const STREAM: usize = 40_000;

fn fake(mode: Mode) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { break };
            thread::spawn(move || {
                s.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut b = [0u8; 4096];
                let mut body = Vec::with_capacity(STREAM + 8);
                match mode {
                    Mode::Redis => {
                        let _ = s.read(&mut b);
                        body.push(b'+');
                    }
                    Mode::SmtpGreeting => body.extend_from_slice(b"220 "),
                    Mode::SmtpEhlo => {
                        let _ = s.write_all(b"220 ok\r\n");
                        let _ = s.read(&mut b);
                        body.extend_from_slice(b"250 ");
                    }
                }
                body.resize(body.len() + STREAM, b'A');
                let _ = s.write_all(&body);
                // Hold the connection well past `timeout check`: the reply never ends.
                thread::sleep(Duration::from_secs(6));
            });
        }
    });
    addr
}

/// The first health-check log line for b/s.
fn check_line(check_lines: &str, server: SocketAddr) -> String {
    let dir = tempfile::TempDir::new().expect("tmp");
    let syslog = UdpSocket::bind("127.0.0.1:0").expect("udp");
    syslog.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let front = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode tcp\n  log 127.0.0.1:{} local0\n  option log-health-checks\n  timeout connect 1s\n  \
         timeout client 2s\n  timeout server 2s\n  timeout check 3s\nfrontend f\n  bind {front}\n  default_backend b\n\
         backend b\n{check_lines}\n  server s {server} check inter 200ms fall 1 rise 1\n",
        syslog.local_addr().unwrap().port()
    );
    let path = dir.path().join("ibex.cfg");
    std::fs::write(&path, &cfg).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let mut ibex = Ibex(child);
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut buf = vec![0u8; 65536];
    while Instant::now() < deadline {
        if let Ok((n, _)) = syslog.recv_from(&mut buf) {
            let line = String::from_utf8_lossy(&buf[..n]).into_owned();
            if line.contains("Health check for server b/s") {
                assert!(matches!(ibex.0.try_wait(), Ok(None)), "ibex exited after the check:\n{line}");
                return line;
            }
        }
        if let Ok(Some(st)) = ibex.0.try_wait() {
            panic!("ibex exited ({st}) before logging a check, for:\n{cfg}");
        }
    }
    panic!("no health-check log line within 6s for:\n{cfg}");
}

/// The quoted info of a check line.
fn info(line: &str) -> &str {
    let start = line.find("info: \"").unwrap_or_else(|| panic!("no info in:\n{line}")) + 7;
    let len = line[start..].find('"').expect("closing quote");
    &line[start..start + len]
}

fn assert_full_buffer_verdict(line: &str, info_prefix: &str) {
    assert!(
        line.contains("failed, reason: Layer7 wrong status, code: 0, info: \""),
        "expected HAProxy's full-buffer verdict, not a timeout, in:\n{}",
        &line[..line.len().min(300)]
    );
    let info = info(line);
    assert_eq!(info.len(), 127, "info is cut to HCHK_DESC_LEN - 1:\n{}", &line[..line.len().min(300)]);
    assert!(info.starts_with(info_prefix), "info `{info}` should start with `{info_prefix}`");
    assert!(info[info_prefix.len()..].bytes().all(|c| c == b'A'), "info `{info}`");
}

#[test]
fn redis_reply_without_crlf_is_judged_on_one_buffer() {
    let line = check_line("  option redis-check", fake(Mode::Redis));
    assert_full_buffer_verdict(&line, "+A");
}

#[test]
fn smtp_greeting_without_crlf_is_judged_on_one_buffer() {
    let line = check_line("  option smtpchk", fake(Mode::SmtpGreeting));
    assert_full_buffer_verdict(&line, "A");
}

#[test]
fn smtp_ehlo_reply_without_crlf_is_judged_on_one_buffer() {
    let line = check_line("  option smtpchk", fake(Mode::SmtpEhlo));
    assert_full_buffer_verdict(&line, "A");
}
