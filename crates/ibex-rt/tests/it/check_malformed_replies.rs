// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `option ldap-check` and `option mysql-check` against malformed and truncated replies
//! (T238). Each of the first few used to index past the end of the reply and panic the
//! worker; each now ends the check with the status `HAProxy` reports.
//!
//! A fake server sends the bytes below and closes. Expected lines measured on `HAProxy`
//! 3.5-dev8-885761-29 (2026-10-10), `option log-health-checks`:
//!
//! ```text
//! ldap  30                              Layer7 invalid response, info: "Not LDAPv3 protocol" (*)
//! ldap  30 04 02 01 01 61               Layer7 invalid response               (no info)
//! ldap  30 81 0c 02 01 01 61 07 0a 01 00 04 00 04 00
//!                                       Layer7 invalid response, info: "Not LDAPv3 protocol"
//! ldap  30 0c 02 01 01 61 07 0a 01 31 04 00 04 00
//!                                       Layer7 wrong status, code: 49, info: "See RFC: ..."
//! mysql 01 00 00 00 ff 00 00 00         Layer7 wrong status, code: 0          (no info)
//! mysql 10 00 00 00 ff 6a 04 "Host blocked!"
//!                                       Layer7 wrong status, code: 1130, info: "Host blocked!"
//! mysql 00 00 00 00                     Layer7 check passed                   (no info)
//! mysql user, greeting + 00 00 00 02    Layer7 check passed, info: "5.7.0-fake"
//! mysql user, greeting + 03 00 00 02 00 Layer7 invalid response               (no info)
//! mysql user, greeting + 16 00 00 02 ff 15 04 "#28000Access denied"
//!                                       Layer7 wrong status, code: 1045, info: "#28000Access denied"
//! mysql user, greeting + 01 00 00 02 ff Layer7 wrong status, code: 127 (**)
//! ```
//!
//! (*) and (**): `HAProxy` reads past the end of the data there, into whatever its buffer
//! held before; `30` alone gave "Not LDAPv3 protocol" on one run and no info on another, and
//! the 127 is not in the reply. Ibex reads such bytes as zero: "Not LDAPv3 protocol", and
//! code 0.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Ibex(Child);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// A server that sends `reply` and closes; after reading the check's request first when
/// `wait_request` (a MySQL check without `user` sends none).
fn fake(reply: Vec<u8>, wait_request: bool) -> SocketAddr {
    fake_holding(reply, wait_request, Duration::ZERO)
}

/// As [`fake`], keeping the connection open for `hold` after the reply.
fn fake_holding(reply: Vec<u8>, wait_request: bool, hold: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { break };
            let reply = reply.clone();
            thread::spawn(move || {
                if wait_request {
                    s.set_read_timeout(Some(Duration::from_secs(1))).ok();
                    let mut b = [0u8; 4096];
                    let _ = s.read(&mut b);
                }
                let _ = s.write_all(&reply);
                thread::sleep(hold);
            });
        }
    });
    addr
}

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

/// A MySQL greeting: protocol 10, version "5.7.0-fake".
fn greeting() -> Vec<u8> {
    hex("0c000000 0a 352e372e302d66616b65 00")
}

/// The first health-check log line for b/s, with ibex checked to be still running after it.
fn check_line(check_lines: &str, reply: Vec<u8>, wait_request: bool) -> String {
    check_line_at(check_lines, fake(reply, wait_request))
}

fn check_line_at(check_lines: &str, server: SocketAddr) -> String {
    let dir = tempfile::TempDir::new().expect("tmp");
    let syslog = UdpSocket::bind("127.0.0.1:0").expect("udp");
    syslog.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let front = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode tcp\n  log 127.0.0.1:{} local0\n  option log-health-checks\n  timeout connect 1s\n  \
         timeout client 2s\n  timeout server 2s\n  timeout check 1s\nfrontend f\n  bind {front}\n  default_backend b\n\
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
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 2048];
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
    panic!("no health-check log line within 5s for:\n{cfg}");
}

fn assert_line(line: &str, expected: &[&str]) {
    for e in expected {
        assert!(line.contains(e), "expected `{e}` in:\n{line}");
    }
}

fn assert_no_info(line: &str) {
    assert!(!line.contains("info:"), "expected no info in:\n{line}");
}

const LDAP: &str = "  option ldap-check";
const MYSQL: &str = "  option mysql-check";
const MYSQL_USER: &str = "  option mysql-check user haproxy post-41";

#[test]
fn ldap_reply_of_one_byte() {
    let line = check_line(LDAP, hex("30"), true);
    assert_line(&line, &["failed, reason: Layer7 invalid response, info: \"Not LDAPv3 protocol\""]);
}

#[test]
fn ldap_reply_cut_after_the_message_id() {
    let line = check_line(LDAP, hex("30 04 02 01 01 61"), true);
    assert_line(&line, &["failed, reason: Layer7 invalid response,"]);
    assert_no_info(&line);
}

#[test]
fn ldap_length_on_one_extra_byte_is_not_ldapv3() {
    let line = check_line(LDAP, hex("30 81 0c 02 01 01 61 07 0a 01 00 04 00 04 00"), true);
    assert_line(&line, &["failed, reason: Layer7 invalid response, info: \"Not LDAPv3 protocol\""]);
}

#[test]
fn ldap_result_code_is_reported() {
    let line = check_line(LDAP, hex("30 0c 02 01 01 61 07 0a 01 31 04 00 04 00"), true);
    assert_line(&line, &[
        "failed, reason: Layer7 wrong status, code: 49, info: \"See RFC: http://tools.ietf.org/html/rfc4511#section-4.1.9\"",
    ]);
}

#[test]
fn mysql_error_packet_shorter_than_its_header() {
    let line = check_line(MYSQL, hex("01 00 00 00 ff 00 00 00"), false);
    assert_line(&line, &["failed, reason: Layer7 wrong status, code: 0,"]);
    assert_no_info(&line);
}

#[test]
fn mysql_error_packet_message() {
    let mut reply = hex("10 00 00 00 ff 6a 04");
    reply.extend_from_slice(b"Host blocked!");
    let line = check_line(MYSQL, reply, false);
    assert_line(&line, &["failed, reason: Layer7 wrong status, code: 1130, info: \"Host blocked!\""]);
}

#[test]
fn mysql_empty_packet_passes() {
    let line = check_line(MYSQL, hex("00 00 00 00"), false);
    assert_line(&line, &["succeeded, reason: Layer7 check passed"]);
    assert_no_info(&line);
}

#[test]
fn mysql_user_empty_second_packet_passes() {
    let mut reply = greeting();
    reply.extend(hex("00 00 00 02"));
    let line = check_line(MYSQL_USER, reply, true);
    assert_line(&line, &["succeeded, reason: Layer7 check passed, code: 0, info: \"5.7.0-fake\""]);
}

#[test]
fn mysql_user_truncated_second_packet() {
    let mut reply = greeting();
    reply.extend(hex("03 00 00 02 00"));
    let line = check_line(MYSQL_USER, reply, true);
    assert_line(&line, &["failed, reason: Layer7 invalid response,"]);
    assert_no_info(&line);
}

#[test]
fn mysql_user_second_packet_error_keeps_the_sqlstate() {
    let mut reply = greeting();
    reply.extend(hex("16 00 00 02 ff 15 04"));
    reply.extend_from_slice(b"#28000Access denied");
    let line = check_line(MYSQL_USER, reply, true);
    assert_line(&line, &["failed, reason: Layer7 wrong status, code: 1045, info: \"#28000Access denied\""]);
}

#[test]
fn mysql_user_second_packet_error_of_one_byte() {
    let mut reply = greeting();
    reply.extend(hex("01 00 00 02 ff"));
    let line = check_line(MYSQL_USER, reply, true);
    assert_line(&line, &["failed, reason: Layer7 wrong status, code: 0,"]);
    assert_no_info(&line);
}

/// A reply longer than the 16 KiB buffer, the connection kept open: a full buffer ends the
/// read, and the packet it cuts is a truncated response (measured on `HAProxy`, both checks:
/// "Layer7 invalid response", no info, in 0-1 ms). Waiting for the rest would have ended in
/// a check timeout.
#[test]
fn a_reply_that_fills_the_buffer_is_judged_on_it() {
    let mut mysql = hex("00 00 01 00 0a");
    mysql.extend(std::iter::repeat_n(b'a', 20000));
    let mut ldap = hex("30 84 00 01 00 00");
    ldap.extend(std::iter::repeat_n(b'a', 20000));
    for (lines, reply, wait) in [(MYSQL, mysql, false), (LDAP, ldap, true)] {
        let line = check_line_at(lines, fake_holding(reply, wait, Duration::from_secs(3)));
        assert_line(&line, &["failed, reason: Layer7 invalid response,"]);
        assert_no_info(&line);
    }
}
