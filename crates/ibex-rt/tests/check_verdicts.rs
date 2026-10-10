// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Health-check verdicts that differed from `HAProxy` (T273 A). Every expected line below
//! was measured on `HAProxy` 3.5-dev8-885761-29 (2026-10-10) with `option
//! log-health-checks`, `timeout check 3s`, a fake server that sends the reply bytes and then
//! either closes or keeps the connection open. "slow" means the verdict arrives only when
//! `timeout check` expires; the lines are compared without their `check duration` and
//! `status:` tail.
//!
//! * `option pgsql-check`: the reply must be `R`, 3 zero bytes, any length byte, 3 zero bytes,
//!   then an authentication type in {0,2,3,4,5,6,7,9,10} (`^52000000XX000000(00|02|..|0A)` on
//!   the hex dump, `min-recv 9`). `R` plus anything else is "wrong status ... unknown error",
//!   and fewer than 9 bytes wait. An `E` reply of 5 bytes or more fails at once, info being
//!   the bytes from offset 6 (none when empty).
//! * `option redis-check`: `expect string +PONG\r\n`, 7 bytes needed, so `-ERR\r\n` is not
//!   judged until the server closes (or a buffer fills); `+PONGXX\r\n` fails too.
//! * `option smtpchk`: the EHLO rule is the regex `^(2xx-...\r\n)*2xx[ \r]` with no `min-recv`,
//!   so a reply that does not match (`450\r\n`, `XYZ\r\n`) is not judged until the close.
//!   Then the code is the first three bytes if they are a number (else 0) and the info is
//!   what follows the first four, up to the line end, left out when empty.
//! * Every status from `L57DATA` on prints `code: N`, `0` when nothing set one.

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

/// Greets with `greet` (if any), reads the client's request, sends `reply`, then closes or
/// holds the connection open.
fn fake(greet: &'static [u8], reply: &'static [u8], close: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { break };
            thread::spawn(move || {
                let mut b = [0u8; 4096];
                s.set_read_timeout(Some(Duration::from_secs(2))).ok();
                if !greet.is_empty() {
                    let _ = s.write_all(greet);
                }
                let _ = s.read(&mut b);
                let _ = s.write_all(reply);
                if !close {
                    thread::sleep(Duration::from_secs(5));
                }
            });
        }
    });
    addr
}

/// The first health-check log line for b/s, without syslog header and trailing durations,
/// and the time it took.
fn verdict(check_line: &str, server: SocketAddr) -> (String, Duration) {
    let dir = tempfile::TempDir::new().expect("tmp");
    let syslog = UdpSocket::bind("127.0.0.1:0").expect("udp");
    syslog.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let front = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode tcp\n  log 127.0.0.1:{} local0\n  option log-health-checks\n  timeout connect 1s\n  \
         timeout client 2s\n  timeout server 2s\n  timeout check 2s\nfrontend f\n  bind {front}\n  default_backend b\n\
         backend b\n{check_line}\n  server s {server} check inter 200ms fall 1 rise 1\n",
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
    let start = Instant::now();
    let mut buf = vec![0u8; 65536];
    while start.elapsed() < Duration::from_secs(6) {
        if let Ok((n, _)) = syslog.recv_from(&mut buf) {
            let line = String::from_utf8_lossy(&buf[..n]).into_owned();
            if let Some(at) = line.find("Health check for server b/s") {
                let took = start.elapsed();
                let end = line.find(", check duration").unwrap_or(line.len());
                assert!(matches!(ibex.0.try_wait(), Ok(None)), "ibex exited:\n{line}");
                return (line[at..end].to_string(), took);
            }
        }
        if let Ok(Some(st)) = ibex.0.try_wait() {
            panic!("ibex exited ({st}) before logging a check, for:\n{cfg}");
        }
    }
    panic!("no health-check log line within 6s for:\n{cfg}");
}

const TIMEOUT: &str = "Health check for server b/s failed, reason: Layer7 timeout";

fn expect(check_line: &str, greet: &'static [u8], reply: &'static [u8], close: bool, want: &str, slow: bool) {
    let (line, took) = verdict(check_line, fake(greet, reply, close));
    assert_eq!(line, want, "reply {reply:?} close={close}");
    if slow {
        assert!(took >= Duration::from_millis(1700), "must wait for timeout check, took {took:?}: {line}");
    } else {
        assert!(took < Duration::from_millis(1200), "must be judged at once, took {took:?}: {line}");
    }
}

const PG: &str = "  option pgsql-check user x";
const PG_UNKNOWN: &str =
    "Health check for server b/s failed, reason: Layer7 wrong status, code: 0, info: \"PostgreSQL unknown error\"";
const PG_OK: &str =
    "Health check for server b/s succeeded, reason: Layer7 check passed, code: 0, info: \"PostgreSQL server is ok\"";
const INVALID: &str = "Health check for server b/s failed, reason: Layer7 invalid response";

#[test]
fn pgsql_r_followed_by_junk_fails() {
    expect(PG, b"", b"R\0\0\0\x08\0\0\0\x08", false, PG_UNKNOWN, false);
    expect(PG, b"", b"R\0\0\0\x08\0\0\0\x01", false, PG_UNKNOWN, false);
    expect(PG, b"", b"R\0\0\0\x08\0\0\0\xff", false, PG_UNKNOWN, false);
    expect(PG, b"", b"RXXXXXXXX", false, PG_UNKNOWN, false);
}

#[test]
fn pgsql_good_auth_requests_pass_with_code_0() {
    expect(PG, b"", b"R\0\0\0\x08\0\0\0\0", false, PG_OK, false);
    expect(PG, b"", b"R\0\0\0\x0a\0\0\0\x03", false, PG_OK, false);
    expect(PG, b"", b"R\0\0\0\x08\0\0\0\n", false, PG_OK, false);
}

#[test]
fn pgsql_short_r_waits_and_fails_on_close() {
    expect(PG, b"", b"R\0\0\0\x08\0\0\0", false, TIMEOUT, true);
    expect(PG, b"", b"R\0\0\0\x08\0\0\0", true, PG_UNKNOWN, false);
    expect(PG, b"", b"XXXXX", false, TIMEOUT, true);
    expect(PG, b"", b"", true, PG_UNKNOWN, false);
}

#[test]
fn pgsql_error_replies() {
    // 5 bytes: judged at once, no info (nothing from offset 6).
    expect(PG, b"", b"E\0\0\0\x08", false, INVALID, false);
    // 4 bytes: only on close, still no info.
    expect(PG, b"", b"E\0\0\0", true, INVALID, false);
    expect(
        PG,
        b"",
        b"E\0\0\0\x0bSEVE",
        false,
        "Health check for server b/s failed, reason: Layer7 invalid response, info: \"EVE\"",
        false,
    );
}

const REDIS: &str = "  option redis-check";

#[test]
fn redis_non_pong_is_judged_only_when_the_reply_ends() {
    expect(REDIS, b"", b"-ERR\r\n", false, TIMEOUT, true);
    expect(REDIS, b"", b"+PONGXX\r\n", false, TIMEOUT, true);
    expect(
        REDIS,
        b"",
        b"-ERR\r\n",
        true,
        "Health check for server b/s failed, reason: Layer7 wrong status, code: 0, info: \"-ERR\"",
        false,
    );
    expect(
        REDIS,
        b"",
        b"+PONG",
        true,
        "Health check for server b/s failed, reason: Layer7 wrong status, code: 0, info: \"+PONG\"",
        false,
    );
}

#[test]
fn redis_pong_passes_with_code_0() {
    expect(
        REDIS,
        b"",
        b"+PONG\r\n",
        false,
        "Health check for server b/s succeeded, reason: Layer7 check passed, code: 0, info: \"Redis server is ok\"",
        false,
    );
}

const SMTP: &str = "  option smtpchk";
const GREET: &[u8] = b"220 ok\r\n";

#[test]
fn smtp_ehlo_reply_that_is_not_2xx_is_judged_only_when_the_reply_ends() {
    expect(SMTP, GREET, b"450\r\n", false, TIMEOUT, true);
    expect(SMTP, GREET, b"XYZ\r\n", false, TIMEOUT, true);
    expect(SMTP, GREET, b"250-x\r\n", false, TIMEOUT, true);
    expect(
        SMTP,
        GREET,
        b"450\r\n",
        true,
        "Health check for server b/s failed, reason: Layer7 wrong status, code: 450",
        false,
    );
    expect(
        SMTP,
        GREET,
        b"XYZ\r\n",
        true,
        "Health check for server b/s failed, reason: Layer7 wrong status, code: 0",
        false,
    );
    expect(
        SMTP,
        GREET,
        b"250-x\r\n",
        true,
        "Health check for server b/s failed, reason: Layer7 wrong status, code: 250, info: \"x\"",
        false,
    );
    expect(
        SMTP,
        GREET,
        b"450 try later\r\n",
        true,
        "Health check for server b/s failed, reason: Layer7 wrong status, code: 450, info: \"try later\"",
        false,
    );
}
