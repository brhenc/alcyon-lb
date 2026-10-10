// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A client that leaves, or fails, during the TLS handshake is closed at once (T259).
//!
//! Measured on HAProxy 3.5-dev8-885761-29 (`bind ... ssl crt`, `timeout client 30s`): a client
//! that connects and half-closes without a byte, half-closes after part of a ClientHello, or
//! sends plaintext HTTP, reads EOF at once (0.0 s). Ibex held all three until `timeout client`
//! (30.0 s): the handshake's error was dropped by the engine's process pass, so nothing ended
//! the session, and a soft stop waited on it (5 s added to every TLS test that probed its
//! listener with `common::wait_listening`).

use crate::common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

struct Ibex(Child);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// How long the client waits for EOF; the session's `timeout client` is 30 s.
const PROMPT: Duration = Duration::from_secs(3);

fn closed_promptly(send: &[u8], half_close: bool) {
    let fe = common::reserve_addr();
    let cert = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/certs/localhost.pem");
    let mut f = NamedTempFile::new().expect("tmp");
    write!(
        f,
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n\
         frontend t\n  bind {fe} ssl crt {cert}\n  http-request return status 200\n"
    )
    .expect("write");
    let _ibex = Ibex(
        Command::new(env!("CARGO_BIN_EXE_ibex"))
            .arg("-f")
            .arg(f.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn"),
    );
    assert!(common::wait_listening(fe), "ibex never listened");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.write_all(send).expect("send");
    if half_close {
        c.shutdown(Shutdown::Write).expect("shutdown");
    }
    c.set_read_timeout(Some(PROMPT + Duration::from_secs(1))).expect("timeout");
    let t0 = Instant::now();
    let mut buf = [0u8; 256];
    let eof = loop {
        match c.read(&mut buf) {
            Ok(0) => break true,
            Ok(_) => {}
            Err(_) => break false,
        }
    };
    assert!(eof && t0.elapsed() < PROMPT, "no EOF within {PROMPT:?} (eof {eof}, after {:?})", t0.elapsed());
}

#[test]
fn a_client_that_leaves_before_a_byte_is_closed() {
    closed_promptly(b"", true);
}

#[test]
fn a_client_that_leaves_mid_client_hello_is_closed() {
    closed_promptly(b"\x16\x03\x01\x00\xff\x01", true);
}

#[test]
fn a_client_that_speaks_plaintext_is_closed() {
    closed_promptly(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", false);
}
