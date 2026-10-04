// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-request tarpit` (T103). Every expected value was measured on `HAProxy
//! 3.5-dev8-885761-29` with a raw-socket client:
//!
//! ```text
//! tarpit, timeout tarpit 1s                  after 1.01s: HTTP/1.1 500, the 500 page    ts=PT
//! tarpit, no timeout tarpit, connect 2s      after 2.01s: the same                      ts=PT
//! tarpit deny_status 429, after-response     after 1.01s: HTTP/1.1 429 ... z: y         ts=PT
//! tarpit, timeout client 1s, tarpit 3s       after 3.01s: the 500 page (client timer idle)
//! tarpit status 418 content-type text/plain string hello hdr x-a b
//!                                            after 0.50s: HTTP/1.1 418 I'm a teapot
//!                                              x-a: b, content-length: 5, hello         ts=PT
//! ```

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const G: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";

/// Starts ibex on `cfg` (`{fe}` replaced by the listening address), runs `f`, stops it.
fn with_ibex<T>(cfg: &str, f: impl FnOnce(SocketAddr) -> T) -> T {
    let fe = common::reserve_addr();
    let mut file = NamedTempFile::new().expect("tmp");
    file.write_all(cfg.replace("{fe}", &fe.to_string()).as_bytes()).expect("write");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(file.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened with:\n{cfg}");
    let out = f(fe);
    common::stop(&mut child);
    out
}

/// What came back on one request, and after how long.
fn timed(fe: SocketAddr, req: &[u8]) -> (Duration, String) {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(6))).expect("timeout");
    let start = Instant::now();
    c.write_all(req).expect("send");
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let mut first = None;
    while start.elapsed() < Duration::from_secs(6) {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                first.get_or_insert_with(|| start.elapsed());
                out.extend_from_slice(&buf[..n]);
                if out.windows(4).any(|w| w == b"\r\n\r\n") && out.ends_with(b"\n") {
                    break;
                }
            }
        }
    }
    (first.unwrap_or_else(|| start.elapsed()), String::from_utf8_lossy(&out).into_owned())
}

fn cfg(client: &str, timeouts: &str, rules: &str) -> String {
    format!(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client {client}\n  timeout server 2s\n{timeouts}\
         listen l\n  bind {{fe}}\n{rules}"
    )
}

#[test]
fn tarpit_holds_the_request_for_timeout_tarpit_then_answers_500() {
    let c = cfg("5s", "  timeout tarpit 700ms\n", "  http-request tarpit\n  server s 127.0.0.1:1\n");
    let (after, resp) = with_ibex(&c, |fe| timed(fe, G));
    assert!(after >= Duration::from_millis(650) && after < Duration::from_millis(1500), "{after:?}");
    assert!(resp.starts_with("HTTP/1.1 500 Internal Server Error\r\n"), "{resp:?}");
    assert!(resp.contains("<h1>500 Internal Server Error</h1>"), "{resp:?}");
}

#[test]
fn tarpit_without_timeout_tarpit_waits_timeout_connect() {
    let c = cfg("5s", "", "  http-request tarpit\n");
    let (after, resp) = with_ibex(&c, |fe| timed(fe, G));
    assert!(after >= Duration::from_millis(1900) && after < Duration::from_millis(3000), "{after:?}");
    assert!(resp.starts_with("HTTP/1.1 500 "), "{resp:?}");
}

#[test]
fn tarpit_takes_a_status_and_the_after_response_rules_run_on_its_reply() {
    let c = cfg(
        "5s",
        "  timeout tarpit 300ms\n",
        "  http-request tarpit deny_status 429\n  http-after-response set-header z y\n",
    );
    let (after, resp) = with_ibex(&c, |fe| timed(fe, G));
    assert!(after >= Duration::from_millis(250), "{after:?}");
    assert!(resp.starts_with("HTTP/1.1 429 Too Many Requests\r\n"), "{resp:?}");
    assert!(resp.contains("\r\nz: y\r\n"), "{resp:?}");
}

#[test]
fn tarpit_takes_the_return_arguments() {
    let c = cfg(
        "5s",
        "  timeout tarpit 300ms\n",
        "  http-request tarpit status 418 content-type text/plain string hello hdr x-a b\n",
    );
    let (after, resp) = with_ibex(&c, |fe| timed(fe, G));
    assert!(after >= Duration::from_millis(250), "{after:?}");
    assert!(resp.starts_with("HTTP/1.1 418 I'm a teapot\r\n"), "{resp:?}");
    assert!(resp.contains("\r\nx-a: b\r\n") || resp.contains("\r\nX-A: b\r\n") || resp.contains("\r\nx-a: b"), "{resp:?}");
    assert!(resp.ends_with("\r\n\r\nhello"), "{resp:?}");
}

/// `timeout client` does not cut a tarpitted request short: the client side has nothing
/// to say for it.
#[test]
fn timeout_client_does_not_cut_a_tarpit_short() {
    let c = cfg("300ms", "  timeout tarpit 1200ms\n", "  http-request tarpit\n");
    let (after, resp) = with_ibex(&c, |fe| timed(fe, G));
    assert!(after >= Duration::from_millis(1100), "{after:?}: {resp:?}");
    assert!(resp.starts_with("HTTP/1.1 500 "), "{resp:?}");
}

#[test]
fn tarpit_is_logged_pt() {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_read_timeout(Some(Duration::from_secs(4))).expect("timeout");
    let c = cfg(
        "5s",
        &format!(
            "  timeout tarpit 200ms\n  log {} local0\n  log-format \"%HU ST=%ST B=%B ts=%ts\"\n",
            collector.local_addr().expect("addr")
        ),
        "  http-request tarpit\n",
    );
    let _ = with_ibex(&c, |fe| timed(fe, G));
    let mut buf = [0u8; 4096];
    let mut line = String::new();
    while let Ok(n) = collector.recv(&mut buf) {
        let l = String::from_utf8_lossy(&buf[..n]).into_owned();
        let body = l.split_once("]: ").map_or("", |(_, b)| b.trim_end()).to_string();
        if body.starts_with("/ ") {
            line = body;
            break;
        }
    }
    assert_eq!(line, "/ ST=500 B=0 ts=PT");
}

/// `http-request set-timeout tarpit` of the stream wins over `timeout tarpit`: measured,
/// `set-timeout tarpit 300ms` with `timeout tarpit 3s` answers after 0.31s.
#[test]
fn set_timeout_tarpit_wins_over_timeout_tarpit() {
    let c = cfg("5s", "  timeout tarpit 3s\n", "  http-request set-timeout tarpit 300ms\n  http-request tarpit\n");
    let (after, resp) = with_ibex(&c, |fe| timed(fe, G));
    assert!(after >= Duration::from_millis(250) && after < Duration::from_millis(1500), "{after:?}");
    assert!(resp.starts_with("HTTP/1.1 500 "), "{resp:?}");
}
