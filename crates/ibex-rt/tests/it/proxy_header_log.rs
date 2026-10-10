// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The log line of a connection whose PROXY header is bad (T128). `HAProxy`
//! (3.5-dev8-885761-29) does not use the frontend's log-format for it: it writes
//! `<src>:<port> [<accept date>] <frontend>/<listener>: <message>` (`src/session.c`,
//! `session_embryonic_build_legacy_err`, with the texts of `conn_err_code_str`), measured
//! 2026-10-04 with `accept-proxy` on a frontend that had `option httplog`:
//!
//! ```text
//! 127.0.0.1:53398 [04/Oct/2026:18:59:48.153] fe/1: Received something which does not look like a PROXY protocol header
//! 127.0.0.1:53408 [04/Oct/2026:18:59:48.254] fe/1: Received an unhandled protocol in the PROXY protocol header
//! 127.0.0.1:53416 [04/Oct/2026:18:59:48.354] fe/1: Truncated PROXY protocol header received
//! 127.0.0.1:53424 [04/Oct/2026:18:59:48.455] fe/1: Received an invalid PROXY protocol header
//! 127.0.0.1:53460 [04/Oct/2026:18:59:48.856] fe/1: Connection closed while waiting for PROXY protocol header
//! 127.0.0.1:53468 [04/Oct/2026:18:59:48.857] fe/1: Timeout while waiting for PROXY protocol header
//! 127.0.0.1:53478 [04/Oct/2026:18:59:49.857] fe/1: Connection error while waiting for PROXY protocol header
//! ```
//!
//! The listener is its `name` if it has one, else its numeric id. (With the default of
//! one listener per thread group, `HAProxy` clones a `bind` into several listeners, each
//! with its own id, and the kernel picks which one takes a connection: that is why a
//! machine with many thread groups logged `fe/6` and then `fe/1` for one `bind`. With one
//! group the id is always 1.) A frontend without a log format logs nothing, and
//! `option dontlognull` silences the three cases where the client sent nothing
//! (closed, reset, timed out) and none of the others. A partial header is not waited for:
//! `HAProxy` peeks once and gives up (`goto missing`).

use crate::common;

use std::io::Write;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::Engine;

const NOT_HDR: &str = "Received something which does not look like a PROXY protocol header";
const BAD_PROTO: &str = "Received an unhandled protocol in the PROXY protocol header";
const TRUNCATED: &str = "Truncated PROXY protocol header received";
const BAD_HDR: &str = "Received an invalid PROXY protocol header";
const EMPTY: &str = "Connection closed while waiting for PROXY protocol header";
const TIMEOUT: &str = "Timeout while waiting for PROXY protocol header";
const ABORT: &str = "Connection error while waiting for PROXY protocol header";

const V2SIG: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

/// What one scenario saw: the client's own address and the line (if any) that was logged.
struct Seen {
    client: SocketAddr,
    line: Option<String>,
}

/// Runs `client` against a frontend with `accept-proxy` and `fe_extra`, whose `bind`
/// carries `bind_extra`, and returns the first log line. `wait` is how long to listen for
/// one before concluding there is none.
fn scenario(fe_extra: &str, bind_extra: &str, wait: Duration, client: impl FnOnce(&mut TcpStream) + Send + 'static) -> Seen {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_nonblocking(true).expect("nonblocking");
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 500ms\n  timeout server 500ms\n\
         frontend fe\n  bind {fe} accept-proxy {bind_extra}\n  log {} local0\n  {fe_extra}\n  default_backend be\n\
         backend be\n  server s 127.0.0.1:9\n",
        collector.local_addr().expect("addr")
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let (tx, rx) = std::sync::mpsc::channel();
    let c = thread::spawn(move || {
        let mut s = TcpStream::connect(fe).expect("connect");
        tx.send(s.local_addr().expect("local")).expect("send");
        client(&mut s);
    });
    let mut line = None;
    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + wait;
    while line.is_none() && Instant::now() < deadline {
        let _ = engine.run_once();
        if let Ok(n) = collector.recv(&mut buf) {
            line = Some(String::from_utf8_lossy(&buf[..n]).split_once("]: ").map_or("", |(_, b)| b.trim_end()).to_string());
        }
        thread::sleep(Duration::from_millis(1));
    }
    let _ = c.join();
    Seen { client: rx.recv().expect("client address"), line }
}

/// The line `HAProxy` writes: `127.0.0.1:<client port> [<date>] <fe>/<listener>: <msg>`.
/// The date is `dd/Mon/yyyy:hh:mm:ss.mmm`, checked by shape (it is the accept time).
fn assert_line(seen: &Seen, listener: &str, msg: &str) {
    let line = seen.line.as_deref().expect("a line was logged");
    let prefix = format!("{} [", seen.client);
    let rest = line.strip_prefix(&prefix).unwrap_or_else(|| panic!("line starts with the client address: {line:?}"));
    let (date, tail) = rest.split_once("] ").unwrap_or_else(|| panic!("a bracketed date: {line:?}"));
    let shape: Vec<char> = date.chars().collect();
    assert_eq!(shape.len(), 24, "date {date:?}");
    for (i, c) in shape.iter().enumerate() {
        let want_digit = !matches!(i, 2..=6 | 11 | 14 | 17 | 20);
        assert_eq!(c.is_ascii_digit(), want_digit, "date {date:?} at {i}");
    }
    assert_eq!(tail, format!("fe/{listener}: {msg}"));
}

fn sends(bytes: &'static [u8]) -> impl FnOnce(&mut TcpStream) + Send + 'static {
    move |s| {
        s.write_all(bytes).expect("send");
        thread::sleep(Duration::from_millis(300));
    }
}

const FMT: &str = "option httplog";
const WAIT: Duration = Duration::from_secs(4);

#[test]
fn a_header_that_is_not_one_is_not_a_proxy_protocol_header() {
    let seen = scenario(FMT, "", WAIT, sends(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
    assert_line(&seen, "1", NOT_HDR);
}

#[test]
fn a_v2_header_with_a_bad_signature_is_not_a_proxy_protocol_header() {
    let seen = scenario(FMT, "", WAIT, |s| {
        let mut h = V2SIG[..11].to_vec();
        h.extend_from_slice(&[0x20, 0x11, 0, 12]);
        h.extend_from_slice(&[0; 12]);
        s.write_all(&h).expect("send");
        thread::sleep(Duration::from_millis(300));
    });
    assert_line(&seen, "1", NOT_HDR);
}

#[test]
fn an_unknown_protocol_is_an_unhandled_protocol() {
    let seen = scenario(FMT, "", WAIT, sends(b"PROXY BLAH\r\n"));
    assert_line(&seen, "1", BAD_PROTO);
}

#[test]
fn a_partial_header_is_truncated() {
    let seen = scenario(FMT, "", WAIT, sends(b"PROXY TCP4 1.1.1.1"));
    assert_line(&seen, "1", TRUNCATED);
}

#[test]
fn a_partial_v2_header_is_truncated() {
    let seen = scenario(FMT, "", WAIT, |s| {
        let mut h = V2SIG.to_vec();
        h.extend_from_slice(&[0x21, 0x11, 0, 12, 1]);
        s.write_all(&h).expect("send");
        thread::sleep(Duration::from_millis(300));
    });
    assert_line(&seen, "1", TRUNCATED);
}

#[test]
fn a_malformed_address_is_an_invalid_header() {
    let seen = scenario(FMT, "", WAIT, sends(b"PROXY TCP4 1.1.1.1X 2.2.2.2 1 2\r\n"));
    assert_line(&seen, "1", BAD_HDR);
}

#[test]
fn a_v2_header_too_short_for_its_family_is_an_invalid_header() {
    let seen = scenario(FMT, "", WAIT, |s| {
        let mut h = V2SIG.to_vec();
        h.extend_from_slice(&[0x21, 0x11, 0, 4]);
        h.extend_from_slice(b"abcd");
        s.write_all(&h).expect("send");
        thread::sleep(Duration::from_millis(300));
    });
    assert_line(&seen, "1", BAD_HDR);
}

#[test]
fn a_client_that_closes_before_a_byte_is_connection_closed() {
    let seen = scenario(FMT, "", WAIT, |_| {});
    assert_line(&seen, "1", EMPTY);
}

#[test]
fn a_client_that_never_sends_the_header_is_a_timeout() {
    let seen = scenario(FMT, "", WAIT, |_| thread::sleep(Duration::from_millis(1200)));
    assert_line(&seen, "1", TIMEOUT);
}

#[test]
fn a_client_that_resets_is_a_connection_error() {
    let seen = scenario(FMT, "", WAIT, |s| {
        rustix::net::sockopt::set_socket_linger(&*s, Some(Duration::ZERO)).expect("linger");
    });
    assert_line(&seen, "1", ABORT);
}

#[test]
fn the_listener_is_named_by_its_name_when_it_has_one() {
    let seen = scenario(FMT, "name foo", WAIT, sends(b"PROXY BLAH\r\n"));
    assert_line(&seen, "foo", BAD_PROTO);
}

#[test]
fn the_listener_is_named_by_its_explicit_id() {
    let seen = scenario(FMT, "id 7", WAIT, sends(b"PROXY BLAH\r\n"));
    assert_line(&seen, "7", BAD_PROTO);
}

#[test]
fn the_frontends_log_format_is_not_used() {
    let seen = scenario("log-format \"X %ci\"", "", WAIT, sends(b"PROXY BLAH\r\n"));
    assert_line(&seen, "1", BAD_PROTO);
}

#[test]
fn a_frontend_without_a_log_format_logs_nothing() {
    let seen = scenario("", "", Duration::from_millis(1500), sends(b"PROXY BLAH\r\n"));
    assert_eq!(seen.line, None);
}

#[test]
fn dontlognull_keeps_the_lines_of_clients_that_sent_something() {
    for (bytes, msg) in [
        (&b"GET / HTTP/1.1\r\n\r\n"[..], NOT_HDR),
        (b"PROXY BLAH\r\n", BAD_PROTO),
        (b"PROXY TCP4 1.1.1.1", TRUNCATED),
        (b"PROXY TCP4 1.1.1.1X 2.2.2.2 1 2\r\n", BAD_HDR),
    ] {
        let seen = scenario("option httplog\n  option dontlognull", "", WAIT, move |s| {
            s.write_all(bytes).expect("send");
            thread::sleep(Duration::from_millis(300));
        });
        assert_line(&seen, "1", msg);
    }
}

#[test]
fn dontlognull_silences_a_client_that_closes_resets_or_times_out() {
    let fe = "option httplog\n  option dontlognull";
    let wait = Duration::from_millis(2000);
    assert_eq!(scenario(fe, "", wait, |_| {}).line, None);
    assert_eq!(scenario(fe, "", wait, |_| thread::sleep(Duration::from_millis(1200))).line, None);
    let reset = scenario(fe, "", wait, |s| {
        rustix::net::sockopt::set_socket_linger(&*s, Some(Duration::ZERO)).expect("linger");
    });
    assert_eq!(reset.line, None);
}

/// A v2 header from 10.1.2.3:42 with nothing after it.
const V2_FROM_10_1_2_3: &[u8] = b"\r\n\r\n\0\r\nQUIT\n\x21\x11\x00\x0c\x0a\x01\x02\x03\x7f\x00\x00\x02\x00\x2a\x05\x39";

/// `tcp-request session` rules wait for the header and run on its addresses (T157). When
/// they refuse the connection, `conn_complete_session` fails with no error code and
/// `session_kill_embryonic` logs the header's source and "Success". Measured on `HAProxy`
/// with `tcp-request session reject if { src 10.1.2.3 }`, and the same with
/// `silent-drop`: `10.1.2.3:42 [04/Oct/2026:21:13:20.808] fe/1: Success`.
#[test]
fn session_rules_that_refuse_after_the_header_log_success() {
    for action in ["reject", "silent-drop"] {
        let fe = format!("option httplog\n  tcp-request session {action} if {{ src 10.1.2.3 }}");
        let seen = scenario(&fe, "", WAIT, sends(V2_FROM_10_1_2_3));
        let line = seen.line.as_deref().unwrap_or_else(|| panic!("{action}: a line was logged"));
        let rest = line.strip_prefix("10.1.2.3:42 [").unwrap_or_else(|| panic!("{action}: the header's source: {line:?}"));
        assert!(rest.ends_with("] fe/1: Success"), "{action}: {line:?}");
    }
}

/// And under `option dontlognull`, nothing (measured: no line).
#[test]
fn dontlognull_silences_session_rules_that_refuse_after_the_header() {
    let fe = "option httplog\n  option dontlognull\n  tcp-request session reject if { src 10.1.2.3 }";
    assert_eq!(scenario(fe, "", Duration::from_millis(1500), sends(V2_FROM_10_1_2_3)).line, None);
}
