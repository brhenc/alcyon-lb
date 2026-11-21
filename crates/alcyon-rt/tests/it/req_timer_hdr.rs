// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `req.timer.hdr`, and the reg-test's companion `req.timer.idle`, as sample fetches.
//!
//! The reg-test `sample_fetches/http_request.vtc` collects both in `http-request` rules
//! and checks each answer is an integer (`^-?[0-9]+$`). Here is the same exchange, plus
//! one request whose header lines are sent 500 ms apart and one whose first byte is
//! sent 500 ms after the connection.
//!
//! Measured on the oracle (3.5-dev11): in an `http-request` rule, `req.timer.hdr`
//! answers `-1` - the stream's `s->logs.request_ts` is stamped by
//! `http_process_req_common` only after the rules ran (`src/http_ana.c`), and the
//! `wait-for-body` rule stamps nothing either; the milliseconds the request spends
//! waiting for its complete header are what the access log writes as `%TR`.
//! `req.timer.idle` answers the request's time to its first byte (`%Ti`): 0 when the
//! first byte follows the connection at once, ~500 when it does not. The tests pin
//! those values, and the log's `%TR`/`%Ti` of the request that waits.
//!
//! Set `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`.

use crate::common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// The wait the slow requests make, between their header lines or after the connect.
const PAUSE: Duration = Duration::from_millis(500);

struct Proxy {
    child: Child,
    fe: SocketAddr,
    logs: Arc<Mutex<Vec<String>>>,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// The backend: answers `200 ok` once the head is whole, closes.
fn server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(8)));
                let mut req = Vec::new();
                let mut b = [0u8; 65536];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&b[..n]),
                    }
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            });
        }
    });
    addr
}

fn start() -> Proxy {
    let (fe, sentinel) = (common::reserve_addr(), common::reserve_addr());
    let be = server();
    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "global\n  log stdout format raw local0\n\
         defaults\n  mode http\n  log global\n\
         \x20 log-format \"th=%TR ti=%Ti r=%r\"\n\
         \x20 timeout connect 2s\n  timeout client 10s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n\
         \x20 http-request set-var(txn.th) req.timer.hdr\n\
         \x20 http-request set-var(txn.ti) req.timer.idle\n\
         \x20 http-response set-header x-timerhdr \"%[var(txn.th)]\"\n\
         \x20 http-response set-header x-timeridle \"%[var(txn.ti)]\"\n\
         \x20 default_backend b\n\
         frontend s\n  bind {sentinel}\n  http-request return status 200\n\
         backend b\n  server s {be}\n"
    )
    .expect("write");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn");
    // The proxy's access log: `log stdout format raw local0` writes one line per
    // finished stream to its stdout, captured here for the `%TR`/`%Ti` checks.
    let out = child.stdout.take().expect("stdout");
    let logs: Arc<Mutex<Vec<String>>> = Arc::default();
    let sink = Arc::clone(&logs);
    thread::spawn(move || {
        let mut r = BufReader::new(out);
        let mut line = String::new();
        while r.read_line(&mut line).map_or(0, |n| n) > 0 {
            sink.lock().unwrap().push(std::mem::take(&mut line));
        }
    });
    assert!(common::wait_listening(sentinel), "proxy never listened");
    assert!(wait_serving(sentinel), "proxy never answered");
    Proxy { child, fe, logs, _cfg: cfg }
}

/// Waits until the proxy answers a request on `addr`. A connect succeeds as soon as the
/// listener is bound, ~35 ms (Alcyon) before the worker serves it: a head sent in that
/// gap is read late, and `%TR`, which starts at the read, loses the difference (T649).
fn wait_serving(addr: SocketAddr) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(mut c) = TcpStream::connect(addr) {
            let _ = c.set_read_timeout(Some(Duration::from_millis(200)));
            let mut b = [0u8; 16];
            if c.write_all(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n").is_ok() && c.read(&mut b).is_ok_and(|n| n > 0) {
                return true;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}

/// The response of the request whose log line is `r={marker}`: its `th=` and `ti=`
/// fields, polled from the captured log until the stream's line is written.
fn log_fields(p: &Proxy, marker: &str) -> (i64, i64) {
    let want = format!("r={marker}");
    let start = Instant::now();
    loop {
        let got = p
            .logs
            .lock()
            .unwrap()
            .iter()
            .find(|l| l.contains(&want))
            .cloned();
        if let Some(line) = got {
            let field = |name: &str| -> i64 {
                line.split_whitespace()
                    .find_map(|t| t.strip_prefix(&format!("{name}=")).and_then(|v| v.parse().ok()))
                    .unwrap_or_else(|| panic!("no {name} in log line '{line}'"))
            };
            return (field("th"), field("ti"));
        }
        assert!(start.elapsed() < Duration::from_secs(5), "no log line matching '{want}': {:?}", &*p.logs.lock().unwrap());
        thread::sleep(Duration::from_millis(20));
    }
}

/// Sends `parts` (with `pause` between two writes), optionally after waiting `pre`
/// with the connection open, reads until the close, and gives the status and the
/// response headers as lowercased `(name, value)` pairs.
fn exchange(p: &Proxy, pre: Option<Duration>, parts: &[&str], pause: Option<Duration>) -> (u16, Vec<(String, String)>) {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    if let Some(d) = pre {
        thread::sleep(d);
    }
    c.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            if let Some(d) = pause {
                thread::sleep(d);
            }
        }
        c.write_all(part.as_bytes()).expect("write");
    }
    let mut got = Vec::new();
    let mut b = [0u8; 65536];
    loop {
        match c.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&b[..n]),
        }
    }
    let text = String::from_utf8_lossy(&got).into_owned();
    let head_end = text.find("\r\n\r\n").expect("end of head");
    let head = &text[..head_end];
    let mut lines = head.lines();
    let status = lines.next().unwrap().split_whitespace().nth(1).unwrap().parse().expect("status");
    let headers = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())))
        .collect();
    (status, headers)
}

/// The header's value; the test fails where the fetch gave none (an empty value).
fn value<'a>(headers: &'a [(String, String)], name: &str) -> &'a str {
    headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str()).unwrap_or_else(|| panic!("no {name} header"))
}

/// `^-?[0-9]+$`, what the reg-test checks of both fetches.
fn is_int(s: &str) -> bool {
    let d = s.strip_prefix('-').unwrap_or(s);
    !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())
}

/// The reg-test's exchange, whole: both fetches answer, and both answers are integers.
#[test]
fn timer_fetches_answer_integers() {
    let p = start();
    let (status, headers) = exchange(&p, None, &["POST / HTTP/1.1\r\nHost: t\r\nx-num: 42\r\n\r\n"], None);
    assert_eq!(status, 200);
    let th = value(&headers, "x-timerhdr");
    assert!(is_int(th), "x-timerhdr '{th}' is not an integer");
    let ti = value(&headers, "x-timeridle");
    assert!(is_int(ti), "x-timeridle '{ti}' is not an integer");
}

/// A request that waits 500 ms between its header lines. In the `http-request` rules
/// (before the request counts as received, where the oracle's
/// `s->logs.request_ts` is not stamped yet) `req.timer.hdr` is `-1` and
/// `req.timer.idle` the short time to the first byte; the wait itself is what the
/// log writes as `%TR` for the stream.
#[test]
fn timer_hdr_spans_the_wait_between_header_lines() {
    let p = start();
    let (status, headers) = exchange(
        &p,
        None,
        &["POST / HTTP/1.1\r\nHost: t\r\nx-a: 1\r\n", "x-b: 2\r\n\r\n"],
        Some(PAUSE),
    );
    assert_eq!(status, 200);
    let th = value(&headers, "x-timerhdr");
    assert!(is_int(th), "x-timerhdr '{th}' is not an integer");
    assert_eq!(th.parse::<i64>().unwrap(), -1, "req.timer.hdr '{th}' in the request rules");
    let ti = value(&headers, "x-timeridle");
    assert!(is_int(ti), "x-timeridle '{ti}' is not an integer");
    let v = ti.parse::<i64>().unwrap();
    assert!((0..=1000).contains(&v), "x-timeridle {v} with the first byte sent at once");
    // The header wait, as the access log writes it for this stream.
    let (th, ti) = log_fields(&p, "POST / HTTP/1.1");
    assert!((470..=5000).contains(&th), "log %TR {th} for a 500 ms wait between the header lines");
    assert!((0..=1000).contains(&ti), "log %Ti {ti} with the first byte sent at once");
}

/// A request that waits 500 ms with the connection open before sending any byte:
/// `req.timer.idle` is the time to that first byte.
#[test]
fn timer_idle_spans_the_wait_for_the_first_byte() {
    let p = start();
    let (status, headers) = exchange(&p, Some(PAUSE), &["POST / HTTP/1.1\r\nHost: t\r\nx-a: 1\r\n\r\n"], None);
    assert_eq!(status, 200);
    let ti = value(&headers, "x-timeridle");
    assert!(is_int(ti), "x-timeridle '{ti}' is not an integer");
    let v = ti.parse::<i64>().unwrap();
    assert!((300..=5000).contains(&v), "x-timeridle {v} after a 500 ms wait for the first byte");
    let th = value(&headers, "x-timerhdr");
    assert!(is_int(th), "x-timerhdr '{th}' is not an integer");
    assert_eq!(th.parse::<i64>().unwrap(), -1, "req.timer.hdr '{th}' in the request rules");
    let (_, ti) = log_fields(&p, "POST / HTTP/1.1");
    assert!((300..=5000).contains(&ti), "log %Ti {ti} after a 500 ms wait for the first byte");
}
