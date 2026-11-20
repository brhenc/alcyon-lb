// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The timer sample fetches `txn.timer.total`, `txn.timer.user`, `req.timer.queue`,
//! `req.timer.tq`, `res.timer.data`, `fc.timer.handshake`, `fc.timer.total` and
//! `bc.timer.connect`, as `HAProxy` registers them in `src/sample.c`
//! (`smp_fetch_txn_timers`, `smp_fetch_conn_timers`, `smp_fetch_reX_timers`).
//!
//! The reg-test `log/txn_state.vtc` reads such fetches from a custom `log-format`; here
//! each fetch is read from a `log-format` (the ones the log admits) and, where `HAProxy`
//! allows it, from an `http-response` / `http-after-response` header.
//!
//! Measured on the oracle (3.5-dev11, plain TCP, backend answering its head at once and
//! its body after 300 ms):
//! - in an `http-request` rule, `req.timer.tq` answers `-1` (`s->logs.request_ts` is
//!   stamped by `http_process_req_common` only after the rules ran) and
//!   `fc.timer.handshake` answers `0` (no TLS on the client);
//! - in an `http-response` rule, `fc.timer.total` is still `0`: `s->logs.t_close` starts
//!   at `0` when the stream is created (`src/stream.c`) and is stamped only when it is
//!   logged, so `txn.timer.total` / `txn.timer.user` read `0 - t_idle` there and
//!   `res.timer.data` reads `0 - t_data`: `0` for a request whose head arrived at once;
//! - in the access log, for the slow body: `tt`, `ta`, `tu` and `td` are the full
//!   ~300 ms, while `tw` (`t_queue - t_request`) and `tc` (`t_connect - t_queue`) are
//!   small and non-negative;
//! - for a denied request the log writes `tw=-1`, `tc=-1`, `td=-1` (the server is never
//!   queued, connected, nor given data), with `tt`, `ta`, `tu` at `0`.
//!
//! The refusals at load must match the oracle's, which splits by the place the fetch is
//! used in (measured, 3.5-dev11):
//! - a bare rule expression (`set-var(txn.a) <fetch>`) is refused with "fetch method
//!   '<action>' extracts information from '<part>', none of which is available here",
//!   the period only for the `http-*` rules: an `http-request` rule has no server
//!   (`req.timer.queue`, `bc.timer.connect`) nor response statistics (`res.timer.data`);
//!   a `tcp-request session`/`connection` rule has neither, plus no request head
//!   (`req.timer.tq`) nor transaction statistics (`txn.timer.*`); a `tcp-request
//!   content` rule has the head (the bytes are in, and `mode http` parses them) and
//!   admits those three; an `http-response` / `http-after-response` / `tcp-response`
//!   rule has no request headers left (`req.timer.tq`);
//! - a rule's format (`set-var-fmt(txn.a) "%[<fetch>]"`, a `set-header` value) is
//!   refused in the `log-format` words, "sample fetch <<fetch>> may not be reliably used
//!   here because it needs '<part>' which is not available here", with the same parts
//!   and the same split between the checkpoints; a `log-format` refuses `req.timer.tq`
//!   only, and a `unique-id-format` refuses the server's and the response's statistics;
//! - a condition that cannot match is only warned about, and still loads.
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

/// The wait the slow backend makes before its body: long enough that `tt`, `ta`,
/// `tu` and `td` are clearly above the bounds the tests check.
const BODY_PAUSE: Duration = Duration::from_millis(300);

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

/// The backend: answers its head at once, its body after `BODY_PAUSE`, closes.
fn slow_server() -> SocketAddr {
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
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n");
                thread::sleep(BODY_PAUSE);
                let _ = s.write_all(b"ok");
            });
        }
    });
    addr
}

/// The proxy: every fetch in a place the oracle admits, read from a `log-format`
/// and from the response headers; `req.timer.tq` travels from the `http-request`
/// rule through a variable, as the oracle refuses it in the response rules' formats.
fn start() -> Proxy {
    let (fe, sentinel) = (common::reserve_addr(), common::reserve_addr());
    let be = slow_server();
    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "global\n  log stdout format raw local0\n\
         defaults\n  mode http\n  log global\n\
         \x20 log-format \"hu=%HU tw=%[req.timer.queue] tc=%[bc.timer.connect] th=%[fc.timer.handshake] \
             tt=%[fc.timer.total] ta=%[txn.timer.total] tu=%[txn.timer.user] td=%[res.timer.data]\"\n\
         \x20 timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend f\n  bind {fe}\n\
         \x20 http-request deny if {{ path /denied }}\n\
         \x20 http-request set-var(txn.tq) req.timer.tq unless {{ path /nope }}\n\
         \x20 http-request set-var(txn.th) fc.timer.handshake unless {{ path /nope }}\n\
         \x20 http-response set-header x-tq %[var(txn.tq)] unless {{ path /nope }}\n\
         \x20 http-response set-header x-th %[fc.timer.handshake] unless {{ path /nope }}\n\
         \x20 http-response set-header x-td %[res.timer.data] unless {{ path /nope }}\n\
         \x20 http-response set-header x-ta %[txn.timer.total] unless {{ path /nope }}\n\
         \x20 http-response set-header x-tt %[fc.timer.total] unless {{ path /nope }}\n\
         \x20 http-after-response set-header y-tu %[txn.timer.user] unless {{ path /nope }}\n\
         \x20 http-after-response set-header y-tw %[req.timer.queue] unless {{ path /nope }}\n\
         \x20 http-after-response set-header y-tc %[bc.timer.connect] unless {{ path /nope }}\n\
         \x20 default_backend b\n\
         frontend s\n  bind {sentinel}\n  http-request return status 200\n\
         backend b\n  server s {be}\n"
    )
    .expect("write");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn");
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
    Proxy { child, fe, logs, _cfg: cfg }
}

/// The `name=` field of the log line of the request to `uri`, polled until the
/// stream's line is written.
fn log_field(p: &Proxy, uri: &str, name: &str) -> i64 {
    let want = format!("hu={uri}");
    let start = Instant::now();
    loop {
        let got = p.logs.lock().unwrap().iter().find(|l| l.contains(&want)).cloned();
        if let Some(line) = got {
            return line
                .split_whitespace()
                .find_map(|t| t.strip_prefix(&format!("{name}=")).and_then(|v| v.parse().ok()))
                .unwrap_or_else(|| panic!("no {name} in log line '{line}'"));
        }
        assert!(start.elapsed() < Duration::from_secs(5), "no log line matching '{want}': {:?}", &*p.logs.lock().unwrap());
        thread::sleep(Duration::from_millis(20));
    }
}

/// Sends one request, reads until the close, and gives the status and the
/// response headers as lowercased `(name, value)` pairs.
fn exchange(p: &Proxy, path: &str) -> (u16, Vec<(String, String)>) {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nhost: t\r\n\r\n");
    c.write_all(req.as_bytes()).expect("write");
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

/// The header's value, parsed; the test fails where the fetch gave none.
fn value(headers: &[(String, String)], name: &str) -> i64 {
    let v = headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str()).unwrap_or_else(|| panic!("no {name} header: {headers:?}"));
    v.parse().unwrap_or_else(|_| panic!("{name} is not an integer: '{v}'"))
}

/// The slow request: every fetch an integer; the rule-time ones at the values the
/// oracle measures (`req.timer.tq` is `-1`, `fc.timer.handshake` is `0`, and the
/// `t_close`-based ones read `0` there); the log's ones the shape the oracle writes.
#[test]
fn timer_fetches_slow_request() {
    let p = start();
    let (status, headers) = exchange(&p, "/slow");
    assert_eq!(status, 200);
    // `http-request` rule: the request is not complete yet, the handshake never was.
    assert_eq!(value(&headers, "x-tq"), -1, "req.timer.tq in an http-request rule");
    assert_eq!(value(&headers, "x-th"), 0, "fc.timer.handshake in an http-request rule");
    // `http-response` rule: `t_close` is still 0; the head arrived at once.
    for (name, why) in [("x-td", "res.timer.data"), ("x-ta", "txn.timer.total"), ("x-tt", "fc.timer.total")] {
        let v = value(&headers, name);
        assert!((-20..=50).contains(&v), "{why} in an http-response rule is {v}, outside -20..=50");
    }
    // `http-after-response` rule: the queue and the connect are done, and short.
    for name in ["y-tw", "y-tc"] {
        let v = value(&headers, name);
        assert!((-20..=100).contains(&v), "{name} is {v}, outside -20..=100");
    }
    let tu = value(&headers, "y-tu");
    assert!((-20..=50).contains(&tu), "txn.timer.user in an http-after-response rule is {tu}");
    // The access log: the slow body makes the close-based timers clearly non-zero,
    // and the queue/connect spans non-negative and below the total.
    let tw = log_field(&p, "/slow", "tw");
    let tc = log_field(&p, "/slow", "tc");
    assert_eq!(log_field(&p, "/slow", "th"), 0, "fc.timer.handshake in the log");
    let tt = log_field(&p, "/slow", "tt");
    let ta = log_field(&p, "/slow", "ta");
    let tu = log_field(&p, "/slow", "tu");
    let td = log_field(&p, "/slow", "td");
    assert!((200..=5000).contains(&tt), "fc.timer.total in the log is {tt}");
    assert!((200..=5000).contains(&ta), "txn.timer.total in the log is {ta}");
    assert!((200..=5000).contains(&tu), "txn.timer.user in the log is {tu}");
    assert!((200..=5000).contains(&td), "res.timer.data in the log is {td}");
    assert!((0..=200).contains(&tw), "req.timer.queue in the log is {tw}");
    assert!((0..=200).contains(&tc), "bc.timer.connect in the log is {tc}");
    assert!(tw <= tt && tc <= tt, "queue {tw} / connect {tc} spans exceed the total {tt}");
    drop(p);
}

/// The denied request: the server is never queued, connected, nor given data.
#[test]
fn timer_fetches_denied_request() {
    let p = start();
    let (status, _) = exchange(&p, "/denied");
    assert_eq!(status, 403);
    assert_eq!(log_field(&p, "/denied", "tw"), -1, "req.timer.queue of a denied request");
    assert_eq!(log_field(&p, "/denied", "tc"), -1, "bc.timer.connect of a denied request");
    assert_eq!(log_field(&p, "/denied", "td"), -1, "res.timer.data of a denied request");
    assert_eq!(log_field(&p, "/denied", "th"), 0, "fc.timer.handshake of a denied request");
    for name in ["tt", "ta", "tu"] {
        let v = log_field(&p, "/denied", name);
        assert!((0..=5000).contains(&v), "{name} of a denied request is {v}");
    }
}

/// Runs the binary on `-c -f` with a config that puts `line` in the `frontend f`
/// (or the `backend b`, where `in_backend`) section; the load's exit and stderr.
fn check_config(line: &str, in_backend: bool) -> (i32, String) {
    let (fe, sentinel) = (common::reserve_addr(), common::reserve_addr());
    let be = common::reserve_addr();
    let mut cfg = NamedTempFile::new().expect("tmp");
    let (fe_line, be_line) = if in_backend {
        ("\x20 default_backend b\n".to_string(), format!("{line}\x20 server s {be}\n"))
    } else {
        (format!("{line}\x20 default_backend b\n"), format!("\x20 server s {be}\n"))
    };
    write!(
        cfg,
        "global\n  log stdout format raw local0\n\
         defaults\n  mode http\n  log global\n\
         \x20 timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n{fe_line}\
         frontend s\n  bind {sentinel}\n  http-request return status 200\n\
         backend b\n{be_line}"
    )
    .expect("write");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let p = Command::new(bin).arg("-c").arg("-f").arg(cfg.path()).stderr(Stdio::piped()).output().expect("spawn");
    (p.status.code().unwrap_or(-1), String::from_utf8_lossy(&p.stderr).into_owned())
}

/// `req.timer.tq` is refused in a `log-format`, in the oracle's words.
#[test]
fn tq_refused_in_log_format() {
    let (code, err) = check_config("\x20 log-format \"tq=%[req.timer.tq]\"\n", false);
    assert_ne!(code, 0, "a log-format reading req.timer.tq must not load:\n{err}");
    assert!(
        err.contains("sample fetch <req.timer.tq> may not be reliably used here because it needs 'HTTP request headers' which is not available here."),
        "refusal without the oracle's reason:\n{err}"
    );
}

/// The other seven fetches are all admitted in a `log-format`: the log is written when
/// everything they read is known.
#[test]
fn log_format_admits_the_rest() {
    let (code, err) = check_config(
        "\x20 log-format \"a=%[req.timer.queue] b=%[bc.timer.connect] c=%[res.timer.data] d=%[txn.timer.total] e=%[txn.timer.user] f=%[fc.timer.handshake] g=%[fc.timer.total]\"\n",
        false,
    );
    assert_eq!(code, 0, "the log-format must load:\n{err}");
}

/// `req.timer.queue` and `bc.timer.connect` read the server, which an `http-request`
/// rule has not chosen: refused there.
#[test]
fn server_timers_refused_in_request_rule() {
    for fetch in ["req.timer.queue", "bc.timer.connect"] {
        let (code, err) = check_config(&format!("\x20 http-request set-var(txn.a) {fetch} unless {{ path /nope }}\n"), false);
        assert_ne!(code, 0, "{fetch} in an http-request rule must not load:\n{err}");
        assert!(
            err.contains("error detected in frontend 'f' while parsing 'http-request set-var(txn.a)' rule : fetch method 'set-var(txn.a)' extracts information from 'server address', none of which is available here."),
            "{fetch} refused without the oracle's reason:\n{err}"
        );
    }
}

/// `res.timer.data` reads the response's final statistics, which a request rule has
/// not: refused there.
#[test]
fn res_data_refused_in_request_rule() {
    let (code, err) = check_config("\x20 http-request set-var(txn.a) res.timer.data unless { path /nope }\n", false);
    assert_ne!(code, 0, "res.timer.data in an http-request rule must not load:\n{err}");
    assert!(
        err.contains("error detected in frontend 'f' while parsing 'http-request set-var(txn.a)' rule : fetch method 'set-var(txn.a)' extracts information from 'response buffer statistics', none of which is available here."),
        "refusal without the oracle's reason:\n{err}"
    );
}

/// The rest is admitted in an `http-request` rule: what the request stamps so far,
/// the connection and the transaction as they go.
#[test]
fn request_rule_admits_the_rest() {
    for fetch in ["req.timer.tq", "txn.timer.total", "txn.timer.user", "fc.timer.handshake", "fc.timer.total"] {
        let (code, err) = check_config(&format!("\x20 http-request set-var(txn.a) {fetch} unless {{ path /nope }}\n"), false);
        assert_eq!(code, 0, "{fetch} in an http-request rule must load:\n{err}");
    }
    // And in a rule's format too, as in a header's value.
    let (code, err) = check_config("\x20 http-request set-header x-tq %[req.timer.tq] unless { path /nope }\n", false);
    assert_eq!(code, 0, "req.timer.tq in an http-request header must load:\n{err}");
}

/// An `http-response` / `http-after-response` rule has no request headers left:
/// `req.timer.tq` is refused in its format, in the oracle's words.
#[test]
fn response_rule_refuses_request_timer() {
    for kw in ["http-response", "http-after-response"] {
        let (code, err) = check_config(&format!("\x20 {kw} set-header x-tq %[req.timer.tq] unless {{ path /nope }}\n"), false);
        assert_ne!(code, 0, "req.timer.tq in a {kw} rule must not load:\n{err}");
        assert!(
            err.contains(&format!("error detected in frontend 'f' while parsing '{kw} set-header' rule : sample fetch <req.timer.tq> may not be reliably used here because it needs 'HTTP request headers' which is not available here.")),
            "refusal without the oracle's reason:\n{err}"
        );
    }
}

/// The other seven fetches are admitted in an `http-response` rule: by then the
/// request's stamps, the server and the response's head are known.
#[test]
fn response_rule_admits_the_rest() {
    for fetch in [
        "req.timer.queue",
        "bc.timer.connect",
        "res.timer.data",
        "txn.timer.total",
        "txn.timer.user",
        "fc.timer.handshake",
        "fc.timer.total",
    ] {
        let (code, err) = check_config(&format!("\x20 http-response set-var(txn.a) {fetch} unless {{ path /nope }}\n"), false);
        assert_eq!(code, 0, "{fetch} in an http-response rule must load:\n{err}");
    }
}

/// A `tcp-request session` rule has no server, no response, no request head and no
/// finished transaction: its expression refuses six of the eight fetches. The oracle
/// splits `session` and `connection` the same way; Alcyon runs the `connection` rules
/// before the session exists, so its parser knows no `set-var` there yet, and this test
/// drives the split through `session`.
#[test]
fn tcp_request_session_connection_refuses() {
    let refused: [(&str, &str); 6] = [
        ("req.timer.tq", "HTTP request headers"),
        ("txn.timer.total", "transaction statistics"),
        ("txn.timer.user", "transaction statistics"),
        ("req.timer.queue", "server address"),
        ("bc.timer.connect", "server address"),
        ("res.timer.data", "response buffer statistics"),
    ];
    for ck in ["session"] {
        for (fetch, part) in refused {
            let line = format!("\x20 tcp-request {ck} set-var(txn.a) {fetch} unless {{ path /nope }}\n");
            let (code, err) = check_config(&line, false);
            assert_ne!(code, 0, "{fetch} in a tcp-request {ck} rule must not load:\n{err}");
            assert!(
                err.contains(&format!("fetch method 'set-var(txn.a)' extracts information from '{part}', none of which is available here")),
                "{fetch} refused without the oracle's reason:\n{err}"
            );
        }
        // The connection's own facts stay: the handshake and the stream's elapsed time.
        for fetch in ["fc.timer.handshake", "fc.timer.total"] {
            let line = format!("\x20 tcp-request {ck} set-var(txn.a) {fetch} unless {{ path /nope }}\n");
            let (code, err) = check_config(&line, false);
            assert_eq!(code, 0, "{fetch} in a tcp-request {ck} rule must load:\n{err}");
        }
        // The rule's format is refused in the log-format words, the same split.
        for (fetch, part) in refused {
            let line = format!("\x20 tcp-request {ck} set-var-fmt(txn.a) %[{fetch}] unless {{ path /nope }}\n");
            let (code, err) = check_config(&line, false);
            assert_ne!(code, 0, "the format %[{fetch}] in a tcp-request {ck} rule must not load:\n{err}");
            assert!(
                err.contains(&format!("sample fetch <{fetch}> may not be reliably used here because it needs '{part}' which is not available here")),
                "the format refused without the oracle's reason:\n{err}"
            );
        }
        let line = format!("\x20 tcp-request {ck} set-var-fmt(txn.a) %[fc.timer.total] unless {{ path /nope }}\n");
        let (code, err) = check_config(&line, false);
        assert_eq!(code, 0, "the format %[fc.timer.total] in a tcp-request {ck} rule must load:\n{err}");
    }
}

/// A `tcp-request content` rule has the request's first bytes -- the head in
/// `mode http` -- so it admits `req.timer.tq` and the `txn.timer.*` fetches, but
/// still has no server and no response.
#[test]
fn tcp_request_content_split() {
    for (fetch, part) in [("req.timer.queue", "server address"), ("bc.timer.connect", "server address"), ("res.timer.data", "response buffer statistics")] {
        let (code, err) = check_config(&format!("\x20 tcp-request content set-var(txn.a) {fetch} unless {{ path /nope }}\n"), false);
        assert_ne!(code, 0, "{fetch} in a tcp-request content rule must not load:\n{err}");
        assert!(
            err.contains(&format!("fetch method 'set-var(txn.a)' extracts information from '{part}', none of which is available here")),
            "{fetch} refused without the oracle's reason:\n{err}"
        );
        let (code, err) = check_config(&format!("\x20 tcp-request content set-var-fmt(txn.a) %[{fetch}] unless {{ path /nope }}\n"), false);
        assert_ne!(code, 0, "the format %[{fetch}] in a tcp-request content rule must not load:\n{err}");
        assert!(
            err.contains(&format!("sample fetch <{fetch}> may not be reliably used here because it needs '{part}' which is not available here")),
            "the format refused without the oracle's reason:\n{err}"
        );
    }
    for fetch in ["req.timer.tq", "txn.timer.total", "txn.timer.user", "fc.timer.handshake", "fc.timer.total"] {
        let (code, err) = check_config(&format!("\x20 tcp-request content set-var(txn.a) {fetch} unless {{ path /nope }}\n"), false);
        assert_eq!(code, 0, "{fetch} in a tcp-request content rule must load:\n{err}");
    }
    let (code, err) = check_config("\x20 tcp-request content set-var-fmt(txn.a) %[req.timer.tq] unless { path /nope }\n", false);
    assert_eq!(code, 0, "the format %[req.timer.tq] in a tcp-request content rule must load:\n{err}");
}

/// A `tcp-response` rule (a backend's) has the response, but no request headers left:
/// its expression and its format refuse `req.timer.tq` only.
#[test]
fn tcp_response_refuses_request_timer() {
    let (code, err) = check_config("\x20 tcp-response content set-var(txn.a) req.timer.tq unless { path /nope }\n", true);
    assert_ne!(code, 0, "req.timer.tq in a tcp-response rule must not load:\n{err}");
    assert!(
        err.contains("fetch method 'set-var(txn.a)' extracts information from 'HTTP request headers', none of which is available here"),
        "refusal without the oracle's reason:\n{err}"
    );
    let (code, err) = check_config("\x20 tcp-response content set-var-fmt(txn.a) %[req.timer.tq] unless { path /nope }\n", true);
    assert_ne!(code, 0, "the format %[req.timer.tq] in a tcp-response rule must not load:\n{err}");
    assert!(
        err.contains("sample fetch <req.timer.tq> may not be reliably used here because it needs 'HTTP request headers' which is not available here"),
        "the format refused without the oracle's reason:\n{err}"
    );
    for fetch in ["req.timer.queue", "bc.timer.connect", "res.timer.data"] {
        let (code, err) = check_config(&format!("\x20 tcp-response content set-var(txn.a) {fetch} unless {{ path /nope }}\n"), true);
        assert_eq!(code, 0, "{fetch} in a tcp-response rule must load:\n{err}");
        let (code, err) = check_config(&format!("\x20 tcp-response content set-var-fmt(txn.a) %[{fetch}] unless {{ path /nope }}\n"), true);
        assert_eq!(code, 0, "the format %[{fetch}] in a tcp-response rule must load:\n{err}");
    }
}

/// A `unique-id-format` is compiled where a `log-format` is not: the server's and the
/// response's final statistics are not known when the id is built.
#[test]
fn unique_id_format_refuses_final_statistics() {
    for (fetch, part) in [("req.timer.queue", "server address"), ("bc.timer.connect", "server address"), ("res.timer.data", "response buffer statistics")] {
        let (code, err) = check_config(&format!("\x20 unique-id-format %[{fetch}]\n"), false);
        assert_ne!(code, 0, "unique-id-format %[{fetch}] must not load:\n{err}");
        assert!(
            err.contains(&format!("failed to parse unique-id : sample fetch <{fetch}> may not be reliably used here because it needs '{part}' which is not available here.")),
            "refusal without the oracle's reason:\n{err}"
        );
    }
    for fetch in ["req.timer.tq", "txn.timer.total", "txn.timer.user", "fc.timer.handshake", "fc.timer.total"] {
        let (code, err) = check_config(&format!("\x20 unique-id-format %[{fetch}]\n"), false);
        assert_eq!(code, 0, "unique-id-format %[{fetch}] must load:\n{err}");
    }
}
