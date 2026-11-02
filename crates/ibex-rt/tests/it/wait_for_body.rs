// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-request wait-for-body`, `http-response wait-for-body` and `option
//! http-buffer-request`: the message is held until its body (or `at-least` bytes of it)
//! is here, the buffer is full, or the time is up, and the rules after the wait see the
//! body in `req.body` / `res.body`.
//!
//! Every expected value below was measured on the reference binary,
//! `HAProxy 3.5-dev8-885761-29`, on 2026-10-04, with the same configurations and a
//! raw-socket client and server. Where a figure depends on how `HAProxy` lays a request
//! out in its buffer (how many body bytes fit when the buffer is full) the test bounds it
//! and says so.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n";

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn start(cfg: &str, srv: SocketAddr, log: Option<SocketAddr>) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let mut text = cfg.replace("{fe}", &fe.to_string()).replace("{srv}", &srv.to_string());
    if let Some(l) = log {
        text = text.replace("{log}", &l.to_string());
    }
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, _cfg: f };
    assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}");
    (ibex, fe)
}

/// What the server saw of one request: its head, the body bytes that followed, and when
/// the first byte arrived.
struct Seen {
    head: String,
    body: Vec<u8>,
    at: Instant,
}

impl Seen {
    fn header(&self, name: &str) -> Option<String> {
        self.head.split("\r\n").skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    }
}

struct Server {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    fn seen(&self) -> std::sync::MutexGuard<'_, Vec<Seen>> {
        self.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Waits until the server has recorded `n` requests, at most 20 s: a loaded host takes far
/// longer than a fixed second to get a request through the proxy.
fn wait_seen(srv: &Server, n: usize) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while srv.seen().len() < n && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
}

/// A server that records each request (head, then the body its framing announces, for up
/// to 400 ms of silence), answers `200 ok` and keeps the connection.
fn server() -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let log = log.clone();
            thread::spawn(move || {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = vec![0u8; 65536];
                loop {
                    c.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match c.read(&mut chunk) {
                            Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                            _ => return,
                        }
                    }
                    let at = Instant::now();
                    let eoh = buf.windows(4).position(|w| w == b"\r\n\r\n").map_or(0, |p| p + 4);
                    let head = String::from_utf8_lossy(&buf[..eoh]).into_owned();
                    buf.drain(..eoh);
                    let lower = head.to_ascii_lowercase();
                    let want = lower
                        .split("\r\n")
                        .find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok()));
                    let chunked = lower.contains("transfer-encoding: chunked");
                    c.set_read_timeout(Some(Duration::from_millis(900))).ok();
                    loop {
                        let done = match (want, chunked) {
                            (Some(n), _) => buf.len() >= n,
                            (None, true) => buf.ends_with(b"0\r\n\r\n"),
                            _ => true,
                        };
                        if done {
                            break;
                        }
                        match c.read(&mut chunk) {
                            Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                            _ => break,
                        }
                    }
                    let body = match want {
                        Some(n) if buf.len() >= n => buf.drain(..n).collect(),
                        _ => std::mem::take(&mut buf),
                    };
                    log.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(Seen { head, body, at });
                    if c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                        return;
                    }
                }
            });
        }
    });
    Server { addr, seen }
}

/// A client: sends in steps, reads what comes back.
struct Client {
    s: TcpStream,
    t0: Instant,
}

impl Client {
    fn connect(fe: SocketAddr) -> Client {
        let s = TcpStream::connect(fe).expect("connect");
        Client { s, t0: Instant::now() }
    }

    fn send(&mut self, bytes: &[u8]) -> &mut Self {
        self.s.write_all(bytes).expect("send");
        self
    }

    fn pause(&mut self, ms: u64) -> &mut Self {
        thread::sleep(Duration::from_millis(ms));
        self
    }

    /// Reads until the peer closes or `idle` passes with nothing; returns what came and
    /// when the first byte did.
    fn read(&mut self, idle: Duration) -> (Vec<u8>, Option<Duration>) {
        self.s.set_read_timeout(Some(idle)).ok();
        let (mut got, mut first) = (Vec::new(), None);
        let mut chunk = vec![0u8; 65536];
        while let Ok(n) = self.s.read(&mut chunk) {
            if n == 0 {
                break;
            }
            first.get_or_insert(self.t0.elapsed());
            got.extend_from_slice(&chunk[..n]);
        }
        (got, first)
    }
}

/// The first log line that mentions `needle`: the probe connection the harness opens to see
/// the proxy is up logs one of its own.
fn log_line_of(logs: &UdpSocket, needle: &str) -> String {
    let mut buf = [0u8; 2048];
    loop {
        let n = logs.recv(&mut buf).unwrap_or_else(|e| panic!("no log line with {needle:?}: {e}"));
        let line = text(&buf[..n]);
        if line.contains(needle) {
            return line;
        }
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// The frontend: `fe_rules` first, then the two rules that report what `req.body` and
/// `req.body_len` were when the rules after the wait ran, then the backend.
fn cfg(fe_rules: &str, be_lines: &str) -> String {
    format!(
        "{DEFAULTS}frontend fe\n  bind {{fe}}\n  {fe_rules}\n  http-request set-header X-Len %[req.body_len]\n  \
         http-request set-header X-Body %[req.body]\n  default_backend be\nbackend be\n  {be_lines}\n  server s {{srv}}\n"
    )
}

const POST_CL10: &[u8] = b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\n";

#[test]
fn the_request_is_held_until_its_whole_body_is_here() {
    // HAProxy: x-len: 10, x-body: abcdefghij, the server's first byte at +0.50 s.
    let srv = server();
    let (_i, fe) = start(&cfg("http-request wait-for-body time 5s", ""), srv.addr, None);
    let mut c = Client::connect(fe);
    c.send(POST_CL10).send(b"abcde").pause(500).send(b"fghij");
    let (resp, _) = c.read(Duration::from_millis(1500));
    assert!(text(&resp).starts_with("HTTP/1.1 200"), "{}", text(&resp));
    let seen = srv.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].header("x-len").as_deref(), Some("10"), "{}", seen[0].head);
    assert_eq!(seen[0].header("x-body").as_deref(), Some("abcdefghij"));
    assert_eq!(seen[0].body, b"abcdefghij");
    let waited = seen[0].at.duration_since(c.t0);
    assert!(waited >= Duration::from_millis(450), "the server heard the request after {waited:?}, before the body was here");
}

#[test]
fn a_body_that_does_not_come_in_time_is_a_408_and_never_reaches_the_server() {
    // HAProxy: `408 Request Time-out` after 300 ms, log `-1/-1/-1/-1/300 408 ... cR--`;
    // the same with at-least 6 and 5 bytes sent.
    for rule in ["http-request wait-for-body time 300ms", "http-request wait-for-body time 300ms at-least 6"] {
        let srv = server();
        let logs = UdpSocket::bind("127.0.0.1:0").expect("log socket");
        logs.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let cfg = format!(
            "{DEFAULTS}frontend fe\n  bind {{fe}}\n  option httplog\n  log {{log}} local0\n  {rule}\n  default_backend be\n\
             backend be\n  server s {{srv}}\n"
        );
        let (_i, fe) = start(&cfg, srv.addr, Some(logs.local_addr().expect("addr")));
        let mut c = Client::connect(fe);
        c.send(POST_CL10).send(b"abcde");
        let (resp, first) = c.read(Duration::from_millis(1500));
        let resp = text(&resp);
        assert!(resp.starts_with("HTTP/1.1 408 Request Time-out\r\n"), "{rule}: {resp}");
        let first = first.expect("an answer");
        assert!(
            first >= Duration::from_millis(280) && first < Duration::from_millis(1200),
            "{rule}: the 408 came after {first:?}, the wait was 300 ms"
        );
        assert!(srv.seen().is_empty(), "{rule}: the request reached the server");
        let line = log_line_of(&logs, "POST /x");
        assert!(line.contains(" 408 ") && line.contains(" cR-- "), "{rule}: {line}");
        assert!(line.contains(" fe/<NOSRV> -1/-1/-1/-1/"), "{rule}: no request time, as HAProxy logs it: {line}");
    }
}

#[test]
fn at_least_lets_the_rules_run_on_the_bytes_that_are_here() {
    // HAProxy, 5 of 10 bytes sent, `time 300ms at-least 5`: x-len: 5, x-body: abcde, at once.
    let srv = server();
    let (_i, fe) = start(&cfg("http-request wait-for-body time 10s at-least 5", ""), srv.addr, None);
    let mut c = Client::connect(fe);
    c.send(POST_CL10).send(b"abcde");
    wait_seen(&srv, 1);
    let seen = srv.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].header("x-len").as_deref(), Some("5"));
    assert_eq!(seen[0].header("x-body").as_deref(), Some("abcde"));
    assert!(seen[0].at.duration_since(c.t0) < Duration::from_millis(5000), "it waited for more than at-least");
}

#[test]
fn a_body_shorter_than_at_least_is_complete_when_it_ends() {
    // HAProxy, a 5-byte body, `at-least 100`: x-len: 5, at once.
    let srv = server();
    // The wait is 4 s and "at once" is anything under 2 s: load moves the arrival by tens of
    // milliseconds, a rule waiting for `at-least` bytes that cannot come moves it by 4 s.
    let (_i, fe) = start(&cfg("http-request wait-for-body time 4s at-least 100", ""), srv.addr, None);
    let mut c = Client::connect(fe);
    c.send(b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nabcde");
    let _ = c.read(Duration::from_millis(1200));
    wait_seen(&srv, 1);
    let seen = srv.seen();
    assert_eq!(seen[0].header("x-len").as_deref(), Some("5"));
    assert!(seen[0].at.duration_since(c.t0) < Duration::from_millis(2000));
}

#[test]
fn a_chunked_body_is_seen_decoded_and_counted_in_data_bytes() {
    // HAProxy, chunks `hello` then (500 ms later) `abc` and the end: x-len: 8, x-body:
    // helloabc at +0.50 s. With `at-least 5`: x-len: 5, x-body: hello, at once. With
    // `at-least 6`: as without, the first chunk is 5 bytes.
    for (rule, len, body, late) in [
        ("http-request wait-for-body time 5s", "8", "helloabc", true),
        ("http-request wait-for-body time 5s at-least 5", "5", "hello", false),
        ("http-request wait-for-body time 5s at-least 6", "8", "helloabc", true),
    ] {
        let srv = server();
        let (_i, fe) = start(&cfg(rule, ""), srv.addr, None);
        let mut c = Client::connect(fe);
        c.send(b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
            .pause(500)
            .send(b"3\r\nabc\r\n0\r\n\r\n");
        let (resp, _) = c.read(Duration::from_millis(1500));
        assert!(text(&resp).starts_with("HTTP/1.1 200"), "{rule}: {}", text(&resp));
        let seen = srv.seen();
        assert_eq!(seen[0].header("x-len").as_deref(), Some(len), "{rule}: {}", seen[0].head);
        assert_eq!(seen[0].header("x-body").as_deref(), Some(body), "{rule}");
        let at = seen[0].at.duration_since(c.t0);
        assert_eq!(at >= Duration::from_millis(450), late, "{rule}: the server heard it after {at:?}");
        // The whole body reaches the server whichever way it was waited for.
        let got = text(&seen[0].body);
        assert!(got.contains("hello") && got.contains("abc") && got.ends_with("0\r\n\r\n"), "{rule}: {got:?}");
    }
}

#[test]
fn a_request_without_a_body_is_not_held() {
    // HAProxy: x-len: 0, at once.
    let srv = server();
    // The wait is 10 s and "at once" is anything under 5 s: a held request is seen at 10 s,
    // and a loaded host is not mistaken for it.
    let (_i, fe) = start(&cfg("http-request wait-for-body time 10s", ""), srv.addr, None);
    let mut c = Client::connect(fe);
    c.send(b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n");
    wait_seen(&srv, 1);
    let seen = srv.seen();
    assert_eq!(seen[0].header("x-len").as_deref(), Some("0"));
    assert!(seen[0].at.duration_since(c.t0) < Duration::from_millis(5000));
}

#[test]
fn a_full_buffer_ends_the_wait_with_what_fits() {
    // HAProxy (tune.bufsize 16384), a 100000-byte body of which 50000 are sent, `time 400ms`:
    // the rules run at once on 15220 body bytes (not a 408). How many bytes fit depends on
    // the head's layout in the buffer, so the test bounds it by the buffer's size.
    let srv = server();
    let cfg = format!(
        "{DEFAULTS}frontend fe\n  bind {{fe}}\n  http-request wait-for-body time 10s\n  \
         http-request set-header X-Len %[req.body_len]\n  default_backend be\nbackend be\n  server s {{srv}}\n"
    );
    let (_i, fe) = start(&cfg, srv.addr, None);
    let mut c = Client::connect(fe);
    c.send(b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 100000\r\n\r\n").send(&vec![b'a'; 50000]);
    wait_seen(&srv, 1);
    let seen = srv.seen();
    assert_eq!(seen.len(), 1, "the request must reach the server, not time out");
    let len: usize = seen[0].header("x-len").and_then(|v| v.parse().ok()).expect("x-len");
    assert!((13_000..=15_360).contains(&len), "x-len {len}");
    assert!(seen[0].at.duration_since(c.t0) < Duration::from_millis(5000), "it waited with a full buffer");
}

#[test]
fn expect_100_continue_is_answered_by_the_proxy_and_not_forwarded() {
    // HAProxy: `100 Continue` to the client at once, the server's request has no Expect
    // header, and (with the body 300 ms later) arrives after it. The same when the body
    // was already there.
    for late in [true, false] {
        let srv = server();
        let (_i, fe) = start(&cfg("http-request wait-for-body time 2s", ""), srv.addr, None);
        let mut c = Client::connect(fe);
        c.send(b"POST /x HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n");
        if late {
            c.pause(300);
        }
        c.send(b"abcd");
        let (resp, _) = c.read(Duration::from_millis(1200));
        let resp = text(&resp);
        assert!(resp.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"), "late={late}: {resp}");
        let seen = srv.seen();
        assert_eq!(seen[0].header("expect"), None, "late={late}: {}", seen[0].head);
        assert_eq!(seen[0].header("x-len").as_deref(), Some("4"), "late={late}");
        assert_eq!(seen[0].body, b"abcd");
    }
}

#[test]
fn a_rule_before_the_wait_runs_before_it_and_one_after_it_waits_for_the_body() {
    // HAProxy: a `deny` ahead of the wait answers 403 at once, without the body; a `deny`
    // after it on `req.body` answers 403 once the body (500 ms) is here; `use_backend` on
    // the body picks `be2` after the wait.
    let srv = server();
    let cfg = format!(
        "{DEFAULTS}frontend fe\n  bind {{fe}}\n  http-request deny if {{ path /deny }}\n  \
         http-request wait-for-body time 5s\n  http-request deny if {{ req.body -m sub fgh }}\n  \
         use_backend be2 if {{ req.body -m sub xyz }}\n  default_backend be\n\
         backend be\n  http-request set-header X-Be be\n  server s {{srv}}\n\
         backend be2\n  http-request set-header X-Be be2\n  server s {{srv}}\n"
    );
    let (_i, fe) = start(&cfg, srv.addr, None);
    let mut c = Client::connect(fe);
    c.send(b"POST /deny HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\n");
    let (resp, first) = c.read(Duration::from_millis(600));
    assert!(text(&resp).starts_with("HTTP/1.1 403"), "{}", text(&resp));
    assert!(first.expect("answer") < Duration::from_millis(400), "the deny before the wait was held");

    let mut c = Client::connect(fe);
    c.send(POST_CL10).send(b"abcde").pause(500).send(b"fghij");
    let (resp, first) = c.read(Duration::from_millis(600));
    assert!(text(&resp).starts_with("HTTP/1.1 403"), "{}", text(&resp));
    assert!(first.expect("answer") >= Duration::from_millis(450), "the deny on the body ran before the body was here");

    let mut c = Client::connect(fe);
    c.send(POST_CL10).send(b"abcde").pause(300).send(b"vwxyz");
    let (resp, _) = c.read(Duration::from_millis(1000));
    assert!(text(&resp).starts_with("HTTP/1.1 200"), "{}", text(&resp));
    assert_eq!(srv.seen().last().and_then(|s| s.header("x-be")).as_deref(), Some("be2"));
}

#[test]
fn the_option_waits_like_a_wait_for_body_ahead_of_the_rules() {
    // HAProxy: `option http-buffer-request` in a frontend, in `defaults`, and in the
    // backend alone each hold the request for its body (x-len: 10 at +0.50 s).
    let in_fe = cfg("option http-buffer-request", "");
    let in_defaults = cfg("", "").replacen(DEFAULTS, &format!("{DEFAULTS}  option http-buffer-request\n"), 1);
    let in_be = cfg("", "option http-buffer-request");
    for (what, conf) in [("frontend", in_fe), ("defaults", in_defaults), ("backend", in_be)] {
        let srv = server();
        let (_i, fe) = start(&conf, srv.addr, None);
        let mut c = Client::connect(fe);
        c.send(POST_CL10).send(b"abcde").pause(500).send(b"fghij");
        let (resp, _) = c.read(Duration::from_millis(1500));
        assert!(text(&resp).starts_with("HTTP/1.1 200"), "{what}: {}", text(&resp));
        let seen = srv.seen();
        assert_eq!(seen[0].header("x-len").as_deref(), Some("10"), "{what}");
        assert!(seen[0].at.duration_since(c.t0) >= Duration::from_millis(450), "{what}: not held");
    }
}

#[test]
fn the_option_times_out_on_timeout_http_request_else_timeout_client() {
    // HAProxy: with `timeout http-request 300ms` (client 5 s) a body that never completes
    // is a 408 at 300 ms; with only `timeout client 600ms`, at 600 ms.
    for (timeouts, want_ms) in [("timeout http-request 300ms", 300u64), ("timeout client 600ms", 600)] {
        let srv = server();
        let cfg = cfg(&format!("option http-buffer-request\n  {timeouts}"), "");
        let (_i, fe) = start(&cfg, srv.addr, None);
        let mut c = Client::connect(fe);
        c.send(POST_CL10).send(b"abcde");
        let (resp, first) = c.read(Duration::from_millis(2500));
        assert!(text(&resp).starts_with("HTTP/1.1 408"), "{timeouts}: {}", text(&resp));
        let first = first.expect("answer");
        assert!(
            first >= Duration::from_millis(want_ms - 20) && first < Duration::from_millis(want_ms + 700),
            "{timeouts}: the 408 came after {first:?}"
        );
        assert!(srv.seen().is_empty(), "{timeouts}: the request reached the server");
    }
}

/// T373. `option http-buffer-request` waits on the `timeout http-request` of the proxy the
/// request is in (`s->be->timeout.httpreq`, http_ana.c:852); unset, there is no deadline of
/// the wait's own, and only the `timeout client` read timer, which each read refreshes,
/// applies. Measured on 3.5-dev8-885761-29: client 1s, a body byte every 300 ms for 3 s:
/// 200, no 408, the server sees the request at ~3.0 s, log `3006/0/1/1/3008 200 ----`.
#[test]
fn the_option_without_timeout_http_request_does_not_time_out_a_client_that_keeps_sending() {
    let srv = server();
    let (_i, fe) = start(&cfg("timeout client 1s\n  option http-buffer-request", ""), srv.addr, None);
    let mut c = Client::connect(fe);
    c.send(b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\n");
    for _ in 0..10 {
        c.pause(300).send(b"a");
    }
    let (resp, _) = c.read(Duration::from_millis(1500));
    assert!(text(&resp).starts_with("HTTP/1.1 200"), "a client sending every 300 ms (timeout client 1s): {}", text(&resp));
    let seen = srv.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].body, b"aaaaaaaaaa");
}

/// Same measurement: `timeout http-request 10s` in the frontend, `1s` in the backend that
/// holds the option, a body byte every 300 ms: `408 cR--` at 1.00 s (the backend's value
/// applies, trickling does not extend it), log `-1/-1/-1/-1/999 408 0 - - cR--`.
#[test]
fn the_option_in_a_backend_times_out_on_that_backends_timeout_http_request() {
    let srv = server();
    let logs = UdpSocket::bind("127.0.0.1:0").expect("log socket");
    logs.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let cfg = format!(
        "{DEFAULTS}frontend fe\n  bind {{fe}}\n  option httplog\n  log {{log}} local0\n  timeout http-request 10s\n  \
         default_backend be\nbackend be\n  timeout http-request 1s\n  option http-buffer-request\n  server s {{srv}}\n"
    );
    let (_i, fe) = start(&cfg, srv.addr, Some(logs.local_addr().expect("addr")));
    let mut c = Client::connect(fe);
    c.send(POST_CL10);
    let mut early = Vec::new();
    for _ in 0..8 {
        c.pause(300).send(b"a");
        c.s.set_nonblocking(true).ok();
        let mut b = [0u8; 512];
        if let Ok(n) = c.s.read(&mut b) {
            early.extend_from_slice(&b[..n]);
        }
        c.s.set_nonblocking(false).ok();
        if !early.is_empty() {
            break;
        }
    }
    let (rest, _) = c.read(Duration::from_millis(500));
    early.extend_from_slice(&rest);
    let at = c.t0.elapsed();
    assert!(text(&early).starts_with("HTTP/1.1 408"), "{}", text(&early));
    assert!(at < Duration::from_millis(2300), "the 408 was still not here after {at:?}; the backend's wait is 1 s");
    assert!(srv.seen().is_empty(), "the request reached the server");
    let line = log_line_of(&logs, "POST /x");
    assert!(line.contains(" 408 ") && line.contains(" cR-- "), "{line}");
}

#[test]
fn a_malformed_request_body_is_a_400_and_never_reaches_the_server() {
    // HAProxy, a chunked request whose first chunk size is `zz`: `400 Bad request`, nothing
    // to the server.
    let srv = server();
    let (_i, fe) = start(&cfg("http-request wait-for-body time 2s", ""), srv.addr, None);
    let mut c = Client::connect(fe);
    c.send(b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n");
    let (resp, first) = c.read(Duration::from_millis(1200));
    assert!(text(&resp).starts_with("HTTP/1.1 400 Bad request\r\n"), "{}", text(&resp));
    assert!(first.expect("answer") < Duration::from_millis(500));
    assert!(srv.seen().is_empty(), "the request reached the server");
}

#[test]
fn every_request_of_a_connection_waits_and_a_client_that_leaves_is_not_forwarded() {
    // HAProxy: two requests on one connection, the second one split 400 ms: both x-len
    // right, the second held. A client that closes mid-body reaches no server.
    let srv = server();
    let (_i, fe) = start(&cfg("http-request wait-for-body time 5s", ""), srv.addr, None);
    let mut c = Client::connect(fe);
    c.send(b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\nabcd");
    thread::sleep(Duration::from_millis(700));
    c.send(b"POST /y HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nabcde").pause(400).send(b"fghij");
    let (resp, _) = c.read(Duration::from_millis(1500));
    assert_eq!(text(&resp).matches("HTTP/1.1 200").count(), 2, "{}", text(&resp));
    {
        let seen = srv.seen();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].header("x-len").as_deref(), Some("4"));
        assert_eq!(seen[1].header("x-len").as_deref(), Some("10"));
        assert!(seen[1].at.duration_since(c.t0) >= Duration::from_millis(1050), "the second request was not held");
    }
    let before = srv.seen().len();
    let mut c = Client::connect(fe);
    c.send(POST_CL10).send(b"abcde").pause(200);
    drop(c);
    thread::sleep(Duration::from_millis(700));
    assert_eq!(srv.seen().len(), before, "a request cut short reached the server");
}

#[test]
fn an_allow_ahead_of_the_wait_ends_the_rules_and_the_request_is_not_held() {
    // HAProxy: `http-request allow` stops the list, so the wait after it is never reached:
    // the request goes at once, with no x-len set.
    let srv = server();
    let cfg = cfg("http-request allow if { path /x }\n  http-request wait-for-body time 20s", "");
    let (_i, fe) = start(&cfg, srv.addr, None);
    let mut c = Client::connect(fe);
    c.send(POST_CL10).send(b"abcde");
    wait_seen(&srv, 1);
    let seen = srv.seen();
    assert_eq!(seen.len(), 1, "the request must go on");
    assert!(seen[0].at.duration_since(c.t0) < Duration::from_millis(10_000), "it was held");
}

#[test]
fn an_http2_client_is_not_held_for_a_body() {
    // The body of an HTTP/2 request does not pass through the buffer the wait reads, so the
    // wait does not apply to it: a GET on an `h2` bind is answered at once.
    let srv = server();
    let cfg = cfg("http-request wait-for-body time 5s", "").replace("bind {fe}", "bind {fe} proto h2");
    let (_i, fe) = start(&cfg, srv.addr, None);
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(1500))).ok();
    let frame = |kind: u8, flags: u8, id: u32, payload: &[u8]| {
        let mut v = u32::try_from(payload.len()).expect("short").to_be_bytes()[1..].to_vec();
        v.extend_from_slice(&[kind, flags]);
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(payload);
        v
    };
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");
    let mut head = vec![0x82, 0x86, 0x04, 1, b'/', 0x01, 9];
    head.extend_from_slice(b"localhost");
    s.write_all(&frame(0x01, 0x05, 1, &head)).expect("headers");
    let t0 = Instant::now();
    let (mut buf, mut answered) = (Vec::new(), false);
    let mut chunk = vec![0u8; 4096];
    while !answered && t0.elapsed() < Duration::from_millis(2500) {
        match s.read(&mut chunk) {
            Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => {}
        }
        // A HEADERS frame of stream 1 whose first byte is `:status 200` (static index 8).
        let mut at = 0;
        while at + 9 <= buf.len() {
            let len = (usize::from(buf[at]) << 16) | (usize::from(buf[at + 1]) << 8) | usize::from(buf[at + 2]);
            if at + 9 + len > buf.len() {
                break;
            }
            answered |= buf[at + 3] == 0x01 && buf[at + 9..].first() == Some(&0x88);
            at += 9 + len;
        }
    }
    assert!(answered, "no `200` HEADERS frame within {:?}", t0.elapsed());
    assert!(t0.elapsed() < Duration::from_millis(1500), "answered after {:?}", t0.elapsed());
    assert_eq!(srv.seen().len(), 1);
}

#[test]
fn a_client_that_leaves_during_the_wait_is_a_400_flagged_cr() {
    // HAProxy, a client that sends 5 of 10 body bytes and shuts down its sending side:
    // the transaction is logged `400 ... CR--` and nothing goes to the server.
    let srv = server();
    let logs = UdpSocket::bind("127.0.0.1:0").expect("log socket");
    logs.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let cfg = format!(
        "{DEFAULTS}frontend fe\n  bind {{fe}}\n  option httplog\n  log {{log}} local0\n  http-request wait-for-body time 5s\n  \
         default_backend be\nbackend be\n  server s {{srv}}\n"
    );
    let (_i, fe) = start(&cfg, srv.addr, Some(logs.local_addr().expect("addr")));
    let mut c = Client::connect(fe);
    c.send(POST_CL10).send(b"abcde").pause(200);
    c.s.shutdown(std::net::Shutdown::Write).expect("shutdown");
    let _ = c.read(Duration::from_millis(1000));
    let line = log_line_of(&logs, "POST /x");
    assert!(line.contains(" 400 ") && line.contains(" CR-- "), "{line}");
    assert!(srv.seen().is_empty(), "a request cut short reached the server");
}

// ---------------------------------------------------------------------------------------
// http-response wait-for-body
// ---------------------------------------------------------------------------------------

/// A server that answers its first request with the `script`: byte strings sent as they
/// are, a number being a pause in milliseconds.
enum Step {
    Send(&'static [u8]),
    Pause(u64),
    /// Close the connection.
    Close,
}

fn scripted(script: Vec<Step>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let script = Arc::new(script);
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let script = script.clone();
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                c.set_read_timeout(Some(Duration::from_secs(5))).ok();
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut chunk) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
                for step in script.iter() {
                    match step {
                        Step::Send(b) => {
                            if c.write_all(b).is_err() {
                                return;
                            }
                        }
                        Step::Pause(ms) => thread::sleep(Duration::from_millis(*ms)),
                        Step::Close => return,
                    }
                }
                thread::sleep(Duration::from_millis(800));
            });
        }
    });
    addr
}

fn res_cfg(rule: &str) -> String {
    format!(
        "{DEFAULTS}frontend fe\n  bind {{fe}}\n  option httplog\n  log {{log}} local0\n  default_backend be\nbackend be\n  {rule}\n  \
         http-response set-header X-Len %[res.body_len]\n  http-response set-header X-Body %[res.body]\n  server s {{srv}}\n"
    )
}

fn res_header(resp: &str, name: &str) -> Option<String> {
    resp.split("\r\n\r\n").next()?.split("\r\n").skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

fn get(fe: SocketAddr, idle: Duration) -> (String, Option<Duration>) {
    let mut c = Client::connect(fe);
    c.send(b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n");
    let (resp, first) = c.read(idle);
    (text(&resp), first)
}

#[test]
fn the_response_is_held_until_its_whole_body_is_here() {
    // HAProxy, 5 of 10 bytes, 500 ms, the rest: the client's first byte at +0.50 s,
    // x-len: 10, x-body: aaaaaaaaaa. Chunked (5 bytes, then 3 more and the end): x-len: 8,
    // x-body: helloabc, the body re-chunked as one chunk by HAProxy and as it came by Ibex.
    let logs = UdpSocket::bind("127.0.0.1:0").expect("log socket");
    let log = logs.local_addr().expect("addr");
    let cl = scripted(vec![Step::Send(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\naaaaa"), Step::Pause(500), Step::Send(b"aaaaa")]);
    let (_i, fe) = start(&res_cfg("http-response wait-for-body time 5s"), cl, Some(log));
    let (resp, first) = get(fe, Duration::from_millis(1500));
    assert_eq!(res_header(&resp, "x-len").as_deref(), Some("10"), "{resp}");
    assert_eq!(res_header(&resp, "x-body").as_deref(), Some("aaaaaaaaaa"), "{resp}");
    assert!(first.expect("answer") >= Duration::from_millis(450), "the head was sent before the body was here");

    let ch = scripted(vec![
        Step::Send(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"),
        Step::Pause(500),
        Step::Send(b"3\r\nabc\r\n0\r\n\r\n"),
    ]);
    let (_j, fe) = start(&res_cfg("http-response wait-for-body time 5s"), ch, Some(log));
    let (resp, first) = get(fe, Duration::from_millis(1500));
    assert_eq!(res_header(&resp, "x-len").as_deref(), Some("8"), "{resp}");
    assert_eq!(res_header(&resp, "x-body").as_deref(), Some("helloabc"), "{resp}");
    assert!(first.expect("answer") >= Duration::from_millis(450));
}

#[test]
fn a_response_body_that_does_not_come_in_time_is_a_504() {
    // HAProxy: `504 Gateway Time-out` at 300 ms, log `.../301 504 ... sH--`; with
    // `at-least 5` and 5 bytes here, the response goes out at once with x-len: 5.
    let logs = UdpSocket::bind("127.0.0.1:0").expect("log socket");
    logs.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let log = logs.local_addr().expect("addr");
    let part = scripted(vec![Step::Send(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\naaaaa"), Step::Pause(1500)]);
    let (_i, fe) = start(&res_cfg("http-response wait-for-body time 300ms"), part, Some(log));
    let (resp, first) = get(fe, Duration::from_millis(1500));
    assert!(resp.starts_with("HTTP/1.1 504 Gateway Time-out\r\n"), "{resp}");
    let first = first.expect("answer");
    assert!(first >= Duration::from_millis(280) && first < Duration::from_millis(1200), "{first:?}");
    let line = log_line_of(&logs, "GET /x");
    assert!(line.contains(" 504 ") && line.contains(" sH-- "), "{line}");

    // `time 3s`, not 300 ms: "answers at once" is "does not wait for the timer", and a bound of
    // 250 ms on a 300 ms timer failed on a loaded host (T614, gate runs: the answer took >250 ms
    // to come back through a busy machine). With 3 s the server's own 1.5 s pause also sits
    // between "at once" and a wait, and 1 s stays well under both. HAProxy releases a response
    // as soon as `at-least` bytes are here, whatever `time` is.
    let (_j, fe) = start(&res_cfg("http-response wait-for-body time 3s at-least 5"), part, Some(log));
    let (resp, first) = get(fe, Duration::from_millis(1200));
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
    assert_eq!(res_header(&resp, "x-len").as_deref(), Some("5"), "{resp}");
    assert!(first.expect("answer") < Duration::from_millis(1000));
    let (_k, fe) = start(&res_cfg("http-response wait-for-body time 300ms at-least 6"), part, Some(log));
    let (resp, _) = get(fe, Duration::from_millis(1200));
    assert!(resp.starts_with("HTTP/1.1 504"), "{resp}");
}

#[test]
fn a_response_without_a_body_is_not_held() {
    // HAProxy: a 204 is answered at once with x-len: 0.
    let logs = UdpSocket::bind("127.0.0.1:0").expect("log socket");
    let log = logs.local_addr().expect("addr");
    let srv = scripted(vec![Step::Send(b"HTTP/1.1 204 No Content\r\n\r\n")]);
    let (_i, fe) = start(&res_cfg("http-response wait-for-body time 2s"), srv, Some(log));
    let (resp, first) = get(fe, Duration::from_millis(1000));
    assert!(resp.starts_with("HTTP/1.1 204"), "{resp}");
    assert_eq!(res_header(&resp, "x-len").as_deref(), Some("0"), "{resp}");
    assert!(first.expect("answer") < Duration::from_millis(250));
}

#[test]
fn a_response_cut_short_goes_on_with_what_is_here() {
    // HAProxy, a server that sends 5 of 10 bytes and closes: the response goes out at
    // once with x-len: 5 and the 5 bytes, flagged `SD--`.
    let logs = UdpSocket::bind("127.0.0.1:0").expect("log socket");
    logs.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let log = logs.local_addr().expect("addr");
    let srv = scripted(vec![Step::Send(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\naaaaa"), Step::Close]);
    let (_i, fe) = start(&res_cfg("http-response wait-for-body time 5s"), srv, Some(log));
    let (resp, _) = get(fe, Duration::from_millis(1500));
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
    assert_eq!(res_header(&resp, "x-len").as_deref(), Some("5"), "{resp}");
    assert!(resp.ends_with("aaaaa"), "{resp}");
    let line = log_line_of(&logs, "GET /x");
    assert!(line.contains(" 200 ") && line.contains(" SD-- "), "{line}");
}

#[test]
fn a_malformed_response_body_is_a_502_flagged_ph() {
    // HAProxy, a chunked response whose first chunk size is `zz`: `502 Bad Gateway` at once,
    // flagged `PH--`.
    let logs = UdpSocket::bind("127.0.0.1:0").expect("log socket");
    logs.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let log = logs.local_addr().expect("addr");
    let srv = scripted(vec![Step::Send(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n")]);
    let (_i, fe) = start(&res_cfg("http-response wait-for-body time 5s"), srv, Some(log));
    let (resp, first) = get(fe, Duration::from_millis(1500));
    assert!(resp.starts_with("HTTP/1.1 502 Bad Gateway\r\n"), "{resp}");
    assert!(first.expect("answer") < Duration::from_millis(500));
    let line = log_line_of(&logs, "GET /x");
    assert!(line.contains(" 502 ") && line.contains(" PH-- "), "{line}");
}

#[test]
fn a_response_body_that_turns_malformed_during_the_wait_is_a_502_flagged_ph() {
    // HAProxy 3.5-dev8-885761-29, measured 2026-11-02: a first chunk, then 300 ms later a chunk
    // size `zz` while `wait-for-body` waits: `502 Bad Gateway` when the bad chunk comes, `PH--`,
    // `%Ta` 300.
    let logs = UdpSocket::bind("127.0.0.1:0").expect("log socket");
    logs.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let log = logs.local_addr().expect("addr");
    let srv = scripted(vec![
        Step::Send(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"),
        Step::Pause(300),
        Step::Send(b"zz\r\nhello\r\n"),
    ]);
    let (_i, fe) = start(&res_cfg("http-response wait-for-body time 5s"), srv, Some(log));
    let (resp, first) = get(fe, Duration::from_millis(1500));
    assert!(resp.starts_with("HTTP/1.1 502 Bad Gateway\r\n"), "{resp}");
    let first = first.expect("answer");
    assert!(first >= Duration::from_millis(250) && first < Duration::from_millis(1000), "{first:?}");
    let line = log_line_of(&logs, "GET /x");
    assert!(line.contains(" 502 ") && line.contains(" PH-- "), "{line}");
}

#[test]
fn a_full_buffer_ends_the_response_wait_with_what_fits() {
    // HAProxy, a 100000-byte body of which 50000 are sent, `time 300ms`: the rules run at
    // once on 15234 body bytes. As for a request, the test bounds the figure by the buffer.
    let srv = scripted(vec![
        Step::Send(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n"),
        Step::Send(&[b'a'; 50000]),
        Step::Pause(4500),
    ]);
    // The wait is 4 s and "at once" is anything under 2 s: a loaded host moves the answer by
    // tens of milliseconds, a rule that kept waiting with a full buffer moves it by 4 s.
    let cfg = format!(
        "{DEFAULTS}frontend fe\n  bind {{fe}}\n  default_backend be\nbackend be\n  http-response wait-for-body time 4s\n  \
         http-response set-header X-Len %[res.body_len]\n  server s {{srv}}\n"
    );
    let (_i, fe) = start(&cfg, srv, None);
    let (resp, first) = get(fe, Duration::from_millis(1000));
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{}", &resp[..resp.len().min(200)]);
    let len: usize = res_header(&resp, "x-len").and_then(|v| v.parse().ok()).expect("x-len");
    assert!((13_000..=15_360).contains(&len), "x-len {len}");
    assert!(first.expect("answer") < Duration::from_millis(2000), "it waited with a full buffer");
}

#[test]
fn timeout_server_ends_a_response_wait_as_a_504() {
    // HAProxy, `timeout server 300ms` and a 2 s wait on a response that stops at 5 of 10
    // bytes: `504 Gateway Time-out` at 300 ms, flagged `sH--`.
    let logs = UdpSocket::bind("127.0.0.1:0").expect("log socket");
    logs.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let log = logs.local_addr().expect("addr");
    let srv = scripted(vec![Step::Send(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\naaaaa"), Step::Pause(1500)]);
    let cfg = res_cfg("http-response wait-for-body time 2s\n  timeout server 300ms");
    let (_i, fe) = start(&cfg, srv, Some(log));
    let (resp, first) = get(fe, Duration::from_millis(1500));
    assert!(resp.starts_with("HTTP/1.1 504 Gateway Time-out\r\n"), "{resp}");
    let first = first.expect("answer");
    assert!(first >= Duration::from_millis(280) && first < Duration::from_millis(1200), "{first:?}");
    let line = log_line_of(&logs, "GET /x");
    assert!(line.contains(" 504 ") && line.contains(" sH-- "), "{line}");
}

#[test]
fn response_rules_run_in_order_around_a_wait_in_either_proxy_and_none_runs_twice() {
    // HAProxy: a backend rule ahead of a frontend `wait-for-body` runs, then the wait, then
    // the frontend's rules on the whole body (x-len: 10, x-febody: aaaaaaaaaa). In one list,
    // a rule ahead of the wait sees the 5 bytes then here (x-pre: 5), the one after sees 10,
    // and an `add-header` after it is added once.
    let part = |ibex_cfg: String| {
        let srv = scripted(vec![Step::Send(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\naaaaa"), Step::Pause(500), Step::Send(b"aaaaa")]);
        let (i, fe) = start(&ibex_cfg, srv, None);
        let (resp, first) = get(fe, Duration::from_millis(1500));
        drop(i);
        (resp, first.expect("answer"))
    };
    let across = format!(
        "{DEFAULTS}frontend fe\n  bind {{fe}}\n  http-response wait-for-body time 5s\n  http-response set-header X-Len %[res.body_len]\n  \
         http-response set-header X-FeBody %[res.body]\n  default_backend be\nbackend be\n  http-response set-header X-Be be\n  server s {{srv}}\n"
    );
    let (resp, first) = part(across);
    assert_eq!(res_header(&resp, "x-be").as_deref(), Some("be"), "{resp}");
    assert_eq!(res_header(&resp, "x-len").as_deref(), Some("10"), "{resp}");
    assert_eq!(res_header(&resp, "x-febody").as_deref(), Some("aaaaaaaaaa"), "{resp}");
    assert!(first >= Duration::from_millis(450));

    let mid = format!(
        "{DEFAULTS}frontend fe\n  bind {{fe}}\n  default_backend be\nbackend be\n  http-response set-header X-Pre %[res.body_len]\n  \
         http-response wait-for-body time 5s\n  http-response set-header X-Len %[res.body_len]\n  http-response add-header X-Dup 1\n  server s {{srv}}\n"
    );
    let (resp, first) = part(mid);
    assert_eq!(res_header(&resp, "x-pre").as_deref(), Some("5"), "{resp}");
    assert_eq!(res_header(&resp, "x-len").as_deref(), Some("10"), "{resp}");
    // Header names are case-insensitive; HAProxy emits them lowercase (T244).
    let dups = resp.split("\r\n").filter(|l| l.split_once(": ").is_some_and(|(n, v)| n.eq_ignore_ascii_case("X-Dup") && v == "1")).count();
    assert_eq!(dups, 1, "{resp}");
    assert!(first >= Duration::from_millis(450));
}
