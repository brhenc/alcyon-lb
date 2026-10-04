// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `declare capture`, `http-request capture` and `http-response capture`: the slots a
//! rule fills, how long each one holds, and the configurations `HAProxy` refuses.
//!
//! Every expected value below was measured on the reference binary,
//! `HAProxy 3.5-dev8-885761-29`, on 2026-10-03, with the same configurations (the
//! `ibex -c` messages from `haproxy -c`, the headers from a raw-socket client).

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n";

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn start(cfg: &str, srv: SocketAddr, srv2: Option<SocketAddr>) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let mut text = cfg.replace("{fe}", &fe.to_string()).replace("{srv}", &srv.to_string());
    if let Some(s) = srv2 {
        text = text.replace("{srv2}", &s.to_string());
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

/// `ibex -c -f` on `cfg`: whether it was accepted, and what it said.
fn check(cfg: &str) -> (bool, String) {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run ibex -c");
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

/// A server answering every request with `HTTP/1.1 200 OK`, the `extra` header lines
/// (raw bytes) and an empty body, then closing.
fn server(extra: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut chunk) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
                let mut resp = b"HTTP/1.1 200 OK\r\n".to_vec();
                resp.extend_from_slice(extra);
                resp.extend_from_slice(b"Content-Length: 0\r\nConnection: close\r\n\r\n");
                let _ = c.write_all(&resp);
            });
        }
    });
    addr
}

/// The raw response to `req` (bytes, as sent), until the peer closes.
fn exchange(fe: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    c.write_all(req).expect("send");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    got
}

/// The value of header `name` (any case) in a raw response, if present.
fn header(resp: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(resp);
    let want = format!("{}:", name.to_ascii_lowercase());
    text.split("\r\n\r\n").next()?.split("\r\n").skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (format!("{}:", k.to_ascii_lowercase()) == want).then(|| v.trim().to_string())
    })
}

/// `http-response capture <sample> id <n>` writes the response slot `declare capture
/// response len <n>` made, cut to that slot's length, and the rules after it (and the
/// logs) read it back with `capture.res.hdr(<n>)`.
///
/// `HAProxy` with two slots of 4 and 5 bytes, a 9-byte `X-S` from the server, a rule
/// writing `res.hdr(x-s)` into slot 0, a backend rule writing `str(be)` into slot 1 unless
/// the server sent `X-T`, and a frontend rule writing `res.hdr(x-s)` into slot 1 when it
/// did: `x-r0: 1234` in both cases, `x-r1: be` without `X-T` and `x-r1: 12345` with it
/// (the backend's rules run first, and `str(be)` is not cut: it is shorter than 5).
#[test]
fn an_http_response_capture_fills_the_slot_it_names() {
    let cfg = format!(
        "{DEFAULTS}frontend fe\n  bind {{fe}}\n  declare capture response len 4\n  declare capture response len 5\n  \
         http-response capture res.hdr(x-s) id 0\n  http-response capture res.hdr(x-s) id 1 if {{ res.hdr(x-t) -m found }}\n  \
         http-response set-header x-r0 \"%[capture.res.hdr(0)]\"\n  http-response set-header x-r1 \"%[capture.res.hdr(1)]\"\n  \
         use_backend be2 if {{ path /t }}\n  default_backend be\n\
         backend be\n  http-response capture str(be) id 1 unless {{ res.hdr(x-t) -m found }}\n  server s1 {{srv}}\n\
         backend be2\n  server s1 {{srv2}}\n"
    );
    let plain = server(b"X-S: 123456789\r\n");
    let with_t = server(b"X-S: 123456789\r\nX-T: 1\r\n");
    let (_ibex, fe) = start(&cfg, plain, Some(with_t));
    let r = exchange(fe, b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");
    assert_eq!(header(&r, "x-r0").as_deref(), Some("1234"), "slot 0 is 4 bytes long: {}", String::from_utf8_lossy(&r));
    assert_eq!(header(&r, "x-r1").as_deref(), Some("be"), "the backend's rule filled slot 1: {}", String::from_utf8_lossy(&r));
    let r = exchange(fe, b"GET /t HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");
    assert_eq!(header(&r, "x-r0").as_deref(), Some("1234"), "{}", String::from_utf8_lossy(&r));
    assert_eq!(header(&r, "x-r1").as_deref(), Some("12345"), "slot 1 is 5 bytes long: {}", String::from_utf8_lossy(&r));
}

/// A response capture of a value shorter than the slot, and a control with no capture
/// rule: the slot reads back empty, the rule is what fills it.
#[test]
fn a_response_slot_nothing_filled_reads_empty_and_a_short_value_is_not_padded() {
    let base = format!(
        "{DEFAULTS}frontend fe\n  bind {{fe}}\n  declare capture response len 4\n  {{rule}}\n  \
         http-response set-header x-r0 \"[%[capture.res.hdr(0)]]\"\n  default_backend be\nbackend be\n  server s1 {{srv}}\n"
    );
    let srv = server(b"X-S: 12\r\n");
    let (_a, fe) = start(&base.replace("{rule}", "http-response capture res.hdr(x-s) id 0"), srv, None);
    let r = exchange(fe, b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");
    assert_eq!(header(&r, "x-r0").as_deref(), Some("[12]"), "{}", String::from_utf8_lossy(&r));
    let (_b, fe) = start(&base.replace("{rule}", ""), srv, None);
    let r = exchange(fe, b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");
    assert_eq!(header(&r, "x-r0").as_deref(), Some("[]"), "without the rule nothing fills the slot: {}", String::from_utf8_lossy(&r));
}

/// What `haproxy -c` refuses, and what it accepts, of `http-response capture` and
/// `declare`. Messages are the part after `parsing [file:line] : `.
#[test]
fn the_configurations_haproxy_refuses_are_refused() {
    let fe = |body: &str| format!("frontend fe\n  mode http\n  bind 127.0.0.1:1\n{body}");
    let refused = [
        (fe("  declare capture response len 4\n  http-response capture res.hdr(x)\n"), "expects <expression> id <idx>."),
        (fe("  declare capture response len 4\n  http-response capture res.hdr(x) len 3 id 0\n"), "expects 'id', found 'len'."),
        (
            fe("  declare capture response len 4\n  http-response capture res.hdr(x) id 1\n"),
            "unable to find capture id '1' referenced by http-response capture rule",
        ),
        (fe("  declare capture response len 4\n  http-response capture res.hdr(x) id abc\n"), "cannot parse id 'abc'."),
        ("backend be\n  mode http\n  declare capture request len 4\n".to_string(), "'declare' only available in frontend or listen section"),
        ("backend be\n  mode http\n  http-response capture str(a)\n".to_string(), "expects <expression> id <idx>."),
        (fe("  declare capture response len 4\n  http-response capture str(a) id\n"), "expects <expression> id <idx>."),
        (
            fe("  declare capture response len 4\n  http-response capture str(a) id 0 foo\n"),
            "'http-response capture' expects either 'if' or 'unless' followed by a condition but found 'foo'",
        ),
        (fe("  declare foo\n"), "unknown declaration type 'foo' (supports 'capture')"),
        (fe("  declare\n"), "'declare' needs a second keyword that specify the type of declaration ('capture')"),
        ("defaults\n  declare capture request len 4\n".to_string(), "'declare' not available in default section"),
    ];
    for (cfg, want) in &refused {
        let (ok, out) = check(cfg);
        assert!(!ok && out.contains(want), "`ibex -c` on\n{cfg}\nwanted a refusal with {want:?}; accepted={ok}, said {out:?}");
    }
    let accepted = [
        // a backend's response capture names a slot of the frontend that serves it, and
        // is not checked against any
        "backend be\n  mode http\n  http-response capture str(a) id 0\n".to_string(),
        "listen li\n  mode http\n  bind 127.0.0.1:1\n  declare capture response len 3\n  http-response capture str(a) id 0\n".to_string(),
        fe("  declare capture response len 4\n  http-response capture res.hdr(x) id 0 if { status 200 }\n"),
    ];
    for cfg in &accepted {
        let (ok, out) = check(cfg);
        assert!(ok, "`ibex -c` refused\n{cfg}\nwhich haproxy accepts: {out:?}");
    }
}

/// A backend's `http-response capture` writes the frontend's slot it names, and: a sample
/// that is not there leaves the slot as it was, and an `id` past the frontend's slots
/// captures nothing. `HAProxy` with one slot of 4 bytes and a backend capturing `str(first)`
/// into 0, an absent header into 0, `str(zz)` into 7 and `str(yy)` into 1: `x-r0: [firs]`,
/// `x-r1: []`.
#[test]
fn a_backend_response_capture_keeps_a_slot_when_there_is_no_sample_and_skips_an_id_past_the_slots() {
    let cfg = format!(
        "{DEFAULTS}frontend fe\n  bind {{fe}}\n  declare capture response len 4\n  \
         http-response set-header x-r0 \"[%[capture.res.hdr(0)]]\"\n  \
         http-response set-header x-r1 \"[%[capture.res.hdr(1)]]\"\n  default_backend be\n\
         backend be\n  http-response capture str(first) id 0\n  http-response capture res.hdr(x-none) id 0\n  \
         http-response capture str(zz) id 7\n  http-response capture str(yy) id 1\n  server s1 {{srv}}\n"
    );
    let (_ibex, fe) = start(&cfg, server(b""), None);
    let r = exchange(fe, b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");
    assert_eq!(header(&r, "x-r0").as_deref(), Some("[firs]"), "{}", String::from_utf8_lossy(&r));
    assert_eq!(header(&r, "x-r1").as_deref(), Some("[]"), "{}", String::from_utf8_lossy(&r));
}

/// An `http-request capture <sample> len <n>` takes a slot of `<n>` bytes, and a later
/// `http-request capture <sample> id <i>` into that slot is cut to it: `HAProxy` with a
/// slot of 6 and a 12-byte value gave `x-q0: zzzzzz`; 1 gave `z`; 12 and 20 the whole 12
/// (`http_action_req_capture_by_id` cuts to `fe->req_cap` of the slot).
#[test]
fn a_capture_rule_s_slot_has_the_length_the_rule_gave_it() {
    for (len, want) in [(1, "z"), (6, "zzzzzz"), (12, "zzzzzzzzzzzz"), (20, "zzzzzzzzzzzz")] {
        let cfg = format!(
            "{DEFAULTS}frontend fe\n  bind {{fe}}\n  http-request capture req.hdr(x-a) len {len}\n  \
             http-request capture str(zzzzzzzzzzzz) id 0\n  http-response set-header x-q0 \"%[capture.req.hdr(0)]\"\n  \
             default_backend be\nbackend be\n  server s1 {{srv}}\n"
        );
        let (_ibex, fe) = start(&cfg, server(b""), None);
        let r = exchange(fe, b"GET / HTTP/1.1\r\nHost: h\r\nX-A: abcdefghij\r\nConnection: close\r\n\r\n");
        assert_eq!(header(&r, "x-q0").as_deref(), Some(want), "slot of {len} bytes: {}", String::from_utf8_lossy(&r));
    }
}

/// What the collector receives until it has been quiet for a second: `start` probes the
/// frontend with a connection that sends nothing, which is logged too (`LOG ` and no
/// captures), so a test looks through every line rather than taking the first.
fn log_lines(collector: &UdpSocket) -> Vec<String> {
    collector.set_read_timeout(Some(Duration::from_secs(1))).expect("timeout");
    let mut lines = Vec::new();
    let mut buf = [0u8; 1024];
    while let Ok(n) = collector.recv(&mut buf) {
        lines.push(String::from_utf8_lossy(&buf[..n]).trim_end().to_string());
    }
    lines
}

const UTF8_CUTS: [(usize, &str, &str); 5] = [
    (1, "61", "{a}"),
    (2, "61C3", "{a#C3}"),
    (3, "61C3A9", "{a#C3#A9}"),
    (4, "61C3A9C3", "{a#C3#A9#C3}"),
    (5, "61C3A9C3A9", "{a#C3#A9#C3#A9}"),
];

/// A capture is cut by bytes: `aéé` (`61 C3 A9 C3 A9`) in a slot of 4 is `61 C3 A9 C3`, and
/// a log line shows the half character as `#C3`. `HAProxy` gave, for slots of 1, 2, 3, 4 and
/// 5 bytes, the values `61`, `61C3`, `61C3A9`, `61C3A9C3` and `61C3A9C3A9` (hex of
/// `capture.req.hdr(0)`) and `%hr` of `{a}`, `{a#C3}`, `{a#C3#A9}`, `{a#C3#A9#C3}` and
/// `{a#C3#A9#C3#A9}`. The cut is on a character boundary at 3 and 5, in the middle of one at
/// 2 and 4.
#[test]
fn a_request_capture_is_cut_by_bytes_not_characters() {
    for (len, hex, logged) in UTF8_CUTS {
        let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
        collector.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        let cfg = format!(
            "{DEFAULTS}frontend fe\n  bind {{fe}}\n  log {} local0\n  log-format \"LOG %hr\"\n  \
             declare capture request len {len}\n  http-request capture req.hdr(x-a) id 0\n  \
             http-response set-header x-q0 \"%[capture.req.hdr(0),hex]\"\n  \
             default_backend be\nbackend be\n  server s1 {{srv}}\n",
            collector.local_addr().expect("addr")
        );
        let (_ibex, fe) = start(&cfg, server(b""), None);
        let r = exchange(fe, "GET / HTTP/1.1\r\nHost: h\r\nX-A: a\u{e9}\u{e9}\r\nConnection: close\r\n\r\n".as_bytes());
        assert_eq!(header(&r, "x-q0").as_deref(), Some(hex), "request slot of {len} bytes: {}", String::from_utf8_lossy(&r));
        let lines = log_lines(&collector);
        assert!(lines.iter().any(|l| l.ends_with(&format!("LOG {logged}"))), "slot of {len} bytes: the log lines are {lines:?}");
    }
}

/// The same for a response slot: `capture.res.hdr(0)` and `%hs`.
#[test]
fn a_response_capture_is_cut_by_bytes_not_characters() {
    for (len, hex, logged) in UTF8_CUTS {
        let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
        collector.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        let cfg = format!(
            "{DEFAULTS}frontend fe\n  bind {{fe}}\n  log {} local0\n  log-format \"LOG %hs\"\n  \
             declare capture response len {len}\n  http-response capture res.hdr(x-s) id 0\n  \
             http-response set-header x-r0 \"%[capture.res.hdr(0),hex]\"\n  \
             default_backend be\nbackend be\n  server s1 {{srv}}\n",
            collector.local_addr().expect("addr")
        );
        let (_ibex, fe) = start(&cfg, server("X-S: a\u{e9}\u{e9}\r\n".as_bytes()), None);
        let r = exchange(fe, b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");
        assert_eq!(header(&r, "x-r0").as_deref(), Some(hex), "response slot of {len} bytes: {}", String::from_utf8_lossy(&r));
        let lines = log_lines(&collector);
        assert!(lines.iter().any(|l| l.ends_with(&format!("LOG {logged}"))), "slot of {len} bytes: the log lines are {lines:?}");
    }
}
