// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-after-response` on the replies the proxy makes itself (T97).
//!
//! `HAProxy` runs the after-response rules on every response it sends: the server's
//! (`http_process_res_common`) and its own, through `http_forward_proxy_resp`, which
//! `http_reply_message` (return, deny, error pages), the redirect and auth actions all
//! reach (`src/http_ana.c`). The backend's rules run first, then the frontend's if it is
//! another proxy -- and until a backend is chosen the frontend *is* `s->be`, so a reply
//! made by a frontend rule runs the frontend's rules once.
//!
//! Every expected value below was measured on the reference binary,
//! `HAProxy 3.5-dev8-885761-29`, on 2026-10-03, with a raw-socket client sending
//! `GET / HTTP/1.1\r\nHost: x\r\n\r\n` (header names as `HAProxy` sends them, which its H1
//! mux lower-cases; Ibex keeps the case it was given, so these tests compare the lines the
//! rules add, not the whole head):
//!
//! ```text
//! return       HTTP/1.1 200 OK            ...content-length: 0\r\nstatic: yes\r\n\r\n
//! deny         HTTP/1.1 403 Forbidden     ...content-type: text/html\r\nstatic: yes\r\n\r\n<html>...
//! redirect     HTTP/1.1 302 Found         ...cache-control: no-cache\r\nstatic: yes\r\n\r\n
//! auth         HTTP/1.1 401 Unauthorized  ...www-authenticate: Basic realm="l"\r\nstatic: yes\r\n\r\n
//! no server    HTTP/1.1 503 ...           ...static: yes
//! srv closes   HTTP/1.1 502 ...           ...static: yes
//! srv silent   HTTP/1.1 504 ...           ...static: yes
//! rsp deny     HTTP/1.1 502 ...           ...static: yes
//! monitor-uri  HTTP/1.1 200 OK            ...static: yes
//! bad request  HTTP/1.1 400 Bad request   (no static: the H1 mux answers, no stream)
//! req timeout  HTTP/1.1 408 ...           (no static: the H1 mux answers, no stream)
//! ```

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const G: &str = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 300ms\n";

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// Starts ibex on `cfg`, `{fe}` replaced by the listening address and `{srv}` by `srv`.
fn start(cfg: &str, srv: Option<SocketAddr>) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let mut text = cfg.replace("{fe}", &fe.to_string());
    if let Some(s) = srv {
        text = text.replace("{srv}", &s.to_string());
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

#[derive(Clone, Copy)]
enum Srv {
    /// Answers `HTTP/1.1 200 OK` with a two-byte body.
    Ok,
    /// Closes as soon as the request head is in: a 502.
    Close,
    /// Reads the request and says nothing: a 504 once `timeout server` passes.
    Silent,
}

fn server(mode: Srv) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 16384];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut chunk) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
                match mode {
                    Srv::Ok => {
                        let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Srv: 1\r\n\r\nok");
                        thread::sleep(Duration::from_millis(500));
                    }
                    Srv::Close => {}
                    Srv::Silent => thread::sleep(Duration::from_secs(2)),
                }
            });
        }
    });
    addr
}

/// Sends `req` on a new connection and returns what came back, until the peer closes or
/// `quiet` passes with nothing arriving.
fn exchange(fe: SocketAddr, req: &str, quiet: Duration) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.write_all(req.as_bytes()).expect("send");
    c.set_read_timeout(Some(quiet)).expect("timeout");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut out = Vec::new();
    let mut buf = [0u8; 16384];
    while Instant::now() < deadline {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn head(resp: &str) -> &str {
    resp.split_once("\r\n\r\n").map_or(resp, |(h, _)| h)
}

/// The header lines of `resp` named `name`, in order, as `name: value`.
fn lines_named<'a>(resp: &'a str, name: &str) -> Vec<&'a str> {
    head(resp)
        .split("\r\n")
        .skip(1)
        .filter(|l| l.split_once(':').is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(name)))
        .collect()
}

fn listen(rules: &str) -> String {
    format!("{DEFAULTS}listen l\n  bind {{fe}}\n  http-after-response set-header static yes\n{rules}")
}

/// One reply of each kind the proxy makes, each carrying `static: yes` as the last header
/// in `HAProxy`'s response.
#[test]
fn after_response_rules_run_on_every_reply_the_proxy_makes() {
    let cases: [(&str, String, Option<Srv>, &str); 9] = [
        ("http-request return", listen("  http-request return status 200\n"), None, "HTTP/1.1 200 "),
        ("http-request deny", listen("  http-request deny\n"), None, "HTTP/1.1 403 "),
        ("http-request redirect", listen("  http-request redirect location /x\n"), None, "HTTP/1.1 302 "),
        ("http-request auth", listen("  http-request auth\n"), None, "HTTP/1.1 401 "),
        ("503, no server", listen(""), None, "HTTP/1.1 503 "),
        ("502, the server closed", listen("  server s {srv}\n"), Some(Srv::Close), "HTTP/1.1 502 "),
        ("504, the server was silent", listen("  server s {srv}\n"), Some(Srv::Silent), "HTTP/1.1 504 "),
        ("http-response deny", listen("  http-response deny\n  server s {srv}\n"), Some(Srv::Ok), "HTTP/1.1 502 "),
        ("monitor-uri", listen("  monitor-uri /\n"), None, "HTTP/1.1 200 "),
    ];
    // Each case has its own daemon, and each waits out `exchange`'s quiet time on a kept-alive
    // connection: run them together (T259).
    let wrong: Vec<String> = thread::scope(|sc| {
        let runs: Vec<_> = cases
            .into_iter()
            .map(|(what, cfg, srv, status)| {
                sc.spawn(move || {
                    let (_ibex, fe) = start(&cfg, srv.map(server));
                    let resp = exchange(fe, G, Duration::from_millis(1500));
                    let last = head(&resp).rsplit("\r\n").next().unwrap_or("");
                    (!resp.starts_with(status) || last != "static: yes").then(|| format!("{what}: {resp:?}"))
                })
            })
            .collect();
        runs.into_iter().filter_map(|r| r.join().expect("case")).collect()
    });
    assert!(
        wrong.is_empty(),
        "`http-after-response set-header static yes` did not reach these replies (HAProxy \
         adds `static: yes` as the last header of each):\n{}",
        wrong.join("\n")
    );
}

/// The control: a request the H1 mux refuses, and one that never completes, are answered
/// before there is a stream, and `HAProxy` runs no rule on them -- measured:
/// `HTTP/1.1 400 Bad request\r\ncontent-length: 90\r\ncache-control: no-cache\r\n
/// connection: close\r\ncontent-type: text/html\r\n\r\n...` and the same for 408, neither
/// with `static`.
#[test]
fn replies_made_before_a_stream_exists_run_no_rule() {
    let (_ibex, fe) = start(&listen("  server s {srv}\n"), Some(server(Srv::Ok)));
    let bad = exchange(fe, "GET / HTTP/1.1\r\nHost: x\r\nBad Header\r\n\r\n", Duration::from_millis(1500));
    assert!(bad.starts_with("HTTP/1.1 400 "), "{bad:?}");
    assert!(lines_named(&bad, "static").is_empty(), "a 400 for an unparsable request ran the rules: {bad:?}");
    let slow = exchange(fe, "GET / HTTP/1.1\r\n", Duration::from_millis(2500));
    assert!(slow.starts_with("HTTP/1.1 408 "), "{slow:?}");
    assert!(lines_named(&slow, "static").is_empty(), "a 408 ran the rules: {slow:?}");
}

/// Backend rules, then frontend rules, once each -- and only the frontend's for a reply
/// made before routing. Measured (`o` headers, in order):
///
/// ```text
/// server response              o: be, o: fe
/// frontend http-request deny   o: fe
/// backend http-request deny    o: be, o: fe
/// 503, backend without server  o: be, o: fe
/// ```
#[test]
fn backend_rules_then_frontend_rules_and_only_the_proxies_the_stream_went_through() {
    let srv = server(Srv::Ok);
    let cfg = |fe_rules: &str, be_rules: &str| {
        format!(
            "{DEFAULTS}frontend f\n  bind {{fe}}\n  http-after-response add-header o fe\n{fe_rules}  default_backend b\n\
             backend b\n  http-after-response add-header o be\n{be_rules}"
        )
    };
    let cases = [
        ("server response", cfg("", "  server s {srv}\n"), vec!["o: be", "o: fe"]),
        ("frontend deny", cfg("  http-request deny\n", "  server s {srv}\n"), vec!["o: fe"]),
        ("backend deny", cfg("", "  http-request deny\n  server s {srv}\n"), vec!["o: be", "o: fe"]),
        ("503", cfg("", ""), vec!["o: be", "o: fe"]),
    ];
    for (what, cfg, want) in cases {
        let (_ibex, fe) = start(&cfg, Some(srv));
        let resp = exchange(fe, G, Duration::from_millis(1500));
        assert_eq!(lines_named(&resp, "o"), want, "{what}: {resp:?}");
    }
}

/// A `listen` section is its own frontend and backend: its rules run once. Measured: one
/// `a: 1` on the server's response and one on a `return`. Ibex added two to the server's
/// response, running the section as backend and again as frontend.
#[test]
fn a_listen_sections_rules_run_once() {
    let srv = server(Srv::Ok);
    for (what, rules) in [("server response", "  server s {srv}\n"), ("return", "  http-request return status 200\n")] {
        let cfg = format!("{DEFAULTS}listen l\n  bind {{fe}}\n  http-after-response add-header a 1\n{rules}");
        let (_ibex, fe) = start(&cfg, Some(srv));
        let resp = exchange(fe, G, Duration::from_millis(1500));
        assert_eq!(lines_named(&resp, "a"), ["a: 1"], "{what}: {resp:?}");
    }
}

/// The rules see what the request rules left: `txn` and `sess` variables, and the reply's
/// status. `req` variables are gone -- the response side prunes them
/// (`http_eval_after_res_rules`). Measured, on a `return` and on the server's response:
///
/// ```text
/// return   t: tv\r\nr: \r\ns: sv\r\nst: 200
/// server   t: tv\r\nr: \r\ns: sv\r\nst: 200
/// ```
#[test]
fn the_rules_see_the_transactions_variables_and_the_replys_status() {
    let srv = server(Srv::Ok);
    for (what, last) in [("return", "  http-request return status 200\n"), ("server response", "  server s {srv}\n")] {
        let cfg = format!(
            "{DEFAULTS}listen l\n  bind {{fe}}\n  http-request set-var(txn.t) str(tv)\n  \
             http-request set-var(req.r) str(rv)\n  http-request set-var(sess.s) str(sv)\n  \
             http-after-response set-header t %[var(txn.t)]\n  \
             http-after-response set-header r \"%[var(req.r)]\"\n  \
             http-after-response set-header s %[var(sess.s)]\n  \
             http-after-response set-header st %[status]\n{last}"
        );
        let (_ibex, fe) = start(&cfg, Some(srv));
        let resp = exchange(fe, G, Duration::from_millis(1500));
        let got: Vec<&str> = ["t", "r", "s", "st"].iter().flat_map(|n| lines_named(&resp, n)).collect();
        assert_eq!(got, ["t: tv", "r: ", "s: sv", "st: 200"], "{what}: {resp:?}");
    }
}

/// `set-status` rewrites the reply's status line. Measured: `HTTP/1.1 299 Success`.
/// (Ibex's reason for an unregistered code is `OK`; only the code is compared.)
#[test]
fn set_status_rewrites_a_generated_reply() {
    let (_ibex, fe) = start(
        &format!("{DEFAULTS}listen l\n  bind {{fe}}\n  http-after-response set-status 299\n  http-request return status 200\n"),
        None,
    );
    let resp = exchange(fe, G, Duration::from_millis(1500));
    assert!(resp.starts_with("HTTP/1.1 299 "), "{resp:?}");
}

/// Three 7000-byte headers do not fit: the rule fails in strict mode (the default). On a
/// reply the proxy made, `http_reply_and_close` then answers 500 instead, running the rules
/// again on that 500; if they fail on it too, the 500 goes out without them
/// (`TX_CONST_REPLY`). Measured:
///
/// ```text
/// big headers only `if { status 200 }`, return   500, `marker: yes`, no h1
/// big headers only `if { status 200 }`, server   500, `marker: yes`, no h1
/// big headers always, return                    500, no `marker`, no h1
/// ```
#[test]
fn a_rule_that_fails_on_a_reply_turns_it_into_a_500() {
    let srv = server(Srv::Ok);
    let big = "A".repeat(7000);
    let req = format!("GET / HTTP/1.1\r\nHost: x\r\nx: {big}\r\n\r\n");
    let rules = |cond: &str, last: &str| {
        format!(
            "{DEFAULTS}listen l\n  bind {{fe}}\n  http-request set-var(txn.big) req.hdr(x)\n  \
             http-after-response set-header h1 %[var(txn.big)]{cond}\n  \
             http-after-response set-header h2 %[var(txn.big)]{cond}\n  \
             http-after-response set-header h3 %[var(txn.big)]{cond}\n  \
             http-after-response set-header marker yes\n{last}"
        )
    };
    let cases = [
        ("return, fails on 200 only", rules(" if { status 200 }", "  http-request return status 200\n"), vec!["marker: yes"]),
        ("server, fails on 200 only", rules(" if { status 200 }", "  server s {srv}\n"), vec!["marker: yes"]),
        ("return, fails always", rules("", "  http-request return status 200\n"), vec![]),
    ];
    for (what, cfg, marker) in cases {
        let (_ibex, fe) = start(&cfg, Some(srv));
        let resp = exchange(fe, &req, Duration::from_millis(1500));
        assert!(resp.starts_with("HTTP/1.1 500 "), "{what}: {}", &resp[..resp.len().min(300)]);
        assert!(lines_named(&resp, "h1").is_empty(), "{what}: the failed rewrite went out: {}", &resp[..resp.len().min(300)]);
        assert_eq!(lines_named(&resp, "marker"), marker, "{what}: {}", &resp[..resp.len().min(300)]);
    }
}

/// The access log carries the reply that went out. Measured with a UDP collector and
/// `log-format "%HU ST=%ST B=%B ts=%ts"`:
///
/// ```text
/// return + after-response set-status 299   / ST=299 B=0 ts=LR
/// return + failing after-response          / ST=500 B=0 ts=LR
/// deny + after-response set-header         / ST=403 B=0 ts=PR
/// ```
#[test]
fn the_log_line_reports_the_reply_the_rules_made() {
    let big = "A".repeat(7000);
    let cases = [
        ("  http-after-response set-status 299\n  http-request return status 200\n", G.to_string(), "/ ST=299 B=0 ts=LR"),
        (
            "  http-request set-var(txn.big) req.hdr(x)\n  \
             http-after-response set-header h1 %[var(txn.big)] if { status 200 }\n  \
             http-after-response set-header h2 %[var(txn.big)] if { status 200 }\n  \
             http-after-response set-header h3 %[var(txn.big)] if { status 200 }\n  \
             http-request return status 200\n",
            format!("GET / HTTP/1.1\r\nHost: x\r\nx: {big}\r\n\r\n"),
            "/ ST=500 B=0 ts=LR",
        ),
        ("  http-after-response set-header a b\n  http-request deny\n", G.to_string(), "/ ST=403 B=0 ts=PR"),
    ];
    for (rules, req, want) in cases {
        let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
        collector.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        let cfg = format!(
            "{DEFAULTS}listen l\n  bind {{fe}}\n  log {} local0\n  log-format \"%HU ST=%ST B=%B ts=%ts\"\n{rules}",
            collector.local_addr().expect("addr")
        );
        let (_ibex, fe) = start(&cfg, None);
        let _ = exchange(fe, &req, Duration::from_millis(1500));
        let mut lines = Vec::new();
        let mut buf = [0u8; 4096];
        // The readiness probe's connection logs a line of its own (`<BADREQ>`); skip it.
        while let Ok(n) = collector.recv(&mut buf) {
            let l = String::from_utf8_lossy(&buf[..n]).into_owned();
            let body = l.split_once("]: ").map_or("", |(_, b)| b.trim_end()).to_string();
            if body.starts_with("/ ") {
                lines.push(body);
                break;
            }
        }
        assert_eq!(lines, [want], "{rules}");
    }
}

/// The reason phrase of a rewritten status is `http_get_reason`'s, class name included for
/// the codes it does not list. Measured on 3.5-dev8 with `http-after-response set-status N`
/// on an `http-request return status 200`.
#[test]
fn set_status_gives_the_reason_haproxy_gives() {
    let expected: [(u16, &str); 14] = [
        (101, "Switching Protocols"),
        (208, "Success"),
        (299, "Success"),
        (306, "Redirection"),
        (402, "Payment Required"),
        (408, "Request Time-out"),
        (416, "Requested range unsatisfiable"),
        (418, "I'm a teapot"),
        (419, "Client Error"),
        (499, "client has closed connection"),
        (502, "Bad Gateway or Proxy Error"),
        (504, "Gateway Time-out"),
        (505, "HTTP Version not supported"),
        (599, "Server Error"),
    ];
    let mut cfg = format!("{DEFAULTS}listen l\n  bind {{fe}}\n  http-request set-var(txn.s) req.hdr(x-s)\n");
    for (s, _) in expected {
        cfg.push_str(&format!("  http-after-response set-status {s} if {{ var(txn.s) -m str {s} }}\n"));
    }
    cfg.push_str("  http-request return status 200\n");
    let (_ibex, fe) = start(&cfg, None);
    let mut wrong = Vec::new();
    for (s, reason) in expected {
        let req = format!("GET / HTTP/1.1\r\nHost: x\r\nx-s: {s}\r\nConnection: close\r\n\r\n");
        let resp = exchange(fe, &req, Duration::from_millis(1500));
        let line = resp.split("\r\n").next().unwrap_or("");
        if line != format!("HTTP/1.1 {s} {reason}") {
            wrong.push(format!("{s}: {line:?}"));
        }
    }
    assert!(wrong.is_empty(), "reason phrases differ from HAProxy's:\n{}", wrong.join("\n"));
}

/// The termination state of a reply the proxy made after a server error. Measured with
/// `log-format "%HU ST=%ST ts=%ts"`:
///
/// ```text
/// listen, no server                                   ST=503 ts=SC
/// frontend + backend, no server                       ST=503 ts=SC
/// `http-after-response` fails on the server's reply   ST=500 ts=PH
/// ```
#[test]
fn the_termination_state_of_a_503_and_of_a_failed_rewrite() {
    let big = "A".repeat(7000);
    let fail = "  http-request set-var(txn.big) req.hdr(x)\n  \
                http-after-response set-header h1 %[var(txn.big)] if { status 200 }\n  \
                http-after-response set-header h2 %[var(txn.big)] if { status 200 }\n  \
                http-after-response set-header h3 %[var(txn.big)] if { status 200 }\n  server s {srv}\n";
    let cases = [
        ("listen l\n  bind {fe}\n", String::new(), G.to_string(), "/ ST=503 ts=SC", None),
        ("frontend f\n  bind {fe}\n  default_backend b\nbackend b\n", String::new(), G.to_string(), "/ ST=503 ts=SC", None),
        (
            "listen l\n  bind {fe}\n",
            fail.to_string(),
            format!("GET / HTTP/1.1\r\nHost: x\r\nx: {big}\r\n\r\n"),
            "/ ST=500 ts=PH",
            Some(Srv::Ok),
        ),
    ];
    for (head_cfg, rules, req, want, srv) in cases {
        let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
        collector.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        let cfg = format!(
            "{DEFAULTS}  log {} local0\n  log-format \"%HU ST=%ST ts=%ts\"\n{head_cfg}{rules}",
            collector.local_addr().expect("addr")
        );
        let (_ibex, fe) = start(&cfg, srv.map(server));
        let _ = exchange(fe, &req, Duration::from_millis(1500));
        let mut line = String::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = collector.recv(&mut buf) {
            let l = String::from_utf8_lossy(&buf[..n]).into_owned();
            let body = l.split_once("]: ").map_or("", |(_, b)| b.trim_end()).to_string();
            if body.starts_with("/ ") {
                line = body;
                break;
            }
        }
        assert_eq!(line, want, "{cfg}");
    }
}
