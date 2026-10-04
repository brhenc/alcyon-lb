// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `http-check` / `tcp-check` rules, black-box against the binary and a fake server each
//! (T134). Every expectation here was measured on `HAProxy` 3.5-dev8-885761-29: set
//! `CHECK_BIN=/home/bhenc/reference/haproxy/haproxy` to run the same file against it.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

struct Proxy(Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// A fake server: `handler` runs per connection.
fn fake(handler: impl Fn(TcpStream) + Send + Sync + 'static) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handler = Arc::new(handler);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(s) = stream else { break };
            let h = Arc::clone(&handler);
            thread::spawn(move || h(s));
        }
    });
    addr
}

/// Reads one HTTP request (head plus `content-length` body) as text.
fn read_request(s: &mut TcpStream) -> String {
    s.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let mut got = Vec::new();
    let mut b = [0u8; 4096];
    loop {
        let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) else {
            match s.read(&mut b) {
                Ok(n) if n > 0 => {
                    got.extend_from_slice(&b[..n]);
                    continue;
                }
                _ => break,
            }
        };
        let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
        let want = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok()))
            .unwrap_or(0);
        if got.len() >= end + want {
            break;
        }
        match s.read(&mut b) {
            Ok(n) if n > 0 => got.extend_from_slice(&b[..n]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&got).into_owned()
}

/// A server that records each request it receives and answers `reply`.
fn http_server(reply: &'static str) -> (SocketAddr, Receiver<String>) {
    let (tx, rx) = channel();
    let tx = Mutex::new(tx);
    let addr = fake(move |mut s| {
        let req = read_request(&mut s);
        let _ = tx.lock().map(|t| t.send(req));
        let _ = s.write_all(reply.as_bytes());
    });
    (addr, rx)
}

const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Runs the proxy on `defaults_extra` + `backend b` made of `body`, logging health checks
/// to UDP, and returns the first health-check log line for server `b/s`.
fn check_line(defaults_extra: &str, mode: &str, body: &str) -> String {
    let dir = tempfile::TempDir::new().expect("tmp");
    let syslog = UdpSocket::bind("127.0.0.1:0").expect("udp");
    syslog.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let front = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode {mode}\n  log 127.0.0.1:{} local0\n  option log-health-checks\n  timeout connect 1s\n  \
         timeout client 2s\n  timeout server 2s\n  timeout check 1s\n{defaults_extra}\nfrontend f\n  bind {front}\n  \
         default_backend b\nbackend b\n{body}\n",
        syslog.local_addr().unwrap().port()
    );
    let path = dir.path().join("p.cfg");
    std::fs::write(&path, &cfg).expect("write cfg");
    let bin = std::env::var("CHECK_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin)
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let _p = Proxy(child);
    assert!(common::wait_listening(front), "never listened:\n{cfg}");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        if let Ok((n, _)) = syslog.recv_from(&mut buf) {
            let line = String::from_utf8_lossy(&buf[..n]).into_owned();
            if line.contains("Health check for server b/s") {
                return line;
            }
        }
    }
    panic!("no health-check log line within 5s for:\n{cfg}");
}

fn has(line: &str, parts: &[&str]) {
    for p in parts {
        assert!(line.contains(p), "expected `{p}` in:\n{line}");
    }
}

fn recv(rx: &Receiver<String>) -> String {
    rx.recv_timeout(Duration::from_secs(5)).expect("the server saw no request")
}

// ---- tcp-check ------------------------------------------------------------------------

/// The server says `valid` at once and then holds the connection.
fn says_valid_then_holds(mut s: TcpStream) {
    let _ = s.write_all(b"valid");
    thread::sleep(Duration::from_millis(800));
}

fn tcp_body(srv: SocketAddr, rules: &str, timeout: &str) -> String {
    format!("  timeout check {timeout}\n  option tcp-check\n{rules}\n  server s {srv} check inter 200ms rise 1 fall 1")
}

/// A negative `expect` without `min-recv` is not conclusive on data that does not match:
/// it waits for more (or the end of the connection) and so times out; the failure is
/// reported at step 2 (the `connect` is step 1, `comment` is not a step of its own).
#[test]
fn negative_expect_without_min_recv_waits_and_reports_its_step() {
    let srv = fake(says_valid_then_holds);
    let rules = "  tcp-check connect\n  tcp-check expect !rstring \"^error\" comment \"negative check\"\n  \
                 tcp-check expect string \"valid\" comment \"positive check\"";
    let line = check_line("", "tcp", &tcp_body(srv, rules, "300ms"));
    has(&line, &["failed, reason: Layer7 timeout", "at step 2 of tcp-check"]);
}

/// With `min-recv 5` the same rule is conclusive once five bytes are in.
#[test]
fn negative_expect_with_min_recv_is_conclusive() {
    let srv = fake(says_valid_then_holds);
    let rules = "  tcp-check connect\n  tcp-check expect min-recv 5 !rstring \"^error\" comment \"negative check\"\n  \
                 tcp-check expect string \"valid\" comment \"positive check\"";
    let line = check_line("", "tcp", &tcp_body(srv, rules, "300ms"));
    has(&line, &["succeeded, reason: Layer7 check passed"]);
}

/// A `connect port 1` is a real connection to that port, whichever step it is.
#[test]
fn tcp_check_connect_port_is_refused_at_its_step() {
    let srv = fake(says_valid_then_holds);
    let rules = format!("  tcp-check connect port {}\n  tcp-check connect port 1", srv.port());
    let line = check_line("", "tcp", &tcp_body(srv, &rules, "1s"));
    has(&line, &["failed", "ECONNREFUSED returned by OS", "at step 2 of tcp-check", "connect port 1"]);
}

// ---- http-check ------------------------------------------------------------------------

fn http_body(srv: SocketAddr, rules: &str) -> String {
    format!("{rules}\n  server s {srv} check inter 200ms rise 1 fall 1")
}

/// `http-check send uri http://a/chk` with a `host` header: the request target carries
/// the authority of the Host header.
#[test]
fn http_check_send_absolute_uri_takes_the_host_headers_authority() {
    let (srv, rx) = http_server(OK);
    let rules = "  option httpchk\n  http-check send meth POST uri http://a/chk ver HTTP/1.1 \
                 hdr host a-much-longer-host-name.example.org body \"hello\"";
    let line = check_line("", "http", &http_body(srv, rules));
    has(&line, &["succeeded"]);
    let req = recv(&rx);
    assert!(
        req.starts_with("POST http://a-much-longer-host-name.example.org/chk HTTP/1.1\r\n"),
        "request was:\n{req}"
    );
    assert!(req.to_ascii_lowercase().contains("host: a-much-longer-host-name.example.org\r\n"), "{req}");
    assert!(req.ends_with("\r\n\r\nhello"), "{req}");
}

fn says(bytes: &'static [u8], hold: bool) -> impl Fn(TcpStream) + Send + Sync + 'static {
    move |mut s| {
        let _ = s.write_all(bytes);
        if hold {
            thread::sleep(Duration::from_millis(800));
        }
    }
}

/// `expect` rules against a server answering `reply`, each row measured on HAProxy:
/// (script, reply, hold the connection open, what the check log line must contain).
#[test]
fn tcp_check_expect_rules_follow_haproxy() {
    const CON: &str = "  tcp-check connect\n";
    let rows: Vec<(String, &'static [u8], bool, Vec<&str>)> = vec![
        // The response ends: a negative expect that does not match is conclusive.
        (format!("{CON}  tcp-check expect !rstring \"^error\""), b"valid", false, vec!["succeeded"]),
        // No data at all: nothing is evaluated until the timeout, whatever min-recv says.
        (
            format!("{CON}  tcp-check expect min-recv 0 !rstring \"^error\""),
            b"",
            true,
            vec!["Layer7 timeout", "\" at step 2 of tcp-check (expect regex)\""],
        ),
        // min-recv 0: a mismatch is conclusive at once.
        (
            format!("{CON}  tcp-check expect min-recv 0 string nope"),
            b"valid",
            true,
            vec!["Layer7 invalid response", "TCPCHK did not match content 'nope' at step 2"],
        ),
        // No min-recv: a mismatch waits for more data.
        (
            format!("{CON}  tcp-check expect string nope"),
            b"valid",
            true,
            vec!["Layer7 timeout", "\" at step 2 of tcp-check (expect string 'nope')\""],
        ),
        // Matched data is not consumed by a match (a `send` drops it); `string` is a substring.
        (format!("{CON}  tcp-check expect string valid\n  tcp-check expect string XXX"), b"validXXX", true, vec!["succeeded"]),
        (format!("{CON}  tcp-check expect string valid\n  tcp-check expect string valid"), b"validXXX", true, vec!["succeeded"]),
        (
            format!("{CON}  tcp-check expect !string valid"),
            b"valid",
            true,
            vec!["Layer7 invalid response", "TCPCHK matched unwanted content 'valid' at step 2"],
        ),
        (format!("{CON}  tcp-check expect min-recv 1 !string error\n  tcp-check expect string valid"), b"valid", true, vec!["succeeded"]),
        // min-recv above what arrives: wait, then time out on that rule.
        (
            format!("{CON}  tcp-check expect min-recv 50 string valid"),
            b"valid",
            true,
            vec!["Layer7 timeout", "(expect string 'valid')"],
        ),
        // No connect rule: HAProxy's own is step 0, the first rule is step 1.
        (
            "  tcp-check expect string nope".to_string(),
            b"valid",
            true,
            vec!["Layer7 timeout", "\" at step 1 of tcp-check (expect string 'nope')\""],
        ),
        // A wait resumes at, and a timeout names, the first inverse expect of the run.
        (
            format!("{CON}  tcp-check expect !string zzz\n  tcp-check expect string valid\n  tcp-check expect string nope"),
            b"valid",
            true,
            vec!["Layer7 timeout", "\" at step 2 of tcp-check (expect string 'zzz')\""],
        ),
        (
            format!("{CON}  tcp-check expect string valid"),
            b"",
            false,
            vec!["Layer7 invalid response", "TCPCHK got an empty response at step 2"],
        ),
        (format!("{CON}  tcp-check expect !string valid"), b"", false, vec!["succeeded"]),
        (
            format!("{CON}  tcp-check expect rstring ^x"),
            b"abc",
            false,
            vec!["TCPCHK did not match content (regex) at step 2"],
        ),
        (
            format!("{CON}  tcp-check expect binary 7878"),
            b"abc",
            false,
            vec!["TCPCHK did not match content (binary) at step 2"],
        ),
        (
            format!("{CON}  tcp-check expect !rstring ^a"),
            b"abc",
            false,
            vec!["TCPCHK matched unwanted content (regex) at step 2"],
        ),
        // Comments: inline, or from a `tcp-check comment` just before; rule indexes count the latter.
        (
            format!("{CON}  tcp-check expect string x comment \"hi there\""),
            b"abc",
            false,
            vec!["TCPCHK did not match content 'x' at step 2 comment: hi there"],
        ),
        (
            format!("{CON}  tcp-check comment hello\n  tcp-check expect min-recv 0 string nope"),
            b"valid",
            true,
            vec!["TCPCHK did not match content 'nope' at step 3 comment: hello"],
        ),
    ];
    for (rules, reply, hold, expected) in rows {
        let srv = fake(says(reply, hold));
        let line = check_line("", "tcp", &tcp_body(srv, &rules, "300ms"));
        for e in &expected {
            assert!(line.contains(e), "script:\n{rules}\nexpected `{e}` in:\n{line}");
        }
    }
}

/// A refused connection names its step and what the connect rule said.
#[test]
fn tcp_check_connection_errors_name_their_step() {
    let dead = common::reserve_addr();
    let cases = [
        ("  tcp-check expect string valid".to_string(), "at initial connection step of tcp-check"),
        ("  tcp-check connect\n  tcp-check expect string valid".to_string(), "at step 1 of tcp-check (connect)\""),
        (format!("  tcp-check connect port {}", dead.port()), &format!("at step 1 of tcp-check (connect port {})", dead.port())),
        ("  tcp-check comment hello\n  tcp-check expect string nope".to_string(), "at initial connection step of tcp-check"),
    ];
    for (rules, tail) in cases {
        let line = check_line("", "tcp", &tcp_body(dead, &rules, "300ms"));
        has(&line, &["Layer4 connection problem", "ECONNREFUSED returned by OS (Connection refused) ", tail]);
    }
}

/// The request an HTTP check sends, one row per configuration: (defaults, backend rules,
/// the request with `\r\n` shown as `|`). Measured on HAProxy 3.5-dev8-885761-29.
#[test]
fn http_check_requests_follow_haproxy() {
    const D: &str = "  option httpchk GET /status HTTP/1.1\n  http-check send hdr Host my body test\n";
    let rows: Vec<(&str, &str, &str)> = vec![
        ("", "  option httpchk\n  http-check send meth GET uri http://a/chk ver HTTP/1.1", "GET http://a/chk HTTP/1.1|connection: close||"),
        ("", "  option httpchk\n  http-check send meth GET uri http://a/chk ver HTTP/1.1 hdr host b", "GET http://b/chk HTTP/1.1|host: b|connection: close||"),
        ("", "  option httpchk", "OPTIONS / HTTP/1.0||"),
        ("", "  option httpchk\n  http-check send meth POST uri /x", "POST /x HTTP/1.0|content-length: 0||"),
        ("", "  option httpchk\n  http-check send meth GET uri / ver HTTP/1.0 hdr connection keep-alive", "GET / HTTP/1.0|connection: keep-alive||"),
        ("", "  option httpchk GET /status HTTP/1.1\n  http-check send hdr X y", "GET /status HTTP/1.1|x: y|connection: close||"),
        // The rule set of a section that has its own replaces the defaults' altogether.
        (D, "  option httpchk", "OPTIONS / HTTP/1.0||"),
        (D, "", "GET /status HTTP/1.1|host: my|content-length: 4|connection: close||test"),
        (D, "  http-check send hdr Host other hdr X-New true body other", "OPTIONS / HTTP/1.0|host: other|x-new: true|content-length: 5||other"),
        ("  option httpchk GET /x HTTP/1.1\n", "  http-check send hdr X y", "OPTIONS / HTTP/1.0|x: y||"),
        ("  option httpchk GET /x HTTP/1.1\n", "  option httpchk /other", "OPTIONS /other HTTP/1.0||"),
        ("  option httpchk GET /x HTTP/1.1\n  http-check expect status 201\n", "  http-check send hdr X y", "OPTIONS / HTTP/1.0|x: y||"),
        ("", "  option httpchk HEAD /h", "HEAD /h HTTP/1.0||"),
        ("", "  option httpchk /u", "OPTIONS /u HTTP/1.0||"),
        ("", "  option httpchk\n  http-check connect\n  http-check send meth GET uri /z\n  http-check expect status 200", "GET /z HTTP/1.0||"),
        ("", "  option httpchk\n  http-check send hdr HOST Foo hdr X-Upper Bar", "OPTIONS / HTTP/1.0|host: Foo|x-upper: Bar||"),
        ("", "  option httpchk\n  http-check send meth OPTIONS body abc", "OPTIONS / HTTP/1.0|content-length: 3||abc"),
        ("", "  option httpchk OPTIONS *", "OPTIONS * HTTP/1.0||"),
        ("", "  option httpchk\n  http-check set-var(check.p) str(/v)\n  http-check send meth GET uri-lf \"%[var(check.p)]\"", "GET /v HTTP/1.0||"),
    ];
    for (defaults, rules, want) in rows {
        let (srv, rx) = http_server(OK);
        check_line(defaults, "http", &http_body(srv, rules));
        let got = recv(&rx).replace("\r\n", "|");
        assert_eq!(got, want, "defaults:\n{defaults}\nrules:\n{rules}");
    }
}

/// A rule set with no `send` (a section that has `http-check expect` rules only) connects
/// and sends nothing; without `option httpchk` the rules are not used at all and the
/// check is a plain connect.
#[test]
fn http_check_without_a_send_sends_nothing() {
    let (srv, rx) = http_server(OK);
    let line = check_line("  option httpchk GET /x HTTP/1.1\n", "http", &http_body(srv, "  http-check expect status 200"));
    has(&line, &["Layer7 timeout"]);
    assert!(rx.recv_timeout(Duration::from_secs(3)).map_or(true, |r| r.is_empty()), "a request was sent");
    let (srv, _rx) = http_server(OK);
    let line = check_line("", "http", &http_body(srv, "  http-check expect status 200"));
    has(&line, &["Layer4 check passed"]);
}

/// `http-check expect` and the failures of an HTTP check, one row per rule set and reply:
/// (rules, reply, what the log line must contain).
#[test]
fn http_check_expect_rules_follow_haproxy() {
    let r200 = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX-A: one, two\r\nX-B: Val\r\nConnection: close\r\n\r\nbar";
    let r202 = "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nX-A: one, two\r\nConnection: close\r\n\r\n";
    let r404 = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let wrong = "reason: Layer7 wrong status";
    let invalid = "reason: Layer7 invalid response";
    let ok = "succeeded, reason: Layer7 check passed";
    let rows: Vec<(&str, &str, Vec<&str>)> = vec![
        ("", r200, vec![ok, "code: 200"]),
        ("", r404, vec![wrong, "code: 404, info: \"Not Found\""]),
        ("  http-check expect status 200", r202, vec![wrong, "code: 202, info: \"Accepted\""]),
        ("  http-check expect status 200,202-204", r202, vec![ok, "code: 202"]),
        ("  http-check expect rstatus ^2", r404, vec![wrong, "code: 404"]),
        ("  http-check expect ! status 200", r200, vec![wrong, "code: 200, info: \"OK\""]),
        ("  http-check expect hdr name x-missing", r200, vec![wrong, "code: 200, info: \"OK\""]),
        ("  http-check expect hdr name X-A", r200, vec![ok]),
        ("  http-check expect string foo", r200, vec![invalid, "info: \"HTTP content check did not match\""]),
        ("  http-check expect string ba", r200, vec![ok]),
        ("  http-check expect !string bar", r200, vec![invalid, "info: \"HTTP check matched unwanted content\""]),
        ("  http-check expect rstring ^z", r200, vec![invalid, "HTTP content check did not match"]),
        ("  http-check expect hdr name x-a value three", r200, vec![wrong]),
        // `hdr` looks at each comma-separated element, `fhdr` at the whole value.
        ("  http-check expect hdr name x-a value two", r200, vec![ok]),
        ("  http-check expect fhdr name x-a value two", r200, vec![wrong]),
        ("  http-check expect fhdr name x-a value \"one, two\"", r200, vec![ok]),
        ("  http-check expect hdr name x-b value val", r200, vec![wrong]),
        ("  http-check expect status 201 comment \"want 201\"", r200, vec![wrong, "info: \"OK comment: want 201\""]),
        ("  http-check expect min-recv 100 string bar", r200, vec![ok]),
        ("  http-check expect string bar", r202, vec![invalid, "HTTP content check could not find a response body"]),
        ("  http-check expect hdr name-lf \"x-%[be_name]\" value-lf Val", r200, vec![ok]),
        ("  http-check set-var(check.v) str(two)\n  http-check expect hdr name x-a value-lf \"%[var(check.v)]\"", r200, vec![ok]),
        // A `set-var` before the first `expect` runs before the response is read.
        (
            "  http-check set-var(check.v) res.fhdr(x-b)\n  http-check expect hdr name x-b value-lf \"%[var(check.v)]\"",
            r200,
            vec![invalid, "log-format string evaluated to an empty string"],
        ),
        (
            "  http-check expect status 200\n  http-check set-var(check.v) res.fhdr(x-b)\n  http-check expect hdr name x-b value-lf \"%[var(check.v)]\"",
            r200,
            vec![ok],
        ),
        ("  http-check expect string-lf \"b%[str(ar)]\"", r200, vec![ok]),
        ("  http-check expect status 200\n  http-check expect status 201", r200, vec![wrong]),
        ("  http-check expect hdr name -m beg x- value -m end ne", r200, vec![ok]),
        ("  http-check expect hdr name -m reg \"^X-[a-z]\\$\"", r200, vec![ok]),
        ("", "", vec!["reason: Socket error"]),
        ("", "garbage\r\n\r\n", vec!["reason: Socket error"]),
    ];
    for (rules, reply, expected) in rows {
        let (srv, _rx) = http_server(Box::leak(reply.to_string().into_boxed_str()));
        let line = check_line("", "http", &http_body(srv, &format!("  option httpchk\n{rules}")));
        for e in &expected {
            assert!(line.contains(e), "rules:\n{rules}\nexpected `{e}` in:\n{line}");
        }
    }
}

/// What the parser refuses rather than drop: each exit status and message is `ibex -c`'s.
#[test]
fn unimplemented_check_rules_are_refused_at_load() {
    let refused = [
        "http-check disable-on-404",
        "http-check connect ssl",
        "http-check expect status 200 on-error \"x\"",
        "http-check send meth GET hdr-lf a b",
        "http-check send meth GET\n  http-check send meth GET",
        "http-check set-var(txn.x) str(a)",
        "tcp-check connect ssl",
        "tcp-check send-lf foo",
        "tcp-check expect string a on-success b",
        "http-check expect rstring \"(\"",
    ];
    for rule in refused {
        let dir = tempfile::TempDir::new().expect("tmp");
        let path = dir.path().join("p.cfg");
        let cfg = format!(
            "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\nbackend b\n  option httpchk\n  {rule}\n  server s 127.0.0.1:1 check\n"
        );
        std::fs::write(&path, cfg).expect("write");
        let bin = env!("CARGO_BIN_EXE_ibex");
        let out = Command::new(bin).arg("-c").arg("-f").arg(&path).output().expect("run");
        assert!(!out.status.success(), "`{rule}` was accepted");
    }
}

/// A server that answers each request with `parts`, each followed by a pause (ms).
fn slow_server(parts: Vec<(&'static str, u64)>) -> SocketAddr {
    fake(move |mut s| {
        let _ = read_request(&mut s);
        for (data, ms) in &parts {
            let _ = s.write_all(data.as_bytes());
            let _ = s.flush();
            thread::sleep(Duration::from_millis(*ms));
        }
    })
}

/// Replies that arrive in pieces (the rules wait for the rest), are chunked, or end with
/// the connection; and rules on header names and values and on variables.
#[test]
fn http_check_waits_for_the_response_it_needs() {
    let head6 = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n";
    let in_three = || vec![(head6, 150), ("foo", 150), ("bar", 0)];
    let chunked = vec![("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfoo\r\n", 150), ("3\r\nbar\r\n0\r\n\r\n", 0)];
    let until_close = vec![("HTTP/1.0 200 OK\r\n\r\nfoo", 100), ("bar", 0)];
    let ok = "succeeded, reason: Layer7 check passed";
    let rows: Vec<(&str, Vec<(&'static str, u64)>, &str)> = vec![
        ("  http-check expect string bar", in_three(), ok),
        ("  http-check expect string foobar", in_three(), ok),
        ("  http-check expect min-recv 6 string foo", in_three(), ok),
        ("  http-check expect rstring ^foo", in_three(), ok),
        ("  http-check expect string zzz", in_three(), "HTTP content check did not match"),
        ("  http-check expect string foobar", chunked, ok),
        ("  http-check expect string foobar", until_close, ok),
        ("  http-check expect string a", vec![("HTTP/1.1 204 No Content\r\n\r\n", 0)], "could not find a response body"),
        ("  http-check expect string-lf \"%[var(check.none)]\"", in_three(), "log-format string evaluated to an empty string"),
        (
            "  http-check set-var(check.v) str(two)\n  http-check unset-var(check.v)\n  http-check expect hdr name x-a value-lf \"%[var(check.v)]\"",
            vec![("HTTP/1.1 200 OK\r\nX-A: two\r\nContent-Length: 0\r\n\r\n", 0)],
            "log-format string evaluated to an empty string",
        ),
        (
            "  http-check expect status 200\n  http-check set-var(check.v) str(two)\n  http-check unset-var(check.v)\n  http-check expect hdr name x-a value-lf \"%[var(check.v)]\"",
            vec![("HTTP/1.1 200 OK\r\nX-A: two\r\nContent-Length: 0\r\n\r\n", 0)],
            "log-format string evaluated to an empty string",
        ),
        ("  http-check expect hdr name -m end -a value -m beg on", vec![("HTTP/1.1 200 OK\r\nX-A: one, two\r\nContent-Length: 0\r\n\r\n", 0)], ok),
        ("  http-check expect hdr name -m sub -b value -m sub al", vec![("HTTP/1.1 200 OK\r\nX-B: Val\r\nContent-Length: 0\r\n\r\n", 0)], ok),
        ("  http-check expect hdr name x-b value -m reg \"^V.l\\$\"", vec![("HTTP/1.1 200 OK\r\nX-B: Val\r\nContent-Length: 0\r\n\r\n", 0)], ok),
        ("  http-check expect hdr name -m reg \"^y\" ", vec![("HTTP/1.1 200 OK\r\nX-B: Val\r\nContent-Length: 0\r\n\r\n", 0)], "reason: Layer7 wrong status"),
        ("  http-check expect hdr name x-b value -m reg \"^v\"", vec![("HTTP/1.1 200 OK\r\nX-B: Val\r\nContent-Length: 0\r\n\r\n", 0)], "reason: Layer7 wrong status"),
        ("  http-check expect hdr name -m end -q", vec![("HTTP/1.1 200 OK\r\nX-B: Val\r\nContent-Length: 0\r\n\r\n", 0)], "reason: Layer7 wrong status"),
        ("  http-check expect hdr name -m sub -q", vec![("HTTP/1.1 200 OK\r\nX-B: Val\r\nContent-Length: 0\r\n\r\n", 0)], "reason: Layer7 wrong status"),
        ("  http-check expect hdr name x-b value -m beg zz", vec![("HTTP/1.1 200 OK\r\nX-B: Val\r\nContent-Length: 0\r\n\r\n", 0)], "reason: Layer7 wrong status"),
        ("  http-check expect hdr name x-b value -m sub zz", vec![("HTTP/1.1 200 OK\r\nX-B: Val\r\nContent-Length: 0\r\n\r\n", 0)], "reason: Layer7 wrong status"),
        ("  http-check expect hdr name x-b value -m end zz", vec![("HTTP/1.1 200 OK\r\nX-B: Val\r\nContent-Length: 0\r\n\r\n", 0)], "reason: Layer7 wrong status"),
    ];
    for (rules, parts, expected) in rows {
        let srv = slow_server(parts);
        let line = check_line("", "http", &http_body(srv, &format!("  option httpchk\n{rules}")));
        assert!(line.contains(expected), "rules:\n{rules}\nexpected `{expected}` in:\n{line}");
    }
}

/// A server that resets the connection once the request is in.
#[test]
fn http_check_connection_reset_is_a_socket_error() {
    let srv = fake(|mut s| {
        let _ = read_request(&mut s);
        let _ = rustix::net::sockopt::set_socket_linger(&s, Some(Duration::ZERO));
    });
    let line = check_line("", "http", &http_body(srv, "  option httpchk"));
    has(&line, &["failed, reason: Socket error"]);
}

/// A connection that fails at once (the broadcast address is unreachable) names its step.
#[test]
fn tcp_check_unreachable_server_fails_at_the_connect() {
    let srv: SocketAddr = "255.255.255.255:9".parse().unwrap();
    let line = check_line("", "tcp", &tcp_body(srv, "  tcp-check connect\n  tcp-check expect string x", "300ms"));
    has(&line, &["Layer4 connection problem", "Network is unreachable", "at step 1 of tcp-check (connect)"]);
    let line = check_line("", "tcp", &tcp_body(srv, "  tcp-check expect string x", "300ms"));
    has(&line, &["Layer4 connection problem", "Network is unreachable", "at initial connection step of tcp-check"]);
}

/// The step named by a timeout on a binary `expect`.
#[test]
fn tcp_check_binary_expect_timeout_names_the_pattern() {
    let srv = fake(says(b"", true));
    let line = check_line("", "tcp", &tcp_body(srv, "  tcp-check connect\n  tcp-check expect binary 616263", "300ms"));
    has(&line, &["Layer7 timeout", "at step 2 of tcp-check (expect binary '616263')"]);
}
