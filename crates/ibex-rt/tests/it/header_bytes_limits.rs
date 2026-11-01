// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! An HTTP/1 request head as `HAProxy` takes it and gives it to the server (T285, V&V VV-8):
//!
//! 1. A header value may carry obs-text (bytes 0x80-0xFF, RFC 9110 section 5.5): Latin-1
//!    from old clients is forwarded byte for byte, and the rules see the header -- a deny on
//!    it still denies. A Latin-1 byte in `Host`, `Content-Length` or `Transfer-Encoding` is a
//!    400.
//! 2. `tune.http.maxhdr` (101) less one: a request of 101 header lines is a 400 (`PR--`,
//!    `<BADREQ>`), a response of 101 a 502 (`PH--`); 100 pass. A `Connection` line that
//!    holds only `close` / `keep-alive` is not counted.
//! 3. The head goes to the server as `HAProxy` writes it again from HTX: CRLF line ends,
//!    `name: value` with the value's blanks trimmed, `Content-Length` in canonical digits,
//!    `Transfer-Encoding: chunked` in lower case.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev8-885761-29.
//! Set `T285_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`.

use crate::common;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

/// What the server received for each request, by the path the test gave it.
type Seen = Arc<Mutex<HashMap<String, Vec<u8>>>>;

struct Proxy {
    child: Child,
    logs: Arc<Mutex<Vec<String>>>,
    /// The frontend without rules, which forwards the head as parsed.
    fe: SocketAddr,
    /// The frontend with header rules.
    rules: SocketAddr,
    seen: Seen,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// `n` response header lines: `Content-Length`, `n - 2` others and `Connection: close`.
/// `n` response header lines, `Content-Length` and `n - 1` others, and a `Connection`
/// line of `conn` if there is one.
fn response_with(n: usize, conn: Option<&str>) -> Vec<u8> {
    let mut r = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n".to_vec();
    for i in 0..n - 1 {
        r.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
    }
    if let Some(c) = conn {
        r.extend_from_slice(format!("Connection: {c}\r\n").as_bytes());
    }
    r.extend_from_slice(b"\r\nok");
    r
}

/// A server that records each request and answers it once the request has gone quiet:
/// `/res<n>` with `n` header lines (`/res<n>?<c>`: and `Connection: <c>`), anything else
/// with a two-byte body.
fn server(seen: Seen) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let seen = Arc::clone(&seen);
            thread::spawn(move || {
                let mut got = Vec::new();
                let mut b = vec![0u8; 65536];
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                loop {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&b[..n]),
                    }
                    let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
                }
                let path = got.split(|&c| c == b' ').nth(1).map(|p| String::from_utf8_lossy(p).into_owned()).unwrap_or_default();
                let res = path.strip_prefix("/res").map(|r| r.split_once('?').map_or((r, None), |(n, c)| (n, Some(c))));
                let reply = match res.and_then(|(n, c)| Some((n.parse().ok()?, c))) {
                    Some((n, c)) => response_with(n, c),
                    None => b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
                };
                seen.lock().unwrap().insert(path, got);
                let _ = s.write_all(&reply);
                thread::sleep(Duration::from_millis(100));
            });
        }
    });
    addr
}

fn start() -> Proxy {
    let (fe, rules, sentinel) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let seen: Seen = Arc::default();
    let be = server(Arc::clone(&seen));
    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "global\n  tune.ibex.h1-lowercase-headers on\n  log stdout format raw local0\n\
         defaults\n  mode http\n  log global\n  option httplog\n  timeout connect 2s\n  \
         timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  default_backend b\n\
         frontend r\n  bind {rules}\n\
         \x20 http-request deny deny_status 403 if {{ req.hdr(x-admin) -m found }}\n\
         \x20 http-request deny deny_status 405 if {{ req.hdr(x-bad) -m sub bad }}\n\
         \x20 http-request del-header x-del\n\
         \x20 http-request set-header x-added 1 if {{ path_beg /rw }}\n\
         \x20 default_backend b\n\
         frontend s\n  bind {sentinel}\n  http-request return status 200\n\
         backend b\n  server s {be}\n"
    )
    .expect("write");
    let bin = std::env::var("T285_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let mut child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn");
    let out = child.stdout.take().expect("stdout");
    let logs: Arc<Mutex<Vec<String>>> = Arc::default();
    let sink = Arc::clone(&logs);
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            sink.lock().unwrap().push(line);
        }
    });
    assert!(common::wait_listening(sentinel), "never listened");
    Proxy { child, logs, fe, rules, seen, _cfg: cfg }
}

/// The client's whole answer to `req`.
fn send(to: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut c = TcpStream::connect(to).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(req).unwrap();
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    got
}

fn esc(b: &[u8]) -> String {
    b.escape_ascii().to_string()
}

/// A request and what comes of it: the status the client gets and, when it is forwarded,
/// all the bytes the server receives.
struct Case {
    sent: Vec<u8>,
    status: u16,
    server: Option<Vec<u8>>,
}

fn case(sent: &[u8], status: u16, server: Option<&[u8]>) -> Case {
    Case { sent: sent.to_vec(), status, server: server.map(<[u8]>::to_vec) }
}

/// Runs the cases at once, each on its own connection with its own path, and lists every
/// case whose answer or forwarded head is not the one measured on `HAProxy`. `to` is
/// `p.fe` or `p.rules`.
fn run(p: &Proxy, to: SocketAddr, cases: &[Case]) {
    let answers: Vec<Vec<u8>> = thread::scope(|s| {
        let hs: Vec<_> = cases.iter().map(|c| s.spawn(move || send(to, &c.sent))).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let seen = p.seen.lock().unwrap();
    let mut wrong = Vec::new();
    for (c, got) in cases.iter().zip(&answers) {
        let path = c.sent.split(|&b| b == b' ').nth(1).map(|p| String::from_utf8_lossy(p).into_owned()).unwrap_or_default();
        let status = std::str::from_utf8(got.get(9..12).unwrap_or_default()).ok().and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
        let fwd = seen.get(&path);
        if status != c.status || fwd.map(Vec::as_slice) != c.server.as_deref() {
            wrong.push(format!(
                "{path}: sent {}\n    got {status}, server saw {:?}\n    want {}, server saw {:?}",
                esc(&c.sent),
                fwd.map(|f| esc(f)),
                c.status,
                c.server.as_deref().map(esc)
            ));
        }
    }
    assert!(wrong.is_empty(), "{} case(s) differ from HAProxy:\n{}", wrong.len(), wrong.join("\n"));
}

/// GET `path` with the extra header lines `hdrs`, and the head the server should get with
/// `fwd` as its header lines.
fn get(path: &str, hdrs: &[u8], status: u16, fwd: Option<&[u8]>) -> Case {
    let mut sent = format!("GET {path} HTTP/1.1\r\nHost: x\r\n").into_bytes();
    sent.extend_from_slice(hdrs);
    sent.extend_from_slice(b"\r\n");
    let server = fwd.map(|f| {
        let mut s = format!("GET {path} HTTP/1.1\r\nhost: x\r\n").into_bytes();
        s.extend_from_slice(f);
        s.extend_from_slice(b"\r\n");
        s
    });
    Case { sent, status, server }
}

#[test]
fn latin1_header_values_are_forwarded_byte_for_byte() {
    let p = start();
    run(&p, p.fe, &[
        get("/ua", b"User-Agent: Mozilla caf\xe9\r\n", 200, Some(b"user-agent: Mozilla caf\xe9\r\n")),
        get("/mixed", b"X-N: caf\xe9 \xff\r\n", 200, Some(b"x-n: caf\xe9 \xff\r\n")),
        get("/c1", b"X-C: \x80\x9f\xa0\r\n", 200, Some(b"x-c: \x80\x9f\xa0\r\n")),
        get("/utf8-and-latin1", b"X-M: \xc3\xa9\xe9\r\n", 200, Some(b"x-m: \xc3\xa9\xe9\r\n")),
        get("/cookie", b"Cookie: a=\xe9\r\n", 200, Some(b"cookie: a=\xe9\r\n")),
        get("/trailing-blank", b"X-A: \xe9 \r\n", 200, Some(b"x-a: \xe9\r\n")),
        get("/folded", b"X-F: a\xe9\r\n \xffb\r\n", 200, Some(b"x-f: a\xe9   \xffb\r\n")),
        // UTF-8 on the first line, Latin-1 on the next: both kept as received.
        get("/folded-utf8", b"X-F: \xc3\xa9\r\n \xff\r\n", 200, Some(b"x-f: \xc3\xa9   \xff\r\n")),
        get("/keepalive", b"Keep-Alive: t\xe9\r\n", 200, Some(b"keep-alive: t\xe9\r\n")),
        get("/trailer", b"Trailer: x\xe9\r\n", 200, Some(b"trailer: x\xe9\r\n")),
    ]);
}

#[test]
fn rules_see_a_latin1_header() {
    let p = start();
    run(&p, p.rules, &[
        get("/admin", b"X-Admin: \xff\r\n", 403, None),
        get("/bad", b"X-Bad: \xe9bad\xe9\r\n", 405, None),
        get("/del", b"X-Del: \xe9\r\nX-Keep: k\r\n", 200, Some(b"x-keep: k\r\n")),
        // The head is written again from HTX for the rule's header: the bytes survive it.
        get("/rw", b"X-R: caf\xe9\r\n", 200, Some(b"x-r: caf\xe9\r\nx-added: 1\r\n")),
    ]);
}

#[test]
fn latin1_in_a_framing_or_routing_header_is_refused() {
    let p = start();
    run(&p, p.fe, &[
        case(b"GET /host HTTP/1.1\r\nHost: caf\xe9\r\n\r\n", 400, None),
        case(b"POST /te HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\xe9\r\n\r\n0\r\n\r\n", 400, None),
        case(b"POST /cl HTTP/1.1\r\nHost: x\r\nContent-Length: 1\xe9\r\n\r\nx", 400, None),
        // Not Latin-1 but a NUL, in a folded line: refused as on any line.
        case(b"GET /fold-nul HTTP/1.1\r\nHost: x\r\nX-F: a\r\n b\x00c\r\n\r\n", 400, None),
    ]);
}

/// `Host` and `n - 1` more header lines, and a `Connection` line of `conn` if there is one.
fn many(path: &str, n: usize, conn: Option<&str>) -> Vec<u8> {
    let mut r = format!("GET {path} HTTP/1.1\r\nHost: x\r\n").into_bytes();
    for i in 0..n - 1 {
        r.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
    }
    if let Some(c) = conn {
        r.extend_from_slice(format!("Connection: {c}\r\n").as_bytes());
    }
    r.extend_from_slice(b"\r\n");
    r
}

fn log_with(p: &Proxy, needle: &str) -> Option<String> {
    for _ in 0..30 {
        if let Some(l) = p.logs.lock().unwrap().iter().find(|l| l.contains(needle)) {
            return Some(l.clone());
        }
        thread::sleep(Duration::from_millis(100));
    }
    None
}

#[test]
fn a_request_of_101_header_lines_is_a_400() {
    let p = start();
    let ok = many("/h100", 100, None);
    // As the server gets it: the names in lower case.
    let fwd = String::from_utf8(ok.clone()).unwrap().replace("Host", "host").replace("X-", "x-").into_bytes();
    // A `Connection` line of only `close` / `keep-alive` is emptied and not counted
    // (`h1_parse_connection_header`); one with another token is.
    let close = many("/h100c", 100, Some("close"));
    // It goes to the server without its `Connection: close`, as HTTP/1.1 implies it.
    let close_fwd = String::from_utf8(many("/h100c", 100, None)).unwrap().replace("Host", "host").replace("X-", "x-").into_bytes();
    let fwd_e = String::from_utf8(many("/h100e", 100, None)).unwrap().replace("Host", "host").replace("X-", "x-").into_bytes();
    let fwd_b = String::from_utf8(many("/h100b", 100, None)).unwrap().replace("Host", "host").replace("X-", "x-").into_bytes();
    run(&p, p.fe, &[
        case(&ok, 200, Some(&fwd)),
        case(&many("/h101", 101, None), 400, None),
        case(&close, 200, Some(&close_fwd)),
        case(&many("/h100f", 100, Some("foo")), 400, None),
        // An empty `Connection` line is emptied too, and not counted (T286).
        case(&many("/h100e", 100, Some("")), 200, Some(&fwd_e)),
        case(&many("/h100b", 100, Some(" , ")), 200, Some(&fwd_b)),
    ]);
    let line = log_with(&p, " f f/<NOSRV> ").expect("the 400 is logged");
    assert!(line.contains(" 400 ") && line.contains(" PR-- ") && line.contains("\"<BADREQ>\""), "{line}");
}

#[test]
fn a_response_of_101_header_lines_is_a_502() {
    let p = start();
    let req = |n: &str| format!("GET /res{n} HTTP/1.1\r\nHost: x\r\n\r\n").into_bytes();
    let fwd = |n: &str| format!("GET /res{n} HTTP/1.1\r\nhost: x\r\n\r\n").into_bytes();
    run(&p, p.fe, &[
        case(&req("100"), 200, Some(&fwd("100"))),
        case(&req("101"), 502, Some(&fwd("101"))),
        // 101 lines, one of them `Connection: close`, which is not counted.
        case(&req("100?close"), 200, Some(&fwd("100?close"))),
        case(&req("100?foo"), 502, Some(&fwd("100?foo"))),
        // An empty `Connection` line is not counted either (T286).
        case(&req("100?"), 200, Some(&fwd("100?"))),
    ]);
    let line = log_with(&p, "/res101 ").expect("the 502 is logged");
    assert!(line.contains(" 502 ") && line.contains(" PH-- "), "{line}");
}

#[test]
fn the_head_reaches_the_server_normalised() {
    let p = start();
    let post = |path: &str, hdrs: &[u8], body: &[u8], fwd: &[u8]| {
        let mut sent = format!("POST {path} HTTP/1.1\r\nHost: x\r\n").into_bytes();
        sent.extend_from_slice(hdrs);
        sent.extend_from_slice(b"\r\n");
        sent.extend_from_slice(body);
        let mut server = format!("POST {path} HTTP/1.1\r\nhost: x\r\n").into_bytes();
        server.extend_from_slice(fwd);
        server.extend_from_slice(b"\r\n");
        server.extend_from_slice(body);
        Case { sent, status: 200, server: Some(server) }
    };
    let ch: &[u8] = b"5\r\nhello\r\n0\r\n\r\n";
    run(&p, p.fe, &[
        case(b"POST /lf HTTP/1.1\nHost: x\nContent-Length: 5\n\nhello", 200,
             Some(b"POST /lf HTTP/1.1\r\nhost: x\r\ncontent-length: 5\r\n\r\nhello")),
        case(b"POST /lf-mixed HTTP/1.1\r\nHost: x\nContent-Length: 5\r\n\r\nhello", 200,
             Some(b"POST /lf-mixed HTTP/1.1\r\nhost: x\r\ncontent-length: 5\r\n\r\nhello")),
        case(b"POST /lf-last HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\nhello", 200,
             Some(b"POST /lf-last HTTP/1.1\r\nhost: x\r\ncontent-length: 5\r\n\r\nhello")),
        case(b"GET /lf-get HTTP/1.1\nHost: x\n\n", 200, Some(b"GET /lf-get HTTP/1.1\r\nhost: x\r\n\r\n")),
        post("/cl0005", b"Content-Length: 0005\r\n", b"hello", b"content-length: 5\r\n"),
        post("/cl000", b"Content-Length: 000\r\n", b"", b"content-length: 0\r\n"),
        post("/cl-blank", b"Content-Length: 5 \t\r\n", b"hello", b"content-length: 5\r\n"),
        post("/te-blank", b"Transfer-Encoding: \tchunked \t\r\n", ch, b"transfer-encoding: chunked\r\n"),
        post("/te-case", b"Transfer-Encoding: Chunked\r\n", ch, b"transfer-encoding: chunked\r\n"),
        post("/te-upper", b"Transfer-Encoding: CHUNKED\r\n", ch, b"transfer-encoding: chunked\r\n"),
        get("/trail", b"X-A: v \t \r\n", 200, Some(b"x-a: v\r\n")),
        get("/lead", b"X-A:\t\tv\r\n", 200, Some(b"x-a: v\r\n")),
        get("/nospace", b"X-A:v\r\n", 200, Some(b"x-a: v\r\n")),
        get("/empty", b"X-A:\r\n", 200, Some(b"x-a: \r\n")),
        get("/empty-sp", b"X-A: \r\n", 200, Some(b"x-a: \r\n")),
        get("/empty-ws", b"X-A:  \t\r\n", 200, Some(b"x-a: \r\n")),
        get("/inner", b"X-A: a  \t b\r\n", 200, Some(b"x-a: a  \t b\r\n")),
        case(b"GET /host-blank HTTP/1.1\r\nHost: x \r\n\r\n", 200, Some(b"GET /host-blank HTTP/1.1\r\nhost: x\r\n\r\n")),
    ]);
}

/// `TE` goes to the server only as `te: trailers`, and only when a token of it is exactly
/// `trailers`; anything else is dropped, so a server that honours `TE` does not compress or
/// chunk for a client that never asked (T286).
#[test]
fn only_te_trailers_reaches_the_server() {
    let p = start();
    let none: &[u8] = b"";
    let tr: &[u8] = b"te: trailers\r\n";
    run(&p, p.fe, &[
        get("/gzip", b"TE: gzip\r\n", 200, Some(none)),
        get("/trailers", b"TE: trailers\r\n", 200, Some(tr)),
        get("/upper", b"TE: Trailers\r\n", 200, Some(none)),
        get("/list", b"TE: trailers, gzip\r\n", 200, Some(tr)),
        get("/list2", b"TE: gzip,trailers,deflate\r\n", 200, Some(tr)),
        get("/blank", b"TE:  trailers \r\n", 200, Some(tr)),
        get("/q", b"TE: trailers;q=0.5\r\n", 200, Some(none)),
        get("/x", b"TE: trailersx\r\n", 200, Some(none)),
        get("/empty", b"TE:\r\n", 200, Some(none)),
        get("/two", b"TE: gzip\r\nTE: trailers\r\n", 200, Some(tr)),
        get("/two2", b"TE: trailers\r\nTE: gzip\r\n", 200, Some(tr)),
        get("/with-others", b"X-A: 1\r\nTE: gzip\r\nX-B: 2\r\n", 200, Some(b"x-a: 1\r\nx-b: 2\r\n")),
    ]);
}

/// A request line is `method target HTTP/<digit>.<digit>` and nothing else (T286): a version
/// that is anything more or less, however long, is a 400 -- before a 414 or a 431 can
/// say that the head is too big -- and a line with no version is one too.
#[test]
fn the_request_line_version_is_http_digit_dot_digit() {
    let p = start();
    let line = |l: &str| case(format!("{l}\r\nHost: x\r\n\r\n").as_bytes(), 400, None);
    let long = |n: usize| line(&format!("GET /long{n} HTTP/1.{}", "z".repeat(n)));
    run(&p, p.fe, &[
        line("GET /bad1 HTTP/1.z"),
        line("GET /bad2 HTTP/1."),
        line("GET /bad3 HTTP/1.10"),
        line("GET /bad4 http/1.1"),
        line("GET /bad5 HTTP/1.1x"),
        line("GET /bad6 HTTP/1.1 x"),
        line("GET /bad7 HTTP/1.1 "),
        line("GET /bad8 HTTP/1"),
        line("GET /bad9 HTTP/1.1.1"),
        line("GET /bad10"),
        long(100),
        long(5000),
        long(16100),
        long(17000),
        // HTTP/1.0 keeps its version and asks to keep alive.
        case(b"GET /ok3 HTTP/1.0\r\nHost: x\r\n\r\n", 200, Some(b"GET /ok3 HTTP/1.0\r\nhost: x\r\nconnection: keep-alive\r\n\r\n")),
    ]);
}

/// Content-Length lines that differ are not answered: `HAProxy` closes the connection
/// with nothing written and logs a 400 `PR--` (T286). A list in one line is a 400 reply.
#[test]
fn differing_content_length_lines_close_the_connection() {
    let p = start();
    let cl = |path: &str, n: usize| {
        let lines: String = (1..=n).map(|i| format!("Content-Length: {i}\r\n")).collect();
        case(format!("POST {path} HTTP/1.1\r\nHost: x\r\n{lines}\r\nxx").as_bytes(), 0, None)
    };
    run(&p, p.fe, &[
        cl("/cl2", 2),
        cl("/cl5", 5),
        case(b"POST /list HTTP/1.1\r\nHost: x\r\nContent-Length: 1, 2\r\n\r\nxx", 400, None),
    ]);
    let line = log_with(&p, " f f/<NOSRV> -1/-1/-1/-1/0 400 0 ").expect("the refusals are logged");
    assert!(line.contains(" 400 0 ") && line.contains(" PR-- "), "{line}");
}

/// A header value that is valid UTF-8 spelling U+F780 (EF 9E 80) reaches the server as those
/// bytes, not as the byte 0x80 (T286).
#[test]
fn utf8_in_the_private_use_range_is_forwarded_as_sent() {
    let p = start();
    run(&p, p.fe, &[
        get("/pua", b"X-A: \xef\x9e\x80\r\n", 200, Some(b"x-a: \xef\x9e\x80\r\n")),
        get("/pua-mixed", b"X-A: \xef\x9e\x80\xe9\r\n", 200, Some(b"x-a: \xef\x9e\x80\xe9\r\n")),
    ]);
}
