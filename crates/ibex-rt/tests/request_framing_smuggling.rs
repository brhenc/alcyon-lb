// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! How a request's body length is decided, and what is refused (tasks/T276, V&V VV-1 and
//! VV-2): every `Transfer-Encoding` and `Content-Length` line counts, not only the first,
//! and a chunked body is held to `HAProxy`'s chunk syntax.
//!
//! Each case sends one request through the proxy to a raw backend that records every byte
//! it receives, and checks both what the client was answered and what the backend saw. A
//! refused request must not reach the backend at all; a forwarded one must reach it framed
//! one way only (one `Transfer-Encoding` or one `Content-Length`, no obs-fold) with exactly
//! its own body behind its head -- a second request smuggled in the body shows up there.
//!
//! The expected values were measured on `HAProxy` 3.5-dev8. Set
//! `T276_ORACLE=/path/to/haproxy` to run the same cases against it: it passes all.

mod common;

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const UNSAFE: &str = "option accept-unsafe-violations-in-http-request";

/// What should happen to one request.
#[derive(Clone, Copy, Debug)]
enum Expect {
    /// Answered with this status by the proxy; the backend never sees it.
    Refused(u16),
    /// [`Expect::Refused`], or the connection reset before the answer was read: `HAProxy`
    /// closes on a refused request with unread body bytes, which may reset it first.
    RefusedOrReset(u16),
    /// Forwarded with exactly this payload (chunking removed), nothing after it.
    Forwarded(&'static [u8]),
    /// Only the head is forwarded: the proxy is still waiting for the first chunk line.
    HeadOnly,
}
use Expect::{Forwarded, HeadOnly, Refused, RefusedOrReset};

/// The bytes of each connection the backend accepted.
type Recorded = Arc<Mutex<Vec<Arc<Mutex<Vec<u8>>>>>>;

struct Backend {
    addr: SocketAddr,
    conns: Recorded,
}

/// A backend that records each connection's bytes and answers `200` once the client has
/// been quiet for 300 ms, then closes.
fn backend() -> Backend {
    let ls = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = ls.local_addr().expect("addr");
    let conns: Recorded = Arc::default();
    let c2 = Arc::clone(&conns);
    thread::spawn(move || {
        for s in ls.incoming() {
            let Ok(mut s) = s else { continue };
            let rec = Arc::new(Mutex::new(Vec::new()));
            c2.lock().unwrap().push(Arc::clone(&rec));
            thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
                let mut buf = vec![0u8; 65536];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) => return,
                        Ok(n) => rec.lock().unwrap().extend_from_slice(&buf[..n]),
                        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
                        Err(_) => return,
                    }
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
                thread::sleep(Duration::from_millis(100));
            });
        }
    });
    Backend { addr, conns }
}

struct Proxy {
    child: Child,
    addr: SocketAddr,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn proxy(be: SocketAddr, extra: &str) -> Proxy {
    let addr = common::reserve_addr();
    let mut cfg = NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "global\n    nbthread 1\ndefaults\n    mode http\n    timeout client 3s\n    timeout server 3s\n    \
         timeout connect 1s\n    timeout http-request 3s\nfrontend f\n    bind {addr}\n    {extra}\n    \
         default_backend b\nbackend b\n    http-reuse never\n    server s {be}\n"
    )
    .expect("write cfg");
    let bin = std::env::var("T276_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin)
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn proxy");
    assert!(common::wait_listening(addr), "proxy never listened");
    Proxy { child, addr, _cfg: cfg }
}

/// Sends `req` and reads one response (head and its `content-length` body), or until the
/// connection ends or 3 s pass. `None` when no status line came back.
fn send(addr: SocketAddr, req: &[u8]) -> (Option<u16>, Vec<u8>) {
    let mut c = TcpStream::connect(addr).expect("connect");
    let _ = c.write_all(req);
    let _ = c.set_read_timeout(Some(Duration::from_millis(200)));
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut out = Vec::new();
    let mut buf = [0u8; 16384];
    while Instant::now() < deadline {
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
        if let Some(h) = out.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&out[..h]).to_ascii_lowercase();
            let cl = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if out.len() >= h + 4 + cl {
                break;
            }
        }
    }
    let status = out
        .starts_with(b"HTTP/1.")
        .then(|| String::from_utf8_lossy(&out[9..12.min(out.len())]).parse().ok())
        .flatten();
    (status, out)
}

/// The payload of a chunked body, read strictly; `None` if it is not one well-formed
/// chunked body with nothing after it.
fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = b.windows(2).position(|w| w == b"\r\n")?;
        let line = std::str::from_utf8(&b[..eol]).ok()?;
        let size = usize::from_str_radix(line.split(';').next()?.trim(), 16).ok()?;
        b = &b[eol + 2..];
        if size == 0 {
            // Trailer fields, then the blank line, then nothing.
            loop {
                let eol = b.windows(2).position(|w| w == b"\r\n")?;
                b = &b[eol + 2..];
                if eol == 0 {
                    return b.is_empty().then_some(out);
                }
            }
        }
        out.extend_from_slice(b.get(..size)?);
        b = b.get(size..)?.strip_prefix(b"\r\n")?;
    }
}

/// What is wrong with how the backend saw the request `path`, if anything.
fn check_forwarded(path: &str, conn: &[u8], expect: Expect) -> Result<(), String> {
    let show = || String::from_utf8_lossy(&conn[..conn.len().min(200)]).into_owned();
    let h = conn.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| format!("no complete head: {:?}", show()))?;
    let head = String::from_utf8_lossy(&conn[..h + 2]).to_ascii_lowercase();
    if !head.starts_with(&format!("post {path} ")) && !head.starts_with(&format!("get {path} ")) {
        return Err(format!("not the request sent: {:?}", show()));
    }
    let lines: Vec<&str> = head.split("\r\n").skip(1).filter(|l| !l.is_empty()).collect();
    if lines.iter().any(|l| l.starts_with([' ', '\t'])) {
        return Err(format!("obs-fold forwarded: {:?}", show()));
    }
    let te = lines.iter().filter(|l| l.starts_with("transfer-encoding:")).count();
    let cl: Vec<&str> = lines.iter().filter_map(|l| l.strip_prefix("content-length:")).map(str::trim).collect();
    if te > 1 || cl.len() > 1 || (te == 1 && !cl.is_empty()) || cl.iter().any(|v| v.contains(',')) {
        return Err(format!("forwarded framed more than one way: {:?}", show()));
    }
    let body = &conn[h + 4..];
    match expect {
        HeadOnly if body.is_empty() => Ok(()),
        HeadOnly => Err(format!("body bytes forwarded: {:?}", show())),
        Forwarded(want) => {
            let got = if te == 1 {
                dechunk(body).ok_or_else(|| format!("not one well-formed chunked body: {:?}", show()))?
            } else {
                let n: usize = cl.first().map_or(Ok(0), |v| v.parse()).map_err(|_| show())?;
                if body.len() != n {
                    return Err(format!("{} body bytes behind a length of {n}: {:?}", body.len(), show()));
                }
                body.to_vec()
            };
            if got == want {
                Ok(())
            } else {
                Err(format!("payload {:?}, want {:?}", String::from_utf8_lossy(&got), String::from_utf8_lossy(want)))
            }
        }
        Refused(_) | RefusedOrReset(_) => unreachable!(),
    }
}

/// Runs every case through one proxy, in parallel, and returns what went wrong.
fn run(extra: &str, cases: &[(&'static str, Vec<u8>, Expect)]) -> Vec<String> {
    let be = backend();
    let px = proxy(be.addr, extra);
    let answers: Vec<_> = thread::scope(|s| {
        let hs: Vec<_> = cases.iter().map(|(_, req, _)| s.spawn(|| send(px.addr, req))).collect();
        hs.into_iter().map(|h| h.join().expect("client")).collect()
    });
    // Let the backend finish recording what the proxy sent.
    thread::sleep(Duration::from_millis(500));
    drop(px);
    let conns: Vec<Vec<u8>> = be.conns.lock().unwrap().iter().map(|c| c.lock().unwrap().clone()).collect();
    let mut bad = Vec::new();
    for ((name, _, expect), (status, out)) in cases.iter().zip(answers) {
        let path = format!("/{name}");
        let needle = format!(" {path} ");
        let seen: Vec<&Vec<u8>> = conns.iter().filter(|c| c.windows(needle.len()).any(|w| w == needle.as_bytes())).collect();
        let smuggled = conns.iter().any(|c| {
            c.windows(needle.len()).any(|w| w == needle.as_bytes()) && c.windows(9).any(|w| w == b"SMUGGLED ")
        });
        let verdict = match *expect {
            Refused(want) | RefusedOrReset(want) => {
                let reset_ok = matches!(expect, RefusedOrReset(_)) && status.is_none();
                if status != Some(want) && !reset_ok {
                    Err(format!("answered {status:?}, want {want}: {:?}", String::from_utf8_lossy(&out[..out.len().min(80)])))
                } else if !seen.is_empty() {
                    Err(format!("refused but forwarded: {:?}", String::from_utf8_lossy(seen[0])))
                } else {
                    Ok(())
                }
            }
            Forwarded(_) | HeadOnly => match seen.as_slice() {
                [conn] if !smuggled => check_forwarded(&path, conn, *expect),
                [] => Err(format!("never forwarded; client got {status:?}: {:?}", String::from_utf8_lossy(&out[..out.len().min(80)]))),
                _ => Err(format!("smuggled or sent twice: {:?}", seen.iter().map(|c| String::from_utf8_lossy(c)).collect::<Vec<_>>())),
            },
        };
        if let Err(e) = verdict {
            bad.push(format!("{name}: {e}"));
        }
    }
    bad
}

fn assert_all(extra: &str, cases: &[(&'static str, Vec<u8>, Expect)]) {
    let bad = run(extra, cases);
    assert!(bad.is_empty(), "{} of {} cases wrong:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

const HELLO: &[u8] = b"5\r\nhello\r\n0\r\n\r\n";

/// A POST to `/<name>` with these header lines (each without its CRLF) and this body.
fn post(name: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut r = format!("POST /{name} HTTP/1.1\r\nHost: x\r\n").into_bytes();
    for h in headers {
        r.extend_from_slice(h.as_bytes());
        r.extend_from_slice(b"\r\n");
    }
    r.extend_from_slice(b"\r\n");
    r.extend_from_slice(body);
    r
}

fn te(name: &'static str, codings: &[&str], body: &[u8], expect: Expect) -> (&'static str, Vec<u8>, Expect) {
    let lines: Vec<String> = codings.iter().map(|c| format!("Transfer-Encoding: {c}")).collect();
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    (name, post(name, &refs, body), expect)
}

fn raw(name: &'static str, headers: &[&str], body: &[u8], expect: Expect) -> (&'static str, Vec<u8>, Expect) {
    (name, post(name, headers, body), expect)
}

fn chunked(name: &'static str, body: &[u8], expect: Expect) -> (&'static str, Vec<u8>, Expect) {
    te(name, &["chunked"], body, expect)
}

/// VV-1: `Transfer-Encoding` on several lines is one list, read in order.
#[test]
fn transfer_encoding_lines_are_one_list() {
    let smuggle = b"GET /SMUGGLED HTTP/1.1\r\nHost: x\r\n\r\n";
    assert_all(
        "",
        &[
            te("te_valid", &["chunked"], HELLO, Forwarded(b"hello")),
            te("te_upper", &["CHUNKED"], HELLO, Forwarded(b"hello")),
            te("te_gzip_then_chunked", &["gzip", "chunked"], HELLO, Refused(422)),
            te("te_gzip_then_chunked_get", &["gzip", "chunked"], smuggle, Refused(422)),
            te("te_identity_then_chunked", &["identity", "chunked"], HELLO, Refused(422)),
            te("te_gzip_chunked_one", &["gzip, chunked"], HELLO, Refused(422)),
            te("te_chunked_then_gzip", &["chunked", "gzip"], HELLO, Refused(400)),
            te("te_chunked_gzip_one", &["chunked, gzip"], HELLO, Refused(400)),
            te("te_chunked_twice_lines", &["chunked", "chunked"], HELLO, Refused(400)),
            te("te_chunked_chunked_one", &["chunked, chunked"], HELLO, Refused(400)),
            te("te_identity", &["identity"], HELLO, Refused(400)),
            te("te_unknown", &["foo"], HELLO, Refused(400)),
            te("te_empty", &[""], HELLO, Refused(400)),
            te("te_empty_then_chunked", &["", "chunked"], HELLO, Refused(400)),
            te("te_chunked_then_empty", &["chunked", ""], HELLO, Refused(400)),
            te("te_trailing_comma", &["chunked,"], HELLO, Refused(400)),
            te("te_leading_comma", &[", chunked"], HELLO, Refused(400)),
            raw("te_case_name", &["tRaNsFeR-eNcOdInG: chunked"], HELLO, Forwarded(b"hello")),
            raw("te_space_colon", &["Transfer-Encoding : chunked"], HELLO, Refused(400)),
            raw("te_obs_fold", &["Transfer-Encoding: gzip,", " chunked"], HELLO, Refused(422)),
            raw("te_obs_fold_value", &["Transfer-Encoding:", " chunked"], HELLO, Forwarded(b"hello")),
        ],
    );
}

/// `Transfer-Encoding` beside `Content-Length`: chunked wins and the length goes; a
/// request whose last coding is not chunked has no length at all.
#[test]
fn transfer_encoding_with_content_length() {
    let cases = [
        raw("te_cl", &["Transfer-Encoding: chunked", "Content-Length: 3"], HELLO, Forwarded(b"hello")),
        raw("cl_te", &["Content-Length: 3", "Transfer-Encoding: chunked"], HELLO, Forwarded(b"hello")),
        raw("te_gzip_cl", &["Transfer-Encoding: gzip", "Content-Length: 3"], b"abc", Refused(400)),
    ];
    assert_all("", &cases);
    assert_all(UNSAFE, &cases);
}

/// `Content-Length` on several lines, or as a list, is one value or a refusal.
#[test]
fn content_length_values() {
    assert_all(
        "",
        &[
            raw("cl_dup_equal", &["Content-Length: 3", "Content-Length: 3"], b"abc", Forwarded(b"abc")),
            raw("cl_dup_diff", &["Content-Length: 3", "Content-Length: 4"], b"abcd", RefusedOrReset(400)),
            raw("cl_list_equal", &["Content-Length: 3, 3"], b"abc", Forwarded(b"abc")),
            raw("cl_list_diff", &["Content-Length: 3, 4"], b"abcd", RefusedOrReset(400)),
            raw("cl_list_trailing_comma", &["Content-Length: 3,"], b"abc", RefusedOrReset(400)),
            raw("cl_plus", &["Content-Length: +3"], b"abc", RefusedOrReset(400)),
            raw("cl_minus", &["Content-Length: -3"], b"abc", RefusedOrReset(400)),
            raw("cl_space_inside", &["Content-Length: 1 2"], b"abcdefghijkl", RefusedOrReset(400)),
            raw("cl_leading_zero", &["Content-Length: 003"], b"abc", Forwarded(b"abc")),
            raw("cl_huge", &["Content-Length: 99999999999999999999999"], b"abc", RefusedOrReset(400)),
            raw("cl_empty", &["Content-Length: "], b"abc", RefusedOrReset(400)),
            raw("cl_hex", &["Content-Length: 0x3"], b"abc", RefusedOrReset(400)),
            raw("cl_space_colon", &["Content-Length : 3"], b"abc", RefusedOrReset(400)),
        ],
    );
}

/// HTTP/1.0: a chunked POST is forwarded; a GET with a body is refused with 413.
#[test]
fn http10_bodies() {
    let post10 = b"POST /te_http10 HTTP/1.0\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec();
    let get10 = b"GET /te_http10_get HTTP/1.0\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec();
    let get10_cl = b"GET /cl_http10_get HTTP/1.0\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc".to_vec();
    assert_all(
        "",
        &[
            ("te_http10", post10, Forwarded(b"hello")),
            ("te_http10_get", get10, Refused(413)),
            ("cl_http10_get", get10_cl, RefusedOrReset(413)),
        ],
    );
}

/// VV-2: the chunk-size line, the CRLF after each chunk, and what may follow the size.
#[test]
fn chunk_syntax() {
    assert_all(
        "",
        &[
            chunked("ck_leading_zeros", b"0005\r\nhello\r\n0\r\n\r\n", Forwarded(b"hello")),
            chunked("ck_ext", b"5;a=b;c=\"d e\"\r\nhello\r\n0\r\n\r\n", Forwarded(b"hello")),
            chunked("ck_space_before_ext", b"5 ;a=b\r\nhello\r\n0\r\n\r\n", Forwarded(b"hello")),
            chunked("ck_space_after_size", b"5 \r\nhello\r\n0\r\n\r\n", Forwarded(b"hello")),
            chunked("ck_tab_after_size", b"5\t;a\r\nhello\r\n0\r\n\r\n", Forwarded(b"hello")),
            chunked("ck_zero_ext_only", b"0;x\r\n\r\n", Forwarded(b"")),
            chunked("ck_size_13hex", b"0000000000005\r\nhello\r\n0\r\n\r\n", Forwarded(b"hello")),
            chunked("ck_size_overflow", b"ffffffffffffffffff\r\nhello\r\n0\r\n\r\n", Refused(400)),
            chunked("ck_size_17hex", b"10000000000000005\r\nhello\r\n0\r\n\r\n", Refused(400)),
            chunked("ck_size_16hex", b"8000000000000005\r\nhello\r\n0\r\n\r\n", Refused(400)),
            chunked("ck_size_2p52", b"10000000000000\r\nhello\r\n0\r\n\r\n", Refused(400)),
            chunked("ck_plus", b"+5\r\nhello\r\n0\r\n\r\n", Refused(400)),
            chunked("ck_neg", b"-5\r\nhello\r\n0\r\n\r\n", Refused(400)),
            chunked("ck_0x", b"0x5\r\nhello\r\n0\r\n\r\n", Refused(400)),
            chunked("ck_space_then_junk", b"5 x\r\nhello\r\n0\r\n\r\n", Refused(400)),
            chunked("ck_data_too_long", b"5\r\nhelloXX\r\n0\r\n\r\n", Refused(400)),
            chunked("ck_data_too_short", b"5\r\nhel\r\n0\r\n\r\n", Refused(400)),
            chunked("ck_bare_lf_size", b"5\nhello\r\n0\r\n\r\n", Refused(400)),
            chunked("ck_bare_lf_after_data", b"5\r\nhello\n0\r\n\r\n", Refused(400)),
            chunked("ck_bare_lf_last", b"5\r\nhello\r\n0\n\n", Refused(400)),
            chunked("ck_bare_cr", b"5\rhello\r\n0\r\n\r\n", Refused(400)),
            chunked("ck_empty_size_line", b"\r\n5\r\nhello\r\n0\r\n\r\n", Refused(400)),
            chunked("ck_ext_bare_lf", b"5;a\nhello\r\n0\r\n\r\n", Refused(400)),
            chunked("ck_ext_ctl", b"5;a\x01b\r\nhello\r\n0\r\n\r\n", Refused(400)),
            chunked("ck_ext_open_quote", b"5;a=\"b\r\nhello\r\n0\r\n\r\n", Refused(400)),
            chunked("ck_ext_backslash", b"5;a=b\\c\r\nhello\r\n0\r\n\r\n", Refused(400)),
            chunked("ck_smuggle_in_ext", b"5;\r\nGET /s HTTP/1.1\r\nhello\r\n0\r\n\r\n", Refused(400)),
            // An extension longer than the buffer: the head is forwarded, then nothing.
            chunked("ck_ext_20k", &[&b"5;"[..], &vec![b'a'; 20000], b"\r\nhello\r\n0\r\n\r\n"].concat(), HeadOnly),
        ],
    );
}

/// VV-2: the trailer section is header syntax, without the fields that frame or route.
#[test]
fn trailer_syntax() {
    assert_all(
        "",
        &[
            chunked("ck_trailer_ok", b"5\r\nhello\r\n0\r\nX-T: 1\r\n\r\n", Forwarded(b"hello")),
            chunked("ck_trailer_bare_lf", b"5\r\nhello\r\n0\r\nX-T: 1\n\r\n", Forwarded(b"hello")),
            chunked("ck_bare_lf_final", b"5\r\nhello\r\n0\r\n\n", Forwarded(b"hello")),
            chunked("ck_trailer_no_colon", b"5\r\nhello\r\n0\r\nbogus\r\n\r\n", Refused(400)),
            chunked("ck_trailer_empty_name", b"5\r\nhello\r\n0\r\n: v\r\n\r\n", Refused(400)),
            chunked("ck_trailer_space_name", b"5\r\nhello\r\n0\r\nX T: 1\r\n\r\n", Refused(400)),
            chunked("ck_trailer_cl", b"5\r\nhello\r\n0\r\nContent-Length: 99\r\n\r\n", Refused(400)),
            chunked("ck_trailer_te", b"5\r\nhello\r\n0\r\nTransfer-Encoding: chunked\r\n\r\n", Refused(400)),
            chunked("ck_trailer_host", b"5\r\nhello\r\n0\r\nHost: y\r\n\r\n", Refused(400)),
            chunked("ck_trailer_connection", b"5\r\nhello\r\n0\r\nconnection: close\r\n\r\n", Refused(400)),
            chunked("ck_trailer_nul", b"5\r\nhello\r\n0\r\nX-T: a\0b\r\n\r\n", Refused(400)),
            chunked("ck_trailer_bare_cr", b"5\r\nhello\r\n0\r\nX-T: a\rb\r\n\r\n", Refused(400)),
        ],
    );
}

/// A complete request after the last chunk is the client's next request, not this body.
#[test]
fn request_after_the_last_chunk_is_not_this_body() {
    let mut req = post("ck_smuggle_after_0", &["Transfer-Encoding: chunked"], b"0\r\n\r\n");
    req.extend_from_slice(b"GET /SMUGGLED HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_all("", &[("ck_smuggle_after_0", req, Forwarded(b""))]);
}
