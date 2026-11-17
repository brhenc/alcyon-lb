// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A chunked body that breaks its framing, after its head was accepted (T281 items 5-6,
//! V&V's `chunked_diff.py`, review r2#9).
//!
//! `HAProxy` parses what is in its buffer into HTX before the stream analyses any of it.
//! A response body that is malformed in the bytes that arrived with its head is therefore
//! refused whole: a 502 (`PH--`), nothing of the response relayed. Once the head has gone,
//! an error closes the client connection behind what was relayed before it. A trailer
//! section is relayed only once all of it is here, with the last-chunk line before it: a
//! trailer section that is refused, or larger than the buffer, relays none of it.
//!
//! On the request side the same rules hold toward the server, and the client is closed
//! without an answer: a trailer section too large for the buffer that arrives with the head
//! is logged `400 PR--` and nothing reaches the server; one that arrives after the head was
//! forwarded is logged `400 PH--`, and the server got the chunks before it and nothing
//! more.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev8-885761-29. Set
//! `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`: it passes all.

use crate::common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// A piece of a message: bytes to send, or a pause before the next ones.
#[derive(Clone)]
enum Part {
    Bytes(Vec<u8>),
    Pause,
}
use Part::{Bytes, Pause};

const PAUSE: Duration = Duration::from_millis(300);
const RSP_HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
const REQ_HEAD: &[u8] = b"Host: x\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n";

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// A body of one chunk `hello` and a trailer field of `n` bytes of value.
fn big_trailer(n: usize) -> Vec<u8> {
    cat(&[b"5\r\nhello\r\n0\r\nX-T: ", &vec![b'a'; n], b"\r\n\r\n"])
}

/// A body of 2000 bytes, then a trailer field of 15000 bytes of value: longer than the
/// buffer with the head, the section alone within its cap.
fn data_then_trailer() -> Vec<u8> {
    cat(&[b"7d0\r\n", &[b'd'; 2000], b"\r\n0\r\nX-T: ", &[b'a'; 15000], b"\r\n\r\n"])
}

/// A body of 2000 bytes, then a trailer field of 20000 bytes of value: past its cap, in a
/// message held whole because the first buffer ended in its trailer section.
fn data_then_big_trailer() -> Vec<u8> {
    cat(&[b"7d0\r\n", &[b'd'; 2000], b"\r\n0\r\nX-T: ", &[b'a'; 20000], b"\r\n\r\n"])
}

/// A body of one chunk `hello` and `n` trailer fields (`HAProxy` takes 100).
fn many_trailers(n: usize) -> Vec<u8> {
    let mut b = b"5\r\nhello\r\n0\r\n".to_vec();
    for i in 0..n {
        b.extend_from_slice(format!("X-T{i}: v\r\n").as_bytes());
    }
    b.extend_from_slice(b"\r\n");
    b
}

struct Proxy {
    child: Child,
    logs: mpsc::Receiver<String>,
    fe: SocketAddr,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// The server: answers `GET /<n>` and `POST /<n>` with `responses[n]` (its parts, with
/// pauses between; a scripted `POST` reply holds the connection afterwards); records what
/// it receives of any other request into `seen`, and answers it with a 200 once its body
/// is complete, or once nothing more has come for a second. `early`: answer a `POST` as
/// soon as its head is complete, without the body.
fn server(responses: Arc<Vec<Vec<Part>>>, seen: Arc<Mutex<Vec<u8>>>, early: bool) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let responses = Arc::clone(&responses);
            let seen = Arc::clone(&seen);
            thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(1)));
                let mut req = Vec::new();
                let mut b = [0u8; 65536];
                loop {
                    match s.read(&mut b) {
                        Ok(0) => return,
                        Err(_) => break,
                        Ok(n) => {
                            req.extend_from_slice(&b[..n]);
                            if req.starts_with(b"POST") {
                                seen.lock().unwrap().extend_from_slice(&b[..n]);
                            }
                        }
                    }
                    let Some(eoh) = req.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
                    let n: usize = String::from_utf8_lossy(&req)
                        .split(' ')
                        .nth(1)
                        .and_then(|p| p.trim_start_matches('/').parse().ok())
                        .unwrap_or(0);
                    if let Some(parts) = responses.get(n).filter(|ps| !ps.is_empty()) {
                        for p in parts {
                            match p {
                                Bytes(b) => {
                                    if s.write_all(b).is_err() {
                                        return;
                                    }
                                }
                                Pause => thread::sleep(PAUSE),
                            }
                        }
                        // A GET keeps the connection for the 500 ms the tests time against;
                        // a scripted POST reply holds it (a body that will not come).
                        thread::sleep(if req.starts_with(b"GET") { Duration::from_millis(500) } else { Duration::from_secs(30) });
                        return;
                    }
                    if early {
                        break;
                    }
                    if req.len() > eoh + 4 && req.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            });
        }
    });
    addr
}

fn start(responses: Vec<Vec<Part>>, seen: Arc<Mutex<Vec<u8>>>, client_to: &str, early: bool) -> Proxy {
    let (fe, sentinel) = (common::reserve_addr(), common::reserve_addr());
    let be = server(Arc::new(responses), seen, early);
    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "global\n  log stdout format raw local0\n\
         defaults\n  mode http\n  log global\n  option httplog\n  timeout connect 2s\n  \
         timeout client {client_to}\n  timeout server 5s\n  timeout http-request 5s\n\
         frontend f\n  bind {fe}\n  default_backend b\n\
         frontend s\n  bind {sentinel}\n  http-request return status 200\n\
         backend b\n  server s {be}\n"
    )
    .expect("write");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn");
    let out = child.stdout.take().expect("stdout");
    let (tx, logs) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    assert!(common::wait_listening(sentinel), "never listened");
    Proxy { child, logs, fe, _cfg: cfg }
}

/// Sends `parts` to the proxy and reads until it closes: what came back, and how long
/// the close took from the last byte sent.
fn exchange(p: &Proxy, parts: &[Part]) -> (Vec<u8>, Duration) {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    for part in parts {
        match part {
            Bytes(b) => {
                if c.write_all(b).is_err() {
                    break;
                }
            }
            Pause => thread::sleep(PAUSE),
        }
    }
    let t0 = Instant::now();
    let mut got = Vec::new();
    let mut b = [0u8; 65536];
    loop {
        match c.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&b[..n]),
        }
    }
    (got, t0.elapsed())
}

/// Sends `parts`, half-closes the write side, then reads until the proxy closes: what came
/// back, and how long the close took from the last byte sent.
fn exchange_fin(p: &Proxy, parts: &[Part]) -> (Vec<u8>, Duration) {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    for part in parts {
        match part {
            Bytes(b) => {
                if c.write_all(b).is_err() {
                    break;
                }
            }
            Pause => thread::sleep(PAUSE),
        }
    }
    let _ = c.shutdown(Shutdown::Write);
    let t0 = Instant::now();
    let mut got = Vec::new();
    let mut b = [0u8; 65536];
    loop {
        match c.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&b[..n]),
        }
    }
    (got, t0.elapsed())
}

/// Sends `parts`, reads until `stop` holds of what came back, half-closes the write side,
/// then reads until the proxy closes: what came back, and how long the close took from the
/// FIN.
fn exchange_fin_when(p: &Proxy, parts: &[Part], stop: impl Fn(&[u8]) -> bool) -> (Vec<u8>, Duration) {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    for part in parts {
        match part {
            Bytes(b) => {
                if c.write_all(b).is_err() {
                    break;
                }
            }
            Pause => thread::sleep(PAUSE),
        }
    }
    let mut got = Vec::new();
    let mut b = [0u8; 65536];
    loop {
        if stop(&got) {
            break;
        }
        match c.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&b[..n]),
        }
    }
    let _ = c.shutdown(Shutdown::Write);
    let t0 = Instant::now();
    loop {
        match c.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&b[..n]),
        }
    }
    (got, t0.elapsed())
}

/// The line's `%TR/%Tw/%Tc/%Tr/%Ta`, `%ST`, `%B`, and `%tsc`, by position (the default
/// `httplog` format of `HAProxy` and Alcyon).
fn log_fields(l: &str) -> Option<([i64; 5], i64, i64, String)> {
    let f: Vec<&str> = l.split_whitespace().collect();
    let parts: Vec<&str> = f.get(4)?.split('/').collect();
    if parts.len() != 5 {
        return None;
    }
    let t = [parts[0].parse().ok()?, parts[1].parse().ok()?, parts[2].parse().ok()?, parts[3].parse().ok()?, parts[4].parse().ok()?];
    Some((t, f.get(5)?.parse().ok()?, f.get(6)?.parse().ok()?, f.get(9)?.to_string()))
}

/// A `POST /<n>` head with a `Content-Length` body of `clen` bytes.
fn cl_head(n: usize, clen: usize) -> Vec<u8> {
    format!("POST /{n} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: {clen}\r\n\r\n").into_bytes()
}

/// A `POST /<n>` request line, before its head fields.
fn post_head(n: usize) -> Vec<u8> {
    format!("POST /{n} HTTP/1.1\r\n").into_bytes()
}

/// The log line naming `/<n>` (or the `<BADREQ>` of a request refused before it was one).
/// The `wait_listening` sentinel connect leaves its own `<BADREQ>` line on the `s`
/// frontend; it is not a request of this test and is never returned. The log's prefix
/// (the listening proxy) is the third field: `<ci>:<cp> [<date>] <prefix> <be>/<srv>`.
fn log_of(p: &Proxy, n: usize) -> String {
    let want = format!("/{n} HTTP/");
    while let Ok(l) = p.logs.recv_timeout(Duration::from_secs(3)) {
        let on_fe = l.split_whitespace().nth(2) == Some("f");
        if l.contains(&want) || (l.contains("<BADREQ>") && on_fe) {
            return l;
        }
    }
    String::new()
}

fn esc(b: &[u8]) -> String {
    let s = b.escape_ascii().to_string();
    if s.len() > 300 {
        format!("{}...({} bytes)", &s[..300], b.len())
    } else {
        s
    }
}

/// The body the client got after the response head.
fn body_of(got: &[u8]) -> &[u8] {
    got.windows(4).position(|w| w == b"\r\n\r\n").map_or(&[][..], |i| &got[i + 4..])
}

#[derive(Clone, Copy)]
enum Rsp {
    /// A 502 and nothing of the server's response, logged 502 `PH--`.
    Refused,
    /// The 200 head, then exactly this body, then the close (no later than `timeout
    /// server` would).
    Cut(&'static [u8]),
    /// The 200 head, then at most this much of this body before the close.
    CutWithin(&'static [u8]),
    /// The 200 head and a body this long.
    Whole(usize),
}

#[test]
fn a_malformed_response_body_is_refused_or_cut_as_haproxy_does() {
    let together = |body: &[u8]| vec![Bytes(cat(&[RSP_HEAD, body]))];
    let cases: Vec<(&str, Vec<Part>, Rsp)> = vec![
        ("valid", together(b"5\r\nhello\r\n0\r\n\r\n"), Rsp::Whole(15)),
        ("data_too_long", together(b"5\r\nhelloXX\r\n0\r\n\r\n"), Rsp::Refused),
        ("size_overflow", together(b"ffffffffffffffffff\r\nhello\r\n0\r\n\r\n"), Rsp::Refused),
        ("neg_sign", together(b"-5\r\nhello\r\n0\r\n\r\n"), Rsp::Refused),
        ("bare_lf", together(b"5\nhello\n0\n\n"), Rsp::Refused),
        ("bad_second_chunk", together(b"5\r\nhello\r\n-5\r\nhello\r\n0\r\n\r\n"), Rsp::Refused),
        ("big_chunk_then_bad", together(&cat(&[b"3000\r\n", &[b'z'; 0x3000], b"\r\nZZ\r\n"])), Rsp::Refused),
        ("forbidden_trailer", together(b"5\r\nhello\r\n0\r\nContent-Length: 3\r\n\r\n"), Rsp::Refused),
        ("trailer_20k", together(&big_trailer(20000)), Rsp::Refused),
        ("trailer_16400", together(&big_trailer(16400)), Rsp::Refused),
        ("trailer_16300", together(&big_trailer(16300)), Rsp::Whole(16322)),
        ("trailers_100", together(&many_trailers(100)), Rsp::Whole(1005)),
        ("data_2k_trailer_15k", together(&data_then_trailer()), Rsp::Whole(17019)),
        ("data_2k_trailer_20k", together(&data_then_big_trailer()), Rsp::Refused),
        ("trailers_101", together(&many_trailers(101)), Rsp::Refused),
        // The head is gone when the error arrives: the connection closes behind what was
        // relayed. HAProxy relays none of a small chunk whose CRLF is wrong; Alcyon may relay
        // its size line and data, never more.
        ("bad_after_head", vec![Bytes(RSP_HEAD.to_vec()), Pause, Bytes(b"5\r\nhelloXX\r\n0\r\n\r\n".to_vec())], Rsp::CutWithin(b"5\r\nhello")),
        (
            "bad_after_chunk",
            vec![Bytes(cat(&[RSP_HEAD, b"5\r\nhello\r\n"])), Pause, Bytes(b"-5\r\nhello\r\n0\r\n\r\n".to_vec())],
            Rsp::Cut(b"5\r\nhello\r\n"),
        ),
        // Nothing of a trailer section that is refused, nor of the last-chunk line before it.
        (
            "trailers_101_after_head",
            vec![Bytes(cat(&[RSP_HEAD, b"5\r\nhello\r\n"])), Pause, Bytes(many_trailers(101)[10..].to_vec())],
            Rsp::Cut(b"5\r\nhello\r\n"),
        ),
        (
            "trailer_20k_after_head",
            vec![Bytes(cat(&[RSP_HEAD, b"5\r\nhello\r\n"])), Pause, Bytes(big_trailer(20000)[10..].to_vec())],
            Rsp::Cut(b"5\r\nhello\r\n"),
        ),
        (
            "forbidden_trailer_after_head",
            vec![Bytes(cat(&[RSP_HEAD, b"5\r\nhello\r\n"])), Pause, Bytes(b"0\r\nContent-Length: 3\r\n\r\n".to_vec())],
            Rsp::Cut(b"5\r\nhello\r\n"),
        ),
        ("trailer_16300_after_head", vec![Bytes(RSP_HEAD.to_vec()), Pause, Bytes(big_trailer(16300))], Rsp::Whole(16322)),
    ];
    let p = start(cases.iter().map(|c| c.1.clone()).collect(), Arc::default(), "5s", false);
    let mut wrong = Vec::new();
    for (n, (name, _, want)) in cases.iter().enumerate() {
        let (got, took) = exchange(&p, &[Bytes(format!("GET /{n} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").into_bytes())]);
        let log = log_of(&p, n);
        let ok200 = got.starts_with(b"HTTP/1.1 200 OK\r\n");
        // The server pauses 500 ms after its last byte; `timeout server` is 5 s.
        let prompt = took < Duration::from_secs(2);
        let fine = match want {
            Rsp::Refused => got.starts_with(b"HTTP/1.1 502 ") && log.contains(" 502 ") && log.contains(" PH-- "),
            Rsp::Cut(b) => ok200 && body_of(&got) == *b && prompt,
            Rsp::CutWithin(b) => ok200 && b.starts_with(body_of(&got)) && prompt,
            Rsp::Whole(len) => ok200 && body_of(&got).len() == *len,
        };
        if !fine {
            wrong.push(format!("{name}: got {} after {took:?} / log {log}", esc(&got)));
        }
    }
    assert!(wrong.is_empty(), "{} of {} cases differ:\n{}", wrong.len(), cases.len(), wrong.join("\n"));
}

#[derive(Clone, Copy)]
enum Req {
    /// The client gets no answer and the connection closes; the server gets this much of
    /// the body after the head (`None`: nothing at all, not even the head); logged with this
    /// 400 termination state.
    Dropped(Option<&'static [u8]>, &'static str),
    /// The client gets the server's 400; nothing reaches the server.
    Refused,
    /// Forwarded whole: the server got a body this long, and its 200 reached the client.
    Whole(usize),
}

#[test]
fn a_request_trailer_section_too_large_or_refused_never_half_reaches_the_server() {
    let head = |n: usize| format!("POST /{n} HTTP/1.1\r\n").into_bytes();
    let cases: Vec<(&str, Vec<Part>, Req)> = vec![
        ("valid_trailer", vec![Bytes(big_trailer(1000))], Req::Whole(1022)),
        ("trailer_16300", vec![Bytes(big_trailer(16300))], Req::Whole(16322)),
        ("data_2k_trailer_15k", vec![Bytes(data_then_trailer())], Req::Whole(17019)),
        ("data_2k_trailer_20k", vec![Bytes(data_then_big_trailer())], Req::Dropped(None, "PR--")),
        // No chunk before it and a short head (no `Host`): the section is past its cap in the
        // first buffer already, before anything is held.
        ("short_head_trailer_only_20k", vec![Bytes(big_trailer(20000)[10..].to_vec())], Req::Dropped(None, "PR--")),
        ("trailer_20k", vec![Bytes(big_trailer(20000))], Req::Dropped(None, "PR--")),
        ("trailer_16400", vec![Bytes(big_trailer(16400))], Req::Dropped(None, "PR--")),
        ("trailers_101", vec![Bytes(many_trailers(101))], Req::Refused),
        ("trailer_20k_after_chunk", vec![Bytes(b"5\r\nhello\r\n".to_vec()), Pause, Bytes(big_trailer(20000)[10..].to_vec())], Req::Dropped(Some(b"5\r\nhello\r\n"), "PH--")),
        ("trailer_20k_after_head", vec![Pause, Bytes(big_trailer(20000))], Req::Dropped(Some(b""), "PH--")),
        ("trailers_101_after_chunk", vec![Bytes(b"5\r\nhello\r\n".to_vec()), Pause, Bytes(many_trailers(101)[10..].to_vec())], Req::Dropped(Some(b"5\r\nhello\r\n"), "PH--")),
        (
            "forbidden_trailer_after_chunk",
            vec![Bytes(b"5\r\nhello\r\n".to_vec()), Pause, Bytes(b"0\r\nContent-Length: 3\r\n\r\n".to_vec())],
            Req::Dropped(Some(b"5\r\nhello\r\n"), "PH--"),
        ),
        ("bad_chunk_after_chunk", vec![Bytes(b"5\r\nhello\r\n".to_vec()), Pause, Bytes(b"-5\r\nhello\r\n0\r\n\r\n".to_vec())], Req::Dropped(Some(b"5\r\nhello\r\n"), "PH--")),
    ];
    let seen: Arc<Mutex<Vec<u8>>> = Arc::default();
    let p = start(Vec::new(), Arc::clone(&seen), "5s", false);
    let mut wrong = Vec::new();
    for (n, (name, parts, want)) in cases.iter().enumerate() {
        seen.lock().unwrap().clear();
        let mut sent = parts.clone();
        match &mut sent[0] {
            Bytes(b) if name.starts_with("short_head") => *b = cat(&[&head(n), b"Transfer-Encoding: chunked\r\n\r\n", b]),
            Bytes(b) => *b = cat(&[&head(n), REQ_HEAD, b]),
            Pause => sent.insert(0, Bytes(cat(&[&head(n), REQ_HEAD]))),
        }
        let (got, took) = exchange(&p, &sent);
        let log = log_of(&p, n);
        thread::sleep(Duration::from_millis(300));
        let be = seen.lock().unwrap().clone();
        let be_body = body_of(&be);
        let fine = match want {
            Req::Dropped(None, term) => got.is_empty() && be.is_empty() && log.contains(&format!(" 400 0 - - {term} ")),
            Req::Dropped(Some(b), term) => {
                got.is_empty() && be.starts_with(&head(n)) && be_body == *b && log.contains(&format!(" 400 0 - - {term} ")) && took < Duration::from_secs(2)
            }
            Req::Refused => got.starts_with(b"HTTP/1.1 400 ") && be.is_empty(),
            Req::Whole(len) => got.starts_with(b"HTTP/1.1 200 ") && be_body.len() == *len,
        };
        if !fine {
            wrong.push(format!("{name}: client got {} after {took:?}; server got {} / log {log}", esc(&got), esc(&be)));
        }
    }
    assert!(wrong.is_empty(), "{} of {} cases differ:\n{}", wrong.len(), cases.len(), wrong.join("\n"));
}

/// A client that abandons its body after the head was forwarded: no `option
/// http-buffer-request`, so the body is relayed as it arrives. `n` 0: a `Content-Length`
/// body; 1: a chunked one; both FIN mid-body before the server answers, so `HAProxy`
/// answers the 400 nobody reads and logs the client abort (`CH--`), the request not
/// complete (`Tr` -1). 2 and 3 FIN mid-body after the server already answered, a 200 of
/// two bytes and one of 12000 in flight: the log keeps the response's status, `CL--` all
/// of it delivered, `CD--` still in flight, the answer stopping behind the FIN, the
/// client seeing the close at once. In every case the server got the head and what was
/// relayed of the body before the close.
#[test]
fn a_client_that_fins_mid_body_logs_the_client_abort() {
    let seen: Arc<Mutex<Vec<u8>>> = Arc::default();
    // 2: a 200 of two bytes, all of it. 3: a 200 of 12000 bytes, 1000 at a time.
    let early = vec![Bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec())];
    let mut stream = vec![Bytes(cat(&[b"HTTP/1.1 200 OK\r\nContent-Length: 12000\r\n\r\n", &[b'x'; 1000]]))];
    for _ in 0..11 {
        stream.push(Pause);
        stream.push(Bytes(vec![b'x'; 1000]));
    }
    let p = start(vec![Vec::new(), Vec::new(), early, stream], Arc::clone(&seen), "5s", false);
    let mut wrong = Vec::new();
    for n in 0..4 {
        seen.lock().unwrap().clear();
        let head: Vec<u8> = if n == 1 {
            cat(&[&post_head(n), REQ_HEAD])
        } else {
            cl_head(n, 100)
        };
        let body: &[u8] = if n == 1 {
            b"5\r\nhel"
        } else if n == 3 {
            &[b'a'; 10]
        } else {
            &[b'a'; 50]
        };
        let (got, _took) = if n < 2 {
            exchange_fin(&p, &[Bytes(cat(&[&head, body]))])
        } else if n == 2 {
            // The whole two-byte response, then the FIN.
            exchange_fin_when(&p, &[Bytes(cat(&[&head, body]))], |g| g.windows(2).any(|w| w == b"ok"))
        } else {
            // Into the third 1000-byte chunk of the 12000-byte answer, then the FIN.
            exchange_fin_when(&p, &[Bytes(cat(&[&head, body]))], |g| g.len() >= 2500)
        };
        let log = log_of(&p, n);
        thread::sleep(Duration::from_millis(300));
        let be = seen.lock().unwrap().clone();
        let Some((timers, status, bytes, tsc)) = log_fields(&log) else {
            wrong.push(format!("{n}: no parseable log line: {log}"));
            continue;
        };
        // `HAProxy` lowercases the forwarded header names and strips the `Connection`
        // header; compare case-insensitively against the head minus that header.
        let be_head: Vec<u8> = if n == 1 {
            format!("POST /{n} HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n").into_bytes()
        } else {
            format!("POST /{n} HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n").into_bytes()
        }
        .to_ascii_lowercase();
        let be_lc = be.to_ascii_lowercase();
        let ok200 = got.starts_with(b"HTTP/1.1 200 OK\r\n");
        let fine = match n {
            0 | 1 => {
                let want: Vec<u8> = cat(&[&be_head, body]).to_ascii_lowercase();
                got.is_empty() && status == 400 && tsc == "CH--" && timers[3] == -1 && bytes == 0 && be_lc.starts_with(&want)
            }
            2 => ok200 && body_of(&got) == b"ok" && status == 200 && tsc == "CL--" && bytes > 0 && be_lc.starts_with(&be_head),
            _ => ok200 && body_of(&got).len() >= 1000 && status == 200 && tsc == "CD--" && bytes > 0 && be_lc.starts_with(&be_head),
        };
        if !fine {
            wrong.push(format!("{n}: got {} / server {} / log {log} (ST {status} B {bytes} T {timers:?} tsc {tsc})", esc(&got), esc(&be)));
        }
    }
    assert!(wrong.is_empty(), "{} of 4 cases differ:\n{}", wrong.len(), wrong.join("\n"));
}

/// The same abandonment left to idle out `timeout client` (1 s here), after the server
/// already answered `200` to the head: the response reached the client, and the log keeps
/// the `200` and the client time-out (`cL--`), the transaction living out its timer. 2:
/// the answer itself still in flight when the client stops sending -- a 200 of 12000
/// bytes of which 3000 arrived, the server holding the connection: the time-out ends the
/// transaction mid-body, `cD--`.
#[test]
fn a_client_that_idles_out_its_body_logs_the_client_timeout() {
    let seen: Arc<Mutex<Vec<u8>>> = Arc::default();
    // 2: 3000 of the 12000, then the connection held open, nothing more coming.
    let stall = vec![Bytes(cat(&[b"HTTP/1.1 200 OK\r\nContent-Length: 12000\r\n\r\n", &[b'x'; 3000]]))];
    let p = start(vec![Vec::new(), Vec::new(), stall], Arc::clone(&seen), "1s", true);
    let mut wrong = Vec::new();
    for n in 0..3 {
        seen.lock().unwrap().clear();
        let parts: Vec<Part> = if n == 0 {
            let head = cl_head(n, 100);
            vec![Bytes(head), Pause, Bytes(vec![b'a'; 50])]
        } else if n == 2 {
            let head = cl_head(n, 100);
            vec![Bytes(head), Pause, Bytes(vec![b'a'; 50])]
        } else {
            vec![Bytes(cat(&[&post_head(n), REQ_HEAD])), Pause, Bytes(b"5\r\nhel".to_vec())]
        };
        let (got, _took) = exchange(&p, &parts);
        let log = log_of(&p, n);
        thread::sleep(Duration::from_millis(300));
        let Some((timers, status, bytes, tsc)) = log_fields(&log) else {
            wrong.push(format!("{n}: no parseable log line: {log}"));
            continue;
        };
        let ok200 = got.starts_with(b"HTTP/1.1 200 OK\r\n");
        // `timers[4]` is `%Ta`, the close from the start: the client's own time-out ends
        // it, so it is its 1 s plus slack -- never the 5 s `timeout server` a proxy that
        // lets the stream live on waits for.
        let fine = if n < 2 {
            body_of(&got) == b"ok" && status == 200 && tsc == "cL--" && (900..3000).contains(&timers[4]) && bytes > 0
        } else {
            ok200 && body_of(&got).len() >= 1000 && status == 200 && tsc == "cD--" && (900..3000).contains(&timers[4]) && bytes > 0
        };
        if !fine {
            wrong.push(format!("{n}: got {} / log {log} (ST {status} B {bytes} T {timers:?} tsc {tsc})", esc(&got)));
        }
    }
    assert!(wrong.is_empty(), "{} of 3 cases differ:\n{}", wrong.len(), wrong.join("\n"));
}
