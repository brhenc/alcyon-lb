// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The HTTP transaction against the real binary: where a request ends, where a response
//! ends, and what happens to the connection afterwards (design 010, step 1).
//!
//! Every case was measured against `HAProxy` 3.5 with the same configuration first. To
//! re-measure, point the suite at the oracle:
//!
//! ```text
//! IBEX_TXN_BIN=/home/bhenc/reference/haproxy/haproxy cargo test -p ibex-rt --test http_txn
//! ```
//!
//! A binary whose name contains `haproxy` is started with `-db`.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

// ---- the backend ------------------------------------------------------------------

/// A request as the backend received it.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    /// The request line and headers as they arrived.
    head: String,
    body: Vec<u8>,
    /// Which backend connection it arrived on, counted from 0.
    conn: usize,
}

/// How the backend answers one request.
struct Reply {
    /// Written in order, with `gap` between writes.
    parts: Vec<Vec<u8>>,
    gap: Duration,
    /// Close the connection after the reply.
    close: bool,
}

impl Reply {
    fn ok(body: &str) -> Self {
        Reply {
            parts: vec![format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()],
            gap: Duration::ZERO,
            close: false,
        }
    }
}

type Handler = fn(&Seen) -> Reply;

/// Reads one request (head and body) from `s`, `buf` holding what was read past the last
/// one. `None` at EOF.
fn read_request(s: &mut TcpStream, buf: &mut Vec<u8>, conn: usize) -> Option<Seen> {
    let mut chunk = vec![0u8; 65536];
    let head_end = loop {
        if let Some(p) = find(buf, b"\r\n\r\n") {
            break p + 4;
        }
        let n = s.read(&mut chunk).ok().filter(|&n| n > 0)?;
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    buf.drain(..head_end);
    let mut first = head.split("\r\n").next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("").to_string();
    let path = first.next().unwrap_or("").to_string();
    let header = |name: &str| {
        head.split("\r\n").skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    };
    if header("expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue")) {
        s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").ok()?;
    }
    let mut body = Vec::new();
    if header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        loop {
            let line_end = loop {
                if let Some(p) = find(buf, b"\r\n") {
                    break p;
                }
                let n = s.read(&mut chunk).ok().filter(|&n| n > 0)?;
                buf.extend_from_slice(&chunk[..n]);
            };
            let size_str = String::from_utf8_lossy(&buf[..line_end]).into_owned();
            let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16).ok()?;
            while buf.len() < line_end + 2 + size + 2 {
                let n = s.read(&mut chunk).ok().filter(|&n| n > 0)?;
                buf.extend_from_slice(&chunk[..n]);
            }
            body.extend_from_slice(&buf[line_end + 2..line_end + 2 + size]);
            buf.drain(..line_end + 2 + size + 2);
            if size == 0 {
                break;
            }
        }
    } else if let Some(cl) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        while buf.len() < cl {
            let n = s.read(&mut chunk).ok().filter(|&n| n > 0)?;
            buf.extend_from_slice(&chunk[..n]);
        }
        body = buf.drain(..cl).collect();
    }
    Some(Seen { method, path, head, body, conn })
}

/// A keep-alive HTTP/1.1 backend that answers each request with `handler` and records it.
fn backend(handler: Handler) -> (SocketAddr, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    thread::spawn(move || {
        for (conn, stream) in listener.incoming().enumerate() {
            let Ok(mut s) = stream else { continue };
            let log = Arc::clone(&log);
            thread::spawn(move || {
                let mut buf = Vec::new();
                while let Some(req) = read_request(&mut s, &mut buf, conn) {
                    log.lock().unwrap().push(req.clone());
                    let reply = handler(&req);
                    for (i, part) in reply.parts.iter().enumerate() {
                        if i > 0 {
                            thread::sleep(reply.gap);
                        }
                        if s.write_all(part).is_err() {
                            return;
                        }
                    }
                    if reply.close {
                        return;
                    }
                }
            });
        }
    });
    (addr, seen)
}

// ---- the proxy ----------------------------------------------------------------------

/// The process, and the config file it reads, kept until the process is gone.
struct Proxy {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        stop(&mut self.child);
    }
}

/// Stops the binary the way it exits cleanly -- `SIGUSR1`, the soft stop -- so an
/// instrumented build writes its coverage profile; `SIGKILL` discards it, which left every
/// line these tests run invisible to `harness/covercheck.py`. Killed if it lingers.
fn stop(child: &mut Child) {
    let _ = Command::new("kill").arg("-USR1").arg(child.id().to_string()).status();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Starts the binary under test with `cfg`, in which `@FE@` is replaced by the frontend
/// address and `@BEn@` by `backends[n]`.
/// A port for the proxy to listen on, below the kernel's ephemeral range. Taken from that
/// range (`bind :0`, then released), it could be handed straight to another test's backend
/// before the proxy bound it -- the readiness probe then connected to the wrong process,
/// and the test talked to a stranger. Backends bind `:0`, so they never land down here.

fn start(cfg: &str, backends: &[SocketAddr]) -> (Proxy, SocketAddr) {
    let fe = common::reserve_addr();
    let mut text = format!(
        // One thread: the suite runs every case at once, and a proxy per case with a worker
        // per CPU is thousands of threads.
        "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n{cfg}"
    )
    .replace("@FE@", &fe.to_string());
    for (i, be) in backends.iter().enumerate() {
        text = text.replace(&format!("@BE{i}@"), &be.to_string());
    }
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).unwrap();
    let bin = std::env::var("IBEX_TXN_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let mut cmd = Command::new(&bin);
    if bin.contains("haproxy") {
        cmd.arg("-db");
    }
    let child = cmd
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn proxy");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "{bin} never started listening on {fe}");
        thread::sleep(Duration::from_millis(20));
    }
    // Answering a connect is not yet being ready. With every case starting a proxy at once,
    // a first request sent straight after the probe was now and then reset -- with
    // HAProxy as the binary as well as Ibex (0-3 resets per run of the suite, never one
    // run alone). A short settle removed them in five runs of five.
    thread::sleep(Duration::from_millis(300));
    (Proxy { child, _cfg: f }, fe)
}

/// One frontend, one backend with one server.
fn simple(handler: Handler, frontend_extra: &str) -> (Proxy, SocketAddr, Arc<Mutex<Vec<Seen>>>) {
    let (be, seen) = backend(handler);
    let (p, fe) = start(
        &format!("frontend fe\n  bind @FE@\n{frontend_extra}  default_backend be\nbackend be\n  server s1 @BE0@\n"),
        &[be],
    );
    (p, fe, seen)
}

// ---- the client ---------------------------------------------------------------------

#[derive(Debug)]
struct Resp {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.head.split("\r\n").skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }
    fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

struct Client {
    s: TcpStream,
    buf: Vec<u8>,
    eof: bool,
}

impl Client {
    fn connect(fe: SocketAddr) -> Self {
        let s = TcpStream::connect(fe).expect("connect");
        s.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        Client { s, buf: Vec::new(), eof: false }
    }

    fn send(&mut self, data: &[u8]) {
        self.s.write_all(data).expect("send");
    }

    /// Reads more into `buf`; false once `deadline` passes or the peer closed.
    fn fill(&mut self, deadline: Instant) -> bool {
        let mut chunk = vec![0u8; 65536];
        while Instant::now() < deadline {
            match self.s.read(&mut chunk) {
                Ok(0) | Err(_) if self.eof => return false,
                Ok(0) => {
                    self.eof = true;
                    return false;
                }
                Ok(n) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    return true;
                }
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(_) => {
                    self.eof = true;
                    return false;
                }
            }
        }
        false
    }

    /// The next complete response, interim (1xx) ones included; `None` if none arrives
    /// within three seconds. `head_req` says the request was a HEAD (no body follows).
    fn response(&mut self, head_req: bool) -> Option<Resp> {
        let deadline = Instant::now() + Duration::from_secs(3);
        let head_end = loop {
            if let Some(p) = find(&self.buf, b"\r\n\r\n") {
                break p + 4;
            }
            if !self.fill(deadline) {
                return None;
            }
        };
        let head = String::from_utf8_lossy(&self.buf[..head_end]).into_owned();
        self.buf.drain(..head_end);
        let status: u16 = head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let mut r = Resp { status, head, body: Vec::new() };
        if head_req || (100..200).contains(&status) || status == 204 || status == 304 {
            return Some(r);
        }
        if r.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
            loop {
                let line_end = loop {
                    if let Some(p) = find(&self.buf, b"\r\n") {
                        break p;
                    }
                    if !self.fill(deadline) {
                        return None;
                    }
                };
                let size_str = String::from_utf8_lossy(&self.buf[..line_end]).into_owned();
                let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16).ok()?;
                while self.buf.len() < line_end + 2 + size + 2 {
                    if !self.fill(deadline) {
                        return None;
                    }
                }
                r.body.extend_from_slice(&self.buf[line_end + 2..line_end + 2 + size]);
                self.buf.drain(..line_end + 2 + size + 2);
                if size == 0 {
                    return Some(r);
                }
            }
        }
        if let Some(cl) = r.header("content-length").and_then(|v| v.parse::<usize>().ok()) {
            while self.buf.len() < cl {
                if !self.fill(deadline) {
                    return None;
                }
            }
            r.body = self.buf.drain(..cl).collect();
            return Some(r);
        }
        while self.fill(deadline) {}
        r.body = std::mem::take(&mut self.buf);
        Some(r)
    }

    /// The next final response, skipping interim ones.
    fn final_response(&mut self) -> Option<Resp> {
        loop {
            let r = self.response(false)?;
            if r.status >= 200 {
                return Some(r);
            }
        }
    }

    /// Whether the proxy closes the connection within `wait`, with nothing more sent.
    fn closed_within(&mut self, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        while self.fill(deadline) {}
        self.eof
    }

    fn get(&mut self, path: &str) -> Option<Resp> {
        self.send(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes());
        self.final_response()
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Echoes what arrived: `METHOD PATH BODYLEN`.
fn echo(r: &Seen) -> Reply {
    Reply::ok(&format!("{} {} {}", r.method, r.path, r.body.len()))
}

// ---- requests -----------------------------------------------------------------------

/// Three requests written in one packet are three transactions, routed one at a time:
/// the second goes where its own path says, not down the connection the first opened.
/// `HAProxy` 3.5: be1, be2, be1.
#[test]
fn pipelined_requests_are_each_routed_on_their_own() {
    let (b1, _) = backend(|_| Reply::ok("be1"));
    let (b2, _) = backend(|_| Reply::ok("be2"));
    let (_p, fe) = start(
        "frontend fe\n  bind @FE@\n  use_backend be2 if { path_beg /b }\n  default_backend be1\n\
         backend be1\n  server s1 @BE0@\nbackend be2\n  server s1 @BE1@\n",
        &[b1, b2],
    );
    let mut c = Client::connect(fe);
    c.send(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\nGET /a HTTP/1.1\r\nHost: x\r\n\r\n");
    let bodies: Vec<String> = (0..3).filter_map(|_| c.final_response()).map(|r| r.body_str()).collect();
    assert_eq!(bodies, ["be1", "be2", "be1"]);
}

/// A POST's body reaches the server intact, and the GET after it on the same connection
/// is a request of its own. `HAProxy` 3.5: both answered, body of 5 bytes forwarded.
#[test]
fn a_post_with_a_body_then_a_get() {
    let (_p, fe, seen) = simple(echo, "");
    let mut c = Client::connect(fe);
    c.send(b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello");
    assert_eq!(c.final_response().map(|r| r.body_str()).as_deref(), Some("POST /p 5"));
    assert_eq!(c.get("/g").map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
    assert_eq!(seen.lock().unwrap()[0].body, b"hello");
}

/// The same with the body and the next request in one packet.
#[test]
fn a_post_body_and_the_next_request_in_one_packet() {
    let (_p, fe, seen) = simple(echo, "");
    let mut c = Client::connect(fe);
    c.send(b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhelloGET /g HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(c.final_response().map(|r| r.body_str()).as_deref(), Some("POST /p 5"));
    assert_eq!(c.final_response().map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
    assert_eq!(seen.lock().unwrap()[0].body, b"hello");
}

/// A chunked request body, then a GET. `HAProxy` 3.5: both answered.
#[test]
fn a_chunked_post_then_a_get() {
    let (_p, fe, seen) = simple(echo, "");
    let mut c = Client::connect(fe);
    c.send(b"POST /p HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n");
    assert_eq!(c.final_response().map(|r| r.body_str()).as_deref(), Some("POST /p 5"));
    assert_eq!(c.get("/g").map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
    assert_eq!(seen.lock().unwrap()[0].body, b"abcde");
}

/// A request body several times the buffer size is streamed through, then a GET.
#[test]
fn a_large_request_body_then_a_get() {
    let (_p, fe, seen) = simple(echo, "");
    let mut c = Client::connect(fe);
    let body = vec![b'x'; 200_000];
    c.send(format!("POST /big HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes());
    c.send(&body);
    assert_eq!(c.final_response().map(|r| r.body_str()).as_deref(), Some("POST /big 200000"));
    assert_eq!(c.get("/g").map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
    assert_eq!(seen.lock().unwrap()[0].body.len(), 200_000);
}

/// `Expect: 100-continue`: the interim response reaches the client, the body follows,
/// and the final response and the next request work. `HAProxy` 3.5: 100, then 200, then
/// the GET.
#[test]
fn expect_100_continue() {
    let (_p, fe, seen) = simple(echo, "");
    let mut c = Client::connect(fe);
    c.send(b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n");
    let interim = c.response(false);
    assert_eq!(interim.as_ref().map(|r| r.status), Some(100), "{interim:?}");
    c.send(b"hello");
    assert_eq!(c.final_response().map(|r| r.body_str()).as_deref(), Some("POST /p 5"));
    assert_eq!(c.get("/g").map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
    assert_eq!(seen.lock().unwrap()[0].body, b"hello");
}

// ---- responses ----------------------------------------------------------------------

/// A response body that arrives in pieces, with pauses, and contains a blank line, is one
/// response: the transaction ends at its `Content-Length`, not when the buffer happens to
/// drain. Then the next request.
#[test]
fn a_slow_response_body_is_not_mistaken_for_the_next_response() {
    let (_p, fe, _) = simple(
        |_| {
            let body = "first part\r\n\r\nHTTP/1.1 500 Fake\r\n\r\nlast part";
            Reply {
                parts: vec![
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\nfirst part", body.len()).into_bytes(),
                    b"\r\n\r\nHTTP/1.1 500 Fake\r\n\r\n".to_vec(),
                    b"last part".to_vec(),
                ],
                gap: Duration::from_millis(100),
                close: false,
            }
        },
        "  http-response set-header X-Seen yes\n",
    );
    let mut c = Client::connect(fe);
    let r = c.get("/1").expect("first response");
    assert_eq!(r.body_str(), "first part\r\n\r\nHTTP/1.1 500 Fake\r\n\r\nlast part");
    let r = c.get("/2").expect("second response");
    assert_eq!(r.status, 200);
    assert_eq!(r.header("x-seen"), Some("yes"), "{r:?}");
}

/// A response much larger than the buffer, then the next request.
#[test]
fn a_large_response_then_a_get() {
    let (_p, fe, _) = simple(
        |r| {
            if r.path == "/big" {
                let body = "y".repeat(300_000);
                Reply {
                    parts: vec![format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()],
                    gap: Duration::ZERO,
                    close: false,
                }
            } else {
                echo(r)
            }
        },
        "",
    );
    let mut c = Client::connect(fe);
    assert_eq!(c.get("/big").map(|r| r.body.len()), Some(300_000));
    assert_eq!(c.get("/g").map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
}

/// A chunked response sent in pieces, then the next request.
#[test]
fn a_chunked_response_in_pieces_then_a_get() {
    let (_p, fe, _) = simple(
        |r| {
            if r.path == "/c" {
                Reply {
                    parts: vec![
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n".to_vec(),
                        b"6\r\n world\r\n".to_vec(),
                        b"0\r\n\r\n".to_vec(),
                    ],
                    gap: Duration::from_millis(50),
                    close: false,
                }
            } else {
                echo(r)
            }
        },
        "",
    );
    let mut c = Client::connect(fe);
    assert_eq!(c.get("/c").map(|r| r.body_str()).as_deref(), Some("hello world"));
    assert_eq!(c.get("/g").map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
}

/// A HEAD response carries a `Content-Length` and no body; the next response follows
/// straight after it.
#[test]
fn a_head_response_has_no_body() {
    let (_p, fe, _) = simple(
        |r| {
            if r.method == "HEAD" {
                Reply {
                    parts: vec![b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".to_vec()],
                    gap: Duration::ZERO,
                    close: false,
                }
            } else {
                echo(r)
            }
        },
        "",
    );
    let mut c = Client::connect(fe);
    c.send(b"HEAD /h HTTP/1.1\r\nHost: x\r\n\r\n");
    let r = c.response(true).expect("HEAD response");
    assert_eq!(r.header("content-length"), Some("5"));
    assert_eq!(c.get("/g").map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
}

/// A 204 has no body; the next response follows straight after it.
#[test]
fn a_204_then_a_get() {
    let (_p, fe, _) = simple(
        |r| {
            if r.path == "/nc" {
                Reply { parts: vec![b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()], gap: Duration::ZERO, close: false }
            } else {
                echo(r)
            }
        },
        "",
    );
    let mut c = Client::connect(fe);
    assert_eq!(c.get("/nc").map(|r| r.status), Some(204));
    assert_eq!(c.get("/g").map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
}

/// Keep-alive to the server: three requests on one client connection use one server
/// connection.
#[test]
fn the_server_connection_is_kept_across_requests() {
    let (_p, fe, seen) = simple(echo, "");
    let mut c = Client::connect(fe);
    for i in 0..3 {
        assert!(c.get(&format!("/{i}")).is_some(), "request {i}");
    }
    let conns: Vec<usize> = seen.lock().unwrap().iter().map(|s| s.conn).collect();
    assert_eq!(conns, [0, 0, 0]);
}

// ---- responses the proxy writes itself ------------------------------------------------

/// What happens to the connection after each kind of locally generated response, then a
/// second request on it.
fn local_reply_then_get(rule: &str) -> (Resp, Option<Resp>) {
    let (_p, fe, _) = simple(echo, &format!("  {rule} if {{ path /local }}\n"));
    let mut c = Client::connect(fe);
    let first = c.get("/local").expect("local reply");
    let second = c.get("/g");
    (first, second)
}

/// `http-request return` keeps the connection. `HAProxy` 3.5: 200 then the GET.
#[test]
fn return_keeps_the_connection() {
    let (first, second) = local_reply_then_get("http-request return status 200 content-type text/plain string hi");
    assert_eq!((first.status, first.body_str().as_str()), (200, "hi"));
    assert_eq!(second.map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
}

/// `http-request deny`. `HAProxy` 3.5: 403, and the connection is kept.
#[test]
fn deny_keeps_the_connection() {
    let (first, second) = local_reply_then_get("http-request deny");
    assert_eq!(first.status, 403);
    assert_eq!(second.map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
}

/// `http-request redirect`. `HAProxy` 3.5: 302, and the connection is kept.
#[test]
fn redirect_keeps_the_connection() {
    let (first, second) = local_reply_then_get("http-request redirect location /elsewhere");
    assert_eq!(first.status, 302);
    assert_eq!(first.header("location"), Some("/elsewhere"));
    assert_eq!(second.map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
}

/// `http-request auth`. `HAProxy` 3.5: 401, and the connection is kept.
#[test]
fn auth_keeps_the_connection() {
    let (first, second) = local_reply_then_get("http-request auth");
    assert_eq!(first.status, 401);
    assert_eq!(second.map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
}

/// A locally answered POST whose body has not been read: the body must not be parsed as
/// the next request.
#[test]
fn a_denied_post_body_is_not_read_as_a_request() {
    let (_p, fe, seen) = simple(echo, "  http-request deny if { path /local }\n");
    let mut c = Client::connect(fe);
    c.send(b"POST /local HTTP/1.1\r\nHost: x\r\nContent-Length: 30\r\n\r\nGET /smuggled HTTP/1.1\r\nX: y\r\n\r\n");
    assert_eq!(c.final_response().map(|r| r.status), Some(403));
    let next = c.get("/g");
    assert!(seen.lock().unwrap().iter().all(|s| s.path != "/smuggled"), "{:?}", seen.lock().unwrap());
    if let Some(r) = next {
        assert_eq!(r.body_str(), "GET /g 0");
    }
}

/// A 503 the proxy generates (no server) then a second request. `HAProxy` 3.5: 503, 503.
#[test]
fn a_generated_503_keeps_the_connection() {
    let (_p, fe) = start("frontend fe\n  bind @FE@\n  default_backend be\nbackend be\n", &[]);
    let mut c = Client::connect(fe);
    assert_eq!(c.get("/1").map(|r| r.status), Some(503));
    assert_eq!(c.get("/2").map(|r| r.status), Some(503));
    assert!(!c.closed_within(Duration::from_millis(200)));
}

/// `Connection: close` from the client: answered, then closed.
#[test]
fn connection_close_from_the_client_closes_after_the_response() {
    let (_p, fe, _) = simple(echo, "");
    let mut c = Client::connect(fe);
    c.send(b"GET /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert_eq!(c.final_response().map(|r| r.body_str()).as_deref(), Some("GET /x 0"));
    assert!(c.closed_within(Duration::from_secs(1)));
}

/// T89: `Content-Length` beside `Transfer-Encoding: chunked`. `HAProxy` forwards it: the
/// chunked encoding wins, the `Content-Length` is removed, and the connection closes after
/// the response (`src/h1.c`, `h1_parse_msg_hdrs`: "T-E + C-L: force close and remove C-L",
/// unless `h1-do-not-close-on-insecure-transfer-encoding`). Measured on HAProxy
/// 3.5-dev7-e6f616-55, 2026-10-02.
///
/// The checkin runs this file against the reference HAProxy (`harness/txn_oracle.py`), so
/// if HAProxy starts refusing these (RFC 9112 6.3 allows either) or keeps the connection,
/// that check goes red and says when.
#[test]
fn content_length_beside_chunked_is_forwarded_chunked_then_closed() {
    let (_p, fe, seen) = simple(echo, "");
    let mut c = Client::connect(fe);
    c.send(
        b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n\
          3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
    );
    let r = c.final_response();
    assert_eq!(r.as_ref().map(|r| (r.status, r.body_str())), Some((200, "POST /p 5".to_string())), "{r:?}");
    assert!(c.closed_within(Duration::from_secs(1)), "the connection must close after the response");
    let seen = seen.lock().unwrap();
    assert_eq!(seen[0].body, b"abcde", "the body is framed by the chunks, not the length");
    let head = seen[0].head.to_ascii_lowercase();
    assert!(!head.contains("content-length"), "Content-Length must be removed:\n{head}");
    assert!(head.contains("transfer-encoding: chunked"), "{head}");
}

/// `http-request` rules run for every request on a connection, not only the first: the
/// second request here is the one the rule matches. `HAProxy` 3.5: 200, 403, 200.
#[test]
fn request_rules_run_on_every_request() {
    let (_p, fe, seen) = simple(echo, "  http-request deny if { path /local }\n");
    let mut c = Client::connect(fe);
    assert_eq!(c.get("/g").map(|r| r.status), Some(200));
    assert_eq!(c.get("/local").map(|r| r.status), Some(403));
    assert_eq!(c.get("/g").map(|r| r.status), Some(200));
    assert!(seen.lock().unwrap().iter().all(|s| s.path != "/local"));
}

/// A server that closes without answering. `HAProxy` 3.5: 502 with its built-in page.
#[test]
fn a_server_closing_without_a_response_gets_a_502() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let be = listener.local_addr().unwrap();
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
        }
    });
    let (_p, fe) = start("frontend fe\n  bind @FE@\n  default_backend be\nbackend be\n  server s1 @BE0@\n", &[be]);
    let mut c = Client::connect(fe);
    let r = c.get("/x").expect("a response");
    assert_eq!(r.status, 502);
    assert!(r.body_str().contains("502 Bad Gateway"), "{r:?}");
}

/// A server that does not answer within `timeout server`. `HAProxy` 3.5: 504.
#[test]
fn a_server_timeout_gets_a_504() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let be = listener.local_addr().unwrap();
    thread::spawn(move || {
        let mut held = Vec::new();
        for s in listener.incoming() {
            held.push(s);
        }
    });
    let (_p, fe) = start(
        "frontend fe\n  bind @FE@\n  default_backend be\nbackend be\n  timeout server 300ms\n  server s1 @BE0@\n",
        &[be],
    );
    let mut c = Client::connect(fe);
    let r = c.get("/x").expect("a response");
    assert_eq!(r.status, 504);
}

/// An interim response and the final one in one packet: both reach the client, in order
/// (RFC 9110 section 15.2). `HAProxy` 3.5-dev8: 103, then 200. (3.5-dev7 aborted on this,
/// `BUG_ON` at `src/htx.c:391`; fixed upstream by 76454cbbf, see
/// `upstream/haproxy-1xx-in-one-read.md`.)
#[test]
fn an_interim_and_a_final_response_in_one_packet() {
    let (_p, fe, _) = simple(
        |r| {
            if r.path == "/eh" {
                Reply {
                    parts: vec![b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()],
                    gap: Duration::ZERO,
                    close: false,
                }
            } else {
                echo(r)
            }
        },
        "",
    );
    let mut c = Client::connect(fe);
    c.send(b"GET /eh HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(c.response(false).map(|r| r.status), Some(103));
    assert_eq!(c.response(false).map(|r| r.body_str()).as_deref(), Some("ok"));
    assert_eq!(c.get("/g").map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
}

/// An interim response, a pause, then the final one. `HAProxy` 3.5: 103, then 200.
#[test]
fn an_interim_response_then_the_final_one() {
    let (_p, fe, _) = simple(
        |r| {
            if r.path == "/eh" {
                Reply {
                    parts: vec![
                        b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n".to_vec(),
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
                    ],
                    gap: Duration::from_millis(100),
                    close: false,
                }
            } else {
                echo(r)
            }
        },
        "",
    );
    let mut c = Client::connect(fe);
    c.send(b"GET /eh HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(c.response(false).map(|r| r.status), Some(103));
    assert_eq!(c.response(false).map(|r| r.body_str()).as_deref(), Some("ok"));
    assert_eq!(c.get("/g").map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
}

/// A `101 Switching Protocols` turns the connection into a tunnel: bytes flow both ways
/// unparsed until one side closes. `HAProxy` 3.5: both messages echoed, then closed. (Without
/// `Sec-WebSocket-Key` it answers the upgrade request with a 400.)
#[test]
fn an_upgrade_becomes_a_tunnel() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let be = listener.local_addr().unwrap();
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                let mut buf = Vec::new();
                if read_request(&mut s, &mut buf, 0).is_none() {
                    return;
                }
                let _ = s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n");
                let mut chunk = [0u8; 4096];
                while let Ok(n) = s.read(&mut chunk) {
                    if n == 0 || s.write_all(&chunk[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    let (_p, fe) = start("frontend fe\n  bind @FE@\n  default_backend be\nbackend be\n  server s1 @BE0@\n", &[be]);
    let mut c = Client::connect(fe);
    c.send(b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
    assert_eq!(c.response(false).map(|r| r.status), Some(101));
    for msg in [&b"\r\n\r\nnot http\r\n\r\n"[..], b"HTTP/1.1 200 OK\r\n\r\n"] {
        c.send(msg);
        let deadline = Instant::now() + Duration::from_secs(2);
        while c.buf.len() < msg.len() && c.fill(deadline) {}
        assert_eq!(c.buf.drain(..).as_slice(), msg);
    }
    // Either side closing ends the tunnel. `HAProxy` 3.5: the client's half-close reaches
    // the server, which closes, and so does the client connection.
    c.s.shutdown(std::net::Shutdown::Write).unwrap();
    assert!(c.closed_within(Duration::from_secs(1)), "the tunnel outlived its client");
}

/// Request rewrites apply to every request on a connection, including those that go down a
/// server connection kept from the previous one. `HAProxy` 3.5: the header on all three.
#[test]
fn request_rewrites_apply_to_every_request() {
    let (_p, fe, seen) = simple(
        |r| Reply::ok(&format!("{} {}", r.path, r.body.len())),
        "  http-request set-header X-Tag tagged\n  http-request set-path /rewritten%[path]\n",
    );
    let mut c = Client::connect(fe);
    for i in 0..3 {
        assert_eq!(c.get(&format!("/{i}")).map(|r| r.body_str()), Some(format!("/rewritten/{i} 0")));
    }
    let paths: Vec<String> = seen.lock().unwrap().iter().map(|s| s.path.clone()).collect();
    assert_eq!(paths, ["/rewritten/0", "/rewritten/1", "/rewritten/2"]);
}

// ---- edges: how each side can end, and the replies that close ---------------------------

/// A server that accepts, answers each request it reads, and closes `idle` after the last.
fn closing_backend(idle: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let be = listener.local_addr().unwrap();
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                s.set_read_timeout(Some(idle)).unwrap();
                let mut buf = Vec::new();
                while let Some(r) = read_request(&mut s, &mut buf, 0) {
                    let body = format!("GET {} 0", r.path);
                    let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes());
                }
            });
        }
    });
    be
}

/// A server that answers every request with `raw` and closes.
fn raw_backend(raw: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let be = listener.local_addr().unwrap();
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            let mut buf = Vec::new();
            if read_request(&mut s, &mut buf, 0).is_some() {
                let _ = s.write_all(raw);
            }
        }
    });
    be
}

fn one_backend(be: SocketAddr, backend_extra: &str) -> (Proxy, SocketAddr) {
    start(&format!("frontend fe\n  bind @FE@\n  default_backend be\nbackend be\n{backend_extra}  server s1 @BE0@\n"), &[be])
}

/// The server closes the connection kept between two requests. The second request gets a
/// new connection, not an error. `HAProxy` 3.5: 200, 200.
#[test]
fn a_kept_server_connection_closed_while_idle_is_replaced() {
    let (_p, fe) = one_backend(closing_backend(Duration::from_millis(100)), "");
    let mut c = Client::connect(fe);
    assert_eq!(c.get("/1").map(|r| r.body_str()).as_deref(), Some("GET /1 0"));
    thread::sleep(Duration::from_millis(400));
    assert_eq!(c.get("/2").map(|r| r.body_str()).as_deref(), Some("GET /2 0"));
}

/// No server answers the connect within `timeout connect`. `HAProxy` 3.5: 503.
#[test]
fn a_connect_timeout_gets_a_503() {
    // TEST-NET-1 (RFC 5737): routed nowhere, so the connect neither completes nor fails.
    let be: SocketAddr = "192.0.2.1:80".parse().unwrap();
    let (_p, fe) = one_backend(be, "  timeout connect 200ms\n  retries 0\n");
    let mut c = Client::connect(fe);
    assert_eq!(c.get("/x").map(|r| r.status), Some(503));
}

/// The server closes in the middle of a body. What arrived is delivered, then the client
/// connection closes. `HAProxy` 3.5: the head and the 5 bytes, then close.
#[test]
fn a_response_cut_short_closes_the_client_after_what_arrived() {
    let (_p, fe) = one_backend(raw_backend(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhello"), "");
    let mut c = Client::connect(fe);
    c.send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(c.closed_within(Duration::from_secs(2)), "the client connection stayed open");
    let got = String::from_utf8_lossy(&c.buf).into_owned();
    assert!(got.starts_with("HTTP/1.1 200"), "{got:?}");
    assert!(got.ends_with("\r\n\r\nhello"), "{got:?}");
}

/// A response whose status line does not parse. `HAProxy` 3.5: 502.
#[test]
fn a_malformed_response_gets_a_502() {
    let (_p, fe) = one_backend(raw_backend(b"NOT HTTP AT ALL\r\n\r\n"), "");
    let mut c = Client::connect(fe);
    assert_eq!(c.get("/x").map(|r| r.status), Some(502));
}

/// `http-request` rules in the backend answer too. `HAProxy` 3.5: 403.
#[test]
fn a_backend_rule_answers() {
    let (be, seen) = backend(echo);
    let (_p, fe) = one_backend(be, "  http-request deny if { path /local }\n");
    let mut c = Client::connect(fe);
    assert_eq!(c.get("/local").map(|r| r.status), Some(403));
    assert_eq!(c.get("/g").map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
    assert!(seen.lock().unwrap().iter().all(|s| s.path != "/local"));
}

/// `http-error` replaces the page for the proxy's own error. `HAProxy` 3.5: the 503 carries
/// the configured body.
#[test]
fn http_error_replaces_the_generated_page() {
    let (_p, fe) = start(
        "frontend fe\n  bind @FE@\n  default_backend be\n\
         backend be\n  http-error status 503 content-type text/plain string busy\n",
        &[],
    );
    let mut c = Client::connect(fe);
    let r = c.get("/x").expect("a response");
    assert_eq!((r.status, r.body_str().as_str()), (503, "busy"));
}

/// A request answered before its body has all arrived: the rest of the body is drained as
/// it comes, and the connection is kept. `HAProxy` 3.5: 403, then once the body is in, the
/// next request on the connection is answered.
#[test]
fn a_reply_before_the_body_arrives_drains_it() {
    let (_p, fe, seen) = simple(echo, "  http-request deny if { path /local }\n");
    let mut c = Client::connect(fe);
    c.send(b"POST /local HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\nonly-a-little");
    assert_eq!(c.final_response().map(|r| r.status), Some(403));
    let mut rest = vec![b'x'; 1000 - 13];
    rest.extend_from_slice(b"GET /g HTTP/1.1\r\nHost: x\r\n\r\n");
    c.send(&rest);
    assert_eq!(c.final_response().map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
    assert_eq!(seen.lock().unwrap().len(), 1, "{:?}", seen.lock().unwrap());
}

/// A client that asked to close gets a reply saying so, then the close. `HAProxy` 3.5:
/// `connection: close` on the 403.
#[test]
fn a_reply_to_a_closing_client_says_so() {
    let (_p, fe, _) = simple(echo, "  http-request deny\n");
    let mut c = Client::connect(fe);
    c.send(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    let r = c.final_response().expect("a response");
    assert_eq!(r.status, 403);
    assert_eq!(r.header("connection").map(str::to_ascii_lowercase).as_deref(), Some("close"));
    assert!(c.closed_within(Duration::from_secs(1)));
}

/// An empty errorfile: nothing is sent and the connection closes (the `/dev/null` idiom).
/// `HAProxy` 3.5: closed with no bytes.
#[test]
fn an_empty_errorfile_closes_without_a_response() {
    let empty = NamedTempFile::new().unwrap();
    let (_p, fe, _) = simple(echo, &format!("  errorfile 403 {}\n  http-request deny\n", empty.path().display()));
    let mut c = Client::connect(fe);
    c.send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(c.closed_within(Duration::from_secs(1)));
    assert!(c.buf.is_empty(), "{:?}", String::from_utf8_lossy(&c.buf));
}

/// A request that does not parse. `HAProxy` 3.5: 400, then close. (Content-Length with
/// chunked is not here: `HAProxy` 3.5 accepts it, Ibex refuses it -- tasks/T89.)
#[test]
fn an_unparsable_request_gets_a_400_and_a_close() {
    let (_p, fe, seen) = simple(echo, "");
    let mut c = Client::connect(fe);
    c.send(b"\x01GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(c.final_response().map(|r| r.status), Some(400));
    assert!(c.closed_within(Duration::from_secs(1)));
    assert!(seen.lock().unwrap().is_empty());
}

/// A server that answers the first request on each connection, then reads the second and
/// closes without answering it.
fn second_request_dropping_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let be = listener.local_addr().unwrap();
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                let mut buf = Vec::new();
                if read_request(&mut s, &mut buf, 0).is_some() {
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                    let _ = read_request(&mut s, &mut buf, 0);
                }
            });
        }
    });
    be
}

/// A request sent on a kept server connection that the server then closes, with nothing
/// answered. The client connection closes with no bytes, so the client retries, as it
/// would on a keep-alive connection closed under it -- `HAProxy`'s `abort_keep_alive`
/// (`src/http_ana.c`, taken on `SF_SRV_REUSED`). A 502 would not be retried. `HAProxy`
/// 3.5: 200, then closed with no bytes.
#[test]
fn a_kept_server_connection_closing_on_the_next_request_closes_the_client() {
    let (_p, fe) = one_backend(second_request_dropping_backend(), "");
    let mut c = Client::connect(fe);
    assert_eq!(c.get("/1").map(|r| r.status), Some(200));
    c.send(b"GET /2 HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(c.closed_within(Duration::from_secs(1)), "the client connection stayed open");
    assert!(c.buf.is_empty(), "{:?}", String::from_utf8_lossy(&c.buf));
}

/// CPU time, in clock ticks, the process has used (`utime` + `stime`).
fn cpu_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("/proc/<pid>/stat");
    // Fields after the parenthesised command name; utime and stime are the 14th and 15th.
    let rest = &stat[stat.rfind(')').expect("comm") + 2..];
    let f: Vec<&str> = rest.split(' ').collect();
    f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()
}

/// After a 502 the client connection is kept, and the server side is gone: its timer must
/// not keep the session awake. Ibex left `timeout server` armed and expired, and spun --
/// a zero-timeout poll and a read of the client, over and over -- until `timeout client`.
/// `HAProxy` 3.5: idle (0-1 ticks over the second measured).
#[test]
fn a_kept_client_connection_after_a_502_is_idle() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let be = listener.local_addr().unwrap();
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
        }
    });
    let (p, fe) = one_backend(be, "  timeout server 200ms\n");
    let mut c = Client::connect(fe);
    assert_eq!(c.get("/x").map(|r| r.status), Some(502));
    // Past the server timer, well inside `timeout client` (5s).
    thread::sleep(Duration::from_millis(500));
    let before = cpu_ticks(p.child.id());
    thread::sleep(Duration::from_secs(1));
    let used = cpu_ticks(p.child.id()) - before;
    assert!(used < 20, "{used} ticks of CPU in one idle second");
}

fn chunked_for_req1(r: &Seen) -> Reply {
    if r.path != "/req1" {
        return Reply::ok("last response");
    }
    let mut parts = vec![b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec()];
    for n in [15usize, 1024, 4048, 50000] {
        parts.push([format!("{n:x}\r\n").into_bytes(), vec![b'x'; n], b"\r\n".to_vec()].concat());
    }
    parts.push(b"0\r\n\r\n".to_vec());
    Reply { parts, gap: Duration::ZERO, close: false }
}

/// A HEAD the proxy turns into a GET: the server sends a body, framed as the GET it
/// answers, and the client, which asked for a HEAD, gets the head alone. Ibex framed the
/// response by the rewritten method and forwarded the body, so the client read it as the
/// start of its next response. `HAProxy` 3.5 (and `reg-tests/http-messaging/
/// http_bodyless_response.vtc`): the head only, then the next response, one server
/// connection.
#[test]
fn a_head_rewritten_to_get_gets_no_body() {
    let (_p, fe, seen) = simple(chunked_for_req1, "  http-request set-method GET\n");
    let mut c = Client::connect(fe);
    c.send(b"HEAD /req1 HTTP/1.1\r\nHost: x\r\n\r\n");
    let r = c.response(true).expect("a response");
    assert_eq!(r.status, 200);
    c.send(b"GET /req2 HTTP/1.1\r\nHost: x\r\n\r\n");
    let r = c.response(false).expect("a second response");
    assert_eq!((r.status, r.body_str().as_str()), (200, "last response"), "{r:?}");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.iter().map(|s| (s.method.as_str(), s.conn)).collect::<Vec<_>>(), [("GET", 0), ("GET", 0)]);
}

// ---- the errors the proxy answers for itself ----------------------------------------
//
// Each of these was a path no test executed (harness/covercheck.py). The status each
// asserts is what `HAProxy` 3.5 answered, run through this file with `IBEX_TXN_BIN`.

/// A loopback address nothing listens on, so a connect to it is refused. Taken from the
/// test port range and kept locked, so nothing else in the run starts listening there.
fn refusing_addr() -> SocketAddr {
    common::reserve_addr()
}

/// A server that refuses the connection, retried, then given up on. `HAProxy` 3.5: 503.
#[test]
fn a_refused_connect_is_retried_then_gets_a_503() {
    let (_p, fe) = one_backend(refusing_addr(), "  retries 1\n");
    let mut c = Client::connect(fe);
    assert_eq!(c.get("/x").map(|r| r.status), Some(503));
}

/// `option redispatch`: the retry goes to another server. `HAProxy` 3.5: every request
/// answered by the live server.
#[test]
fn a_refused_connect_is_redispatched_to_another_server() {
    let (be, _) = backend(echo);
    let (_p, fe) = start(
        "frontend fe\n  bind @FE@\n  default_backend be\n\
         backend be\n  balance roundrobin\n  option redispatch\n  retries 1\n\
         \x20 server dead @BE0@\n  server live @BE1@\n",
        &[refusing_addr(), be],
    );
    for i in 0..4 {
        let mut c = Client::connect(fe);
        assert_eq!(c.get(&format!("/{i}")).map(|r| r.body_str()), Some(format!("GET /{i} 0")), "request {i}");
    }
}

/// A response head that does not end within the buffer. `HAProxy` 3.5: 502.
#[test]
fn a_response_head_too_large_for_the_buffer_gets_a_502() {
    let mut head = b"HTTP/1.1 200 OK\r\nX-Big: ".to_vec();
    head.extend(std::iter::repeat_n(b'a', 40_000));
    let (_p, fe) = one_backend(raw_backend(Box::leak(head.into_boxed_slice())), "");
    let mut c = Client::connect(fe);
    assert_eq!(c.get("/x").map(|r| r.status), Some(502));
}

/// The request path, kept in `txn.p` for response rules: `path` itself is a request
/// sample, and `HAProxy` no longer has it when the response is processed.
const KEEP_PATH: &str = "  http-request set-var(txn.p) path\n";

/// `http-response deny`, in the backend and in the frontend. `HAProxy` 3.5: 502 for both,
/// the server's response discarded.
#[test]
fn a_response_deny_gets_a_502() {
    let (be, _) = backend(echo);
    let (_p, fe) = start(
        &format!(
            "frontend fe\n  bind @FE@\n{KEEP_PATH}  http-response deny if {{ var(txn.p) -m str /fe }}\n\
             \x20 default_backend be\n\
             backend be\n  http-response deny if {{ var(txn.p) -m str /be }}\n  server s1 @BE0@\n"
        ),
        &[be],
    );
    for path in ["/be", "/fe"] {
        let mut c = Client::connect(fe);
        let r = c.get(path).expect("a response");
        assert_eq!(r.status, 502, "{path}: {r:?}");
        assert!(!r.body_str().contains("GET"), "{path}: the server's body was sent: {r:?}");
    }
}

/// `n` header actions of `action` adding 1000 bytes each, each followed by `cond`.
fn big_headers(rule: &str, action: &str, n: usize, cond: &str) -> String {
    (0..n).map(|i| format!("  {rule} {action} X-Big-{i} {} {cond}\n", "a".repeat(1000))).collect()
}

/// Response rewrites that no longer fit the buffer fail the response under the default
/// `strict-mode on`, whichever rule set and proxy they are in. `HAProxy` 3.5: 500 for
/// each.
#[test]
fn a_response_rewrite_that_does_not_fit_gets_a_500() {
    let (be, _) = backend(echo);
    let cases = [
        ("http-response", "add-header"),
        ("http-response", "set-header"),
        ("http-after-response", "add-header"),
        ("http-after-response", "set-header"),
    ];
    let mut fe_rules = String::new();
    let mut routes = String::new();
    let mut backends = String::new();
    for (i, (rule, action)) in cases.iter().enumerate() {
        fe_rules += &big_headers(rule, action, 20, &format!("if {{ var(txn.p) -m str /fe{i} }}"));
        routes += &format!("  use_backend be{i} if {{ path /be{i} }}\n");
        backends += &format!("backend be{i}\n{}  server s1 @BE0@\n", big_headers(rule, action, 20, ""));
    }
    let cfg = format!(
        "frontend fe\n  bind @FE@\n{KEEP_PATH}{routes}{fe_rules}  default_backend be_plain\n\
         {backends}backend be_plain\n  server s1 @BE0@\n"
    );
    let (_p, fe) = start(&cfg, &[be]);
    for i in 0..cases.len() {
        for path in [format!("/be{i}"), format!("/fe{i}")] {
            let mut c = Client::connect(fe);
            assert_eq!(c.get(&path).map(|r| r.status), Some(500), "{path}: {:?}", cases[i]);
        }
    }
    let mut c = Client::connect(fe);
    assert_eq!(c.get("/plain").map(|r| r.status), Some(200));
}

/// `tcp-response content reject` in an HTTP backend. `HAProxy` 3.5: the client connection
/// closes with nothing sent.
#[test]
fn a_tcp_response_reject_closes_without_a_response() {
    let (be, _) = backend(echo);
    let (_p, fe) = one_backend(be, "  tcp-response content reject\n");
    let mut c = Client::connect(fe);
    c.send(b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(c.closed_within(Duration::from_secs(2)), "the client connection stayed open");
    assert!(c.buf.is_empty(), "{:?}", String::from_utf8_lossy(&c.buf));
}

/// `normalize-uri ... strict` on a malformed percent-encoding, in the frontend and in the
/// backend. `HAProxy` 3.5: 400 for both, nothing sent to the server.
#[test]
fn a_strict_uri_normalizer_refuses_a_bad_escape_with_a_400() {
    let (be, seen) = backend(echo);
    let (_p, fe) = start(
        // HAProxy 3.5 calls `normalize-uri` experimental.
        "global\n  expose-experimental-directives\n\
         frontend fe\n  bind @FE@\n\
         \x20 http-request normalize-uri percent-to-uppercase strict if { path_beg /fe }\n\
         \x20 default_backend be\n\
         backend be\n  http-request normalize-uri percent-to-uppercase strict\n  server s1 @BE0@\n",
        &[be],
    );
    for path in ["/fe/%zz", "/be/%zz"] {
        let mut c = Client::connect(fe);
        assert_eq!(c.get(path).map(|r| r.status), Some(400), "{path}");
    }
    assert!(seen.lock().unwrap().is_empty(), "{:?}", seen.lock().unwrap());
}

/// Request rewrites that no longer fit the buffer. `HAProxy` 3.5: 500, nothing sent to the
/// server.
#[test]
fn a_request_rewrite_that_does_not_fit_gets_a_500() {
    let (be, seen) = backend(echo);
    let cfg = format!(
        "frontend fe\n  bind @FE@\n  use_backend be_set if {{ path /set }}\n  default_backend be_add\n\
         backend be_add\n{}  server s1 @BE0@\nbackend be_set\n{}  server s1 @BE0@\n",
        big_headers("http-request", "add-header", 20, ""),
        big_headers("http-request", "set-header", 20, ""),
    );
    let (_p, fe) = start(&cfg, &[be]);
    for path in ["/add", "/set"] {
        let mut c = Client::connect(fe);
        assert_eq!(c.get(path).map(|r| r.status), Some(500), "{path}");
    }
    assert!(seen.lock().unwrap().is_empty(), "{:?}", seen.lock().unwrap());
}

/// `replace-header` and `replace-value` with a back-reference. `HAProxy` 3.5: the server
/// sees `x-a: abc-x` and `x-b: 1-y,2-y` (each value rewritten, rejoined with `,`).
#[test]
fn replace_header_and_value_substitute_back_references() {
    let (_p, fe, seen) = simple(
        echo,
        "  http-request replace-header X-A ^(.*)$ \\1-x\n  http-request replace-value X-B ^(.*)$ \\1-y\n",
    );
    let mut c = Client::connect(fe);
    c.send(b"GET / HTTP/1.1\r\nHost: x\r\nX-A: abc\r\nX-B: 1, 2\r\n\r\n");
    assert_eq!(c.final_response().map(|r| r.status), Some(200));
    let head = seen.lock().unwrap()[0].head.to_ascii_lowercase();
    assert!(head.contains("\r\nx-a: abc-x\r\n"), "{head:?}");
    assert!(head.contains("\r\nx-b: 1-y,2-y\r\n"), "{head:?}");
}

/// A `replace-header` whose result would no longer fit the buffer. `HAProxy` 3.5: 500.
#[test]
fn a_replace_header_that_does_not_fit_gets_a_500() {
    let (be, seen) = backend(echo);
    // The 100-byte value, 200 times over: 20 kB, more than the 16 kB buffer.
    let repl = "\\1".repeat(200);
    let (_p, fe) = start(
        &format!(
            "frontend fe\n  bind @FE@\n  use_backend value if {{ path /value }}\n  default_backend header\n\
             backend header\n  http-request replace-header X-A ^(.*)$ {repl}\n  server s1 @BE0@\n\
             backend value\n  http-request replace-value X-A ^(.*)$ {repl}\n  server s1 @BE0@\n"
        ),
        &[be],
    );
    for path in ["/header", "/value"] {
        let mut c = Client::connect(fe);
        c.send(format!("GET {path} HTTP/1.1\r\nHost: x\r\nX-A: {}\r\n\r\n", "a".repeat(100)).as_bytes());
        assert_eq!(c.final_response().map(|r| r.status), Some(500), "{path}");
    }
    assert!(seen.lock().unwrap().is_empty(), "{:?}", seen.lock().unwrap());
}

/// A response head with bare-LF line ends, through response rules. `HAProxy` 3.5: 200,
/// with the header the rule adds.
#[test]
fn a_bare_lf_response_head_still_goes_through_the_rules() {
    let (_p, fe) = one_backend(
        raw_backend(b"HTTP/1.1 200 OK\nContent-Length: 2\n\nok"),
        "  http-response set-header X-Rule yes\n",
    );
    let mut c = Client::connect(fe);
    let r = c.get("/x").expect("a response");
    assert_eq!((r.status, r.body_str().as_str()), (200, "ok"), "{r:?}");
    assert_eq!(r.header("x-rule"), Some("yes"), "{r:?}");
}

/// A server that answers with a body larger than the buffers and closes at once: the close
/// arrives while the response is still being delivered. It ended the response rather than
/// cutting it short. `HAProxy` 3.5: the whole body, and the client connection is kept.
#[test]
fn a_server_closing_right_after_a_large_response_has_finished_it() {
    let mut raw = b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n".to_vec();
    raw.extend(std::iter::repeat_n(b'x', 1_000_000));
    let (_p, fe) = one_backend(raw_backend(Box::leak(raw.into_boxed_slice())), "");
    let mut c = Client::connect(fe);
    c.send(b"GET /big HTTP/1.1\r\nHost: x\r\n\r\n");
    // Let the server's whole answer and its close reach the proxy before reading any of it.
    thread::sleep(Duration::from_millis(300));
    let r = c.final_response().expect("a response");
    assert_eq!((r.status, r.body.len()), (200, 1_000_000));
    assert!(!c.closed_within(Duration::from_millis(200)), "the client connection was closed");
}

/// A body that runs until the server closes, ended by a reset instead. What arrived is
/// delivered, then the client connection closes. `HAProxy` 3.5: the head and `partial`,
/// then close.
#[test]
fn a_close_delimited_body_ended_by_a_reset_closes_the_client() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let be = listener.local_addr().unwrap();
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            let mut buf = Vec::new();
            if read_request(&mut s, &mut buf, 0).is_some() {
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\npartial");
                thread::sleep(Duration::from_millis(200));
                // SO_LINGER 0: the close is a reset.
                let _ = rustix::net::sockopt::set_socket_linger(&s, Some(Duration::ZERO));
            }
        }
    });
    let (_p, fe) = one_backend(be, "");
    let mut c = Client::connect(fe);
    c.send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(c.closed_within(Duration::from_secs(2)), "the client connection stayed open");
    let got = String::from_utf8_lossy(&c.buf).into_owned();
    assert!(got.starts_with("HTTP/1.1 200"), "{got:?}");
    assert!(got.ends_with("\r\n\r\npartial"), "{got:?}");
}

/// A request answered before its body, from a client that asked `Expect: 100-continue`.
/// Ibex closed the connection after the reply, on the reasoning that such a client will
/// not send a body it was not invited to. `HAProxy` 3.5 keeps it: 403, the connection
/// still open three seconds later, and when the body does come, followed by a request,
/// the body is drained and the request answered.
#[test]
fn a_reply_to_an_expect_100_continue_request_keeps_the_connection() {
    let (_p, fe, seen) = simple(echo, "  http-request deny if { path /local }\n");
    let mut c = Client::connect(fe);
    c.send(b"POST /local HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\nExpect: 100-continue\r\n\r\n");
    assert_eq!(c.final_response().map(|r| r.status), Some(403));
    assert!(!c.closed_within(Duration::from_secs(1)), "the client connection was closed");
    c.send(b"0123456789GET /g HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(c.final_response().map(|r| r.body_str()).as_deref(), Some("GET /g 0"));
    assert_eq!(seen.lock().unwrap().len(), 1, "{:?}", seen.lock().unwrap());
}

/// A header line with no colon. `HAProxy` 3.5: 400, then close.
#[test]
fn a_header_line_without_a_colon_gets_a_400() {
    let (_p, fe, seen) = simple(echo, "");
    let mut c = Client::connect(fe);
    c.send(b"GET / HTTP/1.1\r\nHost: x\r\nNoColonHere\r\n\r\n");
    assert_eq!(c.final_response().map(|r| r.status), Some(400));
    assert!(c.closed_within(Duration::from_secs(1)));
    assert!(seen.lock().unwrap().is_empty());
}

/// A client that stops halfway through its request head, past `timeout client`. `HAProxy`
/// 3.5: 408, then close.
#[test]
fn a_client_silent_in_the_middle_of_a_head_gets_a_408() {
    let (_p, fe) = start(
        "frontend fe\n  bind @FE@\n  timeout client 300ms\n  default_backend be\nbackend be\n",
        &[],
    );
    let mut c = Client::connect(fe);
    c.send(b"GET / HTTP/1.1\r\nHost");
    assert_eq!(c.final_response().map(|r| r.status), Some(408));
    assert!(c.closed_within(Duration::from_secs(1)));
}

/// A connection that sends nothing at all past `timeout client` is answered the same way:
/// `h1_handle_req_tout` (`src/mux_h1.c`) closes silently only for an idle keep-alive
/// connection or under `option http-ignore-probes`. `HAProxy` 3.5: 408, then close.
#[test]
fn a_connection_that_never_sends_a_request_gets_a_408() {
    let (_p, fe) = start(
        "frontend fe\n  bind @FE@\n  timeout client 300ms\n  default_backend be\nbackend be\n",
        &[],
    );
    let mut c = Client::connect(fe);
    assert_eq!(c.final_response().map(|r| r.status), Some(408));
    assert!(c.closed_within(Duration::from_secs(1)));
}

/// Between keep-alive requests, the same timeout closes the connection with nothing sent.
/// `HAProxy` 3.5: the 200, then a close and no 408.
#[test]
fn an_idle_keep_alive_connection_closes_without_a_408() {
    let (_p, fe) = start(
        "frontend fe\n  bind @FE@\n  timeout client 300ms\n  http-request return status 200\n",
        &[],
    );
    let mut c = Client::connect(fe);
    assert_eq!(c.get("/").map(|r| r.status), Some(200));
    assert!(c.closed_within(Duration::from_secs(2)), "the idle connection stayed open");
    assert!(c.buf.is_empty(), "sent after the response: {:?}", String::from_utf8_lossy(&c.buf));
}

/// `timeout client` shorter than the server takes to answer: once the request is all in,
/// the wait is the server's, and the client timer does not end it. `HAProxy` 3.5: 200.
#[test]
fn timeout_client_does_not_cut_off_a_slow_server() {
    fn slow(r: &Seen) -> Reply {
        let body = format!("GET {} 0", r.path);
        Reply {
            parts: vec![
                b"HTTP/1.1 200 OK\r\n".to_vec(),
                format!("Content-Length: {}\r\n\r\n{body}", body.len()).into_bytes(),
            ],
            gap: Duration::from_millis(700),
            close: false,
        }
    }
    let (be, _) = backend(slow);
    let (_p, fe) = start(
        "frontend fe\n  bind @FE@\n  timeout client 250ms\n  default_backend be\n\
         backend be\n  server s1 @BE0@\n",
        &[be],
    );
    let mut c = Client::connect(fe);
    assert_eq!(c.get("/slow").map(|r| r.body_str()).as_deref(), Some("GET /slow 0"));
}

// ---- the Connection header on HTTP/1.0 requests (T430 row 2) -----------------------

/// What the server is sent in `Connection`, what the client is answered with, and whether the
/// client connection is closed, for an HTTP/1.0 POST in each mode. An HTTP/1.0 request with
/// `Transfer-Encoding: chunked` gets no `Connection` token to the server (`keep-alive` would
/// be wrong: its message ends with the connection) and its client connection closes whatever
/// the client asked for (`option httpclose` in the frontend alone leaves the server side as the
/// default mode has it). Measured on HAProxy 3.5-dev8 (`/home/bhenc/reference/haproxy`),
/// 2026-10-18; run with `IBEX_TXN_BIN` set to it to re-measure.
#[test]
fn http10_connection_header_by_framing_and_mode() {
    // (framing, client Connection, server Connection, client answer Connection, closed)
    type Case = (&'static str, &'static str, &'static str, &'static str, bool);
    const DEFAULT: &[Case] = &[
        ("none", "", "keep-alive", "close", true),
        ("none", "keep-alive", "keep-alive", "keep-alive", false),
        ("none", "close", "keep-alive", "close", true),
        ("cl", "", "keep-alive", "close", true),
        ("cl", "keep-alive", "keep-alive", "keep-alive", false),
        ("cl", "close", "keep-alive", "close", true),
        ("te", "", "", "close", true),
        ("te", "keep-alive", "", "close", true),
        ("te", "close", "", "close", true),
    ];
    const SERVER_CLOSE: &[Case] = &[
        ("none", "", "", "close", true),
        ("none", "keep-alive", "", "keep-alive", false),
        ("none", "close", "", "close", true),
        ("cl", "", "", "close", true),
        ("cl", "keep-alive", "", "keep-alive", false),
        ("cl", "close", "", "close", true),
        ("te", "", "", "close", true),
        ("te", "keep-alive", "", "close", true),
        ("te", "close", "", "close", true),
    ];
    const HTTPCLOSE: &[Case] = &[
        ("none", "", "keep-alive", "close", true),
        ("none", "keep-alive", "keep-alive", "close", true),
        ("none", "close", "keep-alive", "close", true),
        ("cl", "", "keep-alive", "close", true),
        ("cl", "keep-alive", "keep-alive", "close", true),
        ("cl", "close", "keep-alive", "close", true),
        ("te", "", "", "close", true),
        ("te", "keep-alive", "", "close", true),
        ("te", "close", "", "close", true),
    ];
    let mut bad = Vec::new();
    for (mode, cases) in [("", DEFAULT), ("  option http-server-close\n", SERVER_CLOSE), ("  option httpclose\n", HTTPCLOSE)] {
        let (_p, fe, seen) = simple(|r| Reply::ok(&r.path), mode);
        for (i, (framing, conn, want_srv, want_rsp, want_closed)) in cases.iter().enumerate() {
            let conn_line = if conn.is_empty() { String::new() } else { format!("Connection: {conn}\r\n") };
            let (fr, body) = match *framing {
                "cl" => ("Content-Length: 5\r\n\r\n", "hello"),
                "te" => ("Transfer-Encoding: chunked\r\n\r\n", "5\r\nhello\r\n0\r\n\r\n"),
                _ => ("\r\n", ""),
            };
            let mut c = Client::connect(fe);
            c.send(format!("POST /c{i} HTTP/1.0\r\nHost: x\r\n{conn_line}{fr}{body}").as_bytes());
            let r = c.final_response();
            let rsp = r.as_ref().and_then(|r| r.header("connection")).unwrap_or("");
            let closed = c.closed_within(Duration::from_millis(500));
            let head = seen.lock().unwrap().iter().find(|s| s.path == format!("/c{i}")).map(|s| s.head.to_ascii_lowercase());
            let srv = head.as_deref().and_then(|h| h.lines().find_map(|l| l.strip_prefix("connection:"))).map_or("", str::trim);
            if (srv, rsp, closed) != (*want_srv, *want_rsp, *want_closed) {
                bad.push(format!("mode {mode:?} {framing} conn={conn:?}: server {srv:?} answer {rsp:?} closed {closed} (want {want_srv:?} {want_rsp:?} {want_closed})"));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

// ---- the Connection header on replies to a request that cannot be parsed (T430 row 3) --

/// `HAProxy` sends the page for a request it cannot parse as it is and closes: the built-in
/// 400 and 408 pages carry `Connection: close` themselves, the 413, 414, 422 and 431 ones do
/// not, and nothing is added (not even to an `errorfile` without it). Measured on 3.5-dev8
/// (`/home/bhenc/reference/haproxy`), 2026-10-18; every one of them closes the connection.
#[test]
fn a_parse_error_reply_has_no_connection_header_but_the_pages() {
    let long_uri = format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "a".repeat(20000));
    let big_head = format!("GET / HTTP/1.1\r\nHost: x\r\nX: {}\r\n\r\n", "a".repeat(20000));
    let cases: [(&str, &[u8], u16, bool); 6] = [
        ("bad header", b"GET / HTTP/1.1\r\nBad\r\n\r\n", 400, true),
        ("1.0 chunked GET", b"GET / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 413, false),
        ("uri too long", long_uri.as_bytes(), 414, false),
        ("unknown coding", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n", 422, false),
        ("head too big", big_head.as_bytes(), 431, false),
        ("incomplete head", b"GET / HTTP/1.1\r\nHost: x\r\n", 408, true),
    ];
    let mut bad = Vec::new();
    let (_p, fe, _) = simple(echo, "  timeout http-request 1s\n");
    for (name, req, status, page_has_close) in cases {
        let mut c = Client::connect(fe);
        c.send(req);
        let r = c.final_response();
        let got = r.as_ref().map(|r| (r.status, r.header("connection").is_some()));
        let closed = c.closed_within(Duration::from_secs(1));
        if got != Some((status, page_has_close)) || !closed {
            bad.push(format!("{name}: {got:?} closed {closed}, want {:?}", Some((status, page_has_close))));
        }
    }
    // A custom page is sent as written.
    let mut page = NamedTempFile::new().expect("errorfile");
    page.write_all(b"HTTP/1.0 400 Bad request\r\nContent-Length: 3\r\nContent-Type: text/plain\r\n\r\nbad").unwrap();
    let (_p2, fe2, _) = simple(echo, &format!("  errorfile 400 {}\n", page.path().display()));
    let mut c = Client::connect(fe2);
    c.send(b"GET / HTTP/1.1\r\nBad\r\n\r\n");
    let r = c.final_response();
    let got = r.as_ref().map(|r| (r.status, r.header("connection").is_some()));
    if got != Some((400, false)) || !c.closed_within(Duration::from_secs(1)) {
        bad.push(format!("errorfile 400: {got:?}, want (400, false) then closed"));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
