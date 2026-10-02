// SPDX-License-Identifier: GPL-2.0-or-later
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

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
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
    Some(Seen { method, path, body, conn })
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
fn frontend_addr() -> SocketAddr {
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let base = u16::try_from(std::process::id() % 1000).unwrap_or(0) * 10;
    loop {
        let port = 20000 + (base + NEXT.fetch_add(1, Ordering::Relaxed)) % 10000;
        if let Ok(l) = TcpListener::bind(("127.0.0.1", port)) {
            return l.local_addr().unwrap();
        }
    }
}

fn start(cfg: &str, backends: &[SocketAddr]) -> (Proxy, SocketAddr) {
    let fe = frontend_addr();
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
/// (RFC 9110 section 15.2). Not measurable against the oracle: `HAProxy` 3.5-dev7 aborts
/// on it, `FATAL: bug condition "htx_msg_ended(htx) && type != HTX_BLK_RAW_DATA" matched
/// at src/htx.c:391`, from `h1_parse_msg_hdrs`. The split-packet case below is measured.
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
