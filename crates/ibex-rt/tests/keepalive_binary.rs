// SPDX-License-Identifier: GPL-2.0-or-later
//! Client keep-alive against the real binary, three requests down one connection, measured
//! against `HAProxy` 3.5 with the same configuration (3 of 3 in both cases below).
//!
//! The in-process tests in `client_keepalive.rs` passed while the binary failed both of
//! these, so these drive `CARGO_BIN_EXE_ibex` over real sockets.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// How the backend ends each response.
#[derive(Clone, Copy)]
enum Backend {
    /// Keeps the connection and answers every request on it.
    KeepAlive,
    /// Answers one request with a complete `Content-Length` response and closes -- no
    /// `Connection: close` header, as an HTTP/1.0-style server does.
    CloseAfterResponse,
}

fn backend(kind: Backend) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0
                        || s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err()
                    {
                        break;
                    }
                    if matches!(kind, Backend::CloseAfterResponse) {
                        break;
                    }
                }
            });
        }
    });
    addr
}

struct Ibex(Child, NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        stop(&mut self.0);
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

fn start(be: SocketAddr, frontend_extra: &str) -> (Ibex, SocketAddr) {
    let fe = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let mut f = NamedTempFile::new().expect("tmp");
    write!(
        f,
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n{frontend_extra}  default_backend be\n\
         backend be\n  server s1 {be}\n"
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
        thread::sleep(Duration::from_millis(20));
    }
    (Ibex(child, f), fe)
}

/// Sends three requests down one connection; returns each complete response, stopping at
/// the first that does not arrive.
fn three_requests(fe: SocketAddr) -> Vec<String> {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut out = Vec::new();
    for i in 0..3 {
        if c.write_all(format!("GET /{i} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).is_err() {
            break;
        }
        let mut resp = Vec::new();
        let mut buf = [0u8; 4096];
        while !resp.ends_with(b"ok") {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => resp.extend_from_slice(&buf[..n]),
            }
        }
        if !resp.ends_with(b"ok") {
            break;
        }
        out.push(String::from_utf8_lossy(&resp).into_owned());
    }
    out
}

fn has_header(resp: &str, name: &str) -> bool {
    resp.split("\r\n")
        .any(|l| l.split_once(':').is_some_and(|(k, _)| k.eq_ignore_ascii_case(name)))
}

/// `http-response` rules apply to every response, not only the first. Ibex applied them
/// to the first and relayed the rest raw: after the first response the server side was
/// left `Established`, and both places that run response rules wait for `Ready`.
#[test]
fn response_rules_apply_to_every_response_on_a_kept_backend_connection() {
    let (_ibex, fe) = start(backend(Backend::KeepAlive), "  http-response set-header X-Seen yes\n");
    let responses = three_requests(fe);
    assert_eq!(responses.len(), 3, "responses: {responses:?}");
    for (i, r) in responses.iter().enumerate() {
        assert!(has_header(r, "X-Seen"), "response {i} skipped the http-response rule: {r:?}");
    }
}

/// A backend that closes after a complete, length-delimited response has finished that
/// response; the client connection stays open and the next request gets a new backend
/// connection. Ibex closed the client connection too.
#[test]
fn a_backend_closing_after_a_complete_response_does_not_close_the_client() {
    let (_ibex, fe) = start(backend(Backend::CloseAfterResponse), "");
    let responses = three_requests(fe);
    assert_eq!(responses.len(), 3, "responses: {responses:?}");
    for (i, r) in responses.iter().enumerate() {
        assert!(!r.to_ascii_lowercase().contains("connection: close"), "response {i}: {r:?}");
    }
}

/// The guard on the change above: a response with no length is delimited by the server's
/// close, so that close must reach the client -- it is the only way the client can know
/// the body ended. HAProxy does the same.
#[test]
fn a_close_delimited_response_still_closes_the_client() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let be = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\nbody until close");
        }
    });
    let (_ibex, fe) = start(be, "");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut resp = Vec::new();
    let closed = loop {
        let mut buf = [0u8; 4096];
        match c.read(&mut buf) {
            Ok(0) => break true,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
            Err(_) => break false,
        }
    };
    let resp = String::from_utf8_lossy(&resp);
    assert!(resp.ends_with("body until close"), "{resp:?}");
    assert!(closed, "the client never saw the close that ends the body: {resp:?}");
}

/// Reads until `quiet` passes with nothing arriving, the peer closes, or two seconds pass.
fn read_for(c: &mut TcpStream, quiet: Duration) -> String {
    c.set_read_timeout(Some(quiet)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&resp).into_owned()
}

/// A 503 the proxy generates itself (no server to send the request to) answers the request
/// once, and the connection stays usable -- `HAProxy` 3.5 answers one 503 per request, three
/// requests in a row on one connection. Ibex answered the first request five times: the
/// request that caused the 503 was never forwarded, so it was still in the buffer when the
/// transaction ended, and the session ran it again.
#[test]
fn a_generated_503_answers_its_request_once_and_keeps_the_connection() {
    let fe = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let mut f = NamedTempFile::new().expect("tmp");
    write!(
        f,
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n  default_backend be\nbackend be\n"
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let _ibex = Ibex(child, f);
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
        thread::sleep(Duration::from_millis(20));
    }

    let mut c = TcpStream::connect(fe).expect("connect");
    for i in 0..3 {
        c.write_all(format!("GET /{i} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).unwrap();
        let got = read_for(&mut c, Duration::from_millis(500));
        assert_eq!(got.matches("HTTP/1.1 503").count(), 1, "request {i}: {got:?}");
    }
}
