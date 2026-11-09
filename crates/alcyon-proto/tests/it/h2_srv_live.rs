// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T537: the h1↔h2 server codec (`alcyon_proto::h2_srv`) driven over TCP against real h2c
//! servers: nghttpd (`--no-tls`, `--echo-upload`, `--trailer`) and HAProxy 3.5-dev8 as the
//! server (`bind … proto h2`), the oracle for GOAWAY after `tune.h2.fe.max-total-streams 3`
//! and for a stream it resets. Skipped, with a line on stderr, when the binary is missing.
//!
//! What the session will do in slice B-H2 is played here by [`Conn::exchange`]: write the
//! HTTP/1.1 request into the codec, the codec's frames to the socket, the socket's bytes into
//! the codec, and take the HTTP/1.1 response text out.

#![allow(clippy::doc_markdown, clippy::many_single_char_names, clippy::type_complexity, clippy::disallowed_macros)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use alcyon_proto::h2_srv::{H2SrvCodec, SrvH2Error};

struct Server {
    child: Child,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn wait_listening(port: u16) {
    let end = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < end, "server on {port} not listening");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn have(bin: &str) -> bool {
    Command::new(bin).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok()
}

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("alcyon-h2srv-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// nghttpd h2c on a docroot holding `index.html` (`hello h2\n`); `args` added. Its frame log
/// (`-v`) goes to `<dir>/nghttpd.log`.
fn nghttpd(tag: &str, args: &[&str]) -> Option<(Server, std::path::PathBuf)> {
    if !have("nghttpd") {
        eprintln!("nghttpd not on this host; skipping");
        return None;
    }
    let d = dir(tag);
    std::fs::write(d.join("index.html"), b"hello h2\n").unwrap();
    let port = free_port();
    let log = std::fs::File::create(d.join("nghttpd.log")).unwrap();
    let child = Command::new("nghttpd")
        .args(["--no-tls", "-v", "-d"])
        .arg(&d)
        .args(args)
        .arg(port.to_string())
        .stdout(log)
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_listening(port);
    Some((Server { child, port }, d))
}

/// HAProxy as an h2c server: at most 3 streams a connection, `/rej` rejected (RST_STREAM),
/// any other path answered `ver=<version> path=<path>`.
fn haproxy_server(tag: &str) -> Option<Server> {
    let oracle = crate::reference::reference("haproxy/haproxy")?;
    let d = dir(tag);
    let port = free_port();
    let cfg = format!(
        "global\n    tune.h2.fe.max-total-streams 3\ndefaults\n    mode http\n    timeout connect 5s\n    timeout client 10s\n    timeout server 10s\n\
         frontend f\n    bind 127.0.0.1:{port} proto h2\n    http-request reject if {{ path_beg /rej }}\n\
         \x20   http-request return status 200 content-type text/plain lf-string \"ver=%[req.ver] path=%[path]\"\n"
    );
    std::fs::write(d.join("s.cfg"), cfg).unwrap();
    let child = Command::new(oracle).arg("-f").arg(d.join("s.cfg")).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    wait_listening(port);
    Some(Server { child, port })
}

struct Conn {
    s: TcpStream,
    c: H2SrvCodec,
}

impl Conn {
    fn open(port: u16) -> Conn {
        let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        Conn { s, c: H2SrvCodec::new() }
    }

    fn flush(&mut self) {
        let n = self.c.output().len();
        if n > 0 {
            self.s.write_all(self.c.output()).unwrap();
            self.c.advance_output(n);
        }
    }

    /// Reads until the server closes (or 2 s), into the codec.
    fn drain(&mut self) {
        let mut buf = vec![0u8; 16384];
        let end = Instant::now() + Duration::from_secs(2);
        let _ = self.c.receive(&[]);
        while Instant::now() < end {
            match self.s.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => {
                    let _ = self.c.receive(&buf[..n]);
                }
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(_) => return,
            }
        }
    }

    /// One request, its response text, as the session would see them.
    fn exchange(&mut self, req: &[u8]) -> Result<Vec<u8>, SrvH2Error> {
        let mut sent = 0;
        let mut rsp = Vec::new();
        let mut buf = vec![0u8; 16384];
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if sent < req.len() {
                sent += self.c.send_request(&req[sent..])?;
            }
            self.flush();
            if sent == req.len() && self.c.response_complete() {
                return Ok(rsp);
            }
            assert!(Instant::now() < end, "no response; so far {:?}", String::from_utf8_lossy(&rsp));
            match self.s.read(&mut buf) {
                Ok(0) => {
                    rsp.extend_from_slice(self.c.response());
                    return if self.c.response_complete() { Ok(rsp) } else { Err(SrvH2Error::Connection(0)) };
                }
                Ok(n) => {
                    let r = self.c.receive(&buf[..n]);
                    rsp.extend_from_slice(self.c.response());
                    let taken = self.c.response().len();
                    self.c.advance_response(taken);
                    self.flush();
                    r?;
                }
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(e) => panic!("read: {e}"),
            }
        }
    }
}

fn body_of(rsp: &[u8]) -> &[u8] {
    let i = memchr_find(rsp, b"\r\n\r\n").unwrap();
    &rsp[i + 4..]
}

fn memchr_find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Decodes a chunked body (the h1 view of a response without content-length).
fn dechunk(mut b: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut out = Vec::new();
    loop {
        let e = memchr_find(b, b"\r\n").unwrap();
        let n = usize::from_str_radix(std::str::from_utf8(&b[..e]).unwrap(), 16).unwrap();
        b = &b[e + 2..];
        if n == 0 {
            return (out, b.to_vec());
        }
        out.extend_from_slice(&b[..n]);
        b = &b[n + 2..];
    }
}

#[test]
fn get_and_head_against_nghttpd() {
    let Some((srv, _d)) = nghttpd("gethead", &[]) else { return };
    let mut c = Conn::open(srv.port);
    let r = c.exchange(b"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
    let t = String::from_utf8_lossy(&r);
    assert!(t.starts_with("HTTP/1.1 200 OK\r\n"), "{t}");
    assert!(t.contains("content-length: 9\r\n"), "{t}");
    assert_eq!(body_of(&r), b"hello h2\n");
    // The same connection, stream 3.
    let r = c.exchange(b"HEAD /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
    let t = String::from_utf8_lossy(&r);
    assert!(t.starts_with("HTTP/1.1 200 OK\r\n") && t.contains("content-length: 9\r\n") && t.ends_with("\r\n\r\n"), "{t}");
    assert_eq!(c.c.streams(), 2);
    assert!(c.c.reusable());
    let r = c.exchange(b"GET /nothing HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
    assert!(r.starts_with(b"HTTP/1.1 404 Not Found\r\n"), "{}", String::from_utf8_lossy(&r));
}

#[test]
fn post_of_100k_over_the_window_is_echoed_whole() {
    let Some((srv, _d)) = nghttpd("post", &["--echo-upload"]) else { return };
    let body: Vec<u8> = (0..100_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let mut req = format!("POST /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    req.extend_from_slice(&body);
    let mut c = Conn::open(srv.port);
    let r = c.exchange(&req).unwrap();
    let t = String::from_utf8_lossy(&r[..r.len().min(200)]).to_string();
    assert!(t.starts_with("HTTP/1.1 200 OK\r\n"), "{t}");
    let got = if t.contains("transfer-encoding: chunked") { dechunk(body_of(&r)).0 } else { body_of(&r).to_vec() };
    assert_eq!(got.len(), body.len());
    assert!(got == body, "echoed body differs");
}

#[test]
fn chunked_post_with_trailers_reaches_nghttpd_as_data_and_trailing_headers() {
    let Some((srv, d)) = nghttpd("chunked", &["--echo-upload"]) else { return };
    let mut c = Conn::open(srv.port);
    let req = b"POST /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\nTE: trailers\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\nx-rt: 9\r\n\r\n";
    let r = c.exchange(req).unwrap();
    let got = if r.windows(26).any(|w| w == b"transfer-encoding: chunked") { dechunk(body_of(&r)).0 } else { body_of(&r).to_vec() };
    assert_eq!(got, b"abcde");
    // A chunked body without trailers ends on an empty DATA frame with END_STREAM.
    let r = c.exchange(b"POST /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwxyz\r\n0\r\n\r\n").unwrap();
    assert!(r.windows(4).any(|w| w == b"wxyz"), "{}", String::from_utf8_lossy(&r));
    drop(srv);
    let log = std::fs::read_to_string(d.join("nghttpd.log")).unwrap();
    // nghttpd -v: the trailer field, then the HEADERS frame it came in (END_STREAM).
    let t = log.find("recv (stream_id=1) x-rt: 9").expect("trailer in nghttpd's log");
    assert!(log[t..].contains("recv HEADERS frame <length=8, flags=0x05, stream_id=1>"), "{log}");
    assert!(log.contains("recv DATA frame <length=0, flags=0x01, stream_id=3>"), "{log}");
}

#[test]
fn response_trailers_pass_on_a_chunked_body_and_are_dropped_after_a_content_length_one() {
    let Some((srv, _d)) = nghttpd("trailers", &["--echo-upload", "--trailer", "grpc-status: 0"]) else { return };
    let mut c = Conn::open(srv.port);
    // A file: content-length; HAProxy's h1 side drops the trailers then (measured).
    let r = c.exchange(b"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\nTE: trailers\r\n\r\n").unwrap();
    let t = String::from_utf8_lossy(&r);
    assert!(t.contains("content-length: 9\r\n") && t.ends_with("hello h2\n") && !t.contains("grpc-status: 0"), "{t}");
    // An echo has no content-length: chunked, trailers in the last chunk.
    let r = c.exchange(b"POST /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\nTE: trailers\r\nContent-Length: 2\r\n\r\nhi").unwrap();
    let t = String::from_utf8_lossy(&r);
    if t.contains("transfer-encoding: chunked") {
        let (b, trl) = dechunk(body_of(&r));
        assert_eq!(b, b"hi");
        assert_eq!(trl, b"grpc-status: 0\r\n\r\n", "{t}");
    } else {
        assert!(!t.contains("grpc-status: 0"), "{t}");
    }
}

#[test]
fn haproxy_server_goaway_after_three_streams_gives_3_3_1() {
    let Some(srv) = haproxy_server("goaway") else { return };
    let mut per_conn = Vec::new();
    let mut c = Conn::open(srv.port);
    let mut n = 0;
    for i in 0..7 {
        if !c.c.reusable() {
            per_conn.push(n);
            n = 0;
            c = Conn::open(srv.port);
        }
        let r = c.exchange(format!("GET /r{i} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes()).unwrap();
        let t = String::from_utf8_lossy(&r);
        assert!(t.starts_with("HTTP/1.1 200 OK\r\n") && t.ends_with(&format!("ver=2.0 path=/r{i}")), "{t}");
        n += 1;
    }
    per_conn.push(n);
    assert_eq!(per_conn, vec![3, 3, 1], "HAProxy (T535 C2): 3 3 1");
}

#[test]
fn haproxy_server_reset_is_a_reset_before_the_head_and_the_connection_goes_on() {
    let Some(srv) = haproxy_server("reset") else { return };
    let mut c = Conn::open(srv.port);
    let r = c.exchange(b"GET /rej HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    // HAProxy writes RST_STREAM ENHANCE_YOUR_CALM, then GOAWAY (last stream 1, the same
    // code) and closes (captured): a reset before the head (502 SH-- in HAProxy's log as the
    // client's proxy), and the connection is not used again.
    assert_eq!(r, Err(SrvH2Error::Reset { code: 0xb, after_head: false }));
    c.drain();
    assert!(!c.c.reusable());
    let mut c = Conn::open(srv.port);
    let r = c.exchange(b"GET /ok HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
    assert!(r.ends_with(b"ver=2.0 path=/ok"), "{}", String::from_utf8_lossy(&r));
}
