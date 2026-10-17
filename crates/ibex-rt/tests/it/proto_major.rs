// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T326: `req_proto_http`, `fc_http_major` and `bc_http_major`, against `HAProxy` 3.5-dev8.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Ibex(Child, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Starts ibex on `cfg` (`{sock}` is replaced by the stats socket path), waits for `addrs` and the
/// socket, then lets the readiness probes slide out of the one-second windows and clears the maxima.
fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> (Ibex, String) {
    let dir = std::env::temp_dir().join(format!("qh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg.replace("{sock}", &sock).replace("{dir}", &dir.display().to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let ibex = Ibex(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "ibex did not listen on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(2200));
    cli(&sock, "clear counters");
    (ibex, sock)
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// One request on a new connection; the whole raw answer.
fn get(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

/// A server on a free port that reads each request head, answers `resp` and closes the connection.
fn backend(resp: &'static [u8]) -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
            let (mut head, mut b) = (Vec::new(), [0u8; 4096]);
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&b[..n]),
                }
            }
            let _ = c.write_all(resp);
        }
    });
    addr
}

/// The value of the `x-out` header in the answer to `req`.
fn xout(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    let head = s.split("\r\n\r\n").next().unwrap_or("");
    head.lines()
        .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("x-out")).map(|(_, v)| v.trim().to_string()))
        .unwrap_or_else(|| panic!("no x-out header in the answer: {s:?}"))
}

fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame payload fits in 24 bits");
    let mut v = len.to_be_bytes()[1..].to_vec();
    v.extend_from_slice(&[ftype, flags]);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// One GET / over cleartext HTTP/2 with prior knowledge: the body of the answer on stream 1.
fn h2c_body(addr: SocketAddr) -> String {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
    s.write_all(&frame(0x04, 0, 0, &[])).unwrap();
    // :method GET, :scheme http, :path /, :authority a
    s.write_all(&frame(0x01, 0x05, 1, &[0x82, 0x86, 0x84, 0x01, 0x01, b'a'])).unwrap();
    let (mut buf, mut tmp, mut out) = (Vec::new(), [0u8; 4096], Vec::new());
    loop {
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let (ty, flags, id) = (buf[3], buf[4], u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]));
            if id == 1 && ty == 0x00 {
                out.extend_from_slice(&buf[9..9 + len]);
            }
            buf.drain(..9 + len);
            if id == 1 && (ty == 0x00 || ty == 0x01) && flags & 1 != 0 {
                return String::from_utf8_lossy(&out).into_owned();
            }
        }
        let n = s.read(&mut tmp).expect("h2 answer");
        assert!(n > 0, "closed before the answer ended");
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// `ibex -c` on `rule` in a frontend in front of one server: the exit status and stderr.
fn check(rule: &str) -> (bool, String) {
    let dir = std::env::temp_dir().join(format!("qh-proto-major-check-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(
        &path,
        format!("defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\nfrontend fe\n  bind 127.0.0.1:0\n  {rule}\n  default_backend b\nbackend b\n  server s 127.0.0.1:9\n"),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn proto_major_fetches() {
    const RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let be = backend(RESP);
    let (a, loc, h2, tcp1, tcp2) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "global\n  stats socket {{sock}} level admin\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {a}\n  tcp-request connection reject if {{ fc_http_major -m found }}\n  http-request set-var(txn.p) req_proto_http\n  http-request set-var(txn.m) fc_http_major\n  default_backend b\n  http-response set-header x-out [%[var(txn.p)]|%[var(txn.m)]|%[bc_http_major]|%[var(sess.c)]]\n\
         frontend loc\n  bind {loc}\n  http-request return status 200 content-type text/plain lf-string \"[%[fc_http_major]]\"\n  http-after-response set-header x-out [%[bc_http_major]]\n\
         frontend h2\n  bind {h2} proto h2\n  tcp-request session set-var(sess.s) fc_http_major\n  http-request return status 200 content-type text/plain lf-string \"[%[req_proto_http]|%[fc_http_major]|%[var(sess.s)]]\"\n\
         frontend tcp1\n  mode tcp\n  bind {tcp1}\n  tcp-request inspect-delay 1s\n  tcp-request content reject if {{ fc_http_major 1 }}\n  default_backend tb\n\
         frontend tcp2\n  mode tcp\n  bind {tcp2}\n  tcp-request inspect-delay 1s\n  tcp-request content reject if !{{ req_proto_http }}\n  default_backend tb\n\
         backend b\n  server s {be}\nbackend tb\n  mode tcp\n  server s {be}\n"
    );
    let (_ibex, _sock) = start("proto_major", &cfg, &[a, loc, h2, tcp1, tcp2]);
    // HTTP/1: fc_http_major is 1 once the mux is up, nothing before it (the tcp-request
    // connection rule does not reject).
    assert_eq!(xout(a, b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"), "[1|1|1|]");
    assert_eq!(xout(a, b"GET / HTTP/1.0\r\nHost: a\r\nConnection: close\r\n\r\n"), "[1|1|1|]");
    // No server connection: no bc_http_major.
    let r = String::from_utf8_lossy(&get(loc, b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")).into_owned();
    assert!(r.ends_with("\r\n\r\n[1]"), "{r:?}");
    assert_eq!(xout(loc, b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"), "[]");
    // Cleartext HTTP/2 with prior knowledge: the H2 mux, so 2 (nothing at tcp-request session).
    assert_eq!(h2c_body(h2), "[1|2|]");
    // TCP mode: a raw mux, so no fc_http_major and the GET goes through.
    let r = get(tcp1, b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    assert!(r.starts_with(b"HTTP/1.1 200 OK"), "{:?}", String::from_utf8_lossy(&r));
    // TCP mode: garbage is not HTTP, so `reject if !{ req_proto_http }` closes it unanswered.
    let r = get(tcp2, b"garbage\r\n\r\n");
    assert!(r.is_empty(), "{:?}", String::from_utf8_lossy(&r));
}

#[test]
fn bc_http_major_is_refused_before_the_server_connection() {
    let (ok, err) = check("http-request set-var(txn.b) bc_http_major");
    assert!(!ok);
    assert!(err.contains("error detected in frontend 'fe' while parsing 'http-request set-var(txn.b)' rule : fetch method 'set-var(txn.b)' extracts information from 'server address', none of which is available here."), "{err}");
    let (ok, err) = check("http-request set-header x %[bc_http_major]");
    assert!(!ok);
    assert!(err.contains("sample fetch <bc_http_major> may not be reliably used here because it needs 'server address' which is not available here."), "{err}");
    let (ok, err) = check("tcp-request content set-var(txn.b) bc_http_major");
    assert!(!ok);
    assert!(err.contains("fetch method 'set-var(txn.b)' extracts information from 'server address', none of which is available here"), "{err}");
    for rule in ["http-response set-var(txn.b) bc_http_major", "http-after-response set-header x %[bc_http_major]", "tcp-request connection reject if { fc_http_major -m found }"] {
        let (ok, err) = check(rule);
        assert!(ok, "{rule}: {err}");
    }
}
