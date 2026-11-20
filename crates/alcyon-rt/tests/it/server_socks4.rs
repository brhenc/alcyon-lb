// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The `socks4` and `check-via-socks4` server keywords: the connection to the server goes
//! to the SOCKS4 proxy instead, sends the 16-byte SOCKS4 CONNECT request for the server's
//! address (version 0x04, command 0x01, the address in network byte order, user id
//! `HAProxy\0`), waits for the 8-byte reply and carries the traffic only once it says
//! 0x5A. A reply that says anything else (0x5B), or a short one, fails the connection,
//! named `SOCKS4_DENY` / `SOCKS4_RECV` by `bc_err`. With `check-via-socks4` the health
//! checks take the same tunnel; without it they go straight to the server.
//!
//! The reference is the reg-test `checks/tcp-checks-socks4.vtc` of `HAProxy` 3.5-dev11;
//! every expected value below was measured on it. Set
//! `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`: it passes all.

use crate::common;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

/// The SOCKS4 CONNECT request: the 16 bytes sent for `target` (user id `HAProxy\0`).
fn socks4_request(target: SocketAddr) -> [u8; 16] {
    let mut req = [0u8; 16];
    req[0] = 0x04;
    req[1] = 0x01;
    req[2..4].copy_from_slice(&target.port().to_be_bytes());
    if let SocketAddr::V4(v4) = target {
        req[4..8].copy_from_slice(&v4.ip().octets());
    }
    req[8..16].copy_from_slice(b"HAProxy\0");
    req
}

const SOCKS4_OK: [u8; 8] = [0x00, 0x5a, 0, 0, 0, 0, 0, 0];
const SOCKS4_DENY: [u8; 8] = [0x00, 0x5b, 0, 0, 0, 0, 0, 0];

/// What one socks4 proxy connection saw: the 16 request bytes, then the tunnel's bytes
/// in each direction (`to_target` what went to the server, `from_target` what came back).
#[derive(Debug)]
struct ProxyEvent {
    request: Vec<u8>,
    to_target: Vec<u8>,
    from_target: Vec<u8>,
}

/// The SOCKS4 proxy: it answers `reply` (or `short_reply`, then gives up) to the 16
/// request bytes, records what it saw, and, when `reply` grants (`0x5A`), pipes the
/// traffic to `target`.
fn socks4_proxy_with_count(
    target: SocketAddr,
    reply: [u8; 8],
    short_reply: Option<Vec<u8>>,
    events: Arc<Mutex<Vec<ProxyEvent>>>,
    attempts: Arc<AtomicUsize>,
) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind the socks4 proxy");
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let _ = s.set_read_timeout(Some(Duration::from_secs(8)));
            let events = Arc::clone(&events);
            let short_reply = short_reply.clone();
            let attempts = Arc::clone(&attempts);
            thread::spawn(move || {
                attempts.fetch_add(1, Ordering::Relaxed);
                let mut req = [0u8; 16];
                if s.read_exact(&mut req).is_err() {
                    return;
                }
                if let Some(short) = short_reply.as_ref() {
                    // A short reply (including empty 0-byte EOF): the proxy gives up after sending it.
                    let _ = s.write_all(short);
                    return;
                }
                if s.write_all(&reply).is_err() {
                    return;
                }
                if reply[1] != 0x5a {
                    return;
                }
                // The tunnel: pipe the bytes to the server the request named.
                let Ok(mut be) = TcpStream::connect(target) else { return };
                let _ = be.set_read_timeout(Some(Duration::from_secs(8)));
                let to_target = Arc::new(Mutex::new(Vec::new()));
                let to_target2 = Arc::clone(&to_target);
                let mut s2 = s.try_clone().unwrap();
                let mut be2 = be.try_clone().unwrap();
                let to_be = thread::spawn(move || {
                    let mut b = [0u8; 65536];
                    loop {
                        match s2.read(&mut b) {
                            Ok(0) => {
                                let _ = be2.shutdown(Shutdown::Write);
                                return;
                            }
                            Ok(n) => {
                                to_target2.lock().unwrap_or_else(|e| e.into_inner()).extend_from_slice(&b[..n]);
                                if be2.write_all(&b[..n]).is_err() {
                                    return;
                                }
                            }
                            Err(_) => return,
                        }
                    }
                });
                let mut from_target = Vec::new();
                let mut b = [0u8; 65536];
                loop {
                    match be.read(&mut b) {
                        Ok(0) => {
                            let _ = s.shutdown(Shutdown::Write);
                            break;
                        }
                        Ok(n) => {
                            from_target.extend_from_slice(&b[..n]);
                            if s.write_all(&b[..n]).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = s.flush();
                let _ = to_be.join();
                events.lock().unwrap_or_else(|e| e.into_inner()).push(ProxyEvent {
                    request: req.to_vec(),
                    to_target: to_target.lock().unwrap_or_else(|e| e.into_inner()).clone(),
                    from_target,
                });
            });
        }
    });
    addr
}

fn socks4_proxy(
    target: SocketAddr,
    reply: [u8; 8],
    short_reply: Option<Vec<u8>>,
    events: Arc<Mutex<Vec<ProxyEvent>>>,
) -> SocketAddr {
    socks4_proxy_with_count(target, reply, short_reply, events, Arc::new(AtomicUsize::new(0)))
}

/// Starts a raw config and collects UDP syslog lines sent to `{log_addr}`.
struct RawProxy {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for RawProxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn start_raw(cfg_text: &str, listen_addrs: &[SocketAddr]) -> RawProxy {
    let mut cfg = NamedTempFile::new().expect("tmp");
    cfg.write_all(cfg_text.as_bytes()).expect("write raw config");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(&bin)
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    for &a in listen_addrs {
        assert!(common::wait_listening(a), "the proxy never listened on {a}");
    }
    RawProxy { child, _cfg: cfg }
}

fn start_syslog() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind syslog");
    let addr = sock.local_addr().unwrap();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let out = Arc::clone(&lines);
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while let Ok((n, _)) = sock.recv_from(&mut buf) {
            out.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).into_owned());
        }
    });
    (addr, lines)
}

fn wait_log(lines: &Arc<Mutex<Vec<String>>>, needle: &str) -> String {
    for _ in 0..80 {
        if let Some(found) = lines.lock().unwrap().iter().find(|l| l.contains(needle)).cloned() {
            return found;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("syslog never saw {needle:?}; got: {:?}", *lines.lock().unwrap());
}

/// What the server saw: the request bytes and the number of accepted connections (the
/// health checks are plain TCP connections).
#[derive(Default)]
struct Seen {
    bytes: Vec<u8>,
    conns: u32,
}

/// The server behind the tunnel: it records what it received and answers any HTTP request
/// with a `200`, closing after.
fn backend(seen: Arc<Mutex<Seen>>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind the backend");
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let _ = s.set_read_timeout(Some(Duration::from_secs(8)));
            let seen = Arc::clone(&seen);
            thread::spawn(move || {
                seen.lock().unwrap().conns += 1;
                let mut buf = Vec::new();
                let mut b = [0u8; 65536];
                loop {
                    match s.read(&mut b) {
                        Ok(0) => return,
                        Err(_) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&b[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                seen.lock().unwrap().bytes.extend_from_slice(&buf);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
                let _ = s.flush();
            });
        }
    });
    addr
}

struct Proxy {
    child: Child,
    fe: SocketAddr,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// Starts the proxy under test (`T281_ORACLE`'s binary when set, the alcyon otherwise)
/// with a frontend on `fe` and `server line` in backend `b` toward the server on `be`.
/// `defaults_extra` holds the extra defaults lines (the `option httpchk` of the health
/// check tests, like the reg-test's).
fn start(server_line: &str, be: SocketAddr, fe: SocketAddr, defaults_extra: &str) -> Proxy {
    let mut cfg = NamedTempFile::new().expect("tmp");
    writeln!(
        cfg,
        "global\n  log stdout format raw local0\ndefaults\n  mode http\n  log global\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n  timeout http-request 5s\n{defaults_extra}\nfrontend f\n  bind {fe}\n  default_backend b\nbackend b\n  server s {be} {server_line}\n"
    )
    .expect("write the config");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(&bin).arg("-f").arg(cfg.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    assert!(common::wait_listening(fe), "the proxy never listened");
    Proxy { child, fe, _cfg: cfg }
}

/// Runs `bin -c` on the config and returns its exit status: the load of the server line.
fn config_check(server_line: &str, be: SocketAddr) -> Option<std::process::ExitStatus> {
    let mut cfg = NamedTempFile::new().expect("tmp");
    writeln!(
        cfg,
        "global\n  log stdout format raw local0\ndefaults\n  mode http\n  log global\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n  timeout http-request 5s\nfrontend f\n  bind 127.0.0.1:1\n  default_backend b\nbackend b\n  server s {be} {server_line}\n"
    )
    .expect("write the config");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    Command::new(&bin).arg("-c").arg("-f").arg(cfg.path()).output().ok().map(|o| o.status)
}

/// One HTTP request through the proxy's frontend: what came back.
fn get(fe: SocketAddr) -> String {
    let mut c = TcpStream::connect(fe).expect("connect the frontend");
    let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    String::from_utf8_lossy(&got).into_owned()
}

/// The reg-test's line: the traffic and the checks both take the socks4 tunnel.
#[test]
fn the_server_line_loads() {
    let be = backend(Arc::new(Mutex::new(Seen::default())));
    let socks = socks4_proxy(be, SOCKS4_OK, None, Arc::new(Mutex::new(Vec::new())));
    let status = config_check(&format!("socks4 {socks} check-via-socks4 check inter 1s rise 1 fall 1"), be)
        .unwrap_or_else(|| panic!("no exit status for -c"));
    assert!(status.success(), "the socks4 server line must load: {status:?}");
}

/// A `socks4` line without an address is refused, like every server keyword with a missing
/// argument.
#[test]
fn a_missing_address_is_refused() {
    let be = backend(Arc::new(Mutex::new(Seen::default())));
    let status = config_check("socks4", be).unwrap_or_else(|| panic!("no exit status for -c"));
    assert!(!status.success(), "a socks4 line without its address must not load: {status:?}");
}

/// The traffic to the server goes through the socks4 proxy: the proxy sees the 16 request
/// bytes for the server's address and the request itself, and the client gets the
/// server's answer.
#[test]
fn the_traffic_goes_through_the_tunnel() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let be = backend(seen.clone());
    let events = Arc::new(Mutex::new(Vec::new()));
    let socks = socks4_proxy(be, SOCKS4_OK, None, events.clone());
    let fe = common::reserve_addr();
    let p = start(&format!("socks4 {socks}"), be, fe, "");
    let body = get(fe);
    assert!(body.starts_with("HTTP/1.1 200"), "the server's answer came back through the tunnel: {body:?}");
    assert!(body.contains("OK"), "the body: {body:?}");
    // The proxy saw the CONNECT request for the server's address, and the request. The
    // proxy records the tunnel once it closes, so poll for it.
    let (req, _to) = loop {
        let v = events.lock().unwrap();
        match v.iter().find(|e| e.to_target.windows(5).any(|w| w == b"GET /")) {
            Some(e) => break (e.request.clone(), e.to_target.clone()),
            None => {
                if v.len() > 3 {
                    panic!("the tunnel carried no request to the server: {:?}", *v);
                }
                drop(v);
                thread::sleep(Duration::from_millis(100));
            }
        }
    };
    assert_eq!(req, socks4_request(be), "the 16 request bytes name the server, not the proxy");
    // The server got the request through the tunnel.
    assert!(seen.lock().unwrap().bytes.windows(5).any(|w| w == b"GET /"), "the server saw the request");
    drop(p);
}

/// A refusal (0x5B) fails the connection as a connect failure: retried, 503 `SC`, and
/// `bc_err` reports `41 SOCKS4_DENY`.
#[test]
fn a_refused_tunnel_fails_the_stream() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let be = backend(seen.clone());
    let attempts = Arc::new(AtomicUsize::new(0));
    let socks = socks4_proxy_with_count(be, SOCKS4_DENY, None, Arc::new(Mutex::new(Vec::new())), attempts.clone());
    let fe = common::reserve_addr();
    let (log_addr, logs) = start_syslog();
    let cfg = format!(
        "global\n  log {log_addr} local0\ndefaults\n  mode http\n  log global\n  \
         log-format \"%ST %ts %rc %[bc_err] %[bc_err_name] %[bc_err_str]\"\n  \
         timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n  retries 2\n\
         frontend f\n  bind {fe}\n  default_backend b\n\
         backend b\n  server s {be} socks4 {socks}\n"
    );
    let _p = start_raw(&cfg, &[fe]);
    let body = get(fe);
    let code = body.get(9..12).unwrap_or("");
    assert_eq!(code, "503", "a refused tunnel is 503: {body:?}");
    assert_eq!(attempts.load(Ordering::Relaxed), 3, "retries 2 makes 3 SOCKS4 attempts");
    assert!(seen.lock().unwrap().bytes.is_empty(), "the server must not see the request when the proxy refuses");
    let line = wait_log(&logs, "SOCKS4_DENY");
    assert!(line.contains("503 SC 2 41 SOCKS4_DENY SOCKS4 Proxy deny the request"), "unexpected log: {line:?}");
}

/// An immediate EOF during the SOCKS4 reply fails with `503 SC` and `40 SOCKS4_RECV`, retried.
#[test]
fn an_eof_reply_fails_with_socks4_recv_and_retries() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let be = backend(seen.clone());
    let attempts = Arc::new(AtomicUsize::new(0));
    let socks = socks4_proxy_with_count(be, SOCKS4_OK, Some(Vec::new()), Arc::new(Mutex::new(Vec::new())), attempts.clone());
    let fe = common::reserve_addr();
    let (log_addr, logs) = start_syslog();
    let cfg = format!(
        "global\n  log {log_addr} local0\ndefaults\n  mode http\n  log global\n  \
         log-format \"%ST %ts %rc %[bc_err] %[bc_err_name] %[bc_err_str]\"\n  \
         timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n  retries 2\n\
         frontend f\n  bind {fe}\n  default_backend b\n\
         backend b\n  server s {be} socks4 {socks}\n"
    );
    let _p = start_raw(&cfg, &[fe]);
    let body = get(fe);
    assert_eq!(body.get(9..12).unwrap_or(""), "503", "an EOF reply is 503: {body:?}");
    assert_eq!(attempts.load(Ordering::Relaxed), 3, "retries 2 makes 3 SOCKS4 attempts");
    assert!(seen.lock().unwrap().bytes.is_empty());
    let line = wait_log(&logs, "SOCKS4_RECV");
    assert!(line.contains("503 SC 2 40 SOCKS4_RECV SOCKS4 Proxy read error during handshake"), "unexpected log: {line:?}");
}

/// A short reply (3 bytes, then the proxy gives up) times out waiting for the rest: `503 sC`.
#[test]
fn a_short_reply_fails_the_stream() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let be = backend(seen.clone());
    let socks = socks4_proxy(be, SOCKS4_OK, Some(vec![0x00, 0x5a, 0x00]), Arc::new(Mutex::new(Vec::new())));
    let fe = common::reserve_addr();
    let (log_addr, logs) = start_syslog();
    let cfg = format!(
        "global\n  log {log_addr} local0\ndefaults\n  mode http\n  log global\n  \
         log-format \"%ST %ts %rc\"\n  \
         timeout connect 400ms\n  timeout client 5s\n  timeout server 5s\n  retries 1\n\
         frontend f\n  bind {fe}\n  default_backend b\n\
         backend b\n  server s {be} socks4 {socks}\n"
    );
    let _p = start_raw(&cfg, &[fe]);
    let body = get(fe);
    let code = body.get(9..12).unwrap_or("");
    assert_eq!(code, "503", "a short reply is 503: {body:?}");
    assert!(seen.lock().unwrap().bytes.is_empty(), "the server must not see the request when the reply is short");
    let line = wait_log(&logs, "503 ");
    assert!(line.contains("503 sC 1"), "unexpected log: {line:?}");
}

/// TCP mode (`frontend -> default_backend` and `listen`) relays through the SOCKS4 tunnel,
/// and a refused tunnel in TCP mode retries and closes without reaching the backend.
#[test]
fn tcp_mode_goes_through_the_tunnel_and_retries_on_refusal() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf) {
                    let _ = s.write_all(&buf[..n]);
                }
            });
        }
    });

    let ok_events = Arc::new(Mutex::new(Vec::new()));
    let ok_socks = socks4_proxy(echo_addr, SOCKS4_OK, None, ok_events.clone());
    let deny_attempts = Arc::new(AtomicUsize::new(0));
    let deny_socks = socks4_proxy_with_count(echo_addr, SOCKS4_DENY, None, Arc::new(Mutex::new(Vec::new())), deny_attempts.clone());

    let fe_be = common::reserve_addr();
    let fe_listen = common::reserve_addr();
    let fe_deny = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode tcp\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n  retries 1\n\
         frontend f_be\n  bind {fe_be}\n  default_backend b_tcp\n\
         backend b_tcp\n  server s {echo_addr} socks4 {ok_socks}\n\
         listen l_tcp\n  bind {fe_listen}\n  server s {echo_addr} socks4 {ok_socks}\n\
         listen l_deny\n  bind {fe_deny}\n  server s {echo_addr} socks4 {deny_socks}\n"
    );
    let _p = start_raw(&cfg, &[fe_be, fe_listen]);

    for addr in [fe_be, fe_listen] {
        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(b"PING\n").unwrap();
        c.shutdown(Shutdown::Write).unwrap();
        let mut out = Vec::new();
        c.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"PING\n", "TCP tunnel via {addr}");
    }

    let mut c = TcpStream::connect(fe_deny).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let _ = c.write_all(b"PING\n");
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    assert!(out.is_empty(), "refused TCP tunnel sends no payload: {out:?}");
    assert_eq!(deny_attempts.load(Ordering::Relaxed), 2, "TCP mode retries once");
}

/// Keep-alive reuse (`http-reuse safe`) and `retry-on 503` both work over a `socks4` tunnel.
#[test]
fn http_keepalive_and_l7_retry_work_over_socks4() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let be_addr = l.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::clone(&count);
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let c2 = Arc::clone(&c2);
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let resp: &[u8] = if req.contains("GET /retry") && c2.fetch_add(1, Ordering::Relaxed) == 0 {
                        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\nConnection: close\r\n\r\nwait"
                    } else {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
                    };
                    if s.write_all(resp).is_err() {
                        break;
                    }
                }
            });
        }
    });

    let socks = socks4_proxy(be_addr, SOCKS4_OK, None, Arc::new(Mutex::new(Vec::new())));
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  http-reuse safe\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n  retries 1\n\
         frontend f\n  bind {fe}\n  default_backend b\n\
         backend b\n  retry-on 503\n  server s {be_addr} socks4 {socks}\n"
    );
    let _p = start_raw(&cfg, &[fe]);

    // Two keep-alive requests on one client socket.
    let mut c = TcpStream::connect(fe).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"GET /one HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut buf = [0u8; 512];
    let n1 = c.read(&mut buf).unwrap();
    assert!(String::from_utf8_lossy(&buf[..n1]).starts_with("HTTP/1.1 200"));
    c.write_all(b"GET /two HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut rest = Vec::new();
    c.read_to_end(&mut rest).unwrap();
    assert!(String::from_utf8_lossy(&rest).starts_with("HTTP/1.1 200"));

    // L7 retry on 503 over socks4.
    let mut c2 = TcpStream::connect(fe).unwrap();
    c2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c2.write_all(b"GET /retry HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut got = Vec::new();
    c2.read_to_end(&mut got).unwrap();
    let s = String::from_utf8_lossy(&got);
    assert!(s.starts_with("HTTP/1.1 200"), "L7 retry over socks4 failed: {s:?}");
}

/// TCP connect, `tcp-check`, `httpchk` failure, and `redis-check` all honor `check-via-socks4`.
#[test]
fn health_checks_cover_tcp_http_tcp_check_and_redis_via_socks4() {
    // Backend for tcp-check and redis-check.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let be_addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 1024];
                if let Ok(n) = s.read(&mut buf) {
                    if buf[..n].starts_with(b"CHECK\n") {
                        let _ = s.write_all(b"ALIVE\n");
                    } else if buf[..n].windows(4).any(|w| w == b"PING") {
                        let _ = s.write_all(b"+PONG\r\n");
                    }
                }
            });
        }
    });

    let ok_tcp_events = Arc::new(Mutex::new(Vec::new()));
    let ok_tcp_socks = socks4_proxy(be_addr, SOCKS4_OK, None, ok_tcp_events.clone());
    let ok_tchk_events = Arc::new(Mutex::new(Vec::new()));
    let ok_tchk_socks = socks4_proxy(be_addr, SOCKS4_OK, None, ok_tchk_events.clone());
    let ok_redis_events = Arc::new(Mutex::new(Vec::new()));
    let ok_redis_socks = socks4_proxy(be_addr, SOCKS4_OK, None, ok_redis_events.clone());

    let deny_attempts = Arc::new(AtomicUsize::new(0));
    let deny_socks = socks4_proxy_with_count(be_addr, SOCKS4_DENY, None, Arc::new(Mutex::new(Vec::new())), deny_attempts.clone());

    let (log_addr, logs) = start_syslog();
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n  log {log_addr} local0\ndefaults\n  mode tcp\n  log global\n  \
         timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  default_backend b_tcp_ok\n\
         backend b_tcp_ok\n  option log-health-checks\n  server s {be_addr} socks4 {ok_tcp_socks} check-via-socks4 check inter 200ms rise 1 fall 1\n\
         backend b_tcp_fail\n  option log-health-checks\n  server s {be_addr} socks4 {deny_socks} check-via-socks4 check inter 200ms rise 1 fall 1\n\
         backend b_tchk_ok\n  option log-health-checks\n  option tcp-check\n  tcp-check send CHECK\\n\n  tcp-check expect string ALIVE\n  server s {be_addr} socks4 {ok_tchk_socks} check-via-socks4 check inter 200ms rise 1 fall 1\n\
         backend b_tchk_fail\n  option log-health-checks\n  option tcp-check\n  tcp-check send CHECK\\n\n  tcp-check expect string ALIVE\n  server s {be_addr} socks4 {deny_socks} check-via-socks4 check inter 200ms rise 1 fall 1\n\
         backend b_http_fail\n  mode http\n  option log-health-checks\n  option httpchk\n  server s {be_addr} socks4 {deny_socks} check-via-socks4 check inter 200ms rise 1 fall 1\n\
         backend b_redis_ok\n  option log-health-checks\n  option redis-check\n  server s {be_addr} socks4 {ok_redis_socks} check-via-socks4 check inter 200ms rise 1 fall 1\n\
         backend b_redis_fail\n  option log-health-checks\n  option redis-check\n  server s {be_addr} socks4 {deny_socks} check-via-socks4 check inter 200ms rise 1 fall 1\n"
    );
    let _p = start_raw(&cfg, &[fe]);

    wait_log(&logs, "b_tcp_ok/s succeeded");
    wait_log(&logs, "b_tchk_ok/s succeeded");
    wait_log(&logs, "b_redis_ok/s succeeded");
    for be_name in ["b_tcp_fail/s", "b_tchk_fail/s", "b_http_fail/s", "b_redis_fail/s"] {
        let l = wait_log(&logs, &format!("{be_name} failed"));
        assert!(l.contains("Socket error") && l.contains("SOCKS4 Proxy deny the request"), "{be_name}: {l:?}");
    }
    assert!(!ok_tcp_events.lock().unwrap().is_empty(), "TCP connect check went via socks4");
    assert!(
        ok_tchk_events.lock().unwrap().iter().any(|e| e.to_target.windows(5).any(|w| w == b"CHECK")),
        "tcp-check went via socks4"
    );
    assert!(
        ok_redis_events.lock().unwrap().iter().any(|e| e.to_target.windows(4).any(|w| w == b"PING")),
        "redis-check went via socks4"
    );
    assert!(deny_attempts.load(Ordering::Relaxed) >= 4);
}

/// With `check-via-socks4`, the health checks take the tunnel: the proxy sees the 16
/// request bytes for the server's address once a second.
#[test]
fn the_check_goes_through_the_tunnel() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let be = backend(seen.clone());
    let events = Arc::new(Mutex::new(Vec::new()));
    let socks = socks4_proxy(be, SOCKS4_OK, None, events.clone());
    let fe = common::reserve_addr();
    let p = start(&format!("socks4 {socks} check-via-socks4 check inter 1s rise 1 fall 1"), be, fe, "  option httpchk");
    // Two or three check rounds: `inter 1s rise 1` succeeds within the first two seconds.
    thread::sleep(Duration::from_secs(3));
    let want = socks4_request(be);
    let via = events.lock().unwrap().iter().any(|e| e.request == want);
    assert!(via, "the health check must go through the tunnel: {:?}", *events.lock().unwrap());
    // The check's `OPTIONS /` reached the server through the tunnel.
    let got = seen.lock().unwrap().bytes.clone();
    let conns = seen.lock().unwrap().conns;
    assert!(got.windows(9).any(|w| w == b"OPTIONS /"), "the check's request reached the server through the tunnel; conns={conns}, got={got:?}");
    drop(p);
}

/// Without `check-via-socks4` the checks go straight to the server: after three rounds
/// the server accepted the check connections and the proxy saw nothing.
#[test]
fn the_check_bypasses_the_tunnel_without_the_keyword() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let be = backend(seen.clone());
    let events = Arc::new(Mutex::new(Vec::new()));
    let socks = socks4_proxy(be, SOCKS4_OK, None, events.clone());
    let fe = common::reserve_addr();
    let p = start(&format!("socks4 {socks} check inter 1s rise 1 fall 1"), be, fe, "  option httpchk");
    thread::sleep(Duration::from_secs(3));
    assert!(seen.lock().unwrap().conns > 0, "the checks reached the server directly");
    assert!(events.lock().unwrap().is_empty(), "the proxy must see nothing of the checks");
    drop(p);
}
