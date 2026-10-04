// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The protocol health checks, black-box against the binary and a small fake server each:
//! `option redis-check`, `ldap-check`, `mysql-check` (with and without `user`),
//! `pgsql-check`, `ssl-hello-chk`, and a `tcp-check` script with a second `connect`.
//!
//! Expected lines measured on `HAProxy` 3.5-dev8-885761-29 (2026-10-04) with
//! `option log-health-checks` and fake servers answering as a healthy one does:
//!
//! ```text
//! redis:    succeeded, reason: Layer7 check passed, code: 0, info: "Redis server is ok"
//! ldap:     succeeded, reason: Layer7 check passed, code: 0, info: "Success"
//! mysql:    succeeded, reason: Layer7 check passed, code: 0, info: "5.7.0-fake"   (user or not)
//! pgsql:    succeeded, reason: Layer7 check passed, code: 0, info: "PostgreSQL server is ok"
//! ssl-hello: succeeded, reason: Layer6 check passed
//! tcp-check: succeeded, reason: Layer7 check passed, code: 0, info: "(tcp-check)"
//! redis against an LDAP answer: failed, reason: Layer7 wrong status, code: 0, info: "0<0C>..."
//! ```
//!
//! T113 renamed these checks' socket calls onto the check transport (so `check-ssl` can
//! wrap them); their behaviour is unchanged, and these tests cover that path. With
//! `T113_BREAK=1` every fake answers `nope`, which makes each test fail.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn broken() -> bool {
    std::env::var_os("T113_BREAK").is_some()
}

fn read_some(s: &mut TcpStream) -> Vec<u8> {
    s.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let mut b = [0u8; 4096];
    match s.read(&mut b) {
        Ok(n) => b[..n].to_vec(),
        Err(_) => Vec::new(),
    }
}

/// A fake server: `handler` runs per connection.
fn fake(handler: fn(TcpStream)) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(s) = stream else { break };
            thread::spawn(move || handler(s));
        }
    });
    addr
}

fn answer(mut s: TcpStream, healthy: &[u8]) {
    let _ = s.write_all(if broken() { b"nope\r\n" } else { healthy });
}

fn redis(mut s: TcpStream) {
    let _ = read_some(&mut s);
    answer(s, b"+PONG\r\n");
}

/// LDAP bindResponse, resultCode success.
fn ldap(mut s: TcpStream) {
    let _ = read_some(&mut s);
    answer(s, &[0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00]);
}

/// MySQL: the server greeting (protocol 10, version "5.7.0-fake"), then an OK packet to
/// whatever authentication arrives.
fn mysql(mut s: TcpStream) {
    let mut body = vec![0x0a];
    body.extend_from_slice(b"5.7.0-fake\0");
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(b"abcdefgh\0");
    body.extend_from_slice(&0xf7ffu16.to_le_bytes());
    body.push(0x21);
    body.extend_from_slice(&0x0002u16.to_le_bytes());
    body.extend_from_slice(&0x8000u16.to_le_bytes());
    body.push(0x15);
    body.extend_from_slice(&[0u8; 10]);
    body.extend_from_slice(b"ijklmnopqrst\0");
    body.extend_from_slice(b"mysql_native_password\0");
    let mut greeting = (body.len() as u32).to_le_bytes()[..3].to_vec();
    greeting.push(0);
    greeting.extend_from_slice(&body);
    if broken() {
        let _ = s.write_all(b"nope\r\n");
        return;
    }
    let _ = s.write_all(&greeting);
    if !read_some(&mut s).is_empty() {
        let _ = s.write_all(&[0x07, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0]);
        let _ = read_some(&mut s);
    }
}

/// PostgreSQL AuthenticationOk.
fn pgsql(mut s: TcpStream) {
    let _ = read_some(&mut s);
    answer(s, &[b'R', 0, 0, 0, 8, 0, 0, 0, 0]);
}

/// A handshake record shaped like a ServerHello, to the SSLv3 ClientHello the check sends.
fn sslhello(mut s: TcpStream) {
    let _ = read_some(&mut s);
    let mut rec = vec![0x16, 0x03, 0x00, 0x00, 0x2a, 0x02, 0x00, 0x00, 0x26, 0x03, 0x00];
    rec.extend_from_slice(&[0u8; 32]);
    rec.extend_from_slice(&[0x00, 0x00, 0x2f, 0x00]);
    answer(s, &rec);
}

fn tcp_step1(mut s: TcpStream) {
    let _ = s.write_all(if broken() { b"nope\r\n" } else { b"hello\r\n" });
    let _ = read_some(&mut s);
    let _ = s.write_all(b"pong\r\n");
}

fn tcp_step2(s: TcpStream) {
    answer(s, b"second\r\n");
}

struct Ibex(Child);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// Starts ibex on one backend with `check_lines` and `server_line`, logging checks to a
/// UDP socket; returns the first health-check log line for that server.
fn check_line(check_lines: &str, server_line: &str) -> String {
    let dir = tempfile::TempDir::new().expect("tmp");
    let syslog = UdpSocket::bind("127.0.0.1:0").expect("udp");
    syslog.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let front = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode tcp\n  log 127.0.0.1:{} local0\n  option log-health-checks\n  timeout connect 1s\n  \
         timeout client 2s\n  timeout server 2s\n  timeout check 1s\nfrontend f\n  bind {front}\n  default_backend b\n\
         backend b\n{check_lines}\n  server s {server_line} check inter 200ms fall 1 rise 1\n",
        syslog.local_addr().unwrap().port()
    );
    let path = dir.path().join("ibex.cfg");
    std::fs::write(&path, &cfg).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let _ibex = Ibex(child);
    assert!(common::wait_listening(front), "ibex never listened");
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

fn assert_line(line: &str, expected: &[&str]) {
    for e in expected {
        assert!(line.contains(e), "expected `{e}` in:\n{line}");
    }
}

#[test]
fn redis_check_passes_on_pong() {
    let line = check_line("  option redis-check", &fake(redis).to_string());
    assert_line(&line, &["succeeded, reason: Layer7 check passed", "info: \"Redis server is ok\""]);
}

#[test]
fn redis_check_fails_on_another_protocols_answer() {
    let line = check_line("  option redis-check", &fake(ldap).to_string());
    assert_line(&line, &["failed, reason: Layer7 wrong status", "info: \"0<0C><02><01><01>a<07>\""]);
}

#[test]
fn ldap_check_passes_on_a_successful_bind_response() {
    let line = check_line("  option ldap-check", &fake(ldap).to_string());
    assert_line(&line, &["succeeded, reason: Layer7 check passed", "info: \"Success\""]);
}

#[test]
fn mysql_check_reports_the_server_version_with_and_without_a_user() {
    let line = check_line("  option mysql-check user haproxy post-41", &fake(mysql).to_string());
    assert_line(&line, &["succeeded, reason: Layer7 check passed", "info: \"5.7.0-fake\""]);
    let line = check_line("  option mysql-check", &fake(mysql).to_string());
    assert_line(&line, &["succeeded, reason: Layer7 check passed", "info: \"5.7.0-fake\""]);
}

#[test]
fn pgsql_check_passes_on_authentication_ok() {
    let line = check_line("  option pgsql-check user haproxy", &fake(pgsql).to_string());
    assert_line(&line, &["succeeded, reason: Layer7 check passed", "info: \"PostgreSQL server is ok\""]);
}

#[test]
fn ssl_hello_check_passes_on_a_handshake_record() {
    let line = check_line("  option ssl-hello-chk", &fake(sslhello).to_string());
    assert_line(&line, &["succeeded, reason: Layer6 check passed"]);
}

#[test]
fn tcp_check_with_a_second_connect_passes() {
    let second = fake(tcp_step2);
    let steps = format!(
        "  option tcp-check\n  tcp-check connect\n  tcp-check expect string hello\n  tcp-check send ping\\r\\n\n  \
         tcp-check expect string pong\n  tcp-check connect port {}\n  tcp-check expect string second",
        second.port()
    );
    let line = check_line(&steps, &fake(tcp_step1).to_string());
    assert_line(&line, &["succeeded, reason: Layer7 check passed", "info: \"(tcp-check)\""]);
}

/// `check-ssl` on a protocol check: the redis PING/PONG runs inside TLS (the check's
/// transport is what T113 wrapped these checks in).
#[test]
fn redis_check_over_tls_with_check_ssl() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![ck.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der())),
        )
        .expect("server config");
    let cfg = Arc::new(cfg);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { break };
            let cfg = Arc::clone(&cfg);
            thread::spawn(move || {
                s.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut conn = rustls::ServerConnection::new(cfg).expect("conn");
                let mut tls = rustls::Stream::new(&mut conn, &mut s);
                let mut b = [0u8; 64];
                if tls.read(&mut b).is_ok() {
                    let _ = tls.write_all(if broken() { b"nope\r\n" } else { b"+PONG\r\n" });
                }
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    let line = check_line("  option redis-check", &format!("{addr} check-ssl verify none"));
    assert_line(&line, &["succeeded, reason: Layer7 check passed", "info: \"Redis server is ok\""]);
}
