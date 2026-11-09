// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A server connection idle in its server's lists is watched for reads; nothing probes it
//! when a request takes it (T434).
//!
//! Measured on `HAProxy` 3.5-dev8 on 2026-10-19 (`nbthread 1`, the servers below; the
//! scripts are in the T434 task file):
//!
//! * the server answers the first request on its connection and closes it (FIN) or resets
//!   it when the second arrives, the client waiting 300 ms between them so that the second
//!   takes the connection from the server's lists: the client connection is closed
//!   unanswered (`abort_keep_alive`), one server connection; so did Alcyon before;
//! * a TLS server sends `close_notify` 50 ms after its response and leaves the socket open;
//!   a second client 300 ms later is answered `200` on a new server connection.

use crate::common;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Alcyon(Child, NamedTempFile);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(server_line: &str) -> (Alcyon, SocketAddr) {
    let fe = common::reserve_addr();
    let mut f = NamedTempFile::new().expect("tmp");
    let cfg = format!(
        "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 3s\n  timeout server 3s\n\
         listen fe\n  bind {fe}\n  {server_line}\n"
    );
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn alcyon");
    let alcyon = Alcyon(child, f);
    assert!(common::wait_listening(fe), "alcyon never listened");
    (alcyon, fe)
}

fn read_head(s: &mut impl Read) -> bool {
    let mut got = Vec::new();
    let mut b = [0u8; 1];
    while !got.ends_with(b"\r\n\r\n") {
        match s.read(&mut b) {
            Ok(1) => got.push(b[0]),
            _ => return false,
        }
    }
    true
}

/// Sends a request on `c` and returns the response's head, or `None` when the connection
/// closed (or was reset) with nothing.
fn ask(c: &mut TcpStream) -> Option<String> {
    c.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").expect("send");
    let mut got = Vec::new();
    let mut b = [0u8; 4096];
    while !(got.windows(4).any(|w| w == b"\r\n\r\n") && got.ends_with(b"ok")) {
        match c.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&b[..n]),
        }
    }
    (!got.is_empty()).then(|| String::from_utf8_lossy(&got).into_owned())
}

/// A server that answers the first request on each connection (`X-Conn: <n>`) and, on the
/// second, closes the connection (or resets it, with `reset`) without a byte.
fn second_request_dropping_server(reset: bool) -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let id = seen.fetch_add(1, Ordering::SeqCst) + 1;
            thread::spawn(move || {
                if read_head(&mut s) {
                    let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Conn: {id}\r\n\r\nok").as_bytes());
                    if read_head(&mut s) {
                        if reset {
                            let _ = rustix::net::sockopt::set_socket_linger(&s, Some(Duration::ZERO));
                        } else {
                            let _ = s.shutdown(Shutdown::Write);
                            let mut b = [0u8; 64];
                            while s.read(&mut b).is_ok_and(|n| n > 0) {}
                        }
                    }
                }
            });
        }
    });
    (addr, count)
}

/// The server drops the connection a request took from its lists, as the request reaches
/// it: the client connection closes unanswered so that the client retries
/// (`abort_keep_alive`), as on `HAProxy`; the next client is answered on a new connection.
fn dropped_on_reuse(reset: bool) {
    let (srv, conns) = second_request_dropping_server(reset);
    let (_alcyon, fe) = start(&format!("server s1 {srv}"));
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    assert!(ask(&mut c).is_some_and(|r| r.starts_with("HTTP/1.1 200")), "the first request");
    // Past the time a connection stays on its session (100 ms): the next request takes it
    // from the server's lists.
    thread::sleep(Duration::from_millis(300));
    assert_eq!(ask(&mut c), None, "the request lost with the reused connection was answered");
    assert_eq!(conns.load(Ordering::SeqCst), 1);
    let mut c2 = TcpStream::connect(fe).expect("connect");
    c2.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    let r = ask(&mut c2).expect("the next client's answer");
    assert!(r.starts_with("HTTP/1.1 200") && r.to_ascii_lowercase().contains("x-conn: 2"), "{r}");
}

#[test]
fn a_connection_taken_from_the_lists_and_closed_on_the_request_closes_the_client_unanswered() {
    dropped_on_reuse(false);
}

#[test]
fn a_connection_taken_from_the_lists_and_reset_on_the_request_closes_the_client_unanswered() {
    dropped_on_reuse(true);
}

/// A TLS server that answers each request (`X-Conn: <n>`), then 50 ms later sends
/// `close_notify` and leaves its socket open until the proxy closes it.
fn close_notify_server() -> (SocketAddr, Arc<AtomicUsize>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let cfg = Arc::new(ServerConfig::builder().with_no_client_auth().with_single_cert(vec![der], key).expect("server config"));
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut sock) = s else { continue };
            let id = seen.fetch_add(1, Ordering::SeqCst) + 1;
            let cfg = Arc::clone(&cfg);
            thread::spawn(move || {
                sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut conn = ServerConnection::new(cfg).expect("conn");
                let mut tls = rustls::Stream::new(&mut conn, &mut sock);
                if !read_head(&mut tls) {
                    return;
                }
                if tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Conn: {id}\r\n\r\nok").as_bytes()).is_err() {
                    return;
                }
                let _ = tls.flush();
                thread::sleep(Duration::from_millis(50));
                conn.send_close_notify();
                while conn.wants_write() {
                    if conn.write_tls(&mut sock).is_err() {
                        return;
                    }
                }
                let mut b = [0u8; 4096];
                while sock.read(&mut b).is_ok_and(|n| n > 0) {}
            });
        }
    });
    (addr, count)
}

/// A TLS connection whose server sent `close_notify` while it was idle is not reused: the
/// next client is answered on a new connection.
#[test]
fn a_tls_connection_its_server_ended_while_idle_is_not_reused() {
    let (srv, conns) = close_notify_server();
    let (_alcyon, fe) = start(&format!("server s1 {srv} ssl verify none"));
    for want in ["x-conn: 1", "x-conn: 2"] {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        let r = ask(&mut c).expect("an answer");
        assert!(r.starts_with("HTTP/1.1 200") && r.to_ascii_lowercase().contains(want), "{r}");
        drop(c);
        thread::sleep(Duration::from_millis(300));
    }
    assert_eq!(conns.load(Ordering::SeqCst), 2);
}
