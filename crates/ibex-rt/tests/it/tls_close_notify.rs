// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A TLS client connection that Ibex closes ends with `close_notify` (T283, MY-2).
//!
//! Ibex wrote a FIN with no `close_notify` before it. An OpenSSL client reads that as
//! "unexpected eof while reading" and marks its session not resumable, so a client that
//! reconnects never resumes: under a flood of one-request connections, every handshake
//! was a full one (an RSA signature each) where `HAProxy` resumed, and the legitimate
//! users on the same threads waited behind them.
//!
//! Measured with `HAProxy` 3.5-dev8-885761-29 (`openssl s_client -tls1_3 -ign_eof -msg`):
//! `<<< TLS 1.3, Alert ... warning close_notify` before the close, for a response from
//! `http-request return` to a `Connection: close` request, for the 400 to a malformed
//! request, and for a `mode tcp` frontend whose server closed. Ibex: `unexpected eof
//! while reading` in all three.
//!
//! rustls tells the two apart the same way: a read returns `Ok(0)` only after
//! `close_notify`, and `UnexpectedEof` on a bare FIN.

use crate::common;

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};

// The config file lives as long as the process that reads it.
struct Ibex(Child, #[allow(dead_code)] NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn cert(dir: &TempDir) -> (String, rustls::pki_types::CertificateDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let path = dir.path().join("c.pem");
    std::fs::write(&path, format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem())).expect("write pem");
    (path.display().to_string(), ck.cert.der().clone())
}

fn start(cfg: &str, addrs: &[SocketAddr]) -> Ibex {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex(child, f);
    for a in addrs {
        assert!(common::wait_listening(*a), "ibex never listened on {a}");
    }
    ibex
}

/// Sends `req` over TLS and reads until the connection ends. Returns what was read and
/// whether the end was a `close_notify` (true) or a bare FIN (false).
fn exchange(addr: SocketAddr, cert: &rustls::pki_types::CertificateDer<'static>, req: &[u8]) -> (String, bool) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).expect("root");
    let cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), name).expect("client");
    let mut tcp = TcpStream::connect(addr).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    // The handshake first, so the request is not in the segment that ends it.
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp).expect("handshake");
    }
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    tls.write_all(req).expect("write");
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let clean = loop {
        match tls.read(&mut buf) {
            Ok(0) => break true,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break false,
            Err(e) => panic!("read from {addr}: {e} after {:?}", String::from_utf8_lossy(&out)),
        }
    };
    (String::from_utf8_lossy(&out).into_owned(), clean)
}

#[test]
fn http_connection_close_ends_with_close_notify() {
    let dir = TempDir::new().unwrap();
    let (pem, der) = cert(&dir);
    let addr = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {addr} ssl crt {pem}\n  http-request return status 200 content-type text/plain string ok\n"
    );
    let _ibex = start(&cfg, &[addr]);

    let (resp, clean) = exchange(addr, &der, b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp:?}");
    assert!(clean, "the response to `Connection: close` ended with a bare FIN, no close_notify");

    let (resp, clean) = exchange(addr, &der, b"BAD\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 400"), "{resp:?}");
    assert!(clean, "the 400 ended with a bare FIN, no close_notify");
}

#[test]
fn tcp_mode_server_close_ends_with_close_notify() {
    let dir = TempDir::new().unwrap();
    let (pem, der) = cert(&dir);
    let srv = TcpListener::bind("127.0.0.1:0").unwrap();
    let srv_addr = srv.local_addr().unwrap();
    // Every connection is served: the readiness probe that waits for Ibex to listen is
    // forwarded here too, and ends without a byte.
    thread::spawn(move || {
        for s in srv.incoming() {
            let Ok(mut s) = s else { return };
            thread::spawn(move || {
                s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut b = [0u8; 256];
                if matches!(s.read(&mut b), Ok(n) if n > 0) {
                    let _ = s.write_all(b"pong\n");
                }
                // Dropping `s` closes: the server is done sending.
            });
        }
    });
    let addr = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode tcp\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         listen t\n  bind {addr} ssl crt {pem}\n  server s {srv_addr}\n"
    );
    let _ibex = start(&cfg, &[addr]);

    let (resp, clean) = exchange(addr, &der, b"ping\n");
    assert_eq!(resp, "pong\n");
    assert!(clean, "the server's close reached the client as a bare FIN, no close_notify");
}
