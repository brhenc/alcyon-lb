// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A client resumes its TLS session after many other clients have connected (T283, MY-2).
//!
//! rustls's default server keeps sessions in a 256-entry memory cache and issues TLS 1.3
//! tickets that are entries in it, two per connection. A few hundred clients pushed every
//! earlier one out, so under a flood of reconnecting clients nearly every handshake was a
//! full one, an RSA signature each, where `HAProxy` (stateless tickets, a 20000-entry
//! session cache: `tune.ssl.cachesize`) resumed them all.
//!
//! Measured with `HAProxy` 3.5-dev8-885761-29: 1000 clients (Python `ssl`, TLS 1.3) each
//! connect once, then the first 100 reconnect with their session: 100/100 resumed. Alcyon
//! with the `close_notify` fix: 0/100.

use crate::common;

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};

// The config file lives as long as the process that reads it.
struct Alcyon(Child, #[allow(dead_code)] NamedTempFile);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// One TLS request with `Connection: close`; true when the handshake resumed a session.
fn get(addr: SocketAddr, cfg: &Arc<rustls::ClientConfig>) -> bool {
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::clone(cfg), name).expect("client");
    let mut tcp = TcpStream::connect(addr).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => panic!("read: {e}"),
        }
    }
    assert!(out.starts_with(b"HTTP/1.1 200"), "{:?}", String::from_utf8_lossy(&out));
    conn.handshake_kind() == Some(rustls::HandshakeKind::Resumed)
}

#[test]
fn a_client_resumes_after_200_others_connected() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = TempDir::new().unwrap();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let pem = dir.path().join("c.pem");
    std::fs::write(&pem, format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem())).unwrap();
    let addr = common::reserve_addr();
    let mut f = NamedTempFile::new().unwrap();
    write!(
        f,
        "global\n  nbthread 4\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {addr} ssl crt {}\n  http-request return status 200 content-type text/plain string ok\n",
        pem.display()
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    let _alcyon = Alcyon(child, f);
    assert!(common::wait_listening(addr));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ck.cert.der().clone()).unwrap();
    // One client config per client: each keeps its own session.
    let clients: Vec<Arc<rustls::ClientConfig>> = (0..200)
        .map(|_| Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots.clone()).with_no_client_auth()))
        .collect();
    for c in &clients {
        assert!(!get(addr, c), "a first connection cannot resume");
    }
    let resumed = clients[..20].iter().filter(|c| get(addr, c)).count();
    assert_eq!(resumed, 20, "of the 20 oldest clients, only {resumed} resumed after 200 had connected");
}
