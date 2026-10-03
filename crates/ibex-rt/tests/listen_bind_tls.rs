// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A `listen` section's `bind` lines, against the real binary (T110).
//!
//! `parse_listen_bind` kept only `accept-proxy` and dropped every other keyword, and kept
//! only the last `bind` line, so
//!
//! ```text
//! listen x
//!   bind :443 ssl crt c.pem
//! ```
//!
//! answered plain HTTP on 443. Measured with `HAProxy` 3.5-dev8-885761-29 on a `listen`
//! with `bind 127.0.0.1:P1 ssl crt common.pem` and `bind 127.0.0.1:P2`:
//!
//! * `curl -k https://127.0.0.1:P1/` gets the response, and `curl http://127.0.0.1:P2/`
//!   gets it too;
//! * a plaintext `GET / HTTP/1.1` sent to P1 gets no byte back: the connection is closed.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::{NamedTempFile, TempDir};

struct Ibex(Child, NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        // The soft stop, so an instrumented build writes its coverage profile.
        let _ = Command::new("kill").arg("-USR1").arg(self.0.id().to_string()).status();
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if matches!(self.0.try_wait(), Ok(Some(_))) {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A self-signed `localhost` certificate: the combined PEM written to `dir`, and the
/// certificate alone as DER for the client to trust.
fn cert(dir: &TempDir) -> (String, rustls::pki_types::CertificateDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let path = dir.path().join("c.pem");
    std::fs::write(&path, format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem())).expect("write pem");
    (path.display().to_string(), ck.cert.der().clone())
}

fn start(binds: &[String], cert_path: &str) -> Ibex {
    let mut f = NamedTempFile::new().expect("tmp");
    let mut cfg = String::from(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         listen x\n",
    );
    for b in binds {
        cfg.push_str(&format!("  bind {}\n", b.replace("CRT", cert_path)));
    }
    cfg.push_str("  http-request return status 200 content-type text/plain string ok\n");
    f.write_all(cfg.as_bytes()).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex(child, f);
    for b in binds {
        let addr: SocketAddr = b.split_whitespace().next().unwrap().parse().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(addr).is_err() {
            assert!(Instant::now() < deadline, "ibex never started listening on {addr}");
            thread::sleep(Duration::from_millis(20));
        }
    }
    ibex
}

fn https_get(addr: SocketAddr, cert: &rustls::pki_types::CertificateDer<'static>) -> String {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).expect("root");
    let cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), name).expect("client");
    let mut tcp = TcpStream::connect(addr).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = tls.read(&mut buf) {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn plain_get(addr: SocketAddr) -> Vec<u8> {
    let mut tcp = TcpStream::connect(addr).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let _ = tcp.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = tcp.read(&mut buf) {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    out
}

#[test]
fn listen_ssl_bind_terminates_tls_and_never_answers_plaintext() {
    let dir = TempDir::new().unwrap();
    let (path, der) = cert(&dir);
    let addr = common::reserve_addr();
    let _ibex = start(&[format!("{addr} ssl crt CRT")], &path);

    let resp = https_get(addr, &der);
    assert!(resp.starts_with("HTTP/1.1 200"), "TLS request must be served, got {resp:?}");

    let plain = plain_get(addr);
    assert!(
        !String::from_utf8_lossy(&plain).contains("HTTP/1."),
        "HAProxy answers nothing in plaintext on an ssl bind; Ibex sent {:?}",
        String::from_utf8_lossy(&plain)
    );
}

#[test]
fn listen_serves_on_every_bind_line() {
    let dir = TempDir::new().unwrap();
    let (path, der) = cert(&dir);
    let tls = common::reserve_addr();
    let plain = common::reserve_addr();
    let _ibex = start(&[format!("{tls} ssl crt CRT"), plain.to_string()], &path);

    let resp = https_get(tls, &der);
    assert!(resp.starts_with("HTTP/1.1 200"), "first bind (ssl) must serve, got {resp:?}");
    let resp = String::from_utf8_lossy(&plain_get(plain)).into_owned();
    assert!(resp.starts_with("HTTP/1.1 200"), "second bind (plain) must serve, got {resp:?}");
}

#[test]
fn listen_ssl_bind_without_crt_refuses_to_start() {
    let mut f = NamedTempFile::new().unwrap();
    let addr = common::reserve_addr();
    write!(
        f,
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         listen x\n  bind {addr} ssl crt /nonexistent/c.pem\n  http-request return status 200\n"
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().unwrap();
    assert!(!out.status.success(), "-c must load the certificate of a listen's ssl bind");
}

/// `HAProxy` loads the certificates of a `disabled` section at parse time and refuses a
/// missing one (measured with `haproxy -c`: "unable to stat SSL certificate").
#[test]
fn disabled_listen_ssl_bind_still_loads_its_certificate() {
    let mut f = NamedTempFile::new().unwrap();
    let addr = common::reserve_addr();
    write!(
        f,
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         listen x\n  disabled\n  bind {addr} ssl crt /nonexistent/c.pem\n  http-request return status 200\n"
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().unwrap();
    assert!(!out.status.success(), "-c must load the certificate of a disabled listen's ssl bind");
}
