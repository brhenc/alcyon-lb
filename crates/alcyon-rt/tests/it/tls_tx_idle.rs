// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T541: the TLS ciphertext buffer is a pool (`show pools` `tls_tx`) and an idle TLS connection,
//! on either side of the proxy, holds none of it. Before, every TLS connection held a 33,792-byte
//! `Vec` for its whole life (56 KB per idle server connection, `tasks/T538-progress.md`).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use crate::common;

const CLIENTS: usize = 20;

struct Stop(std::process::Child);
impl Drop for Stop {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// `show pools`' `tls_tx` line: (allocated, in use). `used` there counts the chunks in the
/// thread caches (`~N by thread caches`), as HAProxy's does.
fn tls_tx(sock: &std::path::Path) -> Option<(usize, usize)> {
    let mut s = UnixStream::connect(sock).expect("cli connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).ok();
    s.write_all(b"show pools\n").expect("cli write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let line = out.lines().find(|l| l.contains("Pool tls_tx "))?;
    let before = |what: &str| -> usize {
        let head = &line[..line.find(what).unwrap_or_else(|| panic!("{line}"))];
        head.trim_end().rsplit(|c: char| !c.is_ascii_digit()).next().and_then(|n| n.parse().ok()).unwrap_or_else(|| panic!("{line}"))
    };
    let cached: usize = line.split("used (~").nth(1)?.split(' ').next()?.parse().ok()?;
    Some((before(" allocated"), before(" used") - cached))
}

fn client(port: u16) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
    let conn = rustls::ClientConnection::new(Arc::new(cfg), name).expect("client");
    let tcp = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
    rustls::StreamOwned::new(conn, tcp)
}

#[derive(Debug)]
struct NoVerify;
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// One keep-alive request; the answer.
fn get(c: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>) -> String {
    c.write_all(b"GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n").expect("write");
    let mut got = Vec::new();
    let mut b = [0u8; 4096];
    while !got.ends_with(b"ok") {
        let n = c.read(&mut b).expect("read");
        assert!(n > 0, "closed: {got:?}");
        got.extend_from_slice(&b[..n]);
    }
    String::from_utf8_lossy(&got).into_owned()
}

/// A TLS bind (the clients), a backend over TLS (to a TLS `listen` of the same proxy), and
/// `CLIENTS` idle keep-alive connections each after one request: no `tls_tx` chunk in use.
#[test]
fn idle_tls_connections_on_both_sides_hold_no_ciphertext_buffer() {
    let dir = tempfile::TempDir::new().expect("dir");
    let (cfg, sock, pem) = (dir.path().join("c.cfg"), dir.path().join("s.sock"), dir.path().join("c.pem"));
    let (port, tp) = (common::reserve_port(), common::reserve_port());
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    std::fs::write(&pem, format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem())).expect("write pem");
    std::fs::write(
        &cfg,
        format!(
            "global\n\tnbthread 1\n\tstats socket {} level admin\n\
             defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 30s\n\ttimeout server 30s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port} ssl crt {pem}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{tp} ssl verify none\n\n\
             listen tlsserver\n\tbind 127.0.0.1:{tp} ssl crt {pem}\n\
             \thttp-request return status 200 content-type text/plain string ok\n",
            sock.display(),
            pem = pem.display()
        ),
    )
    .expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&cfg).arg("-db").stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let mut child = Stop(child);
    assert!(common::wait_listening(([127, 0, 0, 1], port).into()), "the proxy never listened");
    let listed = tls_tx(&sock);
    let mut clients: Vec<_> = (0..CLIENTS).map(|_| client(port)).collect();
    for c in &mut clients {
        assert!(get(c).starts_with("HTTP/1.1 200"));
    }
    std::thread::sleep(Duration::from_millis(500));
    // The counts are published once per loop pass: the first `show pools` may precede the pass
    // that gave the last chunk back.
    let _ = tls_tx(&sock);
    let after = tls_tx(&sock);
    common::stop(&mut child.0);
    assert!(listed.is_some(), "`show pools` does not list tls_tx from the start");
    let (allocated, used) = after.expect("tls_tx listed after the requests");
    assert_eq!(used, 0, "{CLIENTS} idle connections on each side hold {used} ciphertext buffers");
    assert!(allocated <= 4, "{allocated} ciphertext buffers allocated for {CLIENTS} idle connections (the pool keeps only what was in flight)");
}
