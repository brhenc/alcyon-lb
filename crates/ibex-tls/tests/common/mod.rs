// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Certificates, client configurations and an in-memory server/client pair, on rustls 0.24
//! (the binary's TLS, T479).

#![allow(dead_code)]

use ibex_tls::conn::{TlsCtx, VecInput};
use ibex_tls::tcp::{build_backend_client_config, rustls24, BindTls};
use ibex_tls::{BackendTlsOptions, TlsCryptoProvider};
use rcgen::generate_simple_self_signed;
use rustls24::crypto::{Credentials, Identity};
use rustls24::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::io::Write as _;
use std::sync::Arc;

/// A self-signed certificate: its DER, its key, and both in PEM.
pub struct TestCert {
    pub der: CertificateDer<'static>,
    pub key_der: Vec<u8>,
    pub cert_pem: String,
    pub key_pem: String,
}

impl TestCert {
    pub fn new(sans: Vec<String>) -> Self {
        let c = generate_simple_self_signed(sans).expect("Failed to generate test certificate");
        Self {
            der: CertificateDer::from(c.cert.der().to_vec()),
            key_der: c.key_pair.serialize_der(),
            cert_pem: c.cert.pem(),
            key_pem: c.key_pair.serialize_pem(),
        }
    }

    pub fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()))
    }

    /// A bind serving this certificate alone, with `alpn`, TLS 1.2 and 1.3.
    pub fn bind(&self, alpn: Vec<Vec<u8>>) -> Arc<BindTls> {
        BindTls::single(vec![self.der.clone()], self.key(), alpn).expect("bind")
    }

    /// The certificate and its key, as a `crt` file holds them.
    pub fn bundle_pem(&self) -> String {
        format!("{}{}", self.cert_pem, self.key_pem)
    }
}

/// Generates a self-signed certificate for `sans` and its rustls 0.24 credentials (what a
/// bind's resolver holds).
pub fn generate_test_cert(sans: Vec<String>) -> (Arc<Credentials>, CertificateDer<'static>) {
    let c = TestCert::new(sans);
    let keys = ibex_tls::provider::of(TlsCryptoProvider::Ring, true, true);
    let signing = keys.key_provider.load_private_key(c.key()).expect("key");
    let identity = Arc::new(Identity::from_cert_chain(vec![c.der.clone()]).expect("identity"));
    (Arc::new(Credentials::new(identity, signing).expect("credentials")), c.der)
}

/// A PEM bundle holding the certificate and its key, as a `crt` file must.
///
/// `HAProxy` reads one file per `crt` entry and expects the key concatenated with the
/// chain. A helper that returns the certificate alone produces a file that cannot be
/// loaded, which is what `test_sni_name_mismatch_filename` was doing.
pub fn generate_test_cert_bundle_pem(sans: Vec<String>) -> String {
    TestCert::new(sans).bundle_pem()
}

/// A client configuration that trusts `ca_pem` only and offers `alpn`.
pub fn client_trusting(ca_pem: &str, alpn: Vec<Vec<u8>>) -> Arc<rustls24::ClientConfig> {
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    f.write_all(ca_pem.as_bytes()).expect("write");
    build_backend_client_config(&BackendTlsOptions { ca_file: Some(f.path().to_path_buf()), alpn, ..Default::default() })
        .expect("client config")
}

/// A server session and a client session, each one's output shuttled into the other's input.
pub struct Pair {
    pub srv: TlsCtx,
    pub sin: VecInput,
    pub cli: TlsCtx,
    pub cin: VecInput,
}

impl Pair {
    /// A client of `cfg` connecting to `name` (sent as SNI) and a server on `bind`.
    pub fn new(bind: Arc<BindTls>, cfg: &Arc<rustls24::ClientConfig>, name: &str) -> Self {
        let cli = TlsCtx::connect(cfg, ServerName::try_from(name.to_string()).expect("name"), Some(name.into()));
        Self { srv: TlsCtx::accept(bind), sin: VecInput::default(), cli, cin: VecInput::default() }
    }

    /// One round: each side's output into the other's input. Whether anything moved.
    pub fn shuttle(&mut self) -> bool {
        let mut moved = false;
        let out = self.cli.pending_tx().to_vec();
        if !out.is_empty() {
            self.cli.tx_done(out.len());
            self.sin.extend(&out, &self.srv);
            moved = true;
        }
        let out = self.srv.pending_tx().to_vec();
        if !out.is_empty() {
            self.srv.tx_done(out.len());
            self.cin.extend(&out, &self.cli);
            moved = true;
        }
        moved
    }

    /// Runs both handshakes to their end; each side's result.
    pub fn handshake(&mut self) -> (Result<(), rustls24::Error>, Result<(), rustls24::Error>) {
        let (mut s, mut c) = (Ok(()), Ok(()));
        for _ in 0..30 {
            if s.is_ok() {
                s = self.srv.handshake(&mut self.sin);
            }
            if c.is_ok() {
                c = self.cli.handshake(&mut self.cin);
            }
            let moved = self.shuttle();
            if (!moved && !self.srv.is_handshaking() && !self.cli.is_handshaking()) || s.is_err() || c.is_err() {
                break;
            }
        }
        self.shuttle();
        (s, c)
    }

    /// Both handshakes, which must succeed.
    pub fn complete(&mut self) {
        let (s, c) = self.handshake();
        s.expect("server handshake");
        c.expect("client handshake");
        assert!(!self.srv.is_handshaking() && !self.cli.is_handshaking(), "both handshakes done");
    }

    /// `data` written by the client, as the server reads it.
    pub fn send_to_server(&mut self, data: &[u8]) -> Vec<u8> {
        assert_eq!(self.cli.write_plain(data).expect("client write"), data.len());
        self.shuttle();
        read_plain(&mut self.srv, &mut self.sin)
    }

    /// `data` written by the server, as the client reads it.
    pub fn send_to_client(&mut self, data: &[u8]) -> Vec<u8> {
        assert_eq!(self.srv.write_plain(data).expect("server write"), data.len());
        self.shuttle();
        read_plain(&mut self.cli, &mut self.cin)
    }
}

/// All the plaintext `ctx` has in `input`.
pub fn read_plain(ctx: &mut TlsCtx, input: &mut VecInput) -> Vec<u8> {
    use ibex_tls::conn::Plain;
    let mut out = Vec::new();
    let mut dst = [0u8; 4096];
    loop {
        match ctx.read_plain(input, &mut dst).expect("read") {
            Plain::Data(n) => out.extend_from_slice(&dst[..n]),
            _ => return out,
        }
    }
}
