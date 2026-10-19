// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `TlsCtx` (rustls 0.24, the TCP path) server against client, in memory: the handshake
//! states, plaintext in small pieces, close_notify, broken records, and the configurations
//! of `ibex_tls::tcp` (backend verifier, session-ID resumption, option errors).

use ibex_tls::config::BackendTlsOptions;
use ibex_tls::conn::{Plain, TlsCtx, VecInput, TX_CAP};
use ibex_tls::tcp::{build_backend_client_config, rustls24, BindTls};
use rustls24::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::sync::Arc;

struct Ident {
    der: CertificateDer<'static>,
    key: Vec<u8>,
    pem: String,
}

fn ident(name: &str) -> Ident {
    let c = rcgen::generate_simple_self_signed(vec![name.to_string()]).expect("cert");
    Ident { der: CertificateDer::from(c.cert.der().to_vec()), key: c.key_pair.serialize_der(), pem: c.cert.pem() }
}

fn bind(id: &Ident, alpn: Vec<Vec<u8>>) -> Arc<BindTls> {
    BindTls::single(vec![id.der.clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key.clone())), alpn).expect("bind")
}

fn tmp(name: &str, content: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("ibex-tcp-ctx-{}-{name}", std::process::id()));
    std::fs::write(&p, content).expect("write");
    p
}

fn none() -> BackendTlsOptions {
    BackendTlsOptions { verify_required: false, ..Default::default() }
}

struct Pair {
    srv: TlsCtx,
    sin: VecInput,
    cli: TlsCtx,
    cin: VecInput,
}

impl Pair {
    fn new(bind: Arc<BindTls>, opts: &BackendTlsOptions) -> Self {
        let cfg = build_backend_client_config(opts).expect("client config");
        Self::with(bind, &cfg)
    }
    fn with(bind: Arc<BindTls>, cfg: &Arc<rustls24::ClientConfig>) -> Self {
        let cli = TlsCtx::connect(cfg, ServerName::try_from("localhost").unwrap(), Some("localhost".into()));
        Self { srv: TlsCtx::accept(bind), sin: VecInput::default(), cli, cin: VecInput::default() }
    }
    /// One round: each side's output into the other's input. Whether anything moved.
    fn shuttle(&mut self) -> bool {
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
    fn handshake(&mut self) -> (Result<(), rustls24::Error>, Result<(), rustls24::Error>) {
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
        // The alert of a failure is queued: deliver it.
        self.shuttle();
        (s, c)
    }
}

#[test]
fn every_session_state_has_a_name() {
    let id = ident("localhost");
    let mut p = Pair::new(bind(&id, vec![]), &none());
    assert!(format!("{:?}", p.srv).contains("Session::Hello"));
    assert!(format!("{:?}", p.cli).contains("Session::ClientHs"));
    assert!(p.srv.awaiting_hello());
    // The ClientHello only: the server is in the middle of its handshake.
    p.shuttle();
    p.srv.handshake(&mut p.sin).expect("server step");
    assert!(format!("{:?}", p.srv).contains("Session::ServerHs") || format!("{:?}", p.srv).contains("Session::Server"));
    let (s, c) = p.handshake();
    s.expect("server");
    c.expect("client");
    assert!(format!("{:?}", p.srv).contains("Session::Server"));
    assert!(format!("{:?}", p.cli).contains("Session::Client"));
    // A handshake call on a finished session is a no-op.
    p.srv.handshake(&mut p.sin).expect("again");
    assert!(!p.srv.is_handshaking());
}

fn read_all(ctx: &mut TlsCtx, input: &mut VecInput, dst_len: usize) -> (Vec<u8>, Plain) {
    let mut out = Vec::new();
    let mut dst = vec![0u8; dst_len];
    loop {
        match ctx.read_plain(input, &mut dst).expect("read") {
            Plain::Data(n) => out.extend_from_slice(&dst[..n]),
            other => return (out, other),
        }
    }
}

fn data_both_ways(max_ver: Option<ibex_config::TlsVersion>, version: &str) {
    let id = ident("localhost");
    let opts = BackendTlsOptions { max_ver, ..none() };
    let mut p = Pair::new(bind(&id, vec![]), &opts);
    let (s, c) = p.handshake();
    s.expect("server");
    c.expect("client");
    assert_eq!(p.srv.tls_info.protocol_version.as_deref(), Some(version));
    let local = p.srv.tls_info.local_cert.as_ref().expect("the certificate the hello got");
    assert_eq!(local.leaf(), Some(id.der.as_ref()));
    assert_eq!(p.cli.tls_info.protocol_version.as_deref(), Some(version));

    // Writing before the handshake is over is refused; a finished session takes data.
    let fresh = TlsCtx::accept(bind(&id, vec![]));
    let mut fresh = fresh;
    assert!(fresh.write_plain(b"x").is_err());

    // Larger than one output buffer: the first call takes what fits, a full buffer takes 0.
    let body: Vec<u8> = (0..(TX_CAP * 3)).map(|i| (i % 253) as u8).collect();
    let mut sent = 0;
    let mut got = Vec::new();
    let mut zero_seen = false;
    for _ in 0..1000 {
        for _ in 0..3 {
            let n = p.cli.write_plain(&body[sent..]).expect("write");
            zero_seen |= n == 0 && sent < body.len();
            sent += n;
        }
        // Move half of what is queued first: a partial socket write.
        let half = p.cli.pending_tx().len() / 2;
        if half > 0 {
            let part = p.cli.pending_tx()[..half].to_vec();
            p.cli.tx_done(half);
            p.sin.extend(&part, &p.srv);
        }
        p.shuttle();
        // A 100-byte reader: the rest of each record stays pending in the input.
        let (mut d, _) = read_all(&mut p.srv, &mut p.sin, 100);
        got.append(&mut d);
        if got.len() == body.len() {
            break;
        }
    }
    assert!(zero_seen, "a full output buffer must report 0 bytes taken");
    assert!(got == body, "the body arrived intact");

    // close_notify: the data before it, then Closed; the send side is gone after.
    p.cli.write_plain(b"last").unwrap();
    p.cli.close_notify();
    p.cli.close_notify();
    assert!(p.cli.write_plain(b"more").is_err());
    p.shuttle();
    let (d, end) = read_all(&mut p.srv, &mut p.sin, 1000);
    assert_eq!(d, b"last");
    assert_eq!(end, Plain::Closed);
    assert!(p.srv.peer_closed);
    let (d, end) = read_all(&mut p.srv, &mut p.sin, 1000);
    assert!(d.is_empty());
    assert_eq!(end, Plain::Closed, "a closed receive side reads as closed");
}

#[test]
fn data_flows_in_pieces_on_tls13_and_tls12() {
    data_both_ways(None, "TLSv1.3");
    data_both_ways(Some(ibex_config::TlsVersion::Tls12), "TLSv1.2");
}

#[test]
fn a_garbage_record_after_the_handshake_fails_with_an_alert() {
    let id = ident("localhost");
    let mut p = Pair::new(bind(&id, vec![]), &none());
    let (s, c) = p.handshake();
    s.expect("server");
    c.expect("client");
    // An application-data record that decrypts to nothing.
    let mut junk = vec![0x17, 0x03, 0x03, 0x00, 0x20];
    junk.extend_from_slice(&[0x55; 0x20]);
    p.sin.extend(&junk, &p.srv);
    let mut dst = [0u8; 64];
    assert!(p.srv.read_plain(&mut p.sin, &mut dst).is_err());
    assert!(p.srv.wants_write(), "the alert is queued for the peer");
}

#[test]
fn a_hello_that_is_not_a_hello_fails_the_handshake() {
    let id = ident("localhost");
    let mut srv = TlsCtx::accept(bind(&id, vec![]));
    let mut input = VecInput::default();
    input.extend(b"GET / HTTP/1.1\r\n\r\n", &srv);
    assert!(srv.handshake(&mut input).is_err());
    assert!(!srv.is_handshaking());
    assert!(srv.write_plain(b"x").is_err());
    let mut dst = [0u8; 8];
    assert_eq!(srv.read_plain(&mut input, &mut dst).unwrap(), Plain::More);
}

#[test]
fn a_client_that_does_not_trust_the_server_fails_and_alerts() {
    let id = ident("localhost");
    let other = ident("localhost");
    let ca = tmp("other-ca.pem", &other.pem);
    let opts = BackendTlsOptions { verify_required: true, ca_file: Some(ca.clone()), ..Default::default() };
    let mut p = Pair::new(bind(&id, vec![]), &opts);
    let (_, c) = p.handshake();
    assert!(c.is_err(), "unknown issuer");
    let _ = std::fs::remove_file(ca);
}

#[test]
fn a_verifying_client_with_the_right_ca_completes_and_resumes_by_session_id() {
    let id = ident("localhost");
    let ca = tmp("ca.pem", &id.pem);
    let opts = BackendTlsOptions { verify_required: true, ca_file: Some(ca.clone()), max_ver: Some(ibex_config::TlsVersion::Tls12), ..Default::default() };
    let _ = build_backend_client_config(&opts).expect("verifying config");
    let b = bind(&id, vec![b"h2".to_vec()]);
    let mut p = Pair::new(Arc::clone(&b), &opts);
    let (s, c) = p.handshake();
    s.expect("server");
    c.expect("client");
    assert!(p.cli.tls_info.peer_has_cert);
    assert!(!p.srv.tls_info.session_resumed);

    // Session-ID resumption (no tickets) through the bind's expiring cache.
    let cfg = no_ticket_client(&id);
    for round in 0..2 {
        let mut p = Pair::with(Arc::clone(&b), &cfg);
        let (s, c) = p.handshake();
        s.expect("server");
        c.expect("client");
        assert_eq!(p.srv.tls_info.session_resumed, round == 1, "round {round}");
    }
    let _ = std::fs::remove_file(ca);
}

fn no_ticket_client(id: &Ident) -> Arc<rustls24::ClientConfig> {
    let ca = tmp("ca2.pem", &id.pem);
    let opts = BackendTlsOptions { verify_required: true, ca_file: Some(ca.clone()), max_ver: Some(ibex_config::TlsVersion::Tls12), ..Default::default() };
    let cfg = build_backend_client_config(&opts).expect("cfg");
    let _ = std::fs::remove_file(ca);
    let mut c = (*cfg).clone();
    c.resumption = rustls24::client::Resumption::in_memory_sessions(8).tls12_resumption(rustls24::client::Tls12Resumption::SessionIdOnly);
    Arc::new(c)
}

#[test]
fn backend_options_that_cannot_work_are_refused() {
    let e = build_backend_client_config(&BackendTlsOptions::default()).unwrap_err();
    assert!(e.contains("no CA file"), "{e}");
    let e = build_backend_client_config(&BackendTlsOptions {
        min_ver: Some(ibex_config::TlsVersion::Tls13),
        max_ver: Some(ibex_config::TlsVersion::Tls12),
        ..none()
    })
    .unwrap_err();
    assert!(e.contains("no TLS version is left"), "{e}");
    // no-ssl-reuse: a second connection does not resume the first.
    let id = ident("localhost");
    let b = bind(&id, vec![]);
    let cfg = build_backend_client_config(&BackendTlsOptions { no_reuse: true, ..none() }).expect("no-reuse");
    for _ in 0..2 {
        let mut p = Pair::with(Arc::clone(&b), &cfg);
        let (s, c) = p.handshake();
        s.expect("server");
        c.expect("client");
        assert!(!p.srv.tls_info.session_resumed);
    }
}

#[test]
fn a_bind_whose_key_does_not_match_or_is_not_a_certificate_is_refused() {
    let a = ident("localhost");
    let b = ident("localhost");
    let e = BindTls::single(vec![a.der.clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(b.key.clone())), vec![]).unwrap_err();
    assert!(e.contains("inconsistencies between private key and certificate"), "{e}");
    let e = BindTls::single(vec![], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(a.key.clone())), vec![]).unwrap_err();
    assert!(e.contains("wrong tag"), "{e}");
}

#[test]
fn the_input_reports_what_it_holds_and_the_eof() {
    use rustls24::TlsInputBuffer;
    let srv = TlsCtx::accept(bind(&ident("localhost"), vec![]));
    let mut input = VecInput::default();
    assert!(input.is_empty());
    input.extend(b"abcdef", &srv);
    assert_eq!(input.len(), 6);
    assert!(!input.has_seen_eof());
    input.set_eof();
    assert!(input.has_seen_eof());
    input.discard(4);
    assert_eq!(input.len(), 2);
}

#[test]
fn the_certificate_a_legacy_context_serves_names_its_leaf() {
    let (key, der) = crate::common::generate_test_cert(vec!["localhost".into()]);
    let local = ibex_tls::LocalCert::Legacy(key);
    assert_eq!(local.leaf(), Some(der.as_ref()));
}
