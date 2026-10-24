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

/// A rustls 0.23 client (an implementation independent of the server's split API) for `id`.
fn client23(id: &Ident) -> rustls::ClientConnection {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(id.der.to_vec())).expect("root");
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    rustls::ClientConnection::new(Arc::new(cfg), rustls::pki_types::ServerName::try_from("localhost").unwrap())
        .expect("client")
}

/// Moves the 0.23 client's output to the server and the server's to the client.
fn shuttle23(cli: &mut rustls::ClientConnection, srv: &mut TlsCtx, sin: &mut VecInput) -> bool {
    let mut moved = false;
    let mut out = Vec::new();
    while cli.wants_write() {
        cli.write_tls(&mut out).expect("client write_tls");
    }
    if !out.is_empty() {
        sin.extend(&out, srv);
        moved = true;
    }
    let out = srv.pending_tx().to_vec();
    if !out.is_empty() {
        srv.tx_done(out.len());
        let mut rd = &out[..];
        while !rd.is_empty() {
            cli.read_tls(&mut rd).expect("client read_tls");
            cli.process_new_packets().expect("client process");
        }
        moved = true;
    }
    moved
}

fn client_plain(cli: &mut rustls::ClientConnection) -> Vec<u8> {
    use std::io::Read;
    let mut got = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match cli.reader().read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("client read: {e}"),
        }
    }
    got
}

/// TLS 1.3 `KeyUpdate` from the peer with `update_requested`: the server answers with its own
/// `KeyUpdate` under the old keys, switches its write keys, and what it sends afterwards
/// decrypts at the client (RFC 8446 4.6.3) -- before and after the key change, more than once.
#[test]
fn data_after_a_peer_key_update_reaches_the_peer() {
    use std::io::Write;
    let id = ident("localhost");
    let mut srv = TlsCtx::accept(bind(&id, vec![]));
    let mut sin = VecInput::default();
    let mut cli = client23(&id);
    for _ in 0..30 {
        srv.handshake(&mut sin).expect("server handshake");
        if !shuttle23(&mut cli, &mut srv, &mut sin) && !srv.is_handshaking() && !cli.is_handshaking() {
            break;
        }
    }
    assert!(!srv.is_handshaking() && !cli.is_handshaking());

    for round in 0..3 {
        cli.writer().write_all(b"ping").expect("client write");
        cli.refresh_traffic_keys().expect("client key update");
        cli.writer().write_all(b"after").expect("client write");
        shuttle23(&mut cli, &mut srv, &mut sin);
        let (got, end) = read_all(&mut srv, &mut sin, 64);
        assert_eq!(got, b"pingafter", "round {round}: server reads the client's data across its key update");
        assert_eq!(end, Plain::More);

        let msg = format!("hello {round}");
        assert_eq!(srv.write_plain(msg.as_bytes()).expect("server write"), msg.len());
        shuttle23(&mut cli, &mut srv, &mut sin);
        assert_eq!(client_plain(&mut cli), msg.as_bytes(), "round {round}: the client reads what the server sent after the key update");
    }

    // A KeyUpdate with nothing after it: no data, the answer is queued all the same.
    cli.refresh_traffic_keys().expect("client key update");
    shuttle23(&mut cli, &mut srv, &mut sin);
    let (got, end) = read_all(&mut srv, &mut sin, 64);
    assert_eq!(got, b"");
    assert_eq!(end, Plain::More);
    assert!(srv.wants_write(), "the server's KeyUpdate is queued");
    assert_eq!(srv.write_plain(b"last").expect("server write"), 4);
    shuttle23(&mut cli, &mut srv, &mut sin);
    assert_eq!(client_plain(&mut cli), b"last");
}

/// Application-data records encrypted by hand under the 0.23 client's extracted TLS 1.3 keys
/// (rustls's own writer never sends an empty record; other peers may: RFC 8446 5.4).
fn hand_records(id: &Ident, srv: &mut TlsCtx, sin: &mut VecInput, payloads: &[&[u8]]) -> Vec<u8> {
    use rustls::crypto::cipher::{OutboundChunks, OutboundPlainMessage};
    let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: vec![suite],
        ..rustls::crypto::ring::default_provider()
    };
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(id.der.to_vec())).expect("root");
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.enable_secret_extraction = true;
    let mut cli = rustls::ClientConnection::new(Arc::new(cfg), rustls::pki_types::ServerName::try_from("localhost").unwrap())
        .expect("client");
    for _ in 0..30 {
        srv.handshake(sin).expect("server handshake");
        if !shuttle23(&mut cli, srv, sin) && !srv.is_handshaking() && !cli.is_handshaking() {
            break;
        }
    }
    let (mut seq, secrets) = cli.dangerous_extract_secrets().expect("secrets").tx;
    let rustls::ConnectionTrafficSecrets::Aes128Gcm { key, iv } = secrets else { panic!("suite") };
    let mut enc = suite.tls13().expect("1.3").aead_alg.encrypter(key, iv);
    let mut wire = Vec::new();
    for p in payloads {
        let msg = OutboundPlainMessage {
            typ: rustls::ContentType::ApplicationData,
            version: rustls::ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(p),
        };
        wire.extend_from_slice(&enc.encrypt(msg, seq).expect("encrypt").encode());
        seq += 1;
    }
    wire
}

/// An empty application-data record is skipped, not taken for the end of the input: the
/// records after it in the same input are read without more ciphertext arriving (else a
/// socket reader waits on a socket that has nothing more to give).
#[test]
fn an_empty_record_does_not_hide_the_records_after_it() {
    let id = ident("localhost");
    let mut srv = TlsCtx::accept(bind(&id, vec![]));
    let mut sin = VecInput::default();
    let wire = hand_records(&id, &mut srv, &mut sin, &[b"", b"one", b"", b"", b"two"]);
    sin.extend(&wire, &srv);
    let (got, end) = read_all(&mut srv, &mut sin, 64);
    assert_eq!(got, b"onetwo");
    assert_eq!(end, Plain::More);
    assert!(sin.is_empty(), "every record was consumed");
}

/// An input whose memory stops holding the plaintext a short read left behind (a caller
/// that added bytes to it, against the [`ibex_tls::conn::TlsInput`] contract).
struct Losing {
    inner: VecInput,
    lose: bool,
}

impl rustls24::TlsInputBuffer for Losing {
    fn slice_mut(&mut self) -> &mut [u8] {
        self.inner.slice_mut()
    }
    fn discard(&mut self, n: usize) {
        self.inner.discard(n);
    }
    fn received_close_notify(&mut self) {
        self.inner.received_close_notify();
    }
    fn has_seen_eof(&self) -> bool {
        self.inner.has_seen_eof()
    }
}

impl ibex_tls::conn::TlsInput for Losing {
    fn storage(&self) -> &[u8] {
        if self.lose { &[] } else { self.inner.storage() }
    }
}

/// Plaintext left in an input that no longer holds it is an error, not stale bytes.
#[test]
fn plaintext_the_input_lost_is_an_error() {
    use ibex_tls::conn::TlsInput;
    let id = ident("localhost");
    let mut p = Pair::new(bind(&id, vec![]), &none());
    let (s, c) = p.handshake();
    s.expect("server");
    c.expect("client");
    assert_eq!(p.cli.write_plain(&[7u8; 100]).expect("write"), 100);
    let out = p.cli.pending_tx().to_vec();
    p.cli.tx_done(out.len());
    let mut input = Losing { inner: std::mem::take(&mut p.sin), lose: false };
    input.inner.extend(&out, &p.srv);
    let mut dst = [0u8; 10];
    assert_eq!(p.srv.read_plain(&mut input, &mut dst).expect("read"), Plain::Data(10));
    assert!(p.srv.has_plain());
    assert_ne!(input.storage(), b"");
    input.lose = true;
    let e = p.srv.read_plain(&mut input, &mut dst).expect_err("lost");
    assert!(e.to_string().contains("lost plaintext"), "{e}");
    assert!(!p.srv.has_plain());
}

/// TLS 1.3 resumption without a ticketer: rustls keeps the session in the bind's store and
/// takes it back (single use) when the ticket comes back.
#[test]
fn a_bind_without_a_ticketer_resumes_from_its_session_store_once_per_ticket() {
    let id = ident("localhost");
    let b = bind(&id, vec![]);
    let mut cfg = (*b.config).clone();
    cfg.ticketer = None;
    let cfg = Arc::new(cfg);
    let b = Arc::new(BindTls { config: Arc::clone(&cfg), no_alpn: cfg, resolver: Arc::clone(&b.resolver) });
    let ca = tmp("ca3.pem", &id.pem);
    let opts = BackendTlsOptions { verify_required: true, ca_file: Some(ca.clone()), ..Default::default() };
    let client = build_backend_client_config(&opts).expect("cfg");
    let _ = std::fs::remove_file(ca);
    let mut c = (*client).clone();
    c.resumption = rustls24::client::Resumption::in_memory_sessions(8);
    let client = Arc::new(c);
    for round in 0..2 {
        let mut p = Pair::with(Arc::clone(&b), &client);
        let (s, c) = p.handshake();
        s.expect("server");
        c.expect("client");
        assert_eq!(p.srv.tls_info.protocol_version.as_deref(), Some("TLSv1.3"));
        assert_eq!(p.srv.tls_info.session_resumed, round == 1, "round {round}");
        // The client takes the tickets the server sent after its Finished.
        p.shuttle();
        let _ = read_all(&mut p.cli, &mut p.cin, 64);
    }
}

/// A name no certificate of the bind covers gets the default one.
#[test]
fn an_sni_no_certificate_matches_gets_the_default() {
    let id = ident("localhost");
    let cfg = build_backend_client_config(&none()).expect("client config");
    let cli = TlsCtx::connect(&cfg, ServerName::try_from("other.example").unwrap(), Some("other.example".into()));
    let mut p = Pair { srv: TlsCtx::accept(bind(&id, vec![])), sin: VecInput::default(), cli, cin: VecInput::default() };
    let (s, c) = p.handshake();
    s.expect("server");
    c.expect("client");
    assert_eq!(p.srv.tls_info.sni.as_deref(), Some("other.example"));
    assert_eq!(p.srv.tls_info.local_cert.as_ref().and_then(|l| l.leaf()), Some(id.der.as_ref()));
}

/// A leaf that is not a certificate is refused when the bind is built.
#[test]
fn a_bind_whose_leaf_does_not_parse_is_refused() {
    let id = ident("localhost");
    let junk = CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x00]);
    let e = BindTls::single(vec![junk], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key.clone())), vec![]).unwrap_err();
    assert!(e.contains("wrong tag"), "{e}");
}
