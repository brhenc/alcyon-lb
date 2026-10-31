// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T534: the client half of Ibex's quinn adapter on rustls 0.24 (`ibex_quic::crypto::client`).
//!
//! An Ibex client against an Ibex server, both quinn-proto endpoints with no rustls 0.23 in
//! them, in memory: the handshake, a request on a bidirectional stream, a key update each way,
//! an untrusted certificate. Then the same client against the QUIC oracle
//! (`~/reference/haproxy-quic-dev10/haproxy`, `HAProxy` 3.5-dev10-38e65c-10, `OpenSSL` 3.5.9) on a
//! `quic4@` bind, over UDP: an h3 GET answered `200` with the body of a `http-request return`.
//! Both providers each time (`tune.ibex.crypto-provider`).

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use ibex_config::TlsCryptoProvider;
use ibex_quic::crypto::{HandshakeData, QuicClientConfig, QuicServerConfig, ResetKey, TokenKey};
use ibex_tls::tcp::rustls24::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use quinn_proto::{
    ConnectionError, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig, Event,
    StreamEvent, TransportErrorCode,
};

const CLIENT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50001);
const SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50002);

/// A self-signed (not CA) certificate for `localhost`, and its key.
struct Cert {
    der: CertificateDer<'static>,
    key: rcgen::KeyPair,
    pem: String,
}

fn new_cert() -> Cert {
    let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let pem = format!("{}{}", c.cert.pem(), c.key_pair.serialize_pem());
    Cert { der: CertificateDer::from(c.cert.der().to_vec()), key: c.key_pair, pem }
}

/// A self-signed certificate for `localhost` whose subject is `cn`: not the issuer of
/// [`new_cert`]'s (whose subject is rcgen's default), so a chain to it is not found at all.
fn other_cert(cn: &str) -> CertificateDer<'static> {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    let key = rcgen::KeyPair::generate().expect("key");
    CertificateDer::from(params.self_signed(&key).expect("cert").der().to_vec())
}

fn roots(der: &CertificateDer<'static>) -> ibex_tls::tcp::rustls24::RootCertStore {
    let mut roots = ibex_tls::tcp::rustls24::RootCertStore::empty();
    roots.add(der.clone()).expect("trust the test certificate");
    roots
}

fn endpoint_config() -> Arc<EndpointConfig> {
    Arc::new(EndpointConfig::new(Arc::new(ResetKey::new().expect("reset key"))))
}

fn client_endpoint() -> Endpoint {
    Endpoint::new(endpoint_config(), None, false, None)
}

fn server_endpoint(cert: &Cert, p: TlsCryptoProvider) -> Endpoint {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key.serialize_der()));
    let bind = ibex_tls::tcp::BindTls::single_with(vec![cert.der.clone()], key, vec![b"h3".to_vec()], p).expect("bind");
    let crypto = Arc::new(QuicServerConfig::new(bind).expect("server crypto"));
    let server = quinn_proto::ServerConfig::new(crypto, Arc::new(TokenKey::new().expect("token key")));
    Endpoint::new(endpoint_config(), Some(Arc::new(server)), true, None)
}

/// A client and a server endpoint, one connection between them, and the datagrams in memory.
struct Pair {
    now: Instant,
    cep: Endpoint,
    sep: Endpoint,
    ch: ConnectionHandle,
    client: quinn_proto::Connection,
    server: Option<(ConnectionHandle, quinn_proto::Connection)>,
    client_events: Vec<Event>,
    server_events: Vec<Event>,
}

impl Pair {
    fn new(cert: &Cert, p: TlsCryptoProvider, client: QuicClientConfig) -> Self {
        Self::with_name(cert, p, client, "localhost")
    }

    fn with_name(cert: &Cert, p: TlsCryptoProvider, client: QuicClientConfig, name: &str) -> Self {
        let now = Instant::now();
        let mut cep = client_endpoint();
        let config = quinn_proto::ClientConfig::new(Arc::new(client));
        let (ch, client) = cep.connect(now, config, SERVER, name).expect("connect");
        Self { now, cep, sep: server_endpoint(cert, p), ch, client, server: None, client_events: Vec::new(), server_events: Vec::new() }
    }

    fn deliver_to_server(&mut self, data: &[u8]) {
        let mut buf = Vec::new();
        match self.sep.handle(self.now, CLIENT, None, None, BytesMut::from(data), &mut buf) {
            Some(DatagramEvent::NewConnection(incoming)) => {
                let mut resp = Vec::new();
                let accepted = self.sep.accept(incoming, self.now, &mut resp, None).expect("accept");
                self.server = Some(accepted);
            }
            Some(DatagramEvent::ConnectionEvent(h, ev)) => {
                if let Some((sh, conn)) = self.server.as_mut() {
                    assert_eq!(*sh, h);
                    conn.handle_event(ev);
                }
            }
            Some(DatagramEvent::Response(t)) => self.deliver_to_client(&buf[..t.size]),
            None => {}
        }
    }

    fn deliver_to_client(&mut self, data: &[u8]) {
        let mut buf = Vec::new();
        if let Some(DatagramEvent::ConnectionEvent(h, ev)) = self.cep.handle(self.now, SERVER, None, None, BytesMut::from(data), &mut buf) {
            assert_eq!(h, self.ch);
            self.client.handle_event(ev);
        }
    }

    /// One round: every datagram each side has, timers, endpoint events, application events.
    fn step(&mut self) {
        self.now += Duration::from_millis(1);
        let mut buf = Vec::new();
        while let Some(t) = self.client.poll_transmit(self.now, 1, &mut buf) {
            let d = buf[..t.size].to_vec();
            buf.clear();
            self.deliver_to_server(&d);
        }
        if let Some((_, server)) = self.server.as_mut() {
            let mut out = Vec::new();
            let mut datagrams = Vec::new();
            while let Some(t) = server.poll_transmit(self.now, 1, &mut out) {
                datagrams.push(out[..t.size].to_vec());
                out.clear();
            }
            for d in datagrams {
                self.deliver_to_client(&d);
            }
        }
        if self.client.poll_timeout().is_some_and(|t| t <= self.now) {
            self.client.handle_timeout(self.now);
        }
        while let Some(ev) = self.client.poll_endpoint_events() {
            if let Some(ce) = self.cep.handle_event(self.ch, ev) {
                self.client.handle_event(ce);
            }
        }
        while let Some(ev) = self.client.poll() {
            self.client_events.push(ev);
        }
        if let Some((sh, server)) = self.server.as_mut() {
            if server.poll_timeout().is_some_and(|t| t <= self.now) {
                server.handle_timeout(self.now);
            }
            while let Some(ev) = server.poll_endpoint_events() {
                if let Some(ce) = self.sep.handle_event(*sh, ev) {
                    server.handle_event(ce);
                }
            }
            while let Some(ev) = server.poll() {
                self.server_events.push(ev);
            }
        }
    }

    fn run_until(&mut self, what: &str, mut done: impl FnMut(&Self) -> bool) {
        for _ in 0..400 {
            if done(self) {
                return;
            }
            self.step();
        }
        assert!(done(self), "{what}: not after 400 rounds; client events {:?}, server events {:?}", self.client_events, self.server_events);
    }

    fn connected(&self) -> bool {
        self.client_events.iter().any(|e| matches!(e, Event::Connected))
            && self.server_events.iter().any(|e| matches!(e, Event::Connected))
    }

    fn server(&mut self) -> &mut quinn_proto::Connection {
        &mut self.server.as_mut().expect("server connection").1
    }

    /// Sends `data` on a new bidirectional stream from the client and has the server answer
    /// `answer` on it: what each side read.
    fn exchange(&mut self, data: &[u8], answer: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let id = self.client.streams().open(Dir::Bi).expect("open a stream");
        self.client.send_stream(id).write(data).expect("write");
        self.client.send_stream(id).finish().expect("finish");
        let mut got = Vec::new();
        self.run_until("the server takes the stream", |p| p.server_events.iter().any(|e| matches!(e, Event::Stream(StreamEvent::Opened { dir: Dir::Bi }))));
        self.server_events.retain(|e| !matches!(e, Event::Stream(StreamEvent::Opened { dir: Dir::Bi })));
        let sid = self.server().streams().accept(Dir::Bi).expect("the client's stream");
        assert_eq!(sid, id);
        for _ in 0..50 {
            if let Ok(mut chunks) = self.server().recv_stream(sid).read(true) {
                while let Ok(Some(c)) = chunks.next(usize::MAX) {
                    got.extend_from_slice(&c.bytes);
                }
                let _ = chunks.finalize();
            }
            if got.len() >= data.len() {
                break;
            }
            self.step();
        }
        self.server().send_stream(sid).write(answer).expect("answer");
        self.server().send_stream(sid).finish().expect("finish the answer");
        let mut back = Vec::new();
        for _ in 0..50 {
            self.step();
            if let Ok(mut chunks) = self.client.recv_stream(id).read(true) {
                while let Ok(Some(c)) = chunks.next(usize::MAX) {
                    back.extend_from_slice(&c.bytes);
                }
                let _ = chunks.finalize();
            }
            if back.len() >= answer.len() {
                break;
            }
        }
        (got, back)
    }
}

/// The transport error a connection was lost to, if that is what it was lost to.
fn transport_error(reason: Option<&ConnectionError>) -> Option<quinn_proto::TransportError> {
    if let Some(ConnectionError::TransportError(e)) = reason { Some(e.clone()) } else { None }
}

fn handshake_data(conn: &quinn_proto::Connection) -> HandshakeData {
    let hd = conn.crypto_session().handshake_data().expect("handshake data");
    hd.downcast_ref::<HandshakeData>().expect("ibex's handshake data").clone()
}

#[test]
fn an_ibex_client_and_server_agree_on_h3_and_carry_a_request_on_both_providers() {
    for p in TlsCryptoProvider::ALL {
        let cert = new_cert();
        let client = QuicClientConfig::with_roots(roots(&cert.der), &[b"h3"], p).expect("client config");
        let mut pair = Pair::new(&cert, p, client);
        pair.run_until("the handshake", Pair::connected);

        let c = handshake_data(&pair.client);
        assert_eq!(c.protocol.as_deref(), Some(&b"h3"[..]), "{p:?}");
        assert_eq!(c.server_name.as_deref(), Some("localhost"), "the name the client asked for");
        assert_eq!(c.provider, Some(p));
        let s = handshake_data(pair.server());
        assert_eq!(s.server_name.as_deref(), Some("localhost"), "the SNI the client sent");
        assert_eq!(s.protocol.as_deref(), Some(&b"h3"[..]));

        // The client knows the server by its certificate; the server asked for none.
        let id = pair.client.crypto_session().peer_identity().expect("the server's certificate");
        let chain = id.downcast_ref::<Vec<CertificateDer<'static>>>().expect("a certificate chain");
        assert_eq!(chain.first(), Some(&cert.der));
        assert!(pair.server().crypto_session().peer_identity().is_none());
        assert!(!pair.client.crypto_session().is_handshaking());
        assert_eq!(pair.client.crypto_session().early_data_accepted(), Some(false), "no 0-RTT offered");

        // Both ends export the same keying material.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        pair.client.crypto_session().export_keying_material(&mut a, b"EXPERIMENTAL ibex", b"t534").expect("client exporter");
        pair.server().crypto_session().export_keying_material(&mut b, b"EXPERIMENTAL ibex", b"t534").expect("server exporter");
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 32]);

        let (got, back) = pair.exchange(b"GET / HTTP/3", b"200 ok");
        assert_eq!(got, b"GET / HTTP/3", "{p:?}");
        assert_eq!(back, b"200 ok", "{p:?}");
    }
}

#[test]
fn a_key_update_from_either_side_crosses_and_the_streams_go_on() {
    for p in TlsCryptoProvider::ALL {
        let cert = new_cert();
        let client = QuicClientConfig::with_roots(roots(&cert.der), &[b"h3"], p).expect("client config");
        let mut pair = Pair::new(&cert, p, client);
        pair.run_until("the handshake", Pair::connected);
        // Let the handshake confirm (HANDSHAKE_DONE) before changing keys.
        for _ in 0..20 {
            pair.step();
        }
        pair.client.force_key_update();
        let (got, back) = pair.exchange(b"after the client's update", b"answered");
        assert_eq!((got.as_slice(), back.as_slice()), (&b"after the client's update"[..], &b"answered"[..]), "{p:?}");
        pair.server().force_key_update();
        let (got, back) = pair.exchange(b"after the server's update", b"answered again");
        assert_eq!((got.as_slice(), back.as_slice()), (&b"after the server's update"[..], &b"answered again"[..]), "{p:?}");
        pair.client.force_key_update();
        let (got, back) = pair.exchange(b"third phase", b"still");
        assert_eq!((got.as_slice(), back.as_slice()), (&b"third phase"[..], &b"still"[..]), "{p:?}");
        assert!(pair.client_events.iter().all(|e| !matches!(e, Event::ConnectionLost { .. })), "{:?}", pair.client_events);
    }
}

/// RFC 9001 4.8: a TLS alert is the QUIC error `0x100 + alert`. An unverifiable chain is
/// `unknown_ca` (48), as OpenSSL's client sends for a self-signed certificate it does not
/// trust (`X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT` maps to `SSL_AD_UNKNOWN_CA`).
#[test]
fn a_server_certificate_the_client_does_not_trust_closes_with_crypto_error_unknown_ca() {
    for p in TlsCryptoProvider::ALL {
        let cert = new_cert();
        let client = QuicClientConfig::with_roots(roots(&other_cert("ibex t534 other")), &[b"h3"], p).expect("client config");
        let mut pair = Pair::new(&cert, p, client);
        pair.run_until("the client gives up", |p| p.client_events.iter().any(|e| matches!(e, Event::ConnectionLost { .. })));
        let reason = pair.client_events.iter().find_map(|e| if let Event::ConnectionLost { reason } = e { Some(reason.clone()) } else { None });
        let e = transport_error(reason.as_ref());
        assert!(e.is_some(), "{p:?}: lost to {reason:?}");
        let e = e.expect("a transport error");
        assert_eq!(e.code, TransportErrorCode::crypto(48), "{p:?}: {e}");
        pair.run_until("the server is told", |p| p.server_events.iter().any(|e| matches!(e, Event::ConnectionLost { .. })));
        let reason = pair.server_events.iter().find_map(|e| if let Event::ConnectionLost { reason } = e { Some(reason.clone()) } else { None });
        let close = if let Some(ConnectionError::ConnectionClosed(c)) = &reason { Some(c.clone()) } else { None };
        assert!(close.is_some(), "{p:?}: lost to {reason:?}");
        let close = close.expect("a close from the peer");
        assert_eq!(close.error_code, TransportErrorCode::crypto(48), "{p:?}");
    }
}

#[test]
fn a_name_the_certificate_does_not_cover_is_refused_and_verify_none_takes_it() {
    let cert = new_cert();
    let p = TlsCryptoProvider::Ring;
    // The certificate is for `localhost`.
    let client = QuicClientConfig::with_roots(roots(&cert.der), &[b"h3"], p).expect("client config");
    let mut pair = Pair::with_name(&cert, p, client, "example.com");
    pair.run_until("the client gives up", |p| p.client_events.iter().any(|e| matches!(e, Event::ConnectionLost { .. })));
    let reason = pair.client_events.iter().find_map(|e| if let Event::ConnectionLost { reason } = e { Some(reason.clone()) } else { None });
    let e = transport_error(reason.as_ref());
    assert!(e.is_some(), "lost to {reason:?}");
    let e = e.expect("a transport error");
    // `NotValidForName` is `bad_certificate` (42).
    assert_eq!(e.code, TransportErrorCode::crypto(42), "{e}");

    // `verify none`: any certificate, any name.
    let mut pair = Pair::new(&cert, p, QuicClientConfig::without_verification(&[b"h3"], p).expect("client"));
    pair.run_until("the handshake", Pair::connected);
}

#[test]
fn early_data_is_never_offered() {
    let cert = new_cert();
    let p = TlsCryptoProvider::Ring;
    let mut base = (**QuicClientConfig::with_roots(roots(&cert.der), &[b"h3"], p).expect("client").config()).clone();
    base.enable_early_data = true;
    let client = QuicClientConfig::new(Arc::new(base), p).expect("client config");
    assert!(!client.config().enable_early_data, "0-RTT is turned off in the configuration a session starts on");
    let mut pair = Pair::new(&cert, p, client);
    assert!(pair.client.crypto_session().early_crypto().is_none());
    pair.run_until("the handshake", Pair::connected);
    assert_eq!(pair.client.crypto_session().early_data_accepted(), Some(false));
}

#[test]
fn a_configuration_without_tls13_quic_suites_is_refused() {
    let p = ibex_tls::provider::of(TlsCryptoProvider::Ring, true, false);
    let c = ibex_tls::tcp::rustls24::ClientConfig::builder(p)
        .with_root_certificates(roots(&new_cert().der))
        .with_no_client_auth()
        .expect("a TLS 1.2 client");
    let e = QuicClientConfig::new(Arc::new(c), TlsCryptoProvider::Ring).expect_err("refused");
    assert_eq!(e, "QUIC requires TLS 1.3 cipher suites with a QUIC algorithm");
}

#[test]
fn a_server_name_that_is_not_a_name_is_refused_at_connect() {
    let client = QuicClientConfig::without_verification(&[b"h3"], TlsCryptoProvider::Ring).expect("client");
    let mut ep = client_endpoint();
    let e = ep.connect(Instant::now(), quinn_proto::ClientConfig::new(Arc::new(client)), SERVER, "not a name!").expect_err("refused");
    assert!(matches!(e, quinn_proto::ConnectError::InvalidServerName(ref n) if n == "not a name!"), "{e:?}");
}

// --- Against the QUIC oracle ---------------------------------------------------------------

const HAPROXY: &str = "reference/haproxy-quic-dev10/haproxy";

/// A `haproxy` process, stopped by PID when dropped, and its scratch directory.
struct Oracle(std::process::Child, std::path::PathBuf);

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn oracle(cert: &Cert, port: u16) -> Oracle {
    let dir = std::env::temp_dir().join(format!("ibex-t534-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let pem = dir.join("cert.pem");
    std::fs::write(&pem, &cert.pem).expect("write cert");
    let cfg = dir.join("haproxy.cfg");
    std::fs::write(
        &cfg,
        format!(
            "global\n    nbthread 1\n\ndefaults\n    mode http\n    timeout client 5s\n    timeout server 5s\n    timeout connect 5s\n\n\
             frontend fe\n    bind quic4@127.0.0.1:{port} ssl crt {} alpn h3\n    http-request return status 200 content-type text/plain string \"t534 ok\"\n",
            pem.display()
        ),
    )
    .expect("write config");
    let home = std::env::var("HOME").expect("HOME");
    let bin = std::path::Path::new(&home).join(HAPROXY);
    assert!(bin.exists(), "this test needs the QUIC oracle at {}; it fails rather than skips", bin.display());
    let child = std::process::Command::new(bin)
        .arg("-db")
        .arg("-f")
        .arg(&cfg)
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("start haproxy");
    // Not a wait for readiness: an Initial sent before the bind is up is sent again (PTO).
    std::thread::sleep(Duration::from_millis(200));
    Oracle(child, dir)
}

/// A QUIC variable-length integer (RFC 9000 16).
fn varint(v: u64, out: &mut Vec<u8>) {
    match v {
        0..=63 => out.push(u8::try_from(v).expect("small")),
        64..=16383 => out.extend_from_slice(&(u16::try_from(v).expect("u16") | 0x4000).to_be_bytes()),
        _ => out.extend_from_slice(&(u32::try_from(v).expect("u32") | 0x8000_0000).to_be_bytes()),
    }
}

fn read_varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let n = 1usize << (first >> 6);
    if b.len() < n {
        return None;
    }
    let mut v = u64::from(first & 0x3f);
    for x in &b[1..n] {
        v = (v << 8) | u64::from(*x);
    }
    Some((v, n))
}

/// An h3 GET of `/` for `localhost`: one HEADERS frame, QPACK with the static table only.
fn h3_get() -> Vec<u8> {
    let mut block = vec![0x00, 0x00]; // Required Insert Count 0, Base 0.
    block.push(0xc0 | 0x11); // :method GET (static 17)
    block.push(0xc0 | 0x17); // :scheme https (static 23)
    block.push(0xc0 | 0x01); // :path / (static 1)
    block.push(0x50); // :authority, a literal value
    block.push(9);
    block.extend_from_slice(b"localhost");
    let mut frame = vec![0x01];
    varint(block.len() as u64, &mut frame);
    frame.extend_from_slice(&block);
    frame
}

/// The frames (type, payload) of an h3 request stream.
fn h3_frames(mut b: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut out = Vec::new();
    while let Some((t, n)) = read_varint(b) {
        let Some((len, m)) = read_varint(&b[n..]) else { break };
        let start = n + m;
        let end = start + usize::try_from(len).expect("len");
        if b.len() < end {
            break;
        }
        out.push((t, b[start..end].to_vec()));
        b = &b[end..];
    }
    out
}

/// One connection to `server` over UDP, driven until `done` or 5 s.
struct UdpClient {
    sock: UdpSocket,
    ep: Endpoint,
    ch: ConnectionHandle,
    conn: quinn_proto::Connection,
    server: SocketAddr,
    events: Vec<Event>,
}

impl UdpClient {
    fn new(server: SocketAddr, client: QuicClientConfig) -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("client socket");
        sock.set_read_timeout(Some(Duration::from_millis(5))).expect("timeout");
        let mut ep = client_endpoint();
        let (ch, conn) = ep.connect(Instant::now(), quinn_proto::ClientConfig::new(Arc::new(client)), server, "localhost").expect("connect");
        Self { sock, ep, ch, conn, server, events: Vec::new() }
    }

    fn drive(&mut self, what: &str, mut done: impl FnMut(&mut Self) -> bool) {
        let start = Instant::now();
        let mut buf = Vec::new();
        let mut rx = vec![0u8; 65535];
        while start.elapsed() < Duration::from_secs(5) {
            if done(self) {
                return;
            }
            let now = Instant::now();
            while let Some(t) = self.conn.poll_transmit(now, 1, &mut buf) {
                self.sock.send_to(&buf[..t.size], self.server).expect("send");
                buf.clear();
            }
            if let Ok((n, from)) = self.sock.recv_from(&mut rx) {
                let mut resp = Vec::new();
                if let Some(DatagramEvent::ConnectionEvent(h, ev)) = self.ep.handle(Instant::now(), from, None, None, BytesMut::from(&rx[..n]), &mut resp) {
                    assert_eq!(h, self.ch);
                    self.conn.handle_event(ev);
                }
            }
            let now = Instant::now();
            if self.conn.poll_timeout().is_some_and(|t| t <= now) {
                self.conn.handle_timeout(now);
            }
            while let Some(ev) = self.conn.poll_endpoint_events() {
                if let Some(ce) = self.ep.handle_event(self.ch, ev) {
                    self.conn.handle_event(ce);
                }
            }
            while let Some(ev) = self.conn.poll() {
                self.events.push(ev);
            }
        }
        assert!(done(self), "{what}: not within 5 s; events {:?}", self.events);
    }

    fn lost(&self) -> Option<ConnectionError> {
        self.events.iter().find_map(|e| if let Event::ConnectionLost { reason } = e { Some(reason.clone()) } else { None })
    }
}

#[test]
fn an_ibex_client_gets_an_h3_answer_from_the_haproxy_quic_oracle_on_both_providers() {
    let cert = new_cert();
    let port = 63534;
    let _oracle = oracle(&cert, port);
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    for p in TlsCryptoProvider::ALL {
        let mut c = UdpClient::new(server, QuicClientConfig::with_roots(roots(&cert.der), &[b"h3"], p).expect("client"));
        c.drive("the handshake with HAProxy", |c| c.events.iter().any(|e| matches!(e, Event::Connected)) || c.lost().is_some());
        assert!(c.lost().is_none(), "{p:?}: {:?}", c.lost());
        assert_eq!(handshake_data(&c.conn).protocol.as_deref(), Some(&b"h3"[..]));

        // The control stream (type 0, an empty SETTINGS), then the request.
        let ctrl = c.conn.streams().open(Dir::Uni).expect("control stream");
        c.conn.send_stream(ctrl).write(&[0x00, 0x04, 0x00]).expect("settings");
        let id = c.conn.streams().open(Dir::Bi).expect("request stream");
        c.conn.send_stream(id).write(&h3_get()).expect("request");
        c.conn.send_stream(id).finish().expect("finish");
        let mut resp = Vec::new();
        let mut fin = false;
        c.drive("the h3 answer", |c| {
            if let Ok(mut chunks) = c.conn.recv_stream(id).read(true) {
                loop {
                    match chunks.next(usize::MAX) {
                        Ok(Some(ch)) => resp.extend_from_slice(&ch.bytes),
                        Ok(None) => {
                            fin = true;
                            break;
                        }
                        Err(_) => break,
                    }
                }
                let _ = chunks.finalize();
            }
            fin || c.lost().is_some()
        });
        assert!(c.lost().is_none(), "{p:?}: {:?}", c.lost());
        let frames = h3_frames(&resp);
        let headers = frames.iter().find(|(t, _)| *t == 0x01).expect("a HEADERS frame");
        // `:status 200` is static entry 25 (0x19), an indexed field line.
        assert!(headers.1.len() > 2 && headers.1[2] == (0xc0 | 0x19), "{p:?}: {:02x?}", headers.1);
        let body: Vec<u8> = frames.iter().filter(|(t, _)| *t == 0x00).flat_map(|(_, d)| d.clone()).collect();
        assert_eq!(body, b"t534 ok", "{p:?}");

        // A key update, then a second request on the new keys.
        c.conn.force_key_update();
        let id = c.conn.streams().open(Dir::Bi).expect("request stream");
        c.conn.send_stream(id).write(&h3_get()).expect("request");
        c.conn.send_stream(id).finish().expect("finish");
        let mut resp = Vec::new();
        let mut fin = false;
        c.drive("the h3 answer after the key update", |c| {
            if let Ok(mut chunks) = c.conn.recv_stream(id).read(true) {
                loop {
                    match chunks.next(usize::MAX) {
                        Ok(Some(ch)) => resp.extend_from_slice(&ch.bytes),
                        Ok(None) => {
                            fin = true;
                            break;
                        }
                        Err(_) => break,
                    }
                }
                let _ = chunks.finalize();
            }
            fin || c.lost().is_some()
        });
        assert!(c.lost().is_none(), "{p:?} after the key update: {:?}", c.lost());
        let body: Vec<u8> = h3_frames(&resp).iter().filter(|(t, _)| *t == 0x00).flat_map(|(_, d)| d.clone()).collect();
        assert_eq!(body, b"t534 ok", "{p:?} after the key update");
        c.conn.close(Instant::now(), quinn_proto::VarInt::from_u32(0x100), Bytes::new());
        let mut buf = Vec::new();
        while let Some(t) = c.conn.poll_transmit(Instant::now(), 1, &mut buf) {
            let _ = c.sock.send_to(&buf[..t.size], server);
            buf.clear();
        }
    }
}

#[test]
fn the_haproxy_oracle_with_an_untrusted_certificate_is_refused_with_unknown_ca() {
    let cert = new_cert();
    let port = 63535;
    let _oracle = oracle(&cert, port);
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let mut c = UdpClient::new(server, QuicClientConfig::with_roots(roots(&other_cert("ibex t534 other")), &[b"h3"], TlsCryptoProvider::Ring).expect("client"));
    c.drive("the refusal", |c| c.lost().is_some());
    let reason = c.lost();
    let e = transport_error(reason.as_ref());
    assert!(e.is_some(), "lost to {reason:?}");
    let e = e.expect("a transport error");
    assert_eq!(e.code, TransportErrorCode::crypto(48), "{e}");
}
