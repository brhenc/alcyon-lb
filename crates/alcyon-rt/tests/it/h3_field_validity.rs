// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T454: an HTTP/3 field with a byte that is not UTF-8 is a message error on its stream, not
//! a QPACK decompression failure that closes the connection (the HTTP/3 twin of T451, see
//! `h2_field_validity`).
//!
//! Every expected value was measured on `HAProxy` 3.5-dev7 built with QUIC
//! (`/home/bhenc/reference/haproxy-quic/haproxy`; the usual oracle has no QUIC), with a raw
//! HTTP/3 client (aioquic 1.3.0, hand-built QPACK blocks, one fresh QUIC connection):
//!
//! | input | `HAProxy` |
//! |---|---|
//! | name `x-\xe9`, literal | RESET_STREAM `H3_MESSAGE_ERROR` (0x10e), server not contacted |
//! | the same name, Huffman | the same |
//! | value `a\xe9b` | forwarded byte for byte |
//! | `:path` `/a\xe9b` | forwarded byte for byte |
//! | a second request on the same connection after the first | answered 200 |
//!
//! Alcyon refuses the path (stream reset 0x10e), as it does on HTTP/2 (`tradeoff.md` 6.24);
//! the value is forwarded on the mux path since E1 and refused on the relay path. What is
//! tested for a refused row is that the stream, not the connection, is refused, and that the
//! next request on the connection is served.

use crate::common;

use alcyon_quic::quinn_proto::{
    crypto::rustls::QuicClientConfig, ClientConfig, Connection, ConnectionHandle, Dir, Endpoint, EndpointConfig,
    StreamId,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

#[derive(Debug)]
struct Any;
impl ServerCertVerifier for Any {
    fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}


/// The head of each request the backend received.
type Heads = Arc<Mutex<Vec<Vec<u8>>>>;

/// A backend that records each request head and answers `200`.
fn backend() -> (SocketAddr, Heads) {
    let ls = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = ls.local_addr().expect("addr");
    let heads: Heads = Arc::default();
    let h2 = Arc::clone(&heads);
    thread::spawn(move || {
        for s in ls.incoming() {
            let Ok(mut s) = s else { continue };
            let h3 = Arc::clone(&h2);
            thread::spawn(move || {
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                h3.lock().unwrap().push(got);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
                thread::sleep(Duration::from_millis(100));
            });
        }
    });
    (addr, heads)
}

struct Alcyon {
    child: Child,
    quic: SocketAddr,
    _cfg: NamedTempFile,
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn alcyon(be: SocketAddr) -> Alcyon {
    let tcp = common::reserve_addr();
    let quic = common::reserve_addr();
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let mut cfg = NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "global\n    nbthread 1\ndefaults\n    mode http\n    timeout client 3s\n    timeout server 3s\n    \
         timeout connect 1s\nfrontend f\n    bind {tcp}\n    bind quic4@{quic} ssl crt {crt} alpn h3\n    \
         default_backend b\nbackend b\n    http-reuse never\n    server s {be}\n"
    )
    .expect("write cfg");
    let child = common::alcyon_command(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    assert!(common::wait_listening(tcp), "alcyon never listened");
    Alcyon { child, quic, _cfg: cfg }
}

/// One QUIC connection to `alcyon`, driven by hand.
struct Client {
    sock: UdpSocket,
    ep: Endpoint,
    handle: ConnectionHandle,
    conn: Connection,
    buf: Vec<u8>,
    lost: Option<String>,
}

impl Client {
    fn connect(server: SocketAddr) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut ctls = rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(Any)).with_no_client_auth();
        ctls.alpn_protocols = vec![b"h3".to_vec()];
        let client_cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(ctls).expect("client config")));
        let sock = UdpSocket::bind("127.0.0.1:0").expect("client socket");
        sock.set_nonblocking(true).expect("nonblocking");
        let mut ep = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
        let (handle, conn) = ep.connect(Instant::now(), client_cfg, server, "localhost").expect("connect");
        let mut c = Self { sock, ep, handle, conn, buf: vec![0u8; 65536], lost: None };
        assert!(c.run_until(|c| !c.conn.is_handshaking()), "no handshake");
        c
    }

    fn step(&mut self) {
        let now = Instant::now();
        let mut out = Vec::new();
        while let Some(t) = self.conn.poll_transmit(now, 1, &mut out) {
            let _ = self.sock.send_to(&out[..t.size], t.destination);
            out.clear();
        }
        thread::sleep(Duration::from_millis(2));
        let now = Instant::now();
        while let Ok((n, from)) = self.sock.recv_from(&mut self.buf) {
            let mut resp = Vec::new();
            if let Some(alcyon_quic::quinn_proto::DatagramEvent::ConnectionEvent(_, e)) =
                self.ep.handle(now, from, None, None, self.buf[..n].into(), &mut resp)
            {
                self.conn.handle_event(e);
            }
        }
        if self.conn.poll_timeout().is_some_and(|t| t <= now) {
            self.conn.handle_timeout(now);
        }
        while let Some(e) = self.conn.poll_endpoint_events() {
            if let Some(ce) = self.ep.handle_event(self.handle, e) {
                self.conn.handle_event(ce);
            }
        }
        while let Some(e) = self.conn.poll() {
            if let alcyon_quic::quinn_proto::Event::ConnectionLost { reason } = e {
                self.lost = Some(format!("{reason}"));
            }
        }
    }

    fn run_until(&mut self, mut done: impl FnMut(&mut Self) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline {
            self.step();
            if done(self) {
                return true;
            }
        }
        false
    }

    fn open(&mut self, bytes: &[u8]) -> StreamId {
        let id = self.conn.streams().open(Dir::Bi).expect("open");
        let mut s = self.conn.send_stream(id);
        assert_eq!(s.write(bytes).expect("write"), bytes.len());
        s.finish().expect("finish");
        id
    }

    /// How the stream `id` ended: the response bytes, the code of a reset if it was reset.
    fn outcome(&mut self, id: StreamId) -> Outcome {
        let mut all = Vec::new();
        let mut reset = None;
        self.run_until(|c| {
            if c.lost.is_some() {
                return true;
            }
            let mut rs = c.conn.recv_stream(id);
            let Ok(mut chunks) = rs.read(true) else { return true };
            let end = loop {
                match chunks.next(usize::MAX) {
                    Ok(Some(ch)) => all.extend_from_slice(&ch.bytes),
                    Ok(None) => break true,
                    Err(alcyon_quic::quinn_proto::ReadError::Blocked) => break false,
                    Err(alcyon_quic::quinn_proto::ReadError::Reset(code)) => {
                        reset = Some(code.into_inner());
                        break true;
                    }
                    Err(_) => break true,
                }
            };
            let _ = chunks.finalize();
            end
        });
        Outcome { status: status(&all), reset, lost: self.lost.clone() }
    }
}

#[derive(Debug)]
struct Outcome {
    status: Option<u16>,
    reset: Option<u64>,
    /// Why the QUIC connection was lost, if it was.
    lost: Option<String>,
}

fn frames(mut b: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut v = Vec::new();
    while !b.is_empty() {
        let mut off = 0;
        let Ok(ty) = alcyon_proto::h3::parse_varint(b, &mut off) else { break };
        let Ok(len) = alcyon_proto::h3::parse_varint(b, &mut off) else { break };
        let len = usize::try_from(len).expect("len");
        if off + len > b.len() {
            break;
        }
        v.push((ty, b[off..off + len].to_vec()));
        b = &b[off + len..];
    }
    v
}

fn status(resp: &[u8]) -> Option<u16> {
    let f = frames(resp);
    let (_, section) = f.iter().find(|(t, _)| *t == 0x01)?;
    let fields = alcyon_proto::qpack::decode_qpack_static(section).ok()?;
    fields.iter().find(|f| f.name == ":status").and_then(|f| f.value.parse().ok())
}

/// A QPACK string literal: `prefix` bits of length, Huffman flag `h`.
fn qstring(out: &mut Vec<u8>, bytes: &[u8], prefix: u8, flag: u8, huffman: bool) {
    let mut enc = Vec::new();
    let data: &[u8] = if huffman {
        alcyon_proto::hpack::encode_huffman(bytes, &mut enc);
        &enc
    } else {
        bytes
    };
    alcyon_proto::hpack::encode_integer(data.len(), prefix, if huffman { flag } else { 0 }, out);
    out.extend_from_slice(data);
}

/// A literal field line with a literal name (RFC 9204 4.5.6), static table only.
fn lit(out: &mut Vec<u8>, name: &[u8], value: &[u8], huffman_name: bool) {
    let mut n = Vec::new();
    qstring(&mut n, name, 3, 0x08, huffman_name);
    n[0] |= 0x20;
    out.extend_from_slice(&n);
    qstring(out, value, 7, 0x80, false);
}

/// A HEADERS frame for `GET <path>` with one more field `(name, value)` if given.
fn request(path: &[u8], extra: Option<(&[u8], &[u8], bool)>) -> Vec<u8> {
    let mut b = vec![0x00, 0x00, 0xC0 | 17, 0xC0 | 23]; // :method GET, :scheme https
    lit(&mut b, b":path", path, false);
    lit(&mut b, b":authority", b"localhost", false);
    if let Some((n, v, h)) = extra {
        lit(&mut b, n, v, h);
    }
    let mut out = Vec::new();
    alcyon_proto::mux_h3::encode_frame(&mut out, 0x01, &b);
    out
}

/// A HEADERS frame of literal fields in the order given (pseudo-headers included).
fn fields(list: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut b = vec![0x00, 0x00];
    for (n, v) in list {
        lit(&mut b, n, v, false);
    }
    let mut out = Vec::new();
    alcyon_proto::mux_h3::encode_frame(&mut out, 0x01, &b);
    out
}

/// A request with every pseudo-header valid except what `over` replaces or adds.
fn request_with(over: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut list: Vec<(&[u8], &[u8])> =
        vec![(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/r7"), (b":authority", b"localhost")];
    for (n, v) in over {
        match list.iter_mut().find(|(ln, _)| ln == n) {
            Some(slot) => slot.1 = v,
            None => list.push((n, v)),
        }
    }
    list.retain(|(_, v)| *v != b"<absent>");
    fields(&list)
}

const E9: u8 = 0xe9;
const MESSAGE_ERROR: u64 = 0x10e;

fn reached(heads: &Heads, path: &[u8]) -> bool {
    thread::sleep(Duration::from_millis(300));
    heads.lock().unwrap().iter().any(|h| h.windows(path.len() + 5).any(|w| w.starts_with(b"GET ") && &w[4..4 + path.len()] == path))
}

/// Sends `bad`, then a good request on the same connection. The bad stream must be reset
/// (not the connection lost) and never reach the backend; the good one must be served.
fn refused_then_served(bad: &[u8], bad_path: &[u8]) {
    let (be, heads) = backend();
    let alcyon = alcyon(be);
    let mut cl = Client::connect(alcyon.quic);
    let id = cl.open(bad);
    let o = cl.outcome(id);
    assert_eq!(o.lost, None, "the connection was lost for one bad field: {o:?}");
    assert_eq!(o.reset, Some(MESSAGE_ERROR), "expected RESET_STREAM H3_MESSAGE_ERROR: {o:?}");
    assert!(!reached(&heads, bad_path), "the refused request reached the backend: {:?}", heads.lock().unwrap());
    let id = cl.open(&request(b"/good", None));
    let o = cl.outcome(id);
    assert_eq!(o.lost, None, "{o:?}");
    assert_eq!(o.status, Some(200), "the next request on the connection must be served: {o:?}");
}

crate::h3_both_paths! {
/// Row 1.
fn a_literal_name_with_a_byte_that_is_not_utf8_resets_the_stream() {
    refused_then_served(&request(b"/r1", Some((&[b'x', b'-', E9], b"1", false))), b"/r1");
}
}

crate::h3_both_paths! {
/// Row 2.
fn a_huffman_name_with_a_byte_that_is_not_utf8_resets_the_stream() {
    refused_then_served(&request(b"/r2", Some((&[b'x', b'-', E9], b"1", true))), b"/r2");
}
}

crate::h3_both_paths! {
/// Row 3: `HAProxy` forwards it, and so does the mux since E1 (the fields go into the HTX as
/// bytes); the relay path refuses the stream (`tradeoff.md` 6.24).
fn a_value_with_a_byte_that_is_not_utf8_is_forwarded_byte_for_byte() {
    let req = request(b"/r3", Some((b"x-a", &[b'a', E9, b'b'], false)));
    if !crate::common::h3_mux() {
        refused_then_served(&req, b"/r3");
        return;
    }
    let (be, heads) = backend();
    let alcyon = alcyon(be);
    let mut cl = Client::connect(alcyon.quic);
    let id = cl.open(&req);
    assert_eq!(cl.outcome(id).status, Some(200));
    let h = heads.lock().unwrap();
    assert!(h[0].windows(9).any(|w| w == b"x-a: a\xe9b\r"), "{:?}", String::from_utf8_lossy(&h[0]));
}
}

crate::h3_both_paths! {
/// Row 4: `HAProxy` forwards it, and so does the mux since X7; the relay path refuses the
/// stream (`tradeoff.md` 6.24). Measured 2026-11-02 on haproxy-quic 3.5-dev10 (aioquic, `:path`
/// `/r4\xe9`): `200`, no reset; the server saw `GET /r4\xe9 HTTP/1.1\r\nhost: localhost\r\n\r\n`;
/// the log line was `GET https://localhost/r4#E9 HTTP/3.0 U=66 ST=200`.
fn a_path_with_a_byte_that_is_not_utf8_resets_the_stream_only() {
    let req = request(&[b'/', b'r', b'4', E9], None);
    if !crate::common::h3_mux() {
        refused_then_served(&req, b"/r4");
        return;
    }
    let (be, heads) = backend();
    let alcyon = alcyon(be);
    let mut cl = Client::connect(alcyon.quic);
    let id = cl.open(&req);
    assert_eq!(cl.outcome(id).status, Some(200));
    let h = heads.lock().unwrap();
    assert!(h[0].starts_with(b"GET /r4\xe9 HTTP/1.1\r\n"), "{:?}", String::from_utf8_lossy(&h[0]));
}
}

crate::h3_both_paths! {
/// Row 5, in the order the oracle was measured: the request after the refused one.
fn many_bad_streams_do_not_cost_the_connection() {
    let (be, _heads) = backend();
    let alcyon = alcyon(be);
    let mut cl = Client::connect(alcyon.quic);
    for i in 0..3 {
        let id = cl.open(&request(b"/r5", Some((&[b'x', E9], b"1", i % 2 == 0))));
        let o = cl.outcome(id);
        assert_eq!((o.lost, o.reset), (None, Some(MESSAGE_ERROR)), "bad stream {i}");
    }
    let id = cl.open(&request(b"/good", None));
    assert_eq!(cl.outcome(id).status, Some(200));
}
}

crate::h3_both_paths! {
/// Valid UTF-8 (`e` acute as C3 A9) is forwarded byte for byte, as `HAProxy` does.
fn a_utf8_value_is_forwarded_byte_for_byte() {
    let (be, heads) = backend();
    let alcyon = alcyon(be);
    let mut cl = Client::connect(alcyon.quic);
    let id = cl.open(&request(b"/r6", Some((b"x-a", "\u{e9}".as_bytes(), false))));
    assert_eq!(cl.outcome(id).status, Some(200));
    let h = heads.lock().unwrap();
    assert!(h[0].windows(7).any(|w| w == b"x-a: \xc3\xa9"), "{:?}", String::from_utf8_lossy(&h[0]));
}
}

crate::h3_both_paths! {
/// T454 item 3: the field checks of HTTP/2 (`check_request_fields`), on HTTP/3. Every row
/// is RESET_STREAM `H3_MESSAGE_ERROR` on the oracle (QUIC build, same client as above) and
/// never reaches the server; each is a request the HTTP/1 head would carry differently.
fn malformed_pseudo_headers_and_fields_reset_the_stream() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("path with #", request_with(&[(b":path", b"/a#b")])),
        ("path without a slash", request_with(&[(b":path", b"a")])),
        ("path with a space", request_with(&[(b":path", b"/a b")])),
        ("authority with a slash", request_with(&[(b":authority", b"a/b")])),
        ("authority with @", request_with(&[(b":authority", b"a@b")])),
        ("authority with a space", request_with(&[(b":authority", b"a b")])),
        ("scheme with a space", request_with(&[(b":scheme", b"ht tp")])),
        ("empty scheme", request_with(&[(b":scheme", b"")])),
        ("host header with a slash", request_with(&[(b":authority", b"<absent>"), (b"host", b"a/b")])),
        ("neither authority nor host", request_with(&[(b":authority", b"<absent>")])),
        ("method with a space", request_with(&[(b":method", b"G E T")])),
        ("empty method", request_with(&[(b":method", b"")])),
    ];
    let (be, heads) = backend();
    let alcyon = alcyon(be);
    let mut bad = Vec::new();
    for (name, bytes) in &cases {
        // One connection per case: a stream error must not decide the next case.
        let mut cl = Client::connect(alcyon.quic);
        let id = cl.open(bytes);
        let o = cl.outcome(id);
        if o.reset != Some(MESSAGE_ERROR) || o.lost.is_some() {
            bad.push(format!("{name}: {o:?}"));
        }
    }
    assert!(!reached(&heads, b"/"), "a refused request reached the backend: {:?}", heads.lock().unwrap());
    assert!(bad.is_empty(), "not RESET_STREAM H3_MESSAGE_ERROR:\n{}", bad.join("\n"));
}
}

crate::h3_both_paths! {
/// The pseudo-headers `HAProxy` accepts are still served: `OPTIONS *`, a lowercase method
/// is not refused (measured 200), a tab in a value, `te: trailers`, and `host` for authority.
fn valid_requests_with_unusual_fields_are_served() {
    let (be, heads) = backend();
    let alcyon = alcyon(be);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("tab in a value", request_with(&[(b"x-a", b"a\tb")])),
        ("te trailers", request_with(&[(b"te", b"trailers")])),
        ("host without authority", request_with(&[(b":authority", b"<absent>"), (b"host", b"h")])),
    ];
    for (name, bytes) in &cases {
        let mut cl = Client::connect(alcyon.quic);
        let id = cl.open(bytes);
        assert_eq!(cl.outcome(id).status, Some(200), "{name}");
    }
    assert_eq!(heads.lock().unwrap().len(), cases.len());
}
}

crate::h3_both_paths! {
/// A field section that does not decode (required insert count 1, no dynamic table) closes
/// the connection with QPACK_DECOMPRESSION_FAILED (0x200), as `HAProxy` 3.5-dev7 +QUIC does
/// (measured: connection close 0x200); and an empty `:path` is a stream reset 0x10e.
fn an_undecodable_section_closes_the_connection_and_an_empty_path_resets_the_stream() {
    let (be, _heads) = backend();
    let alcyon = alcyon(be);
    let mut cl = Client::connect(alcyon.quic);
    let mut b = vec![0x01, 0x00, 0xC0 | 17, 0xC0 | 23, 0xC0 | 1];
    lit(&mut b, b":authority", b"localhost", false);
    let mut frame = Vec::new();
    alcyon_proto::mux_h3::encode_frame(&mut frame, 0x01, &b);
    let id = cl.open(&frame);
    let o = cl.outcome(id);
    let lost = o.lost.unwrap_or_default();
    assert!(lost == "closed by peer: 512", "connection not closed with 0x200: {lost:?} {:?}", o.status);

    let mut cl = Client::connect(alcyon.quic);
    let id = cl.open(&request_with(&[(b":path", b"")]));
    assert_eq!(cl.outcome(id).reset, Some(MESSAGE_ERROR));
}
}
