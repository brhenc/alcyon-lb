// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T260): lowers the test process's RLIMIT_NOFILE for one test (other tests would get EMFILE)

//! The QUIC listener's side of the HTTP/3 relay (T130), driven without the engine: the test
//! plays both the client (a `quinn-proto` connection, so it can send a request in pieces,
//! reset a stream or close the connection at will) and the engine (it reads the HTTP/1
//! request from the socket pair the listener hands over, and answers on it -- or not).
//! `h3_proxy_path.rs` covers the same path end to end with curl and the real engine.

use ibex_quic::quinn_proto::{
    crypto::rustls::QuicClientConfig, ClientConfig, Connection, ConnectionHandle, Dir, Endpoint, EndpointConfig,
    Event, StreamId, VarInt,
};
use ibex_rt::quic_listener::{AcceptedStream, QuicListener};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// Taken for writing by the one test that runs the process out of descriptors, so no other
/// test is opening sockets meanwhile.
static FDS: std::sync::RwLock<()> = std::sync::RwLock::new(());

/// A listener handing requests to "the engine" (the test), and one client connected to it.
struct Rig {
    server: QuicListener,
    sock: UdpSocket,
    ep: Endpoint,
    handle: ConnectionHandle,
    conn: Connection,
    buf: Vec<u8>,
    lost: bool,
    /// Why the server's connection ended, as the client saw it.
    lost_reason: Option<ibex_quic::quinn_proto::ConnectionError>,
    _guard: Option<std::sync::RwLockReadGuard<'static, ()>>,
}

impl Rig {
    fn new() -> Self {
        Self::with(|s| s.set_frontend(0))
    }

    fn with(setup: impl FnOnce(&mut QuicListener)) -> Self {
        let guard = FDS.read().unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::build(setup, Some(guard))
    }

    fn build(setup: impl FnOnce(&mut QuicListener), guard: Option<std::sync::RwLockReadGuard<'static, ()>>) -> Self {
        ibex_tls::config::install_default_crypto_provider();
        let crt = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/certs/localhost.pem"));
        let (certs, key) = ibex_tls::config::load_cert_file(crt).expect("cert");
        let mut tls = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key).expect("tls");
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut server = QuicListener::bind("127.0.0.1:0".parse().expect("addr"), &tls, None).expect("bind");
        setup(&mut server);

        let mut ctls = rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(Any)).with_no_client_auth();
        ctls.alpn_protocols = vec![b"h3".to_vec()];
        let client_cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(ctls).expect("client config")));
        let sock = UdpSocket::bind("127.0.0.1:0").expect("client socket");
        sock.set_nonblocking(true).expect("nonblocking");
        let mut ep = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
        let (handle, conn) = ep.connect(Instant::now(), client_cfg, server.addr(), "localhost").expect("connect");
        let mut rig = Self { server, sock, ep, handle, conn, buf: vec![0u8; 65536], lost: false, lost_reason: None, _guard: guard };
        assert!(rig.run_until(|r| r.connected()), "no handshake");
        rig
    }

    fn connected(&self) -> bool {
        !self.conn.is_handshaking()
    }

    /// One round: client datagrams out, server pump, client datagrams in.
    fn step(&mut self) {
        let now = Instant::now();
        let mut out = Vec::new();
        while let Some(t) = self.conn.poll_transmit(now, 1, &mut out) {
            let _ = self.sock.send_to(&out[..t.size], t.destination);
            out.clear();
        }
        std::thread::sleep(Duration::from_millis(1));
        let now = Instant::now();
        if self.server.poll_timeout().is_some_and(|d| d <= now) {
            self.server.handle_timeout(now);
        }
        self.server.pump(now).expect("pump");
        while let Ok((n, from)) = self.sock.recv_from(&mut self.buf) {
            let mut resp = Vec::new();
            if let Some(ibex_quic::quinn_proto::DatagramEvent::ConnectionEvent(_, e)) =
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
        while let Some(ev) = self.conn.poll() {
            if let Event::ConnectionLost { reason } = ev {
                self.lost = true;
                self.lost_reason = Some(reason);
            }
        }
    }

    fn run_until(&mut self, mut done: impl FnMut(&mut Self) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            self.step();
            if done(self) {
                return true;
            }
        }
        false
    }

    /// Opens a request stream and writes `bytes` on it.
    fn open(&mut self, bytes: &[u8], fin: bool) -> StreamId {
        let id = self.conn.streams().open(Dir::Bi).expect("open");
        self.send(id, bytes, fin);
        id
    }

    fn send(&mut self, id: StreamId, bytes: &[u8], fin: bool) {
        let mut s = self.conn.send_stream(id);
        assert_eq!(s.write(bytes).expect("write"), bytes.len());
        if fin {
            s.finish().expect("finish");
        }
    }

    /// The engine's end of the next request handed over.
    fn accept(&mut self) -> UnixStream {
        let mut got: Option<AcceptedStream> = None;
        assert!(
            self.run_until(|r| {
                got = r.server.take_accepted().pop();
                got.is_some()
            }),
            "no request was handed to the engine"
        );
        let fd: OwnedFd = got.expect("accepted").fd;
        let s = UnixStream::from(fd);
        s.set_nonblocking(true).expect("nonblocking");
        s
    }

    /// Everything the client received on `id` so far, and whether the stream ended.
    fn read(&mut self, id: StreamId) -> (Vec<u8>, bool) {
        let mut data = Vec::new();
        let mut fin = false;
        let mut rs = self.conn.recv_stream(id);
        if let Ok(mut chunks) = rs.read(true) {
            loop {
                match chunks.next(usize::MAX) {
                    Ok(Some(c)) => data.extend_from_slice(&c.bytes),
                    Ok(None) => {
                        fin = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            let _ = chunks.finalize();
        }
        (data, fin)
    }

    /// The whole response on `id`, waiting for its end.
    fn response(&mut self, id: StreamId) -> Vec<u8> {
        let mut all = Vec::new();
        let ok = self.run_until(|r| {
            let (d, fin) = r.read(id);
            all.extend_from_slice(&d);
            fin
        });
        assert!(ok, "the response never ended; got {all:?}");
        all
    }
}

/// The `:status` of an HTTP/3 response (first HEADERS frame, static-table or literal).
fn status(resp: &[u8]) -> u16 {
    let fields = ibex_proto::qpack::decode_qpack_static(&frame_payload(resp, 0)).expect("qpack");
    fields.iter().find(|f| f.name == ":status").and_then(|f| f.value.parse().ok()).expect("status")
}

/// The payload of the `n`th frame.
fn frame_payload(mut b: &[u8], n: usize) -> Vec<u8> {
    for i in 0.. {
        let mut off = 0;
        let _ty = ibex_proto::h3::parse_varint(b, &mut off).expect("type");
        let len = usize::try_from(ibex_proto::h3::parse_varint(b, &mut off).expect("len")).expect("len");
        if i == n {
            return b[off..off + len].to_vec();
        }
        b = &b[off + len..];
    }
    unreachable!()
}

fn headers(extra: &[(&str, &str)]) -> Vec<u8> {
    let mut f: Vec<(String, String)> = [(":method", "POST"), (":scheme", "https"), (":authority", "localhost"), (":path", "/up")]
        .iter()
        .chain(extra)
        .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
        .collect();
    f.dedup();
    let section = ibex_proto::mux_h3::encode_field_section(&f);
    frame(0x01, &section)
}

fn frame(ty: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    ibex_proto::mux_h3::encode_frame(&mut out, ty, payload);
    out
}

fn engine_read(s: &mut UnixStream, rig: &mut Rig, until: &[u8]) -> Vec<u8> {
    let mut got = Vec::new();
    let ok = rig.run_until(|_| {
        let mut b = [0u8; 65536];
        while let Ok(n) = s.read(&mut b) {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&b[..n]);
        }
        got.windows(until.len()).any(|w| w == until)
    });
    assert!(ok, "the engine never got {:?}; got {:?}", String::from_utf8_lossy(until), String::from_utf8_lossy(&got));
    got
}

fn engine_sees_eof(s: &mut UnixStream, rig: &mut Rig) -> bool {
    rig.run_until(|_| {
        let mut b = [0u8; 4096];
        loop {
            match s.read(&mut b) {
                Ok(0) => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    })
}

/// A body sent after the head, with no length, reaches the engine chunked; the response the
/// engine writes comes back as HEADERS and DATA.
#[test]
fn a_streamed_body_is_chunked_to_the_engine() {
    let mut rig = Rig::new();
    let id = rig.open(&headers(&[]), false);
    let mut eng = rig.accept();
    assert!(
        rig.server.io_fds().iter().any(|&(_, r, _)| r),
        "the relay waits for the engine's answer"
    );
    rig.send(id, &frame(0x00, b"hello"), false);
    let got = engine_read(&mut eng, &mut rig, b"5\r\nhello\r\n");
    assert!(got.starts_with(b"POST /up HTTP/1.1\r\n"), "{}", String::from_utf8_lossy(&got));
    assert!(String::from_utf8_lossy(&got).contains("transfer-encoding: chunked\r\n"));
    rig.send(id, &frame(0x00, b"world"), true);
    engine_read(&mut eng, &mut rig, b"5\r\nworld\r\n0\r\n\r\n");
    eng.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").expect("answer");
    let resp = rig.response(id);
    assert_eq!(status(&resp), 200);
    assert_eq!(frame_payload(&resp, 1), b"ok");
    assert!(engine_sees_eof(&mut eng, &mut rig), "the relay closes its end once the response is out");
}

/// An engine that closes without answering, or answers garbage, gets the client a 502.
#[test]
fn no_answer_or_garbage_from_the_engine_is_a_502() {
    let mut rig = Rig::new();
    let id = rig.open(&headers(&[("content-length", "0")]), true);
    drop(rig.accept());
    assert_eq!(status(&rig.response(id)), 502);

    let id = rig.open(&headers(&[("content-length", "0")]), true);
    let mut eng = rig.accept();
    eng.write_all(b"garbage\r\n\r\n").expect("write");
    assert_eq!(status(&rig.response(id)), 502);
}

/// Malformed requests are refused by the listener and never reach the engine.
#[test]
fn malformed_requests_get_a_400() {
    let mut rig = Rig::new();
    let mut data_first = frame(0x00, b"x");
    data_first.extend_from_slice(&headers(&[]));
    let a = rig.open(&data_first, true);
    let b = rig.open(&headers(&[("connection", "close")]), true);
    let mut too_long = headers(&[("content-length", "2")]);
    too_long.extend_from_slice(&frame(0x00, b"abc"));
    let c = rig.open(&too_long, true);
    let mut cut = headers(&[]);
    cut.extend_from_slice(&frame(0x00, b"abcdef")[..4]);
    let d = rig.open(&cut, true);
    for (what, id) in [("DATA before HEADERS", a), ("connection field", b), ("body over its length", c), ("frame cut by the end", d)] {
        let (resp, _) = { let r = rig.response(id); (r, ()) };
        assert_eq!(status(&resp), 400, "{what}");
    }
    assert!(rig.server.take_accepted().is_empty(), "no malformed request reaches the engine");
}

/// A body that turns out longer than its `content-length` after the engine has the head
/// cuts the engine's stream, and the client gets a 400.
#[test]
fn a_body_over_its_length_later_is_cut() {
    let mut rig = Rig::new();
    let id = rig.open(&headers(&[("content-length", "2")]), false);
    let mut eng = rig.accept();
    engine_read(&mut eng, &mut rig, b"\r\n\r\n");
    rig.send(id, &frame(0x00, b"abc"), true);
    assert_eq!(status(&rig.response(id)), 400);
    assert!(engine_sees_eof(&mut eng, &mut rig));
}

/// A client that resets its request, or stops the response, is gone for the engine too.
#[test]
fn a_reset_or_stopped_stream_closes_the_engine_side() {
    let mut rig = Rig::new();
    let id = rig.open(&headers(&[]), false);
    let mut eng = rig.accept();
    rig.conn.send_stream(id).reset(VarInt::from_u32(0x10c)).expect("reset");
    assert!(engine_sees_eof(&mut eng, &mut rig), "reset");

    let id = rig.open(&headers(&[("content-length", "0")]), true);
    let mut eng = rig.accept();
    rig.conn.recv_stream(id).stop(VarInt::from_u32(0x10c)).expect("stop");
    assert!(engine_sees_eof(&mut eng, &mut rig), "stop sending");
}

/// A response larger than the client lets through waits in the listener, the engine side
/// is not read past the backlog, and a client that closes the connection frees all of it.
#[test]
fn a_blocked_response_waits_and_a_closed_connection_frees_it() {
    let mut rig = Rig::new();
    let id = rig.open(&headers(&[("content-length", "0")]), true);
    let mut eng = rig.accept();
    eng.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4000000\r\n\r\n").expect("head");
    let chunk = vec![b'x'; 65536];
    let mut sent = 0usize;
    // The client does not read: the stream's window fills, then the listener's backlog,
    // then the socket pair.
    let mut idle_steps = 0;
    let stalled = rig.run_until(|_| {
        let before = sent;
        while sent < 4_000_000 {
            match eng.write(&chunk[..chunk.len().min(4_000_000 - sent)]) {
                Ok(n) => sent += n,
                Err(_) => break,
            }
        }
        idle_steps = if sent == before { idle_steps + 1 } else { 0 };
        idle_steps > 100
    });
    assert!(stalled, "the engine side never filled; wrote {sent}");
    assert!(
        rig.server.io_fds().iter().all(|&(_, r, _)| !r),
        "the relay must stop reading the engine while its backlog is full"
    );
    rig.conn.close(Instant::now(), VarInt::from_u32(0x100), Vec::new().into());
    assert!(engine_sees_eof(&mut eng, &mut rig), "the closed connection's relay is dropped");
    let _ = id;
    assert!(rig.run_until(|r| !r.server.is_busy()), "the listener still holds the connection");
}

/// The standalone mode (`set_backend`, no engine) waits on its backend leg for reading only
/// once the request is written: write interest there is what made a slow backend spin.
#[test]
fn a_standalone_leg_waits_for_reading_once_its_request_is_written() {
    let be = std::net::TcpListener::bind("127.0.0.1:0").expect("backend");
    let addr = be.local_addr().expect("addr");
    let mut rig = Rig::with(|s| s.set_backend(addr));
    rig.open(&headers(&[("content-length", "0")]), true);
    assert!(
        rig.run_until(|r| r.server.io_fds().iter().any(|&(_, rd, wr)| rd && !wr)),
        "the leg never settled on read interest"
    );
}

/// A response delimited by the close: its data goes out as it comes, and the stream ends
/// when the engine closes.
#[test]
fn a_close_delimited_response_ends_with_the_engine() {
    let mut rig = Rig::new();
    let id = rig.open(&headers(&[("content-length", "0")]), true);
    let mut eng = rig.accept();
    eng.write_all(b"HTTP/1.1 200 OK\r\n\r\nabc").expect("write");
    let mut got = Vec::new();
    assert!(rig.run_until(|r| {
        got.extend_from_slice(&r.read(id).0);
        got.ends_with(b"abc")
    }));
    eng.shutdown(std::net::Shutdown::Both).expect("close");
    got.extend_from_slice(&rig.response(id));
    assert_eq!(status(&got), 200);
}

/// The engine gives up while request body is still waiting for it: the rest is dropped,
/// and the client gets a 502 since nothing was answered.
#[test]
fn an_engine_that_goes_away_mid_body() {
    let mut rig = Rig::new();
    let id = rig.open(&headers(&[]), false);
    let eng = rig.accept();
    // One big DATA frame, written as the client's flow control lets it through.
    let body = frame(0x00, &vec![b'z'; 3_000_000]);
    let mut off = 0;
    for _ in 0..200 {
        off += rig.conn.send_stream(id).write(&body[off..]).unwrap_or(0);
        rig.step();
    }
    assert!(
        rig.server.io_fds().iter().any(|&(_, _, w)| w),
        "the engine reads nothing, so body waits with write interest"
    );
    drop(eng);
    assert_eq!(status(&rig.response(id)), 502);
}

/// Out of descriptors, the listener cannot open the socket pair: the client gets a 503
/// rather than a stream that is never answered.
#[test]
fn no_descriptor_for_the_relay_is_a_503() {
    use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
    let _all = FDS.write().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut rig = Rig::build(|s| s.set_frontend(0), None);
    let saved = getrlimit(Resource::Nofile);
    let highest = std::fs::read_dir("/proc/self/fd")
        .expect("fds")
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u64>().ok())
        .max()
        .expect("some fd");
    // `read_dir` held one more descriptor while it listed them; that number is free again.
    setrlimit(Resource::Nofile, Rlimit { current: Some(highest), maximum: saved.maximum }).expect("lower");
    // Fill whatever holes earlier tests left below the limit.
    let mut held = Vec::new();
    while let Ok(f) = std::fs::File::open("/dev/null") {
        held.push(f);
    }
    let id = rig.open(&headers(&[("content-length", "0")]), true);
    let resp = rig.response(id);
    setrlimit(Resource::Nofile, saved).expect("restore");
    drop(held);
    assert_eq!(status(&resp), 503);
}

// F1 (T358 footgun #2): the per-stream HTTP/3 request buffer is bounded.
//
// Expected values come from HAProxy's source, because the reference binary is built -QUIC
// and cannot run these: src/h3.c:2037-2070 (h3_rcv_buf): for every frame type but DATA,
// `if (flen > qcm_stream_rx_bufsz()) { qcc_set_error(qcc, H3_ERR_EXCESSIVE_LOAD, 1, ...);
// goto err; }`, decided from the frame header, a connection error 0x107; a shorter,
// incomplete frame just pauses parsing (`if (flen > b_data(b)) break;`).
// qcm_stream_rx_bufsz() = global.tune.bufsize - NCB_RESERVED_SZ (include/haproxy/mux_quic.h:56-59;
// NCB_RESERVED_SZ = sizeof(ncb_sz_t) = 4, ncbuf-t.h:68) = 16380 by default.

const H3_EXCESSIVE_LOAD: u64 = 0x107;
const FRAME_CAP: usize = 16_384 - 4;

fn varint(v: u64) -> Vec<u8> {
    let mut b = Vec::new();
    ibex_proto::mux_h3::encode_varint(&mut b, v);
    b
}

/// A request HEADERS frame whose payload is exactly `payload_len` bytes.
fn headers_of_len(payload_len: usize) -> Vec<u8> {
    let frame_len = |pad: usize| {
        let value = "x".repeat(pad);
        let f = headers(&[("x-pad", value.as_str())]);
        let mut off = 0;
        let _ = ibex_proto::h3::parse_varint(&f, &mut off);
        (ibex_proto::h3::parse_varint(&f, &mut off).expect("len") as usize, f)
    };
    // The field section grows one byte per pad byte at these sizes.
    let (base, _) = frame_len(1000);
    let (len, f) = frame_len(1000 + payload_len - base);
    assert_eq!(len, payload_len);
    f
}

/// Runs the rig until the server closes the connection; returns the largest number of bytes
/// the listener held for request streams at any step.
fn run_to_close(rig: &mut Rig) -> usize {
    let mut peak = 0;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !rig.lost && Instant::now() < deadline {
        rig.step();
        peak = peak.max(rig.server.pending_request_bytes());
    }
    peak
}

fn assert_excessive_load(rig: &Rig) {
    assert!(rig.lost, "the connection was not closed");
    match rig.lost_reason.as_ref().expect("reason") {
        ibex_quic::quinn_proto::ConnectionError::ApplicationClosed(c) => {
            assert_eq!(c.error_code, VarInt::from_u32(H3_EXCESSIVE_LOAD as u32), "{c:?}");
        }
        other => panic!("closed with {other:?}, want H3_EXCESSIVE_LOAD"),
    }
}

/// A stream that keeps sending without ever completing a HEADERS frame is cut off with
/// H3_EXCESSIVE_LOAD, and the listener never holds more than a buffer's worth of it.
#[test]
fn a_request_stream_over_the_cap_is_refused_and_bounded() {
    let mut rig = Rig::new();
    // A DATA frame (no length check of its own) announcing 2^40 bytes, before any HEADERS.
    let mut first = varint(0x00);
    first.extend(varint(1 << 40));
    let id = rig.open(&first, false);
    let mut sent = 0;
    let mut peak = 0;
    while sent < 256 * 1024 && !rig.lost {
        rig.send(id, &[b'a'; 1200], false);
        sent += 1200;
        rig.step();
        peak = peak.max(rig.server.pending_request_bytes());
    }
    peak = peak.max(run_to_close(&mut rig));
    assert_excessive_load(&rig);
    assert!(peak <= FRAME_CAP + 16, "the listener held {peak} bytes of one stream (cap {FRAME_CAP})");
    assert_eq!(rig.server.pending_request_bytes(), 0, "the buffer is released");
}

/// A HEADERS frame (or any non-DATA frame) declaring more than the cap is refused from its
/// header, before a payload byte is buffered.
#[test]
fn a_headers_frame_declaring_more_than_the_cap_is_refused_before_buffering() {
    for ty in [0x01u64, 0x21] {
        let mut rig = Rig::new();
        let mut first = varint(ty);
        first.extend(varint(FRAME_CAP as u64 + 1));
        first.extend([b'a'; 100]);
        rig.open(&first, false);
        let peak = run_to_close(&mut rig);
        assert_excessive_load(&rig);
        assert!(peak <= first.len() && peak < 1000, "type {ty:#x}: held {peak} bytes");
        assert!(peak < 2 * 100, "type {ty:#x}: payload buffered ({peak})");
    }
    // A length no usize holds is refused the same way.
    let mut rig = Rig::new();
    let mut first = varint(0x01);
    first.extend(varint(1 << 40));
    rig.open(&first, false);
    run_to_close(&mut rig);
    assert_excessive_load(&rig);
}

/// A HEADERS frame of exactly the cap, delivered in pieces, is a request; one byte more is not.
#[test]
fn a_headers_frame_just_under_the_cap_still_works() {
    let mut rig = Rig::new();
    let f = headers_of_len(FRAME_CAP);
    let id = rig.open(&f[..f.len() / 2], false);
    rig.step();
    rig.send(id, &f[f.len() / 2..], true);
    let mut eng = rig.accept();
    let got = engine_read(&mut eng, &mut rig, b"\r\n\r\n");
    assert!(got.starts_with(b"POST /up HTTP/1.1\r\n"), "{}", String::from_utf8_lossy(&got[..40.min(got.len())]));
    assert!(!rig.lost);
    drop(eng);
    drop(rig);

    let mut rig = Rig::new();
    rig.open(&headers_of_len(FRAME_CAP + 1), true);
    run_to_close(&mut rig);
    assert_excessive_load(&rig);
}
