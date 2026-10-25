// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The h3 mux over a real QUIC connection, without the engine (T503), in the style of
//! `ibex-rt/tests/h3_relay_streams.rs`: a quinn-proto client and server in one process, the
//! datagrams carried in memory, the server's connection driven by an owner pass written the
//! way slice H3a's `h3_owner_pass` will be (read a stream only while `rx_room` says so, hand
//! the bytes to the mux, write its frames back, carry out its signals), and the test playing
//! the engine's children through `HtxMux`.

use ibex_proto::h3::parse_varint;
use ibex_proto::htx::HtxBlock;
use ibex_proto::htx_mux::{HtxMux, HtxStream};
use ibex_proto::mux_h3::{self, H3MuxContext, H3Signal, RX_DATA_ROOM};
use ibex_proto::qpack;
use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::{
    ClientConfig, Connection, ConnectionError, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig, Event, ReadError,
    ServerConfig, StreamEvent, StreamId, VarInt,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

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
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

const CLIENT: &str = "127.0.0.1:41000";
const SERVER: &str = "127.0.0.1:42000";

/// What the test's "child" does with a stream it serves.
#[derive(Default)]
struct Child {
    path: String,
    body: usize,
    eom: bool,
    answered: bool,
}

/// A client and a server connection, and the server's mux.
struct Pair {
    cep: Endpoint,
    sep: Endpoint,
    chandle: ConnectionHandle,
    client: Connection,
    server: Option<(ConnectionHandle, Connection)>,
    mux: ibex_alloc::PoolBox<H3MuxContext>,
    /// The request and uni streams the server has accepted, and whether their FIN was read.
    srv_streams: Vec<(StreamId, bool)>,
    children: HashMap<u64, Child>,
    /// Most DATA bytes a child takes per pass (a slow server).
    take_per_pass: usize,
    /// The most DATA the mux ever held for one stream.
    max_buffered: usize,
    client_lost: Option<ConnectionError>,
}

impl Pair {
    fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pem = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/certs/localhost.pem");
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(pem).expect("pem").map(|c| c.expect("cert")).collect();
        let key = PrivateKeyDer::from_pem_file(pem).expect("key");
        let mut stls = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key).expect("server tls");
        stls.alpn_protocols = vec![b"h3".to_vec()];
        let scfg = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(stls).expect("quic server")));
        let sep = Endpoint::new(Arc::new(EndpointConfig::default()), Some(Arc::new(scfg)), true, None);

        let mut ctls = rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(Any)).with_no_client_auth();
        ctls.alpn_protocols = vec![b"h3".to_vec()];
        let ccfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(ctls).expect("quic client")));
        let mut cep = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
        let (chandle, client) = cep.connect(Instant::now(), ccfg, SERVER.parse().expect("addr"), "localhost").expect("connect");
        let mut p = Self {
            cep,
            sep,
            chandle,
            client,
            server: None,
            mux: H3MuxContext::take().expect("qcc"),
            srv_streams: Vec::new(),
            children: HashMap::new(),
            take_per_pass: usize::MAX,
            max_buffered: 0,
            client_lost: None,
        };
        p.run(|p| p.server.as_ref().is_some_and(|(_, s)| !s.is_handshaking()) && !p.client.is_handshaking());
        // The client's control stream and its SETTINGS, as any h3 client opens it.
        let ctl = p.client.streams().open(Dir::Uni).expect("control");
        let mut b = vec![0x00];
        mux_h3::encode_frame(&mut b, 0x04, &[]);
        p.client.send_stream(ctl).write(&b).expect("write");
        p
    }

    /// Datagrams both ways, timers, then the server's owner pass, until `done` or 2000 rounds.
    fn run(&mut self, mut done: impl FnMut(&mut Self) -> bool) -> bool {
        for _ in 0..2000 {
            self.round();
            if done(self) {
                return true;
            }
        }
        false
    }

    fn round(&mut self) {
        let now = Instant::now();
        let (caddr, saddr): (SocketAddr, SocketAddr) = (CLIENT.parse().expect("a"), SERVER.parse().expect("a"));
        let mut out = Vec::new();
        let mut c2s = Vec::new();
        while let Some(t) = self.client.poll_transmit(now, 1, &mut out) {
            c2s.push(out[..t.size].to_vec());
            out.clear();
        }
        for d in c2s {
            let mut resp = Vec::new();
            match self.sep.handle(now, caddr, None, None, d.as_slice().into(), &mut resp) {
                Some(DatagramEvent::NewConnection(inc)) => {
                    let (h, conn) = self.sep.accept(inc, now, &mut resp, None).expect("accept");
                    self.server = Some((h, conn));
                }
                Some(DatagramEvent::ConnectionEvent(_, e)) => {
                    if let Some((_, s)) = self.server.as_mut() {
                        s.handle_event(e);
                    }
                }
                _ => {}
            }
        }
        if let Some((sh, s)) = self.server.as_mut() {
            let mut s2c = Vec::new();
            while let Some(t) = s.poll_transmit(now, 1, &mut out) {
                s2c.push(out[..t.size].to_vec());
                out.clear();
            }
            while let Some(e) = s.poll_endpoint_events() {
                if let Some(ce) = self.sep.handle_event(*sh, e) {
                    s.handle_event(ce);
                }
            }
            if s.poll_timeout().is_some_and(|t| t <= now) {
                s.handle_timeout(now);
            }
            for d in s2c {
                let mut resp = Vec::new();
                if let Some(DatagramEvent::ConnectionEvent(_, e)) = self.cep.handle(now, saddr, None, None, d.as_slice().into(), &mut resp) {
                    self.client.handle_event(e);
                }
            }
        }
        while let Some(e) = self.client.poll_endpoint_events() {
            if let Some(ce) = self.cep.handle_event(self.chandle, e) {
                self.client.handle_event(ce);
            }
        }
        if self.client.poll_timeout().is_some_and(|t| t <= now) {
            self.client.handle_timeout(now);
        }
        while let Some(ev) = self.client.poll() {
            if let Event::ConnectionLost { reason } = ev {
                self.client_lost = Some(reason);
            }
        }
        self.owner_pass();
    }

    /// The owner pass H3a's `h3_owner_pass` will be, transport side.
    fn owner_pass(&mut self) {
        let Some((_, s)) = self.server.as_mut() else { return };
        let mux = &mut *self.mux;
        while let Some(ev) = s.poll() {
            match ev {
                Event::Connected if mux.control_out.is_none() => {
                    let id = s.streams().open(Dir::Uni).expect("our control stream");
                    mux.open_control(u64::from(id));
                }
                Event::Stream(StreamEvent::Opened { dir }) => {
                    while let Some(id) = s.streams().accept(dir) {
                        self.srv_streams.push((id, false));
                    }
                }
                Event::Stream(StreamEvent::Stopped { id, error_code }) => {
                    let _ = mux.on_stop_sending(u64::from(id), error_code.into_inner());
                }
                _ => {}
            }
        }
        // Transport -> mux, under each stream's room.
        for (id, finished) in &mut self.srv_streams {
            while !*finished && mux.error.is_none() {
                let room = mux.rx_room(u64::from(*id));
                if room == 0 {
                    break;
                }
                let mut rs = s.recv_stream(*id);
                let Ok(mut chunks) = rs.read(true) else { break };
                let r = chunks.next(room);
                let _ = chunks.finalize();
                match r {
                    Ok(Some(c)) => {
                        let _ = mux.recv(u64::from(*id), &c.bytes, false, 0);
                    }
                    Ok(None) => {
                        *finished = true;
                        let _ = mux.recv(u64::from(*id), &[], true, 0);
                    }
                    Err(ReadError::Reset(code)) => {
                        *finished = true;
                        let _ = mux.on_reset(u64::from(*id), code.into_inner());
                    }
                    Err(ReadError::Blocked) => break,
                }
            }
        }
        // The children.
        while let Some(id) = mux.next_dispatch() {
            let st = mux.stream_mut(id).expect("stream");
            st.set_dispatched();
            let head = st.take_req_head().expect("head");
            self.children.insert(id, Child { path: head.uri().to_string(), ..Child::default() });
            mux.give_back_head(head);
        }
        for (&id, child) in &mut self.children {
            let Some(st) = mux.stream_mut(id) else { continue };
            self.max_buffered = self.max_buffered.max(st.rx_buffered());
            let mut took = 0;
            let blocks = st.rx_htx_mut();
            while let Some(b) = blocks.blocks_mut().iter_mut().find(|b| matches!(b, HtxBlock::Data(d) if !d.is_empty())) {
                let HtxBlock::Data(d) = b else { unreachable!() };
                let n = d.len().min(self.take_per_pass - took);
                d.drain(..n);
                took += n;
                if took == self.take_per_pass {
                    break;
                }
            }
            let left = st.rx_htx().blocks().iter().any(|b| matches!(b, HtxBlock::Data(d) if !d.is_empty()));
            child.eom |= st.rx_htx().is_eom() && !left;
            child.body += took;
            mux.rx_taken(id, took);
            if child.eom && !child.answered && !mux.is_reset(id) {
                child.answered = true;
                if child.path == "/trailers" {
                    mux.send_head(id, b"HTTP/1.1 200 OK\r\ntrailer: x-sum\r\ntransfer-encoding: chunked", false);
                    mux.send_data(id, b"abc", false);
                    mux.send_trailers(id, &[("x-sum", "42")]);
                } else {
                    let body = format!("got {}", child.body);
                    let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}", body.len());
                    mux.send_head(id, head.as_bytes(), false);
                    mux.send_data(id, body.as_bytes(), true);
                }
            }
        }
        // Signals, a connection error, then mux -> transport.
        while let Some(sig) = mux.take_signal() {
            match sig {
                H3Signal::StopSending { id, code } => {
                    let _ = s.recv_stream(sid(id)).stop(VarInt::from_u64(code).expect("code"));
                }
                H3Signal::ResetStream { id, code } => {
                    let _ = s.send_stream(sid(id)).reset(VarInt::from_u64(code).expect("code"));
                }
            }
        }
        if let Some(e) = mux.error {
            s.close(Instant::now(), VarInt::from_u64(e as u64).expect("code"), Vec::new().into());
            return;
        }
        for _ in 0..64 {
            let Some(id) = mux.next_tx() else { break };
            let bytes = mux.tx_bytes(id);
            let n = if bytes.is_empty() { 0 } else { s.send_stream(sid(id)).write(bytes).unwrap_or(0) };
            mux.tx_written(id, n);
            if mux.fin_due(id) {
                let _ = s.send_stream(sid(id)).finish();
                mux.fin_written(id);
                mux.release(id);
                self.children.remove(&id);
            } else if n == 0 {
                break;
            }
        }
    }

    /// Sends a request on a new stream: its HEADERS, then `body` as DATA frames of `frame`
    /// bytes, then FIN.
    fn request(&mut self, fields: &[(&str, &str)], body: &[u8], frame: usize) -> StreamId {
        let id = self.client.streams().open(Dir::Bi).expect("stream");
        let f: Vec<(String, String)> = fields.iter().map(|(n, v)| ((*n).to_string(), (*v).to_string())).collect();
        let mut b = Vec::new();
        mux_h3::encode_frame(&mut b, 0x01, &mux_h3::encode_field_section(&f));
        for c in body.chunks(frame.max(1)) {
            mux_h3::encode_frame(&mut b, 0x00, c);
        }
        let mut sent = 0;
        let ok = self.run(|p| {
            if sent < b.len() {
                sent += p.client.send_stream(id).write(&b[sent..]).unwrap_or(0);
            }
            if sent == b.len() {
                let _ = p.client.send_stream(id).finish();
                return true;
            }
            false
        });
        assert!(ok, "request not sent: {sent} of {}", b.len());
        id
    }

    /// The response on `id`: its bytes, and how the stream ended (FIN or a reset code).
    fn response(&mut self, id: StreamId) -> (Vec<u8>, Result<(), u64>) {
        let mut got = Vec::new();
        let mut end = None;
        self.run(|p| {
            let mut rs = p.client.recv_stream(id);
            let Ok(mut chunks) = rs.read(true) else { return false };
            loop {
                match chunks.next(usize::MAX) {
                    Ok(Some(c)) => got.extend_from_slice(&c.bytes),
                    Ok(None) => {
                        end = Some(Ok(()));
                        break;
                    }
                    Err(ReadError::Reset(code)) => {
                        end = Some(Err(code.into_inner()));
                        break;
                    }
                    Err(ReadError::Blocked) => break,
                }
            }
            let _ = chunks.finalize();
            end.is_some()
        });
        (got, end.expect("the response ends"))
    }
}

/// A QUIC stream id from the mux's.
fn sid(id: u64) -> StreamId {
    StreamId::from(VarInt::from_u64(id).expect("id"))
}

fn frames(mut b: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let mut off = 0;
        let ty = parse_varint(b, &mut off).expect("type");
        let len = parse_varint(b, &mut off).expect("len") as usize;
        out.push((ty, b[off..off + len].to_vec()));
        b = &b[off + len..];
    }
    out
}

fn fields(fs: &[u8]) -> Vec<(String, String)> {
    qpack::decode_qpack_static(fs).expect("qpack").into_iter().map(|f| (f.name, f.value)).collect()
}

const GET_TRAILERS: &[(&str, &str)] = &[(":method", "GET"), (":scheme", "https"), (":authority", "localhost"), (":path", "/trailers")];

#[test]
fn a_response_with_trailers_over_quic_is_the_oracle_s_frames() {
    let mut p = Pair::new();
    let id = p.request(GET_TRAILERS, b"", 1);
    let (bytes, end) = p.response(id);
    assert_eq!(end, Ok(()), "the stream ends with a FIN");
    let f = frames(&bytes);
    assert_eq!(f.len(), 3, "{f:?}");
    assert_eq!(fields(&f[0].1), vec![(":status".into(), "200".into()), ("trailer".into(), "x-sum".into())]);
    assert_eq!(f[1], (0x00, b"abc".to_vec()));
    assert_eq!(fields(&f[2].1), vec![("x-sum".into(), "42".into())]);
    // Our control stream: type 0, SETTINGS capacity 0 and blocked streams 0.
    let ctl = p.client.streams().accept(Dir::Uni).expect("the server's control stream");
    let mut b = Vec::new();
    let mut rs = p.client.recv_stream(ctl);
    if let Ok(mut chunks) = rs.read(true) {
        while let Ok(Some(c)) = chunks.next(usize::MAX) {
            b.extend_from_slice(&c.bytes);
        }
        let _ = chunks.finalize();
    }
    assert_eq!(b, [vec![0x00], mux_h3::encode_settings()].concat());
    assert!(p.mux.streams.is_empty(), "the stream's context went back to qcs");
}

#[test]
fn connect_is_reset_0x10b_and_the_connection_serves_the_next_request() {
    let mut p = Pair::new();
    let id = p.request(&[(":method", "CONNECT"), (":authority", "localhost:443")], b"", 1);
    assert_eq!(p.response(id).1, Err(0x10b));
    let id = p.request(GET_TRAILERS, b"", 1);
    assert_eq!(p.response(id).1, Ok(()));
    assert!(p.client_lost.is_none());
}

#[test]
fn a_qpack_capacity_closes_the_connection_with_0x201() {
    let mut p = Pair::new();
    let enc = p.client.streams().open(Dir::Uni).expect("encoder stream");
    p.client.send_stream(enc).write(&[0x02, 0x25]).expect("capacity 5");
    let lost = p.run(|p| p.client_lost.is_some());
    assert!(lost, "the connection was not closed");
    match p.client_lost.take() {
        Some(ConnectionError::ApplicationClosed(c)) => assert_eq!(c.error_code.into_inner(), 0x201),
        other => panic!("closed how: {other:?}"),
    }
}

#[test]
fn a_large_body_is_held_to_one_buffer_while_a_slow_child_takes_it() {
    let mut p = Pair::new();
    p.take_per_pass = 4096;
    let body = vec![b'z'; 1 << 20];
    let len = body.len().to_string();
    let req = [(":method", "POST"), (":scheme", "https"), (":authority", "localhost"), (":path", "/up"), ("content-length", len.as_str())];
    let id = p.request(&req, &body, 16384);
    let (bytes, end) = p.response(id);
    assert_eq!(end, Ok(()));
    let f = frames(&bytes);
    assert_eq!(f.last().map(|x| x.1.clone()), Some(format!("got {}", 1 << 20).into_bytes()));
    assert!(p.max_buffered <= RX_DATA_ROOM, "the mux held {} bytes of one stream's body", p.max_buffered);
    assert!(p.max_buffered > RX_DATA_ROOM / 2, "the buffer filled: the client was held by its window, not by the mux reading slowly");
}
