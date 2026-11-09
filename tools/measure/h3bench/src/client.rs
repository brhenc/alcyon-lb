// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A deterministic HTTP/3 client (T555): one QUIC connection, sequential requests (one stream
//! at a time), and the client's **ACK policy fixed**, so that the number of datagrams the
//! server receives per request is set by the client and the server alone, not by timing.
//!
//! h2load's ACK-only datagrams vary from 1.12 to 1.91 per request between identical runs
//! (T544), and each one costs the server a full connection pass; this client removes that.
//!
//! - [`AckPolicy::Best`]: no ACK-only datagram. Whatever the client owes (ACKs, flow-control
//!   credit) rides in the packet of its next request: 1.000 client datagrams per request.
//! - [`AckPolicy::Worst`]: every datagram from the server is answered at once with what the
//!   client owes, an ACK if it was ack-eliciting (RFC 9000 13.2.1 with `max_ack_delay` 0):
//!   1 + (ack-eliciting server datagrams) per request, ~2. curl 8.18 (ngtcp2) sends 1.99 a
//!   request to `HAProxy` 3.5-dev10 and h2load 1.96: this is the realistic one.
//!
//! The client is quinn-proto's (sans-IO); time is the wall clock plus a skew. quinn delays an
//! ACK for one ack-eliciting packet by its own max_ack_delay (25 ms, not configurable); Worst
//! moves the client's clock to that timer and fires it instead of waiting, so the ACK goes out
//! at once (its ACK Delay field says 25 ms).
//!
//! [`Client::set_gap`] spaces the client's datagrams (the tool: 200 us), so that the server
//! takes each in a wakeup of its own; back to back, whether it reads an ACK and the next
//! request in one pass or two is timing, and moved Alcyon's figure by ~2 % between rounds.
//!
//! This file is compiled by `tools/measure/h3bench` (the binary) and by
//! `crates/alcyon-rt/tests/it/h3_bench_client.rs` (the test pinning both policies).

use quinn_proto::crypto::rustls::QuicClientConfig;
use quinn_proto::{ClientConfig, Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig, Event, StreamEvent, StreamId, VarInt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// When the client sends what it owes the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckPolicy {
    /// Only with its next request.
    Best,
    /// After every datagram it receives.
    Worst,
}

impl AckPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "best" => Some(Self::Best),
            "worst" => Some(Self::Worst),
            _ => None,
        }
    }
}

/// quinn-proto's own max_ack_delay (`TransportParameters` default; there is no knob for it).
const MAX_ACK_DELAY: Duration = Duration::from_millis(25);
/// How long a wait for the server's next datagram may block before timers are looked at.
const POLL: Duration = Duration::from_millis(2);
/// How long a request may take before the run fails.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Datagrams sent and received by the client.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub sent: u64,
    pub received: u64,
    /// Of `sent`, the datagrams the wait loop sent when quinn's timer expired while nothing came
    /// (a loss probe or a delayed ACK after the host stalled the client): not the policy's.
    pub timer_sent: u64,
}

impl Counts {
    pub fn since(self, before: Counts) -> Counts {
        Counts { sent: self.sent - before.sent, received: self.received - before.received, timer_sent: self.timer_sent - before.timer_sent }
    }
}

/// One run of [`Client::run`].
#[derive(Clone, Copy, Debug)]
pub struct Run {
    pub requests: u64,
    /// Responses with `:status 200`.
    pub ok: u64,
    /// Datagrams during the requests only (the handshake and the close excluded).
    pub requests_phase: Counts,
}

impl Run {
    /// Client datagrams per request, the figure the policy fixes.
    pub fn client_per_request(&self) -> f64 {
        self.requests_phase.sent as f64 / self.requests.max(1) as f64
    }
    pub fn server_per_request(&self) -> f64 {
        self.requests_phase.received as f64 / self.requests.max(1) as f64
    }
}

#[derive(Debug)]
struct AnyCert;

impl ServerCertVerifier for AnyCert {
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

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

/// An HTTP/3 frame: type, length, payload (RFC 9114 7.1).
fn frame(out: &mut Vec<u8>, ty: u8, payload: &[u8]) {
    out.push(ty);
    varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

fn varint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=63 => out.push(v as u8),
        64..=16383 => out.extend_from_slice(&(0x4000 | v as u16).to_be_bytes()),
        _ => out.extend_from_slice(&(0x8000_0000 | v as u32).to_be_bytes()),
    }
}

fn read_varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    let bytes = b.get(..len)?;
    let mut v = u64::from(first & 0x3f);
    for &x in &bytes[1..] {
        v = (v << 8) | u64::from(x);
    }
    Some((v, len))
}

/// The request stream's bytes: a HEADERS frame (QPACK, static table only) for `GET /`, or for
/// `POST /` with `content-length` and one DATA frame of `body`.
pub fn request_bytes(body: &[u8]) -> Vec<u8> {
    // Field section prefix: required insert count 0, base 0 (RFC 9204 4.5.1).
    let mut fs = vec![0x00, 0x00];
    // Indexed static fields (0b11 + 6-bit index): :method GET 17 / POST 20, :scheme https 23,
    // :path / 1; :authority (static name 0) and content-length (4) as literals with a name ref.
    fs.push(if body.is_empty() { 0xc0 | 17 } else { 0xc0 | 20 });
    fs.push(0xc0 | 23);
    fs.push(0xc0 | 1);
    fs.push(0x50);
    fs.push(9);
    fs.extend_from_slice(b"localhost");
    if !body.is_empty() {
        let len = body.len().to_string();
        fs.push(0x54);
        fs.push(len.len() as u8);
        fs.extend_from_slice(len.as_bytes());
    }
    let mut out = Vec::new();
    frame(&mut out, 0x01, &fs);
    if !body.is_empty() {
        frame(&mut out, 0x00, body);
    }
    out
}

/// Whether a response stream starts with a HEADERS frame whose first field is `:status 200`
/// (QPACK static index 25).
fn is_200(resp: &[u8]) -> bool {
    let Some((ty, a)) = read_varint(resp) else { return false };
    let Some((_, b)) = read_varint(&resp[a..]) else { return false };
    ty == 0x01 && resp.get(a + b + 2) == Some(&(0xc0 | 25))
}

pub struct Client {
    sock: UdpSocket,
    ep: Endpoint,
    handle: ConnectionHandle,
    conn: Connection,
    policy: AckPolicy,
    /// Added to the wall clock for quinn (only [`AckPolicy::Worst`] moves it).
    skew: Duration,
    buf: Vec<u8>,
    out: Vec<u8>,
    resp: Vec<u8>,
    uni: Vec<StreamId>,
    /// The least time from the client's last datagram, sent or received, to its next one
    /// ([`Client::set_gap`]).
    gap: Duration,
    last_io: Instant,
    pub counts: Counts,
}

impl Client {
    /// Connects, completes the handshake, opens the control stream (an empty SETTINGS) and
    /// waits until the server has been quiet for 20 ms, so that a run starts in steady state.
    pub fn connect(addr: SocketAddr, policy: AckPolicy) -> io::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut tls = rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(AnyCert)).with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).map_err(|e| err(format!("client config: {e}")))?));
        let bind = if addr.is_ipv4() { "127.0.0.1:0" } else { "[::1]:0" };
        let sock = UdpSocket::bind(bind)?;
        sock.set_read_timeout(Some(POLL))?;
        let mut ep = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
        let (handle, conn) = ep.connect(Instant::now(), cfg, addr, "localhost").map_err(|e| err(format!("connect: {e}")))?;
        let mut c = Client { sock, ep, handle, conn, policy, skew: Duration::ZERO, buf: vec![0; 65536], out: Vec::with_capacity(1500), resp: Vec::new(), uni: Vec::new(), gap: Duration::ZERO, last_io: Instant::now(), counts: Counts::default() };
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        while c.conn.is_handshaking() {
            if Instant::now() > deadline {
                return Err(err("no handshake"));
            }
            c.flush()?;
            c.wait_one()?;
        }
        let ctl = c.conn.streams().open(Dir::Uni).ok_or_else(|| err("no control stream"))?;
        // Stream type 0x00 (control), then SETTINGS (0x04) with no setting.
        c.conn.send_stream(ctl).write(&[0x00, 0x04, 0x00]).map_err(|e| err(format!("control stream: {e}")))?;
        let mut quiet_since = Instant::now();
        while quiet_since.elapsed() < Duration::from_millis(20) {
            c.flush()?;
            if c.wait_one()? {
                quiet_since = Instant::now();
            }
        }
        c.flush()?;
        Ok(c)
    }

    /// Sends each datagram at least `gap` after the client's previous one, sent or received
    /// (busy-waiting), so that the server has finished with the previous one and takes each in
    /// a wakeup of its own, rather than two in one pass or not depending on timing.
    pub fn set_gap(&mut self, gap: Duration) {
        self.gap = gap;
    }

    fn send(&mut self, len: usize, to: SocketAddr) -> io::Result<()> {
        while self.last_io.elapsed() < self.gap {
            std::hint::spin_loop();
        }
        self.sock.send_to(&self.out[..len], to)?;
        self.last_io = Instant::now();
        self.counts.sent += 1;
        Ok(())
    }

    fn now(&self) -> Instant {
        Instant::now() + self.skew
    }

    /// Sends everything quinn has to send now, one packet per datagram.
    fn flush(&mut self) -> io::Result<()> {
        let now = self.now();
        while let Some(t) = self.conn.poll_transmit(now, 1, &mut self.out) {
            self.send(t.size, t.destination)?;
            self.out.clear();
        }
        Ok(())
    }

    /// Waits up to [`POLL`] for one datagram and hands it to quinn. On a timeout, fires
    /// quinn's expired timers and sends what they produce (both policies: a timer is a loss or
    /// a delayed ACK nobody else would send). Returns whether a datagram came.
    fn wait_one(&mut self) -> io::Result<bool> {
        match self.sock.recv_from(&mut self.buf) {
            Ok((n, from)) => {
                self.last_io = Instant::now();
                self.counts.received += 1;
                let now = self.now();
                let mut response = Vec::new();
                match self.ep.handle(now, from, None, None, self.buf[..n].into(), &mut response) {
                    Some(DatagramEvent::ConnectionEvent(_, e)) => self.conn.handle_event(e),
                    Some(DatagramEvent::Response(t)) => {
                        self.out.clear();
                        self.out.extend_from_slice(&response[..t.size]);
                        self.send(t.size, t.destination)?;
                        self.out.clear();
                    }
                    _ => {}
                }
                self.events()?;
                if self.policy == AckPolicy::Worst {
                    self.answer(now)?;
                }
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(false),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                let now = self.now();
                if self.conn.poll_timeout().is_some_and(|t| t <= now) {
                    self.conn.handle_timeout(now);
                    self.events()?;
                    let before = self.counts.sent;
                    self.flush()?;
                    self.counts.timer_sent += self.counts.sent - before;
                }
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// [`AckPolicy::Worst`], after a datagram received at `at`: sends what quinn wants to send
    /// now (an immediate ACK), then fires the timers due within `max_ack_delay` of `at`, the
    /// delayed ACK among them, by moving the client's clock to each, and sends again.
    fn answer(&mut self, at: Instant) -> io::Result<()> {
        self.flush()?;
        while let Some(t) = self.conn.poll_timeout() {
            if t > at + MAX_ACK_DELAY {
                break;
            }
            let now = self.now();
            if t > now {
                self.skew += t - now;
            }
            self.conn.handle_timeout(t.max(now));
            self.events()?;
            self.flush()?;
        }
        Ok(())
    }

    /// quinn's endpoint and application events; the server's unidirectional streams (control,
    /// QPACK) are accepted and read to keep their flow control open.
    fn events(&mut self) -> io::Result<()> {
        while let Some(e) = self.conn.poll_endpoint_events() {
            if let Some(ce) = self.ep.handle_event(self.handle, e) {
                self.conn.handle_event(ce);
            }
        }
        while let Some(ev) = self.conn.poll() {
            match ev {
                Event::ConnectionLost { reason } => return Err(err(format!("connection lost: {reason}"))),
                Event::Stream(StreamEvent::Opened { dir: Dir::Uni }) => {
                    while let Some(id) = self.conn.streams().accept(Dir::Uni) {
                        self.uni.push(id);
                    }
                }
                _ => {}
            }
        }
        for &id in &self.uni {
            let mut rs = self.conn.recv_stream(id);
            if let Ok(mut chunks) = rs.read(true) {
                while let Ok(Some(_)) = chunks.next(usize::MAX) {}
                let _ = chunks.finalize();
            };
        }
        Ok(())
    }

    /// Reads what has arrived on `id` into `self.resp`; returns whether the stream has ended.
    fn read_response(&mut self, id: StreamId) -> bool {
        let mut rs = self.conn.recv_stream(id);
        let mut fin = false;
        if let Ok(mut chunks) = rs.read(true) {
            loop {
                match chunks.next(usize::MAX) {
                    Ok(Some(c)) => self.resp.extend_from_slice(&c.bytes),
                    Ok(None) => {
                        fin = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            let _ = chunks.finalize();
        }
        fin
    }

    /// One request on a new stream, until its response has ended. Returns whether it was a 200.
    pub fn request(&mut self, req: &[u8]) -> io::Result<bool> {
        let id = self.conn.streams().open(Dir::Bi).ok_or_else(|| err("no stream credit"))?;
        let mut s = self.conn.send_stream(id);
        if s.write(req).map_err(|e| err(format!("write: {e}")))? != req.len() {
            return Err(err("request did not fit the stream's window"));
        }
        s.finish().map_err(|e| err(format!("finish: {e}")))?;
        self.flush()?;
        self.resp.clear();
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        while !self.read_response(id) {
            if Instant::now() > deadline {
                return Err(err(format!("no response on {id} ({} bytes)", self.resp.len())));
            }
            self.wait_one()?;
        }
        Ok(is_200(&self.resp))
    }

    /// `n` requests, one after the other.
    pub fn run(&mut self, n: u64, req: &[u8]) -> io::Result<Run> {
        let before = self.counts;
        let mut ok = 0;
        for _ in 0..n {
            ok += u64::from(self.request(req)?);
        }
        Ok(Run { requests: n, ok, requests_phase: self.counts.since(before) })
    }

    /// Closes the connection (H3_NO_ERROR) and sends the CONNECTION_CLOSE.
    pub fn close(mut self) -> io::Result<Counts> {
        let now = self.now();
        self.conn.close(now, VarInt::from_u32(0x100), Default::default());
        self.flush()?;
        Ok(self.counts)
    }
}
