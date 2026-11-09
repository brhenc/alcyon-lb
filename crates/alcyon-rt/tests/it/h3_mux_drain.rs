// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T521: how an HTTP/3 connection ends under the mux (`tune.alcyon.h3-path mux`): the owner's
//! timers, a GOAWAY from the client, the soft stop's drain, client resets, concurrent streams
//! (rows 1-5 of the task). Each row measured on `HAProxy`
//! 3.5-dev7 built with QUIC (`reference/haproxy-quic`, aioquic 1.3.0 client, `timeout
//! http-request 2s`, `http-keep-alive 4s`, `client 6s`, an HTTP/1 backend, 2026-10-31):
//!
//! | case | `HAProxy` |
//! |---|---|
//! | handshake, no request | 2.00 s: GOAWAY(0), then CONNECTION_CLOSE app 0x100 |
//! | 3 bytes of a HEADERS frame on stream 0 | 2.00 s after them: GOAWAY(4), close 0x100 |
//! | one GET served, then idle | 4.00 s after the response: GOAWAY(4), close 0x100 |
//! | GET served, a partial head on stream 4 1 s later | 2.00 s after the partial: GOAWAY(8), close |
//! | GET /slow (backend 2 s) | the response at 2.0 s, nothing cut; close 4 s after it |
//! | client GOAWAY(0) or (4) during /slow, then a GET on stream 4 | stream 4 served (200); close at keep-alive after /slow |
//! | SIGUSR1 during /slow, a GET on stream 4 after it | GOAWAY(4) at once; stream 4 RESET_STREAM 0x10b; /slow's response; close 0x100; exit |
//! | the same, the response's datagrams dropped for 1.3 s | retransmitted: the response arrives at 3.7 s, then the close |
//! | RESET_STREAM + STOP_SENDING 0x10c (or STOP_SENDING alone) 0.5 s into /slow | RESET_STREAM 0x10c; server connection reset; `400 0 - - CD--`; next stream 200 |
//! | 20 GET /slow at once on one connection | all 20 answered at 2.0 s; descriptors 10 -> 31 |
//!
//! `HAProxy`'s client GOAWAY only marks the connection (`QC_CF_CONN_SHUT`, read for backend
//! reuse): a frontend serves streams opened after it. Before T521 the mux owner had no timer
//! (the 30 s transport idle timeout closed every row above, transport NO_ERROR), a soft stop
//! closed the connection once its last FIN was written, not acknowledged (the drop row lost
//! its response, and so, most runs, did the plain SIGUSR1 row: the close went out with the
//! response unsent), and a reset whole request logged `CH--`.

use crate::common;

use alcyon_quic::quinn_proto::{
    crypto::rustls::QuicClientConfig, ClientConfig, Connection, ConnectionHandle, Dir, Endpoint, EndpointConfig,
    StreamId,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::process::{Child, Stdio};
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
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// How long `/slow` takes.
const SLOW: Duration = Duration::from_millis(1500);

/// An HTTP/1 backend: `/slow` answers after [`SLOW`], anything else at once.
fn backend() -> SocketAddr {
    let ls = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = ls.local_addr().expect("addr");
    thread::spawn(move || {
        for s in ls.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    let mut got = Vec::new();
                    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => got.extend_from_slice(&buf[..n]),
                        }
                    }
                    if got.starts_with(b"GET /slow") {
                        thread::sleep(SLOW);
                    }
                    if s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
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

impl Alcyon {
    fn usr1(&self) {
        let pid = rustix::process::Pid::from_raw(i32::try_from(self.child.id()).expect("pid")).expect("pid");
        rustix::process::kill_process(pid, rustix::process::Signal::Usr1).expect("SIGUSR1");
    }

    fn exited_within(&mut self, within: Duration) -> bool {
        let t0 = Instant::now();
        while t0.elapsed() < within {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }
}

/// Alcyon on the mux with `timeouts` (lines of `defaults`) in place of the usual ones.
fn alcyon(be: SocketAddr, timeouts: &str) -> Alcyon {
    let tcp = common::reserve_addr();
    let quic = common::reserve_addr();
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let mut cfg = NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "global\n    nbthread 1\ndefaults\n    mode http\n    timeout server 10s\n    timeout connect 1s\n    \
         {timeouts}\nfrontend f\n    bind {tcp}\n    bind quic4@{quic} ssl crt {crt} alpn h3\n    \
         default_backend b\nbackend b\n    server s {be}\n"
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
pub(crate) struct Client {
    pub(crate) sock: UdpSocket,
    ep: Endpoint,
    handle: ConnectionHandle,
    conn: Connection,
    buf: Vec<u8>,
    /// The application or transport code the connection was closed with, and when.
    pub(crate) lost: Option<(String, Instant)>,
    /// What each of the server's unidirectional streams carried.
    uni: HashMap<StreamId, Vec<u8>>,
    /// Until then, datagrams from the server are dropped unread.
    deaf_until: Option<Instant>,
    /// Until then, what the client sends is dropped (lost on the way, or gone to the other
    /// process of a reload): quinn retransmits it.
    mute_until: Option<Instant>,
    /// Our control stream.
    control: Option<StreamId>,
}

impl Client {
    pub(crate) fn connect(server: SocketAddr) -> Self {
        let mut c = Self::begin(server);
        c.finish_handshake();
        c
    }

    /// Sends the client's first Initial and nothing more: the server's answer waits in the
    /// socket until [`Client::finish_handshake`].
    fn begin(server: SocketAddr) -> Self {
        Self::begin_on(UdpSocket::bind("127.0.0.1:0").expect("client socket"), server)
    }

    /// As [`Client::begin`], from an existing socket (T567: a second client on a source port
    /// a first one still holds).
    pub(crate) fn begin_on(sock: UdpSocket, server: SocketAddr) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut ctls = rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(std::sync::Arc::new(Any)).with_no_client_auth();
        ctls.alpn_protocols = vec![b"h3".to_vec()];
        let client_cfg = ClientConfig::new(std::sync::Arc::new(QuicClientConfig::try_from(ctls).expect("client config")));
        sock.set_nonblocking(true).expect("nonblocking");
        let mut ep = Endpoint::new(std::sync::Arc::new(EndpointConfig::default()), None, true, None);
        let (handle, conn) = ep.connect(Instant::now(), client_cfg, server, "localhost").expect("connect");
        let mut c = Self { sock, ep, handle, conn, buf: vec![0u8; 65536], lost: None, uni: HashMap::new(), deaf_until: None, mute_until: None, control: None };
        c.transmit();
        c
    }

    /// Completes the handshake and opens the control stream.
    pub(crate) fn conn_is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    pub(crate) fn finish_handshake(&mut self) {
        let c = self;
        c.run_until(Duration::from_secs(4), |c| !c.conn.is_handshaking() || c.lost.is_some());
        assert!(!c.conn.is_handshaking(), "no handshake: {:?}", c.lost);
        // A control stream with an empty SETTINGS, as every client sends.
        let ctl = c.conn.streams().open(Dir::Uni).expect("control stream");
        let mut b = vec![0x00];
        alcyon_proto::mux_h3::encode_frame(&mut b, 0x04, b"");
        c.conn.send_stream(ctl).write(&b).expect("write control");
        c.control = Some(ctl);
    }

    fn transmit(&mut self) {
        let now = Instant::now();
        let mute = self.mute_until.is_some_and(|t| now < t);
        let mut out = Vec::new();
        while let Some(t) = self.conn.poll_transmit(now, 1, &mut out) {
            if !mute {
                let _ = self.sock.send_to(&out[..t.size], t.destination);
            }
            out.clear();
        }
    }

    fn step(&mut self) {
        self.transmit();
        thread::sleep(Duration::from_millis(2));
        let now = Instant::now();
        let deaf = self.deaf_until.is_some_and(|t| now < t);
        while let Ok((n, from)) = self.sock.recv_from(&mut self.buf) {
            if deaf {
                continue;
            }
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
                let why = match reason {
                    alcyon_quic::quinn_proto::ConnectionError::ApplicationClosed(a) => format!("app {:#x}", a.error_code.into_inner()),
                    alcyon_quic::quinn_proto::ConnectionError::ConnectionClosed(c) => format!("transport {:#x}", u64::from(c.error_code)),
                    other => format!("{other}"),
                };
                self.lost.get_or_insert((why, Instant::now()));
            }
        }
        while let Some(id) = self.conn.streams().accept(Dir::Uni) {
            self.uni.entry(id).or_default();
        }
        let ids: Vec<StreamId> = self.uni.keys().copied().collect();
        for id in ids {
            let mut rs = self.conn.recv_stream(id);
            let Ok(mut chunks) = rs.read(true) else { continue };
            let mut got = Vec::new();
            while let Ok(Some(ch)) = chunks.next(usize::MAX) {
                got.extend_from_slice(&ch.bytes);
            }
            let _ = chunks.finalize();
            self.uni.get_mut(&id).expect("uni").extend_from_slice(&got);
        }
    }

    pub(crate) fn run_until(&mut self, within: Duration, mut done: impl FnMut(&mut Self) -> bool) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            self.step();
            if done(self) {
                return true;
            }
        }
        false
    }

    /// Runs until the connection is closed (at most `within`): the code and when.
    pub(crate) fn closed(&mut self, within: Duration) -> Option<(String, Instant)> {
        self.run_until(within, |c| c.lost.is_some());
        self.lost.clone()
    }

    pub(crate) fn open(&mut self, bytes: &[u8], fin: bool) -> StreamId {
        let id = self.conn.streams().open(Dir::Bi).expect("open");
        let mut s = self.conn.send_stream(id);
        assert_eq!(s.write(bytes).expect("write"), bytes.len());
        if fin {
            s.finish().expect("finish");
        }
        id
    }

    /// The GOAWAY ids on the server's control stream.
    fn goaways(&self) -> Vec<u64> {
        let Some(ctl) = self.uni.values().find(|b| b.first() == Some(&0x00)) else { return Vec::new() };
        frames(&ctl[1..]).into_iter().filter(|(t, _)| *t == 0x07).filter_map(|(_, p)| alcyon_proto::h3::parse_varint(&p, &mut 0).ok()).collect()
    }

    /// How stream `id` ended: its status, FIN or reset code.
    pub(crate) fn outcome(&mut self, id: StreamId) -> Outcome {
        let mut all = Vec::new();
        let (mut fin, mut reset) = (false, None);
        self.run_until(Duration::from_secs(8), |c| {
            if c.lost.is_some() {
                return true;
            }
            let mut rs = c.conn.recv_stream(id);
            let Ok(mut chunks) = rs.read(true) else { return true };
            let end = loop {
                match chunks.next(usize::MAX) {
                    Ok(Some(ch)) => all.extend_from_slice(&ch.bytes),
                    Ok(None) => {
                        fin = true;
                        break true;
                    }
                    Err(alcyon_quic::quinn_proto::ReadError::Blocked) => break false,
                    Err(alcyon_quic::quinn_proto::ReadError::Reset(code)) => {
                        reset = Some(code.into_inner());
                        break true;
                    }
                }
            };
            let _ = chunks.finalize();
            end
        });
        let f = frames(&all);
        let status = f.iter().find(|(t, _)| *t == 0x01).and_then(|(_, section)| {
            let fields = alcyon_proto::qpack::decode_qpack_static(section).ok()?;
            fields.iter().find(|f| f.name == ":status").and_then(|f| f.value.parse().ok())
        });
        Outcome { status, fin, reset, at: Instant::now() }
    }
}

#[derive(Debug)]
pub(crate) struct Outcome {
    pub(crate) status: Option<u16>,
    pub(crate) fin: bool,
    pub(crate) reset: Option<u64>,
    pub(crate) at: Instant,
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

/// A literal field line with a literal name (RFC 9204 4.5.6), static table only.
fn lit(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    let mut n = Vec::new();
    alcyon_proto::hpack::encode_integer(name.len(), 3, 0, &mut n);
    n[0] |= 0x20;
    out.extend_from_slice(&n);
    out.extend_from_slice(name);
    alcyon_proto::hpack::encode_integer(value.len(), 7, 0, out);
    out.extend_from_slice(value);
}

/// A HEADERS frame for `GET path`.
pub(crate) fn get(path: &[u8]) -> Vec<u8> {
    let mut b = vec![0x00, 0x00];
    for (n, v) in [(&b":method"[..], &b"GET"[..]), (b":scheme", b"https"), (b":path", path), (b":authority", b"localhost")] {
        lit(&mut b, n, v);
    }
    let mut out = Vec::new();
    alcyon_proto::mux_h3::encode_frame(&mut out, 0x01, &b);
    out
}

/// H3_REQUEST_REJECTED.
const REQUEST_REJECTED: u64 = 0x10b;

/// Asserts the connection closed gracefully (GOAWAY `goaway`, then H3_NO_ERROR), between
/// `at_least` and `at_most` after `from`.
fn assert_graceful_close(cl: &mut Client, from: Instant, at_least: Duration, at_most: Duration, goaway: u64) {
    let lost = cl.closed(at_most + Duration::from_secs(1));
    let Some((code, at)) = lost else { panic!("not closed within {at_most:?}") };
    let took = at.duration_since(from);
    assert_eq!(code, "app 0x100", "closed after {took:?}");
    assert!(took >= at_least && took <= at_most, "closed after {took:?}, expected {at_least:?}..{at_most:?}");
    assert_eq!(cl.goaways(), vec![goaway], "GOAWAYs before the close");
}

/// Row 1: a connection that never sends a request ends at `timeout http-request` from its
/// start (`qcc->idle_start`), not at `timeout client` (5 s here).
#[test]
fn a_connection_without_a_request_ends_at_http_request() {
    common::on_h3_path("mux", || {
        let alcyon = alcyon(backend(), "timeout http-request 1s\n    timeout http-keep-alive 5s\n    timeout client 5s");
        let t0 = Instant::now();
        let mut cl = Client::connect(alcyon.quic);
        assert_graceful_close(&mut cl, t0, Duration::from_millis(900), Duration::from_millis(3000), 0);
    });
}

/// Row 1 (RV-16): a partial request head, after a request served on the connection, ends the
/// connection at `timeout http-request` from the partial stream's start, not at `timeout
/// http-keep-alive` from the last response (5 s here), nor 30 s of transport idle.
#[test]
fn a_partial_head_ends_the_connection_at_http_request() {
    common::on_h3_path("mux", || {
        let alcyon = alcyon(backend(), "timeout http-request 1s\n    timeout http-keep-alive 5s\n    timeout client 5s");
        let mut cl = Client::connect(alcyon.quic);
        let id = cl.open(&get(b"/a"), true);
        let o = cl.outcome(id);
        assert_eq!((o.status, o.fin), (Some(200), true), "{o:?}");
        cl.run_until(Duration::from_millis(300), |_| false);
        let head = get(b"/b");
        let t0 = Instant::now();
        let _ = cl.open(&head[..3], false);
        assert_graceful_close(&mut cl, t0, Duration::from_millis(900), Duration::from_millis(2500), 8);
    });
}

/// Row 1: an idle connection that served a request ends at `timeout http-keep-alive` from
/// the end of its last response.
#[test]
fn an_idle_connection_ends_at_http_keep_alive() {
    common::on_h3_path("mux", || {
        let alcyon = alcyon(backend(), "timeout http-request 5s\n    timeout http-keep-alive 1s\n    timeout client 5s");
        let mut cl = Client::connect(alcyon.quic);
        let id = cl.open(&get(b"/a"), true);
        let o = cl.outcome(id);
        assert_eq!((o.status, o.fin), (Some(200), true), "{o:?}");
        assert_graceful_close(&mut cl, o.at, Duration::from_millis(900), Duration::from_millis(2500), 4);
    });
}

/// Row 1: no `timeout http-keep-alive`: the idle wait is `timeout http-request`.
#[test]
fn without_http_keep_alive_the_idle_wait_is_http_request() {
    common::on_h3_path("mux", || {
        let alcyon = alcyon(backend(), "timeout http-request 1s\n    timeout client 5s");
        let mut cl = Client::connect(alcyon.quic);
        let id = cl.open(&get(b"/a"), true);
        let o = cl.outcome(id);
        assert_eq!(o.status, Some(200), "{o:?}");
        assert_graceful_close(&mut cl, o.at, Duration::from_millis(900), Duration::from_millis(2500), 4);
    });
}

/// Row 1: a request being served holds the connection open past every idle timer (its stream
/// has `timeout client` of its own); the keep-alive wait starts at its end.
#[test]
fn a_request_in_progress_is_not_cut_by_the_connection_timers() {
    common::on_h3_path("mux", || {
        let alcyon = alcyon(backend(), "timeout http-request 500ms\n    timeout http-keep-alive 500ms\n    timeout client 5s");
        let mut cl = Client::connect(alcyon.quic);
        let id = cl.open(&get(b"/slow"), true);
        let o = cl.outcome(id);
        assert_eq!((o.status, o.fin, cl.lost.as_ref().map(|l| l.0.clone())), (Some(200), true, None), "{o:?}");
        assert_graceful_close(&mut cl, o.at, Duration::from_millis(400), Duration::from_millis(2000), 4);
    });
}

/// Row 2: a GOAWAY from the client changes nothing on a frontend (`HAProxy` serves a stream
/// opened after it); the connection still ends at its keep-alive timer.
#[test]
fn a_stream_after_the_clients_goaway_is_served() {
    common::on_h3_path("mux", || {
        let alcyon = alcyon(backend(), "timeout http-request 5s\n    timeout http-keep-alive 1s\n    timeout client 5s");
        let mut cl = Client::connect(alcyon.quic);
        let slow = cl.open(&get(b"/slow"), true);
        cl.run_until(Duration::from_millis(300), |_| false);
        let mut b = Vec::new();
        alcyon_proto::mux_h3::encode_frame(&mut b, 0x07, &[0x00]);
        let ctl = cl.control.expect("control");
        cl.conn.send_stream(ctl).write(&b).expect("goaway");
        cl.run_until(Duration::from_millis(300), |_| false);
        let after = cl.open(&get(b"/after"), true);
        let o = cl.outcome(after);
        assert_eq!((o.status, o.fin), (Some(200), true), "{o:?}");
        let o = cl.outcome(slow);
        assert_eq!((o.status, o.fin), (Some(200), true), "{o:?}");
        assert_graceful_close(&mut cl, o.at, Duration::from_millis(900), Duration::from_millis(2500), 8);
    });
}

/// Row 3: SIGUSR1 during a request: GOAWAY with the next stream id at once, a stream opened
/// after it rejected (H3_REQUEST_REJECTED, so the client retries elsewhere), the request in
/// flight answered, then the close, and the process exits.
#[test]
fn a_soft_stop_rejects_new_streams_and_answers_the_one_in_flight() {
    common::on_h3_path("mux", || {
        let mut alcyon = alcyon(backend(), "timeout client 5s");
        let mut cl = Client::connect(alcyon.quic);
        let slow = cl.open(&get(b"/slow"), true);
        cl.run_until(Duration::from_millis(300), |_| false);
        alcyon.usr1();
        assert!(cl.run_until(Duration::from_secs(2), |c| !c.goaways().is_empty()), "no GOAWAY after SIGUSR1");
        assert_eq!(cl.goaways(), vec![4]);
        let late = cl.open(&get(b"/late"), true);
        let o = cl.outcome(late);
        assert_eq!((o.status, o.reset), (None, Some(REQUEST_REJECTED)), "{o:?}");
        let o = cl.outcome(slow);
        assert_eq!((o.status, o.fin), (Some(200), true), "{o:?} {:?}", cl.lost);
        let lost = cl.closed(Duration::from_secs(3));
        assert_eq!(lost.map(|l| l.0).as_deref(), Some("app 0x100"));
        assert!(alcyon.exited_within(Duration::from_secs(5)), "alcyon did not exit after the drain");
    });
}

/// Row 3: a soft stop closes a connection once its responses are acknowledged, not once
/// they are written: the client loses the response's datagrams for 1.3 s and still gets it
/// (`HAProxy`: retransmitted, the response at 3.7 s, then the close). Before T521 the owner
/// closed after the write; quinn retransmits nothing after a close and the response was lost
/// -- the reload loss of M2 §5.3 seen through a soft stop.
#[test]
fn a_soft_stop_waits_for_the_response_to_be_acknowledged() {
    common::on_h3_path("mux", || {
        let mut alcyon = alcyon(backend(), "timeout client 10s");
        let mut cl = Client::connect(alcyon.quic);
        let t0 = Instant::now();
        let slow = cl.open(&get(b"/slow"), true);
        cl.run_until(Duration::from_millis(300), |_| false);
        alcyon.usr1();
        assert!(cl.run_until(Duration::from_secs(2), |c| !c.goaways().is_empty()), "no GOAWAY after SIGUSR1");
        // Deaf from just before the response until well after it.
        let deaf_from = t0 + SLOW - Duration::from_millis(200);
        cl.run_until(deaf_from.saturating_duration_since(Instant::now()), |_| false);
        cl.deaf_until = Some(Instant::now() + Duration::from_millis(1500));
        let o = cl.outcome(slow);
        assert_eq!((o.status, o.fin, cl.lost.as_ref().map(|l| l.0.clone())), (Some(200), true, None), "{o:?}");
        let lost = cl.closed(Duration::from_secs(5));
        assert_eq!(lost.map(|l| l.0).as_deref(), Some("app 0x100"));
        assert!(alcyon.exited_within(Duration::from_secs(5)), "alcyon did not exit after the drain");
    });
}

/// T558 (VV-30): a connection whose handshake the old process of a reload completes after
/// its soft stop began -- the client's Finished and request went first to the new process,
/// whose socket joined the reuseport group, and came back on the pinned socket -- is served.
/// Before T558 the old process found it idle the moment it was accepted, sent GOAWAY(0) and
/// closed it `H3_NO_ERROR`: curl's request on stream 0, already sent, was lost (ngtcp2
/// `ERR_DRAINING`), 1.8 % of short requests across 100 reloads. Here the stop lands between
/// the client's Initial and its Finished, and the request's first transmission is lost.
#[test]
fn a_connection_whose_handshake_ends_during_a_soft_stop_is_served() {
    for path in ["mux", "relay"] {
        common::on_h3_path(path, || {
            let mut alcyon = alcyon(backend(), "timeout client 5s");
            let mut cl = Client::begin(alcyon.quic);
            thread::sleep(Duration::from_millis(100));
            alcyon.usr1();
            thread::sleep(Duration::from_millis(150));
            cl.finish_handshake();
            cl.mute_until = Some(Instant::now() + Duration::from_millis(150));
            let id = cl.open(&get(b"/a"), true);
            let o = cl.outcome(id);
            assert_eq!((o.status, o.fin), (Some(200), true), "{path}: {o:?} {:?} GOAWAYs {:?}", cl.lost, cl.goaways());
            let lost = cl.closed(Duration::from_secs(3));
            assert_eq!(lost.map(|l| l.0).as_deref(), Some("app 0x100"), "{path}");
            if path == "mux" {
                assert_eq!(cl.goaways(), vec![4], "{path}: the GOAWAY names the stream served");
            }
            // The closed connection drains for three PTOs (RFC 9000 10.2) before the process
            // can leave, and this client's held handshake and lost request left the server an
            // RTT estimate of about a second: ~10 s here, ~0 on a real reload.
            assert!(alcyon.exited_within(Duration::from_secs(15)), "{path}: alcyon did not exit after the drain");
        });
    }
}

/// T558: a connection that is established but has sent no request yet when the soft stop
/// begins was opened to send one, which may be on the wire: it gets its first request
/// served (GOAWAY after it), not GOAWAY(0) and a close at once.
#[test]
fn a_fresh_connection_at_a_soft_stop_gets_its_first_request_served() {
    for path in ["mux", "relay"] {
        common::on_h3_path(path, || {
            let mut alcyon = alcyon(backend(), "timeout client 5s");
            let mut cl = Client::connect(alcyon.quic);
            cl.run_until(Duration::from_millis(100), |_| false);
            alcyon.usr1();
            cl.run_until(Duration::from_millis(150), |c| c.lost.is_some());
            let id = cl.open(&get(b"/a"), true);
            let o = cl.outcome(id);
            assert_eq!((o.status, o.fin), (Some(200), true), "{path}: {o:?} {:?} GOAWAYs {:?}", cl.lost, cl.goaways());
            let lost = cl.closed(Duration::from_secs(3));
            assert_eq!(lost.map(|l| l.0).as_deref(), Some("app 0x100"), "{path}");
            assert!(alcyon.exited_within(Duration::from_secs(5)), "{path}: alcyon did not exit after the drain");
        });
    }
}

/// T564: the first request's wait is counted in the process's time awake, not the wall's: a
/// stopping process starved past the grace (the reload test under the gate's load, `SIGSTOP`
/// here) finds the request its client sent meanwhile waiting in its socket. It must read it
/// before it judges the connection idle, not close it (`H3_NO_ERROR`; curl `ERR_DRAINING`).
#[test]
fn a_first_request_sent_while_the_stopping_process_is_starved_is_served() {
    common::on_h3_path("mux", || {
        let mut alcyon = alcyon(backend(), "timeout client 10s");
        let mut cl = Client::connect(alcyon.quic);
        cl.run_until(Duration::from_millis(100), |_| false);
        alcyon.usr1();
        cl.run_until(Duration::from_millis(150), |c| c.lost.is_some());
        assert!(cl.lost.is_none(), "closed before the request: {:?}", cl.lost);
        let pid = rustix::process::Pid::from_raw(i32::try_from(alcyon.child.id()).expect("pid")).expect("pid");
        rustix::process::kill_process(pid, rustix::process::Signal::Stop).expect("SIGSTOP");
        let id = cl.open(&get(b"/a"), true);
        cl.run_until(Duration::from_millis(1300), |_| false);
        rustix::process::kill_process(pid, rustix::process::Signal::Cont).expect("SIGCONT");
        let o = cl.outcome(id);
        assert_eq!((o.status, o.fin), (Some(200), true), "{o:?} {:?} GOAWAYs {:?}", cl.lost, cl.goaways());
        let lost = cl.closed(Duration::from_secs(3));
        assert_eq!(lost.map(|l| l.0).as_deref(), Some("app 0x100"));
        assert!(alcyon.exited_within(Duration::from_secs(5)), "alcyon did not exit after the drain");
    });
}

/// T558: the wait for that first request is bounded: a fresh connection that sends nothing
/// is closed (GOAWAY(0), `H3_NO_ERROR`) about a second into the stop, and the process exits.
#[test]
fn a_fresh_connection_that_sends_nothing_is_closed_after_the_stop_grace() {
    common::on_h3_path("mux", || {
        let mut alcyon = alcyon(backend(), "timeout client 10s");
        let mut cl = Client::connect(alcyon.quic);
        cl.run_until(Duration::from_millis(100), |_| false);
        let t0 = Instant::now();
        alcyon.usr1();
        assert_graceful_close(&mut cl, t0, Duration::from_millis(800), Duration::from_millis(2500), 0);
        assert!(alcyon.exited_within(Duration::from_secs(3)), "alcyon did not exit after the drain");
    });
}

/// The first log line `collector` receives that contains `what` (within 6 s).
fn log_line_with(collector: &UdpSocket, what: &str) -> String {
    collector.set_read_timeout(Some(Duration::from_secs(6))).expect("timeout");
    let mut buf = [0u8; 2048];
    loop {
        let n = collector.recv(&mut buf).unwrap_or_else(|_| panic!("no log line with {what}"));
        let l = String::from_utf8_lossy(&buf[..n]).into_owned();
        if l.contains(what) {
            return l;
        }
    }
}

/// Row 4: the client resets a request it sent whole while the server has not answered
/// (RESET_STREAM and STOP_SENDING H3_REQUEST_CANCELLED, or STOP_SENDING alone): `HAProxy`
/// 3.5-dev7 resets the stream with the client's code, resets the server connection, logs
/// `400 0 - - CD--` (h2 RST_STREAM the same, on 3.5-dev8 as well), counts `cli_abrt` twice,
/// and serves the connection's next stream. Alcyon logged `CH--` on h2 and h3 alike.
#[test]
fn a_reset_from_the_client_aborts_its_stream_as_on_h2() {
    common::on_h3_path("mux", || {
        let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
        let log = format!("timeout client 5s\n    log {} local0\n    option httplog", collector.local_addr().expect("addr"));
        let alcyon = alcyon(backend(), &log);
        let mut cl = Client::connect(alcyon.quic);
        for (path, reset) in [(&b"/slow?reset"[..], true), (&b"/slow?stop"[..], false)] {
            let id = cl.open(&get(path), true);
            cl.run_until(Duration::from_millis(300), |_| false);
            let code = alcyon_quic::quinn_proto::VarInt::from_u32(0x10c);
            if reset {
                // Refused once our FIN is acknowledged (quinn: `ClosedStream`); the
                // STOP_SENDING below then carries the abort alone.
                let _ = cl.conn.send_stream(id).reset(code);
            }
            cl.conn.recv_stream(id).stop(code).expect("stop");
            // (A stream we stopped is not readable here: the RESET_STREAM that answers it
            // is quinn's to absorb.)
            cl.run_until(Duration::from_millis(300), |_| false);
            let line = log_line_with(&collector, std::str::from_utf8(path).expect("path"));
            assert!(line.contains(" 400 0 - - CD-- "), "{line}");
        }
        let id = cl.open(&get(b"/after"), true);
        let o = cl.outcome(id);
        assert_eq!((o.status, o.fin), (Some(200), true), "{o:?}");
    });
}

fn fds(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd")).map_or(0, Iterator::count)
}

/// Row 5 (M2 §4.1 under the mux): 20 requests at once on one connection are served at once,
/// each a child holding one descriptor, its server connection (`HAProxy` 3.5-dev7, the same
/// 20 `/slow` streams from aioquic: answered together at 2.0 s, 10 -> 31 descriptors; the
/// relay path: 3 a request, its socket pair and server connection).
#[test]
fn twenty_concurrent_streams_are_served_at_once_one_descriptor_each() {
    common::on_h3_path("mux", || {
        let alcyon = alcyon(backend(), "timeout client 5s");
        let mut cl = Client::connect(alcyon.quic);
        cl.run_until(Duration::from_millis(200), |_| false);
        let before = fds(alcyon.child.id());
        let t0 = Instant::now();
        let ids: Vec<StreamId> = (0..20).map(|i| cl.open(&get(format!("/slow?{i}").as_bytes()), true)).collect();
        cl.run_until(SLOW / 2, |_| false);
        let extra = fds(alcyon.child.id()).saturating_sub(before);
        for id in ids {
            let o = cl.outcome(id);
            assert_eq!((o.status, o.fin), (Some(200), true), "{o:?}");
        }
        // One after the other they would take 20 x 1.5 s.
        assert!(t0.elapsed() < SLOW * 3, "20 streams took {:?}", t0.elapsed());
        assert!((20..=21).contains(&extra), "{extra} descriptors for 20 requests in flight");
    });
}

/// The log line of the stream whose request line contains `what`, as the fields of
/// `TR=%TR Tw=%Tw Tc=%Tc Tr=%Tr Ta=%Ta Th=%Th Ti=%Ti Tt=%Tt` (T529).
fn timings(collector: &UdpSocket, what: &str) -> std::collections::HashMap<String, i64> {
    let l = log_line_with(collector, what);
    l.split_whitespace().filter_map(|w| w.split_once('=')).filter_map(|(k, v)| Some((k.to_owned(), v.parse().ok()?))).collect()
}

const TIMINGS_FORMAT: &str = "log-format \"TR=%TR Tw=%Tw Tc=%Tc Tr=%Tr Ta=%Ta Th=%Th Ti=%Ti Tt=%Tt %ST %{+Q}r\"";

/// T529: a stream is timed from its own start, not from the end of the connection's previous
/// stream. `HAProxy` 3.5-dev7 (QUIC), a stream reset 500 ms after it started, then a
/// `GET /plain` 500 ms later: `TR=0 Tw=0 Tc=0 Tr=1 Ta=1 Th=0 Ti=501 Tt=502` (the idle time
/// before the stream is `Ti`; 3.5-dev8 on h2 the same, `Ti=500`). Alcyon logged `TR=501 Ta=502 Ti=-1`.
#[test]
fn the_stream_after_a_reset_stream_is_timed_from_its_own_start() {
    common::on_h3_path("mux", || {
        let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
        let log = format!("timeout client 5s\n    log {} local0\n    {TIMINGS_FORMAT}", collector.local_addr().expect("addr"));
        let alcyon = alcyon(backend(), &log);
        let mut cl = Client::connect(alcyon.quic);
        let id = cl.open(&get(b"/slow?cancel"), true);
        cl.run_until(Duration::from_millis(500), |_| false);
        let code = alcyon_quic::quinn_proto::VarInt::from_u32(0x10c);
        let _ = cl.conn.send_stream(id).reset(code);
        cl.conn.recv_stream(id).stop(code).expect("stop");
        cl.run_until(Duration::from_millis(500), |_| false);
        let id = cl.open(&get(b"/after"), true);
        let o = cl.outcome(id);
        assert_eq!((o.status, o.fin), (Some(200), true), "{o:?}");
        let t = timings(&collector, "/after");
        assert!(t["TR"] <= 50 && t["Ta"] <= 100 && t["Tr"] <= 50, "{t:?}");
        assert!((400..=700).contains(&t["Ti"]) && t["Tt"] >= t["Ti"], "{t:?}");
    });
}

/// T529: the same with no reset: stream 1 done, 500 ms idle, stream 2. `HAProxy` 3.5-dev7
/// (QUIC): `TR=0 Ta=0 Ti=500 Tt=500`.
#[test]
fn the_stream_after_an_idle_gap_is_timed_from_its_own_start() {
    common::on_h3_path("mux", || {
        let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
        let log = format!("timeout client 5s\n    log {} local0\n    {TIMINGS_FORMAT}", collector.local_addr().expect("addr"));
        let alcyon = alcyon(backend(), &log);
        let mut cl = Client::connect(alcyon.quic);
        let id = cl.open(&get(b"/first"), true);
        let o = cl.outcome(id);
        assert_eq!((o.status, o.fin), (Some(200), true), "{o:?}");
        let first = timings(&collector, "/first");
        // The first stream has no idle time to speak of (`Ti=0` on HAProxy).
        assert!(first["Ti"] >= 0 && first["Ti"] <= 50 && first["TR"] <= 50, "{first:?}");
        cl.run_until(Duration::from_millis(500), |_| false);
        let id = cl.open(&get(b"/second"), true);
        let o = cl.outcome(id);
        assert_eq!((o.status, o.fin), (Some(200), true), "{o:?}");
        let t = timings(&collector, "/second");
        assert!(t["TR"] <= 50 && t["Ta"] <= 100, "{t:?}");
        assert!((400..=700).contains(&t["Ti"]) && t["Tt"] >= t["Ti"], "{t:?}");
    });
}
