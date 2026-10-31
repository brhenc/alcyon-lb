// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T525: `tune.quic.fe.max-idle-timeout`, `tune.quic.fe.stream.max-concurrent`,
//! `tune.quic.fe.stream.max-total` and `tune.quic.listen` reach the QUIC listener.
//! (`tune.quic.fe.sec.retry-threshold` has its tests in `quic_retry.rs`.)
//!
//! Measured on the QUIC oracle (`HAProxy` 3.5-dev7-e6f616-55, `reference/haproxy-quic`, aioquic
//! 1.3.0 client, `nbthread 1`, 2026-10-31, `frontend` answering `http-request return status 200`):
//!
//! | config | `HAProxy` |
//! |---|---|
//! | `max-idle-timeout 2s` | transport parameter 2 s; a silent client's connection ends at 2.01 s, "Idle timeout" |
//! | idle `4s`, `timeout client 1s` | closed at 1.10 s, application error 0x100 (the owner's timer first) |
//! | idle `1s`, `timeout client 4s` | closed at 1.01 s, "Idle timeout" |
//! | `stream.max-concurrent 3` | `initial_max_streams_bidi` 3 (default 100); a compliant client waits for credit |
//! | `stream.max-total 3` (concurrent 100) | `initial_max_streams_bidi` 3; responses 1-3 delivered, then close 0x100; stream 4 gets nothing |
//! | `stream.max-total 3`, `max-concurrent 2` | `initial_max_streams_bidi` 2 (the smaller) |
//! | `tune.quic.listen off` | `haproxy -c` passes, no message, the TCP bind of the frontend is served, no UDP socket exists |
//! | `tune.quic.listen on` (default) | one UDP socket per bind and thread |

use crate::common;

use ibex_quic::quinn_proto::{
    crypto::rustls::QuicClientConfig, ClientConfig, Connection, ConnectionHandle, Dir, Endpoint, EndpointConfig, StreamId,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
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

struct Ibex {
    child: Child,
    tcp: SocketAddr,
    quic: SocketAddr,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// Ibex with `global` extra lines and `timeouts` (lines of `defaults`); every request is
/// answered 200 by the frontend itself.
fn ibex(global: &str, timeouts: &str) -> Ibex {
    ibex_in("frontend f", global, timeouts)
}

/// `ibex` with the binds in `section` (`frontend f` or `listen l`, T530).
fn ibex_in(section: &str, global: &str, timeouts: &str) -> Ibex {
    let tcp = common::reserve_addr();
    let quic = common::reserve_addr();
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let mut cfg = NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "global\n    nbthread 1\n    hard-stop-after 300ms\n    {global}\ndefaults\n    mode http\n    {timeouts}\n\
         {section}\n    bind {tcp}\n    bind quic4@{quic} ssl crt {crt} alpn h3\n    http-request return status 200\n"
    )
    .expect("write cfg");
    let child = common::ibex_command(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    assert!(common::wait_listening(tcp), "ibex never listened");
    Ibex { child, tcp, quic, _cfg: cfg }
}

/// One QUIC connection to `ibex`, driven by hand.
struct Client {
    sock: UdpSocket,
    ep: Endpoint,
    handle: ConnectionHandle,
    conn: Connection,
    buf: Vec<u8>,
    /// How the connection was lost and when.
    lost: Option<(String, Instant)>,
}

impl Client {
    /// Starts a handshake; `connect` waits for it.
    fn start(server: SocketAddr) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut ctls = rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(std::sync::Arc::new(Any)).with_no_client_auth();
        ctls.alpn_protocols = vec![b"h3".to_vec()];
        let client_cfg = ClientConfig::new(std::sync::Arc::new(QuicClientConfig::try_from(ctls).expect("client config")));
        let sock = UdpSocket::bind("127.0.0.1:0").expect("client socket");
        sock.set_nonblocking(true).expect("nonblocking");
        let mut ep = Endpoint::new(std::sync::Arc::new(EndpointConfig::default()), None, true, None);
        let (handle, conn) = ep.connect(Instant::now(), client_cfg, server, "localhost").expect("connect");
        Self { sock, ep, handle, conn, buf: vec![0u8; 65536], lost: None }
    }

    fn connect(server: SocketAddr) -> Self {
        let mut c = Self::start(server);
        c.run_until(Duration::from_secs(4), |c| !c.conn.is_handshaking() || c.lost.is_some());
        assert!(!c.conn.is_handshaking(), "no handshake: {:?}", c.lost);
        // A control stream with an empty SETTINGS, as every client sends.
        let ctl = c.conn.streams().open(Dir::Uni).expect("control stream");
        let mut b = vec![0x00];
        ibex_proto::mux_h3::encode_frame(&mut b, 0x04, b"");
        c.conn.send_stream(ctl).write(&b).expect("write control");
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
        while let Some(e) = self.conn.poll() {
            if let ibex_quic::quinn_proto::Event::ConnectionLost { reason } = e {
                let why = match reason {
                    ibex_quic::quinn_proto::ConnectionError::ApplicationClosed(a) => format!("app {:#x}", a.error_code.into_inner()),
                    ibex_quic::quinn_proto::ConnectionError::ConnectionClosed(c) => format!("transport {:#x}", u64::from(c.error_code)),
                    other => format!("{other}"),
                };
                self.lost.get_or_insert((why, Instant::now()));
            }
        }
    }

    fn run_until(&mut self, within: Duration, mut done: impl FnMut(&mut Self) -> bool) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            self.step();
            if done(self) {
                return true;
            }
        }
        false
    }

    /// Runs until the connection is lost (at most `within`): how, and when.
    fn closed(&mut self, within: Duration) -> Option<(String, Instant)> {
        self.run_until(within, |c| c.lost.is_some());
        self.lost.clone()
    }

    /// Opens a request stream with `GET /`, or `None` when the server's stream limit is reached.
    fn try_get(&mut self) -> Option<StreamId> {
        let id = self.conn.streams().open(Dir::Bi)?;
        let mut s = self.conn.send_stream(id);
        let req = get();
        assert_eq!(s.write(&req).expect("write"), req.len());
        s.finish().expect("finish");
        Some(id)
    }

    /// How many request streams the server lets this client open at once.
    fn open_streams(&mut self) -> usize {
        let mut n = 0;
        while self.try_get().is_some() {
            n += 1;
        }
        n
    }

    /// The status of the response on stream `id`, if it arrives within `within`.
    fn status(&mut self, id: StreamId, within: Duration) -> Option<u16> {
        let mut all = Vec::new();
        self.run_until(within, |c| {
            let mut rs = c.conn.recv_stream(id);
            let Ok(mut chunks) = rs.read(true) else { return true };
            let end = loop {
                match chunks.next(usize::MAX) {
                    Ok(Some(ch)) => all.extend_from_slice(&ch.bytes),
                    Ok(None) => break true,
                    Err(_) => break false,
                }
            };
            let _ = chunks.finalize();
            end || c.lost.is_some()
        });
        let mut b = &all[..];
        while !b.is_empty() {
            let mut off = 0;
            let ty = ibex_proto::h3::parse_varint(b, &mut off).ok()?;
            let len = usize::try_from(ibex_proto::h3::parse_varint(b, &mut off).ok()?).ok()?;
            if off + len > b.len() {
                return None;
            }
            if ty == 0x01 {
                let fields = ibex_proto::qpack::decode_qpack_static(&b[off..off + len]).ok()?;
                return fields.iter().find(|f| f.name == ":status").and_then(|f| f.value.parse().ok());
            }
            b = &b[off + len..];
        }
        None
    }
}

/// A literal field line with a literal name (RFC 9204 4.5.6), static table only.
fn lit(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    let mut n = Vec::new();
    ibex_proto::hpack::encode_integer(name.len(), 3, 0, &mut n);
    n[0] |= 0x20;
    out.extend_from_slice(&n);
    out.extend_from_slice(name);
    ibex_proto::hpack::encode_integer(value.len(), 7, 0, out);
    out.extend_from_slice(value);
}

/// A HEADERS frame for `GET /`.
fn get() -> Vec<u8> {
    let mut b = vec![0x00, 0x00];
    for (n, v) in [(&b":method"[..], &b"GET"[..]), (b":scheme", b"https"), (b":path", b"/"), (b":authority", b"localhost")] {
        lit(&mut b, n, v);
    }
    let mut out = Vec::new();
    ibex_proto::mux_h3::encode_frame(&mut out, 0x01, &b);
    out
}

crate::h3_both_paths! {
    /// `max-idle-timeout` shorter than the owner's timers: the transport ends the connection,
    /// silently (the client's own idle timer, 30 s, would not have fired), at the configured time.
    fn idle_timeout_shorter_than_timeout_client_ends_the_connection_at_the_idle_time() {
        let ibex = ibex("tune.quic.fe.max-idle-timeout 1s", "timeout client 5s\n    timeout http-request 5s\n    timeout http-keep-alive 5s");
        let t0 = Instant::now();
        let mut cl = Client::connect(ibex.quic);
        let (why, at) = cl.closed(Duration::from_secs(4)).expect("closed by the idle timeout");
        let took = at.duration_since(t0);
        assert_eq!(why, "timed out", "after {took:?}");
        assert!(took >= Duration::from_millis(900) && took <= Duration::from_millis(2500), "closed after {took:?}");
    }
}

crate::h3_both_paths! {
    /// The default idle time is 30 s: nothing closes an idle connection in 2 s.
    fn without_the_keyword_the_idle_time_is_not_short() {
        let ibex = ibex("", "timeout client 20s\n    timeout http-request 20s\n    timeout http-keep-alive 20s");
        let mut cl = Client::connect(ibex.quic);
        assert_eq!(cl.closed(Duration::from_millis(2500)), None);
    }
}

/// `max-idle-timeout` longer than the owner's timer: `timeout http-request` ends the
/// connection first, gracefully (`H3_NO_ERROR`), as in T521. (The relay has no owner timer.)
#[test]
fn idle_timeout_longer_than_timeout_client_leaves_the_owners_timer_first() {
    common::on_h3_path("mux", || {
        let ibex = ibex("tune.quic.fe.max-idle-timeout 5s", "timeout client 1s\n    timeout http-request 1s\n    timeout http-keep-alive 1s");
        let t0 = Instant::now();
        let mut cl = Client::connect(ibex.quic);
        let (why, at) = cl.closed(Duration::from_secs(4)).expect("closed by the owner");
        let took = at.duration_since(t0);
        assert_eq!(why, "app 0x100", "after {took:?}");
        assert!(took >= Duration::from_millis(900) && took <= Duration::from_millis(2500), "closed after {took:?}");
    });
}

crate::h3_both_paths! {
    /// The default limit is 100 request streams, `max-concurrent` replaces it in the
    /// transport parameters the client reads.
    fn max_concurrent_is_the_stream_credit_the_client_gets() {
        let ibex = ibex("", "timeout client 10s");
        let mut cl = Client::connect(ibex.quic);
        assert_eq!(cl.open_streams(), 100);
        drop(cl);
        let ibex = self::ibex("tune.quic.fe.stream.max-concurrent 3", "timeout client 10s");
        let mut cl = Client::connect(ibex.quic);
        assert_eq!(cl.open_streams(), 3);
    }
}

crate::h3_both_paths! {
    /// Streams past the credit are opened as the earlier ones end: all of them are answered.
    fn streams_past_the_concurrent_limit_wait_for_credit_and_are_served() {
        let ibex = ibex("tune.quic.fe.stream.max-concurrent 2", "timeout client 10s");
        let mut cl = Client::connect(ibex.quic);
        for _ in 0..6 {
            let id = loop {
                if let Some(id) = cl.try_get() {
                    break id;
                }
                cl.run_until(Duration::from_millis(50), |_| false);
                assert!(cl.lost.is_none(), "lost: {:?}", cl.lost);
            };
            assert_eq!(cl.status(id, Duration::from_secs(3)), Some(200));
        }
    }
}

crate::h3_both_paths! {
    /// `max-total` limits the credit like `max-concurrent` (the smaller of the two), and after
    /// that many streams are done the connection is closed with `H3_NO_ERROR`; the last response
    /// is delivered first.
    fn max_total_closes_the_connection_after_that_many_streams() {
        let ibex = ibex("tune.quic.fe.stream.max-total 3", "timeout client 10s");
        let mut cl = Client::connect(ibex.quic);
        for n in 1..=3 {
            let id = cl.try_get().unwrap_or_else(|| panic!("stream {n} not opened"));
            assert_eq!(cl.status(id, Duration::from_secs(3)), Some(200), "stream {n}");
        }
        let (why, _) = cl.closed(Duration::from_secs(3)).expect("closed after the third stream");
        assert_eq!(why, "app 0x100");
        // A new connection starts again at stream 0.
        let mut cl = Client::connect(ibex.quic);
        let id = cl.try_get().expect("first stream of a new connection");
        assert_eq!(cl.status(id, Duration::from_secs(3)), Some(200));
    }
}

crate::h3_both_paths! {
    fn max_total_is_also_the_initial_credit_when_smaller_than_max_concurrent() {
        let ibex = ibex("tune.quic.fe.stream.max-total 4", "timeout client 10s");
        let mut cl = Client::connect(ibex.quic);
        assert_eq!(cl.open_streams(), 4);
        drop(cl);
        let ibex = self::ibex("tune.quic.fe.stream.max-total 4\n    tune.quic.fe.stream.max-concurrent 2", "timeout client 10s");
        let mut cl = Client::connect(ibex.quic);
        assert_eq!(cl.open_streams(), 2);
    }
}

/// True when a UDP socket of ours can take `addr`: nothing else holds it.
fn udp_free(addr: SocketAddr) -> bool {
    UdpSocket::bind(addr).is_ok()
}

#[test]
fn listen_off_binds_no_udp_socket_and_the_tcp_bind_still_serves() {
    let ibex = ibex("tune.quic.listen off", "timeout client 10s");
    assert!(udp_free(ibex.quic), "a UDP socket is bound on {}", ibex.quic);
    let mut s = std::net::TcpStream::connect(ibex.tcp).expect("tcp");
    s.write_all(b"GET / HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n").expect("write");
    let mut got = String::new();
    std::io::Read::read_to_string(&mut s, &mut got).expect("read");
    assert!(got.starts_with("HTTP/1.1 200"), "{got}");
    let mut cl = Client::start(ibex.quic);
    assert!(!cl.run_until(Duration::from_millis(600), |c| !c.conn.is_handshaking()), "a handshake completed with listen off");
}

/// `listen off` reaches a `listen` section's QUIC bind too (T530 opens those binds).
#[test]
fn listen_off_binds_no_udp_socket_for_a_listen_section_either() {
    let ibex = ibex_in("listen l", "tune.quic.listen off", "timeout client 10s");
    assert!(udp_free(ibex.quic), "a UDP socket is bound on {}", ibex.quic);
    let on = ibex_in("listen l", "", "timeout client 10s");
    assert!(!udp_free(on.quic), "no UDP socket on {} with listen on", on.quic);
}

#[test]
fn listen_on_is_the_default_and_binds_the_udp_socket() {
    for line in ["", "tune.quic.listen on"] {
        let ibex = ibex(line, "timeout client 10s");
        assert!(!udp_free(ibex.quic), "{line:?}: no UDP socket on {}", ibex.quic);
    }
}
