// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T511: the HTTP/3 owner and bridge (`tune.ibex.h3-path mux`) on the edges of a stream's
//! life, each row measured on `HAProxy` 3.5-dev7 built with QUIC (`reference/haproxy-quic`,
//! aioquic 1.3.0 client, `http-reuse never`, an HTTP/1 backend acting by path):
//!
//! | case | `HAProxy` |
//! |---|---|
//! | `tcp-request session reject` on the QUIC bind | no response, the connection closed (transport NO_ERROR) |
//! | server: `content-length: 100`, 10 bytes, close | 200, the 10 bytes, RESET_STREAM 0x10c |
//! | server: no length, `connection: close`, 10 bytes, close | 200, the 10 bytes, FIN |
//! | server: 204 | 204 and FIN, no DATA |
//! | 4 MiB response, client stream window 16 KiB | all of it, FIN |
//! | client resets its upload (RESET_STREAM 0x10c) after 10 of 100 bytes | server connection reset; the next request on the connection 200 |
//! | STOP_SENDING 0x10c on a 4 MiB response being sent | RESET_STREAM 0x10c, server connection reset; the next request 200 |
//! | a second SETTINGS on the client's control stream, a request at the server | CONNECTION_CLOSE 0x105 (H3_FRAME_UNEXPECTED); server connection reset |
//!
//! The relay (the default path until slice H5) differs on the session rule (502), the cut
//! response (FIN, then a connection error), the reset upload and the second SETTINGS (not
//! seen): those rows run on the mux only. On STOP_SENDING the relay stops sending but keeps
//! the server connection: that row checks the server connection on the mux only. Ibex closes a rejected connection with the
//! application code `H3_NO_ERROR` (0x100): quinn-proto has no transport-level close for an
//! application to send (`docs/differences.md`).

use crate::common;

use ibex_quic::quinn_proto::{
    crypto::rustls::QuicClientConfig, ClientConfig, Connection, ConnectionHandle, Dir, Endpoint, EndpointConfig,
    StreamId, TransportConfig, VarInt,
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
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// What the backend saw, one line an event: `head <path>`, `end <path> <how>`.
type Events = Arc<Mutex<Vec<String>>>;

const BIG: usize = 4 * 1024 * 1024;

/// A backend acting by path: `/cut` (length 100, 10 bytes, close), `/eof` (no length,
/// `connection: close`, 10 bytes, close), `/204`, `/big` (4 MiB), `/hold` (reads until the
/// proxy ends the connection, at most 3 s, and records how), anything else `200 ok`.
fn backend() -> (SocketAddr, Events) {
    let ls = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = ls.local_addr().expect("addr");
    let ev: Events = Arc::default();
    let ev2 = Arc::clone(&ev);
    thread::spawn(move || {
        for s in ls.incoming() {
            let Ok(mut s) = s else { continue };
            let ev = Arc::clone(&ev2);
            thread::spawn(move || {
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&got).lines().next().unwrap_or_default().to_string();
                let path = line.split(' ').nth(1).unwrap_or_default().to_string();
                ev.lock().unwrap().push(format!("head {path}"));
                let _ = match path.as_str() {
                    "/cut" => s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n0123456789"),
                    "/eof" => s.write_all(b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n0123456789"),
                    "/204" => s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n"),
                    "/big" => {
                        let mut r = format!("HTTP/1.1 200 OK\r\ncontent-length: {BIG}\r\n\r\n").into_bytes();
                        r.resize(r.len() + BIG, b'x');
                        let w = s.write_all(&r);
                        ev.lock().unwrap().push(format!("end /big {}", if w.is_ok() { "written" } else { "closed" }));
                        w
                    }
                    "/hold" => {
                        let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
                        let how = loop {
                            match s.read(&mut buf) {
                                Ok(0) => break "closed",
                                Ok(_) => {}
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => break "timeout",
                                Err(_) => break "closed",
                            }
                        };
                        ev.lock().unwrap().push(format!("end {path} {how}"));
                        return;
                    }
                    _ => s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"),
                };
                if matches!(path.as_str(), "/cut" | "/eof") {
                    thread::sleep(Duration::from_millis(100));
                    return;
                }
                thread::sleep(Duration::from_millis(500));
            });
        }
    });
    (addr, ev)
}

fn saw(ev: &Events, what: &str, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if ev.lock().unwrap().iter().any(|e| e == what) {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

struct Ibex {
    child: Child,
    quic: SocketAddr,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn ibex(be: SocketAddr, frontend_rule: &str) -> Ibex {
    let tcp = common::reserve_addr();
    let quic = common::reserve_addr();
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let mut cfg = NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "global\n    nbthread 1\ndefaults\n    mode http\n    timeout client 5s\n    timeout server 5s\n    \
         timeout connect 1s\nfrontend f\n    bind {tcp}\n    bind quic4@{quic} ssl crt {crt} alpn h3\n    \
         {frontend_rule}\n    default_backend b\nbackend b\n    http-reuse never\n    server s {be}\n"
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
    Ibex { child, quic, _cfg: cfg }
}

/// One QUIC connection to `ibex`, driven by hand.
struct Client {
    sock: UdpSocket,
    ep: Endpoint,
    handle: ConnectionHandle,
    conn: Connection,
    buf: Vec<u8>,
    /// The application or transport code the connection was closed with, if it was.
    lost: Option<String>,
}

impl Client {
    /// `window`: the stream receive window the client grants (quinn's default if `None`).
    fn connect(server: SocketAddr, window: Option<u32>) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut ctls = rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(Any)).with_no_client_auth();
        ctls.alpn_protocols = vec![b"h3".to_vec()];
        let mut client_cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(ctls).expect("client config")));
        if let Some(w) = window {
            let mut t = TransportConfig::default();
            t.stream_receive_window(VarInt::from_u32(w));
            t.receive_window(VarInt::from_u32(w * 4));
            client_cfg.transport_config(Arc::new(t));
        }
        let sock = UdpSocket::bind("127.0.0.1:0").expect("client socket");
        sock.set_nonblocking(true).expect("nonblocking");
        let mut ep = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
        let (handle, conn) = ep.connect(Instant::now(), client_cfg, server, "localhost").expect("connect");
        let mut c = Self { sock, ep, handle, conn, buf: vec![0u8; 65536], lost: None };
        c.run_until(Duration::from_secs(4), |c| !c.conn.is_handshaking() || c.lost.is_some());
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
                self.lost = Some(match reason {
                    ibex_quic::quinn_proto::ConnectionError::ApplicationClosed(a) => format!("app {:#x}", a.error_code.into_inner()),
                    ibex_quic::quinn_proto::ConnectionError::ConnectionClosed(c) => format!("transport {:#x}", u64::from(c.error_code)),
                    other => format!("{other}"),
                });
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

    fn open(&mut self, bytes: &[u8], fin: bool) -> StreamId {
        let id = self.conn.streams().open(Dir::Bi).expect("open");
        let mut s = self.conn.send_stream(id);
        assert_eq!(s.write(bytes).expect("write"), bytes.len());
        if fin {
            s.finish().expect("finish");
        }
        id
    }

    /// How stream `id` ended: the response's frames, its FIN, the code of a reset.
    fn outcome(&mut self, id: StreamId) -> Outcome {
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
                    Err(ibex_quic::quinn_proto::ReadError::Blocked) => break false,
                    Err(ibex_quic::quinn_proto::ReadError::Reset(code)) => {
                        reset = Some(code.into_inner());
                        break true;
                    }
                    Err(_) => break true,
                }
            };
            let _ = chunks.finalize();
            end
        });
        let f = frames(&all);
        let status = f.iter().find(|(t, _)| *t == 0x01).and_then(|(_, section)| {
            let fields = ibex_proto::qpack::decode_qpack_static(section).ok()?;
            fields.iter().find(|f| f.name == ":status").and_then(|f| f.value.parse().ok())
        });
        let data: Vec<u8> = f.iter().filter(|(t, _)| *t == 0x00).flat_map(|(_, p)| p.iter().copied()).collect();
        let data_frames = f.iter().filter(|(t, _)| *t == 0x00).count();
        Outcome { status, body: data.len(), data_frames, fin, reset, lost: self.lost.clone() }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct Outcome {
    status: Option<u16>,
    body: usize,
    data_frames: usize,
    fin: bool,
    reset: Option<u64>,
    lost: Option<String>,
}

fn frames(mut b: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut v = Vec::new();
    while !b.is_empty() {
        let mut off = 0;
        let Ok(ty) = ibex_proto::h3::parse_varint(b, &mut off) else { break };
        let Ok(len) = ibex_proto::h3::parse_varint(b, &mut off) else { break };
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
    ibex_proto::hpack::encode_integer(name.len(), 3, 0, &mut n);
    n[0] |= 0x20;
    out.extend_from_slice(&n);
    out.extend_from_slice(name);
    ibex_proto::hpack::encode_integer(value.len(), 7, 0, out);
    out.extend_from_slice(value);
}

/// A HEADERS frame: `method path`, `extra` fields after the pseudo-headers.
fn headers(method: &[u8], path: &[u8], extra: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut b = vec![0x00, 0x00];
    for (n, v) in [(&b":method"[..], method), (b":scheme", b"https"), (b":path", path), (b":authority", b"localhost")] {
        lit(&mut b, n, v);
    }
    for (n, v) in extra {
        lit(&mut b, n, v);
    }
    let mut out = Vec::new();
    ibex_proto::mux_h3::encode_frame(&mut out, 0x01, &b);
    out
}

fn get(path: &[u8]) -> Vec<u8> {
    headers(b"GET", path, &[])
}

/// H3_REQUEST_CANCELLED.
const REQUEST_CANCELLED: u64 = 0x10c;

crate::h3_both_paths! {
/// `HAProxy`: the 10 bytes, then FIN (the end of a close-delimited body).
fn a_close_delimited_response_ends_the_stream_with_its_fin() {
    let (be, _ev) = backend();
    let ibex = ibex(be, "");
    let mut cl = Client::connect(ibex.quic, None);
    let id = cl.open(&get(b"/eof"), true);
    let o = cl.outcome(id);
    assert_eq!((o.status, o.body, o.fin, o.reset, o.lost.as_deref()), (Some(200), 10, true, None, None), "{o:?}");
}
}

crate::h3_both_paths! {
/// `HAProxy`: 204, FIN, no DATA frame.
fn a_response_without_a_body_ends_with_its_head() {
    let (be, _ev) = backend();
    let ibex = ibex(be, "");
    let mut cl = Client::connect(ibex.quic, None);
    let id = cl.open(&get(b"/204"), true);
    let o = cl.outcome(id);
    assert_eq!((o.status, o.data_frames, o.fin, o.reset), (Some(204), 0, true, None), "{o:?}");
}
}

crate::h3_both_paths! {
/// `HAProxy`: all 4 MiB and FIN through a 16 KiB stream window (the owner writes what
/// quinn takes and the rest when the client grants more).
fn a_response_larger_than_the_clients_window_arrives_whole() {
    let (be, _ev) = backend();
    let ibex = ibex(be, "");
    let mut cl = Client::connect(ibex.quic, Some(16 * 1024));
    let id = cl.open(&get(b"/big"), true);
    let o = cl.outcome(id);
    assert_eq!((o.status, o.body, o.fin, o.reset), (Some(200), BIG, true, None), "{o:?}");
}
}

/// `HAProxy`: 200, the 10 bytes it had, then RESET_STREAM H3_REQUEST_CANCELLED.
#[test]
fn a_response_the_server_cuts_short_resets_the_stream() {
    common::on_h3_path("mux", || {
        let (be, _ev) = backend();
        let ibex = ibex(be, "");
        let mut cl = Client::connect(ibex.quic, None);
        let id = cl.open(&get(b"/cut"), true);
        let o = cl.outcome(id);
        assert_eq!((o.status, o.body, o.reset, o.lost.as_deref()), (Some(200), 10, Some(REQUEST_CANCELLED), None), "{o:?}");
        let id = cl.open(&get(b"/next"), true);
        assert_eq!(cl.outcome(id).status, Some(200), "the connection serves the next request");
    });
}

/// `HAProxy`: the connection closed, nothing served, the server never contacted.
#[test]
fn tcp_request_session_reject_closes_the_quic_connection() {
    common::on_h3_path("mux", || {
        let (be, ev) = backend();
        let ibex = ibex(be, "tcp-request session reject if { src 127.0.0.1 }");
        let mut cl = Client::connect(ibex.quic, None);
        if cl.lost.is_none() {
            let id = cl.open(&get(b"/x"), true);
            let o = cl.outcome(id);
            assert_eq!(o.status, None, "a rejected session was served: {o:?}");
        }
        cl.run_until(Duration::from_secs(2), |c| c.lost.is_some());
        assert_eq!(cl.lost.as_deref(), Some("app 0x100"), "closed with H3_NO_ERROR (HAProxy: transport NO_ERROR)");
        assert!(ev.lock().unwrap().is_empty(), "the server was contacted: {:?}", ev.lock().unwrap());
    });
}

/// `HAProxy`: the client resets its upload; the server connection is closed, and the next
/// request on the QUIC connection is served.
#[test]
fn an_upload_the_client_resets_ends_its_server_connection() {
    common::on_h3_path("mux", || {
        let (be, ev) = backend();
        let ibex = ibex(be, "");
        let mut cl = Client::connect(ibex.quic, None);
        let mut req = headers(b"POST", b"/hold", &[(b"content-length", b"100")]);
        ibex_proto::mux_h3::encode_frame(&mut req, 0x00, b"0123456789");
        let id = cl.open(&req, false);
        cl.run_until(Duration::from_millis(500), |_| false);
        assert!(saw(&ev, "head /hold", Duration::from_secs(2)), "the upload never reached the server: {:?}", ev.lock().unwrap());
        cl.conn.send_stream(id).reset(VarInt::from_u32(REQUEST_CANCELLED as u32)).expect("reset");
        cl.run_until(Duration::from_millis(300), |_| false);
        assert!(saw(&ev, "end /hold closed", Duration::from_secs(2)), "the server connection outlived the reset: {:?}", ev.lock().unwrap());
        let id = cl.open(&get(b"/after"), true);
        let o = cl.outcome(id);
        assert_eq!((o.status, o.lost.as_deref()), (Some(200), None), "{o:?}");
    });
}

/// `HAProxy`: a second SETTINGS on the client's control stream is H3_FRAME_UNEXPECTED, a
/// connection error (CONNECTION_CLOSE 0x105), and the request at the server is ended.
#[test]
fn a_connection_error_closes_the_connection_and_ends_its_streams() {
    common::on_h3_path("mux", || {
        let (be, ev) = backend();
        let ibex = ibex(be, "");
        let mut cl = Client::connect(ibex.quic, None);
        let id = cl.open(&get(b"/hold"), true);
        cl.run_until(Duration::from_millis(300), |_| false);
        assert!(saw(&ev, "head /hold", Duration::from_secs(2)), "the request never reached the server");
        let ctl = cl.conn.streams().open(Dir::Uni).expect("control stream");
        let mut b = vec![0x00];
        ibex_proto::mux_h3::encode_frame(&mut b, 0x04, b"");
        ibex_proto::mux_h3::encode_frame(&mut b, 0x04, b"");
        cl.conn.send_stream(ctl).write(&b).expect("write control");
        let o = cl.outcome(id);
        cl.run_until(Duration::from_secs(2), |c| c.lost.is_some());
        assert_eq!(cl.lost.as_deref(), Some("app 0x105"), "{o:?}");
        assert!(saw(&ev, "end /hold closed", Duration::from_secs(2)), "the server connection outlived the connection: {:?}", ev.lock().unwrap());
    });
}

crate::h3_both_paths! {
/// A soft stop closes an idle connection at once, also one whose client went away without
/// a word after a stream of it was refused (`content-length` 3, DATA of 5: H3_MESSAGE_ERROR).
/// `HAProxy` 3.5-dev7 exits 0.06 s after SIGUSR1 (the same client, measured, T511); the mux
/// owner used to sleep through the stop until quinn's 30 s idle timeout.
fn a_soft_stop_closes_an_abandoned_connection_at_once() {
    let (be, _ev) = backend();
    let mut ibex = ibex(be, "");
    let mut cl = Client::connect(ibex.quic, None);
    let mut req = headers(b"POST", b"/x", &[(b"content-length", b"3")]);
    ibex_proto::mux_h3::encode_frame(&mut req, 0x00, b"hello");
    let id = cl.open(&req, true);
    let o = cl.outcome(id);
    assert_eq!((o.status, o.reset), (None, Some(0x10e)), "{o:?}");
    drop(cl);
    let pid = rustix::process::Pid::from_raw(i32::try_from(ibex.child.id()).expect("pid")).expect("pid");
    rustix::process::kill_process(pid, rustix::process::Signal::Usr1).expect("SIGUSR1");
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(10) && !matches!(ibex.child.try_wait(), Ok(Some(_))) {
        thread::sleep(Duration::from_millis(20));
    }
    let took = t0.elapsed();
    assert!(took < Duration::from_secs(2), "ibex took {took:?} to stop (HAProxy: 0.06 s)");
}
}

crate::h3_both_paths! {
/// The client stops reading a large response (STOP_SENDING H3_REQUEST_CANCELLED) once its
/// first bytes are in: `HAProxy` resets the stream with that code and the server connection,
/// and serves the next request on the connection.
fn stop_sending_on_a_response_ends_its_server_connection() {
    let (be, ev) = backend();
    let ibex = ibex(be, "");
    let mut cl = Client::connect(ibex.quic, Some(16 * 1024));
    let id = cl.open(&get(b"/big"), true);
    let mut got = 0usize;
    cl.run_until(Duration::from_secs(4), |c| {
        let mut rs = c.conn.recv_stream(id);
        if let Ok(mut chunks) = rs.read(true) {
            while let Ok(Some(ch)) = chunks.next(usize::MAX) {
                got += ch.bytes.len();
            }
            let _ = chunks.finalize();
        }
        got > 0
    });
    assert!(got > 0 && got < BIG, "got {got} bytes before the stop");
    cl.conn.recv_stream(id).stop(VarInt::from_u32(REQUEST_CANCELLED as u32)).expect("stop");
    cl.run_until(Duration::from_millis(300), |_| false);
    if common::h3_mux() {
        assert!(saw(&ev, "end /big closed", Duration::from_secs(3)), "the server connection outlived the stop: {:?}", ev.lock().unwrap());
    }
    let id = cl.open(&get(b"/after"), true);
    let o = cl.outcome(id);
    assert_eq!((o.status, o.lost.as_deref()), (Some(200), None), "{o:?}");
}
}
