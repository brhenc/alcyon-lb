// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T520 (slice H3b, part 1): trailers, interim responses and CONNECT under
//! `tune.ibex.h3-path mux`, each row measured on `HAProxy` 3.5-dev7 built with QUIC
//! (`reference/haproxy-quic`, aioquic 1.3.0 client, an HTTP/1 backend acting by path):
//!
//! | case | `HAProxy` |
//! |---|---|
//! | chunked response with a trailer section | HEADERS 200, DATA `abc`, HEADERS `x-sum: 42` + FIN; `B=81` |
//! | the same with `option http-drop-response-trailers` | HEADERS 200, DATA `abc` + FIN; `B=81` (Ibex: 74, the trailers are cut before they are counted) |
//! | request: HEADERS, DATA, HEADERS (trailers) + FIN | the server gets `5\r\nhello\r\n0\r\nx-t: v1\r\nx-u: v2\r\n\r\n` chunked; `U=106` |
//! | `:method CONNECT` | RESET_STREAM `0x10b` (H3_REQUEST_REJECTED); the next request on the connection 200 |
//! | extended CONNECT (`:protocol`) | RESET_STREAM `0x10e` (H3_MESSAGE_ERROR); the next request 200 |
//! | `te: gzip` | RESET_STREAM `0x10e`; the next request 200 |
//! | server: `103` then (400 ms later) `200` | **HEADERS 103 with FIN, the final response never sent** (3.5-dev7 bug) |
//! | `expect: 100-continue`, the server answers `100` | **HEADERS 100 with FIN, the final response never sent** (same) |
//! | server: `103` and `200` in one segment | `BUG_ON htx.c:391`, SIGILL |
//!
//! The last three rows are the oracle failing: the interim HEADERS carries the FIN
//! (`h3_resp_headers_send`), which ends the stream. Ibex follows RFC 9114 section 4.1 (an
//! interim response is a HEADERS frame without FIN, the final response follows) and does not
//! reproduce the crash; the difference is in `docs/differences.md`. The relay (the default
//! path until slice H5) drops interim responses and response trailers, and resets CONNECT with
//! `400` for CONNECT; the relay's CONNECT row is pinned below.

use crate::common;

use ibex_quic::quinn_proto::{
    crypto::rustls::QuicClientConfig, ClientConfig, Connection, ConnectionHandle, Dir, Endpoint, EndpointConfig, StreamId,
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

/// The requests the backend read, as bytes.
pub(crate) type Seen = Arc<Mutex<Vec<Vec<u8>>>>;

/// Whether `got` is a whole request: its head, and the body its framing announces.
fn complete(got: &[u8]) -> bool {
    let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") else { return false };
    let head = String::from_utf8_lossy(&got[..at]).to_ascii_lowercase();
    let body = &got[at + 4..];
    if head.contains("transfer-encoding: chunked") {
        let text = String::from_utf8_lossy(body);
        return text.ends_with("\r\n\r\n") && (text.starts_with("0\r\n") || text.contains("\r\n0\r\n"));
    }
    let len = head.split("content-length: ").nth(1).and_then(|r| r.split("\r\n").next()).and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
    body.len() >= len
}

/// A backend acting by path: `/trailers` (chunked, `x-sum: 42` trailer), `/split` (the same in two writes), `/early2` (`103`,
/// 300 ms, `200`), `/early1` (both in one segment), `/cont` (`100 Continue`, then the
/// answer once the body is in), anything else `200 ok`. The requests are recorded.
pub(crate) fn backend() -> (SocketAddr, Seen) {
    let ls = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = ls.local_addr().expect("addr");
    let seen: Seen = Arc::default();
    let seen2 = Arc::clone(&seen);
    thread::spawn(move || {
        for s in ls.incoming() {
            let Ok(mut s) = s else { continue };
            let seen = Arc::clone(&seen2);
            thread::spawn(move || {
                s.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                let mut continued = false;
                loop {
                    let head_in = got.windows(4).any(|w| w == b"\r\n\r\n");
                    if head_in && !continued && got.starts_with(b"POST /cont") {
                        continued = true;
                        let _ = s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                    }
                    if complete(&got) {
                        break;
                    }
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let path = String::from_utf8_lossy(&got).split(' ').nth(1).unwrap_or_default().to_string();
                seen.lock().unwrap().push(got);
                let _ = match path.as_str() {
                    "/trailers" => s.write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ntrailer: x-sum\r\n\r\n3\r\nabc\r\n0\r\nx-sum: 42\r\n\r\n"),
                    "/split" => {
                        // The trailer section arrives in two reads.
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ntrailer: x-sum\r\n\r\n3\r\nabc\r\n0\r\nx-sum: ");
                        thread::sleep(Duration::from_millis(300));
                        s.write_all(b"42\r\n\r\n")
                    }
                    "/early2" => {
                        let _ = s.write_all(b"HTTP/1.1 103 Early Hints\r\nlink: </s.css>; rel=preload\r\n\r\n");
                        thread::sleep(Duration::from_millis(300));
                        s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                    }
                    "/early1" => s.write_all(b"HTTP/1.1 103 Early Hints\r\nlink: </s.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"),
                    _ => s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"),
                };
                thread::sleep(Duration::from_millis(500));
            });
        }
    });
    (addr, seen)
}

struct Ibex {
    child: Child,
    quic: SocketAddr,
    log: UdpSocket,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// An ibex with a QUIC bind to the backend, `frontend_extra` lines in the frontend, and
/// every request logged as `B=%B U=%U r=%r` to the UDP socket `log`.
fn ibex(be: SocketAddr, frontend_extra: &str) -> Ibex {
    ibex_srv(be, frontend_extra, "")
}

/// As `ibex`, with `server_extra` on the server line (`proto h2`).
fn ibex_srv(be: SocketAddr, frontend_extra: &str, server_extra: &str) -> Ibex {
    let tcp = common::reserve_addr();
    let quic = common::reserve_addr();
    let log = UdpSocket::bind("127.0.0.1:0").expect("log socket");
    log.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let mut cfg = NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "global\n    nbthread 1\ndefaults\n    mode http\n    timeout client 5s\n    timeout server 5s\n    \
         timeout connect 1s\nfrontend f\n    bind {tcp}\n    bind quic4@{quic} ssl crt {crt} alpn h3\n    \
         log {} local0\n    log-format \"B=%B U=%U r=%r\"\n    {frontend_extra}\n    default_backend b\n\
         backend b\n    http-reuse never\n    server s {be} {server_extra}\n",
        log.local_addr().expect("log addr")
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
    // The probe connection above is logged as a request that never came.
    let mut b = [0u8; 512];
    let _ = log.recv(&mut b);
    Ibex { child, quic, log, _cfg: cfg }
}

impl Ibex {
    /// The next log line, from `B=` on.
    fn log_line(&self) -> String {
        let mut b = [0u8; 1024];
        let n = self.log.recv(&mut b).expect("a log line");
        let s = String::from_utf8_lossy(&b[..n]).into_owned();
        s[s.find("B=").expect("B=")..].trim_end().to_string()
    }
}

/// One QUIC connection to `ibex`, driven by hand.
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
                self.lost = Some(format!("{reason}"));
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
        self.write(id, bytes);
        if fin {
            self.conn.send_stream(id).finish().expect("finish");
        }
        id
    }

    fn write(&mut self, id: StreamId, bytes: &[u8]) {
        assert_eq!(self.conn.send_stream(id).write(bytes).expect("write"), bytes.len());
    }

    fn finish(&mut self, id: StreamId) {
        self.conn.send_stream(id).finish().expect("finish");
    }

    /// The response of stream `id` until its FIN or reset (or `within`, if it never ends):
    /// the frames in order, as `Item`s.
    fn response(&mut self, id: StreamId, within: Duration) -> Response {
        let mut all = Vec::new();
        let (mut fin, mut reset) = (false, None);
        self.run_until(within, |c| {
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
        let items = frames(&all)
            .into_iter()
            .filter_map(|(ty, payload)| match ty {
                0x01 => {
                    let fields = ibex_proto::qpack::decode_qpack_static(&payload).expect("a field section");
                    Some(Item::Headers(fields.into_iter().map(|f| (f.name.to_string(), f.value.to_string())).collect()))
                }
                0x00 => Some(Item::Data(payload)),
                _ => None,
            })
            .collect();
        Response { items, fin, reset, lost: self.lost.clone() }
    }
}

#[derive(Debug, PartialEq)]
enum Item {
    Headers(Vec<(String, String)>),
    Data(Vec<u8>),
}

#[derive(Debug)]
struct Response {
    items: Vec<Item>,
    fin: bool,
    reset: Option<u64>,
    lost: Option<String>,
}

impl Response {
    /// The frames as `H <status> [name: value ..]` and `D <bytes>` lines, to compare as text.
    fn shape(&self) -> Vec<String> {
        self.items
            .iter()
            .map(|i| match i {
                Item::Headers(f) => format!("H {}", f.iter().map(|(n, v)| format!("{n}: {v}")).collect::<Vec<_>>().join(", ")),
                Item::Data(d) => format!("D {}", String::from_utf8_lossy(d)),
            })
            .collect()
    }
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

/// A HEADERS frame of the fields `fields` (a field section with no dynamic table).
fn headers_frame(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut b = vec![0x00, 0x00];
    for (n, v) in fields {
        lit(&mut b, n, v);
    }
    let mut out = Vec::new();
    ibex_proto::mux_h3::encode_frame(&mut out, 0x01, &b);
    out
}

fn data_frame(d: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    ibex_proto::mux_h3::encode_frame(&mut out, 0x00, d);
    out
}

/// A request head: `method path`, `extra` fields after the pseudo-headers.
fn request(method: &[u8], path: &[u8], extra: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut f: Vec<(&[u8], &[u8])> = vec![(b":method", method), (b":scheme", b"https"), (b":path", path), (b":authority", b"localhost")];
    f.extend_from_slice(extra);
    headers_frame(&f)
}

const WAIT: Duration = Duration::from_secs(5);

fn mux<R>(test: impl FnOnce() -> R) -> R {
    let mut out = None;
    common::on_h3_path("mux", || out = Some(test()));
    out.expect("ran")
}

/// `HAProxy`: HEADERS 200 (`trailer: x-sum`), DATA, HEADERS `x-sum: 42` with the FIN.
#[test]
fn response_trailers_are_a_headers_frame_after_the_data() {
    mux(|| {
        let (be, _seen) = backend();
        let ibex = ibex(be, "");
        let mut cl = Client::connect(ibex.quic);
        let id = cl.open(&request(b"GET", b"/trailers", &[]), true);
        let r = cl.response(id, WAIT);
        assert_eq!(r.shape(), ["H :status: 200, trailer: x-sum", "D abc", "H x-sum: 42"], "{r:?}");
        assert!((r.fin, r.reset, r.lost.as_deref()) == (true, None, None), "{r:?}");
        assert_eq!(ibex.log_line(), "B=81 U=71 r=GET https://localhost/trailers HTTP/3.0");
    });
}

/// The trailer section is forwarded once all of it is in, however it arrives.
#[test]
fn a_trailer_section_that_arrives_in_two_reads_is_one_headers_frame() {
    mux(|| {
        let (be, _seen) = backend();
        let ibex = ibex(be, "");
        let mut cl = Client::connect(ibex.quic);
        let id = cl.open(&request(b"GET", b"/split", &[]), true);
        let r = cl.response(id, WAIT);
        assert_eq!(r.shape(), ["H :status: 200, trailer: x-sum", "D abc", "H x-sum: 42"], "{r:?}");
        assert!((r.fin, r.reset, r.lost.as_deref()) == (true, None, None), "{r:?}");
    });
}

/// `HAProxy` with `option http-drop-response-trailers`: HEADERS 200, DATA with the FIN.
#[test]
fn drop_response_trailers_leaves_the_data_to_end_the_stream() {
    mux(|| {
        let (be, _seen) = backend();
        let ibex = ibex(be, "option http-drop-response-trailers");
        let mut cl = Client::connect(ibex.quic);
        let id = cl.open(&request(b"GET", b"/trailers", &[]), true);
        let r = cl.response(id, WAIT);
        assert_eq!(r.shape(), ["H :status: 200, trailer: x-sum", "D abc"], "{r:?}");
        assert!((r.fin, r.reset, r.lost.as_deref()) == (true, None, None), "{r:?}");
        // `HAProxy` logs B=81 here (the trailers are in its HTX message when counted); Ibex cuts
        // them from the buffer first, so B=74: not asserted (docs/differences.md).
        assert!(ibex.log_line().contains(" U=71 "));
    });
}

/// `HAProxy`: the server gets the trailers as chunked trailers, and `U` counts them.
#[test]
fn request_trailers_reach_an_h1_server_as_chunked_trailers() {
    mux(|| {
        let (be, seen) = backend();
        let ibex = ibex(be, "");
        let mut cl = Client::connect(ibex.quic);
        let id = cl.open(&request(b"POST", b"/echo", &[(b"content-type", b"text/plain")]), false);
        cl.write(id, &data_frame(b"hello"));
        cl.run_until(Duration::from_millis(200), |_| false);
        cl.write(id, &headers_frame(&[(b"x-t", b"v1"), (b"x-u", b"v2")]));
        cl.finish(id);
        let r = cl.response(id, WAIT);
        assert_eq!(r.shape(), ["H :status: 200, content-length: 2", "D ok"], "{r:?}");
        let got = String::from_utf8_lossy(&seen.lock().unwrap()[0]).into_owned();
        assert_eq!(
            got,
            "POST /echo HTTP/1.1\r\nhost: localhost\r\ncontent-type: text/plain\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nx-t: v1\r\nx-u: v2\r\n\r\n"
        );
        assert_eq!(ibex.log_line(), "B=51 U=106 r=POST https://localhost/echo HTTP/3.0");
    });
}

/// RFC 9114 4.1 (the oracle sends the interim HEADERS with the FIN, see the header): an
/// interim HEADERS, then the final response.
#[test]
fn an_early_hint_is_an_interim_headers_before_the_final_response() {
    mux(|| {
        let (be, _seen) = backend();
        let ibex = ibex(be, "");
        let mut cl = Client::connect(ibex.quic);
        let id = cl.open(&request(b"GET", b"/early2", &[]), true);
        let r = cl.response(id, WAIT);
        assert_eq!(r.shape(), ["H :status: 103, link: </s.css>; rel=preload", "H :status: 200, content-length: 2", "D ok"], "{r:?}");
        assert!((r.fin, r.reset, r.lost.as_deref()) == (true, None, None), "{r:?}");
    });
}

/// The oracle crashes on this; Ibex forwards both.
#[test]
fn an_early_hint_and_the_final_response_in_one_segment_are_both_forwarded() {
    mux(|| {
        let (be, _seen) = backend();
        let ibex = ibex(be, "");
        let mut cl = Client::connect(ibex.quic);
        let id = cl.open(&request(b"GET", b"/early1", &[]), true);
        let r = cl.response(id, WAIT);
        assert_eq!(r.shape(), ["H :status: 103, link: </s.css>; rel=preload", "H :status: 200, content-length: 2", "D ok"], "{r:?}");
        assert!((r.fin, r.reset, r.lost.as_deref()) == (true, None, None), "{r:?}");
        // The connection serves the next stream.
        let id = cl.open(&request(b"GET", b"/next", &[]), true);
        assert_eq!(cl.response(id, WAIT).shape(), ["H :status: 200, content-length: 2", "D ok"]);
    });
}

/// `expect: 100-continue`: the server's `100` is forwarded as an interim HEADERS, then the
/// final response once the body is in.
#[test]
fn a_100_continue_is_an_interim_headers() {
    mux(|| {
        let (be, seen) = backend();
        let ibex = ibex(be, "");
        let mut cl = Client::connect(ibex.quic);
        let id = cl.open(&request(b"POST", b"/cont", &[(b"expect", b"100-continue"), (b"content-length", b"3")]), false);
        let r = cl.response(id, Duration::from_millis(600));
        assert_eq!(r.shape(), ["H :status: 100"], "{r:?}");
        assert!(!r.fin && r.reset.is_none(), "an interim response does not end the stream: {r:?}");
        cl.write(id, &data_frame(b"abc"));
        cl.finish(id);
        let r = cl.response(id, WAIT);
        assert_eq!(r.shape(), ["H :status: 200, content-length: 2", "D ok"], "{r:?}");
        assert!(String::from_utf8_lossy(&seen.lock().unwrap()[0]).ends_with("content-length: 3\r\n\r\nabc"));
    });
}

/// `HAProxy`: RESET_STREAM `0x10b`, and the connection serves the next request.
fn rejected_then_served(head: &[u8], code: u64) {
    let (be, seen) = backend();
    let ibex = ibex(be, "");
    let mut cl = Client::connect(ibex.quic);
    let id = cl.open(head, false);
    let r = cl.response(id, WAIT);
    assert_eq!((r.reset, r.lost.as_deref()), (Some(code), None), "{r:?}");
    let id = cl.open(&request(b"GET", b"/next", &[]), true);
    let r = cl.response(id, WAIT);
    assert_eq!(r.shape(), ["H :status: 200, content-length: 2", "D ok"], "the connection serves the next request: {r:?}");
    assert_eq!(seen.lock().unwrap().len(), 1, "the rejected stream reached no server");
}

const REQUEST_REJECTED: u64 = 0x10b;
const MESSAGE_ERROR: u64 = 0x10e;

#[test]
fn connect_is_a_rejected_request() {
    mux(|| rejected_then_served(&headers_frame(&[(b":method", b"CONNECT"), (b":authority", b"localhost:80")]), REQUEST_REJECTED));
}

/// The relay answers `400` to it (no reset); it goes with the relay (slice H5).
#[test]
fn connect_on_the_relay_is_a_400() {
    common::on_h3_path("relay", || {
        let (be, seen) = backend();
        let ibex = ibex(be, "");
        let mut cl = Client::connect(ibex.quic);
        let id = cl.open(&headers_frame(&[(b":method", b"CONNECT"), (b":authority", b"localhost:80")]), false);
        let r = cl.response(id, WAIT);
        assert!(matches!(r.items.first(), Some(Item::Headers(f)) if f[0] == (":status".into(), "400".into())), "{r:?}");
        assert!(seen.lock().unwrap().is_empty(), "no server saw it");
    });
}

#[test]
fn extended_connect_is_a_message_error() {
    mux(|| {
        let head = headers_frame(&[
            (b":method", b"CONNECT"),
            (b":protocol", b"websocket"),
            (b":scheme", b"https"),
            (b":path", b"/ws"),
            (b":authority", b"localhost"),
        ]);
        rejected_then_served(&head, MESSAGE_ERROR);
    });
}

#[test]
fn a_te_other_than_trailers_is_a_message_error() {
    mux(|| rejected_then_served(&request(b"GET", b"/x", &[(b"te", b"gzip")]), MESSAGE_ERROR));
}

/// T549: a response trailer from an HTTP/2 server (nghttpd `--trailer`, behind `proto h2`)
/// reaches an h3 client as a trailing HEADERS frame with the FIN.
#[test]
fn response_trailers_from_an_h2_server_reach_the_h3_client() {
    if !crate::server_h2::have_nghttpd() {
        return;
    }
    mux(|| {
        let srv = crate::server_h2::nghttpd(false, &["--trailer=grpc-status: 0", "--no-content-length"]);
        let ibex = ibex_srv(srv.addr, "", "proto h2");
        let mut cl = Client::connect(ibex.quic);
        let id = cl.open(&request(b"GET", b"/index.html", &[]), true);
        let r = cl.response(id, WAIT);
        let shape = r.shape();
        assert!(shape.first().is_some_and(|h| h.starts_with("H :status: 200")), "{r:?}");
        assert_eq!(shape.last().map(String::as_str), Some("H grpc-status: 0"), "the trailing HEADERS frame: {r:?}");
        assert!((r.fin, r.reset, r.lost.as_deref()) == (true, None, None), "{r:?}");
    });
}
