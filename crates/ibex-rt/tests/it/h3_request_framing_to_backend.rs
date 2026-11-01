// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! What an HTTP/3 request becomes on the HTTP/1 backend connection (tasks/T281 item 1).
//!
//! The QUIC listener rewrites each HTTP/3 request as an HTTP/1 message for the engine,
//! which forwards it to an HTTP/1 server. A request whose framing fields disagree with the
//! frames that carried it -- a `transfer-encoding` (connection-specific, malformed in
//! HTTP/3), a `content-length` other than the sum of the DATA frames -- must not reach the
//! server at all: an HTTP/1 server would read the body by those fields, and a body framed
//! one way by the client and another by the server is a smuggled request.
//!
//! The reference binary here is built without QUIC (`haproxy -vv`: `-QUIC`), so the
//! expected values come from RFC 9114 (4.1.2, 4.2) and HAProxy's `src/h3.c`
//! (`h3_headers_to_htx`, `h3_check_body_size`, `http_parse_cont_len_header`): a
//! connection-specific field, a `te` other than `trailers`, an unparsable or conflicting
//! `content-length`, and DATA frames whose sum differs from it are all a message error,
//! and a DATA frame is checked against the length when its header arrives, before any of
//! its payload is passed on.
//!
//! T511 measured the framing of a body without `content-length` on `HAProxy` 3.5-dev7 built
//! with QUIC (`reference/haproxy-quic`): chunked, see [`SMUGGLED_CHUNKED`].
//!
//! Each case drives a raw `quinn-proto` client against the `ibex` binary and records every
//! byte the backend receives.

use crate::common;

use ibex_quic::quinn_proto::{
    crypto::rustls::QuicClientConfig, ClientConfig, Connection, ConnectionHandle, Dir, Endpoint, EndpointConfig,
    StreamId,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::{ErrorKind, Read, Write};
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

/// The bytes of each connection the backend accepted.
type Recorded = Arc<Mutex<Vec<Arc<Mutex<Vec<u8>>>>>>;

/// A backend that records each connection's bytes and answers `200` once the client has
/// been quiet for 300 ms; `/chunked` is answered with a chunked body.
fn backend() -> (SocketAddr, Recorded) {
    let ls = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = ls.local_addr().expect("addr");
    let conns: Recorded = Arc::default();
    let c2 = Arc::clone(&conns);
    thread::spawn(move || {
        for s in ls.incoming() {
            let Ok(mut s) = s else { continue };
            let rec = Arc::new(Mutex::new(Vec::new()));
            c2.lock().unwrap().push(Arc::clone(&rec));
            thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
                let mut buf = vec![0u8; 65536];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) => return,
                        Ok(n) => rec.lock().unwrap().extend_from_slice(&buf[..n]),
                        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
                        Err(_) => return,
                    }
                }
                let chunked = rec.lock().unwrap().starts_with(b"GET /chunked ");
                let resp: &[u8] = if chunked {
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
                } else {
                    b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"
                };
                let _ = s.write_all(resp);
                thread::sleep(Duration::from_millis(100));
            });
        }
    });
    (addr, conns)
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

fn ibex(be: SocketAddr) -> Ibex {
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
        let mut c = Self { sock, ep, handle, conn, buf: vec![0u8; 65536] };
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
        while self.conn.poll().is_some() {}
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

    fn open(&mut self, bytes: &[u8], fin: bool) -> StreamId {
        let id = self.conn.streams().open(Dir::Bi).expect("open");
        let mut s = self.conn.send_stream(id);
        assert_eq!(s.write(bytes).expect("write"), bytes.len());
        if fin {
            s.finish().expect("finish");
        }
        id
    }

    /// What the client received on `id` within the deadline: the bytes, and whether the
    /// stream ended (FIN or reset).
    fn response(&mut self, id: StreamId) -> (Vec<u8>, bool) {
        let mut all = Vec::new();
        let ended = self.run_until(|c| {
            let mut rs = c.conn.recv_stream(id);
            let Ok(mut chunks) = rs.read(true) else { return true };
            let end = loop {
                match chunks.next(usize::MAX) {
                    Ok(Some(ch)) => all.extend_from_slice(&ch.bytes),
                    Ok(None) => break true,
                    Err(ibex_quic::quinn_proto::ReadError::Blocked) => break false,
                    Err(_) => break true,
                }
            };
            let _ = chunks.finalize();
            end
        });
        (all, ended)
    }
}

/// The frames of an HTTP/3 stream: (type, payload).
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

fn status(resp: &[u8]) -> Option<u16> {
    let f = frames(resp);
    let (_, section) = f.iter().find(|(t, _)| *t == 0x01)?;
    let fields = ibex_proto::qpack::decode_qpack_static(section).ok()?;
    fields.iter().find(|f| f.name == ":status").and_then(|f| f.value.parse().ok())
}

fn body(resp: &[u8]) -> Vec<u8> {
    frames(resp).into_iter().filter(|(t, _)| *t == 0x00).flat_map(|(_, p)| p).collect()
}

fn headers(method: &str, path: &str, extra: &[(&str, &str)]) -> Vec<u8> {
    let f: Vec<(String, String)> = [(":method", method), (":scheme", "https"), (":authority", "localhost"), (":path", path)]
        .iter()
        .chain(extra)
        .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
        .collect();
    frame(0x01, &ibex_proto::mux_h3::encode_field_section(&f))
}

fn frame(ty: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    ibex_proto::mux_h3::encode_frame(&mut out, ty, payload);
    out
}

/// A DATA frame header announcing `len` bytes, without its payload.
fn data_header(len: u64) -> Vec<u8> {
    let mut f = frame(0x00, &vec![0u8; usize::try_from(len).expect("len")]);
    f.truncate(f.len() - usize::try_from(len).expect("len"));
    f
}

/// What should become of one request.
#[derive(Clone, Copy, Debug)]
enum Expect {
    /// The client is answered with this status, or its stream is reset; the backend never
    /// sees the request.
    Refused(u16),
    /// The backend receives exactly this head line (name: value) once, no other framing
    /// field, and exactly this body behind the head.
    Forwarded { framing: &'static str, body: &'static [u8] },
    /// The backend receives at most the head, none of the body, and the client no 200.
    HeadOnly,
}
use Expect::{Forwarded, HeadOnly, Refused};

struct Case {
    name: &'static str,
    bytes: Vec<u8>,
    fin: bool,
    expect: Expect,
}

fn case(name: &'static str, method: &str, fields: &[(&str, &str)], data: &[&[u8]], expect: Expect) -> Case {
    let mut bytes = headers(method, &format!("/{name}"), fields);
    for d in data {
        bytes.extend_from_slice(&frame(0x00, d));
    }
    Case { name, bytes, fin: true, expect }
}

fn check(c: &Case, status: Option<u16>, ended: bool, conns: &[Vec<u8>]) -> Result<(), String> {
    let path = format!(" /{} ", c.name);
    let mine: Vec<&Vec<u8>> = conns.iter().filter(|b| b.windows(path.len()).any(|w| w == path.as_bytes())).collect();
    match c.expect {
        Refused(code) => {
            if !mine.is_empty() {
                return Err(format!("refused request reached the backend: {:?}", String::from_utf8_lossy(mine[0])));
            }
            if status.is_some_and(|s| s != code) || (status.is_none() && !ended) {
                return Err(format!("expected {code} or a reset, got status {status:?}, ended {ended}"));
            }
        }
        HeadOnly if mine.is_empty() && status != Some(200) => {}
        Forwarded { .. } | HeadOnly if mine.len() != 1 => {
            return Err(format!("expected one backend connection with the request, got {}", mine.len()));
        }
        Forwarded { framing, body } => {
            let got = mine[0];
            let h = got.windows(4).position(|w| w == b"\r\n\r\n").ok_or("no complete head at the backend")?;
            let head = String::from_utf8_lossy(&got[..h]).to_ascii_lowercase();
            let framing_lines: Vec<&str> = head
                .split("\r\n")
                .filter(|l| l.starts_with("content-length:") || l.starts_with("transfer-encoding:"))
                .collect();
            if framing_lines != [framing] {
                return Err(format!("framing at the backend {framing_lines:?}, expected [{framing:?}]; head {head:?}"));
            }
            if &got[h + 4..] != body {
                return Err(format!("body at the backend {:?}, expected {:?}", String::from_utf8_lossy(&got[h + 4..]), String::from_utf8_lossy(body)));
            }
            if status != Some(200) {
                return Err(format!("client got {status:?}, expected 200"));
            }
        }
        HeadOnly => {
            let got = mine[0];
            let h = got.windows(4).position(|w| w == b"\r\n\r\n").ok_or("no complete head at the backend")?;
            if got.len() != h + 4 {
                return Err(format!("body bytes reached the backend: {:?}", String::from_utf8_lossy(&got[h + 4..])));
            }
            if status == Some(200) {
                return Err("client got 200 for a malformed request".into());
            }
        }
    }
    Ok(())
}

fn assert_all(cases: &[Case]) {
    let (be, rec) = backend();
    let ibex = ibex(be);
    let mut failures = Vec::new();
    for c in cases {
        // One connection per case: a stream error must not decide the next case.
        let mut cl = Client::connect(ibex.quic);
        let id = cl.open(&c.bytes, c.fin);
        let (resp, ended) = cl.response(id);
        thread::sleep(Duration::from_millis(500));
        let conns: Vec<Vec<u8>> = rec.lock().unwrap().iter().map(|b| b.lock().unwrap().clone()).collect();
        if let Err(e) = check(c, status(&resp), ended, &conns) {
            failures.push(format!("{}: {e}", c.name));
        }
    }
    assert!(failures.is_empty(), "{} of {} cases wrong:\n{}", failures.len(), cases.len(), failures.join("\n"));
}

const SMUGGLED: &[u8] = b"5\r\nhello\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nhost: x\r\n\r\n";
/// A body without `content-length` goes chunked, even when all of it came with the head
/// and the stream's FIN: measured on `HAProxy` 3.5-dev7 with QUIC (aioquic, HEADERS and DATA
/// in one STREAM frame with FIN, T511): `transfer-encoding: chunked`, one chunk.
const SMUGGLED_CHUNKED: &[u8] = b"32\r\n5\r\nhello\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nhost: x\r\n\r\n\r\n0\r\n\r\n";
const HELLO_CHUNKED: &[u8] = b"5\r\nhello\r\n0\r\n\r\n";

crate::h3_both_paths! {
/// RFC 9114 4.2: connection-specific fields make a request malformed, and `te` may only be
/// `trailers`. HAProxy's `h3_headers_to_htx` answers each with H3_MESSAGE_ERROR.
fn connection_specific_fields_never_reach_the_server() {
    assert_all(&[
        case("te-chunked", "POST", &[("transfer-encoding", "chunked")], &[SMUGGLED], Refused(400)),
        case("te-chunked-cl", "POST", &[("transfer-encoding", "chunked"), ("content-length", "43")], &[&SMUGGLED[..43]], Refused(400)),
        case("te-gzip", "POST", &[("transfer-encoding", "gzip")], &[b"hello"], Refused(400)),
        case("te-twice", "POST", &[("transfer-encoding", "gzip"), ("transfer-encoding", "chunked")], &[SMUGGLED], Refused(400)),
        case("te-on-get", "GET", &[("transfer-encoding", "chunked")], &[], Refused(400)),
        case("te-gzip-hop", "POST", &[("te", "gzip")], &[b"hello"], Refused(400)),
        case("connection", "POST", &[("connection", "keep-alive")], &[b"hello"], Refused(400)),
        case("te-trailers", "POST", &[("te", "trailers")], &[b"hello"], Forwarded { framing: "transfer-encoding: chunked", body: HELLO_CHUNKED }),
    ]);
}
}

/// E1, the mux path: a path the HTTP/1 parser refuses (UTF-8, not ASCII) goes as text, the
/// length written as its digits there too (`h2_bridge::text_wire`). (The relay path refuses
/// such a path.)
#[test]
fn a_head_without_htx_gets_its_length_in_digits() {
    crate::common::on_h3_path("mux", || {
        assert_all(&[case("cl-leading-zero-caf\u{e9}", "POST", &[("content-length", "005")], &[b"hello"], Forwarded { framing: "content-length: 5", body: b"hello" })]);
    });
}

crate::h3_both_paths! {
/// RFC 9114 4.1.2: a `content-length` other than the sum of the DATA frames is malformed.
/// HAProxy (`http_parse_cont_len_header`) takes a comma list of one repeated value, and
/// repeated lines of one value, as that value; anything else that is not digits is an error.
fn content_length_matches_the_data_frames() {
    assert_all(&[
        case("cl-over", "POST", &[("content-length", "3")], &[b"hello"], Refused(400)),
        case("cl-under", "POST", &[("content-length", "5")], &[b"hel"], Refused(400)),
        case("cl-over-split", "POST", &[("content-length", "3")], &[b"abc", b"GET /x HTTP/1.1\r\n\r\n"], Refused(400)),
        case("cl-zero-with-body", "POST", &[("content-length", "0")], &[SMUGGLED], Refused(400)),
        case("cl-conflict", "POST", &[("content-length", "3"), ("content-length", "5")], &[b"hello"], Refused(400)),
        case("cl-plus", "POST", &[("content-length", "+5")], &[b"hello"], Refused(400)),
        case("cl-minus", "POST", &[("content-length", "-5")], &[b"hello"], Refused(400)),
        case("cl-hex", "POST", &[("content-length", "0x5")], &[b"hello"], Refused(400)),
        case("cl-empty", "POST", &[("content-length", "")], &[b"hello"], Refused(400)),
        case("cl-list-differs", "POST", &[("content-length", "5, 6")], &[b"hello"], Refused(400)),
        case("cl-twice", "POST", &[("content-length", "5"), ("content-length", "5")], &[b"hello"], Forwarded { framing: "content-length: 5", body: b"hello" }),
        case("cl-list-same", "POST", &[("content-length", "5, 5")], &[b"hello"], Forwarded { framing: "content-length: 5", body: b"hello" }),
        case("cl-leading-zero", "POST", &[("content-length", "005")], &[b"hello"], Forwarded { framing: "content-length: 5", body: b"hello" }),
        case("cl-two-frames", "POST", &[("content-length", "5")], &[b"he", b"llo"], Forwarded { framing: "content-length: 5", body: b"hello" }),
        case("get-with-cl", "GET", &[("content-length", "5")], &[b"hello"], Forwarded { framing: "content-length: 5", body: b"hello" }),
        case("get-with-body", "GET", &[], &[b"hello"], Forwarded { framing: "transfer-encoding: chunked", body: HELLO_CHUNKED }),
        case("body-no-cl", "POST", &[], &[SMUGGLED], Forwarded { framing: "transfer-encoding: chunked", body: SMUGGLED_CHUNKED }),
    ]);
}
}

crate::h3_both_paths! {
/// A DATA frame longer than what is left of the `content-length` is refused when its
/// header arrives (HAProxy adds the frame length before taking any payload): none of its
/// payload reaches the server, even the part that would have completed the length.
fn an_oversized_data_frame_is_refused_before_its_payload() {
    let mut bytes = headers("POST", "/oversized-frame", &[("content-length", "3")]);
    bytes.extend_from_slice(&data_header(43));
    bytes.extend_from_slice(b"abc");
    let mut streamed = headers("POST", "/streamed-te", &[("transfer-encoding", "chunked")]);
    streamed.extend_from_slice(&frame(0x00, SMUGGLED));
    assert_all(&[
        Case { name: "oversized-frame", bytes, fin: false, expect: HeadOnly },
        Case { name: "streamed-te", bytes: streamed, fin: false, expect: Refused(400) },
    ]);
}
}

crate::h3_both_paths! {
/// The response side: a chunked HTTP/1 response comes back as its payload in DATA frames.
fn a_chunked_response_arrives_as_its_payload() {
    let (be, _rec) = backend();
    let ibex = ibex(be);
    let mut cl = Client::connect(ibex.quic);
    let id = cl.open(&headers("GET", "/chunked", &[]), true);
    let (resp, ended) = cl.response(id);
    assert!(ended, "the response never ended");
    assert_eq!(status(&resp), Some(200));
    assert_eq!(body(&resp), b"hello world");
}
}

crate::h3_both_paths! {
/// The relay frames the engine's HTTP/1 response for HTTP/3 the way the engine framed it
/// (`txn::response_framing`, every `Transfer-Encoding` line as one list): a single line
/// searched for "chunked" read a response the engine forwards as close-delimited as
/// chunked, and the last of several lines decided alone.
fn the_relay_reads_a_response_as_the_engine_framed_it() {
    use ibex_rt::h3_relay::ResponseConv;
    let raw = b"5\r\nhello\r\n0\r\n\r\n";
    // (head, body the client must get)
    let cases: [(&str, &[u8]); 5] = [
        ("Transfer-Encoding: chunked", b"hello"),
        ("Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nContent-Length: 3", b"hello"),
        ("Transfer-Encoding: chunked, gzip", raw),
        ("Transfer-Encoding: xchunkedx", raw),
        ("Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\nContent-Length: 3", raw),
    ];
    let mut failures = Vec::new();
    for (fields, want) in cases {
        let mut c = ResponseConv::new(false);
        let mut out = Vec::new();
        let mut input = format!("HTTP/1.1 200 OK\r\n{fields}\r\n\r\n").into_bytes();
        input.extend_from_slice(raw);
        let fed = c.feed(&input, &mut out);
        let ended = fed.is_ok() && c.eof().is_ok();
        let headers = frames(&out).into_iter().find(|(t, _)| *t == 0x01).map(|(_, p)| p).unwrap_or_default();
        let cl_sent = ibex_proto::qpack::decode_qpack_static(&headers).is_ok_and(|f| f.iter().any(|f| f.name == "content-length"));
        if !ended || body(&out) != want || cl_sent {
            failures.push(format!(
                "{fields:?}: ended {ended}, body {:?}, content-length sent {cl_sent}",
                String::from_utf8_lossy(&body(&out))
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
}
