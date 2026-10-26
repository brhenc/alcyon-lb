// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T505 (VV-25): a WebSocket over HTTP/2, RFC 8441's extended CONNECT, carried to an
//! HTTP/1.1 server as its `Upgrade` handshake and then tunnelled, as `HAProxy` carries it.
//! Without it a browser opens a second, HTTP/1.1 connection for the WebSocket of a page
//! it loaded over h2 (the `06-browsers` practical topology, Firefox).
//!
//! Every expected value was measured on `HAProxy` 3.5-dev8-885761-29 (`bind proto h2`, a
//! raw h2 client, an HTTP/1.1 server that answers 101 and echoes):
//! - the server's SETTINGS are `ENABLE_CONNECT_PROTOCOL=1`, `INITIAL_WINDOW_SIZE=16384`,
//!   `MAX_CONCURRENT_STREAMS=100`, in that order;
//! - `:method CONNECT`, `:protocol websocket`, `:path /ws` reaches the server as
//!   `GET /ws HTTP/1.1` with the client's headers, then `upgrade: websocket`,
//!   `connection: upgrade`, what the rules add (`option forwardfor`) and a
//!   `sec-websocket-key` of 24 characters the proxy made;
//! - the server's 101 reaches the client as `:status 200` with its `sec-websocket-accept`
//!   and without `upgrade` / `connection`; the DATA that follow go both ways unchanged; the
//!   client's `END_STREAM` ends the server's input, and the server's close ends the stream
//!   with an empty DATA `END_STREAM`;
//! - `:protocol h2c`, or an extended CONNECT without `:path`, is `RST_STREAM`
//!   `PROTOCOL_ERROR` and the server is not contacted.

use crate::common;

use ibex_proto::hpack::HpackDecoder;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("short");
    let mut v = Vec::new();
    v.extend_from_slice(&len.to_be_bytes()[1..]);
    v.push(ftype);
    v.push(flags);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// A literal field without indexing, new name, no Huffman.
fn lit(name: &str, value: &str) -> Vec<u8> {
    let mut v = vec![0x00, u8::try_from(name.len()).expect("short")];
    v.extend_from_slice(name.as_bytes());
    v.push(u8::try_from(value.len()).expect("short"));
    v.extend_from_slice(value.as_bytes());
    v
}

fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for (i, s) in [18, 12, 6, 0].into_iter().enumerate() {
            out.push(if i <= c.len() { char::from(A[((n >> s) & 63) as usize]) } else { '=' });
        }
    }
    out
}

/// What the server saw: the request head, then every event of its connection.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Head(String),
    Bytes(Vec<u8>),
    Eof,
}

/// An HTTP/1.1 WebSocket server: answers the handshake with 101 and the accept its key
/// calls for, then echoes what comes until the client's end, and closes.
fn ws_server() -> (std::net::SocketAddr, mpsc::Receiver<Seen>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let tx = tx.clone();
            thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let p = loop {
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p;
                    }
                    match c.read(&mut tmp) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                };
                let head = String::from_utf8_lossy(&buf[..p]).into_owned();
                let key = head
                    .lines()
                    .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("sec-websocket-key")).map(|(_, v)| v.trim().to_string()))
                    .unwrap_or_default();
                let _ = tx.send(Seen::Head(head.clone()));
                let acc = base64(&ibex_sample::hash::sha1_digest(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes()));
                let _ = c.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {acc}\r\nX-Be: 1\r\n\r\n").as_bytes());
                // `/close`: the server ends the tunnel first.
                if head.starts_with("GET /close ") {
                    return;
                }
                let mut rest = buf.split_off(p + 4);
                loop {
                    if !rest.is_empty() {
                        let _ = c.write_all(&rest);
                        let _ = tx.send(Seen::Bytes(std::mem::take(&mut rest)));
                    }
                    match c.read(&mut tmp) {
                        Ok(0) | Err(_) => {
                            let _ = tx.send(Seen::Eof);
                            return;
                        }
                        Ok(n) => rest.extend_from_slice(&tmp[..n]),
                    }
                }
            });
        }
    });
    (addr, rx)
}

struct Proxy {
    _ibex: common::Ibex,
    addr: std::net::SocketAddr,
    _dir: tempfile::TempDir,
    /// The log lines, as they come.
    logs: mpsc::Receiver<String>,
}

fn proxy(server: std::net::SocketAddr) -> Proxy {
    let dir = tempfile::tempdir().expect("dir");
    let addr = common::reserve_addr();
    let cfg = dir.path().join("ibex.cfg");
    std::fs::write(
        &cfg,
        format!(
            "global\n  log stdout format raw local0\n\
             defaults\n  mode http\n  log global\n  option httplog\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n  timeout tunnel 5s\n  option forwardfor\n\
             frontend fe\n  bind {addr} proto h2\n  default_backend be\n\
             backend be\n  server s1 {server}\n"
        ),
    )
    .expect("cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Ibex)
        .expect("spawn ibex");
    let out = child.stdout.take().expect("stdout");
    let (tx, logs) = mpsc::channel();
    thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    assert!(common::wait_listening(addr), "ibex never listened");
    Proxy { _ibex: child, addr, _dir: dir, logs }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Frame {
    ftype: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

/// The frames that come within `wait`, or until `stop` says enough.
fn read_frames(s: &mut TcpStream, wait: Duration, mut stop: impl FnMut(&[Frame]) -> bool) -> Vec<Frame> {
    let deadline = Instant::now() + wait;
    let mut buf = Vec::new();
    let mut out = Vec::new();
    let mut tmp = [0u8; 16384];
    while Instant::now() < deadline && !stop(&out) {
        s.set_read_timeout(Some(Duration::from_millis(50))).ok();
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let stream = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
            out.push(Frame { ftype: buf[3], flags: buf[4], stream, payload: buf[9..9 + len].to_vec() });
            buf.drain(..9 + len);
        }
    }
    out
}

/// The next log line of a stream within `wait`: not the one of `wait_listening`'s probe.
fn next_log(p: &Proxy, wait: Duration) -> Option<String> {
    let deadline = Instant::now() + wait;
    loop {
        let line = p.logs.recv_timeout(deadline.saturating_duration_since(Instant::now())).ok()?;
        if !line.contains("<BADREQ>") {
            return Some(line);
        }
    }
}

fn connect(p: &Proxy) -> TcpStream {
    let mut s = TcpStream::connect(p.addr).expect("connect");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(4, 0, 0, b"")).expect("settings");
    s.write_all(&frame(4, 1, 0, b"")).expect("ack");
    s
}

fn settings(payload: &[u8]) -> Vec<(u16, u32)> {
    payload.chunks(6).map(|c| (u16::from_be_bytes([c[0], c[1]]), u32::from_be_bytes([c[2], c[3], c[4], c[5]]))).collect()
}

/// The extended CONNECT of a WebSocket to `/ws`, without `END_STREAM`.
fn ext_connect(protocol: &str, path: Option<&str>) -> Vec<u8> {
    let mut b = lit(":method", "CONNECT");
    b.extend(lit(":protocol", protocol));
    b.extend(lit(":scheme", "http"));
    if let Some(p) = path {
        b.extend(lit(":path", p));
    }
    b.extend(lit(":authority", "127.0.0.1"));
    b.extend(lit("sec-websocket-version", "13"));
    b.extend(lit("origin", "http://x"));
    frame(1, 4, 1, &b)
}

#[test]
fn the_server_settings_are_haproxy_s() {
    let (server, _rx) = ws_server();
    let p = proxy(server);
    let mut s = connect(&p);
    let frames = read_frames(&mut s, Duration::from_secs(3), |f| f.iter().any(|f| f.ftype == 4 && f.flags == 0));
    let first = frames.iter().find(|f| f.ftype == 4 && f.flags == 0).expect("the server's SETTINGS");
    assert_eq!(settings(&first.payload), vec![(8, 1), (4, 16384), (3, 100)]);
}

#[test]
fn a_websocket_over_extended_connect_is_an_upgrade_to_the_server_and_a_tunnel() {
    let (server, rx) = ws_server();
    let p = proxy(server);
    let mut s = connect(&p);
    s.write_all(&ext_connect("websocket", Some("/ws"))).expect("headers");

    let Ok(Seen::Head(head)) = rx.recv_timeout(Duration::from_secs(3)) else { panic!("the server saw no request") };
    let lines: Vec<&str> = head.lines().collect();
    assert_eq!(lines[0], "GET /ws HTTP/1.1", "{head}");
    let key = lines.iter().find_map(|l| l.strip_prefix("sec-websocket-key: ")).unwrap_or_default();
    assert_eq!(key.len(), 24, "a key made by the proxy: {head}");
    // `HAProxy` writes the key last, after what the rules added (`option forwardfor`); Ibex
    // writes it into the head the rules see, so before.
    let others: Vec<&str> = lines[1..].iter().copied().filter(|l| !l.starts_with("sec-websocket-key: ")).collect();
    assert_eq!(
        others,
        ["host: 127.0.0.1", "sec-websocket-version: 13", "origin: http://x", "upgrade: websocket", "connection: upgrade", "x-forwarded-for: 127.0.0.1"],
        "{head}"
    );

    let frames = read_frames(&mut s, Duration::from_secs(3), |f| f.iter().any(|f| f.ftype == 1 && f.stream == 1));
    let h = frames.iter().find(|f| f.ftype == 1 && f.stream == 1).expect("the response HEADERS");
    assert_eq!(h.flags & 1, 0, "no END_STREAM on the tunnel's head");
    let fields: Vec<(String, String)> =
        HpackDecoder::new().decode(&h.payload).expect("hpack").into_iter().map(|f| (f.name, f.value)).collect();
    let accept = base64(&ibex_sample::hash::sha1_digest(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes()));
    assert_eq!(
        fields,
        vec![(":status".into(), "200".into()), ("sec-websocket-accept".into(), accept), ("x-be".into(), "1".into())]
    );

    // A masked text frame "hello", and its echo.
    let ws = [&[0x81u8, 0x85, 1, 2, 3, 4][..], &[b'h' ^ 1, b'e' ^ 2, b'l' ^ 3, b'l' ^ 4, b'o' ^ 1]].concat();
    s.write_all(&frame(0, 0, 1, &ws)).expect("data");
    assert_eq!(rx.recv_timeout(Duration::from_secs(3)).ok(), Some(Seen::Bytes(ws.clone())));
    let frames = read_frames(&mut s, Duration::from_secs(3), |f| f.iter().any(|f| f.ftype == 0 && f.stream == 1));
    let echo: Vec<u8> = frames.iter().filter(|f| f.ftype == 0 && f.stream == 1).flat_map(|f| f.payload.clone()).collect();
    assert_eq!(echo, ws, "{frames:?}");

    // The client's end is the server's end of input; the server's close ends the stream.
    s.write_all(&frame(0, 1, 1, b"")).expect("end");
    assert_eq!(rx.recv_timeout(Duration::from_secs(3)).ok(), Some(Seen::Eof));
    let frames = read_frames(&mut s, Duration::from_secs(3), |f| f.iter().any(|f| f.stream == 1 && (f.ftype == 3 || f.flags & 1 == 1)));
    let end: Vec<(u8, u8, Vec<u8>)> = frames.iter().filter(|f| f.stream == 1).map(|f| (f.ftype, f.flags, f.payload.clone())).collect();
    assert_eq!(end, vec![(0, 1, vec![])], "an empty DATA END_STREAM");
}

#[test]
fn an_extended_connect_for_h2c_or_without_a_path_is_reset() {
    let (server, rx) = ws_server();
    let p = proxy(server);
    for (proto, path) in [("h2c", Some("/ws")), ("h2", Some("/ws")), ("websocket", None)] {
        let mut s = connect(&p);
        s.write_all(&ext_connect(proto, path)).expect("headers");
        let frames = read_frames(&mut s, Duration::from_secs(3), |f| f.iter().any(|f| f.ftype == 3 || (f.ftype == 1 && f.stream == 1)));
        let rst: Vec<(u8, Vec<u8>)> = frames.iter().filter(|f| f.stream == 1).map(|f| (f.ftype, f.payload.clone())).collect();
        assert_eq!(rst, vec![(3, vec![0, 0, 0, 1])], "{proto} {path:?}: RST_STREAM PROTOCOL_ERROR");
    }
    assert!(rx.recv_timeout(Duration::from_millis(200)).is_err(), "the server was not contacted");
}

/// The tunnel ends, and the stream with it (logged), once both sides have: the server
/// closing first leaves the stream until the client's `END_STREAM`, the connection open
/// (measured: `HAProxy` logs the stream at the client's `END_STREAM`, `101`, `----`).
#[test]
fn a_tunnel_the_server_ended_first_ends_at_the_client_s_end_stream() {
    let (server, rx) = ws_server();
    let p = proxy(server);
    let mut s = connect(&p);
    s.write_all(&ext_connect("websocket", Some("/close"))).expect("headers");
    assert!(matches!(rx.recv_timeout(Duration::from_secs(3)), Ok(Seen::Head(_))));
    let frames = read_frames(&mut s, Duration::from_secs(3), |f| f.iter().any(|f| f.ftype == 0 && f.flags & 1 == 1));
    let ends: Vec<(u8, u8)> = frames.iter().filter(|f| f.stream == 1).map(|f| (f.ftype, f.flags & 1)).collect();
    assert_eq!(ends, vec![(1, 0), (0, 1)], "HEADERS, then an empty DATA END_STREAM");
    if let Some(l) = next_log(&p, Duration::from_millis(300)) {
        panic!("not over while the client has not ended: {l}");
    }
    s.write_all(&frame(0, 1, 1, b"")).expect("end");
    let line = next_log(&p, Duration::from_secs(2)).expect("the stream is logged once the client has ended");
    assert!(line.contains(" 101 ") && line.contains(" ---- ") && line.contains("\"GET http://127.0.0.1/close HTTP/2.0\""), "{line}");
    // The connection is still there, and takes another request.
    s.write_all(&{
        let mut b = lit(":method", "GET");
        b.extend(lit(":scheme", "http"));
        b.extend(lit(":path", "/close"));
        b.extend(lit(":authority", "127.0.0.1"));
        frame(1, 5, 3, &b)
    })
    .expect("next");
    assert!(matches!(rx.recv_timeout(Duration::from_secs(3)), Ok(Seen::Head(h)) if h.starts_with("GET /close HTTP/1.1")));
}
