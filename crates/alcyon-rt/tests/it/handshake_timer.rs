// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The handshake timer `%Th` (and the `fc.timer.handshake` fetch): the time
//! between the connection's accept and the end of its handshakes (the PROXY
//! header, the TLS accept). `%Ti` runs after that, not over it.
//!
//! The client connects, waits 300 ms, performs the connection's handshake
//! (nothing on the plain bind, the PROXY line on the `accept-proxy` one, the
//! TLS ClientHello on the `ssl` one), waits 200 ms, then requests. Measured on
//! the oracle (3.5-dev11, `log-format "hu=%HU th=%Th ti=%Ti tr=%TR
//! hf=%[fc.timer.handshake]"`):
//! - `ssl crt` (300 ms before the ClientHello):    `th=303 ti=201 tr=0`;
//! - `accept-proxy` (300 ms before the PROXY line): `th=300 ti=200 tr=0`;
//! - plain:                                          `th=0 ti=500 tr=0`;
//! and the second request of a keep-alive TLS connection sees the handshake
//! over already: `th` is back to `0` and `ti` runs again from its own start.
//! `hf` reads the same value as `th` (`logs->t_handshake`, `src/sample.c` and
//! `src/log.c`).
//!
//! The bounds are the oracle's shape ± 100 ms (`th >= 250` where the
//! handshake was delayed 300 ms), never exact values: the same test passes on
//! both binaries.
//!
//! Set `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`.

use crate::common;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// The tests run one at a time: under parallel load the proxy's `accept()`
/// lags the client's `connect()` by tens of milliseconds, and `th` is the
/// time from the accept, not from the connect.
static SERIALIZER: Mutex<()> = Mutex::new(());

/// The test certificate's subject alternative name.
const NAME: &str = "www.test1.com";
const CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ssl_f_common.pem");
/// The wait between the connect and the handshake: long enough that a timer
/// counting it is unmistakably above the bounds the tests check.
const HANDSHAKE_DELAY: Duration = Duration::from_millis(300);
/// The wait between the end of the handshake and the request.
const REQUEST_DELAY: Duration = Duration::from_millis(200);

struct Proxy {
    child: Child,
    plain: SocketAddr,
    prox: SocketAddr,
    tls: SocketAddr,
    h2: SocketAddr,
    logs: Arc<Mutex<Vec<String>>>,
    stderr: Arc<Mutex<String>>,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// The proxy: a plain bind, an `accept-proxy` one and two `ssl` ones (HTTP/1.1
/// and `alpn h2`), all answering with `http-request return status 200` and
/// logging the four timers.
fn start() -> Proxy {
    let plain = common::reserve_addr();
    let prox = common::reserve_addr();
    let tls = common::reserve_addr();
    let h2 = common::reserve_addr();
    let sentinel = common::reserve_addr();
    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "global\n  log stdout format raw local0\n\
         defaults\n  mode http\n  log global\n\
         \x20 log-format \"hu=%HU th=%Th ti=%Ti tr=%TR hf=%[fc.timer.handshake]\"\n\
         \x20 timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend plain\n  bind {plain}\n  http-request return status 200\n\
         frontend prox\n  bind {prox} accept-proxy\n  http-request return status 200\n\
         frontend tls\n  bind {tls} ssl crt {CERT} alpn http/1.1\n  http-request return status 200\n\
         frontend h2\n  bind {h2} ssl crt {CERT} alpn h2\n  http-request return status 200\n\
         frontend s\n  bind {sentinel}\n  http-request return status 200\n"
    )
    .expect("write");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut child = Command::new(bin)
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let out = child.stdout.take().expect("stdout");
    let err = child.stderr.take().expect("stderr");
    let logs: Arc<Mutex<Vec<String>>> = Arc::default();
    let stderr: Arc<Mutex<String>> = Arc::default();
    {
        let sink = Arc::clone(&logs);
        thread::spawn(move || {
            let mut r = BufReader::new(out);
            let mut line = String::new();
            while r.read_line(&mut line).map_or(0, |n| n) > 0 {
                sink.lock().unwrap().push(std::mem::take(&mut line));
            }
        });
    }
    {
        let sink = Arc::clone(&stderr);
        thread::spawn(move || {
            let mut r = BufReader::new(err);
            let mut chunk = vec![0u8; 65536];
            loop {
                match r.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        sink.lock().unwrap().push_str(&String::from_utf8_lossy(&chunk[..n]));
                    }
                    Err(_) => break,
                }
            }
        });
    }
    assert!(common::wait_listening(sentinel), "proxy never listened: {}", &*stderr.lock().unwrap());
    // Let the proxy settle after its listeners are up: the first connection after the
    // start is accepted late on a loaded host, and `th` counts from the accept.
    thread::sleep(Duration::from_millis(150));
    Proxy { child, plain, prox, tls, h2, logs, stderr, _cfg: cfg }
}

/// The `th`, `ti`, `tr` and `hf` fields of the log line of the request whose
/// `%HU` is `path`, polled until the stream's line is written.
fn fields(p: &Proxy, path: &str) -> (i64, i64, i64, i64) {
    let want = format!("hu={path}");
    let start = Instant::now();
    loop {
        let got = p
            .logs
            .lock()
            .unwrap()
            .iter()
            .find(|l| l.split_whitespace().any(|t| t == want))
            .cloned();
        if let Some(line) = got {
            let v = |name: &str| -> i64 {
                line.split_whitespace()
                    .find_map(|t| t.strip_prefix(&format!("{name}=")).and_then(|x| x.parse().ok()))
                    .unwrap_or_else(|| panic!("no {name} in log line '{line}'"))
            };
            return (v("th"), v("ti"), v("tr"), v("hf"));
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "no log line matching '{want}': logs {:?} stderr: {}",
            &*p.logs.lock().unwrap(),
            &*p.stderr.lock().unwrap()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// The row: `th` (and `hf`, the same value) in its band, `ti` and `tr` in
/// theirs - the oracle's shape, never exact values.
fn row(what: &str, th: i64, ti: i64, tr: i64, hf: i64, th_lo: i64, th_hi: i64, ti_lo: i64, ti_hi: i64, tr_lo: i64, tr_hi: i64) {
    assert!((th_lo..=th_hi).contains(&th), "{what}: %Th is {th}, not in {th_lo}..={th_hi}");
    assert!((ti_lo..=ti_hi).contains(&ti), "{what}: %Ti is {ti}, not in {ti_lo}..={ti_hi}");
    assert!((tr_lo..=tr_hi).contains(&tr), "{what}: %TR is {tr}, not in {tr_lo}..={tr_hi}");
    assert!(th.abs_diff(hf) <= 1, "{what}: fc.timer.handshake is {hf}, %Th is {th}");
}

/// Connects, waits the two delays (there is no handshake), then requests and
/// reads the response until the close.
fn plain_row(fe: SocketAddr, path: &str) {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    thread::sleep(HANDSHAKE_DELAY);
    thread::sleep(REQUEST_DELAY);
    c.write_all(format!("GET {path} HTTP/1.1\r\nhost: {NAME}\r\nConnection: close\r\n\r\n").as_bytes()).expect("write");
    let mut r = [0u8; 65536];
    while c.read(&mut r).map_or(false, |n| n > 0) {}
}

/// Connects, waits, sends the PROXY line (the handshake), waits, then
/// requests and reads the response until the close.
fn proxy_row(fe: SocketAddr, path: &str) {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    thread::sleep(HANDSHAKE_DELAY);
    c.write_all(b"PROXY TCP4 10.1.1.1 10.2.2.2 1234 5678\r\n").expect("proxy line");
    thread::sleep(REQUEST_DELAY);
    c.write_all(format!("GET {path} HTTP/1.1\r\nhost: {NAME}\r\nConnection: close\r\n\r\n").as_bytes()).expect("write");
    let mut r = [0u8; 65536];
    while c.read(&mut r).map_or(false, |n| n > 0) {}
}

/// The test certificate as a root store.
/// Trusts every certificate in `ssl_f_common.pem` (leaf + intermediate CA);
/// webpki then chains the presented leaf to the intermediate anchor.
fn roots() -> RootCertStore {
    let pem = std::fs::read(CERT).expect("cert");
    let s = String::from_utf8_lossy(&pem).into_owned();
    let mut roots = RootCertStore::empty();
    for blk in s.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let end = blk.split("-----END CERTIFICATE-----").next().unwrap_or("");
        let one = format!("-----BEGIN CERTIFICATE-----{end}-----END CERTIFICATE-----\n");
        if let Ok(der) = CertificateDer::from_pem_slice(one.as_bytes()) {
            roots.add(der);
        }
    }
    roots
}

/// A TLS client over HTTP/1.1: connects, waits, does the handshake, waits,
/// then requests in order - all but the last on the same connection.
fn tls_rows(fe: SocketAddr, paths: &[&str]) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut conf = ClientConfig::builder().with_root_certificates(roots()).with_no_client_auth();
    conf.alpn_protocols = vec![b"http/1.1".to_vec()];
    let conn = ClientConnection::new(Arc::new(conf), ServerName::try_from(NAME).expect("name")).expect("client");
    let sock = TcpStream::connect(fe).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let mut s = StreamOwned::new(conn, sock);
    thread::sleep(HANDSHAKE_DELAY);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock).expect("handshake");
    }
    assert_eq!(s.conn.alpn_protocol(), Some(&b"http/1.1"[..]), "alpn");
    thread::sleep(REQUEST_DELAY);
    for (i, path) in paths.iter().enumerate() {
        if i > 0 {
            // Keep-alive gap between the previous response and the next request:
            // the interval the second request's ti measures. 200 ms puts it at ~200 ms,
            // the shape both implementations produce.
            thread::sleep(Duration::from_millis(200));
        }
        // The last request of the session asks the server to close, so the
        // session (and its log line) ends right after the response.
        let req = if i + 1 == paths.len() {
            format!("GET {path} HTTP/1.1\r\nhost: {NAME}\r\nConnection: close\r\n\r\n")
        } else {
            format!("GET {path} HTTP/1.1\r\nhost: {NAME}\r\n\r\n")
        };
        s.write_all(req.as_bytes()).expect("write");
        // The response: its head and the body it declares. `rustls` answers a read with
        // `WouldBlock` while the socket has no buffered plaintext yet, so that is a wait,
        // not an end.
        let mut buf = Vec::new();
        let mut b = [0u8; 65536];
        let started = Instant::now();
        loop {
            match s.read(&mut b) {
                Ok(0) => return,
                Ok(n) => buf.extend_from_slice(&b[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(started.elapsed() < Duration::from_secs(10), "timeout waiting for {path} response");
                    thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("read {path}: {e:?}"),
            }
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..end]);
                let cl = head
                    .lines()
                    .filter_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok()))
                    .max()
                    .unwrap_or(0);
                if buf.len() >= end + 4 + cl {
                    break;
                }
            }
        }
    }
}

/// A TLS client that negotiates `h2`: connects, waits, does the handshake,
/// waits, then sends one `GET /` (END_STREAM) and lets the connection end.
fn h2_row(fe: SocketAddr) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut conf = ClientConfig::builder().with_root_certificates(roots()).with_no_client_auth();
    conf.alpn_protocols = vec![b"h2".to_vec()];
    let conn = ClientConnection::new(Arc::new(conf), ServerName::try_from(NAME).expect("name")).expect("client");
    let sock = TcpStream::connect(fe).expect("connect");
    sock.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    let mut s = StreamOwned::new(conn, sock);
    thread::sleep(HANDSHAKE_DELAY);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock).expect("handshake");
    }
    assert_eq!(s.conn.alpn_protocol(), Some(&b"h2"[..]), "alpn");
    thread::sleep(REQUEST_DELAY);
    // The client preface, an empty SETTINGS, one HEADERS for `GET /`
    // (END_STREAM | END_HEADERS) with literal HPACK fields: `:method GET`,
    // `:scheme https`, `:path /`, `:authority www.test1.com`.
    const BLOCK: [u8; 63] = [
        0x00, 0x07, b':', b'm', b'e', b't', b'h', b'o', b'd', 0x03, b'G', b'E', b'T',
        0x00, 0x07, b':', b's', b'c', b'h', b'e', b'm', b'e', 0x05, b'h', b't', b't', b'p', b's',
        0x00, 0x05, b':', b'p', b'a', b't', b'h', 0x01, b'/',
        0x00, 0x0a, b':', b'a', b'u', b't', b'h', b'o', b'r', b'i', b't', b'y', 0x0d, b'w', b'w', b'w', b'.', b't', b'e', b's', b't', b'1', b'.', b'c', b'o', b'm',
    ];
    let mut frame = [0u8; 9 + BLOCK.len()];
    frame[2] = BLOCK.len() as u8;
    frame[3] = 0x1;
    frame[4] = 0x5;
    frame[6..9].copy_from_slice(&[0, 0, 1]);
    frame[9..].copy_from_slice(&BLOCK);
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).expect("settings");
    s.write_all(&frame).expect("headers");
    // Consume the response until the socket goes quiet, then let it end: a
    // `WouldBlock` is a wait, as above. The stream's reply ends in a HEADERS
    // frame with END_STREAM for stream 1; once it is in, the stream is over
    // and its log line is written.
    let mut b = [0u8; 65536];
    let mut got = Vec::new();
    let start = Instant::now();
    loop {
        match s.read(&mut b) {
            Ok(0) => return,
            Ok(n) => got.extend_from_slice(&b[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return,
        }
        if got.windows(9).any(|w| w[3..9] == [0x01, 0x05, 0, 0, 0, 1]) {
            thread::sleep(Duration::from_millis(100));
            return;
        }
        assert!(start.elapsed() < Duration::from_secs(5), "h2: no response: {got:?}");
        thread::sleep(Duration::from_millis(50));
    }
}

/// No handshake: `th` stays `0`, `ti` counts the whole 500 ms.
#[test]
fn handshake_timer_plain() {
    let _g = SERIALIZER.lock().unwrap();
    let p = start();
    plain_row(p.plain, "/plain");
    let (th, ti, tr, hf) = fields(&p, "/plain");
    row("plain", th, ti, tr, hf, 0, 100, 400, 600, 0, 100);
}

/// The PROXY line is the handshake: `th` counts the 300 ms before it, `ti`
/// the 200 ms after.
#[test]
fn handshake_timer_accept_proxy() {
    let _g = SERIALIZER.lock().unwrap();
    let p = start();
    proxy_row(p.prox, "/prox");
    let (th, ti, tr, hf) = fields(&p, "/prox");
    row("accept-proxy", th, ti, tr, hf, 250, 900, 100, 300, 0, 100);
}

/// The TLS accept is the handshake: `th` counts the 300 ms before the
/// ClientHello, `ti` the 200 ms after; the second request of the keep-alive
/// connection finds the handshake over already.
#[test]
fn handshake_timer_tls_keepalive() {
    let _g = SERIALIZER.lock().unwrap();
    let p = start();
    tls_rows(p.tls, &["/ka1", "/ka2"]);
    let (th, ti, tr, hf) = fields(&p, "/ka1");
    row("tls first request", th, ti, tr, hf, 250, 900, 100, 300, 0, 100);
    let (th, ti, tr, hf) = fields(&p, "/ka2");
    row("tls keep-alive second request", th, ti, tr, hf, 0, 100, 100, 300, 0, 100);
}

/// HTTP/2 over TLS: the handshake is the TLS accept, as on the HTTP/1.1 one.
/// `%HU` is the absolute URI there (both binaries log it as
/// `https://www.test1.com/`), not the origin form.
#[test]
fn handshake_timer_h2_over_tls() {
    let _g = SERIALIZER.lock().unwrap();
    let p = start();
    h2_row(p.h2);
    let (th, ti, tr, hf) = fields(&p, "https://www.test1.com/");
    row("h2 over tls", th, ti, tr, hf, 250, 900, 100, 300, 0, 100);
}
