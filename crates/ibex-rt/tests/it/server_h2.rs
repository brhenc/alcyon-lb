// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTTP/2 to servers (T540, slice B-H2 of T535): `server ... ssl alpn h2` and `proto h2`
//! (h2c) speak h2 through `ibex_proto::h2_srv::H2SrvCodec`, one stream at a time, as
//! `HAProxy` 3.5-dev8 does under `http-reuse safe`.
//!
//! Measured on `HAProxy` 3.5-dev8 (T535, T537, `/tmp/t540` rigs, 2026-10-31):
//! * `alpn h2` and `alpn h2,http/1.1` to nghttpd (which speaks only h2): 200; Ibex before
//!   T540 wrote HTTP/1.1 into the h2 connection: 502;
//! * `proto h2` to an h2c server: 200 (Ibex before: refused at load);
//! * a server's RST_STREAM before the response head: 502 `SH--`; a response head with a
//!   connection-specific field (`connection`): 502 `PH--`; REFUSED_STREAM: 502 `SH--`;
//! * a server that sends GOAWAY after its third stream: seven requests take connections of
//!   3, 3 and 1 streams, all answered;
//! * ten requests of one client connection under `http-reuse safe` to a TLS h2 server: one
//!   server connection.
//!
//! nghttpd missing: those tests say so on stderr and pass.

use crate::common::{self, Ibex};

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const BODY: &str = "hello from nghttpd\n";

/// nghttpd, stopped when dropped; its `-v` log lines collected.
pub(crate) struct Nghttpd {
    child: Child,
    pub(crate) addr: SocketAddr,
    log: Arc<Mutex<Vec<String>>>,
    _dir: TempDir,
}

impl Drop for Nghttpd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Nghttpd {
    /// The connections that carried a request: the sessions (`[id=<n>]`) nghttpd logged a
    /// request HEADERS on (the readiness probe is a session too, with none).
    fn connections(&self) -> usize {
        let log = self.log.lock().unwrap();
        let mut ids: Vec<&str> =
            log.iter().filter(|l| l.contains("recv HEADERS frame")).filter_map(|l| l.split("[id=").nth(1)?.split(']').next()).collect();
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    }

    fn saw(&self, needle: &str) -> bool {
        self.log.lock().unwrap().iter().any(|l| l.contains(needle))
    }
}

pub(crate) fn have_nghttpd() -> bool {
    let ok = Command::new("nghttpd").arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    if !ok {
        eprintln!("nghttpd not found: skipped");
    }
    ok
}

/// nghttpd on a reserved port: TLS with a self-signed certificate, or `--no-tls`; `extra`
/// options (`--echo-upload`, `--trailer=...`).
pub(crate) fn nghttpd(tls: bool, extra: &[&str]) -> Nghttpd {
    let dir = TempDir::new().expect("dir");
    std::fs::write(dir.path().join("index.html"), BODY).expect("index");
    let port = common::reserve_port();
    let mut cmd = Command::new("nghttpd");
    cmd.arg("-v").arg("-a").arg("127.0.0.1").arg(format!("--htdocs={}", dir.path().display())).args(extra);
    if tls {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
        std::fs::write(dir.path().join("cert.pem"), cert.cert.pem()).expect("cert.pem");
        std::fs::write(dir.path().join("key.pem"), cert.key_pair.serialize_pem()).expect("key.pem");
        cmd.arg(port.to_string()).arg(dir.path().join("key.pem")).arg(dir.path().join("cert.pem"));
    } else {
        cmd.arg("--no-tls").arg(port.to_string());
    }
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn nghttpd");
    let out = child.stdout.take().expect("stdout");
    let log = Arc::new(Mutex::new(Vec::new()));
    let l2 = Arc::clone(&log);
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            l2.lock().unwrap().push(line);
        }
    });
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    assert!(common::wait_listening(addr), "nghttpd never listened");
    Nghttpd { child, addr, log, _dir: dir }
}

/// Ibex with one frontend and `backend` as its backend's lines; its log lines (stdout,
/// `option httplog`) collected.
struct Proxy {
    _ibex: Ibex,
    fe: SocketAddr,
    logs: mpsc::Receiver<String>,
    dir: TempDir,
}

fn proxy(backend: &str) -> Proxy {
    proxy_bind(backend, "")
}

/// As `proxy`, with `bind_opts` on the frontend's `bind` line (`proto h2`).
fn proxy_bind(backend: &str, bind_opts: &str) -> Proxy {
    let dir = TempDir::new().expect("dir");
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n  log stdout format raw local0\n  stats socket {}/stats.sock\n\
         defaults\n  mode http\n  log global\n  option httplog\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe} {bind_opts}\n  default_backend b\n\
         backend b\n{backend}\n",
        dir.path().display()
    );
    let path = dir.path().join("ibex.cfg");
    std::fs::write(&path, cfg).expect("cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let out = child.stdout.take().expect("stdout");
    let (tx, logs) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let ibex = Ibex(child);
    assert!(common::wait_listening(fe), "ibex never listened");
    Proxy { _ibex: ibex, fe, logs, dir }
}

impl Proxy {
    /// The next log line that holds `want`.
    fn log_with(&self, want: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
        while let Ok(l) = self.logs.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            if l.contains(want) {
                return l;
            }
        }
        String::new()
    }
}

/// Status and body of one HTTP/1.1 exchange on its own connection; `req` is the request
/// text after the request line's method and target.
fn exchange(fe: SocketAddr, req: &[u8]) -> (u16, Vec<u8>, String) {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    s.write_all(req).expect("write");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    split(&out)
}

/// Status, de-chunked body and head of a response.
fn split(out: &[u8]) -> (u16, Vec<u8>, String) {
    let Some(end) = out.windows(4).position(|w| w == b"\r\n\r\n") else {
        return (0, Vec::new(), String::from_utf8_lossy(out).into_owned());
    };
    let head = String::from_utf8_lossy(&out[..end]).into_owned();
    let status = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut body = out[end + 4..].to_vec();
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        body = dechunk(&body).0;
    }
    (status, body, head)
}

/// A chunked body's data and its trailer section.
fn dechunk(mut b: &[u8]) -> (Vec<u8>, String) {
    let mut data = Vec::new();
    loop {
        let Some(eol) = b.windows(2).position(|w| w == b"\r\n") else { return (data, String::new()) };
        let size = usize::from_str_radix(String::from_utf8_lossy(&b[..eol]).split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        b = &b[eol + 2..];
        if size == 0 {
            return (data, String::from_utf8_lossy(b).into_owned());
        }
        data.extend_from_slice(&b[..size.min(b.len())]);
        b = &b[(size + 2).min(b.len())..];
    }
}

fn get(fe: SocketAddr, path: &str) -> (u16, Vec<u8>, String) {
    exchange(fe, format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes())
}

/// `n` GETs on one kept-alive client connection: their statuses.
fn get_keepalive(fe: SocketAddr, n: usize) -> Vec<u16> {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut statuses = Vec::new();
    for _ in 0..n {
        if s.write_all(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n").is_err() {
            break;
        }
        let mut line = String::new();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        statuses.push(line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0));
        let (mut len, mut chunked) = (0usize, false);
        loop {
            let mut h = String::new();
            if r.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                break;
            }
            let lower = h.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                len = v.trim().parse().unwrap_or(0);
            }
            chunked |= lower.starts_with("transfer-encoding:") && lower.contains("chunked");
        }
        if chunked {
            loop {
                let mut sz = String::new();
                r.read_line(&mut sz).ok();
                let n = usize::from_str_radix(sz.trim(), 16).unwrap_or(0);
                let mut skip = vec![0u8; n + 2];
                r.read_exact(&mut skip).ok();
                if n == 0 {
                    break;
                }
            }
        } else {
            let mut skip = vec![0u8; len];
            r.read_exact(&mut skip).ok();
        }
    }
    statuses
}

// ----------------------------------------------------------------------------------------
// A scripted h2c server: what nghttpd cannot be made to do (reset a stream, send a bad
// head, GOAWAY after n streams).
// ----------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Script {
    /// `:status 200`, body `ok`; GOAWAY and close after `n` streams (0: never).
    Ok { goaway_after: u32 },
    /// `:status 200` and `ok` with no content-length.
    NoLength,
    /// `:status 200`, then 50 ms later a GOAWAY on the idle connection, which stays open:
    /// a stream after it is refused (REFUSED_STREAM).
    GoawayWhenIdle,
    /// RST_STREAM INTERNAL_ERROR before any response.
    Reset,
    /// RST_STREAM REFUSED_STREAM before any response.
    Refuse,
    /// REFUSED_STREAM on the first connection, `Ok` on the others.
    RefuseFirstConnection,
    /// A response head with `connection: close` in it.
    BadHead,
    /// The head, part of a content-length body, then RST_STREAM.
    ResetAfterHead,
}

struct Scripted {
    addr: SocketAddr,
    /// Streams answered on each connection, in the order the connections came.
    streams: Arc<Mutex<Vec<u32>>>,
}

fn frame(out: &mut Vec<u8>, typ: u8, flags: u8, id: u32, payload: &[u8]) {
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    out.push(typ);
    out.push(flags);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(payload);
}

fn scripted(script: Script) -> Scripted {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().unwrap();
    let streams = Arc::new(Mutex::new(Vec::new()));
    let st = Arc::clone(&streams);
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { continue };
            let st = Arc::clone(&st);
            let idx = {
                let mut v = st.lock().unwrap();
                v.push(0);
                v.len() - 1
            };
            thread::spawn(move || serve_h2c(s, script, &st, idx));
        }
    });
    Scripted { addr, streams }
}

fn serve_h2c(mut s: TcpStream, script: Script, st: &Mutex<Vec<u32>>, idx: usize) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let mut pre = [0u8; 24];
    if s.read_exact(&mut pre).is_err() {
        return;
    }
    let mut out = Vec::new();
    frame(&mut out, 4, 0, 0, &[]);
    let _ = s.write_all(&out);
    let mut served = 0u32;
    let mut gone_away = false;
    loop {
        let mut h = [0u8; 9];
        if s.read_exact(&mut h).is_err() {
            return;
        }
        let len = usize::from(h[0]) << 16 | usize::from(h[1]) << 8 | usize::from(h[2]);
        let (typ, flags) = (h[3], h[4]);
        let id = u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff;
        let mut p = vec![0u8; len];
        if s.read_exact(&mut p).is_err() {
            return;
        }
        let mut out = Vec::new();
        if typ == 4 && flags & 1 == 0 {
            frame(&mut out, 4, 1, 0, &[]);
        }
        // The request is whole at END_STREAM, on HEADERS or DATA.
        if (typ == 1 || typ == 0) && flags & 1 != 0 && id != 0 {
            if gone_away {
                frame(&mut out, 3, 0, id, &7u32.to_be_bytes());
                let _ = s.write_all(&out);
                continue;
            }
            served += 1;
            st.lock().unwrap()[idx] = served;
            match script {
                Script::GoawayWhenIdle => {
                    frame(&mut out, 1, 4, id, &[0x88, 0x0f, 0x0d, 0x01, b'2']);
                    frame(&mut out, 0, 1, id, b"ok");
                    let _ = s.write_all(&out);
                    out.clear();
                    thread::sleep(Duration::from_millis(50));
                    let mut g = id.to_be_bytes().to_vec();
                    g.extend_from_slice(&0u32.to_be_bytes());
                    frame(&mut out, 7, 0, 0, &g);
                    gone_away = true;
                }
                Script::Ok { goaway_after } => {
                    frame(&mut out, 1, 4, id, &[0x88, 0x0f, 0x0d, 0x01, b'2']);
                    frame(&mut out, 0, 1, id, b"ok");
                    if goaway_after != 0 && served >= goaway_after {
                        let mut g = id.to_be_bytes().to_vec();
                        g.extend_from_slice(&0u32.to_be_bytes());
                        frame(&mut out, 7, 0, 0, &g);
                        let _ = s.write_all(&out);
                        thread::sleep(Duration::from_millis(100));
                        return;
                    }
                }
                Script::Reset => frame(&mut out, 3, 0, id, &2u32.to_be_bytes()),
                Script::Refuse => frame(&mut out, 3, 0, id, &7u32.to_be_bytes()),
                Script::NoLength => {
                    frame(&mut out, 1, 4, id, &[0x88]);
                    frame(&mut out, 0, 1, id, b"ok");
                }
                Script::RefuseFirstConnection if idx == 0 => frame(&mut out, 3, 0, id, &7u32.to_be_bytes()),
                Script::RefuseFirstConnection => {
                    frame(&mut out, 1, 4, id, &[0x88, 0x0f, 0x0d, 0x01, b'2']);
                    frame(&mut out, 0, 1, id, b"ok");
                }
                Script::BadHead => {
                    let mut b = vec![0x88, 0x00, 10];
                    b.extend_from_slice(b"connection");
                    b.push(5);
                    b.extend_from_slice(b"close");
                    frame(&mut out, 1, 5, id, &b);
                }
                Script::ResetAfterHead => {
                    // `content-length: 10` (static index 28), then 3 bytes, then the reset.
                    frame(&mut out, 1, 4, id, &[0x88, 0x0f, 0x0d, 0x02, b'1', b'0']);
                    frame(&mut out, 0, 0, id, b"abc");
                    frame(&mut out, 3, 0, id, &2u32.to_be_bytes());
                }
            }
        }
        if !out.is_empty() && s.write_all(&out).is_err() {
            return;
        }
    }
}

// ----------------------------------------------------------------------------------------
// The tests
// ----------------------------------------------------------------------------------------

#[test]
fn tls_alpn_h2_reaches_an_h2_only_server() {
    if !have_nghttpd() {
        return;
    }
    for alpn in ["h2", "h2,http/1.1"] {
        let srv = nghttpd(true, &[]);
        let p = proxy(&format!("  server s {} ssl verify none alpn {alpn}", srv.addr));
        let (status, body, head) = get(p.fe, "/index.html");
        assert_eq!(status, 200, "alpn {alpn}: {head}");
        assert_eq!(body, BODY.as_bytes(), "alpn {alpn}");
        assert!(srv.saw("recv HEADERS frame"), "alpn {alpn}: nghttpd saw no HTTP/2 request");
    }
}

#[test]
fn proto_h2_speaks_h2c_to_a_cleartext_server() {
    if !have_nghttpd() {
        return;
    }
    let srv = nghttpd(false, &[]);
    let p = proxy(&format!("  server s {} proto h2", srv.addr));
    let (status, body, head) = get(p.fe, "/index.html");
    assert_eq!(status, 200, "{head}");
    assert_eq!(body, BODY.as_bytes());
    let (status, _, _) = get(p.fe, "/missing");
    assert_eq!(status, 404);
}

#[test]
fn a_one_mib_post_and_a_chunked_post_are_echoed_whole() {
    if !have_nghttpd() {
        return;
    }
    for tls in [false, true] {
        let srv = nghttpd(tls, &["--echo-upload"]);
        let line = if tls { format!("  server s {} ssl verify none alpn h2", srv.addr) } else { format!("  server s {} proto h2", srv.addr) };
        let p = proxy(&line);
        let big: Vec<u8> = (0..1 << 20).map(|i: u32| b'a' + (i % 26) as u8).collect();
        let mut req = format!("POST /up HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", big.len()).into_bytes();
        req.extend_from_slice(&big);
        let (status, body, head) = exchange(p.fe, &req);
        assert_eq!(status, 200, "tls {tls}: {head}");
        assert_eq!(body.len(), big.len(), "tls {tls}: the 1 MiB body echoed whole");
        assert!(body == big, "tls {tls}: the echoed body differs");
        let req = b"POST /up HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        let (status, body, head) = exchange(p.fe, req);
        assert_eq!(status, 200, "tls {tls}: {head}");
        assert_eq!(body, b"abcde", "tls {tls}");
    }
}

#[test]
fn request_and_response_trailers_cross_h2() {
    if !have_nghttpd() {
        return;
    }
    let srv = nghttpd(false, &["--echo-upload", "--trailer=grpc-status: 0", "--no-content-length"]);
    let p = proxy(&format!("  server s {} proto h2", srv.addr));
    let req = b"POST /up HTTP/1.1\r\nHost: localhost\r\nTE: trailers\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\nx-req-trailer: yes\r\n\r\n";
    let mut s = TcpStream::connect(p.fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let end = out.windows(4).position(|w| w == b"\r\n\r\n").expect("a head");
    let head = String::from_utf8_lossy(&out[..end]).to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert!(head.contains("transfer-encoding: chunked"), "{head}");
    let (data, trailers) = dechunk(&out[end + 4..]);
    assert_eq!(data, b"abc");
    assert!(trailers.contains("grpc-status: 0"), "the response trailer reaches the h1 client: {trailers:?}");
    assert!(wait_for(|| srv.saw("x-req-trailer: yes")), "the request trailer reached the server as HEADERS");
}

/// An h2 server's response trailer behind a TLS `alpn h2` server reaches an h1 client.
#[test]
fn response_trailers_cross_tls_h2_server() {
    if !have_nghttpd() {
        return;
    }
    let srv = nghttpd(true, &["--trailer=grpc-status: 0", "--no-content-length"]);
    let p = proxy(&format!("  server s {} ssl verify none alpn h2", srv.addr));
    let mut s = TcpStream::connect(p.fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    s.write_all(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\nTE: trailers\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let end = out.windows(4).position(|w| w == b"\r\n\r\n").expect("a head");
    let (data, trailers) = dechunk(&out[end + 4..]);
    assert_eq!(data, BODY.as_bytes());
    assert!(trailers.contains("grpc-status: 0"), "the response trailer reaches the h1 client: {trailers:?}");
}

/// T549: the same through an **h2 client** (`bind ... proto h2`, nghttp as the client).
///
/// `HAProxy` 3.5-dev8 on the same topology (`nghttp -v http://fe/index.html`, nghttpd
/// `--trailer='grpc-status: 0' --no-content-length` behind `proto h2`): HEADERS (flags 0x04,
/// `:status: 200`, `trailer: grpc-status`), DATA (3 bytes), then a second HEADERS frame,
/// flags 0x05 (END_STREAM | END_HEADERS), `grpc-status: 0`. Identical to what nghttpd sends
/// direct. Ibex's h2 frontend drops response trailers (`tradeoff.md` 6.31 row 8): this test
/// is red until that is fixed.
#[test]
fn response_trailers_reach_an_h2_client() {
    if !have_nghttpd() || Command::new("nghttp").arg("--version").stdout(Stdio::null()).status().is_err() {
        eprintln!("nghttpd or nghttp not found: skipped");
        return;
    }
    let srv = nghttpd(false, &["--trailer=grpc-status: 0", "--no-content-length"]);
    let p = proxy_bind(&format!("  server s {} proto h2", srv.addr), "proto h2");
    let out = Command::new("nghttp").arg("-v").arg(format!("http://{}/index.html", p.fe)).output().expect("nghttp");
    let log = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(log.contains("recv (stream_id=1) :status: 200"), "{log}");
    let trailing = log.lines().skip_while(|l| !l.contains("recv DATA frame")).skip(1).collect::<Vec<_>>().join("\n");
    assert!(trailing.contains("recv (stream_id=1) grpc-status: 0"), "a trailing HEADERS frame with grpc-status: 0 after the DATA:\n{log}");
    assert!(trailing.contains("flags=0x05"), "the trailing HEADERS frame ends the stream:\n{log}");
}

/// The `show stat` field `field` of server `b/s`.
fn stat(p: &Proxy, field: &str) -> String {
    let Ok(mut s) = std::os::unix::net::UnixStream::connect(p.dir.path().join("stats.sock")) else { return String::new() };
    let _ = s.write_all(b"show stat\n");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let mut lines = out.lines();
    let header: Vec<&str> = lines.next().unwrap_or("").trim_start_matches("# ").split(',').collect();
    let Some(col) = header.iter().position(|h| *h == field) else { return String::new() };
    lines.find(|l| l.starts_with("b,s,")).and_then(|l| l.split(',').nth(col)).unwrap_or("").to_string()
}

/// An HTTP check to an h2 server goes as an h2 stream, as `HAProxy`'s (A.3 rows 20, 22-24:
/// UP, `L7OK`, the server sees HTTP/2): over TLS when ALPN selects `h2` (`alpn h2` inherited
/// by the check, or `check-alpn h2`), over cleartext for `proto h2` (inherited) or
/// `check-proto h2`. Ibex before T540: `L7TOUT` for `check-alpn h2`, refused for the others.
#[test]
fn http_checks_to_an_h2_server_speak_h2() {
    if !have_nghttpd() {
        return;
    }
    let tls = nghttpd(true, &[]);
    let clear = nghttpd(false, &[]);
    for (srv, line) in [
        (&tls, "ssl verify none alpn h2 check inter 100ms"),
        (&tls, "ssl verify none check check-alpn h2 inter 100ms"),
        (&clear, "proto h2 check inter 100ms"),
        (&clear, "check check-proto h2 inter 100ms"),
    ] {
        // nghttpd refuses a request with neither `:authority` nor `host` (GOAWAY: `SOCKERR` for
        // `HAProxy` as for Ibex), which a check sends unless told.
        let p = proxy(&format!("  option httpchk GET /index.html\n  http-check send hdr host localhost\n  server s {} {line}", srv.addr));
        let ok = wait_for(|| stat(&p, "check_status") == "L7OK" && stat(&p, "status") == "UP");
        assert!(ok, "`{line}`: check_status {} status {}", stat(&p, "check_status"), stat(&p, "status"));
    }
}

fn wait_for(mut f: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn a_reset_before_the_head_is_502_sh_and_a_bad_head_502_ph() {
    for (script, status, term) in [(Script::Reset, 502, " SH-- "), (Script::Refuse, 502, " SH-- "), (Script::BadHead, 502, " PH-- ")] {
        let srv = scripted(script);
        let p = proxy(&format!("  server s {} proto h2", srv.addr));
        let (got, _, head) = get(p.fe, "/x");
        assert_eq!(got, status, "{head}");
        let log = p.log_with("/x HTTP/1.1");
        assert!(log.contains(term), "want {term}: {log}");
    }
}

/// `HAProxy` 3.5-dev8 retries a refused stream as an empty response (`retry-on
/// empty-response`: 200, one retry in the log, on a new connection) and has no
/// `refused-stream` keyword; without it, 502 `SH--` as above.
#[test]
fn a_refused_stream_is_retried_under_retry_on_empty_response() {
    let srv = scripted(Script::RefuseFirstConnection);
    let p = proxy(&format!("  retry-on empty-response\n  server s {} proto h2", srv.addr));
    let (got, body, head) = get(p.fe, "/x");
    assert_eq!((got, body.as_slice()), (200, b"ok".as_slice()), "{head}");
    let log = p.log_with("/x HTTP/1.1");
    assert!(log.contains(" 1/1/0/0/1 "), "one retry: {log}");
    assert_eq!(*srv.streams.lock().unwrap(), [1, 1]);
}

/// `%B` counts what `HAProxy`'s HTX of the response holds: no reason phrase from an h2 server,
/// no `transfer-encoding` for a response without a length. Measured on 3.5-dev8 with this
/// server: 49 bytes with `content-length: 2`, 34 without.
#[test]
fn the_bytes_logged_for_an_h2_response_are_haproxys() {
    for (script, want) in [(Script::Ok { goaway_after: 0 }, " 200 49 "), (Script::NoLength, " 200 34 ")] {
        let srv = scripted(script);
        let p = proxy(&format!("  server s {} proto h2", srv.addr));
        assert_eq!(get(p.fe, "/x").0, 200);
        let log = p.log_with("/x HTTP/1.1");
        assert!(log.contains(want), "want {want}: {log}");
    }
}

#[test]
fn a_reset_after_the_head_truncates_the_response_sd() {
    let srv = scripted(Script::ResetAfterHead);
    let p = proxy(&format!("  server s {} proto h2", srv.addr));
    let (got, body, head) = get(p.fe, "/x");
    assert_eq!(got, 200, "{head}");
    assert_eq!(body, b"abc");
    let log = p.log_with("/x HTTP/1.1");
    assert!(log.contains(" SD-- "), "{log}");
}

#[test]
fn a_server_goaway_after_three_streams_moves_to_a_new_connection() {
    let srv = scripted(Script::Ok { goaway_after: 3 });
    let p = proxy(&format!("  server s {} proto h2", srv.addr));
    let statuses = get_keepalive(p.fe, 7);
    assert_eq!(statuses, [200; 7]);
    assert_eq!(*srv.streams.lock().unwrap(), [3, 3, 1], "as HAProxy");
}

/// `max-reuse 2`: an h2 connection carries 3 streams (`HAProxy` A.3 row 11, 7 sequential requests
/// under `always`: `3 3 1`); `max-reuse` on an HTTP/1.1 server is ignored by both (row 12).
#[test]
fn max_reuse_caps_the_streams_of_an_h2_connection() {
    let srv = scripted(Script::Ok { goaway_after: 0 });
    let p = proxy(&format!("  http-reuse always\n  server s {} proto h2 max-reuse 2", srv.addr));
    for _ in 0..7 {
        assert_eq!(get(p.fe, "/x").0, 200);
        thread::sleep(Duration::from_millis(30));
    }
    assert_eq!(*srv.streams.lock().unwrap(), [3, 3, 1]);
}

#[test]
fn ten_requests_of_one_client_take_one_tls_h2_connection_under_safe() {
    if !have_nghttpd() {
        return;
    }
    let srv = nghttpd(true, &[]);
    let p = proxy(&format!("  http-reuse safe\n  server s {} ssl verify none alpn h2", srv.addr));
    assert_eq!(get_keepalive(p.fe, 10), [200; 10]);
    assert_eq!(srv.connections(), 1, "one server connection, as HAProxy");
}

/// One request per client connection, five clients one after the other: `HAProxy` (A.3 rows
/// 6, 7) opens one server connection for each under `safe`, where an h2 connection is
/// private to its session, and one for all under `aggressive` and `always`.
#[test]
fn sequential_clients_share_an_h2_connection_as_the_reuse_mode_says() {
    for (mode, want) in [("safe", 5), ("aggressive", 1), ("always", 1)] {
        let srv = scripted(Script::Ok { goaway_after: 0 });
        let p = proxy(&format!("  http-reuse {mode}\n  server s {} proto h2", srv.addr));
        for _ in 0..5 {
            assert_eq!(get(p.fe, "/x").0, 200, "{mode}");
            thread::sleep(Duration::from_millis(50));
        }
        let streams = srv.streams.lock().unwrap().clone();
        assert_eq!(streams.len(), want, "{mode}: connections and their streams {streams:?}");
    }
}

/// A GOAWAY on an idle h2 connection: it is read there and the connection dropped, so the
/// next request opens another and is answered.
#[test]
fn an_idle_h2_connection_that_got_a_goaway_is_not_reused() {
    let srv = scripted(Script::GoawayWhenIdle);
    let p = proxy(&format!("  http-reuse always\n  server s {} proto h2", srv.addr));
    for _ in 0..3 {
        assert_eq!(get(p.fe, "/x").0, 200);
        thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(*srv.streams.lock().unwrap(), [1, 1, 1]);
}

#[test]
fn proto_h2_is_accepted_and_alpn_h3_on_a_tcp_server_refused() {
    let dir = TempDir::new().expect("dir");
    let run = |server: &str| {
        let path = dir.path().join("c.cfg");
        std::fs::write(&path, format!("defaults\n  mode http\nbackend b\n  {server}\n")).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("ibex -c");
        (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
    };
    let (ok, out) = run("server s 127.0.0.1:1 proto h2");
    assert!(ok, "{out}");
    let (ok, out) = run("default-server proto h2\n  server s 127.0.0.1:1");
    assert!(ok, "{out}");
    let (ok, out) = run("server s 127.0.0.1:1 ssl verify none alpn h3");
    assert!(!ok && out.contains("h3"), "{out}");
}
