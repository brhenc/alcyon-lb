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
struct Nghttpd {
    child: Child,
    addr: SocketAddr,
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

fn have_nghttpd() -> bool {
    let ok = Command::new("nghttpd").arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    if !ok {
        eprintln!("nghttpd not found: skipped");
    }
    ok
}

/// nghttpd on a reserved port: TLS with a self-signed certificate, or `--no-tls`; `extra`
/// options (`--echo-upload`, `--trailer=...`).
fn nghttpd(tls: bool, extra: &[&str]) -> Nghttpd {
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
    let dir = TempDir::new().expect("dir");
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n  log stdout format raw local0\n  stats socket {}/stats.sock\n\
         defaults\n  mode http\n  log global\n  option httplog\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  default_backend b\n\
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
    /// `Ok`, then the connection closed (FIN, no GOAWAY).
    CloseAfterResponse,
    /// `Ok`, then 50 ms later the connection reset (RST, no GOAWAY).
    ResetAfterResponse,
    /// RST_STREAM INTERNAL_ERROR on the request's HEADERS, its body not waited for.
    ResetOnHeaders,
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
        if matches!(script, Script::ResetOnHeaders) && typ == 1 && id != 0 {
            frame(&mut out, 3, 0, id, &2u32.to_be_bytes());
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
                Script::CloseAfterResponse => {
                    frame(&mut out, 1, 4, id, &[0x88, 0x0f, 0x0d, 0x01, b'2']);
                    frame(&mut out, 0, 1, id, b"ok");
                    let _ = s.write_all(&out);
                    // A FIN, not the RST a close with unread bytes would be.
                    let _ = s.shutdown(std::net::Shutdown::Write);
                    thread::sleep(Duration::from_millis(50));
                    return;
                }
                Script::ResetAfterResponse => {
                    frame(&mut out, 1, 4, id, &[0x88, 0x0f, 0x0d, 0x01, b'2']);
                    frame(&mut out, 0, 1, id, b"ok");
                    let _ = s.write_all(&out);
                    thread::sleep(Duration::from_millis(50));
                    let _ = rustix::net::sockopt::set_socket_linger(&s, Some(Duration::ZERO));
                    return;
                }
                Script::ResetOnHeaders => {}
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

/// `proto h2` with `ssl alpn h2`: the h2 layer is put on at the connect, before the TLS
/// handshake, so the handshake's own switch on `h2` in ALPN must not put on a second one.
/// `HAProxy` 3.5-dev8 (measured 2026-10-31, nghttpd): 200 `----`, the check (`check-proto h2`)
/// `L7OK`, UP. Ibex before this test: 502 `SH--` and the check `Socket error`, DOWN.
#[test]
fn proto_h2_with_alpn_h2_over_tls_is_one_h2_layer() {
    if !have_nghttpd() {
        return;
    }
    let srv = nghttpd(true, &[]);
    let p = proxy(&format!(
        "  option httpchk GET /index.html\n  http-check send hdr host localhost\n  server s {} ssl verify none alpn h2 proto h2 check check-proto h2 inter 100ms",
        srv.addr
    ));
    let ok = wait_for(|| stat(&p, "check_status") == "L7OK" && stat(&p, "status") == "UP");
    assert!(ok, "check_status {} status {}", stat(&p, "check_status"), stat(&p, "status"));
    let (status, body, head) = get(p.fe, "/index.html");
    assert_eq!(status, 200, "{head}");
    assert_eq!(body, BODY.as_bytes());
}

/// The transport of a TLS connection that selected `h2`, seen through the h2 layer the
/// handshake put on: its ALPN, its TLS facts, its key name and its truncation are the TLS
/// connection's, and it is one layer deep.
#[test]
fn a_tls_h2_transport_answers_for_the_tls_under_it() {
    use ibex_rt::ServerXprt;
    use std::os::fd::AsFd;
    if !have_nghttpd() {
        return;
    }
    let srv = nghttpd(true, &[]);
    let opts = ibex_tls::BackendTlsOptions { verify_required: false, alpn: vec![b"h2".to_vec()], ..Default::default() };
    let cfg = ibex_tls::tcp::build_backend_client_config(&opts).expect("client config");
    let sock = TcpStream::connect(srv.addr).expect("connect");
    sock.set_nonblocking(true).expect("nonblocking");
    let name = rustls24::pki_types::ServerName::try_from("localhost").expect("name");
    let mut x = ibex_rt::connect_tls(&sock, cfg, name);
    let ready = wait_for(|| x.handshake(sock.as_fd()).expect("handshake"));
    assert!(ready, "handshake never finished");
    assert!(matches!(x, ServerXprt::H2(_)), "h2 in ALPN puts the h2 layer on: {x:?}");
    let dbg = format!("{x:?}");
    assert!(dbg.starts_with("ServerXprt::H2(") && dbg.matches("ServerXprt::H2(").count() == 1, "{dbg}");
    assert_eq!(x.alpn(), Some(b"h2".as_slice()));
    assert!(x.tls_info().is_some(), "the TLS facts of the connection under the h2 layer");
    assert!(!x.was_truncated());
    x.set_key_name(Some("key.example"));
    assert_eq!(x.sni(), Some("key.example"), "the key name reaches the TLS connection under the h2 layer");
}

/// A server that closes (FIN) or resets (RST, 50 ms after the response) its connection, with
/// no GOAWAY: the idle connection reads its end and is dropped, the next request takes a new
/// one. `HAProxy` 3.5-dev8 (measured 2026-10-31, the same servers in Python, `http-reuse
/// always`): 200 `----` three times, three connections, for both.
#[test]
fn an_h2_connection_the_server_closed_is_not_reused() {
    for script in [Script::CloseAfterResponse, Script::ResetAfterResponse] {
        let srv = scripted(script);
        let p = proxy(&format!("  http-reuse always\n  server s {} proto h2", srv.addr));
        for _ in 0..3 {
            assert_eq!(get(p.fe, "/x").0, 200);
            let log = p.log_with("/x HTTP/1.1");
            assert!(log.contains(" ---- "), "{log}");
            thread::sleep(Duration::from_millis(200));
        }
        assert_eq!(*srv.streams.lock().unwrap(), [1, 1, 1]);
    }
}

/// A server that resets the stream on the request's HEADERS while its 4 MB body is still on
/// the way: the rest of the body is not sent into the reset stream and the client gets 502
/// `SH--`, as from `HAProxy` 3.5-dev8 (measured 2026-10-31, `curl --data-binary` of 4 MB).
#[test]
fn a_reset_during_the_request_body_is_502_sh() {
    let srv = scripted(Script::ResetOnHeaders);
    let p = proxy(&format!("  server s {} proto h2", srv.addr));
    let body = vec![b'z'; 4_000_000];
    let mut req = format!("POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    req.extend_from_slice(&body);
    let mut s = TcpStream::connect(p.fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    // The proxy may answer and close before it has read the whole body.
    let _ = s.write_all(&req);
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let (status, _, head) = split(&out);
    assert_eq!(status, 502, "{head}");
    let log = p.log_with("POST /x HTTP/1.1");
    assert!(log.contains(" SH-- "), "{log}");
}

/// The TLS handshake may end in `send` or `recv` rather than in `handshake` (T535): the h2
/// layer goes on there, so the request text goes out as h2 and the response comes back as
/// text. An empty `send` or `recv` on the layer moves nothing.
#[test]
fn a_tls_handshake_that_ends_in_send_or_recv_puts_the_h2_layer_on_there() {
    use ibex_rt::{Io, ServerXprt};
    use std::os::fd::AsFd;
    if !have_nghttpd() {
        return;
    }
    let srv = nghttpd(true, &[]);
    let opts = ibex_tls::BackendTlsOptions { verify_required: false, alpn: vec![b"h2".to_vec()], ..Default::default() };
    let cfg = ibex_tls::tcp::build_backend_client_config(&opts).expect("client config");
    let req = b"GET /index.html HTTP/1.1\r\nhost: localhost\r\n\r\n";
    for in_send in [true, false] {
        let sock = TcpStream::connect(srv.addr).expect("connect");
        sock.set_nonblocking(true).expect("nonblocking");
        let fd = sock.as_fd();
        let name = rustls24::pki_types::ServerName::try_from("localhost").expect("name");
        let mut x = ibex_rt::connect_tls(&sock, std::sync::Arc::clone(&cfg), name);
        let mut buf = vec![0u8; 16384];
        let mut sent = false;
        let up = wait_for(|| {
            if in_send {
                sent = matches!(x.send(fd, req).expect("send"), Io::Done(n) if n == req.len());
                sent
            } else {
                let _ = x.recv(fd, &mut buf).expect("recv");
                matches!(x, ServerXprt::H2(_))
            }
        });
        assert!(up && matches!(x, ServerXprt::H2(_)), "in_send {in_send}: {x:?}");
        assert!(matches!(x.send(fd, b"").expect("empty send"), Io::WouldBlock), "in_send {in_send}");
        assert!(matches!(x.recv(fd, &mut []).expect("empty recv"), Io::WouldBlock), "in_send {in_send}");
        // Cleartext under the layer (`proto h2`) has no handshake to drive.
        let mut clear = ServerXprt::Plain.into_h2().expect("h2c_srv pool");
        assert!(clear.handshake(fd).expect("handshake"), "h2c is ready at once");
        if !sent {
            assert!(wait_for(|| matches!(x.send(fd, req).expect("send"), Io::Done(n) if n == req.len())), "the request taken");
        }
        let mut text = Vec::new();
        let done = wait_for(|| {
            if let Io::Done(n) = x.recv(fd, &mut buf).expect("recv") {
                text.extend_from_slice(&buf[..n]);
            }
            text.windows(BODY.len()).any(|w| w == BODY.as_bytes())
        });
        assert!(done && text.starts_with(b"HTTP/1.1 200"), "in_send {in_send}: {}", String::from_utf8_lossy(&text));
    }
}

/// CONNECT to an h2 server: the codec refuses it (no extended CONNECT yet, T548), so the
/// request fails 502 where `HAProxy` 3.5-dev8 tunnels it (T540's measurements;
/// docs/differences.md). The server sees no stream.
#[test]
fn connect_to_an_h2_server_is_refused_502() {
    let srv = scripted(Script::Ok { goaway_after: 0 });
    let p = proxy(&format!("  server s {} proto h2", srv.addr));
    let (status, _, head) = exchange(p.fe, b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
    assert_eq!(status, 502, "{head}");
    assert!(srv.streams.lock().unwrap().iter().all(|&n| n == 0), "no stream reached the server");
}
