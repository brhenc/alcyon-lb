// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTTP/3 requests go through the proxy like H1 and H2 ones (T130): `http-request` and
//! `http-response` rules, `use_backend`, load balancing over the backend's servers, and one
//! access-log line per request. Before T130 the QUIC listener decoded the request and sent
//! it straight to the first server of the default backend, so none of that ran: a
//! `http-request deny` frontend served the request anyway over HTTP/3.
//!
//! Expected values measured on HAProxy 3.5-dev7 with QUIC (`reference/haproxy-quic`), same
//! configuration, `curl --http3-only` and `curl` over H1:
//! - `/deny`: 403, HAProxy's error page; log `PR--`, `"GET https://localhost:<port>/deny HTTP/3.0"`
//! - `/ret`: 203 `returned`; `/other` goes to backend `other`; the backend sees `x-added: yes`
//!   and `GET /other HTTP/1.1` with `host: localhost:<port>`
//! - every response carries `x-resp: ok`; the frontend shows as `fe~` in the log
//! - a 1 MB response arrives whole; a POST body reaches the server.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// A backend named `name` that answers every request with its name and the request head it
/// received, `/big` with 1 MB, `/slow` after two seconds, and echoes a request body.
fn backend(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut data = Vec::new();
                let mut buf = [0u8; 65536];
                loop {
                    let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") else {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => data.extend_from_slice(&buf[..n]),
                        }
                        continue;
                    };
                    let head = String::from_utf8_lossy(&data[..end]).to_string();
                    let cl: usize = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.trim().eq_ignore_ascii_case("content-length").then(|| v.trim().parse().ok())?
                        })
                        .unwrap_or(0);
                    // A server slow to take an upload: the body backs up into the engine,
                    // then into the relay, which must wait for the engine with write
                    // interest rather than drop or spin.
                    if head.starts_with("POST /upload ") {
                        thread::sleep(Duration::from_millis(500));
                    }
                    while data.len() < end + 4 + cl {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => data.extend_from_slice(&buf[..n]),
                        }
                    }
                    let req_body = data[end + 4..end + 4 + cl].to_vec();
                    data.drain(..end + 4 + cl);
                    let first = head.lines().next().unwrap_or("").to_string();
                    if first.contains(" /slow ") {
                        thread::sleep(Duration::from_secs(2));
                    }
                    let body = if first.contains(" /upload ") {
                        format!("got {} bytes", req_body.len()).into_bytes()
                    } else if first.contains(" /big ") {
                        vec![b'x'; 1_000_000]
                    } else if first.contains(" /huge ") {
                        vec![b'x'; 16_000_000]
                    } else {
                        let mut b = format!("server={name}\n{head}\n\n").into_bytes();
                        b.extend_from_slice(&req_body);
                        b
                    };
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Srv: {name}\r\n\r\n", body.len());
                    if s.write_all(resp.as_bytes()).is_err() || s.write_all(&body).is_err() {
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
    _cfg: NamedTempFile,
    quic: SocketAddr,
    tcp: SocketAddr,
    log: UdpSocket,
}

impl Alcyon {
    fn start() -> Self {
        let s1 = backend("s1");
        let s2 = backend("s2");
        let other = backend("other");
        let log = UdpSocket::bind("127.0.0.1:0").expect("bind syslog");
        log.set_read_timeout(Some(Duration::from_millis(200))).expect("timeout");
        let log_addr = log.local_addr().expect("addr");
        let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
        let tcp = common::reserve_addr();
        let quic = common::reserve_addr();
        let cfg = format!(
            "global\n  nbthread 1\n  log {log_addr} local0\n\
             defaults\n  mode http\n  log global\n  option httplog\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
             frontend fe\n  bind {tcp}\n  bind quic4@{quic} ssl crt {crt} alpn h3\n\
             \x20 http-request deny if {{ path /deny }}\n\
             \x20 http-request return status 203 content-type text/plain string \"returned\" if {{ path /ret }}\n\
             \x20 http-request set-header X-Added yes\n\
             \x20 http-response set-header X-Resp ok\n\
             \x20 acl other path_beg /other\n\
             \x20 use_backend other if other\n\
             \x20 default_backend be\n\
             backend be\n  balance roundrobin\n  server s1 {s1}\n  server s2 {s2}\n\
             backend other\n  server o {other}\n"
        );
        let mut f = NamedTempFile::new().expect("tmp");
        f.write_all(cfg.as_bytes()).expect("write cfg");
        let child = common::alcyon_command(env!("CARGO_BIN_EXE_alcyon"))
            .arg("-f")
            .arg(f.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn alcyon");
        assert!(common::wait_listening(tcp), "alcyon never started listening on {tcp}");
        Self { child, _cfg: f, quic, tcp, log }
    }

    /// One HTTP/3 request; returns the response head and body as curl prints them (`-i`).
    fn h3(&self, path: &str, extra: &[&str]) -> String {
        let out = Command::new("curl")
            .args(["-sS", "-i", "--http3-only", "-k", "--max-time", "8", "--resolve"])
            .arg(format!("localhost:{}:127.0.0.1", self.quic.port()))
            .args(extra)
            .arg(format!("https://localhost:{}{path}", self.quic.port()))
            .output()
            .expect("curl");
        let s = String::from_utf8_lossy(&out.stdout).replace('\r', "");
        assert!(
            s.starts_with("HTTP/3 "),
            "no HTTP/3 response for {path}:\n{s}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        s
    }

    /// Log lines received within `wait`.
    fn logs(&self, wait: Duration) -> Vec<String> {
        let deadline = Instant::now() + wait;
        let mut lines = Vec::new();
        let mut buf = [0u8; 4096];
        while Instant::now() < deadline {
            if let Ok(n) = self.log.recv(&mut buf) {
                lines.push(String::from_utf8_lossy(&buf[..n]).to_string());
            }
        }
        lines
    }

    fn cpu_ticks(&self) -> u64 {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.child.id())).expect("stat");
        let after = &stat[stat.rfind(')').expect("comm") + 2..];
        let f: Vec<&str> = after.split(' ').collect();
        // utime and stime: fields 14 and 15 of stat(5), 12 and 13 after the comm.
        f[11].parse::<u64>().expect("utime") + f[12].parse::<u64>().expect("stime")
    }
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn require_curl_http3() {
    let ok = Command::new("curl")
        .arg("--version")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("HTTP3"));
    assert!(ok, "this test needs a curl with HTTP/3; it fails rather than skips");
}

fn status(resp: &str) -> &str {
    resp.lines().next().unwrap_or("").trim()
}

crate::h3_both_paths! {
fn http_request_rules_run_on_h3() {
    require_curl_http3();
    let alcyon = Alcyon::start();
    let deny = alcyon.h3("/deny", &[]);
    assert_eq!(status(&deny), "HTTP/3 403", "http-request deny must refuse an H3 request:\n{deny}");
    assert!(deny.contains("403 Forbidden"), "HAProxy's 403 page:\n{deny}");
    let ret = alcyon.h3("/ret", &[]);
    assert_eq!(status(&ret), "HTTP/3 203", "http-request return over H3:\n{ret}");
    assert!(ret.ends_with("returned"), "{ret}");
    let fwd = alcyon.h3("/a", &[]);
    // Case-insensitive: HAProxy sends `x-added` (HTX names are lower case), Alcyon keeps the
    // rule's spelling, on H1 as well; that difference is not HTTP/3's.
    assert!(
        fwd.to_ascii_lowercase().contains("x-added: yes"),
        "http-request set-header must reach the server:\n{fwd}"
    );
    assert!(fwd.contains("GET /a HTTP/1.1\n"), "the server gets an origin-form H1 request:\n{fwd}");
    assert!(
        fwd.to_ascii_lowercase().contains(&format!("host: localhost:{}", alcyon.quic.port())),
        ":authority becomes Host:\n{fwd}"
    );
}
}

crate::h3_both_paths! {
fn use_backend_chooses_the_backend_on_h3() {
    require_curl_http3();
    let alcyon = Alcyon::start();
    let r = alcyon.h3("/other", &[]);
    assert!(r.contains("server=other"), "use_backend on a path ACL must route an H3 request:\n{r}");
}
}

crate::h3_both_paths! {
fn h3_requests_are_balanced_over_the_servers() {
    require_curl_http3();
    let alcyon = Alcyon::start();
    let seen: Vec<bool> = (0..4).map(|_| alcyon.h3("/a", &[]).contains("server=s1")).collect();
    assert!(
        seen.contains(&true) && seen.contains(&false),
        "balance roundrobin must spread H3 requests over s1 and s2; s1 took {seen:?}"
    );
}
}

crate::h3_both_paths! {
fn http_response_rules_run_on_h3() {
    require_curl_http3();
    let alcyon = Alcyon::start();
    let r = alcyon.h3("/a", &[]);
    assert!(r.contains("x-resp: ok"), "http-response set-header must reach the H3 client:\n{r}");
    assert!(r.contains("x-srv: "), "the server's own headers are relayed:\n{r}");
    let deny = alcyon.h3("/deny", &[]);
    assert!(!deny.contains("x-resp"), "a denied request runs no response rule (HAProxy):\n{deny}");
}
}

crate::h3_both_paths! {
fn one_log_line_per_h3_request() {
    require_curl_http3();
    let alcyon = Alcyon::start();
    let _ = alcyon.logs(Duration::from_millis(300));
    alcyon.h3("/deny", &[]);
    alcyon.h3("/other", &[]);
    let lines = alcyon.logs(Duration::from_millis(800));
    assert_eq!(lines.len(), 2, "one log line per H3 request: {lines:#?}");
    let port = alcyon.quic.port();
    assert!(
        lines[0].contains(" fe~ fe/<NOSRV> ")
            && lines[0].contains(" 403 ")
            && lines[0].contains(" PR-- ")
            && lines[0].contains(&format!("\"GET https://localhost:{port}/deny HTTP/3.0\"")),
        "{}",
        lines[0]
    );
    assert!(
        lines[1].contains(" fe~ other/o ")
            && lines[1].contains(" 200 ")
            && lines[1].contains(&format!("\"GET https://localhost:{port}/other HTTP/3.0\"")),
        "{}",
        lines[1]
    );
}
}

crate::h3_both_paths! {
/// Larger than what the stream's flow-control window and send buffer take at once: before
/// T130 `write_stream` dropped what did not fit and finished the stream, so curl got a
/// truncated body (1 MB happened to fit; 16 MB does not).
fn large_h3_responses_arrive_whole() {
    require_curl_http3();
    let alcyon = Alcyon::start();
    for (path, len) in [("/big", 1_000_000), ("/huge", 16_000_000)] {
        let out = Command::new("curl")
            .args(["-sS", "--http3-only", "-k", "--max-time", "30", "--resolve"])
            .arg(format!("localhost:{}:127.0.0.1", alcyon.quic.port()))
            .arg(format!("https://localhost:{}{path}", alcyon.quic.port()))
            .output()
            .expect("curl");
        assert_eq!(out.stdout.len(), len, "{path}: stderr: {}", String::from_utf8_lossy(&out.stderr));
        assert!(out.stdout.iter().all(|&b| b == b'x'));
    }
}
}

crate::h3_both_paths! {
fn an_h3_request_body_reaches_the_server() {
    require_curl_http3();
    let alcyon = Alcyon::start();
    let r = alcyon.h3("/post", &["-d", "hello=world"]);
    assert!(r.contains("POST /post HTTP/1.1") && r.ends_with("hello=world"), "{r}");
    // Without a content-length the body is streamed, chunked to the H1 side.
    let r = alcyon.h3("/post", &["-H", "Transfer-Encoding: chunked", "--data-binary", "streamed-body"]);
    assert!(r.ends_with("streamed-body"), "{r}");
}
}

crate::h3_both_paths! {
fn a_slow_server_does_not_spin_the_loop() {
    require_curl_http3();
    let alcyon = Alcyon::start();
    // Warm up, so the connection setup is not counted.
    alcyon.h3("/a", &[]);
    let before = alcyon.cpu_ticks();
    let r = alcyon.h3("/slow", &[]);
    let used = alcyon.cpu_ticks() - before;
    assert!(r.contains("server="), "{r}");
    // Two seconds of waiting; a spinning loop burns ~200 ticks (at 100 Hz), an idle one a few.
    assert!(used < 40, "the loop spun while the server took 2 s: {used} ticks");
}
}

crate::h3_both_paths! {
/// The same rules on H1, so a failure above is about HTTP/3 and not about the configuration.
fn the_same_configuration_on_h1() {
    let alcyon = Alcyon::start();
    let mut s = std::net::TcpStream::connect(alcyon.tcp).expect("connect");
    s.write_all(b"GET /deny HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
}
}

crate::h3_both_paths! {
/// A body larger than what the engine's side of the relay takes at once: the relay writes
/// it as the engine reads, and the client's flow control holds the rest back.
fn a_large_h3_request_body_reaches_the_server() {
    require_curl_http3();
    let alcyon = Alcyon::start();
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(&vec![b'y'; 3_000_000]).expect("write");
    let path = format!("@{}", f.path().display());
    let r = alcyon.h3("/upload", &["--data-binary", &path]);
    assert!(r.ends_with("got 3000000 bytes"), "{r}");
}
}

crate::h3_both_paths! {
/// Concurrent requests on one connection are each a stream of their own in the engine.
/// (curl opens them a flight apart, so this passed before the endpoint learned to accept
/// several streams per `Opened` event; `h3_relay_streams.rs` `malformed_requests_get_a_400`
/// is the one that opens three in a single flight.)
fn parallel_h3_requests_are_all_answered() {
    require_curl_http3();
    let alcyon = Alcyon::start();
    let url = |p: &str| format!("https://localhost:{}{p}", alcyon.quic.port());
    let out = Command::new("curl")
        .args(["-sS", "--http3-only", "-k", "--max-time", "8", "--parallel", "--parallel-immediate", "--resolve"])
        .arg(format!("localhost:{}:127.0.0.1", alcyon.quic.port()))
        .args([url("/p1"), url("/p2"), url("/p3"), url("/p4")])
        .args(["-w", "[%{http_code}]"])
        .output()
        .expect("curl");
    let s = String::from_utf8_lossy(&out.stdout);
    assert_eq!(s.matches("[200]").count(), 4, "{s}\nstderr: {}", String::from_utf8_lossy(&out.stderr));
}
}
