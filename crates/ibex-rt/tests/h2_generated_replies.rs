// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Replies the proxy makes itself, on an HTTP/2 connection (T142).
//!
//! `return`, `deny`, `tarpit`, `redirect`, `auth`, `monitor-uri`, the error pages and the
//! `http-response` deny/redirect all end in an HTTP/1 reply built as bytes. On an HTTP/2
//! connection those bytes were written as they were, and the client failed with
//! `nghttp2 ... PROTOCOL_ERROR`. `HAProxy` answers each as HEADERS + DATA on the stream.
//!
//! Expected values measured on `HAProxy 3.5-dev8-885761-29` with
//! `curl --http2-prior-knowledge` (cleartext) on a `bind ... proto h2`:
//!
//! ```text
//! /ret     200 content-length: 5  content-type: text/plain         hello
//! /deny    403 content-length: 93 cache-control: no-cache          <h1>403 Forbidden</h1>...
//! /deny429 429 content-length: 117                                 <h1>429 Too Many Requests</h1>...
//! /tar     500 content-length: 97, after 1.0 s with `timeout tarpit 1s`
//! /red     302 content-length: 0  location: /x
//! /auth    401 content-length: 112 www-authenticate: Basic realm="L" (Ibex's H1 `auth` differs: realm and
//!                                  body are not the oracle's, and `redirect` lacks cache-control; not h2)
//! /r204    204 (no content-length)
//! /mon     200 content-length: 58  Service ready.
//! no srv   503 content-length: 107
//! ```

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::{NamedTempFile, TempDir};

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
    _dir: TempDir,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// An HTTP/1 server that answers every request `200 OK` with a two-byte body.
fn server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 || c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn start() -> (Ibex, SocketAddr, SocketAddr) {
    let dir = TempDir::new().expect("dir");
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let pem = dir.path().join("c.pem");
    std::fs::write(&pem, format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem())).expect("pem");
    let (plain, tls, srv) = (common::reserve_addr(), common::reserve_addr(), server());
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 1s\n  timeout tarpit 1s\n\
         frontend fe\n  bind {plain} proto h2\n  bind {tls} ssl crt {} alpn h2,http/1.1\n  monitor-uri /mon\n\
         \x20 http-after-response set-header static yes\n\
         \x20 http-request return status 200 content-type text/plain string hello if {{ path /ret }}\n\
         \x20 http-request deny if {{ path /deny }}\n\
         \x20 http-request deny deny_status 429 if {{ path /deny429 }}\n\
         \x20 http-request tarpit if {{ path /tar }}\n\
         \x20 http-request redirect location /x if {{ path /red }}\n\
         \x20 http-request auth realm L if {{ path /auth }}\n\
         \x20 http-request return status 204 if {{ path /r204 }}\n\
         \x20 use_backend nosrv if {{ path /nosrv }}\n\
         \x20 default_backend be\n\
         backend be\n  http-response deny if {{ path /rdeny }}\n\
         \x20 http-response redirect location /y if {{ path /rred }}\n\
         \x20 server s {srv}\n\
         backend nosrv\n",
        pem.display()
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, _cfg: f, _dir: dir };
    assert!(common::wait_listening(plain) && common::wait_listening(tls), "ibex never listened:\n{cfg}");
    (ibex, plain, tls)
}

struct Case {
    path: &'static str,
    status: u16,
    /// Header lines (lower-case `name: value`) that must be present.
    headers: &'static [&'static str],
    body: &'static str,
    min_secs: f64,
}

const CASES: &[Case] = &[
    Case { path: "/ret", status: 200, headers: &["content-length: 5", "content-type: text/plain", "static: yes"], body: "hello", min_secs: 0.0 },
    Case { path: "/deny", status: 403, headers: &["content-length: 93", "cache-control: no-cache", "content-type: text/html", "static: yes"], body: "<html><body><h1>403 Forbidden</h1>\nRequest forbidden by administrative rules.\n</body></html>\n", min_secs: 0.0 },
    Case { path: "/deny429", status: 429, headers: &["content-length: 117"], body: "<html><body><h1>429 Too Many Requests</h1>\nYou have sent too many requests in a given amount of time.\n</body></html>\n", min_secs: 0.0 },
    Case { path: "/tar", status: 500, headers: &["content-length: 97", "static: yes"], body: "<html><body><h1>500 Internal Server Error</h1>\nAn internal server error occurred.\n</body></html>\n", min_secs: 0.95 },
    Case { path: "/red", status: 302, headers: &["content-length: 0", "location: /x", "static: yes"], body: "", min_secs: 0.0 },
    Case { path: "/auth", status: 401, headers: &["static: yes"], body: "*", min_secs: 0.0 },
    Case { path: "/r204", status: 204, headers: &["static: yes"], body: "", min_secs: 0.0 },
    Case { path: "/mon", status: 200, headers: &["content-length: 58"], body: "<html><body><h1>200 OK</h1>\nService ready.\n</body></html>\n", min_secs: 0.0 },
    Case { path: "/nosrv", status: 503, headers: &["content-length: 107", "static: yes"], body: "<html><body><h1>503 Service Unavailable</h1>\nNo server is available to handle this request.\n</body></html>\n", min_secs: 0.0 },
    Case { path: "/rdeny", status: 502, headers: &["static: yes"], body: "<html><body><h1>502 Bad Gateway</h1>\nThe server returned an invalid or incomplete response.\n</body></html>\n", min_secs: 0.0 },
    Case { path: "/rred", status: 302, headers: &["location: /y", "static: yes"], body: "", min_secs: 0.0 },
];

fn check(url_base: &str, flags: &[&str]) {
    let mut failures = Vec::new();
    for c in CASES {
        let t0 = Instant::now();
        let out = Command::new("curl")
            .args(["-s", "-i", "-k", "--max-time", "10", "-w", "\n%{http_version}"])
            .args(flags)
            .arg(format!("{url_base}{}", c.path))
            .output()
            .expect("curl");
        let secs = t0.elapsed().as_secs_f64();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let (resp, ver) = text.rsplit_once('\n').unwrap_or((&text, ""));
        let (head, body) = resp.split_once("\r\n\r\n").unwrap_or((resp, ""));
        let lower = head.to_ascii_lowercase();
        let mut why = Vec::new();
        if ver != "2" {
            why.push(format!("version {ver:?} (curl exit {:?})", out.status.code()));
        }
        if !head.starts_with(&format!("HTTP/2 {}", c.status)) {
            why.push(format!("status line {:?}", head.lines().next()));
        }
        for h in c.headers {
            if !lower.lines().any(|l| l.trim_end() == *h) {
                why.push(format!("missing header {h:?}"));
            }
        }
        if c.body != "*" && body != c.body {
            why.push(format!("body {body:?}"));
        }
        if secs < c.min_secs {
            why.push(format!("answered in {secs:.2}s, before the tarpit delay"));
        }
        if !why.is_empty() {
            failures.push(format!("{}: {}", c.path, why.join("; ")));
        }
    }
    assert!(failures.is_empty(), "generated replies over h2:\n{}", failures.join("\n"));
}

#[test]
fn generated_replies_over_h2_prior_knowledge() {
    let (_ibex, plain, _) = start();
    check(&format!("http://{plain}"), &["--http2-prior-knowledge"]);
}

#[test]
fn generated_replies_over_h2_alpn() {
    let (_ibex, _, tls) = start();
    let port = tls.port();
    check(&format!("https://localhost:{port}"), &["--http2", "--resolve", &format!("localhost:{port}:127.0.0.1")]);
}

#[test]
fn tarpit_over_h2_waits_for_timeout_tarpit() {
    let (_ibex, plain, _) = start();
    let t0 = Instant::now();
    let out = Command::new("curl")
        .args(["-s", "-o", "/dev/null", "-w", "%{http_code} %{http_version}", "--http2-prior-knowledge"])
        .arg(format!("http://{plain}/tar"))
        .output()
        .expect("curl");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "500 2");
    assert!(t0.elapsed() >= Duration::from_millis(950), "tarpit answered after {:?}", t0.elapsed());
}

/// `timeout client` on an HTTP/2 connection that has sent its preface and nothing more:
/// the H2 mux closes it, it does not write the H1 `408` page into the frame stream.
#[test]
fn client_timeout_on_h2_writes_no_http1_page() {
    let (_ibex, plain, _) = start();
    let mut c = std::net::TcpStream::connect(plain).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(8))).expect("timeout");
    // The preface and a SETTINGS frame, then silence; `timeout client` is 5 s.
    c.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00").expect("preface");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    assert!(!got.windows(8).any(|w| w == b"HTTP/1.1"), "HTTP/1 text on an h2 connection: {:?}", String::from_utf8_lossy(&got));
}
