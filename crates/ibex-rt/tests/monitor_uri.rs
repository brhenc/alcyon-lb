// SPDX-License-Identifier: GPL-2.0-or-later
//! `monitor-uri` against the real binary. The expected bytes are what `HAProxy` 3.5 sends
//! for the same configuration, captured from the reference binary.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// HAProxy's response, plus the `Connection: close` Ibex adds because it closes the
/// connection after a synthetic answer where HAProxy keeps it alive. That header is the
/// one known difference; everything else is byte for byte.
const HAPROXY_RESPONSE: &str = "HTTP/1.1 200 OK\r\ncontent-length: 58\r\n\
cache-control: no-cache\r\ncontent-type: text/html\r\nConnection: close\r\n\r\n\
<html><body><h1>200 OK</h1>\nService ready.\n</body></html>\n";

fn ask(fe: std::net::SocketAddr, request_line: &str) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    write!(c, "{request_line}\r\nHost: x\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while !out.ends_with(b"</html>\n") {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn monitor_uri_is_answered_by_the_proxy_with_haproxys_response() {
    let fe = common::reserve_addr();
    // No backend at all: a request that reached one would fail, so a 200 can only come
    // from the proxy itself.
    let mut cfg = tempfile::NamedTempFile::new().unwrap();
    write!(
        cfg,
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 3s\n  timeout server 3s\n\
         frontend fe\n  bind {fe}\n  monitor-uri /health\n"
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening");
        thread::sleep(Duration::from_millis(20));
    }

    let origin = ask(fe, "GET /health HTTP/1.1");
    let absolute = ask(fe, "GET http://x/health HTTP/1.1");
    let other = ask(fe, "GET /other HTTP/1.1");
    common::stop(&mut child);

    assert_eq!(origin, HAPROXY_RESPONSE);
    assert_eq!(absolute, HAPROXY_RESPONSE, "absolute-form must match the path too");
    assert!(!other.starts_with("HTTP/1.1 200"), "only the monitor URI is answered: {other:?}");
}
