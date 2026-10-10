// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The headers of the replies the proxy generates, as `HAProxy` 3.5-dev8 sends them: names
//! in lower case, in the order below (measured on the oracle). The reply goes through HTX
//! there, which the built-in pages, `errorfile` pages and `http-request deny` all do.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

/// Starts ibex on `cfg` (`{fe}` is the listening address, `{0}` the errorfile), sends `req`
/// and returns the head of the reply.
fn reply_head(cfg: &str, errorfile: &str, req: &[u8]) -> String {
    let fe = common::reserve_addr();
    let mut ef = NamedTempFile::new().expect("tmp");
    ef.write_all(errorfile.as_bytes()).expect("write page");
    let text = cfg.replace("{fe}", &fe.to_string()).replace("{0}", &ef.path().display().to_string());
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Ibex)
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened on {fe}");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    c.write_all(req).unwrap();
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = c.read(&mut buf) {
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&buf[..n]);
        if resp.windows(4).any(|w| w == b"\r\n\r\n") && resp.ends_with(b"\n") {
            break;
        }
    }
    common::stop(&mut child);
    let text = String::from_utf8_lossy(&resp).into_owned();
    text.split("\r\n\r\n").next().unwrap_or("").to_string()
}

const CFG: &str = "global\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n  timeout http-request 1s\n\
                   frontend f\n  bind {fe}\n  default_backend b\n  errorfile 503 {0}\n  http-request deny deny_status 400 if { path /d400 }\n  http-request deny deny_status 500 if { path /d500 }\n\
                   backend b\n  http-request deny if { path /deny }\n";

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";

/// Oracle: `content-length: 107`, `cache-control: no-cache`, `content-type: text/html`.
#[test]
fn the_built_in_503_is_in_lower_case() {
    let head = reply_head(&CFG.replace("  errorfile 503 {0}\n", ""), "", GET);
    assert_eq!(
        head,
        "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 107\r\ncache-control: no-cache\r\ncontent-type: text/html"
    );
}

/// Oracle: the denied 400 puts `connection: close` last, unlike the 400 of a request that
/// does not parse.
#[test]
fn a_denied_400_ends_with_connection_close() {
    let head = reply_head(CFG, "", b"GET /d400 HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(
        head,
        "HTTP/1.1 400 Bad request\r\ncontent-length: 90\r\ncache-control: no-cache\r\ncontent-type: text/html\r\nconnection: close"
    );
}

#[test]
fn a_denied_500_and_403_are_in_lower_case() {
    let head = reply_head(CFG, "", b"GET /d500 HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(
        head,
        "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 97\r\ncache-control: no-cache\r\ncontent-type: text/html"
    );
    let head = reply_head(CFG, "", b"GET /deny HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(
        head,
        "HTTP/1.1 403 Forbidden\r\ncontent-length: 93\r\ncache-control: no-cache\r\ncontent-type: text/html"
    );
}

/// Oracle: an `errorfile` goes through HTX as well; `X-Page` comes out as `x-page`.
#[test]
fn an_errorfile_page_is_in_lower_case() {
    let head = reply_head(
        &CFG.replace("backend b\n", "backend b\n  http-request deny deny_status 503 if { path /ef }\n"),
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 3\r\nX-Page: fe\r\n\r\nfe\n",
        b"GET /ef HTTP/1.1\r\nHost: x\r\n\r\n",
    );
    assert_eq!(head, "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 3\r\nx-page: fe");
}

/// Oracle: a request that does not arrive in time gets `connection: close` before
/// `content-type`.
#[test]
fn the_408_for_a_slow_request_is_in_lower_case() {
    let head = reply_head(CFG, "", b"GET / HTTP/1.1\r\n");
    assert_eq!(
        head,
        "HTTP/1.1 408 Request Time-out\r\ncontent-length: 110\r\ncache-control: no-cache\r\nconnection: close\r\ncontent-type: text/html"
    );
}
