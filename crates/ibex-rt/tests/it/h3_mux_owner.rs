// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The owner session of an HTTP/3 connection (T509, `tune.ibex.h3-path mux`): its
//! `tcp-request connection` rules run once, for the connection. Measured on `HAProxy` 3.5-dev7
//! with QUIC (`reference/haproxy-quic`), `tcp-request connection reject if { src 127.0.0.1 }`
//! on the QUIC bind: curl gets no response (`ERR_DRAINING`, the connection closed); a rule that
//! does not match leaves the request served. On the relay (`tune.ibex.h3-path relay`) the rules run
//! per request stream, and the stream is answered 502 by the relay (T504's known gap, gone
//! with the relay in slice H5): there the test asserts only that nothing was served.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::thread;

fn backend() -> std::net::SocketAddr {
    backend_answering(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
}

/// A backend that answers each connection's first request with `response` and closes it.
fn backend_answering(response: &'static [u8]) -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = s.write_all(response);
            });
        }
    });
    addr
}

struct Ibex {
    child: Child,
    _cfg: tempfile::NamedTempFile,
    quic: std::net::SocketAddr,
}

impl Ibex {
    fn start(rule_src: &str) -> Self {
        Self::start_with(rule_src, backend())
    }

    fn start_with(rule_src: &str, be: std::net::SocketAddr) -> Self {
        let tcp = common::reserve_addr();
        let quic = common::reserve_addr();
        let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
        let cfg = format!(
            "global\n  nbthread 1\n\
             defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
             frontend fe\n  bind {tcp}\n  bind quic4@{quic} ssl crt {crt} alpn h3\n\
             \x20 tcp-request connection reject if {{ src {rule_src} }}\n  default_backend be\n\
             backend be\n  server s1 {be}\n"
        );
        let mut f = tempfile::NamedTempFile::new().expect("tmp");
        f.write_all(cfg.as_bytes()).expect("write cfg");
        let child = common::ibex_command(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
        assert!(common::wait_listening(tcp), "ibex never started listening on {tcp}");
        Self { child, _cfg: f, quic }
    }

    fn get(&self) -> String {
        let out = Command::new("curl")
            .args(["-sS", "--http3-only", "-k", "--max-time", "4", "-w", "%{http_code}", "--resolve"])
            .arg(format!("localhost:{}:127.0.0.1", self.quic.port()))
            .arg(format!("https://localhost:{}/", self.quic.port()))
            .output()
            .expect("curl");
        String::from_utf8_lossy(&out.stdout).to_string()
    }
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

crate::h3_both_paths! {
fn tcp_request_connection_reject_refuses_the_quic_connection() {
    let ibex = Ibex::start("127.0.0.1");
    let got = ibex.get();
    assert!(!got.contains("ok"), "a rejected connection was served: {got:?}");
    if common::h3_mux() {
        assert!(got.ends_with("000"), "no response expected, as HAProxy: {got:?}");
    }
}
}

crate::h3_both_paths! {
fn a_tcp_request_connection_rule_that_does_not_match_serves_the_request() {
    let ibex = Ibex::start("10.9.9.9");
    assert_eq!(ibex.get(), "ok200");
}
}

crate::h3_both_paths! {
/// T511: a server connection that closed right after its response is not the next stream's.
/// Two requests one after the other on one HTTP/3 connection, to a server that closes each
/// connection once it has answered (with `connection: close`, and without: keep-alive
/// implied, the close comes unannounced): both are served, over one QUIC connection
/// (`num_connects` 1, then 0). `HAProxy` 3.5-dev7 with QUIC, the same backend: 200 and 200,
/// a server connection each. (A server that closes only some milliseconds after its
/// response, the next request already sent on the connection, has that stream reset on
/// `HAProxy` and on the mux alike: measured, not pinned, see `tasks/T509-progress.md`.)
fn a_server_connection_closed_after_its_response_is_not_the_next_streams() {
    for response in [
        &b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"[..],
        &b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"[..],
    ] {
        let ibex = Ibex::start_with("10.9.9.9", backend_answering(response));
        let port = ibex.quic.port();
        let url = format!("https://localhost:{port}/");
        let out = Command::new("curl")
            .args(["-sS", "--http3-only", "-k", "--max-time", "4", "-w", " %{http_code} %{num_connects}\n", "--resolve"])
            .arg(format!("localhost:{port}:127.0.0.1"))
            .args([&url, &url])
            .output()
            .expect("curl");
        let got = String::from_utf8_lossy(&out.stdout);
        assert_eq!(got, "ok 200 1\nok 200 0\n", "{:?}: stderr {}", String::from_utf8_lossy(response), String::from_utf8_lossy(&out.stderr));
    }
}
}
