// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Every HTTP/3 request may take an idle server connection, also the first request of its
//! QUIC connection (T523). `HAProxy`'s QUIC mux marks every stream `SE_FL_NOT_FIRST`
//! (`mux_quic.c` `qcs_new`), so its transaction is `TX_NOT_FIRST` (`http_ana.c`
//! `http_create_txn`) and `be_reuse_connection` serves it from the server's idle
//! connections under the default `http-reuse safe`, as an HTTP/2 stream.
//!
//! The relay path gave each HTTP/3 request a frontend session whose request was a first
//! one, and under `safe` a first request takes no idle connection: one server connection
//! per HTTP/3 request. With 200 HTTP/3 connections opened at once against a server with a
//! listen backlog of 5 (the M2 plan's `be.py`), the extra connects overflowed its accept
//! queue, a dropped SYN cost a connect timeout and a retry, and 2-57 of 200 requests were
//! not answered within the client's 10 s (`tools/battery/h3_burst.sh`).
//!
//! Expected values measured on `HAProxy` 3.5-dev7 with QUIC (`reference/haproxy-quic`),
//! `nbthread 1`, same configuration: five `curl --http3-only` one after the other reach
//! the server over **one** connection (5 requests, 1 accept); Ibex before T523, relay path:
//! 5 accepts; mux path: 1.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use tempfile::NamedTempFile;

const REQUESTS: usize = 5;

/// A keep-alive HTTP/1.1 server answering `ok` to every request; counts the connections it
/// accepted.
fn backend() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("backend addr");
    let accepts = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&accepts);
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            counted.fetch_add(1, Ordering::SeqCst);
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        buf.drain(..end + 4);
                        if conn.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").is_err() {
                            return;
                        }
                    }
                    match conn.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
            });
        }
    });
    (addr, accepts)
}

fn require_curl_http3() {
    let ok = Command::new("curl")
        .arg("--version")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("HTTP3"));
    assert!(ok, "this test needs a curl with HTTP/3; it fails rather than skips");
}

crate::h3_both_paths! {
    fn sequential_h3_connections_share_one_server_connection() {
        require_curl_http3();
        let (srv, accepts) = backend();
        let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
        let tcp = common::reserve_addr();
        let quic = common::reserve_addr();
        let cfg = format!(
            "global\n  nbthread 1\n\
             defaults\n  mode http\n  timeout connect 3s\n  timeout client 10s\n  timeout server 10s\n\
             frontend fe\n  bind {tcp}\n  bind quic4@{quic} ssl crt {crt} alpn h3\n  default_backend be\n\
             backend be\n  server s1 {srv}\n"
        );
        let mut f = NamedTempFile::new().expect("tmp");
        f.write_all(cfg.as_bytes()).expect("write cfg");
        let mut ibex = common::ibex_command(std::env::var("IBEX_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string()))
            .arg("-f")
            .arg(f.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(common::Ibex)
            .expect("spawn ibex");
        assert!(common::wait_listening(tcp), "ibex never started listening on {tcp}");
        let mut codes = Vec::new();
        for _ in 0..REQUESTS {
            // One curl, one QUIC connection: each request is the first of its connection.
            let out = Command::new("curl")
                .args(["-sk", "--http3-only", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}"])
                .arg(format!("https://127.0.0.1:{}/", quic.port()))
                .output()
                .expect("curl");
            codes.push(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        common::stop(&mut ibex);
        assert_eq!(codes, vec!["200"; REQUESTS], "every HTTP/3 request is answered");
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            1,
            "{REQUESTS} HTTP/3 connections one after the other reach the server over one connection, as HAProxy's"
        );
    }
}
