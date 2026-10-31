// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A TCP `ssl` bind and a `quic4@` bind on one ip:port (T494): the standard HTTP/3 deployment.
//! `bind_tls` used to take the first `ssl` bind at the address whatever its transport, so the
//! QUIC listener got the TCP bind's `alpn h2,http/1.1` and curl's `h3` was refused (or, with
//! the QUIC line first, the TCP listener got `alpn h3`).
//!
//! Expected values measured on HAProxy 3.5-dev7 (QUIC build), same configuration:
//! `curl --http3-only` is `3 200`, `curl --http2` over TCP is `2 200`, in both bind orders.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::process::{Command, Stdio};
use std::thread;
use tempfile::NamedTempFile;

fn backend() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn curl_version(port: u16, flag: &str) -> String {
    let out = Command::new("curl")
        .args(["-sk", flag, "--max-time", "8", "--resolve"])
        .arg(format!("localhost:{port}:127.0.0.1"))
        .args(["-o", "/dev/null", "-w", "%{http_version} %{http_code}"])
        .arg(format!("https://localhost:{port}/"))
        .output()
        .expect("curl");
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn run(quic_first: bool) {
    let be = backend();
    let addr = common::reserve_addr();
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let tcp = format!("bind {addr} ssl crt {crt} alpn h2,http/1.1");
    let quic = format!("bind quic4@{addr} ssl crt {crt} alpn h3");
    let (a, b) = if quic_first { (quic, tcp) } else { (tcp, quic) };
    let cfg = format!(
        "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend fe\n  {a}\n  {b}\n  default_backend be\nbackend be\n  server s1 {be}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = common::ibex_command(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    assert!(common::wait_listening(addr), "ibex never listened on {addr}");
    let h3 = curl_version(addr.port(), "--http3-only");
    let h2 = curl_version(addr.port(), "--http2");
    common::stop(&mut child);
    assert_eq!(h3, "3 200", "h3 on a port shared with a TCP ssl bind (quic first: {quic_first})");
    assert_eq!(h2, "2 200", "h2 over TCP on the shared port (quic first: {quic_first})");
}

crate::h3_both_paths! {
fn tcp_line_first() {
    run(false);
}
}

crate::h3_both_paths! {
fn quic_line_first() {
    run(true);
}
}
