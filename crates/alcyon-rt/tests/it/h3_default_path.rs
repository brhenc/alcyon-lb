// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T536: the default of `tune.alcyon.h3-path` is `mux`. Neither a `tune.alcyon.h3-path` line nor
//! `ALCYON_H3_PATH` in the environment: h3 is served by the mux. The two paths are told apart by a
//! server's `103 Early Hints`: the mux forwards the interim response (T520, as `HAProxy` since
//! 3.5-dev8), the relay drops it. (T523 made the relay reset a rejected stream as the mux does, so
//! a `tcp-request connection reject` no longer tells them apart.)
use crate::common;

use std::io::Write;
use std::process::{Command, Stdio};

/// A server that answers every request with a `103` then a `200`.
fn early_hints_server() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut c = c;
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut c, &mut buf);
                let _ = c.write_all(b"HTTP/1.1 103 Early Hints\r\nlink: </s.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
            });
        }
    });
    addr
}

/// Starts alcyon with `path_line` in `global` (may be empty) and no `ALCYON_H3_PATH`; one h3 request
/// to a server that sends `103` then `200`; the response heads curl printed.
fn heads_of_an_early_hint(path_line: &str) -> String {
    let tcp = common::reserve_addr();
    let quic = common::reserve_addr();
    let be = early_hints_server();
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let cfg = format!(
        "global\n  nbthread 1\n{path_line}\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend fe\n  bind {tcp}\n  bind quic4@{quic} ssl crt {crt} alpn h3\n\
         \x20 default_backend be\n\
         backend be\n  server s1 {be}\n"
    );
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = common::Alcyon(Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .env_remove("ALCYON_H3_PATH")
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon"));
    assert!(common::wait_listening(tcp), "alcyon never started listening on {tcp}");
    let out = Command::new("curl")
        .args(["-sS", "--http3-only", "-k", "--max-time", "4", "-o", "/dev/null", "-D", "-", "--resolve"])
        .arg(format!("localhost:{}:127.0.0.1", quic.port()))
        .arg(format!("https://localhost:{}/", quic.port()))
        .output()
        .expect("curl");
    common::stop(&mut child);
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn unset_h3_path_is_the_mux() {
    let got = heads_of_an_early_hint("");
    assert!(got.contains("HTTP/3 103") && got.contains("HTTP/3 200"), "the default path is not the mux (no 103 forwarded): {got:?}");
}

#[test]
fn the_relay_is_still_selectable() {
    let got = heads_of_an_early_hint("  tune.alcyon.h3-path relay\n");
    assert!(!got.contains("HTTP/3 103") && got.contains("HTTP/3 200"), "the relay forwarded a 103 or no 200: {got:?}");
}

#[test]
fn the_mux_is_still_selectable() {
    let got = heads_of_an_early_hint("  tune.alcyon.h3-path mux\n");
    assert!(got.contains("HTTP/3 103") && got.contains("HTTP/3 200"), "{got:?}");
}
