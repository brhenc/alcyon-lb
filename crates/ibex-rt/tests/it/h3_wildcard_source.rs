// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T552 (VV-27): a QUIC listener bound to the wildcard address answers from the address the
//! client sent to. curl's QUIC socket is connected, so it drops a reply from any other source:
//! with `bind quic4@0.0.0.0:<port>` and the client on 127.0.0.2, Ibex's replies left from
//! 127.0.0.1 (the route's source) and curl timed out (rc=28); `HAProxy` 3.5-dev10 returns 200
//! (`quic_lstnr_may_set_src` + `cmsg_set_saddr`, `quic_sock.c`). Mux, relay, and the Retry path
//! (`quic-force-retry`: the Retry is sent before any connection exists).
use crate::common;

use std::io::Write;
use std::process::{Command, Stdio};

fn backend() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut c = c;
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut c, &mut buf);
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
            });
        }
    });
    addr
}

/// Ibex with `bind quic4@0.0.0.0:<port>{bind_opts}` and `global_line`; one h3 request to
/// `client_ip`; curl's status line and exit code.
fn status_via(global_line: &str, bind_opts: &str, client_ip: &str) -> (String, Option<i32>) {
    let tcp = common::reserve_addr();
    let port = common::reserve_addr().port();
    let be = backend();
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let cfg = format!(
        "global\n  nbthread 1\n{global_line}\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend fe\n  bind {tcp}\n  bind quic4@0.0.0.0:{port} ssl crt {crt} alpn h3{bind_opts}\n\
         \x20 default_backend be\n\
         backend be\n  server s1 {be}\n"
    );
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .env_remove("IBEX_H3_PATH")
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    assert!(common::wait_listening(tcp), "ibex never started listening on {tcp}");
    let out = Command::new("curl")
        .args(["-sS", "--http3-only", "-k", "--max-time", "4", "-o", "/dev/null", "-w", "%{http_code}", "--resolve"])
        .arg(format!("localhost:{port}:{client_ip}"))
        .arg(format!("https://localhost:{port}/"))
        .output()
        .expect("curl");
    common::stop(&mut child);
    (String::from_utf8_lossy(&out.stdout).to_string(), out.status.code())
}

#[test]
fn mux_answers_a_secondary_address() {
    let got = status_via("  tune.ibex.h3-path mux\n", "", "127.0.0.2");
    assert_eq!(got, ("200".to_string(), Some(0)), "h3 to 127.0.0.2 on a wildcard bind (mux)");
}

#[test]
fn relay_answers_a_secondary_address() {
    let got = status_via("  tune.ibex.h3-path relay\n", "", "127.0.0.2");
    assert_eq!(got, ("200".to_string(), Some(0)), "h3 to 127.0.0.2 on a wildcard bind (relay)");
}

#[test]
fn retry_is_sent_from_the_secondary_address() {
    let got = status_via("", " quic-force-retry", "127.0.0.2");
    assert_eq!(got, ("200".to_string(), Some(0)), "h3 to 127.0.0.2 on a wildcard bind with quic-force-retry");
}

/// The address the route would pick anyway still works with the cmsg attached.
#[test]
fn primary_address_still_answers() {
    let got = status_via("", "", "127.0.0.1");
    assert_eq!(got, ("200".to_string(), Some(0)), "h3 to 127.0.0.1 on a wildcard bind");
}
