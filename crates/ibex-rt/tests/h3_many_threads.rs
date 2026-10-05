// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! An HTTP/3 client that connects the moment Ibex answers, with many worker threads (T210).
//!
//! Each worker has its own `SO_REUSEPORT` QUIC socket. They used to be bound from inside the
//! worker threads, one after the other, while the first workers were already serving: a
//! client that came early had its first datagrams hashed over a partial set of sockets, and
//! once the rest had joined the group its later datagrams were hashed to a worker that had
//! never heard of the connection. At `nbthread` 64 that failed most handshakes made in the
//! first second.
//!
//! HAProxy (3.5-dev7 with QUIC, `nbthread 8`, strace): the QUIC listener is one UDP socket,
//! bound on the main thread before the first `clone3`, and `show fd` lists it with
//! `tmask=0xff`, shared by all threads. At `nbthread 64`, 20 of 20 HTTP/3 requests made as
//! soon as its TCP port answered succeeded (this test with `IBEX_TEST_BIN` pointing at it).

mod common;

use std::io::Write;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use tempfile::NamedTempFile;

const NBTHREAD: usize = 64;
const ATTEMPTS: usize = 20;

fn require_curl_http3() {
    let ok = Command::new("curl")
        .arg("--version")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("HTTP3"));
    assert!(ok, "this test needs a curl with HTTP/3; it fails rather than skips");
}

/// Starts Ibex (or `IBEX_TEST_BIN`, to run this against HAProxy) with an HTTP/3 frontend
/// that answers every request itself, and waits only for its TCP port.
fn start() -> (Child, NamedTempFile, SocketAddr) {
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let tcp = common::reserve_addr();
    let quic = common::reserve_addr();
    let cfg = format!(
        "global\n  nbthread {NBTHREAD}\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend fe\n  bind {tcp}\n  bind quic4@{quic} ssl crt {crt} alpn h3\n\
         \x20 http-request return status 200 content-type text/plain string \"ok\"\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(std::env::var("IBEX_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string()))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    assert!(common::wait_listening(tcp), "ibex never started listening on {tcp}");
    (child, f, quic)
}

/// Starts Ibex, then makes one HTTP/3 request at once.
/// Returns `None` on success, or what curl said.
fn one_attempt() -> Option<String> {
    let (mut child, _cfg, quic) = start();
    let out = Command::new("curl")
        .args(["-sS", "-i", "--http3-only", "-k", "--max-time", "5", "--resolve"])
        .arg(format!("localhost:{}:127.0.0.1", quic.port()))
        .arg(format!("https://localhost:{}/", quic.port()))
        .output()
        .expect("curl");
    common::stop(&mut child);
    let body = String::from_utf8_lossy(&out.stdout).replace('\r', "");
    if body.starts_with("HTTP/3 200") && body.ends_with("ok") {
        None
    } else {
        Some(format!("{body:?} / {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

#[test]
fn h3_client_right_after_start_with_many_threads() {
    require_curl_http3();
    let failures: Vec<String> = (0..ATTEMPTS).filter_map(|_| one_attempt()).collect();
    assert!(
        failures.is_empty(),
        "{} of {ATTEMPTS} HTTP/3 requests made as soon as ibex answered (nbthread {NBTHREAD}) failed:\n{failures:#?}",
        failures.len()
    );
}

/// A QUIC address that cannot be bound stops the start, before any worker runs, with
/// HAProxy's alert. HAProxy (3.5-dev7 with QUIC), the port held by a UDP socket without
/// `SO_REUSEPORT`: exit status 1 and
/// `[ALERT] ... : Binding [<file>:10] for frontend fe: protocol quic4: cannot bind socket (Address already in use) for [127.0.0.1:18443].`
#[test]
fn an_unbindable_quic_address_stops_the_start() {
    let held = std::net::UdpSocket::bind("127.0.0.1:0").expect("hold a UDP port");
    let quic = held.local_addr().expect("addr");
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let tcp = common::reserve_addr();
    let cfg = format!(
        "global\n  nbthread 4\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend fe\n  bind {tcp}\n  bind quic4@{quic} ssl crt {crt} alpn h3\n\
         \x20 http-request return status 200 content-type text/plain string \"ok\"\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdin(Stdio::null())
        .output()
        .expect("run ibex");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {err}");
    let want = format!("for frontend fe: protocol quic4: cannot bind socket (Address already in use) for [{quic}].");
    assert!(err.contains("[ALERT]") && err.contains(&want), "want {want:?} in:\n{err}");
}

