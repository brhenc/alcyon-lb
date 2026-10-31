// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T536: the default of `tune.ibex.h3-path` is `mux`. Neither a `tune.ibex.h3-path` line nor
//! `IBEX_H3_PATH` in the environment: the connection is served by the owner session, so
//! `tcp-request connection reject` closes the QUIC connection (curl: no response, `000`, as
//! `HAProxy` 3.5-dev10 with QUIC). The relay (explicit `tune.ibex.h3-path relay`) answers the
//! request stream instead, which is how this test tells the two paths apart.

use crate::common;

use std::io::Write;
use std::process::{Command, Stdio};

/// Starts ibex with `path_line` in `global` (may be empty) and no `IBEX_H3_PATH`, rejecting
/// connections from 127.0.0.1; one h3 request; the `%{http_code}` curl printed.
fn reject_and_get(path_line: &str) -> String {
    let tcp = common::reserve_addr();
    let quic = common::reserve_addr();
    let be = common::reserve_addr();
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let cfg = format!(
        "global\n  nbthread 1\n{path_line}\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend fe\n  bind {tcp}\n  bind quic4@{quic} ssl crt {crt} alpn h3\n\
         \x20 tcp-request connection reject if {{ src 127.0.0.1 }}\n  default_backend be\n\
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
        .args(["-sS", "--http3-only", "-k", "--max-time", "4", "-w", "%{http_code}", "--resolve"])
        .arg(format!("localhost:{}:127.0.0.1", quic.port()))
        .arg(format!("https://localhost:{}/", quic.port()))
        .output()
        .expect("curl");
    common::stop(&mut child);
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn unset_h3_path_is_the_mux() {
    let got = reject_and_get("");
    assert!(got.ends_with("000"), "the default path is not the mux (a rejected connection answered): {got:?}");
}

#[test]
fn the_relay_is_still_selectable() {
    let got = reject_and_get("  tune.ibex.h3-path relay\n");
    assert!(!got.ends_with("000"), "the relay does not answer the request stream: {got:?}");
}

#[test]
fn the_mux_is_still_selectable() {
    let got = reject_and_get("  tune.ibex.h3-path mux\n");
    assert!(got.ends_with("000"), "{got:?}");
}
