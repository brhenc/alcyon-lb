// SPDX-License-Identifier: GPL-2.0-or-later

//! A config requesting TLS must be refused while TLS is unwired.
//!
//! `ibex-config` parses `bind ... ssl crt <file>`, but `ibex-rt` does not depend on
//! `ibex-tls`, so the flag reaches no transport. Without this guard the daemon binds
//! :443, reports success, and serves plaintext to clients that believe they negotiated
//! TLS — a silent downgrade of every connection on that listener.
//!
//! **Delete this test in the same change that wires `ibex-tls` into `ibex-rt`**, and
//! replace it with one asserting TLS actually happens.

use std::io::Write;
use std::process::Command;

fn ibex_bin() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.join("target").join("debug").join("ibex")
}

fn write_cfg(name: &str, body: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("ibex_tls_test_{}_{}.cfg", name, std::process::id()));
    let mut f = std::fs::File::create(&p).expect("create cfg");
    f.write_all(body.as_bytes()).expect("write cfg");
    p
}

const BASE: &str = "defaults\n\tmode http\n\ttimeout connect 5s\n\ttimeout client 30s\n\ttimeout server 30s\n\n";

#[test]
fn ssl_bind_is_refused_rather_than_silently_downgraded() {
    let bin = ibex_bin();
    if !bin.exists() {
        eprintln!("skipping: {} not built", bin.display());
        return;
    }
    let cfg = write_cfg(
        "ssl",
        &format!("{BASE}frontend fe\n\tbind 127.0.0.1:18443 ssl crt /etc/ssl/x.pem\n\tdefault_backend be\n\nbackend be\n\tserver s1 127.0.0.1:18444\n"),
    );

    let out = Command::new(&bin).arg("-c").arg("-f").arg(&cfg).output().expect("run ibex");
    let _ = std::fs::remove_file(&cfg);

    assert!(
        !out.status.success(),
        "a config requesting TLS must be refused while no TLS transport is wired; \
         accepting it means serving plaintext on a port the operator believes is encrypted"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("TLS is configured but not supported"),
        "the refusal must say why. got stderr: {err}"
    );
    assert!(
        err.contains("plaintext"),
        "the refusal must name the actual risk. got stderr: {err}"
    );
}

#[test]
fn plaintext_bind_still_starts() {
    // The guard must not be a blanket rejection of every bind line.
    let bin = ibex_bin();
    if !bin.exists() {
        eprintln!("skipping: {} not built", bin.display());
        return;
    }
    let cfg = write_cfg(
        "plain",
        &format!("{BASE}frontend fe\n\tbind 127.0.0.1:18445\n\tdefault_backend be\n\nbackend be\n\tserver s1 127.0.0.1:18444\n"),
    );

    let out = Command::new(&bin).arg("-c").arg("-f").arg(&cfg).output().expect("run ibex");
    let _ = std::fs::remove_file(&cfg);

    assert!(
        out.status.success(),
        "a plaintext config must still be accepted. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
