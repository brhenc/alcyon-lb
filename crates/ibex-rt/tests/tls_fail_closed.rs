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

// ---- connect retry turn-around delay ------------------------------------------------

// HAProxy waits `MIN(1s, timeout connect)` before retrying the *same* server after an
// asynchronous connect failure (`src/backend.c:2890`), because an instant retry almost
// always reproduces the same error and burns the retry budget for nothing.
// // The differential harness caught this: against HAProxy 3.5 the `server_refused`
// scenario took ~2000ms across its retries while Ibex gave up in 152ms.

use ibex_rt::proxy::{TcpSession, Timeouts};
use ibex_sched::Tick;

fn session_with(timeouts: Timeouts, retries: u16) -> TcpSession {
    // A pipe gives us an owned fd without needing a socket peer.
    // Any owned fd will do; the retry logic never touches the client socket.
    let f = std::fs::File::open("/dev/null").expect("open /dev/null");
    TcpSession::new(std::os::fd::OwnedFd::from(f), timeouts, retries, Tick(1000))
}

#[test]
fn same_server_retry_waits_one_second_by_default() {
    let mut s = session_with(Timeouts::default(), 3);
    assert!(s.server_failed_at(Tick(1000), true), "a retry should remain");
    assert_eq!(s.retry_delay_ms(), 1000, "default turn-around is 1s");
    assert!(s.retry_pending(Tick(1500)), "must still be waiting mid-delay");
    assert!(!s.retry_pending(Tick(2001)), "must be clear once the delay elapses");
}

#[test]
fn turn_around_is_capped_by_a_shorter_connect_timeout() {
    // MIN(1s, timeout connect). A 200ms connect timeout must not wait 1s to retry.
    let t = Timeouts { client: 0, server: 0, connect: 200 };
    let mut s = session_with(t, 3);
    assert_eq!(s.retry_delay_ms(), 200);
    assert!(s.server_failed_at(Tick(1000), true));
    assert!(s.retry_pending(Tick(1100)));
    assert!(!s.retry_pending(Tick(1201)), "capped delay must expire at 200ms");
}

#[test]
fn a_longer_connect_timeout_does_not_extend_the_delay() {
    let t = Timeouts { client: 0, server: 0, connect: 30_000 };
    let s = session_with(t, 3);
    assert_eq!(s.retry_delay_ms(), 1000, "1s is a ceiling, not a floor");
}

#[test]
fn redispatch_to_a_different_server_retries_immediately() {
    // The delay exists because retrying the same endpoint reproduces the same error.
    // A different server has no such implication, so waiting would be pure latency.
    let mut s = session_with(Timeouts::default(), 3);
    assert!(s.server_failed_at(Tick(1000), false));
    assert!(!s.retry_pending(Tick(1000)), "redispatch must not wait");
}

#[test]
fn exhausting_retries_clears_the_delay() {
    let mut s = session_with(Timeouts::default(), 1);
    assert!(s.server_failed_at(Tick(1000), true), "one retry available");
    assert!(!s.server_failed_at(Tick(1000), true), "now exhausted");
    assert!(
        !s.retry_pending(Tick(1000)),
        "a session that has given up must not report a pending retry, or the caller \
         will wait forever for a retry that will never happen"
    );
}
