// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T256: an `ibex` a test spawned is stopped when the test panics before its own cleanup.
//! A `common::stop(&mut child)` at the end of the body is skipped by a failed assertion and
//! leaves the daemon running (and, under coverage, without a profile); `common::Ibex` stops
//! it from `Drop`.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static PID: AtomicU32 = AtomicU32::new(0);

fn gone(pid: u32) -> bool {
    let Some(p) = i32::try_from(pid).ok().and_then(rustix::process::Pid::from_raw) else {
        return true;
    };
    rustix::process::test_kill_process(p).is_err()
}

#[test]
fn ibex_is_stopped_when_the_test_panics_after_spawning_it() {
    let fe = common::reserve_addr();
    let mut cfg = tempfile::NamedTempFile::new().expect("tmp");
    write!(cfg, "defaults\n  mode http\n  timeout client 2s\nfrontend f\n  bind {fe}\n  http-request return status 200\n")
        .expect("cfg");
    let path = cfg.path().to_path_buf();
    let r = std::panic::catch_unwind(|| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
            .arg("-f")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(common::Ibex)
            .expect("spawn ibex");
        PID.store(child.id(), Ordering::SeqCst);
        assert!(common::wait_listening(fe), "ibex never listened");
        assert_eq!(1, 2, "the failed assertion a test makes before it reaches stop");
        common::stop(&mut child);
    });
    assert!(r.is_err(), "the closure must have panicked");
    let pid = PID.load(Ordering::SeqCst);
    assert_ne!(pid, 0);
    let deadline = Instant::now() + Duration::from_secs(6);
    while !gone(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let leaked = !gone(pid);
    if leaked {
        // Do not leave the daemon this test just proved leaks.
        if let Some(p) = i32::try_from(pid).ok().and_then(rustix::process::Pid::from_raw) {
            let _ = rustix::process::kill_process(p, rustix::process::Signal::Kill);
        }
    }
    assert!(!leaked, "ibex pid {pid} still running 6 s after the test panicked");
}
