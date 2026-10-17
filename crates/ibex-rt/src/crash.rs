// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! What a panic does: it takes the whole process down (T238).
//!
//! A panic is a bug, the equivalent of `HAProxy`'s `BUG_ON()`, which aborts the process
//! (SIGABRT, a core where core dumps are enabled). Left to Rust's default, a panic unwinds
//! only the thread it happened on: one worker of N went away with a line on stderr and the
//! process served on with less capacity, and with one worker the process then exited 0, so
//! a service manager's `Restart=on-failure` saw a clean stop and did not restart it.
//!
//! [`abort_on_panic`] keeps the standard message (thread, location, backtrace under
//! `RUST_BACKTRACE`) and then aborts, from whichever thread panicked. Under `-W` the master
//! sees its worker die of SIGABRT, logs `exited with code 134 (Aborted)`, stops every
//! process and exits 134, as `HAProxy`'s does (measured on 3.5-dev8: `kill -ABRT` of the
//! worker, master exit status 134).
//!
//! This is a hook rather than `panic = "abort"` in the Cargo profiles: a profile setting
//! cannot apply to the test builds (the test harness needs unwinding), and the hook behaves
//! the same in every build.

use std::panic;

/// Installs the hook. The first thing `main` does, so that no thread starts without it.
pub fn abort_on_panic() {
    let report = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        report(info);
        crate::stderr_line!("[ALERT] ibex: a thread panicked; this is a bug in Ibex, aborting the process");
        die();
    }));
}

/// SIGABRT, except in a coverage-instrumented run. An instrumented binary writes its
/// profile from an `atexit` handler, which `abort()` never reaches; `harness/covercheck.py`
/// would then count the code a panicking run executed as executed by no test. That run
/// exits with 134, the status a shell reports for SIGABRT, instead. `LLVM_PROFILE_FILE` is
/// what `cargo llvm-cov` sets; a deployed binary is not instrumented and never sees it.
/// tests/panic_policy.rs sets it too, so that the test suite makes no crash reports.
fn die() -> ! {
    if std::env::var_os("LLVM_PROFILE_FILE").is_some() { std::process::exit(134) } else { std::process::abort() }
}
