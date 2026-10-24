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

//!
//! The one exception is a panic in the run of a stream (T447): [`contain`] catches it, the
//! hook only reports it, and the engine closes that stream and serves on
//! (`EngineDispatcher::stream_panicked`, the design in `tasks/T447-progress.md`). That needs
//! unwinding: a build with `panic = "abort"` would turn every contained panic back into an
//! abort, so it does not compile.

use std::cell::Cell;
use std::panic;

#[cfg(panic = "abort")]
compile_error!("Ibex contains a panic in one stream's run with `catch_unwind` (T447): build with `panic = \"unwind\"`");

thread_local! {
    /// This thread is in a stream's run, under [`contain`].
    static CONTAINED: Cell<bool> = const { Cell::new(false) };
}

/// Installs the hook. The first thing `main` does, so that no thread starts without it.
pub fn abort_on_panic() {
    let report = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        report(info);
        if CONTAINED.get() {
            // [`contain`] catches it: the caller says what it closed.
            return;
        }
        crate::stderr_line!("[ALERT] ibex: a thread panicked; this is a bug in Ibex, aborting the process");
        die();
    }));
}

/// Runs `f`, one run of a stream: `Err` if it panicked, the panic reported by the hook and
/// not aborting. On the happy path this costs two thread-local stores; `catch_unwind` itself
/// is free until something unwinds. Not reentrant: nothing it runs calls it again.
pub(crate) fn contain<R>(f: impl FnOnce() -> R) -> Result<R, ()> {
    CONTAINED.set(true);
    let out = panic::catch_unwind(panic::AssertUnwindSafe(f));
    CONTAINED.set(false);
    // The payload (the message) is dropped here; it was printed by the hook.
    out.map_err(drop)
}

/// A panic that could not be contained after all (shared state left half-changed, or the
/// cleanup panicked too): the alert, then [`die`].
pub(crate) fn abort_uncontained(why: &str) -> ! {
    crate::stderr_line!("[ALERT] ibex: a stream panicked and {why}; this is a bug in Ibex, aborting the process");
    die()
}

/// SIGABRT, except in a coverage-instrumented run. An instrumented binary writes its
/// profile from an `atexit` handler, which `abort()` never reaches; `harness/covercheck.py`
/// would then count the code a panicking run executed as executed by no test. That run
/// exits with 134, the status a shell reports for SIGABRT, instead. `LLVM_PROFILE_FILE` is
/// what `cargo llvm-cov` sets; a deployed binary is not instrumented and never sees it.
/// tests/panic_policy.rs sets it too, so that the test suite makes no crash reports.
pub(crate) fn die() -> ! {
    if std::env::var_os("LLVM_PROFILE_FILE").is_some() { std::process::exit(134) } else { std::process::abort() }
}

/// `ibex.debug.panic` (T447): where a stream's run panics, for the tests of [`contain`]. Set
/// with the configuration; the parser refuses the keyword in release builds, which compile
/// [`fault_point`] out.
static FAULT: std::sync::RwLock<Option<ibex_config::ast::DebugPanic>> = std::sync::RwLock::new(None);

/// Installs the configuration's `ibex.debug.panic`, or clears it.
pub(crate) fn set_fault(fault: Option<ibex_config::ast::DebugPanic>) {
    *FAULT.write().unwrap_or_else(std::sync::PoisonError::into_inner) = fault;
}

/// The lock of `ibex.debug.panic` was poisoned: its `request-locked` fault panicked under
/// it, the stand-in for a panic under a shared lock (the stream's panic is then not
/// contained). Never in a release build, where nothing takes the lock in a stream's run.
pub(crate) fn fault_poisoned() -> bool {
    FAULT.is_poisoned()
}

/// Panics if `ibex.debug.panic` names this point of a stream's run: its request head
/// parsed (`at_response` false) or its response head in, with a request path `uri`.
#[cfg(debug_assertions)]
pub(crate) fn fault_point(at_response: bool, uri: Option<&str>) {
    let Some(uri) = uri else { return };
    let fault = FAULT
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .filter(|f| f.at_response == at_response && uri.starts_with(f.path.as_str()))
        .map(|f| f.under_lock);
    let Some(under_lock) = fault else { return };
    let _held = under_lock.then(|| FAULT.write().unwrap_or_else(std::sync::PoisonError::into_inner));
    panic!("ibex.debug.panic: deliberate panic in the stream of {uri}");
}
