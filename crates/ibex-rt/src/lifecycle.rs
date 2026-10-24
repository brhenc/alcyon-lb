// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Process lifecycle: the signals `HAProxy` uses to stop and reload, as flags the run loop
//! observes.
//!
//! `HAProxy`'s standalone mode registers exactly one lifecycle handler, `SIGUSR1`, for the soft
//! stop (`src/haproxy.c:2609`, `sig_soft_stop`). `SIGTERM` and `SIGINT` are left at the
//! default action standalone (status 143 and 130); under `-W` the master exits 0 on
//! `SIGTERM` (measured), which Ibex matches with [`Lifecycle::install_term_handler`].
//! A handler here is a behaviour change an operator would notice, so there is one only
//! where `HAProxy` has one.
//!
//! The handlers only set an [`AtomicBool`]; everything else happens on the engine's own
//! thread when it next wakes, at most one poll timeout (100 ms) later. `signal-hook` is what
//! keeps this free of `unsafe`: the crate forbids it, and a hand-rolled `sigaction` would
//! need it.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Shared stop and reload requests, cloned into every worker.
#[derive(Clone, Debug, Default)]
pub struct Lifecycle {
    soft_stop: Arc<AtomicBool>,
    reload: Arc<AtomicBool>,
    terminate: Arc<AtomicBool>,
    /// Set by `SIGTTOU` (a successor could not bind a name this process holds: let go of
    /// it) and cleared by `SIGTTIN` (the successor gave up: take it back). A level, not an
    /// edge: every worker looks at it.
    paused: Arc<AtomicBool>,
    ttou: Arc<AtomicBool>,
    ttin: Arc<AtomicBool>,
    /// A `SIGTTIN` not yet acted on: an edge, for a resume that failed last time (the
    /// name was still held) and is tried again on the next signal, as `HAProxy`'s
    /// `protocol_resume_all` is (T370).
    resumed: Arc<AtomicBool>,
    /// `SIGQUIT`: run `pool_gc` (`HAProxy`'s `dump`, `src/haproxy.c:951`), an edge.
    flush: Arc<AtomicBool>,
}

impl Lifecycle {
    /// A lifecycle with nothing requested and no handlers installed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs the `SIGUSR1` soft-stop handler.
    ///
    /// # Errors
    /// Propagates a failure to register the handler.
    pub fn install_signal_handlers(&self) -> io::Result<()> {
        signal_hook::flag::register(signal_hook::consts::SIGUSR1, Arc::clone(&self.soft_stop))?;
        // HAProxy ignores SIGUSR2 in standalone mode (`src/haproxy.c:2606`) and reloads on it
        // in master-worker mode; with a handler registered it is never fatal, and the binary
        // acts on it only under `-W` / `-Ws`.
        signal_hook::flag::register(signal_hook::consts::SIGUSR2, Arc::clone(&self.reload))?;
        // HAProxy's pause and resume (`src/haproxy.c`): a new process whose bind finds an
        // address in use sends SIGTTOU to the processes it replaces, and SIGTTIN if it then
        // fails to start. Every listener is paused (T456), QUIC ones excepted.
        // Plain flags: no thread and no self-pipe (a pipe or socketpair is a descriptor the
        // process would hold for nothing).
        signal_hook::flag::register(signal_hook::consts::SIGTTOU, Arc::clone(&self.ttou))?;
        signal_hook::flag::register(signal_hook::consts::SIGTTIN, Arc::clone(&self.ttin))?;
        // SIGQUIT flushes the pool caches and the process goes on (`HAProxy`'s `dump`; `show
        // pools` says "Use SIGQUIT to flush them"). HAProxy's master ignores it and forwards
        // nothing (measured): Ibex's master sets this flag and never reads it.
        signal_hook::flag::register(signal_hook::consts::SIGQUIT, Arc::clone(&self.flush))?;
        Ok(())
    }

    /// Whether the last of `SIGTTOU` and `SIGTTIN` was `SIGTTOU`.
    #[must_use]
    pub fn pause_requested(&self) -> bool {
        if self.ttou.swap(false, Ordering::Relaxed) {
            self.paused.store(true, Ordering::Relaxed);
            // `sig_pause` ends with `pool_gc(NULL)`.
            crate::pool_gc::request();
        }
        if self.ttin.swap(false, Ordering::Relaxed) {
            self.paused.store(false, Ordering::Relaxed);
            self.resumed.store(true, Ordering::Relaxed);
        }
        self.paused.load(Ordering::Relaxed)
    }

    /// Consumes a pending `SIGQUIT`, if there is one: the caller runs `pool_gc`.
    #[must_use]
    pub fn take_flush_request(&self) -> bool {
        self.flush.swap(false, Ordering::Relaxed)
    }

    /// Whether a `SIGTTIN` arrived since the last call (after `pause_requested`, which
    /// records it).
    #[must_use]
    pub fn take_resume(&self) -> bool {
        self.resumed.swap(false, Ordering::Relaxed)
    }

    /// Makes `SIGTERM` a clean, immediate stop that exits 0, as it is for `HAProxy`'s master
    /// under `-W` (the worker dies of it at once, the master reports 143 for it and exits
    /// 0, which is why the stock unit needs no `SuccessExitStatus=143`). Standalone,
    /// `HAProxy` dies of `SIGTERM` (status 143) and so does Ibex: this is only called for
    /// `-W` and `-Ws`.
    ///
    /// # Errors
    /// Propagates a failure to register the handler.
    pub fn install_term_handler(&self) -> io::Result<()> {
        signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&self.terminate))?;
        Ok(())
    }

    /// Whether `SIGTERM` arrived with the handler of [`Self::install_term_handler`] installed.
    #[must_use]
    pub fn term_requested(&self) -> bool {
        self.terminate.load(Ordering::Relaxed)
    }

    /// Consumes a pending reload request (`SIGUSR2`), if there is one.
    #[must_use]
    pub fn take_reload_request(&self) -> bool {
        self.reload.swap(false, Ordering::Relaxed)
    }

    /// Consumes a pending soft-stop request (`SIGUSR1`), if there is one. The master uses
    /// it, because a `reload` can take it out of stopping again.
    #[must_use]
    pub fn take_soft_stop_request(&self) -> bool {
        self.soft_stop.swap(false, Ordering::Relaxed)
    }

    /// Whether a soft stop has been requested.
    #[must_use]
    pub fn soft_stop_requested(&self) -> bool {
        self.soft_stop.load(Ordering::Relaxed)
    }
}
