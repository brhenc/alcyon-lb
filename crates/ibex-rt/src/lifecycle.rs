// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Process lifecycle: the signals `HAProxy` uses to stop and reload, as flags the run loop
//! observes.
//!
//! `HAProxy`'s standalone mode registers exactly one lifecycle handler, `SIGUSR1`, for the soft
//! stop (`src/haproxy.c:2609`, `sig_soft_stop`). `SIGTERM` and `SIGINT` are left at the
//! default action, which is why `admin/systemd/haproxy.service.in` carries
//! `SuccessExitStatus=143`. Ibex matches that: a handler here is a behaviour change an
//! operator would notice, so there is one only where `HAProxy` has one.
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
        Ok(())
    }

    /// Consumes a pending reload request (`SIGUSR2`), if there is one.
    #[must_use]
    pub fn take_reload_request(&self) -> bool {
        self.reload.swap(false, Ordering::Relaxed)
    }

    /// Whether a soft stop has been requested.
    #[must_use]
    pub fn soft_stop_requested(&self) -> bool {
        self.soft_stop.load(Ordering::Relaxed)
    }
}
