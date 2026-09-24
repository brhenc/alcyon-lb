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
        Ok(())
    }

    /// Requests a soft stop, as `SIGUSR1` would.
    pub fn request_soft_stop(&self) {
        self.soft_stop.store(true, Ordering::Relaxed);
    }

    /// Whether a soft stop has been requested.
    #[must_use]
    pub fn soft_stop_requested(&self) -> bool {
        self.soft_stop.load(Ordering::Relaxed)
    }
}
