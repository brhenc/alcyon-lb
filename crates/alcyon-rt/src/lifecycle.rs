// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Process lifecycle: the signals `HAProxy` uses to stop and reload, as flags the run loop
//! observes.
//!
//! `HAProxy`'s standalone mode registers exactly one lifecycle handler, `SIGUSR1`, for the soft
//! stop (`src/haproxy.c:2609`, `sig_soft_stop`). `SIGTERM` and `SIGINT` are left at the
//! default action standalone (status 143 and 130); under `-W` the master exits 0 on
//! `SIGTERM` (measured), which Alcyon matches with [`Lifecycle::install_term_handler`].
//! A handler here is a behaviour change an operator would notice, so there is one only
//! where `HAProxy` has one.
//!
//! The handlers set an [`AtomicBool`] and write a byte to a pipe the supervising thread
//! sleeps on ([`Lifecycle::wait`]); that thread wakes every worker ([`Lifecycle::attach_workers`]),
//! whose poller has no timeout while it has no deadline (T659). Everything else happens on the
//! engine's own thread when it next wakes. `signal-hook` is what
//! keeps this free of `unsafe`: the crate forbids it, and a hand-rolled `sigaction` would
//! need it.

use std::io;
use std::os::fd::{IntoRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

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
    /// The self-pipe every handler writes a byte to: what [`Self::wait`] sleeps on, plus one
    /// shared write-end raw fd passed to `signal_hook::low_level::pipe::register_raw` for all
    /// signals (a pipe rather than a socketpair and one shared write fd so the process holds
    /// neither extra `socket:` descriptors nor extra fds past `maxsock`).
    wake: Arc<OnceLock<(OwnedFd, OwnedFd, RawFd)>>,
    /// The workers' mailboxes, woken by [`Self::wait`] when a signal arrived.
    workers: Arc<OnceLock<Arc<crate::mailbox::Mailboxes>>>,
    /// A worker thread ended ([`Self::exit_guard`]).
    worker_exited: Arc<AtomicBool>,
}

/// Wakes the supervising thread when dropped: a worker thread that ended, by return or panic.
#[derive(Debug)]
pub struct ExitGuard(Lifecycle);

impl Drop for ExitGuard {
    fn drop(&mut self) {
        self.0.worker_exited.store(true, Ordering::Relaxed);
        self.0.poke();
    }
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
        let (_, _, sig_fd) = self.wake_pair()?;
        for sig in [
            signal_hook::consts::SIGUSR1,
            signal_hook::consts::SIGUSR2,
            signal_hook::consts::SIGTTOU,
            signal_hook::consts::SIGTTIN,
            signal_hook::consts::SIGQUIT,
        ] {
            signal_hook::low_level::pipe::register_raw(sig, *sig_fd)?;
        }
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
        // nothing (measured): Alcyon's master sets this flag and never reads it.
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

    /// The master's view of `SIGTTOU` and `SIGTTIN`: whether each arrived since the last
    /// call, to relay to the workers (T456). The master pauses nothing of its own.
    #[must_use]
    pub fn take_pause_signals(&self) -> (bool, bool) {
        (self.ttou.swap(false, Ordering::Relaxed), self.ttin.swap(false, Ordering::Relaxed))
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
    /// `HAProxy` dies of `SIGTERM` (status 143) and so does Alcyon: this is only called for
    /// `-W` and `-Ws`.
    ///
    /// # Errors
    /// Propagates a failure to register the handler.
    pub fn install_term_handler(&self) -> io::Result<()> {
        signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&self.terminate))?;
        let (_, _, sig_fd) = self.wake_pair()?;
        signal_hook::low_level::pipe::register_raw(signal_hook::consts::SIGTERM, *sig_fd)?;
        Ok(())
    }

    fn wake_pair(&self) -> io::Result<&(OwnedFd, OwnedFd, RawFd)> {
        if let Some(p) = self.wake.get() {
            return Ok(p);
        }
        let (r, w) = io::pipe()?;
        let (r, w) = (OwnedFd::from(r), OwnedFd::from(w));
        for fd in [&r, &w] {
            let fl = rustix::fs::fcntl_getfl(fd)?;
            rustix::fs::fcntl_setfl(fd, fl | rustix::fs::OFlags::NONBLOCK)?;
        }
        let sig_fd = w.try_clone()?.into_raw_fd();
        Ok(self.wake.get_or_init(|| (r, w, sig_fd)))
    }

    /// Gives [`Self::wait`] the workers to wake when a signal arrives.
    pub fn attach_workers(&self, boxes: &Arc<crate::mailbox::Mailboxes>) {
        let _ = self.workers.set(Arc::clone(boxes));
    }

    /// A guard for a worker thread: when it is dropped, [`Self::wait`] returns and
    /// [`Self::worker_exited`] is true.
    #[must_use]
    pub fn exit_guard(&self) -> ExitGuard {
        ExitGuard(self.clone())
    }

    /// Whether a worker thread has ended.
    #[must_use]
    pub fn worker_exited(&self) -> bool {
        self.worker_exited.load(Ordering::Relaxed)
    }

    fn poke(&self) {
        if let Some((_, w, _)) = self.wake.get() {
            let _ = rustix::io::write(w, &[1]);
        }
    }

    /// Sleeps until a signal arrives, or a worker ends, or `timeout` passes
    /// (`None`: never): the supervising thread's wait, which used to be a 20 ms nap. Wakes the
    /// workers when a signal arrived, so that their pollers need no timeout to see its flag.
    pub fn wait(&self, timeout: Option<Duration>) {
        use rustix::event::{poll, PollFd, PollFlags};
        let Some((r, _, _)) = self.wake.get() else {
            std::thread::sleep(timeout.unwrap_or(Duration::from_millis(20)).min(Duration::from_millis(20)));
            return;
        };
        let mut fds = [PollFd::new(r, PollFlags::IN)];
        let ms = timeout.map_or(-1, |t| i32::try_from(t.as_millis().max(1)).unwrap_or(i32::MAX));
        let _ = poll(&mut fds, ms);
        let mut buf = [0u8; 64];
        let mut woke = false;
        while rustix::io::read(r, &mut buf).is_ok_and(|n| n > 0) {
            woke = true;
        }
        if woke {
            if let Some(boxes) = self.workers.get() {
                boxes.kick_all();
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn wait_without_handlers_naps_at_most_the_timeout() {
        let l = Lifecycle::new();
        let t = Instant::now();
        l.wait(Some(Duration::from_millis(5)));
        assert!(t.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn wait_times_out_and_wakes_on_a_worker_exit_and_kicks_the_workers() {
        let l = Lifecycle::new();
        l.install_signal_handlers().expect("handlers");
        let boxes = crate::mailbox::Mailboxes::new(1).expect("mailboxes");
        l.attach_workers(&boxes);
        assert!(format!("{l:?}").contains("Mailboxes(1)"));
        let t = Instant::now();
        l.wait(Some(Duration::from_millis(30)));
        assert!(t.elapsed() >= Duration::from_millis(25), "returned before its timeout");
        assert!(!l.worker_exited());
        // A worker ending ends an unbounded wait, and wakes the workers' pollers.
        let g = l.exit_guard();
        let h = std::thread::spawn(move || drop(g));
        l.wait(None);
        h.join().expect("join");
        assert!(l.worker_exited());
        let fd = boxes.fd(0);
        let mut fds = [rustix::event::PollFd::new(&fd, rustix::event::PollFlags::IN)];
        assert_eq!(rustix::event::poll(&mut fds, 0).expect("poll"), 1, "the worker was not woken");
    }
}
