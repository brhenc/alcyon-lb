// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/check.c, include/haproxy/check.h and src/server.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! TCP Health Check engine for backend servers.
//!
//! Periodic health checks execute as [`ibex_sched::task::Kind::Check`] tasks in the scheduler.
//! When a check fires, a non-blocking TCP connection is initiated. On connect completion
//! or error, the server's health counters (`rise_count`, `fall_count`) are updated, and
//! server availability transitions between `Up` and `Down`.

use crate::fdtab::{FdState, FdTab, Interest};
use crate::poller::Poller;
use crate::raw;
use ibex_sched::task::TaskRef;
use ibex_sched::Tick;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::time::Duration;

/// Availability state of a backend server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerStatus {
    /// Server is active and accepting connections.
    Up,
    /// Server is down due to consecutive health check failures.
    Down,
    /// Server is draining existing connections.
    Drain,
    /// Server is in maintenance mode.
    Maint,
}

impl ServerStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ServerStatus::Up => "UP",
            ServerStatus::Down => "DOWN",
            ServerStatus::Drain => "DRAIN",
            ServerStatus::Maint => "MAINT",
        }
    }
}

/// Health check configuration parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCheckConfig {
    /// Time between consecutive health checks.
    pub inter: Duration,
    /// Consecutive successful checks required to transition from `Down` to `Up`.
    pub rise: u32,
    /// Consecutive failed checks required to transition from `Up` to `Down`.
    pub fall: u32,
    /// Timeout for an individual health check connection attempt.
    pub timeout: Duration,
}

impl Default for ServerCheckConfig {
    fn default() -> Self {
        ServerCheckConfig {
            inter: Duration::from_millis(2000),
            rise: 2,
            fall: 3,
            timeout: Duration::from_millis(2000),
        }
    }
}

/// Dynamic health check runtime state for a backend server.
#[derive(Debug)]
pub struct ServerCheckState {
    pub proxy_idx: usize,
    pub server_idx: usize,
    pub addr: SocketAddr,
    pub config: ServerCheckConfig,
    pub status: ServerStatus,
    pub enabled: bool,
    /// Consecutive successes and failures, kept for the stats page's "pass N"/"fails N".
    pub rise_count: u32,
    pub fall_count: u32,
    /// `HAProxy`'s single health counter, in `0 ..= rise + fall - 1` (`src/check.c`).
    ///
    /// A failure decrements it and a success increments it, and it saturates at both
    /// ends: at `0` the server is DOWN, at `rise + fall - 1` it is fully UP. Saturation
    /// is what stops a permanently dead server from reporting a result on every check --
    /// with two separate counters that only ever climbed, a 100ms interval logged ten
    /// lines a second per server, forever.
    ///
    /// `health >= rise` means UP. It starts at `rise` (`src/server.c:937`), so a server
    /// that has only just been configured goes DOWN on its first failed check, while one
    /// that has reached full health takes `fall` of them.
    pub health: u32,
    pub in_progress: bool,
    pub sock: Option<OwnedFd>,
    pub check_fd: Option<RawFd>,
    pub exp: Tick,
    pub next_check: Tick,
    pub last_status_desc: &'static str,
    pub last_status_code: &'static str,
    pub check_duration_ms: u32,
    pub check_start_tick: Tick,
    pub total_checks: u64,
    pub failed_checks: u64,
    pub down_transitions: u64,
    pub task: TaskRef,
}

/// What a completed health check means for logging.
///
/// `HAProxy` logs every check when `option log-health-checks` is set, but logs a status
/// *transition* unconditionally -- a server going down is news whether or not per-check
/// logging is on.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CheckEvent {
    /// Check passed, server already up.
    Succeeded,
    /// Check failed, server still up (below the fall threshold).
    Failed,
    /// Server transitioned Down -> Up.
    WentUp,
    /// Server transitioned Up -> Down.
    WentDown,
}

impl CheckEvent {
    /// True for events that are logged regardless of `option log-health-checks`.
    #[must_use]
    pub const fn is_transition(self) -> bool {
        matches!(self, CheckEvent::WentUp | CheckEvent::WentDown)
    }
}


impl ServerCheckState {
    /// Creates a new health check state for a server.
    #[must_use]
    pub fn new(
        proxy_idx: usize,
        server_idx: usize,
        addr: SocketAddr,
        config: ServerCheckConfig,
        now: Tick,
    ) -> Self {
        let config_rise = config.rise;
        ServerCheckState {
            proxy_idx,
            server_idx,
            addr,
            config,
            status: ServerStatus::Up,
            enabled: true,
            rise_count: 0,
            fall_count: 0,
            health: config_rise,
            in_progress: false,
            sock: None,
            check_fd: None,
            exp: Tick::ETERNITY,
            next_check: now,
            last_status_desc: "Initial state",
            last_status_code: "L4OK",
            check_duration_ms: 0,
            check_start_tick: now,
            total_checks: 0,
            failed_checks: 0,
            down_transitions: 0,
            task: TaskRef::NONE,
        }
    }

    /// The ceiling of the health counter: fully healthy.
    const fn full_health(&self) -> u32 {
        self.config.rise + self.config.fall - 1
    }

    /// Handles a health check success.
    ///
    /// Returns `None` when the result changed nothing -- an already-healthy server
    /// passing another check. `HAProxy` calls this `report`, and uses it to decide
    /// whether the check is worth logging at all.
    pub fn on_success(&mut self, duration_ms: u32) -> Option<CheckEvent> {
        self.total_checks += 1;
        self.fall_count = 0;
        self.rise_count += 1;
        self.last_status_desc = "Layer4 check passed";
        self.last_status_code = "L4OK";
        self.check_duration_ms = duration_ms;

        if self.health >= self.full_health() {
            return None;
        }
        self.health += 1;
        if self.health >= self.config.rise {
            self.health = self.full_health();
            if self.status == ServerStatus::Down {
                self.status = ServerStatus::Up;
                return Some(CheckEvent::WentUp);
            }
        }
        Some(CheckEvent::Succeeded)
    }

    /// Handles a health check failure.
    pub fn on_failure(
        &mut self,
        code: &'static str,
        desc: &'static str,
        duration_ms: u32,
    ) -> Option<CheckEvent> {
        self.total_checks += 1;
        self.failed_checks += 1;
        self.rise_count = 0;
        self.fall_count += 1;
        self.last_status_code = code;
        self.last_status_desc = desc;
        self.check_duration_ms = duration_ms;

        // Already at the floor: the server is down and staying down, and repeating that
        // on every check is what floods a collector.
        if self.health == 0 {
            return None;
        }
        self.health -= 1;
        if self.health < self.config.rise {
            self.health = 0;
            if self.status == ServerStatus::Up {
                self.status = ServerStatus::Down;
                self.down_transitions += 1;
                return Some(CheckEvent::WentDown);
            }
        }
        Some(CheckEvent::Failed)
    }

    /// Formats the check result as `HAProxy` does.
    ///
    /// The shape is fixed by what consumers match on -- the reg-tests assert against it
    /// with regexes, and operators grep it:
    ///
    /// ```text
    /// Health check for server be1/srv1 succeeded, reason: Layer4 check passed,
    /// check duration: 0ms, status: 1/1 UP.
    /// ```
    ///
    /// The `status:` field is `<successful checks>/<threshold> <state>`, which is how
    /// an operator sees a flapping server climbing toward its rise threshold.
    #[must_use]
    pub fn log_line(&self, backend: &str, server: &str, event: CheckEvent) -> String {
        let verb = match event {
            CheckEvent::Succeeded | CheckEvent::WentUp => "succeeded",
            CheckEvent::Failed | CheckEvent::WentDown => "failed",
        };
        // src/check.c: the numerator counts up from the rise threshold while healthy,
        // and is the raw health while not. Both are bounded by the counter, so neither
        // can run away past its own denominator the way two free counters did.
        let (count, threshold) = if self.health >= self.config.rise {
            (self.health - self.config.rise + 1, self.config.fall)
        } else {
            (self.health, self.config.rise)
        };
        format!(
            // The trailing period is HAProxy's: src/check.c sends this through
            // `send_log(s->proxy, LOG_NOTICE, "%s.\n", trash.area)`. Operators grep
            // these lines and reg-tests match them, so the punctuation is part of the
            // interface, not decoration.
            "Health check for server {backend}/{server} {verb}, reason: {}, \
             check duration: {}ms, status: {}/{} {}.",
            self.last_status_desc,
            self.check_duration_ms,
            count,
            threshold,
            self.status.as_str()
        )
    }

    /// Computes the interval until the next check as a [`Tick`].
    #[must_use]
    pub fn schedule_next(&self, now: Tick) -> Tick {
        #[allow(clippy::cast_possible_truncation)]
        let ms = self.config.inter.as_millis().min(u128::from(u32::MAX)) as u32;
        now.add(ms)
    }
}

/// The outcome of one step: when to run next, and what happened if anything did.
///
/// The event used to be discarded here -- `on_success`/`on_failure` return a
/// [`CheckEvent`] and the call sites below dropped it -- so nothing downstream could
/// know a server had gone down, and no check was ever logged.
pub struct CheckStep {
    /// When this check should next run, if it should.
    pub next: Option<Tick>,
    /// Set when this step produced a result. `None` while a check is still in flight.
    pub event: Option<CheckEvent>,
}

impl CheckStep {
    const fn pending(next: Option<Tick>) -> Self {
        Self { next, event: None }
    }
}

/// Executes or progresses a health check.
///
/// # Errors
///
/// Returns an error if polling or socket operation fails unexpectedly.
pub fn step_check(
    check: &mut ServerCheckState,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
) -> io::Result<CheckStep> {
    if !check.enabled {
        if check.in_progress {
            cleanup_check_socket(check, fdtab, poller);
        }
        let next = check.schedule_next(now);
        check.next_check = next;
        return Ok(CheckStep::pending(Some(next)));
    }

    if check.in_progress {
        // Check is in progress: either timeout or write-readiness
        let duration = now.remaining(check.check_start_tick).unwrap_or(0);
        let timed_out = check.exp.is_expired(now);

        if timed_out {
            cleanup_check_socket(check, fdtab, poller);
            let event = check.on_failure("L4TOUT", "Connection timed out", duration);
            let next = check.schedule_next(now);
            check.next_check = next;
            return Ok(CheckStep {
                next: Some(next),
                event,
            });
        }

        let Some(raw_fd) = check.check_fd else {
            cleanup_check_socket(check, fdtab, poller);
            let next = check.schedule_next(now);
            return Ok(CheckStep::pending(Some(next)));
        };

        let ready = fdtab.ready(raw_fd);
        if !ready.writable && !ready.readable {
            // Still waiting for connect completion
            return Ok(CheckStep::pending(Some(check.exp)));
        }

        fdtab.clear_ready(raw_fd, true, true);
        let connect_res = if let Some(sock) = check.sock.as_ref() {
            raw::check_connect_error(sock.as_fd())
        } else {
            Ok(Some(io::Error::from(io::ErrorKind::NotConnected)))
        };

        cleanup_check_socket(check, fdtab, poller);

        let event = match connect_res {
            Ok(None) => check.on_success(duration),
            Ok(Some(_)) | Err(_) => {
                check.on_failure("L4CON", "Connection refused / error", duration)
            }
        };

        let next = check.schedule_next(now);
        check.next_check = next;
        Ok(CheckStep {
            next: Some(next),
            event,
        })
    } else {
        // Start new check
        check.check_start_tick = now;
        if let Ok((sock, immediate)) = raw::connect(check.addr) {
            if immediate {
                let event = check.on_success(0);
                let next = check.schedule_next(now);
                check.next_check = next;
                return Ok(CheckStep {
                    next: Some(next),
                    event,
                });
            }
            let raw_fd = sock.as_raw_fd();
            check.check_fd = Some(raw_fd);
            #[allow(clippy::cast_possible_truncation)]
            let timeout_ms = check.config.timeout.as_millis().min(u128::from(u32::MAX)) as u32;
            check.exp = now.add(timeout_ms);
            check.in_progress = true;

            fdtab.insert(
                raw_fd,
                FdState::Conn {
                    task: check.task,
                    conn: 0,
                },
                Interest::WRITE,
            );
            #[allow(clippy::cast_sign_loss)]
            let _ = poller.add(sock.as_fd(), raw_fd as u64, false, true);
            check.sock = Some(sock);
            Ok(CheckStep::pending(Some(check.exp)))
        } else {
            let event = check.on_failure("L4CON", "Connection refused / error", 0);
            let next = check.schedule_next(now);
            check.next_check = next;
            Ok(CheckStep {
                next: Some(next),
                event,
            })
        }
    }
}

/// Cleans up any open sockets or poller registrations for a check in progress.
pub fn cleanup_check_socket(check: &mut ServerCheckState, fdtab: &mut FdTab, poller: &mut Poller) {
    if let Some(sock) = check.sock.take() {
        let _ = poller.delete(sock.as_fd());
    }
    if let Some(raw_fd) = check.check_fd.take() {
        fdtab.remove(raw_fd);
    }
    check.in_progress = false;
    check.exp = Tick::ETERNITY;
}
