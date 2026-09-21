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
    pub rise_count: u32,
    pub fall_count: u32,
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
        ServerCheckState {
            proxy_idx,
            server_idx,
            addr,
            config,
            status: ServerStatus::Up,
            enabled: true,
            rise_count: 0,
            fall_count: 0,
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

    /// Handles a health check success.
    pub fn on_success(&mut self, duration_ms: u32) {
        self.total_checks += 1;
        self.fall_count = 0;
        self.rise_count += 1;
        self.last_status_desc = "Layer4 check passed";
        self.last_status_code = "L4OK";
        self.check_duration_ms = duration_ms;

        if self.status == ServerStatus::Down && self.rise_count >= self.config.rise {
            self.status = ServerStatus::Up;
        }
    }

    /// Handles a health check failure.
    pub fn on_failure(&mut self, code: &'static str, desc: &'static str, duration_ms: u32) {
        self.total_checks += 1;
        self.failed_checks += 1;
        self.rise_count = 0;
        self.fall_count += 1;
        self.last_status_code = code;
        self.last_status_desc = desc;
        self.check_duration_ms = duration_ms;

        if self.status == ServerStatus::Up && self.fall_count >= self.config.fall {
            self.status = ServerStatus::Down;
            self.down_transitions += 1;
        }
    }

    /// Computes the interval until the next check as a [`Tick`].
    #[must_use]
    pub fn schedule_next(&self, now: Tick) -> Tick {
        #[allow(clippy::cast_possible_truncation)]
        let ms = self.config.inter.as_millis().min(u128::from(u32::MAX)) as u32;
        now.add(ms)
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
) -> io::Result<Option<Tick>> {
    if !check.enabled {
        if check.in_progress {
            cleanup_check_socket(check, fdtab, poller);
        }
        let next = check.schedule_next(now);
        check.next_check = next;
        return Ok(Some(next));
    }

    if check.in_progress {
        // Check is in progress: either timeout or write-readiness
        let duration = now.remaining(check.check_start_tick).unwrap_or(0);
        let timed_out = check.exp.is_expired(now);

        if timed_out {
            cleanup_check_socket(check, fdtab, poller);
            check.on_failure("L4TOUT", "Connection timed out", duration);
            let next = check.schedule_next(now);
            check.next_check = next;
            return Ok(Some(next));
        }

        let Some(raw_fd) = check.check_fd else {
            cleanup_check_socket(check, fdtab, poller);
            let next = check.schedule_next(now);
            return Ok(Some(next));
        };

        let ready = fdtab.ready(raw_fd);
        if !ready.writable && !ready.readable {
            // Still waiting for connect completion
            return Ok(Some(check.exp));
        }

        fdtab.clear_ready(raw_fd, true, true);
        let connect_res = if let Some(sock) = check.sock.as_ref() {
            raw::check_connect_error(sock.as_fd())
        } else {
            Ok(Some(io::Error::from(io::ErrorKind::NotConnected)))
        };

        cleanup_check_socket(check, fdtab, poller);

        match connect_res {
            Ok(None) => {
                check.on_success(duration);
            }
            Ok(Some(_)) | Err(_) => {
                check.on_failure("L4CON", "Connection refused / error", duration);
            }
        }

        let next = check.schedule_next(now);
        check.next_check = next;
        Ok(Some(next))
    } else {
        // Start new check
        check.check_start_tick = now;
        if let Ok((sock, immediate)) = raw::connect(check.addr) {
            if immediate {
                check.on_success(0);
                let next = check.schedule_next(now);
                check.next_check = next;
                return Ok(Some(next));
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
            Ok(Some(check.exp))
        } else {
            check.on_failure("L4CON", "Connection refused / error", 0);
            let next = check.schedule_next(now);
            check.next_check = next;
            Ok(Some(next))
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
