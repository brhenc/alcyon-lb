// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/check.c, include/haproxy/check.h and src/server.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Health Check engine for backend servers supporting L4 TCP, L7 HTTP, and multi-step TCP checks.
//!
//! Periodic health checks execute as [`ibex_sched::task::Kind::Check`] tasks in the scheduler.
//! When a check fires, connection and protocol transactions are initiated. On check completion
//! or error, the server's health counters (`rise_count`, `fall_count`, `health`) are updated,
//! and server availability transitions between `Up` and `Down`.

use crate::fdtab::{FdState, FdTab, Interest};
use crate::poller::Poller;
use crate::raw::{self, Io};
use ibex_config::ast::{
    get_resolved_check_config, ResolvedCheckConfig, ResolvedHttpCheck, ResolvedTcpStep,
};
use ibex_sched::task::TaskRef;
use ibex_sched::Tick;
use std::fmt::Write as _;
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

impl From<u8> for ServerStatus {
    fn from(v: u8) -> Self {
        match v {
            0 => ServerStatus::Up,
            2 => ServerStatus::Drain,
            3 => ServerStatus::Maint,
            _ => ServerStatus::Down,
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

/// Sub-state for health checks progressing through multiple phases or steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckSubState {
    Idle,
    TcpConnecting,
    HttpConnecting {
        req_buf: Vec<u8>,
        send_offset: usize,
    },
    HttpSending {
        req_buf: Vec<u8>,
        send_offset: usize,
    },
    HttpReceiving {
        recv_buf: Vec<u8>,
    },
    TcpRunning {
        step_idx: usize,
        send_offset: usize,
        recv_buf: Vec<u8>,
    },
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
    /// ends: at `0` the server is DOWN, at `rise + fall - 1` it is fully UP.
    pub health: u32,
    pub in_progress: bool,
    pub sock: Option<OwnedFd>,
    pub check_fd: Option<RawFd>,
    pub exp: Tick,
    pub next_check: Tick,
    pub last_status_desc: &'static str,
    pub last_status_code: &'static str,
    pub http_code: Option<u16>,
    pub last_status_info: Option<String>,
    pub resolved_config: Option<ResolvedCheckConfig>,
    pub sub_state: CheckSubState,
    pub check_duration_ms: u32,
    pub check_start_tick: Tick,
    pub total_checks: u64,
    pub failed_checks: u64,
    pub down_transitions: u64,
    pub task: TaskRef,
}

/// What a completed health check means for logging.
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
        let resolved_config = get_resolved_check_config(proxy_idx, server_idx, addr);
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
            http_code: None,
            last_status_info: None,
            resolved_config,
            sub_state: CheckSubState::Idle,
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
    pub fn on_success(&mut self, duration_ms: u32) -> Option<CheckEvent> {
        self.on_success_full("L4OK", "Layer4 check passed", duration_ms, None, None)
    }

    /// Handles a health check failure.
    pub fn on_failure(
        &mut self,
        code: &'static str,
        desc: &'static str,
        duration_ms: u32,
    ) -> Option<CheckEvent> {
        self.on_failure_full(code, desc, duration_ms, None, None)
    }

    /// Handles a health check success with detailed status code, description, and info.
    pub fn on_success_full(
        &mut self,
        code: &'static str,
        desc: &'static str,
        duration_ms: u32,
        http_code: Option<u16>,
        info: Option<String>,
    ) -> Option<CheckEvent> {
        self.total_checks += 1;
        self.fall_count = 0;
        self.rise_count += 1;
        self.last_status_code = code;
        self.last_status_desc = desc;
        self.http_code = http_code;
        self.last_status_info = info;
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

    /// Handles a health check failure with detailed status code, description, and info.
    pub fn on_failure_full(
        &mut self,
        code: &'static str,
        desc: &'static str,
        duration_ms: u32,
        http_code: Option<u16>,
        info: Option<String>,
    ) -> Option<CheckEvent> {
        self.total_checks += 1;
        self.failed_checks += 1;
        self.rise_count = 0;
        self.fall_count += 1;
        self.last_status_code = code;
        self.last_status_desc = desc;
        self.http_code = http_code;
        self.last_status_info = info;
        self.check_duration_ms = duration_ms;

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
    #[must_use]
    pub fn log_line(&self, backend: &str, server: &str, event: CheckEvent) -> String {
        let verb = match event {
            CheckEvent::Succeeded | CheckEvent::WentUp => "succeeded",
            CheckEvent::Failed | CheckEvent::WentDown => "failed",
        };
        let (count, threshold) = if self.health >= self.config.rise {
            (self.health - self.config.rise + 1, self.config.fall)
        } else {
            (self.health, self.config.rise)
        };

        let mut out = format!(
            "Health check for server {backend}/{server} {verb}, reason: {}",
            self.last_status_desc
        );

        if let Some(code) = self.http_code {
            let _ = write!(out, ", code: {code}");
        }

        if let Some(ref info) = self.last_status_info {
            let _ = write!(out, ", info: \"{info}\"");
        }

        let _ = write!(
            out,
            ", check duration: {}ms, status: {}/{} {}.",
            self.check_duration_ms,
            count,
            threshold,
            self.status.as_str()
        );

        out
    }

    /// Computes the interval until the next check as a [`Tick`].
    #[must_use]
    pub fn schedule_next(&self, now: Tick) -> Tick {
        let ms = u32::try_from(self.config.inter.as_millis()).unwrap_or(u32::MAX);
        now.add(ms)
    }
}

/// The outcome of one step: when to run next, and what happened if anything did.
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

/// Builds the HTTP request payload for a health check.
fn build_http_request_payload(chk: &ResolvedHttpCheck, target_addr: SocketAddr) -> Vec<u8> {
    let mut payload = Vec::new();

    if chk.send_proxy {
        let line = format!(
            "PROXY TCP4 {} {} {} {}\r\n",
            target_addr.ip(),
            target_addr.ip(),
            0,
            target_addr.port()
        );
        payload.extend_from_slice(line.as_bytes());
    }

    let req_line = format!("{} {} {}\r\n", chk.method, chk.uri, chk.version);
    payload.extend_from_slice(req_line.as_bytes());

    let mut has_host = false;
    let mut has_connection = false;
    let mut has_content_length = false;

    for (name, val) in &chk.headers {
        if name.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        if name.eq_ignore_ascii_case("connection") {
            has_connection = true;
        }
        if name.eq_ignore_ascii_case("content-length") {
            has_content_length = true;
        }
        let hdr_line = format!("{name}: {val}\r\n");
        payload.extend_from_slice(hdr_line.as_bytes());
    }

    if !has_host {
        if let Some(ref host) = chk.host {
            let host_line = format!("host: {host}\r\n");
            payload.extend_from_slice(host_line.as_bytes());
        }
    }

    if chk.send_state {
        let state_line = format!(
            "x-haproxy-server-state: UP 1/1; name=srv; qcur=0; srv_port={}\r\n",
            target_addr.port()
        );
        payload.extend_from_slice(state_line.as_bytes());
    }

    if chk.version.eq_ignore_ascii_case("HTTP/1.1") && !has_connection {
        payload.extend_from_slice(b"connection: close\r\n");
    }

    if let Some(ref body) = chk.body {
        if !has_content_length {
            let cl_line = format!("content-length: {}\r\n", body.len());
            payload.extend_from_slice(cl_line.as_bytes());
        }
        payload.extend_from_slice(b"\r\n");
        payload.extend_from_slice(body.as_bytes());
    } else {
        payload.extend_from_slice(b"\r\n");
    }

    payload
}

/// Parses an HTTP status code, headers, and body from received data.
#[allow(clippy::type_complexity)]
fn parse_http_response(buf: &[u8]) -> Option<(u16, Vec<(String, String)>, Vec<u8>)> {
    let header_end = if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        pos + 4
    } else {
        buf.windows(2).position(|w| w == b"\n\n")? + 2
    };

    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = header_str.lines();
    let status_line = lines.next()?;
    let mut parts = status_line.split_whitespace();
    let _proto = parts.next()?;
    let code_str = parts.next()?;
    let status_code = code_str.parse::<u16>().ok()?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, val)) = line.split_once(':') {
            headers.push((name.trim().to_string(), val.trim().to_string()));
        }
    }

    let body = buf[header_end..].to_vec();
    Some((status_code, headers, body))
}

/// Executes or progresses a health check.
///
/// # Errors
///
/// Returns an error if polling or socket operation fails unexpectedly.
#[allow(clippy::too_many_lines)]
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

    if check.resolved_config.is_none() {
        check.resolved_config = get_resolved_check_config(check.proxy_idx, check.server_idx, check.addr);
    }

    if check.in_progress {
        let duration = now.remaining(check.check_start_tick).unwrap_or(0);
        let timed_out = check.exp.is_expired(now);

        if timed_out {
            let (code, desc, info) = match &check.sub_state {
                CheckSubState::TcpConnecting | CheckSubState::HttpConnecting { .. } | CheckSubState::Idle => {
                    ("L4TOUT", "Layer4 timeout", None)
                }
                CheckSubState::HttpSending { .. } | CheckSubState::HttpReceiving { .. } => {
                    ("L7TOUT", "Layer7 timeout", None)
                }
                CheckSubState::TcpRunning { step_idx, .. } => (
                    "L7TOUT",
                    "Layer7 timeout",
                    Some(format!("at step {} of tcp-check", step_idx + 1)),
                ),
            };

            cleanup_check_socket(check, fdtab, poller);
            let event = check.on_failure_full(code, desc, duration, None, info);
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

        match check.sub_state.clone() {
            CheckSubState::TcpConnecting => {
                if !ready.writable && !ready.readable {
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
            }
            CheckSubState::HttpConnecting {
                req_buf,
                send_offset,
            } => {
                if !ready.writable && !ready.readable {
                    return Ok(CheckStep::pending(Some(check.exp)));
                }
                fdtab.clear_ready(raw_fd, true, true);
                let connect_res = if let Some(sock) = check.sock.as_ref() {
                    raw::check_connect_error(sock.as_fd())
                } else {
                    Ok(Some(io::Error::from(io::ErrorKind::NotConnected)))
                };

                if let Ok(None) = connect_res {
                    check.sub_state = CheckSubState::HttpSending {
                        req_buf,
                        send_offset,
                    };
                    progress_http_check(check, fdtab, poller, now, duration)
                } else {
                    cleanup_check_socket(check, fdtab, poller);
                    let event = check.on_failure_full(
                        "L4CON",
                        "Connection refused / error",
                        duration,
                        None,
                        None,
                    );
                    let next = check.schedule_next(now);
                    check.next_check = next;
                    Ok(CheckStep {
                        next: Some(next),
                        event,
                    })
                }
            }
            CheckSubState::HttpSending { .. } | CheckSubState::HttpReceiving { .. } => {
                progress_http_check(check, fdtab, poller, now, duration)
            }
            CheckSubState::TcpRunning { .. } => {
                progress_tcp_check(check, fdtab, poller, now, duration)
            }
            CheckSubState::Idle => {
                cleanup_check_socket(check, fdtab, poller);
                let next = check.schedule_next(now);
                check.next_check = next;
                Ok(CheckStep::pending(Some(next)))
            }
        }
    } else {
        // Start a brand new check
        check.check_start_tick = now;
        check.http_code = None;
        check.last_status_info = None;

        let resolved = check.resolved_config.clone().unwrap_or(ResolvedCheckConfig::TcpConnect);

        match resolved {
            ResolvedCheckConfig::Http(chk) => {
                let target_addr =
                    SocketAddr::new(check.addr.ip(), chk.check_port.unwrap_or(check.addr.port()));
                let payload = build_http_request_payload(&chk, target_addr);

                if let Ok((sock, immediate)) = raw::connect(target_addr) {
                        let raw_fd = sock.as_raw_fd();
                        check.check_fd = Some(raw_fd);
                        let timeout_ms =
                            u32::try_from(check.config.timeout.as_millis()).unwrap_or(u32::MAX);
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
                        let _ = poller.add(
                            sock.as_fd(),
                            u64::try_from(raw_fd).unwrap_or(0),
                            false,
                            true,
                        );
                        check.sock = Some(sock);

                        if immediate {
                            check.sub_state = CheckSubState::HttpSending {
                                req_buf: payload,
                                send_offset: 0,
                            };
                            progress_http_check(check, fdtab, poller, now, 0)
                        } else {
                            check.sub_state = CheckSubState::HttpConnecting {
                                req_buf: payload,
                                send_offset: 0,
                            };
                            Ok(CheckStep::pending(Some(check.exp)))
                        }
                    } else {
                        let event = check.on_failure_full(
                            "L4CON",
                            "Connection refused / error",
                            0,
                            None,
                            None,
                        );
                        let next = check.schedule_next(now);
                        check.next_check = next;
                        Ok(CheckStep {
                            next: Some(next),
                            event,
                        })
                    }
            }
            ResolvedCheckConfig::TcpSteps(steps) => {
                check.sub_state = CheckSubState::TcpRunning {
                    step_idx: 0,
                    send_offset: 0,
                    recv_buf: Vec::new(),
                };
                let timeout_ms =
                    u32::try_from(check.config.timeout.as_millis()).unwrap_or(u32::MAX);
                check.exp = now.add(timeout_ms);
                check.in_progress = true;
                progress_tcp_steps_start(check, &steps, fdtab, poller, now)
            }
            ResolvedCheckConfig::TcpConnect => {
                check.sub_state = CheckSubState::TcpConnecting;
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
                    let timeout_ms =
                        u32::try_from(check.config.timeout.as_millis()).unwrap_or(u32::MAX);
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
                    let _ = poller.add(
                        sock.as_fd(),
                        u64::try_from(raw_fd).unwrap_or(0),
                        false,
                        true,
                    );
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
    }
}

/// Progresses an HTTP check during send or receive phase.
#[allow(clippy::too_many_lines)]
fn progress_http_check(
    check: &mut ServerCheckState,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
    duration: u32,
) -> io::Result<CheckStep> {
    let Some(raw_fd) = check.check_fd else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    let Some(ResolvedCheckConfig::Http(chk)) = check.resolved_config.clone() else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    match check.sub_state.clone() {
        CheckSubState::HttpSending {
            req_buf,
            mut send_offset,
        } => {
            let Some(sock) = check.sock.as_ref() else {
                cleanup_check_socket(check, fdtab, poller);
                let next = check.schedule_next(now);
                return Ok(CheckStep::pending(Some(next)));
            };

            while send_offset < req_buf.len() {
                match raw::send(sock.as_fd(), &req_buf[send_offset..]) {
                    Ok(Io::Done(n)) => {
                        send_offset += n;
                    }
                    Ok(Io::WouldBlock) => {
                        fdtab.clear_ready(raw_fd, false, true);
                        check.sub_state = CheckSubState::HttpSending {
                            req_buf,
                            send_offset,
                        };
                        return Ok(CheckStep::pending(Some(check.exp)));
                    }
                    Ok(Io::Closed | Io::Eof) | Err(_) => {
                        cleanup_check_socket(check, fdtab, poller);
                        let event = check.on_failure_full(
                            "L7RSP",
                            "Connection closed by server",
                            duration,
                            None,
                            None,
                        );
                        let next = check.schedule_next(now);
                        check.next_check = next;
                        return Ok(CheckStep {
                            next: Some(next),
                            event,
                        });
                    }
                }
            }

            fdtab.set_interest(raw_fd, Interest::READ);
            let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), true, false);
            check.sub_state = CheckSubState::HttpReceiving {
                recv_buf: Vec::new(),
            };
            progress_http_check(check, fdtab, poller, now, duration)
        }
        CheckSubState::HttpReceiving { mut recv_buf } => {
            let Some(sock) = check.sock.as_ref() else {
                cleanup_check_socket(check, fdtab, poller);
                let next = check.schedule_next(now);
                return Ok(CheckStep::pending(Some(next)));
            };

            let mut buf = [0u8; 4096];
            loop {
                match raw::recv(sock.as_fd(), &mut buf) {
                    Ok(Io::Done(n)) => {
                        recv_buf.extend_from_slice(&buf[..n]);
                        if let Some((status_code, headers, body)) = parse_http_response(&recv_buf) {
                            check.http_code = Some(status_code);
                            let mut passed = true;
                            for rule in &chk.expect_rules {
                                if !rule.matches(status_code, &headers, &body) {
                                    passed = false;
                                    break;
                                }
                            }

                            cleanup_check_socket(check, fdtab, poller);
                            let event = if passed {
                                check.on_success_full(
                                    "L7OK",
                                    "Layer7 check passed",
                                    duration,
                                    Some(status_code),
                                    None,
                                )
                            } else {
                                let code = if (200..400).contains(&status_code) {
                                    "L7RSP"
                                } else {
                                    "L7STS"
                                };
                                let desc = if code == "L7STS" {
                                    "Layer7 wrong status"
                                } else {
                                    "Layer7 invalid response"
                                };
                                check.on_failure_full(
                                    code,
                                    desc,
                                    duration,
                                    Some(status_code),
                                    None,
                                )
                            };
                            let next = check.schedule_next(now);
                            check.next_check = next;
                            return Ok(CheckStep {
                                next: Some(next),
                                event,
                            });
                        }
                    }
                    Ok(Io::WouldBlock) => {
                        fdtab.clear_ready(raw_fd, true, false);
                        check.sub_state = CheckSubState::HttpReceiving { recv_buf };
                        return Ok(CheckStep::pending(Some(check.exp)));
                    }
                    Ok(Io::Eof) => {
                        cleanup_check_socket(check, fdtab, poller);
                        let event = if let Some((status_code, headers, body)) =
                            parse_http_response(&recv_buf)
                        {
                            check.http_code = Some(status_code);
                            let mut passed = true;
                            for rule in &chk.expect_rules {
                                if !rule.matches(status_code, &headers, &body) {
                                    passed = false;
                                    break;
                                }
                            }
                            if passed {
                                check.on_success_full(
                                    "L7OK",
                                    "Layer7 check passed",
                                    duration,
                                    Some(status_code),
                                    None,
                                )
                            } else {
                                check.on_failure_full(
                                    "L7STS",
                                    "Layer7 wrong status",
                                    duration,
                                    Some(status_code),
                                    None,
                                )
                            }
                        } else {
                            check.on_failure_full(
                                "L7RSP",
                                "Layer7 invalid response",
                                duration,
                                None,
                                None,
                            )
                        };
                        let next = check.schedule_next(now);
                        check.next_check = next;
                        return Ok(CheckStep {
                            next: Some(next),
                            event,
                        });
                    }
                    Ok(Io::Closed) | Err(_) => {
                        cleanup_check_socket(check, fdtab, poller);
                        let event = check.on_failure_full(
                            "L7RSP",
                            "Layer7 invalid response",
                            duration,
                            None,
                            None,
                        );
                        let next = check.schedule_next(now);
                        check.next_check = next;
                        return Ok(CheckStep {
                            next: Some(next),
                            event,
                        });
                    }
                }
            }
        }
        _ => {
            cleanup_check_socket(check, fdtab, poller);
            let next = check.schedule_next(now);
            check.next_check = next;
            Ok(CheckStep::pending(Some(next)))
        }
    }
}

/// Starts execution of TCP multi-step check.
fn progress_tcp_steps_start(
    check: &mut ServerCheckState,
    steps: &[ResolvedTcpStep],
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
) -> io::Result<CheckStep> {
    if steps.is_empty() {
        let event = check.on_success_full("L7OK", "Layer7 check passed", 0, None, None);
        let next = check.schedule_next(now);
        check.next_check = next;
        return Ok(CheckStep {
            next: Some(next),
            event,
        });
    }

    if let ResolvedTcpStep::Connect { port, .. } = &steps[0] {
            let target_addr = SocketAddr::new(check.addr.ip(), port.unwrap_or(check.addr.port()));
            if let Ok((sock, immediate)) = raw::connect(target_addr) {
                    let raw_fd = sock.as_raw_fd();
                    check.check_fd = Some(raw_fd);
                    fdtab.insert(
                        raw_fd,
                        FdState::Conn {
                            task: check.task,
                            conn: 0,
                        },
                        Interest::WRITE,
                    );
                    let _ = poller.add(
                        sock.as_fd(),
                        u64::try_from(raw_fd).unwrap_or(0),
                        false,
                        true,
                    );
                    check.sock = Some(sock);

                    if immediate {
                        check.sub_state = CheckSubState::TcpRunning {
                            step_idx: 1,
                            send_offset: 0,
                            recv_buf: Vec::new(),
                        };
                        progress_tcp_check(check, fdtab, poller, now, 0)
                    } else {
                        check.sub_state = CheckSubState::TcpRunning {
                            step_idx: 0,
                            send_offset: 0,
                            recv_buf: Vec::new(),
                        };
                        Ok(CheckStep::pending(Some(check.exp)))
                    }
                } else {
                    cleanup_check_socket(check, fdtab, poller);
                    let event = check.on_failure_full(
                        "L4CON",
                        "Connection refused / error",
                        0,
                        None,
                        Some(format!("ECONNREFUSED returned by OS at step 1 of tcp-check (connect port {})", target_addr.port())),
                    );
                    let next = check.schedule_next(now);
                    check.next_check = next;
                    Ok(CheckStep {
                        next: Some(next),
                        event,
                    })
                }
        } else {
            check.sub_state = CheckSubState::TcpRunning {
                step_idx: 0,
                send_offset: 0,
                recv_buf: Vec::new(),
            };
            progress_tcp_check(check, fdtab, poller, now, 0)
        }
}

/// Progresses execution through TCP steps.
#[allow(clippy::too_many_lines, clippy::unnecessary_wraps)]
fn progress_tcp_check(
    check: &mut ServerCheckState,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
    duration: u32,
) -> io::Result<CheckStep> {
    let Some(ResolvedCheckConfig::TcpSteps(steps)) = check.resolved_config.clone() else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    let CheckSubState::TcpRunning {
        mut step_idx,
        mut send_offset,
        mut recv_buf,
    } = check.sub_state.clone()
    else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    while step_idx < steps.len() {
        match &steps[step_idx] {
            ResolvedTcpStep::Connect { port, .. } => {
                let target_addr =
                    SocketAddr::new(check.addr.ip(), port.unwrap_or(check.addr.port()));
                if let Some(sock) = check.sock.as_ref() {
                    let raw_fd = sock.as_raw_fd();
                    let ready = fdtab.ready(raw_fd);
                    if !ready.writable && !ready.readable {
                        check.sub_state = CheckSubState::TcpRunning {
                            step_idx,
                            send_offset,
                            recv_buf,
                        };
                        return Ok(CheckStep::pending(Some(check.exp)));
                    }
                    fdtab.clear_ready(raw_fd, true, true);
                    let connect_res = raw::check_connect_error(sock.as_fd());
                    if let Ok(None) = connect_res {
                        step_idx += 1;
                        continue;
                    }
                    
                    cleanup_check_socket(check, fdtab, poller);
                    let event = check.on_failure_full(
                        "L4CON",
                        "Connection refused / error",
                        duration,
                        None,
                        Some(format!("ECONNREFUSED returned by OS at step {} of tcp-check (connect port {})", step_idx + 1, target_addr.port())),
                    );
                    let next = check.schedule_next(now);
                    check.next_check = next;
                    return Ok(CheckStep {
                        next: Some(next),
                        event,
                    });
                }

                // If connecting a new connection mid-check:
                cleanup_check_socket(check, fdtab, poller);
                check.in_progress = true;
                let timeout_ms =
                    u32::try_from(check.config.timeout.as_millis()).unwrap_or(u32::MAX);
                check.exp = now.add(timeout_ms);

                if let Ok((sock, immediate)) = raw::connect(target_addr) {
                        let raw_fd = sock.as_raw_fd();
                        check.check_fd = Some(raw_fd);
                        fdtab.insert(
                            raw_fd,
                            FdState::Conn {
                                task: check.task,
                                conn: 0,
                            },
                            Interest::WRITE,
                        );
                        let _ = poller.add(
                            sock.as_fd(),
                            u64::try_from(raw_fd).unwrap_or(0),
                            false,
                            true,
                        );
                        check.sock = Some(sock);

                        if immediate {
                            step_idx += 1;
                            continue;
                        }
                        check.sub_state = CheckSubState::TcpRunning {
                            step_idx,
                            send_offset,
                            recv_buf,
                        };
                        return Ok(CheckStep::pending(Some(check.exp)));
                }
                
                cleanup_check_socket(check, fdtab, poller);
                let event = check.on_failure_full(
                    "L4CON",
                    "Connection refused / error",
                    duration,
                    None,
                    Some(format!("ECONNREFUSED returned by OS at step {} of tcp-check (connect port {})", step_idx + 1, target_addr.port())),
                );
                let next = check.schedule_next(now);
                check.next_check = next;
                return Ok(CheckStep {
                    next: Some(next),
                    event,
                });
            }
            ResolvedTcpStep::Send(data) => {
                let Some(sock) = check.sock.as_ref() else {
                    cleanup_check_socket(check, fdtab, poller);
                    let event = check.on_failure_full(
                        "L7RSP",
                        "Layer7 invalid response",
                        duration,
                        None,
                        Some(format!("at step {} of tcp-check", step_idx + 1)),
                    );
                    let next = check.schedule_next(now);
                    check.next_check = next;
                    return Ok(CheckStep {
                        next: Some(next),
                        event,
                    });
                };

                let raw_fd = sock.as_raw_fd();
                while send_offset < data.len() {
                    match raw::send(sock.as_fd(), &data[send_offset..]) {
                        Ok(Io::Done(n)) => {
                            send_offset += n;
                        }
                        Ok(Io::WouldBlock) => {
                            fdtab.clear_ready(raw_fd, false, true);
                            check.sub_state = CheckSubState::TcpRunning {
                                step_idx,
                                send_offset,
                                recv_buf,
                            };
                            return Ok(CheckStep::pending(Some(check.exp)));
                        }
                        Ok(Io::Closed | Io::Eof) | Err(_) => {
                            cleanup_check_socket(check, fdtab, poller);
                            let event = check.on_failure_full(
                                "L7RSP",
                                "Layer7 invalid response",
                                duration,
                                None,
                                Some(format!("at step {} of tcp-check", step_idx + 1)),
                            );
                            let next = check.schedule_next(now);
                            check.next_check = next;
                            return Ok(CheckStep {
                                next: Some(next),
                                event,
                            });
                        }
                    }
                }
                send_offset = 0;
                step_idx += 1;
            }
            ResolvedTcpStep::Expect {
                pattern,
                negate,
                min_recv,
                comment: _,
            } => {
                let Some(sock) = check.sock.as_ref() else {
                    cleanup_check_socket(check, fdtab, poller);
                    let event = check.on_failure_full(
                        "L7RSP",
                        "Layer7 invalid response",
                        duration,
                        None,
                        Some(format!("at step {} of tcp-check", step_idx + 1)),
                    );
                    let next = check.schedule_next(now);
                    check.next_check = next;
                    return Ok(CheckStep {
                        next: Some(next),
                        event,
                    });
                };

                let raw_fd = sock.as_raw_fd();
                fdtab.set_interest(raw_fd, Interest::READ);
                let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), true, false);

                let mut buf = [0u8; 4096];
                let mut eof = false;

                loop {
                    match raw::recv(sock.as_fd(), &mut buf) {
                        Ok(Io::Done(n)) => {
                            recv_buf.extend_from_slice(&buf[..n]);
                        }
                        Ok(Io::WouldBlock) => {
                            break;
                        }
                        Ok(Io::Eof | Io::Closed) | Err(_) => {
                            eof = true;
                            break;
                        }
                    }
                }

                if recv_buf.len() < *min_recv && !eof {
                    fdtab.clear_ready(raw_fd, true, false);
                    check.sub_state = CheckSubState::TcpRunning {
                        step_idx,
                        send_offset,
                        recv_buf,
                    };
                    return Ok(CheckStep::pending(Some(check.exp)));
                }

                let matches_pattern = pattern.matches(&recv_buf);
                let passed = if *negate {
                    !matches_pattern && (recv_buf.len() >= *min_recv || eof)
                } else {
                    matches_pattern
                };

                if passed {
                    recv_buf.clear();
                    step_idx += 1;
                } else if !eof && !*negate {
                    fdtab.clear_ready(raw_fd, true, false);
                    check.sub_state = CheckSubState::TcpRunning {
                        step_idx,
                        send_offset,
                        recv_buf,
                    };
                    return Ok(CheckStep::pending(Some(check.exp)));
                } else {
                    cleanup_check_socket(check, fdtab, poller);
                    let (code, desc) = if *negate {
                        ("L7STS", "Layer7 wrong status")
                    } else {
                        ("L7RSP", "Layer7 invalid response")
                    };
                    let event = check.on_failure_full(
                        code,
                        desc,
                        duration,
                        None,
                        Some(format!("at step {} of tcp-check", step_idx + 1)),
                    );
                    let next = check.schedule_next(now);
                    check.next_check = next;
                    return Ok(CheckStep {
                        next: Some(next),
                        event,
                    });
                }
            }
            ResolvedTcpStep::Comment(_) => {
                step_idx += 1;
            }
        }
    }

    // All steps completed successfully!
    cleanup_check_socket(check, fdtab, poller);
    let code = if steps.len() == 1 && matches!(steps[0], ResolvedTcpStep::Connect { .. }) {
        "L4OK"
    } else {
        "L7OK"
    };
    let desc = if code == "L4OK" {
        "Layer4 check passed"
    } else {
        "Layer7 check passed"
    };
    let event = check.on_success_full(code, desc, duration, None, None);
    let next = check.schedule_next(now);
    check.next_check = next;
    Ok(CheckStep {
        next: Some(next),
        event,
    })
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
    check.sub_state = CheckSubState::Idle;
}
