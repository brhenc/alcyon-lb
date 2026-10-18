// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/check.c, include/haproxy/check.h and src/server.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Health Check engine for backend servers supporting L4 TCP, L7 HTTP, and multi-step TCP checks.
//!
//! Periodic health checks execute as [`ibex_sched::task::Kind::Check`] tasks in the scheduler.
//! When a check fires, connection and protocol transactions are initiated. On check completion
//! or error, the server's health counters (`rise_count`, `fall_count`, `health`) are updated,
//! and server availability transitions between `Up` and `Down`.

use crate::check_reply;
use crate::engine::Proxy;
use crate::fdtab::{FdState, FdTab, Interest};
use crate::logfmt::{LogData, LogFormat};
use crate::proxy_state::{total_weight, ProxiesView};
use crate::poller::Poller;
use crate::raw::{self, Io};
use crate::srv_tls::CheckTls;
use crate::xprt::ServerXprt;
use std::sync::Arc;
use ibex_config::ast::{
    get_resolved_check_config, HttpCheckExpectPattern, MatchType, MysqlCheckVersion, ResolvedCheckConfig,
    ResolvedHttpCheck, ResolvedHttpExpectRule, ResolvedHttpRule, ResolvedTcpExpectPattern, ResolvedTcpStep,
};
use ibex_sched::task::TaskRef;
use ibex_sched::Tick;
use std::fmt::Write as _;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::Ordering;
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

/// The value of `Proxy::server_statuses` for a server the operator drains and the checks
/// found dead: [`ServerStatus::from`] reads it as `Down` (it takes no traffic, `show stat`
/// prints `DOWN`), and `show servers state` still prints the drain (`srv_admin_state` 8).
/// `HAProxy` keeps the two apart as `srv->cur_admin` and `srv->cur_state`.
pub const DRAIN_DOWN: u8 = 4;

/// The state of a server that is `cur` (a `Proxy::server_statuses` value) once the operator
/// sets its admin state to `to` (`Up` for `ready`, `Drain` or `Maint`), for a server with no
/// check of its own: leaving maintenance starts it running, as `_srv_update_status_adm`
/// does; otherwise a stopped server stays stopped and a running one stays running.
#[must_use]
pub fn admin_transition(cur: u8, to: ServerStatus) -> u8 {
    let cur_st = ServerStatus::from(cur);
    match to {
        ServerStatus::Maint => ServerStatus::Maint as u8,
        _ if cur_st == ServerStatus::Maint => to as u8,
        ServerStatus::Drain if cur_st == ServerStatus::Down => DRAIN_DOWN,
        _ if cur_st == ServerStatus::Down => ServerStatus::Down as u8,
        _ => to as u8,
    }
}

/// The state of a server that is `cur` once `set server health up|down` moves its
/// operational state: maintenance is kept, a drain is kept.
#[must_use]
pub fn health_transition(cur: u8, up: bool) -> u8 {
    let drain = cur == DRAIN_DOWN || cur == ServerStatus::Drain as u8;
    match ServerStatus::from(cur) {
        ServerStatus::Maint => cur,
        _ if up && drain => ServerStatus::Drain as u8,
        _ if up => ServerStatus::Up as u8,
        _ if drain => DRAIN_DOWN,
        _ => ServerStatus::Down as u8,
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
    /// `fastinter` in ms: the interval while the server is changing state; 0 is `inter`, as in
    /// `srv_getinter()`.
    pub fastinter_ms: u32,
    /// `downinter` in ms: the interval while the server is down; 0 is `inter`.
    pub downinter_ms: u32,
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
            fastinter_ms: 0,
            downinter_ms: 0,
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
    ProtoConnecting {
        target_addr: SocketAddr,
    },
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
    RedisRunning {
        phase: u8,
        send_offset: usize,
        recv_buf: Vec<u8>,
    },
    SmtpRunning {
        phase: u8,
        cmd: String,
        send_offset: usize,
        recv_buf: Vec<u8>,
    },
    LdapRunning {
        phase: u8,
        send_offset: usize,
        recv_buf: Vec<u8>,
    },
    MysqlRunning {
        phase: u8,
        user: Option<String>,
        version: MysqlCheckVersion,
        send_offset: usize,
        req_buf: Vec<u8>,
        recv_buf: Vec<u8>,
    },
    PgsqlRunning {
        phase: u8,
        user: String,
        send_offset: usize,
        req_buf: Vec<u8>,
        recv_buf: Vec<u8>,
    },
    SslHelloRunning {
        phase: u8,
        send_offset: usize,
        recv_buf: Vec<u8>,
    },
}

/// Dynamic health check runtime state for a backend server.
#[derive(Debug)]
pub struct ServerCheckState {
    /// The proxy and server indexes, `u32` as everywhere a server is named (T304).
    pub proxy_idx: u32,
    pub server_idx: u32,
    pub addr: SocketAddr,
    /// The check parameters: one copy per distinct server line, shared by every server of
    /// the backend that has the same (`Proxy::server_check_configs`, T304).
    pub config: Arc<ServerCheckConfig>,
    /// What the server is: the operator's admin state combined with the checks' verdict.
    /// `Down` under a drain is the server the checks found dead ([`Self::published`]).
    pub status: ServerStatus,
    /// The operator's admin state alone (`cur_admin`): `Up` for ready, `Drain` or `Maint`.
    pub admin: ServerStatus,
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
    /// The transport over `sock`: plaintext, or the TLS of `tls` (T113).
    pub xprt: ServerXprt,
    /// The protocol state of the check in progress (T304): held only while
    /// a check runs, from a per-thread pool.
    pub run: CheckRunSlot,
    /// The server line's check TLS (`check-ssl`, or `ssl` inherited), `None` for plaintext.
    pub tls: Option<Arc<CheckTls>>,
    pub exp: Tick,
    pub next_check: Tick,
    pub last_status_desc: &'static str,
    pub last_status_code: &'static str,
    pub http_code: Option<u16>,
    /// Boxed, not a `String`: one is held per checked server (T304).
    pub last_status_info: Option<Box<str>>,
    /// The backend's resolved check, shared by its servers (T304).
    pub resolved_config: Option<Arc<ResolvedCheckConfig>>,
    /// The `http-check send` log-formats, compiled once from `resolved_config` and shared
    /// with the servers that share it.
    pub http_send: Option<Arc<HttpSendFormats>>,
    pub check_duration_ms: u32,
    pub total_checks: u64,
    pub failed_checks: u64,
    pub down_transitions: u64,
    pub task: TaskRef,
}

/// The state of one check while it runs: where the protocol is, and its variables. A server
/// between two checks holds none of it ([`CheckRunSlot`]).
#[derive(Debug)]
pub struct CheckRun {
    /// The `tcp-check connect` step (after the first) whose connection is being opened:
    /// while it is set, the socket in `sock` is that step's, not the previous step's.
    pub tcp_connect_step: Option<usize>,
    pub check_fd: Option<RawFd>,
    pub sub_state: CheckSubState,
    /// The check's variables (`http-check set-var`, scope `check`), for the run in progress.
    pub vars: ibex_sample::VarStore,
    /// When the check started, for its duration.
    pub start_tick: Tick,
}

impl CheckRun {
    fn idle() -> Self {
        CheckRun {
            tcp_connect_step: None,
            check_fd: None,
            sub_state: CheckSubState::Idle,
            vars: ibex_sample::VarStore::new(),
            start_tick: Tick(0),
        }
    }
}

thread_local! {
    /// The runs of finished checks, for the next ones: a check takes one when it starts
    /// and gives it back when it ends ([`cleanup_check_socket`]), so after the first round
    /// a check allocates nothing for it, and only as many exist as checks ever ran at once
    /// on this thread (`HAProxy` allocates a check's buffers when it runs, likewise).
    static RUN_POOL: std::cell::RefCell<Vec<Box<CheckRun>>> = const { std::cell::RefCell::new(Vec::new()) };
    /// What a server reads of a check that is not running.
    static IDLE_RUN: &'static CheckRun = Box::leak(Box::new(CheckRun::idle()));
}

/// A server's [`CheckRun`]: none between checks (T304: 60,000 servers paid ~170 bytes each
/// for state that only the few checks in flight use). Reading it between checks reads an
/// idle run; writing to it takes one from the pool.
#[derive(Debug, Default)]
pub struct CheckRunSlot(Option<Box<CheckRun>>);

impl CheckRunSlot {
    /// Ends the run: the state goes back to the pool, reset.
    fn release(&mut self) {
        if let Some(mut run) = self.0.take() {
            run.vars.clear();
            run.sub_state = CheckSubState::Idle;
            run.tcp_connect_step = None;
            run.check_fd = None;
            RUN_POOL.with(|p| p.borrow_mut().push(run));
        }
    }

    /// Whether a check holds a run (a test hook: the pool is the only other owner).
    #[must_use]
    pub const fn is_held(&self) -> bool {
        self.0.is_some()
    }
}

impl std::ops::Deref for CheckRunSlot {
    type Target = CheckRun;
    fn deref(&self) -> &CheckRun {
        match &self.0 {
            Some(run) => run,
            None => IDLE_RUN.with(|r| *r),
        }
    }
}

impl std::ops::DerefMut for CheckRunSlot {
    fn deref_mut(&mut self) -> &mut CheckRun {
        self.0.get_or_insert_with(|| RUN_POOL.with(|p| p.borrow_mut().pop()).unwrap_or_else(|| Box::new(CheckRun::idle())))
    }
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
        config: impl Into<Arc<ServerCheckConfig>>,
        now: Tick,
    ) -> Self {
        let resolved_config = get_resolved_check_config(proxy_idx, server_idx, addr);
        let http_send = HttpSendFormats::shared_for(resolved_config.as_ref());
        ServerCheckState {
            proxy_idx: crate::engine::usize_to_u32(proxy_idx),
            server_idx: crate::engine::usize_to_u32(server_idx),
            addr,
            config: config.into(),
            status: ServerStatus::Up,
            admin: ServerStatus::Up,
            enabled: true,
            rise_count: 0,
            fall_count: 0,
            // A new server runs with its counter at zero, as `HAProxy` allocates it: the
            // first successes climb to `rise` and a failure before that takes it down.
            health: 0,
            in_progress: false,
            sock: None,
            xprt: ServerXprt::Plain,
            run: CheckRunSlot::default(),
            tls: None,
            exp: Tick::ETERNITY,
            next_check: now,
            last_status_desc: "Initializing",
            // HAProxy seeds this with HCHK_STATUS_INI ("Initializing"), a placeholder that
            // matches no real check result code, so the first real outcome always differs
            // from it and `report = (status != prev_status)` (src/check.c) is always true.
            // "L4OK" here (a real success code) made the very first successful check
            // indistinguishable from this placeholder, silently dropping the "succeeded ...
            // status: 1/1 UP" log line a fresh, already-healthy server should always emit.
            last_status_code: "INI",
            http_code: None,
            last_status_info: None,
            resolved_config,
            http_send,
            check_duration_ms: 0,
            total_checks: 0,
            failed_checks: 0,
            down_transitions: 0,
            task: TaskRef::NONE,
        }
    }

    /// The index of the server's proxy in the worker's proxies.
    #[must_use]
    #[inline]
    pub const fn proxy(&self) -> usize {
        self.proxy_idx as usize
    }

    /// The index of the server in its proxy.
    #[must_use]
    #[inline]
    pub const fn server(&self) -> usize {
        self.server_idx as usize
    }

    /// The ceiling of the health counter: fully healthy.
    fn full_health(&self) -> u32 {
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
        // HAProxy opens set_server_check_status() with
        //
        //     int report = (status != prev_status) ? 1 : 0;
        //
        // (src/check.c) and the health-counter branches below it can only raise `report`,
        // never clear it. A result whose status code differs from the previous one is
        // therefore always reported, even when the counter is pinned at full health --
        // which is what makes the first check after boot loggable under
        // `option log-health-checks`.
        let status_changed = self.last_status_code != code;
        self.last_status_code = code;
        self.last_status_desc = desc;
        self.http_code = http_code;
        self.last_status_info = info.map(|i| cut_check_desc(i).into_boxed_str());
        self.check_duration_ms = duration_ms;

        if self.health >= self.full_health() {
            return if status_changed {
                Some(CheckEvent::Succeeded)
            } else {
                None
            };
        }
        self.health += 1;
        if self.health >= self.config.rise {
            self.health = self.full_health();
            if self.status == ServerStatus::Down {
                self.status = self.running();
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
        // See on_success_full: the status-code change is HAProxy's first reporting term.
        let status_changed = self.last_status_code != code;
        self.last_status_code = code;
        self.last_status_desc = desc;
        self.http_code = http_code;
        self.last_status_info = info.map(|i| cut_check_desc(i).into_boxed_str());
        self.check_duration_ms = duration_ms;

        if self.health == 0 {
            // `check_notify_failure`: a running server whose counter is already at zero (a
            // new one) goes down on its first failure.
            if matches!(self.status, ServerStatus::Up | ServerStatus::Drain) {
                self.status = ServerStatus::Down;
                self.down_transitions += 1;
                return Some(CheckEvent::WentDown);
            }
            return if status_changed {
                Some(CheckEvent::Failed)
            } else {
                None
            };
        }
        self.health -= 1;
        if self.health < self.config.rise {
            self.health = 0;
            if matches!(self.status, ServerStatus::Up | ServerStatus::Drain) {
                self.status = ServerStatus::Down;
                self.down_transitions += 1;
                return Some(CheckEvent::WentDown);
            }
        }
        Some(CheckEvent::Failed)
    }

    /// The running state under the operator's admin state: `Drain` or `Up`.
    const fn running(&self) -> ServerStatus {
        if matches!(self.admin, ServerStatus::Drain) { ServerStatus::Drain } else { ServerStatus::Up }
    }

    /// An operator's `disable server`, `enable server` or `set server state`: entering
    /// maintenance zeroes the counter, leaving it restores `rise` and starts the server
    /// running (`_srv_update_status_adm`, `src/server.c`). `ready` and `drain` otherwise move
    /// the admin state only: a server the checks found dead stays down (measured).
    pub fn set_admin_status(&mut self, to: ServerStatus) {
        self.admin = to;
        if to == ServerStatus::Maint {
            if self.status != ServerStatus::Maint {
                self.health = 0;
            }
            self.status = ServerStatus::Maint;
        } else if self.status == ServerStatus::Maint {
            self.health = self.config.rise;
            self.status = self.running();
        } else if self.status != ServerStatus::Down {
            self.status = self.running();
        }
    }

    /// `set server health up|down`: the counter goes to full health or zero, and the
    /// operational state follows unless the server is in maintenance (measured: `MAINT`
    /// stays, the counter moves).
    pub fn set_health(&mut self, up: bool) {
        self.health = if up { self.full_health() } else { 0 };
        if self.status != ServerStatus::Maint {
            self.status = if up { self.running() } else { ServerStatus::Down };
        }
    }

    /// The value published in `Proxy::server_statuses`: the status, or [`DRAIN_DOWN`].
    #[must_use]
    pub fn published(&self) -> u8 {
        if self.status == ServerStatus::Down && self.admin == ServerStatus::Drain {
            DRAIN_DOWN
        } else {
            self.status as u8
        }
    }

    /// The `status` column of `show stat` (`stats_fill_sv_computestate`): `UP`, or `UP n/fall`
    /// while the counter is short of full health (`n` is signed and starts negative), `DRAIN`
    /// likewise, `DOWN`, or `DOWN n/rise` while a down server climbs.
    #[must_use]
    pub fn status_word(&self) -> String {
        StatusWord(self).to_string()
    }

    /// True for the statuses from L57DATA on, the ones that have a `code` (log line and
    /// `show stat` `check_code`).
    #[must_use]
    pub fn carries_code(&self) -> bool {
        matches!(
            self.last_status_code,
            "L57DATA" | "L7OK" | "L7OKD" | "L7OKC" | "L7OKCD" | "L7STS" | "PROCERR" | "PROCTOUT" | "PROCOK"
        )
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

        // `check_append_info` (src/check.c): every status from L57DATA on prints a code,
        // 0 when the check set none.
        if self.carries_code() {
            let _ = write!(out, ", code: {}", self.http_code.unwrap_or(0));
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
        let ms = u32::try_from(self.interval().as_millis()).unwrap_or(u32::MAX);
        now.add(ms)
    }

    /// `srv_getinter()` (`src/check.c`): `inter` while fully healthy, `downinter` once the
    /// counter is at zero and the server is down, `fastinter` in between (UP but failing,
    /// or DOWN but succeeding). An unset `fastinter` or `downinter` is `inter`.
    #[must_use]
    pub fn interval(&self) -> Duration {
        let inter = self.config.inter;
        if self.health >= self.full_health() {
            inter
        } else if self.health == 0 && self.status == ServerStatus::Down {
            if self.config.downinter_ms == 0 { inter } else { Duration::from_millis(u64::from(self.config.downinter_ms)) }
        } else {
            if self.config.fastinter_ms == 0 { inter } else { Duration::from_millis(u64::from(self.config.fastinter_ms)) }
        }
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

/// The log-formats of an `http-check send`: its `hdr` values, and `uri-lf` and
/// `body-lf`, compiled when the check is set up. The configuration was refused at load if
/// one did not compile ([`crate::rule_exprs::validate_formats`]).
#[derive(Debug, Clone)]
pub struct HttpSendFormats {
    uri: Option<LogFormat>,
    body: Option<LogFormat>,
    /// One per `hdr`, in order.
    hdrs: Vec<Option<LogFormat>>,
}

impl HttpSendFormats {
    /// The formats of `cfg`, compiled once per resolved check: the servers that share a
    /// resolved check share its formats too.
    fn shared_for(cfg: Option<&Arc<ResolvedCheckConfig>>) -> Option<Arc<Self>> {
        thread_local! {
            static LAST: std::cell::RefCell<Option<(Arc<ResolvedCheckConfig>, Option<Arc<HttpSendFormats>>)>> =
                const { std::cell::RefCell::new(None) };
        }
        let cfg = cfg?;
        LAST.with(|last| {
            let mut last = last.borrow_mut();
            if let Some((_, fmts)) = last.as_ref().filter(|(prev, _)| Arc::ptr_eq(prev, cfg)) {
                return fmts.clone();
            }
            let fmts = Self::for_config(Some(cfg)).map(Arc::new);
            *last = Some((Arc::clone(cfg), fmts.clone()));
            fmts
        })
    }

    fn for_config(cfg: Option<&ResolvedCheckConfig>) -> Option<Self> {
        let Some(ResolvedCheckConfig::Http(chk)) = cfg else { return None };
        let reg = crate::engine::sample_registry();
        let compile = |f: &str| LogFormat::compile(f, reg).ok();
        Some(HttpSendFormats {
            uri: chk.uri_lf.then(|| compile(&chk.uri)).flatten(),
            body: chk.body.as_deref().filter(|_| chk.body_lf).and_then(compile),
            hdrs: chk.headers.iter().map(|(_, v)| compile(v)).collect(),
        })
    }
}

/// The check's view of itself for its log-formats, as `HAProxy`'s check session has it:
/// the backend as both frontend and backend, the server, and the unique ID the backend's
/// `unique-id-format` gives (`sess_build_logline` on `check->sess`).
fn render_check_formats(
    fmts: &HttpSendFormats,
    check: &ServerCheckState,
    px: &Proxy,
    proxies: &[Proxy],
) -> RenderedSend {
    let reg = crate::engine::sample_registry();
    with_check_ctx(check, px, proxies, &check.run.vars, None, |data, ctx| {
        let render = |f: &LogFormat| f.render_value(data, reg, ctx);
        (fmts.uri.as_ref().map(render), fmts.body.as_ref().map(render), fmts.hdrs.iter().map(|h| h.as_ref().map(render)).collect())
    })
}

/// Runs `f` with the log data and sample context of a check: the backend as both frontend
/// and backend, the server, the unique ID, the check's variables and, once a response is
/// in, the response (`res.fhdr` and the like).
fn with_check_ctx<R>(
    check: &ServerCheckState,
    px: &Proxy,
    proxies: &[Proxy],
    vars: &ibex_sample::VarStore,
    resp: Option<&HttpResp>,
    f: impl FnOnce(&LogData, &ibex_sample::SampleContext) -> R,
) -> R {
    let reg = crate::engine::sample_registry();
    let srv = px.server_ids.get(check.server()).map(String::as_str);
    let view = ProxiesView(proxies);
    let mut ctx = ibex_sample::SampleContext {
        fe_name: Some(&px.name),
        fe_id: Some(px.ids.iid),
        be_name: Some(&px.name),
        be_id: Some(px.ids.iid),
        srv_name: srv,
        srv_id: Some(px.server_puid(check.server())),
        server_addr: Some(check.addr),
        proxies: Some(&view),
        vars: Some(vars),
        ..Default::default()
    };
    if let Some(r) = resp {
        ctx.res_status = Some(r.status);
        ctx.res_version = Some(&r.version);
        ctx.res_headers = Some(&r.headers);
        ctx.res_body = Some(&r.body);
    }
    let mut data = LogData {
        frontend: &px.name,
        backend: &px.name,
        server: srv,
        server_addr: Some(check.addr),
        pid: std::process::id(),
        ..LogData::default()
    };
    let unique_id = px.unique_id_format.as_ref().map(|f| f.render(&data, reg, &ctx));
    ctx.unique_id = unique_id.as_deref();
    data.unique_id = unique_id.as_deref();
    f(&data, &ctx)
}

/// Runs the `set-var` / `unset-var` rules among `rules` in order on `vars`; a `set-var`
/// sees the response `resp` when there is one.
fn run_var_rules(
    check: &ServerCheckState,
    proxies: &[Proxy],
    rules: &[ResolvedHttpRule],
    vars: &mut ibex_sample::VarStore,
    resp: Option<&HttpResp>,
) {
    let Some(px) = proxies.get(check.proxy()) else { return };
    let reg = crate::engine::sample_registry();
    for rule in rules {
        if let ResolvedHttpRule::SetVar { var_name, expr } = rule {
            let val = with_check_ctx(check, px, proxies, vars, resp, |_, ctx| {
                ibex_sample::Expr::cached(expr)
                    .ok()
                    .and_then(|e| e.eval_sample(reg, ctx))
            });
            // An expression that gives no sample leaves the variable as it was.
            if let Some(v) = val {
                ibex_sample::vars::set_in(vars, var_name, ibex_sample::vars::In::Owned(v));
            }
        } else if let ResolvedHttpRule::UnsetVar { var_name } = rule {
            vars.remove(var_name);
        }
    }
}

/// `uri-lf`, `body-lf` and each `hdr` as rendered for one check; `None` where the request
/// uses the configured text.
type RenderedSend = (Option<String>, Option<String>, Vec<Option<String>>);

/// `srv_check_result` of `show servers state` for a check status code: the `result` column
/// of `check_statuses` in `src/check.c` (`CHK_RES_*`: UNKNOWN 0, NEUTRAL 1, FAILED 2,
/// PASSED 3, CONDPASS 4).
#[must_use]
pub fn check_result_of(code: &str) -> u8 {
    match code {
        "UNK" | "INI" | "START" => 0,
        "CHECKED" => 1,
        "L7OKC" | "L7OKCD" => 4,
        "L4OK" | "L6OK" | "L7OK" | "L7OKD" | "PROCOK" => 3,
        _ => 2,
    }
}

/// `httpchk_build_status_header` (`src/check.c`): the value of `X-Haproxy-Server-State`.
///
/// The backend's stream count in `scur=<srv>/<backend>` is the streams on the backend's
/// servers: Ibex counts no backend streams of its own, and has no queue to subtract.
fn server_state_header(check: &ServerCheckState, proxies: &[Proxy]) -> String {
    let health = i64::from(check.health);
    let (rise, fall) = (i64::from(check.config.rise), i64::from(check.config.fall));
    let stopped = matches!(check.status, ServerStatus::Down | ServerStatus::Maint);
    let mut out = if !check.enabled {
        "no check".to_string()
    } else if !stopped {
        if health == rise + fall - 1 {
            "UP".to_string()
        } else {
            format!("UP {}/{fall}", health - rise + 1)
        }
    } else if health > 0 {
        format!("DOWN {health}/{rise}")
    } else {
        "DOWN".to_string()
    };
    let Some(px) = proxies.get(check.proxy()) else { return out };
    let i = check.server();
    let addr = px.servers.get(i).unwrap_or(check.addr);
    let cur = |j: usize| px.server_actconn.get(j).map_or(0, |a| a.load(Ordering::Relaxed));
    let be_streams: u32 = (0..px.servers.len()).map(cur).sum();
    let _ = write!(
        out,
        "; address={}; port={}; name={}/{}; node={}; weight={}/{}; scur={}/{}; qcur=0",
        addr.ip(),
        addr.port(),
        px.name,
        px.server_ids.get(i).map_or("", String::as_str),
        crate::engine::log_hostname(),
        px.server_weights.get(i).unwrap_or(1),
        total_weight(px),
        cur(i),
        be_streams,
    );
    out
}

/// Builds the HTTP request payload for a health check, as `tcpcheck_eval_send` sends it:
/// the request line, the `hdr` headers (one whose value renders empty is left out), the
/// server state, `content-length` when there is a body, `connection: close`.
fn build_http_request_payload(chk: &ResolvedHttpCheck, target_addr: SocketAddr, check: &ServerCheckState, proxies: &[Proxy]) -> Vec<u8> {
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

    // A rule set without a `send` (a backend with `http-check expect` rules only) connects
    // and sends nothing, as `HAProxy` does.
    if !chk.has_send {
        return payload;
    }

    let rendered = check.http_send.as_ref().zip(proxies.get(check.proxy()));
    let (uri, body, hdr_values) = rendered.map(|(fmts, px)| render_check_formats(fmts, check, px, proxies)).unwrap_or_default();
    // An `uri-lf` that renders empty sends `/`.
    let uri = match uri {
        Some(u) if u.is_empty() => "/".to_string(),
        Some(u) => u,
        None => chk.uri.clone(),
    };
    let body = body.or_else(|| chk.body.clone());

    // The headers, names in lower case as the HTX the request is built in keeps them; one
    // whose value renders empty is left out.
    let mut headers: Vec<(String, String)> = Vec::new();
    for (i, (name, val)) in chk.headers.iter().enumerate() {
        let val = hdr_values.get(i).and_then(Option::as_deref).unwrap_or(val);
        if !val.is_empty() {
            headers.push((name.to_ascii_lowercase(), val.to_string()));
        }
    }
    let host_hdr = headers.iter().find(|(n, _)| n == "host").map(|(_, v)| v.clone());
    // An absolute-form target takes the authority of the Host header, once there is one
    // (`http_update_authority`).
    let uri = match host_hdr {
        Some(host) => replace_authority(&uri, &host).unwrap_or(uri),
        None => uri,
    };

    let req_line = format!("{} {} {}\r\n", chk.method, uri, chk.version);
    payload.extend_from_slice(req_line.as_bytes());

    let mut has_host = false;
    let mut has_connection = false;

    for (name, val) in &headers {
        if name == "host" {
            has_host = true;
        }
        if name == "connection" {
            has_connection = true;
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
        let state_line = format!("x-haproxy-server-state: {}\r\n", server_state_header(check, proxies));
        payload.extend_from_slice(state_line.as_bytes());
    }

    // A body, or a method that has one by default: the length is always sent (`0` for
    // an empty `POST`).
    let body_len = body.as_ref().map_or(0, String::len);
    if body_len > 0 || !matches!(chk.method.as_str(), "OPTIONS" | "GET" | "HEAD" | "DELETE") {
        let cl_line = format!("content-length: {body_len}\r\n");
        payload.extend_from_slice(cl_line.as_bytes());
    }

    if http_version_at_least_11(&chk.version) && !has_connection {
        payload.extend_from_slice(b"connection: close\r\n");
    }

    payload.extend_from_slice(b"\r\n");
    if let Some(ref body) = body {
        payload.extend_from_slice(body.as_bytes());
    }

    payload
}

/// `HTTP/1.1` and later (`HTTP/2` included): where a request carries `connection: close`.
fn http_version_at_least_11(version: &str) -> bool {
    let Some(v) = version.strip_prefix("HTTP/") else { return false };
    let mut it = v.split('.');
    let major: u32 = it.next().and_then(|m| m.parse().ok()).unwrap_or(0);
    let minor: u32 = it.next().and_then(|m| m.parse().ok()).unwrap_or(0);
    major > 1 || (major == 1 && minor >= 1)
}

/// `uri` with the authority of an absolute-form target (`scheme://authority/path`)
/// replaced by `host`; `None` for any other form.
fn replace_authority(uri: &str, host: &str) -> Option<String> {
    let (scheme, rest) = uri.split_once("://")?;
    if scheme.is_empty() || !scheme.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')) {
        return None;
    }
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    Some(format!("{scheme}://{host}{}", &rest[end..]))
}

/// An HTTP response, as far as it has arrived.
#[derive(Debug)]
pub(crate) struct HttpResp {
    status: u16,
    reason: String,
    version: String,
    pub(crate) headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// The message is complete: its length is reached, its last chunk is in, or it has
    /// no body.
    ended: bool,
    /// A `Transfer-Encoding` other than a lone `chunked`: `HAProxy`'s HTTP/1 parser marks
    /// such a reply a parsing error (`HTX_FL_PARSING_ERROR`) and the first `expect` fails
    /// on it whatever it asks.
    parse_error: bool,
}

/// Parses a response head and as much of the body as there is: `Ok(None)` while the head
/// is incomplete, `Err` for one that is not HTTP.
pub(crate) fn parse_http_response(buf: &[u8]) -> Result<Option<HttpResp>, ()> {
    let Some(head_end) = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .or_else(|| buf.windows(2).position(|w| w == b"\n\n").map(|p| p + 2))
    else {
        // Not even a status line can start like this.
        if buf.len() >= 5 && !buf.starts_with(b"HTTP/") {
            return Err(());
        }
        return Ok(None);
    };

    let head = String::from_utf8_lossy(&buf[..head_end]);
    let mut lines = head.lines();
    let status_line = lines.next().ok_or(())?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().ok_or(())?;
    if !version.starts_with("HTTP/") {
        return Err(());
    }
    let code = parts.next().ok_or(())?;
    if code.len() != 3 {
        return Err(());
    }
    let status = code.parse::<u16>().map_err(|_| ())?;
    let reason = parts.next().unwrap_or("").trim().to_string();

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, val) = line.split_once(':').ok_or(())?;
        headers.push((name.trim().to_string(), val.trim().to_string()));
    }

    // Every `Transfer-Encoding` and `Content-Length` line frames the body, as on the
    // proxied path (T276, T281): the first line alone read `gzip` / `chunked` on two lines,
    // or two different lengths, as a reply that passed.
    let te = ibex_proto::h1::TransferCodings::of(headers.iter().map(|(n, v)| (n.as_str(), v.as_str())), true);
    if te.invalid {
        return Err(());
    }
    let parse_error = te.present && (te.other || !te.chunked_last);
    let content_length = if te.present { None } else { reply_content_length(&headers)? };
    let raw_body = &buf[head_end..];
    let (body, ended) = if status < 200 || status == 204 || status == 304 {
        (Vec::new(), true)
    } else if te.present {
        decode_chunked(raw_body)
    } else if let Some(cl) = content_length {
        let cl = usize::try_from(cl).unwrap_or(usize::MAX);
        let n = raw_body.len().min(cl);
        (raw_body[..n].to_vec(), raw_body.len() >= cl)
    } else {
        (raw_body.to_vec(), false)
    };
    Ok(Some(HttpResp { status, reason, version: version.to_string(), headers, body, ended, parse_error }))
}

/// The length every `Content-Length` line of a reply gives, as `HAProxy` reads them
/// (`http_parse_cont_len_header`): digits only, a comma list of one repeated number, and
/// the same number on every line. `Err` for anything else, which `HAProxy`'s parser
/// refuses outright (a socket error for the check).
fn reply_content_length(headers: &[(String, String)]) -> Result<Option<u64>, ()> {
    let mut len = None;
    for (_, v) in headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("content-length")) {
        for word in v.split(',').map(|w| w.trim_matches([' ', '\t'])) {
            if word.is_empty() || !word.bytes().all(|b| b.is_ascii_digit()) {
                return Err(());
            }
            let n: u64 = word.parse().map_err(|_| ())?;
            if len.is_some_and(|l| l != n) {
                return Err(());
            }
            len = Some(n);
        }
    }
    Ok(len)
}

/// What the first `expect` says of a reply `HAProxy` could not parse into a message: the
/// generic message of its kind and step (`tcpcheck_expect_onerror_message`).
fn unparsed_reply_failure(rule: &ResolvedHttpExpectRule, resp: &HttpResp) -> HttpVerdict {
    let kind = match &rule.pattern {
        HttpCheckExpectPattern::Status(_) => "(status codes)".to_string(),
        HttpCheckExpectPattern::String(t) => format!(" '{t}'"),
        HttpCheckExpectPattern::StringLf(_) => " (log-format string)".to_string(),
        HttpCheckExpectPattern::RStatus(_) | HttpCheckExpectPattern::RString(_) => " (regex)".to_string(),
        HttpCheckExpectPattern::Hdr { .. } => " (header pattern)".to_string(),
    };
    // `HAProxy` reaches this through its `error:` label, which always words it as a miss,
    // negated rule or not.
    let info = format!("TCPCHK did not match content{kind} at step {}", rule.step);
    fail_with(("L7RSP", "Layer7 invalid response"), resp, info, rule.comment.as_deref())
}

/// The data of the chunks in `raw` and whether the last one is there.
fn decode_chunked(raw: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let Some(eol) = raw[pos..].windows(2).position(|w| w == b"\r\n") else { return (out, false) };
        let size_text = String::from_utf8_lossy(&raw[pos..pos + eol]);
        let Ok(size) = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16) else {
            return (out, false);
        };
        pos += eol + 2;
        if size == 0 {
            return (out, true);
        }
        let avail = raw.len().saturating_sub(pos).min(size);
        out.extend_from_slice(&raw[pos..pos + avail]);
        if avail < size {
            return (out, false);
        }
        pos += size + 2;
        if pos > raw.len() {
            return (out, false);
        }
    }
}

/// What the rules say of a response so far.
enum HttpVerdict {
    /// More data is needed.
    Wait,
    Pass { status: u16 },
    Fail { code: &'static str, desc: &'static str, status: Option<u16>, info: Option<String> },
}

fn fail_with(status: (&'static str, &'static str), resp: &HttpResp, info: String, comment: Option<&str>) -> HttpVerdict {
    let info = match comment {
        Some(c) => format!("{info} comment: {c}"),
        None => info,
    };
    // The status is logged with a wrong status, not with an invalid response.
    let status_code = (status.0 == "L7STS").then_some(resp.status);
    HttpVerdict::Fail { code: status.0, desc: status.1, status: status_code, info: Some(info) }
}

/// Compiles a regular expression written in the configuration (checked when it was read).
fn config_regex_nocapture(pattern: &str, case_insensitive: bool) -> Option<ibex_regex::UserRegex> {
    ibex_regex::UserRegex::with_case_nocapture(pattern, case_insensitive).ok()
}

/// Compiles a regular expression written in the configuration (checked when it was read).
fn config_regex(pattern: &str, case_insensitive: bool) -> Option<ibex_regex::UserRegex> {
    ibex_regex::UserRegex::with_case(pattern, case_insensitive).ok()
}

/// The values of a header `hdr` looks at: the comma-separated elements, trimmed, or with
/// `full` the whole value.
pub(crate) fn header_values(value: &str, full: bool) -> Vec<&str> {
    if full {
        vec![value.trim()]
    } else {
        value.split(',').map(str::trim).filter(|v| !v.is_empty()).collect()
    }
}

/// A header name or value pattern with its log-format, if any, rendered.
#[derive(Clone, Copy)]
struct Pat<'a> {
    mt: MatchType,
    text: &'a str,
}

/// `http-check expect hdr|fhdr`: whether a header of the response matches.
fn hdr_expect_matches(resp: &HttpResp, full: bool, name: Pat, value: Option<Pat>) -> bool {
    let name_re = (name.mt == MatchType::Reg).then(|| config_regex(name.text, true)).flatten();
    let name_matches = |h: &str| match name.mt {
        MatchType::Str => h.eq_ignore_ascii_case(name.text),
        MatchType::Beg => h.to_ascii_lowercase().starts_with(&name.text.to_ascii_lowercase()),
        MatchType::End => h.to_ascii_lowercase().ends_with(&name.text.to_ascii_lowercase()),
        MatchType::Sub => h.to_ascii_lowercase().contains(&name.text.to_ascii_lowercase()),
        MatchType::Reg => name_re.as_ref().is_some_and(|re| re.is_match(h)),
    };
    let val_re = value.and_then(|v| (v.mt == MatchType::Reg).then(|| config_regex(v.text, false)).flatten());
    resp.headers.iter().filter(|(h, _)| name_matches(h)).any(|(_, v)| {
        let Some(vp) = value else { return true };
        header_values(v, full).into_iter().any(|e| match vp.mt {
            MatchType::Str => e == vp.text,
            MatchType::Beg => e.starts_with(vp.text),
            MatchType::End => e.ends_with(vp.text),
            MatchType::Sub => e.contains(vp.text),
            MatchType::Reg => val_re.as_ref().is_some_and(|re| re.is_match(e)),
        })
    })
}

/// One `http-check expect` rule against the response so far (`tcpcheck_eval_expect_http`).
/// `render` turns a log-format written in the rule into text, as the check renders it.
fn http_expect(rule: &ResolvedHttpExpectRule, resp: &HttpResp, last_read: bool, render: &dyn Fn(&str) -> String) -> HttpVerdict {
    let comment = rule.comment.as_deref();
    let last_read = last_read || resp.ended;
    let rsp = ("L7RSP", "Layer7 invalid response");
    let empty_lf = || fail_with(rsp, resp, "log-format string evaluated to an empty string".to_string(), comment);
    let matched = match &rule.pattern {
        HttpCheckExpectPattern::Status(ranges) => ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&resp.status)),
        HttpCheckExpectPattern::RStatus(re) => {
            config_regex_nocapture(re, false).is_some_and(|re| re.is_match(&resp.status.to_string()))
        }
        HttpCheckExpectPattern::Hdr { full, name, value } => {
            let name_text = if name.lf { render(&name.text) } else { name.text.clone() };
            let value_text = value.as_ref().map(|v| if v.lf { render(&v.text) } else { v.text.clone() });
            if name_text.is_empty() || value_text.as_ref().is_some_and(String::is_empty) {
                return empty_lf();
            }
            let np = Pat { mt: name.mt, text: &name_text };
            let vp = value.as_ref().zip(value_text.as_deref()).map(|(v, t)| Pat { mt: v.mt, text: t });
            hdr_expect_matches(resp, *full, np, vp)
        }
        HttpCheckExpectPattern::String(_) | HttpCheckExpectPattern::StringLf(_) | HttpCheckExpectPattern::RString(_) => {
            // The body so far; nothing to look at yet is a wait, until the message ends.
            if resp.body.is_empty() {
                if !last_read {
                    return HttpVerdict::Wait;
                }
                return fail_with(rsp, resp, "HTTP content check could not find a response body".to_string(), comment);
            }
            let needle = match &rule.pattern {
                HttpCheckExpectPattern::String(t) => Some(t.clone()),
                HttpCheckExpectPattern::StringLf(t) => {
                    let r = render(t);
                    if r.is_empty() {
                        return empty_lf();
                    }
                    Some(r)
                }
                _ => None,
            };
            let short = needle.as_ref().is_some_and(|n| resp.body.len() < n.len());
            let min_short = rule.min_recv > 0 && i64::try_from(resp.body.len()).unwrap_or(i64::MAX) < rule.min_recv;
            if !last_read && (short || min_short) {
                return HttpVerdict::Wait;
            }
            let m = if let HttpCheckExpectPattern::RString(re) = &rule.pattern {
                config_regex_nocapture(re, false).is_some_and(|re| re.is_match(&String::from_utf8_lossy(&resp.body)))
            } else {
                needle.as_deref().is_some_and(|n| resp.body.windows(n.len().max(1)).any(|w| w == n.as_bytes()))
            };
            // A mismatch is not conclusive before the message ends, unless `min-recv` says so.
            if !m && !last_read && rule.min_recv == -1 {
                return HttpVerdict::Wait;
            }
            if m != rule.negate {
                return HttpVerdict::Pass { status: resp.status };
            }
            let info = if rule.negate { "HTTP check matched unwanted content" } else { "HTTP content check did not match" };
            return fail_with(rsp, resp, info.to_string(), comment);
        }
    };
    if matched != rule.negate {
        HttpVerdict::Pass { status: resp.status }
    } else {
        fail_with(("L7STS", "Layer7 wrong status"), resp, resp.reason.clone(), comment)
    }
}

/// What the rules of an HTTP check say of the bytes received so far (`last_read`: no more
/// are coming).
fn http_verdict(check: &ServerCheckState, chk: &ResolvedHttpCheck, buf: &[u8], last_read: bool, proxies: &[Proxy]) -> HttpVerdict {
    let resp = match parse_http_response(buf) {
        Ok(Some(r)) => r,
        Ok(None) if !last_read => return HttpVerdict::Wait,
        Ok(None) | Err(()) => {
            // `HAProxy` calls both an HTTP response that never came and one that is not
            // HTTP a socket error.
            return HttpVerdict::Fail { code: "SOCKERR", desc: "Socket error", status: None, info: None };
        }
    };
    // The first rule is an `expect`: the parser holds `set-var` and `unset-var` ahead of it
    // apart, and adds one to a check that has none.
    if let Some(ResolvedHttpRule::Expect(rule)) = chk.rules.first().filter(|_| resp.parse_error) {
        return unparsed_reply_failure(rule, &resp);
    }
    let px = &proxies[check.proxy()];
    let reg = crate::engine::sample_registry();
    // The rules run in order from the same starting variables each time more of the
    // response is in; what one sets is for the ones after it.
    let mut vars = check.run.vars.clone();
    for rule in &chk.rules {
        match rule {
            ResolvedHttpRule::Expect(e) => {
                let render = |fmt: &str| {
                    // Every format was compiled when the configuration was read.
                    LogFormat::compile(fmt, reg)
                        .map(|f| with_check_ctx(check, px, proxies, &vars, Some(&resp), |data, ctx| f.render_value(data, reg, ctx)))
                        .unwrap_or_default()
                };
                match http_expect(e, &resp, last_read, &render) {
                    HttpVerdict::Pass { .. } => {}
                    other => return other,
                }
            }
            other => run_var_rules(check, proxies, std::slice::from_ref(other), &mut vars, Some(&resp)),
        }
    }
    HttpVerdict::Pass { status: resp.status }
}

/// The bare `strerror(errno)` text, without the `" (os error N)"` that Rust's
/// `io::Error` Display appends. HAProxy reports the former, and the reg-tests anchor on
/// it -- `\(Network.* unreachable\)` needs the string to end at the closing paren.
fn strerror(err: &io::Error) -> String {
    let text = err.to_string();
    match text.find(" (os error ") {
        Some(idx) => text[..idx].to_string(),
        None => text,
    }
}

fn format_l4_connect_error(err: &io::Error) -> String {
    if err.kind() == io::ErrorKind::ConnectionRefused || err.raw_os_error() == Some(111) {
        "ECONNREFUSED returned by OS (Connection refused)".to_string()
    } else {
        format!("General socket error ({})", strerror(err))
    }
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
    proxies: &[Proxy],
) -> io::Result<CheckStep> {
    if !check.enabled {
        if check.in_progress {
            cleanup_check_socket(check, fdtab, poller);
        }
        let next = check.schedule_next(now);
        check.next_check = next;
        return Ok(CheckStep::pending(Some(next)));
    }

    // `CHK_ST_PAUSED`: a server in maintenance is not checked. The task only looks again
    // after a second at most, so that `enable server` has its check soon (HAProxy runs it
    // at once).
    if check.status == ServerStatus::Maint {
        if check.in_progress {
            cleanup_check_socket(check, fdtab, poller);
        }
        let next = now.add(u32::try_from(check.config.inter.as_millis().min(1000)).unwrap_or(1000));
        check.next_check = next;
        return Ok(CheckStep::pending(Some(next)));
    }

    if check.resolved_config.is_none() {
        check.resolved_config = get_resolved_check_config(check.proxy(), check.server(), check.addr);
        check.http_send = HttpSendFormats::shared_for(check.resolved_config.as_ref());
    }

    if check.in_progress {
        let duration = now.remaining(check.run.start_tick).unwrap_or(0);
        let timed_out = check.exp.is_expired(now);

        if timed_out {
            let handshaking = check.xprt.is_tls() && !check.xprt.is_ready();
            let (code, desc, info) = match &check.run.sub_state {
                _ if handshaking => ("L6TOUT", "Layer6 timeout", None),
                CheckSubState::TcpConnecting
                | CheckSubState::HttpConnecting { .. }
                | CheckSubState::ProtoConnecting { .. }
                | CheckSubState::Idle => ("L4TOUT", "Layer4 timeout", None),
                CheckSubState::HttpSending { .. }
                | CheckSubState::HttpReceiving { .. }
                | CheckSubState::RedisRunning { .. }
                | CheckSubState::SmtpRunning { .. }
                | CheckSubState::LdapRunning { .. }
                | CheckSubState::MysqlRunning { .. }
                | CheckSubState::PgsqlRunning { .. } => ("L7TOUT", "Layer7 timeout", None),
                CheckSubState::SslHelloRunning { .. } => ("L6TOUT", "Layer6 timeout", None),
                CheckSubState::TcpRunning { step_idx, .. } => {
                    tcp_timeout_status(tcp_steps_of(check), *step_idx)
                }
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

        let Some(raw_fd) = check.run.check_fd else {
            cleanup_check_socket(check, fdtab, poller);
            let next = check.schedule_next(now);
            return Ok(CheckStep::pending(Some(next)));
        };

        let ready = fdtab.ready(raw_fd);

        match check.run.sub_state.clone() {
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
                if let Ok(None) = connect_res {
                    match drive_check_handshake(check, fdtab, poller, raw_fd) {
                        Handshake::Ready => {}
                        Handshake::Pending => return Ok(CheckStep::pending(Some(check.exp))),
                        Handshake::Failed(info) => return Ok(fail_check_l6(check, fdtab, poller, now, duration, info)),
                    }
                }
                // A connect check over TLS passes at layer 6 ("Layer6 check passed").
                let l6 = check.xprt.is_tls();
                cleanup_check_socket(check, fdtab, poller);

                let event = match connect_res {
                    Ok(None) if l6 => check.on_success_full("L6OK", "Layer6 check passed", duration, None, None),
                    Ok(None) => check.on_success(duration),
                    Ok(Some(ref err)) => {
                        let info = Some(format_l4_connect_error(err));
                        check.on_failure_full("L4CON", "Layer4 connection problem", duration, None, info)
                    }
                    Err(ref e) => {
                        let info = Some(format!("General socket error ({})", strerror(e)));
                        check.on_failure_full("L4CON", "Layer4 connection problem", duration, None, info)
                    }
                };

                let next = check.schedule_next(now);
                check.next_check = next;
                Ok(CheckStep {
                    next: Some(next),
                    event,
                })
            }
            CheckSubState::ProtoConnecting { target_addr: _ } => {
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
                    match drive_check_handshake(check, fdtab, poller, raw_fd) {
                        Handshake::Ready => {}
                        Handshake::Pending => return Ok(CheckStep::pending(Some(check.exp))),
                        Handshake::Failed(info) => return Ok(fail_check_l6(check, fdtab, poller, now, duration, info)),
                    }
                    match check.resolved_config.as_deref().cloned() {
                        Some(ResolvedCheckConfig::Redis) => {
                            check.run.sub_state = CheckSubState::RedisRunning {
                                phase: 0,
                                send_offset: 0,
                                recv_buf: Vec::new(),
                            };
                            progress_redis_check(check, fdtab, poller, now, duration)
                        }
                        Some(ResolvedCheckConfig::Smtp(cmd)) => {
                            fdtab.set_interest(raw_fd, Interest::READ);
                            if let Some(sock) = check.sock.as_ref() {
                                let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), true, false);
                            }
                            check.run.sub_state = CheckSubState::SmtpRunning {
                                phase: 0,
                                cmd: cmd.unwrap_or_else(|| "HELO localhost".to_string()),
                                send_offset: 0,
                                recv_buf: Vec::new(),
                            };
                            progress_smtp_check(check, fdtab, poller, now, duration)
                        }
                        Some(ResolvedCheckConfig::Ldap) => {
                            check.run.sub_state = CheckSubState::LdapRunning {
                                phase: 0,
                                send_offset: 0,
                                recv_buf: Vec::new(),
                            };
                            progress_ldap_check(check, fdtab, poller, now, duration)
                        }
                        Some(ResolvedCheckConfig::Mysql { user, version }) => {
                            let req_buf = user.as_deref().map(|u| build_mysql_req(u, version)).unwrap_or_default();
                            let initial_interest = if req_buf.is_empty() { Interest::READ } else { Interest::WRITE };
                            fdtab.set_interest(raw_fd, initial_interest);
                            if let Some(sock) = check.sock.as_ref() {
                                let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), initial_interest.readable, initial_interest.writable);
                            }
                            check.run.sub_state = CheckSubState::MysqlRunning {
                                phase: 0,
                                user,
                                version,
                                send_offset: 0,
                                req_buf,
                                recv_buf: Vec::new(),
                            };
                            progress_mysql_check(check, fdtab, poller, now, duration)
                        }
                        Some(ResolvedCheckConfig::Pgsql { user }) => {
                            check.run.sub_state = CheckSubState::PgsqlRunning {
                                phase: 0,
                                user,
                                send_offset: 0,
                                req_buf: Vec::new(),
                                recv_buf: Vec::new(),
                            };
                            progress_pgsql_check(check, fdtab, poller, now, duration)
                        }
                        Some(ResolvedCheckConfig::SslHello) => {
                            check.run.sub_state = CheckSubState::SslHelloRunning {
                                phase: 0,
                                send_offset: 0,
                                recv_buf: Vec::new(),
                            };
                            progress_ssl_hello_check(check, fdtab, poller, now, duration)
                        }
                        _ => {
                            cleanup_check_socket(check, fdtab, poller);
                            let next = check.schedule_next(now);
                            Ok(CheckStep::pending(Some(next)))
                        }
                    }
                } else {
                    cleanup_check_socket(check, fdtab, poller);
                    let info = match connect_res {
                        Ok(Some(ref err)) => Some(format_l4_connect_error(err)),
                        Err(ref e) => Some(format!("General socket error ({})", strerror(e))),
                        _ => None,
                    };
                    let event = check.on_failure_full(
                        "L4CON",
                        "Layer4 connection problem",
                        duration,
                        None,
                        info,
                    );
                    let next = check.schedule_next(now);
                    check.next_check = next;
                    Ok(CheckStep {
                        next: Some(next),
                        event,
                    })
                }
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
                    match drive_check_handshake(check, fdtab, poller, raw_fd) {
                        Handshake::Ready => {}
                        Handshake::Pending => return Ok(CheckStep::pending(Some(check.exp))),
                        Handshake::Failed(info) => return Ok(fail_check_l6(check, fdtab, poller, now, duration, info)),
                    }
                    fdtab.set_interest(raw_fd, Interest::WRITE);
                    if let Some(sock) = check.sock.as_ref() {
                        let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), false, true);
                    }
                    check.run.sub_state = CheckSubState::HttpSending {
                        req_buf,
                        send_offset,
                    };
                    progress_http_check(check, fdtab, poller, now, duration, proxies)
                } else {
                    cleanup_check_socket(check, fdtab, poller);
                    let info = match connect_res {
                        Ok(Some(ref err)) => Some(format_l4_connect_error(err)),
                        Err(ref e) => Some(format!("General socket error ({})", strerror(e))),
                        _ => None,
                    };
                    let event = check.on_failure_full(
                        "L4CON",
                        "Layer4 connection problem",
                        duration,
                        None,
                        info,
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
                progress_http_check(check, fdtab, poller, now, duration, proxies)
            }
            CheckSubState::TcpRunning { .. } => {
                progress_tcp_check(check, fdtab, poller, now, duration)
            }
            CheckSubState::RedisRunning { .. } => {
                progress_redis_check(check, fdtab, poller, now, duration)
            }
            CheckSubState::SmtpRunning { .. } => {
                progress_smtp_check(check, fdtab, poller, now, duration)
            }
            CheckSubState::LdapRunning { .. } => {
                progress_ldap_check(check, fdtab, poller, now, duration)
            }
            CheckSubState::MysqlRunning { .. } => {
                progress_mysql_check(check, fdtab, poller, now, duration)
            }
            CheckSubState::PgsqlRunning { .. } => {
                progress_pgsql_check(check, fdtab, poller, now, duration)
            }
            CheckSubState::SslHelloRunning { .. } => {
                progress_ssl_hello_check(check, fdtab, poller, now, duration)
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
        check.run.start_tick = now;
        check.http_code = None;
        check.last_status_info = None;

        // A reference to the backend's shared check (it was a deep copy per run).
        let resolved = check.resolved_config.clone();

        match resolved.as_deref().unwrap_or(&ResolvedCheckConfig::TcpConnect) {
            ResolvedCheckConfig::Http(chk) => {
                let base = chk.connect_addr.map_or(check.addr.ip(), |a| a.ip());
                let target_addr = SocketAddr::new(base, chk.check_port.unwrap_or(check.addr.port()));
                // The variables of this run: the rules before the request set them.
                let mut vars = ibex_sample::VarStore::new();
                run_var_rules(check, proxies, &chk.pre_rules, &mut vars, None);
                check.run.vars = vars;
                let payload = build_http_request_payload(chk, target_addr, check, proxies);

                match connect_check(check, Some(target_addr)) {
                    Ok((sock, _)) => {
                        let raw_fd = sock.as_raw_fd();
                        check.run.check_fd = Some(raw_fd);
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

                        // Even a connection that is already up is waited for: the poller
                        // reports its socket writable at once.
                        check.run.sub_state = CheckSubState::HttpConnecting {
                            req_buf: payload,
                            send_offset: 0,
                        };
                        Ok(CheckStep::pending(Some(check.exp)))
                    }
                    Err(e) => {
                        let info = Some(format_l4_connect_error(&e));
                        let event = check.on_failure_full(
                            "L4CON",
                            "Layer4 connection problem",
                            0,
                            None,
                            info,
                        );
                        let next = check.schedule_next(now);
                        check.next_check = next;
                        Ok(CheckStep {
                            next: Some(next),
                            event,
                        })
                    }
                }
            }
            ResolvedCheckConfig::TcpSteps(_) => {
                check.run.sub_state = CheckSubState::TcpRunning {
                    step_idx: 0,
                    send_offset: 0,
                    recv_buf: Vec::new(),
                };
                let timeout_ms =
                    u32::try_from(check.config.timeout.as_millis()).unwrap_or(u32::MAX);
                check.exp = now.add(timeout_ms);
                check.in_progress = true;
                progress_tcp_steps_start(check, fdtab, poller, now)
            }
            // The protocol checks connect, then start their exchange once the connection is
            // up (`ProtoConnecting` in `step_check`), an immediate one included: the poller
            // reports its socket writable at once.
            ResolvedCheckConfig::Redis
            | ResolvedCheckConfig::Smtp(_)
            | ResolvedCheckConfig::Ldap
            | ResolvedCheckConfig::Mysql { .. }
            | ResolvedCheckConfig::Pgsql { .. }
            | ResolvedCheckConfig::SslHello => {
                match connect_check(check, None) {
                    Ok((sock, _)) => {
                        let raw_fd = sock.as_raw_fd();
                        check.run.check_fd = Some(raw_fd);
                        let timeout_ms = u32::try_from(check.config.timeout.as_millis()).unwrap_or(u32::MAX);
                        check.exp = now.add(timeout_ms);
                        check.in_progress = true;
                        fdtab.insert(raw_fd, FdState::Conn { task: check.task, conn: 0 }, Interest::WRITE);
                        let _ = poller.add(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), false, true);
                        check.sock = Some(sock);

                        check.run.sub_state = CheckSubState::ProtoConnecting { target_addr: check.addr };
                        Ok(CheckStep::pending(Some(check.exp)))
                    }
                    Err(e) => {
                        let info = Some(format_l4_connect_error(&e));
                        let event = check.on_failure_full("L4CON", "Layer4 connection problem", 0, None, info);
                        let next = check.schedule_next(now);
                        check.next_check = next;
                        Ok(CheckStep { next: Some(next), event })
                    }
                }
            }
            ResolvedCheckConfig::TcpConnect => {
                check.run.sub_state = CheckSubState::TcpConnecting;
                match connect_check(check, None) {
                    Ok((sock, immediate)) => {
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
                        check.run.check_fd = Some(raw_fd);
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
                    }
                    Err(e) => {
                        let info = Some(format_l4_connect_error(&e));
                        let event = check.on_failure_full(
                            "L4CON",
                            "Layer4 connection problem",
                            0,
                            None,
                            info,
                        );
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
}

/// Progresses an HTTP check during send or receive phase.
#[allow(clippy::too_many_lines)]
fn progress_http_check(
    check: &mut ServerCheckState,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
    duration: u32,
    proxies: &[Proxy],
) -> io::Result<CheckStep> {
    let Some(raw_fd) = check.run.check_fd else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    let resolved = check.resolved_config.clone();
    let Some(ResolvedCheckConfig::Http(chk)) = resolved.as_deref() else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    match check.run.sub_state.clone() {
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
                match check.xprt.send(sock.as_fd(), &req_buf[send_offset..]) {
                    Ok(Io::Done(n)) => {
                        send_offset += n;
                    }
                    Ok(Io::WouldBlock) => {
                        fdtab.clear_ready(raw_fd, false, true);
                        check.run.sub_state = CheckSubState::HttpSending {
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
            check.run.sub_state = CheckSubState::HttpReceiving {
                recv_buf: Vec::new(),
            };
            progress_http_check(check, fdtab, poller, now, duration, proxies)
        }
        // The receiving state; `step_check` runs this only in a sending or receiving one.
        other => {
            let mut recv_buf = if let CheckSubState::HttpReceiving { recv_buf } = other { recv_buf } else { Vec::new() };
            let Some(sock) = check.sock.as_ref() else {
                cleanup_check_socket(check, fdtab, poller);
                let next = check.schedule_next(now);
                return Ok(CheckStep::pending(Some(next)));
            };

            // One buffer, as `HAProxy` reads: once it is full the response is judged on what
            // it holds (T238; it used to grow with the response, re-parsed on every read).
            let mut buf = [0u8; 4096];
            let mut eof = false;
            let mut broken = false;
            while recv_buf.len() < TCP_CHECK_BUFSIZE {
                let room = (TCP_CHECK_BUFSIZE - recv_buf.len()).min(buf.len());
                match check.xprt.recv(sock.as_fd(), &mut buf[..room]) {
                    Ok(Io::Done(n)) => recv_buf.extend_from_slice(&buf[..n]),
                    Ok(Io::WouldBlock) => break,
                    Ok(Io::Eof) => {
                        eof = true;
                        break;
                    }
                    Ok(Io::Closed) | Err(_) => {
                        broken = true;
                        break;
                    }
                }
            }
            // A connection that fails with nothing received is an invalid response; one
            // that fails after some data is the end of what there is, as is a full buffer.
            let last_read = eof || (broken && !recv_buf.is_empty()) || recv_buf.len() >= TCP_CHECK_BUFSIZE;
            let verdict = if broken && recv_buf.is_empty() {
                HttpVerdict::Fail { code: "SOCKERR", desc: "Socket error", status: None, info: None }
            } else {
                http_verdict(check, &chk, &recv_buf, last_read, proxies)
            };
            let event = match verdict {
                HttpVerdict::Wait => {
                    fdtab.clear_ready(raw_fd, true, false);
                    check.run.sub_state = CheckSubState::HttpReceiving { recv_buf };
                    return Ok(CheckStep::pending(Some(check.exp)));
                }
                HttpVerdict::Pass { status } => {
                    check.http_code = Some(status);
                    cleanup_check_socket(check, fdtab, poller);
                    check.on_success_full("L7OK", "Layer7 check passed", duration, Some(status), None)
                }
                HttpVerdict::Fail { code, desc, status, info } => {
                    check.http_code = status;
                    cleanup_check_socket(check, fdtab, poller);
                    check.on_failure_full(code, desc, duration, status, info)
                }
            };
            let next = check.schedule_next(now);
            check.next_check = next;
            Ok(CheckStep { next: Some(next), event })
        }
    }
}

/// The status of a timeout while rule `idx` of a script was running: while it was
/// connecting, layer 4; otherwise layer 7.
fn tcp_timeout_status(steps: &[ResolvedTcpStep], idx: usize) -> (&'static str, &'static str, Option<String>) {
    let info = Some(tcp_step_suffix(steps, idx));
    match steps.get(idx) {
        Some(ResolvedTcpStep::Connect { .. }) => ("L4TOUT", "Layer4 timeout", info),
        _ => ("L7TOUT", "Layer7 timeout", info),
    }
}

/// The script of a check that is running one.
fn tcp_steps_of(check: &ServerCheckState) -> &[ResolvedTcpStep] {
    if let Some(ResolvedCheckConfig::TcpSteps(steps)) = check.resolved_config.as_deref() { steps } else { &[] }
}

/// The step number `HAProxy` gives rule `idx` of a `tcp-check` script: rules count from 1,
/// and the connect it adds itself, when the script does not start with one, is step 0 (so
/// the first rule after it is step 1). Comment rules take an index too.
fn tcp_step_id(steps: &[ResolvedTcpStep], idx: usize) -> usize {
    if matches!(steps.first(), Some(ResolvedTcpStep::Connect { implicit: true, .. })) {
        idx
    } else {
        idx + 1
    }
}

/// The comment of a rule: its own, or that of the `tcp-check comment` just before it.
fn tcp_step_comment(steps: &[ResolvedTcpStep], idx: usize) -> Option<&str> {
    if let Some(ResolvedTcpStep::Expect { comment: Some(c), .. } | ResolvedTcpStep::Connect { comment: Some(c), .. }) =
        steps.get(idx)
    {
        return Some(c);
    }
    match idx.checked_sub(1).and_then(|p| steps.get(p)) {
        Some(ResolvedTcpStep::Comment(c)) => Some(c),
        _ => None,
    }
}

/// The first inverse `expect` of the run of `expect` rules `idx` belongs to, or `idx`
/// itself: where `HAProxy` resumes (and which step it reports) when an `expect` has to
/// wait for more data.
fn tcp_expect_head(steps: &[ResolvedTcpStep], idx: usize) -> usize {
    let mut head = idx;
    for j in (0..idx).rev() {
        match &steps[j] {
            ResolvedTcpStep::Expect { negate: true, .. } => head = j,
            ResolvedTcpStep::Expect { .. } | ResolvedTcpStep::Comment(_) => {}
            _ => break,
        }
    }
    head
}

/// What `HAProxy` appends to a timeout or connection error that hit rule `idx`
/// (`chk_report_conn_err`): the step, what the rule was doing, its comment.
fn tcp_step_suffix(steps: &[ResolvedTcpStep], idx: usize) -> String {
    let id = tcp_step_id(steps, idx);
    if id == 0 {
        return " at initial connection step of tcp-check".to_string();
    }
    let mut s = format!(" at step {id} of tcp-check");
    match steps.get(idx) {
        Some(ResolvedTcpStep::Connect { rule_port: Some(p), .. }) => s.push_str(&format!(" (connect port {p})")),
        Some(ResolvedTcpStep::Connect { .. }) => s.push_str(" (connect)"),
        Some(ResolvedTcpStep::Send(_)) => s.push_str(" (send)"),
        Some(ResolvedTcpStep::Expect { pattern, .. }) => match pattern {
            ResolvedTcpExpectPattern::String(t) => s.push_str(&format!(" (expect string '{t}')")),
            ResolvedTcpExpectPattern::Binary(b) => {
                let hex: String = b.iter().map(|x| format!("{x:02X}")).collect();
                s.push_str(&format!(" (expect binary '{hex}')"));
            }
            ResolvedTcpExpectPattern::RString(_) => s.push_str(" (expect regex)"),
        },
        _ => {}
    }
    if let Some(c) = tcp_step_comment(steps, idx) {
        s.push_str(&format!(" comment: '{c}'"));
    }
    s
}

/// The info of a failed `expect` (`tcpcheck_expect_onerror_message`).
fn tcp_expect_failure_info(steps: &[ResolvedTcpStep], idx: usize, empty: bool, matched: bool) -> String {
    let id = tcp_step_id(steps, idx);
    let mut s = if empty {
        format!("TCPCHK got an empty response at step {id}")
    } else {
        let what = if matched { "TCPCHK matched unwanted content" } else { "TCPCHK did not match content" };
        match steps.get(idx) {
            Some(ResolvedTcpStep::Expect { pattern: ResolvedTcpExpectPattern::String(t), .. }) => {
                format!("{what} '{t}' at step {id}")
            }
            Some(ResolvedTcpStep::Expect { pattern: ResolvedTcpExpectPattern::Binary(_), .. }) => {
                format!("{what} (binary) at step {id}")
            }
            _ => format!("{what} (regex) at step {id}"),
        }
    };
    if let Some(c) = tcp_step_comment(steps, idx) {
        s.push_str(" comment: ");
        s.push_str(c);
    }
    s
}

/// The info of a failed connection of a `tcp-check` script, as `HAProxy` words it:
/// `ECONNREFUSED returned by OS (Connection refused) at step 2 of tcp-check (connect port 1)`.
fn tcp_connect_failure_info(steps: &[ResolvedTcpStep], idx: usize, err: Option<&io::Error>) -> String {
    let what = match err {
        Some(e) if e.kind() == io::ErrorKind::ConnectionRefused || e.raw_os_error() == Some(111) => {
            "ECONNREFUSED returned by OS (Connection refused)".to_string()
        }
        Some(e) => format_l4_connect_error(e),
        None => "General socket error".to_string(),
    };
    format!("{what}{}", tcp_step_suffix(steps, idx))
}

/// `tune.bufsize`: an input buffer this full ends the wait for more data.
const TCP_CHECK_BUFSIZE: usize = 16384;

/// Starts execution of TCP multi-step check.
fn progress_tcp_steps_start(
    check: &mut ServerCheckState,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
) -> io::Result<CheckStep> {
    // The first rule is a connect (the script's own, or the one `HAProxy` adds): the loop
    // opens its connection as it opens any other.
    check.run.sub_state = CheckSubState::TcpRunning {
        step_idx: 0,
        send_offset: 0,
        recv_buf: Vec::new(),
    };
    progress_tcp_check(check, fdtab, poller, now, 0)
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
    let resolved = check.resolved_config.clone();
    let Some(ResolvedCheckConfig::TcpSteps(steps)) = resolved.as_deref() else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    let CheckSubState::TcpRunning {
        mut step_idx,
        mut send_offset,
        mut recv_buf,
    } = check.run.sub_state.clone()
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
                // The socket in hand is this step's own connection only for the first
                // step (opened by `progress_tcp_steps_start`) or when this step's connect
                // is the one in flight. Otherwise it is the previous step's, and a
                // `tcp-check connect` mid-script means a new connection (HAProxy drops
                // the buffers too: "Always release input and output buffer when a new
                // connect is evaluated"). Treating the old socket as the new connection
                // made the next `expect` read the old server's end of stream.
                let this_steps_socket = step_idx == 0 || check.run.tcp_connect_step == Some(step_idx);
                if let (true, Some(sock)) = (this_steps_socket, check.sock.as_ref()) {
                    let raw_fd = sock.as_raw_fd();
                    let ready = fdtab.ready(raw_fd);
                    if !ready.writable && !ready.readable {
                        check.run.sub_state = CheckSubState::TcpRunning {
                            step_idx,
                            send_offset,
                            recv_buf,
                        };
                        return Ok(CheckStep::pending(Some(check.exp)));
                    }
                    fdtab.clear_ready(raw_fd, true, true);
                    let connect_res = raw::check_connect_error(sock.as_fd());
                    if let Ok(None) = connect_res {
                        check.run.tcp_connect_step = None;
                        step_idx += 1;
                        continue;
                    }
                    
                    let connect_err = connect_res.as_ref().ok().and_then(Option::as_ref);
                    let info = tcp_connect_failure_info(&steps, step_idx, connect_err);
                    cleanup_check_socket(check, fdtab, poller);
                    let event = check.on_failure_full("L4CON", "Layer4 connection problem", duration, None, Some(info));
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
                recv_buf.clear();
                send_offset = 0;

                let connected = connect_check(check, Some(target_addr));
                if let Ok((sock, immediate)) = connected {
                        let raw_fd = sock.as_raw_fd();
                        check.run.check_fd = Some(raw_fd);
                        check.run.tcp_connect_step = Some(step_idx);
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
                        check.run.sub_state = CheckSubState::TcpRunning {
                            step_idx,
                            send_offset,
                            recv_buf,
                        };
                        return Ok(CheckStep::pending(Some(check.exp)));
                }
                
                let info = tcp_connect_failure_info(&steps, step_idx, connected.err().as_ref());
                cleanup_check_socket(check, fdtab, poller);
                let event = check.on_failure_full("L4CON", "Layer4 connection problem", duration, None, Some(info));
                let next = check.schedule_next(now);
                check.next_check = next;
                return Ok(CheckStep {
                    next: Some(next),
                    event,
                });
            }
            ResolvedTcpStep::Send(data) => {
                // A connect that passed left its socket in place.
                let sock = check.sock.as_ref().ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;

                let raw_fd = sock.as_raw_fd();
                if send_offset == 0 {
                    // The input buffer is released when a `send` is evaluated.
                    recv_buf.clear();
                }
                while send_offset < data.len() {
                    match check.xprt.send(sock.as_fd(), &data[send_offset..]) {
                        Ok(Io::Done(n)) => {
                            send_offset += n;
                        }
                        Ok(Io::WouldBlock) => {
                            fdtab.clear_ready(raw_fd, false, true);
                            check.run.sub_state = CheckSubState::TcpRunning {
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
                let sock = check.sock.as_ref().ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;

                let raw_fd = sock.as_raw_fd();
                fdtab.set_interest(raw_fd, Interest::READ);
                let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), true, false);

                let mut buf = [0u8; 4096];
                let mut eof = false;

                while recv_buf.len() < TCP_CHECK_BUFSIZE {
                    match check.xprt.recv(sock.as_fd(), &mut buf) {
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
                // No more data is coming: the end of the response, or a full buffer.
                let last_read = eof || recv_buf.len() >= TCP_CHECK_BUFSIZE;

                // `tcpcheck_eval_recv` / `tcpcheck_eval_expect`: nothing is evaluated on an
                // empty buffer until the response ends, and an inconclusive rule waits and
                // resumes from the head of its run of `expect` rules (which is also the step
                // a timeout then names). Matched data is not consumed; a `send` or a new
                // `connect` drops it.
                let decided = check_reply::tcp_expect(pattern, *min_recv, &recv_buf, last_read);
                let wait = decided.is_none();
                let matched = decided.unwrap_or(false);
                if wait {
                    fdtab.clear_ready(raw_fd, true, false);
                    check.run.sub_state = CheckSubState::TcpRunning {
                        step_idx: tcp_expect_head(&steps, step_idx),
                        send_offset,
                        recv_buf,
                    };
                    return Ok(CheckStep::pending(Some(check.exp)));
                }
                if matched != *negate {
                    step_idx += 1;
                } else {
                    let info = tcp_expect_failure_info(&steps, step_idx, recv_buf.is_empty(), matched);
                    cleanup_check_socket(check, fdtab, poller);
                    let event = check.on_failure_full("L7RSP", "Layer7 invalid response", duration, None, Some(info));
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
    // HAProxy's tcp-check success carries `info: "(tcp-check)"` (measured: a two-connect
    // script logs `Layer7 check passed, code: 0, info: "(tcp-check)"`).
    let (desc, http_code, info) = if code == "L4OK" {
        ("Layer4 check passed", None, Some("(tcp-check)".to_string()))
    } else {
        ("Layer7 check passed", Some(0), Some("(tcp-check)".to_string()))
    };
    let event = check.on_success_full(code, desc, duration, http_code, info);
    let next = check.schedule_next(now);
    check.next_check = next;
    Ok(CheckStep {
        next: Some(next),
        event,
    })
}

/// Ends a check on a reply verdict from [`check_reply`]: closes the socket, records the
/// result and schedules the next check.
fn finish_reply(
    check: &mut ServerCheckState,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
    duration: u32,
    v: check_reply::Verdict,
) -> CheckStep {
    cleanup_check_socket(check, fdtab, poller);
    let event = if v.ok {
        check.on_success_full(v.status, v.desc, duration, v.code, v.info)
    } else {
        check.on_failure_full(v.status, v.desc, duration, v.code, v.info)
    };
    let next = check.schedule_next(now);
    check.next_check = next;
    CheckStep { next: Some(next), event }
}

/// Connects a check to `addr` (the server's unless given) and, when the server line asks
/// for it (`check-ssl`, or `ssl` inherited), puts the check's TLS over the socket. This
/// is where `check-ssl` reaches the check (T113). A TLS check never takes the immediate
/// path: its handshake runs from the `*Connecting` state ([`drive_check_handshake`]).
fn connect_check(check: &mut ServerCheckState, addr: Option<SocketAddr>) -> io::Result<(OwnedFd, bool)> {
    let addr = addr.unwrap_or(check.addr);
    let (sock, immediate) = raw::connect(addr)?;
    let Some(tls) = check.tls.as_ref() else {
        check.xprt = ServerXprt::Plain;
        return Ok((sock, immediate));
    };
    let host = check_host(check);
    check.xprt = tls.connect(&sock, host.as_deref(), addr.ip());
    Ok((sock, false))
}

/// The Host header an HTTP check sends, the automatic SNI of a TLS check
/// (`tcpcheck_connect_auto_sni`). A log-format value is taken as written.
fn check_host(check: &ServerCheckState) -> Option<String> {
    let Some(ResolvedCheckConfig::Http(chk)) = check.resolved_config.as_deref() else { return None };
    chk.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone())
        .or_else(|| chk.host.clone())
}

/// Where a check's TLS handshake stands.
enum Handshake {
    /// A plaintext check, or a handshake already complete.
    Ready,
    /// Still going: the poller will bring the check back.
    Pending,
    /// Failed, with `HAProxy`'s wording for the log.
    Failed(String),
}

/// Drives the TLS handshake of a check whose socket is connected.
fn drive_check_handshake(check: &mut ServerCheckState, fdtab: &mut FdTab, poller: &mut Poller, raw_fd: RawFd) -> Handshake {
    if !check.xprt.is_tls() || check.xprt.is_ready() {
        return Handshake::Ready;
    }
    // A check past its connect always has its socket; a missing one reads as a failed
    // handshake, through the arm below.
    let step = check.sock.as_ref().map_or_else(|| Err(io::ErrorKind::NotConnected.into()), |s| check.xprt.handshake(s.as_fd()));
    match step {
        Ok(true) => Handshake::Ready,
        Ok(false) => {
            let interest = Interest { readable: true, writable: check.xprt.wants_write() };
            fdtab.set_interest(raw_fd, interest);
            if let Some(sock) = check.sock.as_ref() {
                let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), interest.readable, interest.writable);
            }
            Handshake::Pending
        }
        Err(e) => {
            // `HAProxy`'s `conn_err_code_str`: a certificate the name check refused is
            // reported apart from the other handshake failures.
            let name_mismatch = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()).is_some_and(|e| {
                matches!(
                    e,
                    rustls::Error::InvalidCertificate(
                        rustls::CertificateError::NotValidForName | rustls::CertificateError::NotValidForNameContext { .. }
                    )
                )
            });
            Handshake::Failed(
                if name_mismatch {
                    "Server presented an SSL certificate different from the configured one"
                } else {
                    "SSL handshake failure"
                }
                .to_string(),
            )
        }
    }
}

/// Ends a check whose TLS handshake failed: `L6RSP`, as `HAProxy` reports it.
fn fail_check_l6(check: &mut ServerCheckState, fdtab: &mut FdTab, poller: &mut Poller, now: Tick, duration: u32, info: String) -> CheckStep {
    cleanup_check_socket(check, fdtab, poller);
    let event = check.on_failure_full("L6RSP", "Layer6 invalid response", duration, None, Some(info));
    let next = check.schedule_next(now);
    check.next_check = next;
    CheckStep { next: Some(next), event }
}

pub fn cleanup_check_socket(check: &mut ServerCheckState, fdtab: &mut FdTab, poller: &mut Poller) {
    if let Some(sock) = check.sock.take() {
        check.xprt.send_close_notify(sock.as_fd());
        let _ = poller.delete(sock.as_fd());
    }
    check.xprt = ServerXprt::Plain;
    if let Some(raw_fd) = check.run.check_fd {
        fdtab.remove(raw_fd);
    }
    check.run.release();
    check.in_progress = false;
    check.exp = Tick::ETERNITY;
}

#[allow(clippy::too_many_lines, clippy::unnecessary_wraps)]
fn progress_redis_check(
    check: &mut ServerCheckState,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
    duration: u32,
) -> io::Result<CheckStep> {
    let Some(raw_fd) = check.run.check_fd else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };
    let Some(sock) = check.sock.as_ref() else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    let CheckSubState::RedisRunning {
        mut phase,
        mut send_offset,
        mut recv_buf,
    } = check.run.sub_state.clone()
    else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    if phase == 0 {
        let ping_req = b"*1\r\n$4\r\nPING\r\n";
        while send_offset < ping_req.len() {
            match check.xprt.send(sock.as_fd(), &ping_req[send_offset..]) {
                Ok(Io::Done(n)) => {
                    send_offset += n;
                }
                Ok(Io::WouldBlock) => {
                    fdtab.clear_ready(raw_fd, false, true);
                    check.run.sub_state = CheckSubState::RedisRunning {
                        phase,
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
        phase = 1;
        send_offset = 0;
        fdtab.set_interest(raw_fd, Interest::READ);
        let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), true, false);
    }

    if phase == 1 {
        // True once nothing more is coming: the server closed, or one buffer is full.
        let eof = recv_check_reply(&mut check.xprt, sock.as_fd(), &mut recv_buf);

        let Some(v) = check_reply::redis(&recv_buf, eof) else {
            fdtab.clear_ready(raw_fd, true, false);
            check.run.sub_state = CheckSubState::RedisRunning { phase, send_offset, recv_buf };
            return Ok(CheckStep::pending(Some(check.exp)));
        };
        return Ok(finish_reply(check, fdtab, poller, now, duration, v));
    }

    cleanup_check_socket(check, fdtab, poller);
    let next = check.schedule_next(now);
    Ok(CheckStep::pending(Some(next)))
}

#[allow(clippy::too_many_lines, clippy::unnecessary_wraps)]
fn progress_smtp_check(
    check: &mut ServerCheckState,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
    duration: u32,
) -> io::Result<CheckStep> {
    let Some(raw_fd) = check.run.check_fd else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };
    let Some(sock) = check.sock.as_ref() else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    let CheckSubState::SmtpRunning {
        mut phase,
        cmd,
        mut send_offset,
        mut recv_buf,
    } = check.run.sub_state.clone()
    else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    if phase == 0 {
        fdtab.set_interest(raw_fd, Interest::READ);
        let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), true, false);

        // True once nothing more is coming: the server closed, or one buffer is full.
        let eof = recv_check_reply(&mut check.xprt, sock.as_fd(), &mut recv_buf);

        let Some(greeting) = check_reply::smtp_greeting(&recv_buf, eof) else {
            fdtab.clear_ready(raw_fd, true, false);
            check.run.sub_state = CheckSubState::SmtpRunning {
                phase,
                cmd,
                send_offset,
                recv_buf,
            };
            return Ok(CheckStep::pending(Some(check.exp)));
        };

        match greeting {
            check_reply::SmtpGreeting::Accepted => {
                phase = 1;
                send_offset = 0;
                recv_buf.clear();
                fdtab.set_interest(raw_fd, Interest::WRITE);
                let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), false, true);
            }
            check_reply::SmtpGreeting::Failed(code, info) => {
                cleanup_check_socket(check, fdtab, poller);
                let event = check.on_failure_full("L7STS", "Layer7 wrong status", duration, Some(code), info);
                let next = check.schedule_next(now);
                check.next_check = next;
                return Ok(CheckStep { next: Some(next), event });
            }
            check_reply::SmtpGreeting::Invalid(info) => {
                cleanup_check_socket(check, fdtab, poller);
                let event = check.on_failure_full("L7RSP", "Layer7 invalid response", duration, None, info);
                let next = check.schedule_next(now);
                check.next_check = next;
                return Ok(CheckStep { next: Some(next), event });
            }
        }
    }

    if phase == 1 {
        let req_bytes = format!("{cmd}\r\n").into_bytes();
        while send_offset < req_bytes.len() {
            match check.xprt.send(sock.as_fd(), &req_bytes[send_offset..]) {
                Ok(Io::Done(n)) => {
                    send_offset += n;
                }
                Ok(Io::WouldBlock) => {
                    fdtab.clear_ready(raw_fd, false, true);
                    check.run.sub_state = CheckSubState::SmtpRunning {
                        phase,
                        cmd,
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
        phase = 2;
        send_offset = 0;
        recv_buf.clear();
        fdtab.set_interest(raw_fd, Interest::READ);
        let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), true, false);
        fdtab.clear_ready(raw_fd, false, true);
        check.run.sub_state = CheckSubState::SmtpRunning {
            phase,
            cmd,
            send_offset,
            recv_buf,
        };
        return Ok(CheckStep::pending(Some(check.exp)));
    }

    if phase == 2 {
        // True once nothing more is coming: the server closed, or one buffer is full.
        let eof = recv_check_reply(&mut check.xprt, sock.as_fd(), &mut recv_buf);

        let Some(reply) = check_reply::smtp_reply(&recv_buf, eof) else {
            fdtab.clear_ready(raw_fd, true, false);
            check.run.sub_state = CheckSubState::SmtpRunning {
                phase,
                cmd,
                send_offset,
                recv_buf,
            };
            return Ok(CheckStep::pending(Some(check.exp)));
        };

        match reply {
            check_reply::SmtpEhlo::Accepted => {
                phase = 3;
                send_offset = 0;
                recv_buf.clear();
                fdtab.set_interest(raw_fd, Interest::WRITE);
                let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), false, true);
            }
            check_reply::SmtpEhlo::Failed(code, info) => {
                cleanup_check_socket(check, fdtab, poller);
                let event = check.on_failure_full("L7STS", "Layer7 wrong status", duration, Some(code), info);
                let next = check.schedule_next(now);
                check.next_check = next;
                return Ok(CheckStep {
                    next: Some(next),
                    event,
                });
            }
        }
    }

    if phase == 3 {
        let quit_req = b"QUIT\r\n";
        while send_offset < quit_req.len() {
            match check.xprt.send(sock.as_fd(), &quit_req[send_offset..]) {
                Ok(Io::Done(n)) => {
                    send_offset += n;
                }
                Ok(Io::WouldBlock) => {
                    fdtab.clear_ready(raw_fd, false, true);
                    check.run.sub_state = CheckSubState::SmtpRunning {
                        phase,
                        cmd,
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
        phase = 4;
        send_offset = 0;
        recv_buf.clear();
        fdtab.set_interest(raw_fd, Interest::READ);
        let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), true, false);
        fdtab.clear_ready(raw_fd, false, true);
        check.run.sub_state = CheckSubState::SmtpRunning {
            phase,
            cmd,
            send_offset,
            recv_buf,
        };
        return Ok(CheckStep::pending(Some(check.exp)));
    }

    if phase == 4 {
        // The reply is judged on four bytes (the QUIT answer needs no CRLF).
        let eof = recv_check_reply(&mut check.xprt, sock.as_fd(), &mut recv_buf);

        let Some(answer) = check_reply::smtp_quit(&recv_buf, eof) else {
            fdtab.clear_ready(raw_fd, true, false);
            check.run.sub_state = CheckSubState::SmtpRunning {
                phase,
                cmd,
                send_offset,
                recv_buf,
            };
            return Ok(CheckStep::pending(Some(check.exp)));
        };

        cleanup_check_socket(check, fdtab, poller);
        let event = match answer {
            Ok((code, info)) => check.on_success_full("L7OK", "Layer7 check passed", duration, Some(code), info),
            Err((code, info)) => check.on_failure_full("L7STS", "Layer7 wrong status", duration, Some(code), info),
        };
        let next = check.schedule_next(now);
        check.next_check = next;
        return Ok(CheckStep {
            next: Some(next),
            event,
        });
    }

    cleanup_check_socket(check, fdtab, poller);
    let next = check.schedule_next(now);
    Ok(CheckStep::pending(Some(next)))
}

/// How a protocol check's reply ends the check: `HAProxy`'s statuses for the custom
/// `expect` rules of `ldap-check` and `mysql-check` (src/tcpcheck.c). `None` from a parser
/// is "wait for more data".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProtoReply {
    /// L7OK, code 0.
    Passed(Option<String>),
    /// L7RSP.
    Invalid(Option<String>),
    /// L7STS, with the server's code.
    WrongStatus(u16, Option<String>),
}

/// Byte `i` of a reply, 0 past its end. `HAProxy` reads past the end of the data in places
/// (into whatever its buffer held before); Ibex reads zeros there, which is what a fresh
/// buffer holds.
fn byte_at(buf: &[u8], i: usize) -> u8 {
    buf.get(i).copied().unwrap_or(0)
}

/// The bytes from `from` to the first NUL or the end, as `HAProxy` prints a C string;
/// `None` when that is empty.
fn c_string_at(buf: &[u8], from: usize) -> Option<String> {
    let rest = buf.get(from..).unwrap_or_default();
    let s = &rest[..rest.iter().position(|&b| b == 0).unwrap_or(rest.len())];
    (!s.is_empty()).then(|| String::from_utf8_lossy(s).into_owned())
}

const NOT_LDAPV3: &str = "Not LDAPv3 protocol";

/// `option ldap-check`'s reply: `expect rbinary ^30 min-recv 14 on-error "Not LDAPv3
/// protocol"`, then `tcpcheck_ldap_expect_bindrsp`. `last_read`: no more data is coming.
pub(crate) fn ldap_bind_reply(buf: &[u8], last_read: bool) -> Option<ProtoReply> {
    if !last_read && buf.len() < 14 {
        return None;
    }
    if buf.first() != Some(&0x30) {
        return Some(ProtoReply::Invalid(Some(NOT_LDAPV3.into())));
    }
    let too_short = || last_read.then_some(ProtoReply::Invalid(None));
    let at = |i| byte_at(buf, i);
    // The LDAPMessage length: one byte, or 0x82 / 0x84 and two or four.
    let mut nbytes = 0;
    let msglen = if at(1) & 0x80 == 0 {
        usize::from(at(1))
    } else {
        nbytes = usize::from(at(1) & 0x7f);
        if buf.len() - 1 < 1 + nbytes {
            return too_short();
        }
        match nbytes {
            4 => u32::from_be_bytes([at(2), at(3), at(4), at(5)]) as usize,
            2 => usize::from(u16::from_be_bytes([at(2), at(3)])),
            _ => return Some(ProtoReply::Invalid(Some(NOT_LDAPV3.into()))),
        }
    };
    let mut ptr = 2 + nbytes;
    // `end - ptr < msglen` in C compares unsigned: never true once `ptr` is past the end.
    if buf.len() >= ptr && buf.len() - ptr < msglen {
        return too_short();
    }
    // messageID 1, bindResponse.
    if [at(ptr), at(ptr + 1), at(ptr + 2), at(ptr + 3)] != [0x02, 0x01, 0x01, 0x61] {
        return Some(ProtoReply::Invalid(Some(NOT_LDAPV3.into())));
    }
    ptr += 4;
    let nbytes = if at(ptr) & 0x80 == 0 { 0 } else { usize::from(at(ptr) & 0x7f) };
    // Four real bytes matched above, so `ptr` is within the reply.
    if buf.len() - ptr < 1 + nbytes + 2 + 1 {
        return too_short();
    }
    ptr += 1 + nbytes;
    if [at(ptr), at(ptr + 1)] != [0x0a, 0x01] {
        return Some(ProtoReply::Invalid(Some(NOT_LDAPV3.into())));
    }
    Some(match at(ptr + 2) {
        0 => ProtoReply::Passed(Some("Success".into())),
        code => ProtoReply::WrongStatus(
            u16::from(code),
            Some("See RFC: http://tools.ietf.org/html/rfc4511#section-4.1.9".into()),
        ),
    })
}

/// `option mysql-check`'s reply (`tcpcheck_mysql_expect_iniths`, then with `user`
/// `tcpcheck_mysql_expect_ok` on the packet after the greeting). The info on success is the
/// server version from the greeting; on an error packet, the rest of the data.
pub(crate) fn mysql_reply(buf: &[u8], last_read: bool, with_user: bool) -> Option<ProtoReply> {
    if buf.is_empty() {
        // A custom rule is not evaluated on an empty buffer: the generic message, at the
        // step of the first `expect` (after `connect`, and `send` with a user).
        let step = if with_user { 3 } else { 2 };
        return last_read.then(|| ProtoReply::Invalid(Some(format!("TCPCHK got an empty response at step {step}"))));
    }
    let packet = |offset: usize, last_rule: bool| -> Option<Option<ProtoReply>> {
        let at = |i| byte_at(buf, i);
        let plen = usize::from(at(offset)) | usize::from(at(offset + 1)) << 8 | usize::from(at(offset + 2)) << 16;
        if buf.len() < offset + 4 || buf.len() < offset + plen + 4 {
            return Some(last_read.then_some(ProtoReply::Invalid(None)));
        }
        if at(offset + 4) == 0xff {
            let code = u16::from(at(offset + 5)) | u16::from(at(offset + 6)) << 8;
            return Some(Some(ProtoReply::WrongStatus(code, c_string_at(buf, offset + 7))));
        }
        last_rule.then(|| Some(ProtoReply::Passed(c_string_at(buf, 5))))
    };
    if let Some(verdict) = packet(0, !with_user) {
        return verdict;
    }
    let hslen = 4 + (usize::from(buf[0]) | usize::from(byte_at(buf, 1)) << 8 | usize::from(byte_at(buf, 2)) << 16);
    packet(hslen, true).flatten()
}

/// `HAProxy` keeps a check's info in `char desc[HCHK_DESC_LEN]` (128) and copies it with
/// `strncpy(.., HCHK_DESC_LEN - 1)` (src/check.c): what a server put in its reply is cut to
/// 127 bytes. Cut on a character boundary here, since the info is a `String`.
const HCHK_DESC_MAX: usize = 127;

fn cut_check_desc(mut info: String) -> String {
    if info.len() > HCHK_DESC_MAX {
        let mut end = HCHK_DESC_MAX;
        while !info.is_char_boundary(end) {
            end -= 1;
        }
        info.truncate(end);
    }
    info
}

/// Reads what has arrived into `recv_buf`, never past `TCP_CHECK_BUFSIZE` (`HAProxy` reads
/// one buffer). True once no more is coming: the peer closed, or the buffer is full.
fn recv_check_reply(xprt: &mut ServerXprt, fd: std::os::fd::BorrowedFd<'_>, recv_buf: &mut Vec<u8>) -> bool {
    let mut buf = [0u8; 4096];
    while recv_buf.len() < TCP_CHECK_BUFSIZE {
        let room = (TCP_CHECK_BUFSIZE - recv_buf.len()).min(buf.len());
        match xprt.recv(fd, &mut buf[..room]) {
            Ok(Io::Done(n)) => recv_buf.extend_from_slice(&buf[..n]),
            Ok(Io::WouldBlock) => return false,
            Ok(Io::Eof | Io::Closed) | Err(_) => return true,
        }
    }
    true
}

/// Ends a protocol check on its reply's verdict.
fn end_proto_check(
    check: &mut ServerCheckState,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
    duration: u32,
    reply: ProtoReply,
) -> CheckStep {
    cleanup_check_socket(check, fdtab, poller);
    let event = match reply {
        ProtoReply::Passed(info) => check.on_success_full("L7OK", "Layer7 check passed", duration, Some(0), info),
        ProtoReply::Invalid(info) => check.on_failure_full("L7RSP", "Layer7 invalid response", duration, None, info),
        ProtoReply::WrongStatus(code, info) => {
            check.on_failure_full("L7STS", "Layer7 wrong status", duration, Some(code), info)
        }
    };
    let next = check.schedule_next(now);
    check.next_check = next;
    CheckStep { next: Some(next), event }
}

#[allow(clippy::too_many_lines, clippy::unnecessary_wraps)]
fn progress_ldap_check(
    check: &mut ServerCheckState,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
    duration: u32,
) -> io::Result<CheckStep> {
    let Some(raw_fd) = check.run.check_fd else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };
    let Some(sock) = check.sock.as_ref() else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    let CheckSubState::LdapRunning {
        mut phase,
        mut send_offset,
        mut recv_buf,
    } = check.run.sub_state.clone()
    else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    if phase == 0 {
        let ldap_req: [u8; 14] = [
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
        ];
        while send_offset < ldap_req.len() {
            match check.xprt.send(sock.as_fd(), &ldap_req[send_offset..]) {
                Ok(Io::Done(n)) => {
                    send_offset += n;
                }
                Ok(Io::WouldBlock) => {
                    fdtab.clear_ready(raw_fd, false, true);
                    check.run.sub_state = CheckSubState::LdapRunning {
                        phase,
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
        phase = 1;
        send_offset = 0;
        recv_buf.clear();
        fdtab.set_interest(raw_fd, Interest::READ);
        let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), true, false);
    }

    if phase == 1 {
        let last_read = recv_check_reply(&mut check.xprt, sock.as_fd(), &mut recv_buf);
        let Some(reply) = ldap_bind_reply(&recv_buf, last_read) else {
            fdtab.clear_ready(raw_fd, true, false);
            check.run.sub_state = CheckSubState::LdapRunning { phase, send_offset, recv_buf };
            return Ok(CheckStep::pending(Some(check.exp)));
        };
        return Ok(end_proto_check(check, fdtab, poller, now, duration, reply));
    }

    cleanup_check_socket(check, fdtab, poller);
    let next = check.schedule_next(now);
    Ok(CheckStep::pending(Some(next)))
}

fn build_mysql_req(user: &str, version: MysqlCheckVersion) -> Vec<u8> {
    let ubytes = user.as_bytes();
    let mut pkt = Vec::new();
    match version {
        MysqlCheckVersion::Pre41 => {
            let packetlen = ubytes.len() + 7;
            pkt.extend_from_slice(&[
                (packetlen & 0xff) as u8,
                ((packetlen >> 8) & 0xff) as u8,
                ((packetlen >> 16) & 0xff) as u8,
                1,
                0x00,
                0x80,
                0x00,
                0x00,
                0x01,
            ]);
            pkt.extend_from_slice(ubytes);
            pkt.push(0);
            pkt.push(0);
            pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x01]);
        }
        MysqlCheckVersion::Post41 => {
            let packetlen = ubytes.len() + 7 + 27;
            pkt.extend_from_slice(&[
                (packetlen & 0xff) as u8,
                ((packetlen >> 8) & 0xff) as u8,
                ((packetlen >> 16) & 0xff) as u8,
                1,
                0x00,
                0x82,
                0x00,
                0x00,
                0x00,
                0x80,
                0x00,
                0x01,
                0x21,
            ]);
            pkt.extend_from_slice(&[0u8; 23]);
            pkt.extend_from_slice(ubytes);
            pkt.push(0);
            pkt.push(0);
            pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x01]);
        }
        MysqlCheckVersion::Post80 => {
            let packetlen = ubytes.len() + 7 + 27 + 22;
            pkt.extend_from_slice(&[
                (packetlen & 0xff) as u8,
                ((packetlen >> 8) & 0xff) as u8,
                ((packetlen >> 16) & 0xff) as u8,
                1,
                0x00,
                0x82,
                0x08,
                0x00,
                0x00,
                0x80,
                0x00,
                0x01,
                0x21,
            ]);
            pkt.extend_from_slice(&[0u8; 23]);
            pkt.extend_from_slice(ubytes);
            pkt.push(0);
            pkt.push(0);
            pkt.extend_from_slice(b"mysql_native_password\0");
            pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x01]);
        }
    }
    pkt
}

#[allow(clippy::too_many_lines, clippy::unnecessary_wraps)]
fn progress_mysql_check(
    check: &mut ServerCheckState,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
    duration: u32,
) -> io::Result<CheckStep> {
    let Some(raw_fd) = check.run.check_fd else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };
    let Some(sock) = check.sock.as_ref() else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    let CheckSubState::MysqlRunning {
        mut phase,
        user,
        version,
        mut send_offset,
        req_buf,
        mut recv_buf,
    } = check.run.sub_state.clone()
    else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    if phase == 0 {
        if !req_buf.is_empty() {
            while send_offset < req_buf.len() {
                match check.xprt.send(sock.as_fd(), &req_buf[send_offset..]) {
                    Ok(Io::Done(n)) => {
                        send_offset += n;
                    }
                    Ok(Io::WouldBlock) => {
                        fdtab.clear_ready(raw_fd, false, true);
                        check.run.sub_state = CheckSubState::MysqlRunning {
                            phase,
                            user,
                            version,
                            send_offset,
                            req_buf,
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
        phase = 1;
        send_offset = 0;
        recv_buf.clear();
        fdtab.set_interest(raw_fd, Interest::READ);
        let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), true, false);
    }

    if phase == 1 {
        let last_read = recv_check_reply(&mut check.xprt, sock.as_fd(), &mut recv_buf);
        let Some(reply) = mysql_reply(&recv_buf, last_read, user.is_some()) else {
            fdtab.clear_ready(raw_fd, true, false);
            check.run.sub_state = CheckSubState::MysqlRunning {
                phase,
                user,
                version,
                send_offset,
                req_buf,
                recv_buf,
            };
            return Ok(CheckStep::pending(Some(check.exp)));
        };
        return Ok(end_proto_check(check, fdtab, poller, now, duration, reply));
    }

    cleanup_check_socket(check, fdtab, poller);
    let next = check.schedule_next(now);
    Ok(CheckStep::pending(Some(next)))
}

#[allow(clippy::too_many_lines, clippy::unnecessary_wraps)]
fn progress_pgsql_check(
    check: &mut ServerCheckState,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
    duration: u32,
) -> io::Result<CheckStep> {
    let Some(raw_fd) = check.run.check_fd else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };
    let Some(sock) = check.sock.as_ref() else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    let CheckSubState::PgsqlRunning {
        mut phase,
        user,
        mut send_offset,
        mut req_buf,
        mut recv_buf,
    } = check.run.sub_state.clone()
    else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    if phase == 0 {
        if req_buf.is_empty() {
            let ubytes = user.as_bytes();
            let packetlen = (4 + 4 + 5 + ubytes.len() + 1 + 1) as u32;
            req_buf.extend_from_slice(&packetlen.to_be_bytes());
            req_buf.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
            req_buf.extend_from_slice(b"user\0");
            req_buf.extend_from_slice(ubytes);
            req_buf.extend_from_slice(b"\0\0");
        }

        while send_offset < req_buf.len() {
            match check.xprt.send(sock.as_fd(), &req_buf[send_offset..]) {
                Ok(Io::Done(n)) => {
                    send_offset += n;
                }
                Ok(Io::WouldBlock) => {
                    fdtab.clear_ready(raw_fd, false, true);
                    check.run.sub_state = CheckSubState::PgsqlRunning {
                        phase,
                        user,
                        send_offset,
                        req_buf,
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
        phase = 1;
        send_offset = 0;
        recv_buf.clear();
        fdtab.set_interest(raw_fd, Interest::READ);
        let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), true, false);
    }

    if phase == 1 {
        // True once nothing more is coming: the server closed, or one buffer is full.
        let eof = recv_check_reply(&mut check.xprt, sock.as_fd(), &mut recv_buf);

        let Some(v) = check_reply::pgsql(&recv_buf, eof) else {
            fdtab.clear_ready(raw_fd, true, false);
            check.run.sub_state = CheckSubState::PgsqlRunning { phase, user, send_offset, req_buf, recv_buf };
            return Ok(CheckStep::pending(Some(check.exp)));
        };
        return Ok(finish_reply(check, fdtab, poller, now, duration, v));
    }

    cleanup_check_socket(check, fdtab, poller);
    let next = check.schedule_next(now);
    Ok(CheckStep::pending(Some(next)))
}

#[allow(clippy::too_many_lines, clippy::unnecessary_wraps)]
fn progress_ssl_hello_check(
    check: &mut ServerCheckState,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
    duration: u32,
) -> io::Result<CheckStep> {
    let Some(raw_fd) = check.run.check_fd else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };
    let Some(sock) = check.sock.as_ref() else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    let CheckSubState::SslHelloRunning {
        mut phase,
        mut send_offset,
        mut recv_buf,
    } = check.run.sub_state.clone()
    else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    if phase == 0 {
        let mut client_hello = Vec::with_capacity(126);
        client_hello.extend_from_slice(&[
            0x16, 0x03, 0x00, 0x00, 0x79, 0x01, 0x00, 0x00, 0x75, 0x03, 0x00,
        ]);
        let ts = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32)
            .to_be_bytes();
        client_hello.extend_from_slice(&ts);
        client_hello.extend_from_slice(b"HAPROXYSSLCHK\nHAPROXYSSLCHK\n");
        client_hello.extend_from_slice(&[0x00, 0x00, 0x4e]);
        for c in 1u16..=0x1b {
            client_hello.extend_from_slice(&c.to_be_bytes());
        }
        for c in 0x2fu16..=0x3a {
            client_hello.extend_from_slice(&c.to_be_bytes());
        }
        client_hello.extend_from_slice(&[0x01, 0x00]);

        while send_offset < client_hello.len() {
            match check.xprt.send(sock.as_fd(), &client_hello[send_offset..]) {
                Ok(Io::Done(n)) => {
                    send_offset += n;
                }
                Ok(Io::WouldBlock) => {
                    fdtab.clear_ready(raw_fd, false, true);
                    check.run.sub_state = CheckSubState::SslHelloRunning {
                        phase,
                        send_offset,
                        recv_buf,
                    };
                    return Ok(CheckStep::pending(Some(check.exp)));
                }
                Ok(Io::Closed | Io::Eof) | Err(_) => {
                    cleanup_check_socket(check, fdtab, poller);
                    let event = check.on_failure_full(
                        "L6RSP",
                        "Layer6 invalid response",
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
        phase = 1;
        send_offset = 0;
        recv_buf.clear();
        fdtab.set_interest(raw_fd, Interest::READ);
        let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), true, false);
    }

    if phase == 1 {
        // True once nothing more is coming: the server closed, or one buffer is full.
        let eof = recv_check_reply(&mut check.xprt, sock.as_fd(), &mut recv_buf);

        let Some(v) = check_reply::ssl_hello(&recv_buf, eof) else {
            fdtab.clear_ready(raw_fd, true, false);
            check.run.sub_state = CheckSubState::SslHelloRunning { phase, send_offset, recv_buf };
            return Ok(CheckStep::pending(Some(check.exp)));
        };
        return Ok(finish_reply(check, fdtab, poller, now, duration, v));
    }

    cleanup_check_socket(check, fdtab, poller);
    let next = check.schedule_next(now);
    Ok(CheckStep::pending(Some(next)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HAProxy prints the bare `strerror(errno)` text in a check's `info:` field:
    ///
    ///     info: "General socket error (Network is unreachable)"
    ///
    /// Rust's `io::Error` Display appends `" (os error N)"` to the same string, and
    /// checks/4be_1srv_smtpchk_httpchk_layer47errors.vtc anchors on the closing paren:
    ///
    ///     info: "General socket error \(Network.* unreachable\)"
    ///
    /// which the suffix makes unmatchable, since the text no longer ends in
    /// `unreachable)`.
    #[test]
    fn l4_connect_errors_read_like_strerror_not_like_rust() {
        let unreachable = io::Error::from_raw_os_error(101);
        assert_eq!(
            format_l4_connect_error(&unreachable),
            "General socket error (Network is unreachable)"
        );

        // ECONNREFUSED keeps its own wording, which HAProxy special-cases too.
        let refused = io::Error::from_raw_os_error(111);
        assert_eq!(format_l4_connect_error(&refused), "ECONNREFUSED returned by OS (Connection refused)");
    }

    /// HAProxy seeds a fresh check's status with `HCHK_STATUS_INI` ("Initializing"), a
    /// placeholder that matches no real result code, so `report = (status != prev_status)`
    /// (src/check.c) is always true for the very first check outcome and it is always
    /// logged. A server with `rise == 1` starts at full health already, so its first
    /// successful check is the only chance to log the transition to a confirmed UP --
    /// reg-test checks/40be_2srv_odd_health_checks.vtc depends on exactly this line
    /// appearing under `option log-health-checks`.
    #[test]
    fn first_success_after_boot_is_reported_under_log_health_checks() {
        let config = ServerCheckConfig {
            rise: 1,
            fall: 1,
            ..ServerCheckConfig::default()
        };
        let mut state = ServerCheckState::new(0, 0, "127.0.0.1:1".parse().unwrap(), config, Tick(0));
        let event = state.on_success(5);
        assert!(
            event.is_some(),
            "the first successful check after boot must be reported under option log-health-checks"
        );
    }

    /// `srv_check_result` of `show servers state`: `check_statuses[].result` in
    /// `src/check.c`, from the table (T274 D2). `HANA` needs `observe`/`on-error` and
    /// `CHECKED` is only an internal marker, and `L7OKC` needs `ok-status`: Ibex refuses
    /// all three at parse time, so these three rows are checked here and unreachable from
    /// a configuration.
    #[test]
    fn check_result_follows_the_status_table() {
        let r = |c| check_result_of(c);
        // UNKNOWN 0, NEUTRAL 1, FAILED 2, PASSED 3, CONDPASS 4
        assert_eq!([r("UNK"), r("INI"), r("CHECKED")], [0, 0, 1]);
        assert_eq!([r("HANA"), r("SOCKERR"), r("L4TOUT"), r("L4CON"), r("L6TOUT"), r("L6RSP")], [2; 6]);
        assert_eq!([r("L7TOUT"), r("L7RSP"), r("L7STS"), r("PROCERR"), r("PROCTOUT")], [2; 5]);
        assert_eq!([r("L4OK"), r("L6OK"), r("L7OK"), r("L7OKD"), r("PROCOK")], [3; 5]);
        assert_eq!([r("L7OKC"), r("L7OKCD")], [4; 2]);
    }

    /// The state word of `X-Haproxy-Server-State` (`httpchk_build_status_header`) across
    /// the health counter, `rise 2 fall 2`. `HAProxy` 3.5-dev8-885761-29, 2026-10-03, sent
    /// `UP 0/2` with health 1 while running, `UP` at full health, `DOWN` at 0; `DOWN 1/2`
    /// (health 1 while stopped) and `no check` (check disabled) are the same function's
    /// other branches, read from `src/check.c`.
    #[test]
    fn server_state_word_follows_the_health_counter() {
        let config = ServerCheckConfig { rise: 2, fall: 2, ..ServerCheckConfig::default() };
        let mut s = ServerCheckState::new(0, 0, "127.0.0.1:1".parse().unwrap(), config, Tick(0));
        let word = |s: &ServerCheckState| server_state_header(s, &[]);
        s.status = ServerStatus::Up;
        s.health = 3;
        assert_eq!(word(&s), "UP");
        s.health = 1;
        assert_eq!(word(&s), "UP 0/2");
        s.status = ServerStatus::Down;
        assert_eq!(word(&s), "DOWN 1/2");
        s.health = 0;
        assert_eq!(word(&s), "DOWN");
        s.enabled = false;
        assert_eq!(word(&s), "no check");
    }
    fn connect(implicit: bool, rule_port: Option<u16>, comment: Option<&str>) -> ResolvedTcpStep {
        ResolvedTcpStep::Connect { port: rule_port, send_proxy: false, implicit, rule_port, comment: comment.map(String::from) }
    }

    fn expect(pattern: ResolvedTcpExpectPattern, negate: bool, comment: Option<&str>) -> ResolvedTcpStep {
        ResolvedTcpStep::Expect { pattern, negate, min_recv: -1, comment: comment.map(String::from) }
    }

    /// The words `HAProxy` puts after a failing tcp-check step: the step, what it did, its
    /// comment (own, or the `tcp-check comment` before it).
    #[test]
    fn tcp_step_suffix_names_what_the_step_was_doing() {
        let steps = vec![
            connect(true, None, None),
            ResolvedTcpStep::Comment("c1".into()),
            ResolvedTcpStep::Send(b"x".to_vec()),
            expect(ResolvedTcpExpectPattern::Binary(vec![0x61, 0x0A]), false, None),
            expect(ResolvedTcpExpectPattern::RString("a".into()), true, Some("own")),
            expect(ResolvedTcpExpectPattern::String("s".into()), false, None),
        ];
        assert_eq!(tcp_step_suffix(&steps, 0), " at initial connection step of tcp-check");
        assert_eq!(tcp_step_suffix(&steps, 1), " at step 1 of tcp-check");
        assert_eq!(tcp_step_suffix(&steps, 2), " at step 2 of tcp-check (send) comment: 'c1'");
        assert_eq!(tcp_step_suffix(&steps, 3), " at step 3 of tcp-check (expect binary '610A')");
        assert_eq!(tcp_step_suffix(&steps, 4), " at step 4 of tcp-check (expect regex) comment: 'own'");
        assert_eq!(tcp_step_suffix(&steps, 9), " at step 9 of tcp-check");
        let own = vec![connect(false, Some(7), Some("cc")), connect(false, None, None)];
        assert_eq!(tcp_step_suffix(&own, 0), " at step 1 of tcp-check (connect port 7) comment: 'cc'");
        assert_eq!(tcp_step_suffix(&own, 1), " at step 2 of tcp-check (connect)");
        // a wait resumes at the first inverse expect of the run, over comments
        let run = vec![
            connect(false, None, None),
            expect(ResolvedTcpExpectPattern::String("a".into()), true, None),
            ResolvedTcpStep::Comment("x".into()),
            expect(ResolvedTcpExpectPattern::String("b".into()), false, None),
            expect(ResolvedTcpExpectPattern::String("c".into()), false, None),
        ];
        assert_eq!(tcp_expect_head(&run, 4), 1);
        assert_eq!(tcp_expect_head(&run, 3), 1);
        assert_eq!(tcp_expect_head(&run, 1), 1);
    }

    #[test]
    fn a_timeout_while_connecting_is_layer_4() {
        let steps = vec![connect(false, None, None), expect(ResolvedTcpExpectPattern::String("a".into()), false, None)];
        assert_eq!(tcp_timeout_status(&steps, 0), ("L4TOUT", "Layer4 timeout", Some(" at step 1 of tcp-check (connect)".into())));
        assert_eq!(tcp_timeout_status(&steps, 1).0, "L7TOUT");
    }

    #[test]
    fn tcp_connect_failures_are_worded_as_haproxy_words_them() {
        let steps = vec![connect(false, None, None)];
        let refused = io::Error::from_raw_os_error(111);
        assert_eq!(
            tcp_connect_failure_info(&steps, 0, Some(&refused)),
            "ECONNREFUSED returned by OS (Connection refused) at step 1 of tcp-check (connect)"
        );
        let unreachable = io::Error::from_raw_os_error(101);
        assert!(tcp_connect_failure_info(&steps, 0, Some(&unreachable)).starts_with("General socket error (Network is unreachable)"));
        assert!(tcp_connect_failure_info(&steps, 0, None).starts_with("General socket error at step 1"));
    }

    #[test]
    fn response_parsing_follows_the_message_framing() {
        assert!(matches!(parse_http_response(b"HTT"), Ok(None)));
        assert!(parse_http_response(b"garbage not http").is_err());
        assert!(parse_http_response(b"HTTP/1.1 20 OK\r\n\r\n").is_err());
        assert!(parse_http_response(b"HTTP/1.1 200 OK\r\nbad header\r\n\r\n").is_err());
        let r = parse_http_response(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap().unwrap();
        assert!(r.ended && r.body.is_empty());
        let r = parse_http_response(b"HTTP/1.0 200 OK\n\nabc").unwrap().unwrap();
        assert!(!r.ended && r.body == b"abc" && r.reason == "OK");
        let r = parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc").unwrap().unwrap();
        assert!(!r.ended && r.body == b"abc");
        let r = parse_http_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n").unwrap().unwrap();
        assert!(r.ended && r.body == b"abc");
    }

    #[test]
    fn chunked_bodies_are_decoded_as_far_as_they_go() {
        assert_eq!(decode_chunked(b"3\r\nabc\r\n0\r\n\r\n"), (b"abc".to_vec(), true));
        assert_eq!(decode_chunked(b"3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"), (b"abcde".to_vec(), true));
        assert_eq!(decode_chunked(b"3\r\nab"), (b"ab".to_vec(), false));
        assert_eq!(decode_chunked(b"3\r\nabc"), (b"abc".to_vec(), false));
        assert_eq!(decode_chunked(b"3\r\nabc\r\n"), (b"abc".to_vec(), false));
        assert_eq!(decode_chunked(b"zz\r\n"), (Vec::new(), false));
        assert_eq!(decode_chunked(b"3"), (Vec::new(), false));
    }

    #[test]
    fn only_absolute_targets_take_the_host_authority() {
        assert_eq!(replace_authority("http://a/x?y", "h:1").as_deref(), Some("http://h:1/x?y"));
        assert_eq!(replace_authority("http://a", "h").as_deref(), Some("http://h"));
        assert_eq!(replace_authority("/x", "h"), None);
        assert_eq!(replace_authority("://a/x", "h"), None);
        assert_eq!(replace_authority("a b://a/x", "h"), None);
        assert!(http_version_at_least_11("HTTP/2") && http_version_at_least_11("HTTP/1.1"));
        assert!(!http_version_at_least_11("HTTP/1.0") && !http_version_at_least_11("1.1"));
    }

    #[test]
    fn header_expectations_match_names_and_values_as_haproxy_does() {
        let resp = HttpResp {
            status: 200,
            reason: "OK".into(),
            version: "HTTP/1.1".into(),
            headers: vec![("X-Abc".into(), "one, two".into())],
            body: Vec::new(),
            ended: true,
            parse_error: false,
        };
        let p = |mt, text| Pat { mt, text };
        let any = |full, n: Pat, v: Option<Pat>| hdr_expect_matches(&resp, full, n, v);
        assert!(any(false, p(MatchType::Str, "x-ABC"), None));
        assert!(any(false, p(MatchType::Beg, "X-A"), None));
        assert!(any(false, p(MatchType::End, "bc"), None));
        assert!(any(false, p(MatchType::Sub, "-ab"), None));
        assert!(any(false, p(MatchType::Reg, "^x-[a-c]+$"), None));
        assert!(!any(false, p(MatchType::End, "zz"), None));
        assert!(!any(false, p(MatchType::Sub, "zz"), None));
        let n = p(MatchType::Str, "x-abc");
        assert!(any(false, n, Some(p(MatchType::Str, "two"))));
        assert!(any(false, n, Some(p(MatchType::Beg, "tw"))));
        assert!(any(false, n, Some(p(MatchType::End, "wo"))));
        assert!(any(false, n, Some(p(MatchType::Sub, "w"))));
        assert!(any(false, n, Some(p(MatchType::Reg, "^t.o$"))));
        assert!(!any(true, n, Some(p(MatchType::Str, "two"))));
        assert!(any(true, n, Some(p(MatchType::Str, "one, two"))));
    }

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn not_ldapv3() -> Option<ProtoReply> {
        Some(ProtoReply::Invalid(Some(NOT_LDAPV3.into())))
    }

    /// Each reply measured on HAProxy 3.5-dev8 (T238), sent whole and the connection closed.
    #[test]
    fn ldap_replies_as_haproxy_judges_them() {
        let ok = Some(ProtoReply::Passed(Some("Success".into())));
        let short = Some(ProtoReply::Invalid(None));
        for (hex, want) in [
            ("", not_ldapv3()),
            ("0a", not_ldapv3()),
            ("30", not_ldapv3()),
            ("3000", not_ldapv3()),
            ("30020201", not_ldapv3()),
            ("300402010161", short.clone()),
            ("30050201016100", short.clone()),
            ("3000020101610a0a01", short.clone()),
            ("3007020101610a0a01", short.clone()),
            ("308200", short.clone()),
            ("30ff02010161070a010004000400", short.clone()),
            ("30200201016107 0a010004000400", short.clone()),
            ("300c020101618f0a01000400040000", short.clone()),
            ("300c02010161870a010004000400", short.clone()),
            ("30810c02010161070a010004000400", not_ldapv3()),
            ("300c02010261070a010004000400", not_ldapv3()),
            ("300c02010161070b010004000400", not_ldapv3()),
            ("300c02010161070a010004000400", ok.clone()),
            ("300802010161000a0100", ok.clone()),
            ("30820000020101610a0a0100040004000000", ok.clone()),
            ("3084000000000201016107 0a010004000400", ok.clone()),
            (
                "300c02010161070a013104000400",
                Some(ProtoReply::WrongStatus(49, Some("See RFC: http://tools.ietf.org/html/rfc4511#section-4.1.9".into()))),
            ),
        ] {
            assert_eq!(ldap_bind_reply(&unhex(hex), true), want, "{hex}");
        }
        // Before the end of the reply: 14 bytes are awaited, and a length that runs past
        // what has arrived waits for the rest.
        assert_eq!(ldap_bind_reply(&unhex("30"), false), None);
        assert_eq!(ldap_bind_reply(&unhex("30ff02010161070a010004000400"), false), None);
        assert_eq!(ldap_bind_reply(&unhex("0a0c02010161070a010004000400"), false), not_ldapv3());
    }

    #[test]
    fn mysql_replies_as_haproxy_judges_them() {
        let greeting = "0c000000 0a 352e372e302d66616b65 00";
        let version = Some(ProtoReply::Passed(Some("5.7.0-fake".into())));
        let short = Some(ProtoReply::Invalid(None));
        let sts = |code, info: Option<&str>| Some(ProtoReply::WrongStatus(code, info.map(Into::into)));
        let host_blocked = format!("10000000ff6a04{}", "486f737420626c6f636b656421");
        for (hex, want) in [
            ("01000000ff000000", sts(0, None)),
            ("01000000ff", sts(0, None)),
            ("02000000ff15", sts(21, None)),
            ("03000000ff1504", sts(1045, None)),
            (host_blocked.as_str(), sts(1130, Some("Host blocked!"))),
            ("07000000ff1504410142 43440045", sts(1045, Some("A\u{1}BCD"))),
            ("00000000", Some(ProtoReply::Passed(None))),
            ("0000000000", Some(ProtoReply::Passed(None))),
            (greeting, version.clone()),
            ("050000000a3500", short.clone()),
            ("0c0000000a352e37", short.clone()),
            ("ff", short.clone()),
            ("", Some(ProtoReply::Invalid(Some("TCPCHK got an empty response at step 2".into())))),
        ] {
            assert_eq!(mysql_reply(&unhex(hex), true, false), want, "{hex}");
        }
        let access = "4163636573732064656e696564";
        for (second, want) in [
            ("01000002ff", sts(0, None)),
            ("00000002", version.clone()),
            ("0000000200", version.clone()),
            ("0700000200000002000000", version.clone()),
            ("03000002ff1504", sts(1045, None)),
            (&format!("16000002ff1504 23 3238303030 {access}"), sts(1045, Some("#28000Access denied"))),
            (&format!("11000002ff1504 {access} 00"), sts(1045, Some("Access denied"))),
            ("0300000200", short.clone()),
            ("05000002ff", short.clone()),
            ("01000002", short.clone()),
            ("ff", short.clone()),
            ("", short.clone()),
        ] {
            let hex = format!("{greeting}{second}");
            assert_eq!(mysql_reply(&unhex(&hex), true, true), want, "{hex}");
        }
        assert_eq!(
            mysql_reply(&[], true, true),
            Some(ProtoReply::Invalid(Some("TCPCHK got an empty response at step 3".into())))
        );
        assert_eq!(mysql_reply(&unhex(greeting), false, true), None);
        assert_eq!(mysql_reply(&unhex("0c00"), false, false), None);
    }

    /// No reply of up to four bytes, nor any prefix of a well-formed one, panics either
    /// parser (the T238 panics were all of this kind).
    #[test]
    fn short_and_truncated_replies_never_panic() {
        let interesting = [0x00, 0x01, 0x02, 0x04, 0x0a, 0x30, 0x61, 0x7f, 0x80, 0x81, 0x82, 0x84, 0xff];
        let mut replies: Vec<Vec<u8>> = vec![Vec::new()];
        for len in 1..=4 {
            let mut next = Vec::new();
            for r in replies.iter().filter(|r| r.len() == len - 1) {
                for b in interesting {
                    let mut r = r.clone();
                    r.push(b);
                    next.push(r);
                }
            }
            replies.extend(next);
        }
        let wellformed = [
            unhex("3084000000000201016107 0a010004000400"),
            unhex("0c0000000a352e372e302d66616b65 00 16000002ff1504 23 3238303030 4163636573"),
        ];
        for w in &wellformed {
            replies.extend((0..=w.len()).map(|n| w[..n].to_vec()));
        }
        for r in &replies {
            for last_read in [false, true] {
                let _ = ldap_bind_reply(r, last_read);
                let _ = mysql_reply(r, last_read, false);
                let _ = mysql_reply(r, last_read, true);
            }
        }
    }

    /// `set server health down` on a drained server, and on one in maintenance
    /// (`health_transition`): the drain is kept as `DRAIN_DOWN` and maintenance is kept.
    #[test]
    fn health_transition_keeps_drain_and_maintenance() {
        let (up, drain, down) = (ServerStatus::Up as u8, ServerStatus::Drain as u8, ServerStatus::Down as u8);
        assert_eq!(health_transition(ServerStatus::Maint as u8, true), ServerStatus::Maint as u8);
        assert_eq!(health_transition(ServerStatus::Maint as u8, false), ServerStatus::Maint as u8);
        assert_eq!(health_transition(drain, false), DRAIN_DOWN);
        assert_eq!(health_transition(DRAIN_DOWN, false), DRAIN_DOWN);
        assert_eq!(health_transition(DRAIN_DOWN, true), drain);
        assert_eq!(health_transition(down, true), up);
        assert_eq!(health_transition(up, false), down);
    }

    /// The `status` column of a server whose check is off but which runs: `no check`.
    #[test]
    fn status_word_of_a_running_server_without_a_check() {
        let config = ServerCheckConfig { rise: 2, fall: 2, ..ServerCheckConfig::default() };
        let mut s = ServerCheckState::new(0, 0, "127.0.0.1:1".parse().unwrap(), config, Tick(0));
        s.status = ServerStatus::Up;
        s.health = 3;
        s.enabled = false;
        assert_eq!(s.status_word(), "no check");
        s.status = ServerStatus::Down;
        s.health = 0;
        assert_eq!(s.status_word(), "DOWN");
    }

    /// A check cut short by maintenance drops its connection: the task does not look at it
    /// again, and the state is idle when the server comes back.
    #[test]
    fn maintenance_closes_a_check_in_progress() {
        let config = ServerCheckConfig { rise: 2, fall: 2, ..ServerCheckConfig::default() };
        let mut s = ServerCheckState::new(0, 0, "127.0.0.1:1".parse().unwrap(), config, Tick(0));
        s.enabled = true;
        s.status = ServerStatus::Maint;
        s.in_progress = true;
        s.run.sub_state = CheckSubState::TcpConnecting;
        let mut fdtab = FdTab::with_capacity(16);
        let mut poller = Poller::new(4).unwrap();
        let step = step_check(&mut s, &mut fdtab, &mut poller, Tick(100), &[]).unwrap();
        assert!(!s.in_progress);
        assert!(matches!(s.run.sub_state, CheckSubState::Idle));
        assert!(!s.run.is_held(), "the run goes back to the pool");
        assert!(step.next.is_some());
    }

    /// `info:` is cut at 127 bytes, backing up to a character boundary.
    #[test]
    fn check_description_is_cut_on_a_character_boundary() {
        let long = format!("{}é{}", "a".repeat(126), "b".repeat(10));
        let cut = cut_check_desc(long);
        assert_eq!(cut, "a".repeat(126));
        let ascii = cut_check_desc("x".repeat(300));
        assert_eq!(ascii.len(), HCHK_DESC_MAX);
    }

    /// A connected loopback socket whose peer never reads, with small buffers: a check
    /// writing to it soon finds it full.
    fn stalled_socket() -> (std::net::TcpListener, OwnedFd) {
        use nix::sys::socket::{setsockopt, sockopt};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let _ = setsockopt(&listener, sockopt::RcvBuf, &4096);
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client.set_nonblocking(true).unwrap();
        let fd = OwnedFd::from(client);
        let _ = setsockopt(&fd, sockopt::SndBuf, &4096);
        (listener, fd)
    }

    /// An HTTP check whose request does not fit in the socket keeps the rest for when the
    /// socket is writable again, in the run it holds.
    #[test]
    fn an_http_check_request_larger_than_the_socket_waits_for_room() {
        let (_listener, fd) = stalled_socket();
        let config = ServerCheckConfig::default();
        let mut s = ServerCheckState::new(0, 0, "127.0.0.1:1".parse().unwrap(), config, Tick(0));
        s.resolved_config = Some(Arc::new(ResolvedCheckConfig::Http(Box::new(ResolvedHttpCheck {
            method: "GET".into(),
            uri: "/".into(),
            uri_lf: false,
            version: "HTTP/1.0".into(),
            host: None,
            headers: Vec::new(),
            body: None,
            body_lf: false,
            has_send: true,
            send_state: false,
            pre_rules: Vec::new(),
            rules: Vec::new(),
            check_port: None,
            send_proxy: false,
            connect_addr: None,
        }))));
        let mut fdtab = FdTab::with_capacity(16);
        let mut poller = Poller::new(4).unwrap();
        let raw_fd = fd.as_raw_fd();
        fdtab.insert(raw_fd, FdState::Conn { task: TaskRef::NONE, conn: 0 }, Interest::WRITE);
        s.run.check_fd = Some(raw_fd);
        s.sock = Some(fd);
        s.in_progress = true;
        s.exp = Tick(10_000);
        let len = 16 << 20;
        s.run.sub_state = CheckSubState::HttpSending { req_buf: vec![b'x'; len], send_offset: 0 };
        let step = progress_http_check(&mut s, &mut fdtab, &mut poller, Tick(1), 0, &[]).unwrap();
        assert_eq!(step.next, Some(Tick(10_000)), "pending until the check's expiry");
        let CheckSubState::HttpSending { send_offset, .. } = &s.run.sub_state else { panic!("{:?}", s.run.sub_state) };
        assert!(*send_offset > 0 && *send_offset < len, "sent {send_offset} of {len}");
        cleanup_check_socket(&mut s, &mut fdtab, &mut poller);
        assert!(!s.run.is_held());
    }

    /// A `tcp-check` woken before its connection is up waits on, its place in the script kept.
    #[test]
    fn a_tcp_check_woken_before_its_connection_is_up_waits() {
        let (_listener, fd) = stalled_socket();
        let config = ServerCheckConfig::default();
        let mut s = ServerCheckState::new(0, 0, "127.0.0.1:1".parse().unwrap(), config, Tick(0));
        s.resolved_config = Some(Arc::new(ResolvedCheckConfig::TcpSteps(vec![ResolvedTcpStep::Connect {
            port: None,
            send_proxy: false,
            implicit: true,
            rule_port: None,
            comment: None,
        }])));
        let mut fdtab = FdTab::with_capacity(16);
        let mut poller = Poller::new(4).unwrap();
        let raw_fd = fd.as_raw_fd();
        // Registered, and no readiness reported for it.
        fdtab.insert(raw_fd, FdState::Conn { task: TaskRef::NONE, conn: 0 }, Interest::WRITE);
        s.run.check_fd = Some(raw_fd);
        s.sock = Some(fd);
        s.in_progress = true;
        s.exp = Tick(10_000);
        s.run.sub_state = CheckSubState::TcpRunning { step_idx: 0, send_offset: 0, recv_buf: Vec::new() };
        let step = progress_tcp_check(&mut s, &mut fdtab, &mut poller, Tick(1), 0).unwrap();
        assert_eq!(step.next, Some(Tick(10_000)));
        assert!(matches!(s.run.sub_state, CheckSubState::TcpRunning { step_idx: 0, .. }));
        cleanup_check_socket(&mut s, &mut fdtab, &mut poller);
    }

    /// Every protocol check whose request finds the socket full keeps its place (phase,
    /// offset) for when there is room: the sending arms of each `progress_*` check.
    #[test]
    fn a_protocol_check_finding_the_socket_full_waits_for_room() {
        type Progress = fn(&mut ServerCheckState, &mut FdTab, &mut Poller, Tick, u32) -> io::Result<CheckStep>;
        let cases: Vec<(CheckSubState, Progress)> = vec![
            (CheckSubState::RedisRunning { phase: 0, send_offset: 0, recv_buf: Vec::new() }, progress_redis_check),
            (CheckSubState::SmtpRunning { phase: 1, cmd: "HELO x".into(), send_offset: 0, recv_buf: Vec::new() }, progress_smtp_check),
            (CheckSubState::SmtpRunning { phase: 3, cmd: "HELO x".into(), send_offset: 0, recv_buf: Vec::new() }, progress_smtp_check),
            (CheckSubState::LdapRunning { phase: 0, send_offset: 0, recv_buf: Vec::new() }, progress_ldap_check),
            (
                CheckSubState::MysqlRunning {
                    phase: 0,
                    user: Some("u".into()),
                    version: MysqlCheckVersion::Post41,
                    send_offset: 0,
                    req_buf: build_mysql_req("u", MysqlCheckVersion::Post41),
                    recv_buf: Vec::new(),
                },
                progress_mysql_check,
            ),
            (
                CheckSubState::PgsqlRunning { phase: 0, user: "u".into(), send_offset: 0, req_buf: Vec::new(), recv_buf: Vec::new() },
                progress_pgsql_check,
            ),
            (CheckSubState::SslHelloRunning { phase: 0, send_offset: 0, recv_buf: Vec::new() }, progress_ssl_hello_check),
        ];
        for (state, progress) in cases {
            let (_listener, fd) = stalled_socket();
            // Fill it: the request then finds no room at all.
            let mut stream = std::net::TcpStream::from(fd);
            let junk = vec![0u8; 65_536];
            while std::io::Write::write(&mut stream, &junk).is_ok() {}
            let fd = OwnedFd::from(stream);
            let mut s = ServerCheckState::new(0, 0, "127.0.0.1:1".parse().unwrap(), ServerCheckConfig::default(), Tick(0));
            let mut fdtab = FdTab::with_capacity(16);
            let mut poller = Poller::new(4).unwrap();
            let raw_fd = fd.as_raw_fd();
            fdtab.insert(raw_fd, FdState::Conn { task: TaskRef::NONE, conn: 0 }, Interest::WRITE);
            s.run.check_fd = Some(raw_fd);
            s.sock = Some(fd);
            s.in_progress = true;
            s.exp = Tick(10_000);
            let kind = std::mem::discriminant(&state);
            s.run.sub_state = state;
            let step = progress(&mut s, &mut fdtab, &mut poller, Tick(1), 0).unwrap();
            assert_eq!(step.next, Some(Tick(10_000)), "{:?}", s.run.sub_state);
            assert_eq!(std::mem::discriminant(&s.run.sub_state), kind, "{:?}", s.run.sub_state);
            cleanup_check_socket(&mut s, &mut fdtab, &mut poller);
        }
    }
}

/// [`ServerCheckState::status_word`] written without building a `String`.
pub struct StatusWord<'a>(pub &'a ServerCheckState);

impl std::fmt::Display for StatusWord<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.0;
        let (health, rise, fall) = (i64::from(s.health), i64::from(s.config.rise), i64::from(s.config.fall));
        let full = s.health >= s.full_health();
        match s.status {
            ServerStatus::Maint => f.write_str("MAINT"),
            ServerStatus::Down if s.health > 0 => write!(f, "DOWN {health}/{rise}"),
            ServerStatus::Down => f.write_str("DOWN"),
            ServerStatus::Up if !s.enabled => f.write_str("no check"),
            st @ (ServerStatus::Up | ServerStatus::Drain) if full => f.write_str(st.as_str()),
            st => write!(f, "{} {}/{fall}", st.as_str(), health - rise + 1),
        }
    }
}
