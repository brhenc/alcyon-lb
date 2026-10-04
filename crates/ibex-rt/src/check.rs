// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/check.c, include/haproxy/check.h and src/server.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Health Check engine for backend servers supporting L4 TCP, L7 HTTP, and multi-step TCP checks.
//!
//! Periodic health checks execute as [`ibex_sched::task::Kind::Check`] tasks in the scheduler.
//! When a check fires, connection and protocol transactions are initiated. On check completion
//! or error, the server's health counters (`rise_count`, `fall_count`, `health`) are updated,
//! and server availability transitions between `Up` and `Down`.

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
use std::collections::HashMap;
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
        server_version: String,
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
    /// The transport over `sock`: plaintext, or the TLS of `tls` (T113).
    pub xprt: ServerXprt,
    /// The server line's check TLS (`check-ssl`, or `ssl` inherited), `None` for plaintext.
    pub tls: Option<Arc<CheckTls>>,
    /// The `tcp-check connect` step (after the first) whose connection is being opened:
    /// while it is set, the socket in `sock` is that step's, not the previous step's.
    pub tcp_connect_step: Option<usize>,
    pub check_fd: Option<RawFd>,
    pub exp: Tick,
    pub next_check: Tick,
    pub last_status_desc: &'static str,
    pub last_status_code: &'static str,
    pub http_code: Option<u16>,
    pub last_status_info: Option<String>,
    pub resolved_config: Option<ResolvedCheckConfig>,
    pub sub_state: CheckSubState,
    /// The `http-check send` log-formats, compiled once from `resolved_config`.
    pub http_send: Option<Box<HttpSendFormats>>,
    /// The check's variables (`http-check set-var`, scope `check`), for the run in progress.
    pub vars: HashMap<String, String>,
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
        let http_send = HttpSendFormats::for_config(resolved_config.as_ref()).map(Box::new);
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
            xprt: ServerXprt::Plain,
            tls: None,
            tcp_connect_step: None,
            check_fd: None,
            exp: Tick::ETERNITY,
            next_check: now,
            last_status_desc: "Initial state",
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
            sub_state: CheckSubState::Idle,
            http_send,
            vars: HashMap::new(),
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
        self.last_status_info = info;
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
        // See on_success_full: the status-code change is HAProxy's first reporting term.
        let status_changed = self.last_status_code != code;
        self.last_status_code = code;
        self.last_status_desc = desc;
        self.http_code = http_code;
        self.last_status_info = info;
        self.check_duration_ms = duration_ms;

        if self.health == 0 {
            return if status_changed {
                Some(CheckEvent::Failed)
            } else {
                None
            };
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
    with_check_ctx(check, px, proxies, &check.vars, None, |data, ctx| {
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
    vars: &HashMap<String, String>,
    resp: Option<&HttpResp>,
    f: impl FnOnce(&LogData, &ibex_sample::SampleContext) -> R,
) -> R {
    let reg = crate::engine::sample_registry();
    let srv = px.server_ids.get(check.server_idx).map(String::as_str);
    let view = ProxiesView(proxies);
    let mut ctx = ibex_sample::SampleContext {
        fe_name: Some(&px.name),
        fe_id: Some(px.ids.iid),
        be_name: Some(&px.name),
        be_id: Some(px.ids.iid),
        srv_name: srv,
        srv_id: Some(px.server_puid(check.server_idx)),
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
    vars: &mut HashMap<String, String>,
    resp: Option<&HttpResp>,
) {
    let Some(px) = proxies.get(check.proxy_idx) else { return };
    let reg = crate::engine::sample_registry();
    for rule in rules {
        if let ResolvedHttpRule::SetVar { var_name, expr } = rule {
            let val = with_check_ctx(check, px, proxies, vars, resp, |_, ctx| {
                ibex_sample::Expr::parse(expr)
                    .ok()
                    .and_then(|e| e.eval_sample(reg, ctx))
                    .map(|smp| crate::engine::sample_to_string(&smp))
            });
            // An expression that gives no sample leaves the variable as it was.
            if let Some(v) = val {
                vars.insert(var_name.clone(), v);
            }
        } else if let ResolvedHttpRule::UnsetVar { var_name } = rule {
            vars.remove(var_name);
        }
    }
}

/// `uri-lf`, `body-lf` and each `hdr` as rendered for one check; `None` where the request
/// uses the configured text.
type RenderedSend = (Option<String>, Option<String>, Vec<Option<String>>);

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
    let Some(px) = proxies.get(check.proxy_idx) else { return out };
    let i = check.server_idx;
    let addr = px.servers.get(i).copied().unwrap_or(check.addr);
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
        px.server_weights.get(i).copied().unwrap_or(1),
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

    let rendered = check.http_send.as_ref().zip(proxies.get(check.proxy_idx));
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
struct HttpResp {
    status: u16,
    reason: String,
    version: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// The message is complete: its length is reached, its last chunk is in, or it has
    /// no body.
    ended: bool,
}

/// Parses a response head and as much of the body as there is: `Ok(None)` while the head
/// is incomplete, `Err` for one that is not HTTP.
fn parse_http_response(buf: &[u8]) -> Result<Option<HttpResp>, ()> {
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

    let raw_body = &buf[head_end..];
    let header = |n: &str| headers.iter().find(|(h, _)| h.eq_ignore_ascii_case(n)).map(|(_, v)| v.as_str());
    let (body, ended) = if status < 200 || status == 204 || status == 304 {
        (Vec::new(), true)
    } else if header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        decode_chunked(raw_body)
    } else if let Some(cl) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        let n = raw_body.len().min(cl);
        (raw_body[..n].to_vec(), raw_body.len() >= cl)
    } else {
        (raw_body.to_vec(), false)
    };
    Ok(Some(HttpResp { status, reason, version: version.to_string(), headers, body, ended }))
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
fn config_regex(pattern: &str, case_insensitive: bool) -> Option<ibex_regex::UserRegex> {
    ibex_regex::UserRegex::with_case(pattern, case_insensitive).ok()
}

/// The values of a header `hdr` looks at: the comma-separated elements, trimmed, or with
/// `full` the whole value.
fn header_values(value: &str, full: bool) -> Vec<&str> {
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
            config_regex(re, false).is_some_and(|re| re.is_match(&resp.status.to_string()))
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
                config_regex(re, false).is_some_and(|re| re.is_match(&String::from_utf8_lossy(&resp.body)))
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
    let px = &proxies[check.proxy_idx];
    let reg = crate::engine::sample_registry();
    // The rules run in order from the same starting variables each time more of the
    // response is in; what one sets is for the ones after it.
    let mut vars = check.vars.clone();
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
        "ECONNREFUSED returned by OS".to_string()
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

    if check.resolved_config.is_none() {
        check.resolved_config = get_resolved_check_config(check.proxy_idx, check.server_idx, check.addr);
        check.http_send = HttpSendFormats::for_config(check.resolved_config.as_ref()).map(Box::new);
    }

    if check.in_progress {
        let duration = now.remaining(check.check_start_tick).unwrap_or(0);
        let timed_out = check.exp.is_expired(now);

        if timed_out {
            let handshaking = check.xprt.is_tls() && !check.xprt.is_ready();
            let (code, desc, info) = match &check.sub_state {
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
                    match check.resolved_config.clone() {
                        Some(ResolvedCheckConfig::Redis) => {
                            check.sub_state = CheckSubState::RedisRunning {
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
                            check.sub_state = CheckSubState::SmtpRunning {
                                phase: 0,
                                cmd: cmd.unwrap_or_else(|| "HELO localhost".to_string()),
                                send_offset: 0,
                                recv_buf: Vec::new(),
                            };
                            progress_smtp_check(check, fdtab, poller, now, duration)
                        }
                        Some(ResolvedCheckConfig::Ldap) => {
                            check.sub_state = CheckSubState::LdapRunning {
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
                            check.sub_state = CheckSubState::MysqlRunning {
                                phase: 0,
                                user,
                                version,
                                server_version: String::new(),
                                send_offset: 0,
                                req_buf,
                                recv_buf: Vec::new(),
                            };
                            progress_mysql_check(check, fdtab, poller, now, duration)
                        }
                        Some(ResolvedCheckConfig::Pgsql { user }) => {
                            check.sub_state = CheckSubState::PgsqlRunning {
                                phase: 0,
                                user,
                                send_offset: 0,
                                req_buf: Vec::new(),
                                recv_buf: Vec::new(),
                            };
                            progress_pgsql_check(check, fdtab, poller, now, duration)
                        }
                        Some(ResolvedCheckConfig::SslHello) => {
                            check.sub_state = CheckSubState::SslHelloRunning {
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
                    check.sub_state = CheckSubState::HttpSending {
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
        check.check_start_tick = now;
        check.http_code = None;
        check.last_status_info = None;

        let resolved = check.resolved_config.clone().unwrap_or(ResolvedCheckConfig::TcpConnect);

        match resolved {
            ResolvedCheckConfig::Http(chk) => {
                let base = chk.connect_addr.map_or(check.addr.ip(), |a| a.ip());
                let target_addr = SocketAddr::new(base, chk.check_port.unwrap_or(check.addr.port()));
                // The variables of this run: the rules before the request set them.
                let mut vars = HashMap::new();
                run_var_rules(check, proxies, &chk.pre_rules, &mut vars, None);
                check.vars = vars;
                let payload = build_http_request_payload(&chk, target_addr, check, proxies);

                match connect_check(check, Some(target_addr)) {
                    Ok((sock, _)) => {
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

                        // Even a connection that is already up is waited for: the poller
                        // reports its socket writable at once.
                        check.sub_state = CheckSubState::HttpConnecting {
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
                check.sub_state = CheckSubState::TcpRunning {
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
            ResolvedCheckConfig::Redis => {
                match connect_check(check, None) {
                    Ok((sock, immediate)) => {
                        let raw_fd = sock.as_raw_fd();
                        check.check_fd = Some(raw_fd);
                        let timeout_ms = u32::try_from(check.config.timeout.as_millis()).unwrap_or(u32::MAX);
                        check.exp = now.add(timeout_ms);
                        check.in_progress = true;
                        fdtab.insert(raw_fd, FdState::Conn { task: check.task, conn: 0 }, Interest::WRITE);
                        let _ = poller.add(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), false, true);
                        check.sock = Some(sock);

                        if immediate {
                            check.sub_state = CheckSubState::RedisRunning {
                                phase: 0,
                                send_offset: 0,
                                recv_buf: Vec::new(),
                            };
                            progress_redis_check(check, fdtab, poller, now, 0)
                        } else {
                            check.sub_state = CheckSubState::ProtoConnecting { target_addr: check.addr };
                            Ok(CheckStep::pending(Some(check.exp)))
                        }
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
            ResolvedCheckConfig::Smtp(cmd) => {
                match connect_check(check, None) {
                    Ok((sock, immediate)) => {
                        let raw_fd = sock.as_raw_fd();
                        check.check_fd = Some(raw_fd);
                        let timeout_ms = u32::try_from(check.config.timeout.as_millis()).unwrap_or(u32::MAX);
                        check.exp = now.add(timeout_ms);
                        check.in_progress = true;
                        fdtab.insert(raw_fd, FdState::Conn { task: check.task, conn: 0 }, Interest::WRITE);
                        let _ = poller.add(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), false, true);
                        check.sock = Some(sock);

                        if immediate {
                            check.sub_state = CheckSubState::SmtpRunning {
                                phase: 0,
                                cmd: cmd.unwrap_or_else(|| "HELO localhost".to_string()),
                                send_offset: 0,
                                recv_buf: Vec::new(),
                            };
                            progress_smtp_check(check, fdtab, poller, now, 0)
                        } else {
                            check.sub_state = CheckSubState::ProtoConnecting { target_addr: check.addr };
                            Ok(CheckStep::pending(Some(check.exp)))
                        }
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
            ResolvedCheckConfig::Ldap => {
                match connect_check(check, None) {
                    Ok((sock, immediate)) => {
                        let raw_fd = sock.as_raw_fd();
                        check.check_fd = Some(raw_fd);
                        let timeout_ms = u32::try_from(check.config.timeout.as_millis()).unwrap_or(u32::MAX);
                        check.exp = now.add(timeout_ms);
                        check.in_progress = true;
                        fdtab.insert(raw_fd, FdState::Conn { task: check.task, conn: 0 }, Interest::WRITE);
                        let _ = poller.add(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), false, true);
                        check.sock = Some(sock);

                        if immediate {
                            check.sub_state = CheckSubState::LdapRunning {
                                phase: 0,
                                send_offset: 0,
                                recv_buf: Vec::new(),
                            };
                            progress_ldap_check(check, fdtab, poller, now, 0)
                        } else {
                            check.sub_state = CheckSubState::ProtoConnecting { target_addr: check.addr };
                            Ok(CheckStep::pending(Some(check.exp)))
                        }
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
            ResolvedCheckConfig::Mysql { user, version } => {
                match connect_check(check, None) {
                    Ok((sock, immediate)) => {
                        let raw_fd = sock.as_raw_fd();
                        check.check_fd = Some(raw_fd);
                        let timeout_ms = u32::try_from(check.config.timeout.as_millis()).unwrap_or(u32::MAX);
                        check.exp = now.add(timeout_ms);
                        check.in_progress = true;
                        let req_buf = user.as_deref().map(|u| build_mysql_req(u, version)).unwrap_or_default();
                        fdtab.insert(raw_fd, FdState::Conn { task: check.task, conn: 0 }, Interest::WRITE);
                        let _ = poller.add(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), false, true);
                        check.sock = Some(sock);

                        if immediate {
                            check.sub_state = CheckSubState::MysqlRunning {
                                phase: 0,
                                user,
                                version,
                                server_version: String::new(),
                                send_offset: 0,
                                req_buf,
                                recv_buf: Vec::new(),
                            };
                            progress_mysql_check(check, fdtab, poller, now, 0)
                        } else {
                            check.sub_state = CheckSubState::ProtoConnecting { target_addr: check.addr };
                            Ok(CheckStep::pending(Some(check.exp)))
                        }
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
            ResolvedCheckConfig::Pgsql { user } => {
                match connect_check(check, None) {
                    Ok((sock, immediate)) => {
                        let raw_fd = sock.as_raw_fd();
                        check.check_fd = Some(raw_fd);
                        let timeout_ms = u32::try_from(check.config.timeout.as_millis()).unwrap_or(u32::MAX);
                        check.exp = now.add(timeout_ms);
                        check.in_progress = true;
                        fdtab.insert(raw_fd, FdState::Conn { task: check.task, conn: 0 }, Interest::WRITE);
                        let _ = poller.add(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), false, true);
                        check.sock = Some(sock);

                        if immediate {
                            check.sub_state = CheckSubState::PgsqlRunning {
                                phase: 0,
                                user,
                                send_offset: 0,
                                req_buf: Vec::new(),
                                recv_buf: Vec::new(),
                            };
                            progress_pgsql_check(check, fdtab, poller, now, 0)
                        } else {
                            check.sub_state = CheckSubState::ProtoConnecting { target_addr: check.addr };
                            Ok(CheckStep::pending(Some(check.exp)))
                        }
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
            ResolvedCheckConfig::SslHello => {
                match connect_check(check, None) {
                    Ok((sock, immediate)) => {
                        let raw_fd = sock.as_raw_fd();
                        check.check_fd = Some(raw_fd);
                        let timeout_ms = u32::try_from(check.config.timeout.as_millis()).unwrap_or(u32::MAX);
                        check.exp = now.add(timeout_ms);
                        check.in_progress = true;
                        fdtab.insert(raw_fd, FdState::Conn { task: check.task, conn: 0 }, Interest::WRITE);
                        let _ = poller.add(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), false, true);
                        check.sock = Some(sock);

                        if immediate {
                            check.sub_state = CheckSubState::SslHelloRunning {
                                phase: 0,
                                send_offset: 0,
                                recv_buf: Vec::new(),
                            };
                            progress_ssl_hello_check(check, fdtab, poller, now, 0)
                        } else {
                            check.sub_state = CheckSubState::ProtoConnecting { target_addr: check.addr };
                            Ok(CheckStep::pending(Some(check.exp)))
                        }
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
                check.sub_state = CheckSubState::TcpConnecting;
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
                match check.xprt.send(sock.as_fd(), &req_buf[send_offset..]) {
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

            let mut buf = [0u8; 4096];
            let mut eof = false;
            let mut broken = false;
            loop {
                match check.xprt.recv(sock.as_fd(), &mut buf) {
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
            // that fails after some data is the end of what there is.
            let last_read = eof || (broken && !recv_buf.is_empty());
            let verdict = if broken && recv_buf.is_empty() {
                HttpVerdict::Fail { code: "SOCKERR", desc: "Socket error", status: None, info: None }
            } else {
                http_verdict(check, &chk, &recv_buf, last_read, proxies)
            };
            let event = match verdict {
                HttpVerdict::Wait => {
                    fdtab.clear_ready(raw_fd, true, false);
                    check.sub_state = CheckSubState::HttpReceiving { recv_buf };
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
    if let Some(ResolvedCheckConfig::TcpSteps(steps)) = &check.resolved_config { steps } else { &[] }
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
    check.sub_state = CheckSubState::TcpRunning {
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
                // The socket in hand is this step's own connection only for the first
                // step (opened by `progress_tcp_steps_start`) or when this step's connect
                // is the one in flight. Otherwise it is the previous step's, and a
                // `tcp-check connect` mid-script means a new connection (HAProxy drops
                // the buffers too: "Always release input and output buffer when a new
                // connect is evaluated"). Treating the old socket as the new connection
                // made the next `expect` read the old server's end of stream.
                let this_steps_socket = step_idx == 0 || check.tcp_connect_step == Some(step_idx);
                if let (true, Some(sock)) = (this_steps_socket, check.sock.as_ref()) {
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
                        check.tcp_connect_step = None;
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
                        check.check_fd = Some(raw_fd);
                        check.tcp_connect_step = Some(step_idx);
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
                let mut wait = recv_buf.is_empty() && !last_read;
                let needed = match pattern {
                    ResolvedTcpExpectPattern::String(t) => t.len(),
                    ResolvedTcpExpectPattern::Binary(b) => b.len(),
                    ResolvedTcpExpectPattern::RString(_) => 0,
                };
                if !wait && !last_read {
                    wait = recv_buf.len() < needed || (*min_recv > 0 && (recv_buf.len() as i64) < *min_recv);
                }
                let matched = !wait && pattern.matches(&recv_buf);
                if !wait && !matched && !last_read && *min_recv == -1 {
                    wait = true;
                }
                if wait {
                    fdtab.clear_ready(raw_fd, true, false);
                    check.sub_state = CheckSubState::TcpRunning {
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

/// Cleans up any open sockets or poller registrations for a check in progress.
/// `cut_crlf`: the bytes before the first CR or LF.
fn cut_crlf(b: &[u8]) -> &[u8] {
    let end = b.iter().position(|&c| c == b'\r' || c == b'\n').unwrap_or(b.len());
    &b[..end]
}

/// `chunk_asciiencode` (src/chunk.c): printable ASCII as is, every other byte as `<XX>`.
fn ascii_encode(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len());
    for &c in b {
        if (0x20..0x7f).contains(&c) {
            out.push(char::from(c));
        } else {
            let _ = write!(out, "<{c:02X}>");
        }
    }
    out
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
    let Some(ResolvedCheckConfig::Http(chk)) = check.resolved_config.as_ref() else { return None };
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
    check.tcp_connect_step = None;
    if let Some(raw_fd) = check.check_fd.take() {
        fdtab.remove(raw_fd);
    }
    check.in_progress = false;
    check.exp = Tick::ETERNITY;
    check.sub_state = CheckSubState::Idle;
}

#[allow(clippy::too_many_lines, clippy::unnecessary_wraps)]
fn progress_redis_check(
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
    let Some(sock) = check.sock.as_ref() else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    let CheckSubState::RedisRunning {
        mut phase,
        mut send_offset,
        mut recv_buf,
    } = check.sub_state.clone()
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
                    check.sub_state = CheckSubState::RedisRunning {
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
        let mut buf = [0u8; 4096];
        let mut eof = false;
        loop {
            match check.xprt.recv(sock.as_fd(), &mut buf) {
                Ok(Io::Done(n)) => {
                    recv_buf.extend_from_slice(&buf[..n]);
                }
                Ok(Io::WouldBlock) => break,
                Ok(Io::Eof | Io::Closed) | Err(_) => {
                    eof = true;
                    break;
                }
            }
        }

        let has_crlf = recv_buf.windows(2).any(|w| w == b"\r\n");
        if !has_crlf && !eof {
            fdtab.clear_ready(raw_fd, true, false);
            check.sub_state = CheckSubState::RedisRunning {
                phase,
                send_offset,
                recv_buf,
            };
            return Ok(CheckStep::pending(Some(check.exp)));
        }

        cleanup_check_socket(check, fdtab, poller);
        // HAProxy's rule: `expect string +PONG error-status L7STS on-error
        // %[res.payload(0,0),cut_crlf]` (src/tcpcheck.c): anything but a PONG is "Layer7
        // wrong status", with the reply up to its first CR/LF, non-printables as `<XX>`.
        // Measured: an LDAP answer gives `info: "0<0C><02><01><01>a<07>"`.
        let event = if recv_buf.starts_with(b"+PONG") {
            check.on_success_full(
                "L7OK",
                "Layer7 check passed",
                duration,
                None,
                Some("Redis server is ok".to_string()),
            )
        } else {
            check.on_failure_full(
                "L7STS",
                "Layer7 wrong status",
                duration,
                None,
                Some(ascii_encode(cut_crlf(&recv_buf))),
            )
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

#[allow(clippy::too_many_lines, clippy::unnecessary_wraps)]
fn progress_smtp_check(
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
    } = check.sub_state.clone()
    else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    let find_crlf = |b: &[u8]| b.windows(2).position(|w| w == b"\r\n");

    if phase == 0 {
        fdtab.set_interest(raw_fd, Interest::READ);
        let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), true, false);

        let mut buf = [0u8; 4096];
        let mut eof = false;
        loop {
            match check.xprt.recv(sock.as_fd(), &mut buf) {
                Ok(Io::Done(n)) => {
                    recv_buf.extend_from_slice(&buf[..n]);
                }
                Ok(Io::WouldBlock) => break,
                Ok(Io::Eof | Io::Closed) | Err(_) => {
                    eof = true;
                    break;
                }
            }
        }

        if find_crlf(&recv_buf).is_none() && !eof {
            fdtab.clear_ready(raw_fd, true, false);
            check.sub_state = CheckSubState::SmtpRunning {
                phase,
                cmd,
                send_offset,
                recv_buf,
            };
            return Ok(CheckStep::pending(Some(check.exp)));
        }

        let line = String::from_utf8_lossy(&recv_buf)
            .trim_end_matches(&['\r', '\n'][..])
            .to_string();
        let code_res = line.get(0..3).and_then(|s| s.parse::<u16>().ok());
        match code_res {
            Some(code) if (200..300).contains(&code) => {
                phase = 1;
                send_offset = 0;
                recv_buf.clear();
                fdtab.set_interest(raw_fd, Interest::WRITE);
                let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), false, true);
            }
            Some(code) => {
                cleanup_check_socket(check, fdtab, poller);
                let info = line.get(4..).unwrap_or("").trim().to_string();
                let event = check.on_failure_full(
                    "L7STS",
                    "Layer7 wrong status",
                    duration,
                    Some(code),
                    if info.is_empty() { None } else { Some(info) },
                );
                let next = check.schedule_next(now);
                check.next_check = next;
                return Ok(CheckStep {
                    next: Some(next),
                    event,
                });
            }
            None => {
                cleanup_check_socket(check, fdtab, poller);
                let info = line.trim().to_string();
                let event = check.on_failure_full(
                    "L7RSP",
                    "Layer7 invalid response",
                    duration,
                    None,
                    if info.is_empty() { None } else { Some(info) },
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

    if phase == 1 {
        let req_bytes = format!("{cmd}\r\n").into_bytes();
        while send_offset < req_bytes.len() {
            match check.xprt.send(sock.as_fd(), &req_bytes[send_offset..]) {
                Ok(Io::Done(n)) => {
                    send_offset += n;
                }
                Ok(Io::WouldBlock) => {
                    fdtab.clear_ready(raw_fd, false, true);
                    check.sub_state = CheckSubState::SmtpRunning {
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
        check.sub_state = CheckSubState::SmtpRunning {
            phase,
            cmd,
            send_offset,
            recv_buf,
        };
        return Ok(CheckStep::pending(Some(check.exp)));
    }

    if phase == 2 {
        let mut buf = [0u8; 4096];
        let mut eof = false;
        loop {
            match check.xprt.recv(sock.as_fd(), &mut buf) {
                Ok(Io::Done(n)) => {
                    recv_buf.extend_from_slice(&buf[..n]);
                }
                Ok(Io::WouldBlock) => break,
                Ok(Io::Eof | Io::Closed) | Err(_) => {
                    eof = true;
                    break;
                }
            }
        }

        let resp_str = String::from_utf8_lossy(&recv_buf);
        let mut completed = false;
        let mut last_code = None;
        let mut last_info = None;

        // T117: judge only lines that are complete. A reply `248\r\n` arriving as `2`,
        // `4`, `8`, `\r\n` has the shape of a final line ("248", nothing after the code)
        // as soon as the `8` is in; taking it then sent QUIT early and read the trailing
        // CRLF as the QUIT answer. HAProxy's expect (`^(2xx-...\r\n)*2xx[ \r]`, no
        // min-recv) keeps waiting while it cannot decide. At EOF the partial tail counts,
        // as before.
        let judged = if eof {
            &resp_str[..]
        } else {
            &resp_str[..resp_str.rfind('\n').map_or(0, |i| i + 1)]
        };
        for line in judged.lines() {
            if line.len() >= 3
                && line.as_bytes()[0].is_ascii_digit()
                && line.as_bytes()[1].is_ascii_digit()
                && line.as_bytes()[2].is_ascii_digit()
            {
                let code = line[0..3].parse::<u16>().ok();
                if line.len() == 3 || line.as_bytes().get(3) == Some(&b' ') {
                    completed = true;
                    last_code = code;
                    last_info = Some(line.get(4..).unwrap_or("").trim().to_string());
                }
            }
        }

        if !completed && !eof {
            fdtab.clear_ready(raw_fd, true, false);
            check.sub_state = CheckSubState::SmtpRunning {
                phase,
                cmd,
                send_offset,
                recv_buf,
            };
            return Ok(CheckStep::pending(Some(check.exp)));
        }

        match last_code {
            Some(code) if (200..300).contains(&code) => {
                phase = 3;
                send_offset = 0;
                recv_buf.clear();
                fdtab.set_interest(raw_fd, Interest::WRITE);
                let _ = poller.modify(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), false, true);
            }
            Some(code) => {
                cleanup_check_socket(check, fdtab, poller);
                let event = check.on_failure_full(
                    "L7STS",
                    "Layer7 wrong status",
                    duration,
                    Some(code),
                    last_info,
                );
                let next = check.schedule_next(now);
                check.next_check = next;
                return Ok(CheckStep {
                    next: Some(next),
                    event,
                });
            }
            None => {
                cleanup_check_socket(check, fdtab, poller);
                let info = resp_str.trim().to_string();
                let event = check.on_failure_full(
                    "L7RSP",
                    "Layer7 invalid response",
                    duration,
                    None,
                    if info.is_empty() { None } else { Some(info) },
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

    if phase == 3 {
        let quit_req = b"QUIT\r\n";
        while send_offset < quit_req.len() {
            match check.xprt.send(sock.as_fd(), &quit_req[send_offset..]) {
                Ok(Io::Done(n)) => {
                    send_offset += n;
                }
                Ok(Io::WouldBlock) => {
                    fdtab.clear_ready(raw_fd, false, true);
                    check.sub_state = CheckSubState::SmtpRunning {
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
        check.sub_state = CheckSubState::SmtpRunning {
            phase,
            cmd,
            send_offset,
            recv_buf,
        };
        return Ok(CheckStep::pending(Some(check.exp)));
    }

    if phase == 4 {
        let mut buf = [0u8; 4096];
        let mut eof = false;
        loop {
            match check.xprt.recv(sock.as_fd(), &mut buf) {
                Ok(Io::Done(n)) => {
                    recv_buf.extend_from_slice(&buf[..n]);
                }
                Ok(Io::WouldBlock) => break,
                Ok(Io::Eof | Io::Closed) | Err(_) => {
                    eof = true;
                    break;
                }
            }
        }

        if find_crlf(&recv_buf).is_none() && !eof {
            fdtab.clear_ready(raw_fd, true, false);
            check.sub_state = CheckSubState::SmtpRunning {
                phase,
                cmd,
                send_offset,
                recv_buf,
            };
            return Ok(CheckStep::pending(Some(check.exp)));
        }

        cleanup_check_socket(check, fdtab, poller);
        let line = String::from_utf8_lossy(&recv_buf)
            .trim_end_matches(&['\r', '\n'][..])
            .to_string();
        let code_res = line.get(0..3).and_then(|s| s.parse::<u16>().ok());
        let event = match code_res {
            Some(code) if (200..300).contains(&code) => {
                let info = line.get(4..).unwrap_or("").trim().to_string();
                check.on_success_full(
                    "L7OK",
                    "Layer7 check passed",
                    duration,
                    Some(code),
                    if info.is_empty() { None } else { Some(info) },
                )
            }
            Some(code) => {
                let info = line.get(4..).unwrap_or("").trim().to_string();
                check.on_failure_full(
                    "L7STS",
                    "Layer7 wrong status",
                    duration,
                    Some(code),
                    if info.is_empty() { None } else { Some(info) },
                )
            }
            None => check.on_failure_full(
                "L7RSP",
                "Layer7 invalid response",
                duration,
                None,
                Some(line),
            ),
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

#[allow(clippy::too_many_lines, clippy::unnecessary_wraps)]
fn progress_ldap_check(
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
    let Some(sock) = check.sock.as_ref() else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    let CheckSubState::LdapRunning {
        mut phase,
        mut send_offset,
        mut recv_buf,
    } = check.sub_state.clone()
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
                    check.sub_state = CheckSubState::LdapRunning {
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
        let mut buf = [0u8; 4096];
        let mut eof = false;
        loop {
            match check.xprt.recv(sock.as_fd(), &mut buf) {
                Ok(Io::Done(n)) => {
                    recv_buf.extend_from_slice(&buf[..n]);
                }
                Ok(Io::WouldBlock) => break,
                Ok(Io::Eof | Io::Closed) | Err(_) => {
                    eof = true;
                    break;
                }
            }
        }

        if recv_buf.is_empty() && !eof {
            fdtab.clear_ready(raw_fd, true, false);
            check.sub_state = CheckSubState::LdapRunning {
                phase,
                send_offset,
                recv_buf,
            };
            return Ok(CheckStep::pending(Some(check.exp)));
        }

        if recv_buf.first() != Some(&0x30) {
            cleanup_check_socket(check, fdtab, poller);
            let event = check.on_failure_full(
                "L7RSP",
                "Layer7 invalid response",
                duration,
                None,
                Some("Not LDAPv3 protocol".to_string()),
            );
            let next = check.schedule_next(now);
            check.next_check = next;
            return Ok(CheckStep {
                next: Some(next),
                event,
            });
        }

        if recv_buf.len() < 2 {
            if !eof {
                fdtab.clear_ready(raw_fd, true, false);
                check.sub_state = CheckSubState::LdapRunning {
                    phase,
                    send_offset,
                    recv_buf,
                };
                return Ok(CheckStep::pending(Some(check.exp)));
            }
        }

        let mut ptr = 1;
        let msglen: usize;
        if recv_buf[ptr] & 0x80 != 0 {
            let nbytes = (recv_buf[ptr] & 0x7f) as usize;
            ptr += 1;
            if recv_buf.len() < ptr + nbytes {
                if !eof {
                    fdtab.clear_ready(raw_fd, true, false);
                    check.sub_state = CheckSubState::LdapRunning {
                        phase,
                        send_offset,
                        recv_buf,
                    };
                    return Ok(CheckStep::pending(Some(check.exp)));
                }
            }
            if nbytes == 4 && recv_buf.len() >= ptr + 4 {
                msglen = u32::from_be_bytes([
                    recv_buf[ptr],
                    recv_buf[ptr + 1],
                    recv_buf[ptr + 2],
                    recv_buf[ptr + 3],
                ]) as usize;
            } else if nbytes == 2 && recv_buf.len() >= ptr + 2 {
                msglen = u16::from_be_bytes([recv_buf[ptr], recv_buf[ptr + 1]]) as usize;
            } else if nbytes == 1 && recv_buf.len() >= ptr + 1 {
                msglen = recv_buf[ptr] as usize;
            } else {
                cleanup_check_socket(check, fdtab, poller);
                let event = check.on_failure_full(
                    "L7RSP",
                    "Layer7 invalid response",
                    duration,
                    None,
                    Some("Not LDAPv3 protocol".to_string()),
                );
                let next = check.schedule_next(now);
                check.next_check = next;
                return Ok(CheckStep {
                    next: Some(next),
                    event,
                });
            }
            ptr += nbytes;
        } else {
            msglen = recv_buf[ptr] as usize;
            ptr += 1;
        }

        if recv_buf.len() < ptr + msglen && !eof {
            fdtab.clear_ready(raw_fd, true, false);
            check.sub_state = CheckSubState::LdapRunning {
                phase,
                send_offset,
                recv_buf,
            };
            return Ok(CheckStep::pending(Some(check.exp)));
        }

        if recv_buf.len() < ptr + 4 || &recv_buf[ptr..ptr + 4] != &[0x02, 0x01, 0x01, 0x61] {
            cleanup_check_socket(check, fdtab, poller);
            let event = check.on_failure_full(
                "L7RSP",
                "Layer7 invalid response",
                duration,
                None,
                Some("Not LDAPv3 protocol".to_string()),
            );
            let next = check.schedule_next(now);
            check.next_check = next;
            return Ok(CheckStep {
                next: Some(next),
                event,
            });
        }
        ptr += 4;

        if ptr >= recv_buf.len() {
            if !eof {
                fdtab.clear_ready(raw_fd, true, false);
                check.sub_state = CheckSubState::LdapRunning {
                    phase,
                    send_offset,
                    recv_buf,
                };
                return Ok(CheckStep::pending(Some(check.exp)));
            }
        }
        if recv_buf[ptr] & 0x80 != 0 {
            let nbytes = (recv_buf[ptr] & 0x7f) as usize;
            ptr += 1 + nbytes;
        } else {
            ptr += 1;
        }

        if recv_buf.len() < ptr + 3 || &recv_buf[ptr..ptr + 2] != &[0x0a, 0x01] {
            cleanup_check_socket(check, fdtab, poller);
            let event = check.on_failure_full(
                "L7RSP",
                "Layer7 invalid response",
                duration,
                None,
                Some("Not LDAPv3 protocol".to_string()),
            );
            let next = check.schedule_next(now);
            check.next_check = next;
            return Ok(CheckStep {
                next: Some(next),
                event,
            });
        }
        ptr += 2;
        let result_code = recv_buf[ptr];

        cleanup_check_socket(check, fdtab, poller);
        let event = if result_code == 0 {
            check.on_success_full(
                "L7OK",
                "Layer7 check passed",
                duration,
                None,
                Some("Success".to_string()),
            )
        } else {
            check.on_failure_full(
                "L7STS",
                "Layer7 wrong status",
                duration,
                Some(u16::from(result_code)),
                Some("See RFC: http://tools.ietf.org/html/rfc4511#section-4.1.9".to_string()),
            )
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
    let Some(raw_fd) = check.check_fd else {
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
        mut server_version,
        mut send_offset,
        req_buf,
        mut recv_buf,
    } = check.sub_state.clone()
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
                        check.sub_state = CheckSubState::MysqlRunning {
                            phase,
                            user,
                            version,
                            server_version,
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
        let mut buf = [0u8; 4096];
        let mut eof = false;
        loop {
            match check.xprt.recv(sock.as_fd(), &mut buf) {
                Ok(Io::Done(n)) => {
                    recv_buf.extend_from_slice(&buf[..n]);
                }
                Ok(Io::WouldBlock) => break,
                Ok(Io::Eof | Io::Closed) | Err(_) => {
                    eof = true;
                    break;
                }
            }
        }

        if recv_buf.len() < 4 {
            if !eof {
                fdtab.clear_ready(raw_fd, true, false);
                check.sub_state = CheckSubState::MysqlRunning {
                    phase,
                    user,
                    version,
                    server_version,
                    send_offset,
                    req_buf,
                    recv_buf,
                };
                return Ok(CheckStep::pending(Some(check.exp)));
            }
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

        let plen_hs = recv_buf[0] as usize
            | ((recv_buf[1] as usize) << 8)
            | ((recv_buf[2] as usize) << 16);
        if recv_buf.len() < 4 + plen_hs {
            if !eof {
                fdtab.clear_ready(raw_fd, true, false);
                check.sub_state = CheckSubState::MysqlRunning {
                    phase,
                    user,
                    version,
                    server_version,
                    send_offset,
                    req_buf,
                    recv_buf,
                };
                return Ok(CheckStep::pending(Some(check.exp)));
            }
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

        if recv_buf.len() < 5 {
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

        if recv_buf[4] == 0xff {
            let err_code = if recv_buf.len() >= 7 {
                recv_buf[5] as u16 | ((recv_buf[6] as u16) << 8)
            } else {
                0
            };
            let info = if recv_buf.len() >= 8 {
                let msg_bytes = &recv_buf[7..4 + plen_hs];
                let null_end = msg_bytes.iter().position(|&b| b == 0).unwrap_or(msg_bytes.len());
                String::from_utf8_lossy(&msg_bytes[..null_end]).to_string()
            } else {
                "Error".to_string()
            };
            cleanup_check_socket(check, fdtab, poller);
            let event = check.on_failure_full(
                "L7STS",
                "Layer7 wrong status",
                duration,
                Some(err_code),
                Some(info),
            );
            let next = check.schedule_next(now);
            check.next_check = next;
            return Ok(CheckStep {
                next: Some(next),
                event,
            });
        }

        let srv_ver_bytes = &recv_buf[5..4 + plen_hs];
        let null_pos = srv_ver_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(srv_ver_bytes.len());
        server_version = String::from_utf8_lossy(&srv_ver_bytes[..null_pos]).to_string();

        if user.is_some() {
            let offset = 4 + plen_hs;
            if recv_buf.len() < offset + 4 {
                if !eof {
                    fdtab.clear_ready(raw_fd, true, false);
                    check.sub_state = CheckSubState::MysqlRunning {
                        phase,
                        user,
                        version,
                        server_version,
                        send_offset,
                        req_buf,
                        recv_buf,
                    };
                    return Ok(CheckStep::pending(Some(check.exp)));
                }
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

            let plen_res = recv_buf[offset] as usize
                | ((recv_buf[offset + 1] as usize) << 8)
                | ((recv_buf[offset + 2] as usize) << 16);
            if recv_buf.len() < offset + 4 + plen_res {
                if !eof {
                    fdtab.clear_ready(raw_fd, true, false);
                    check.sub_state = CheckSubState::MysqlRunning {
                        phase,
                        user,
                        version,
                        server_version,
                        send_offset,
                        req_buf,
                        recv_buf,
                    };
                    return Ok(CheckStep::pending(Some(check.exp)));
                }
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

            let res_type = recv_buf[offset + 4];
            cleanup_check_socket(check, fdtab, poller);
            let event = if res_type == 0xff {
                let err_code = if recv_buf.len() >= offset + 7 {
                    recv_buf[offset + 5] as u16 | ((recv_buf[offset + 6] as u16) << 8)
                } else {
                    0
                };
                let mut msg_offset = offset + 7;
                if recv_buf.len() > msg_offset && recv_buf[msg_offset] == b'#' {
                    msg_offset += 6;
                }
                let err_msg = if recv_buf.len() > msg_offset {
                    let end_pos = (offset + 4 + plen_res).min(recv_buf.len());
                    String::from_utf8_lossy(&recv_buf[msg_offset..end_pos])
                        .trim_end_matches(&['\r', '\n', '\0'][..])
                        .to_string()
                } else {
                    String::new()
                };
                check.on_failure_full(
                    "L7STS",
                    "Layer7 wrong status",
                    duration,
                    Some(err_code),
                    Some(err_msg),
                )
            } else {
                check.on_success_full(
                    "L7OK",
                    "Layer7 check passed",
                    duration,
                    None,
                    Some(server_version),
                )
            };
            let next = check.schedule_next(now);
            check.next_check = next;
            return Ok(CheckStep {
                next: Some(next),
                event,
            });
        }

        cleanup_check_socket(check, fdtab, poller);
        let event = check.on_success_full(
            "L7OK",
            "Layer7 check passed",
            duration,
            None,
            Some(server_version),
        );
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

#[allow(clippy::too_many_lines, clippy::unnecessary_wraps)]
fn progress_pgsql_check(
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
    } = check.sub_state.clone()
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
                    check.sub_state = CheckSubState::PgsqlRunning {
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
        let mut buf = [0u8; 4096];
        let mut eof = false;
        loop {
            match check.xprt.recv(sock.as_fd(), &mut buf) {
                Ok(Io::Done(n)) => {
                    recv_buf.extend_from_slice(&buf[..n]);
                }
                Ok(Io::WouldBlock) => break,
                Ok(Io::Eof | Io::Closed) | Err(_) => {
                    eof = true;
                    break;
                }
            }
        }

        if recv_buf.len() < 5 && !eof {
            fdtab.clear_ready(raw_fd, true, false);
            check.sub_state = CheckSubState::PgsqlRunning {
                phase,
                user,
                send_offset,
                req_buf,
                recv_buf,
            };
            return Ok(CheckStep::pending(Some(check.exp)));
        }

        cleanup_check_socket(check, fdtab, poller);
        let event = if recv_buf.first() == Some(&b'R') {
            check.on_success_full(
                "L7OK",
                "Layer7 check passed",
                duration,
                None,
                Some("PostgreSQL server is ok".to_string()),
            )
        } else if recv_buf.first() == Some(&b'E') {
            let info = if recv_buf.len() > 6 {
                let s_bytes = &recv_buf[6..];
                let null_pos = s_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(s_bytes.len());
                String::from_utf8_lossy(&s_bytes[..null_pos]).to_string()
            } else {
                "Error".to_string()
            };
            check.on_failure_full(
                "L7RSP",
                "Layer7 invalid response",
                duration,
                None,
                Some(info),
            )
        } else {
            check.on_failure_full(
                "L7STS",
                "Layer7 wrong status",
                duration,
                None,
                Some("PostgreSQL unknown error".to_string()),
            )
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

#[allow(clippy::too_many_lines, clippy::unnecessary_wraps)]
fn progress_ssl_hello_check(
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
    let Some(sock) = check.sock.as_ref() else {
        cleanup_check_socket(check, fdtab, poller);
        let next = check.schedule_next(now);
        return Ok(CheckStep::pending(Some(next)));
    };

    let CheckSubState::SslHelloRunning {
        mut phase,
        mut send_offset,
        mut recv_buf,
    } = check.sub_state.clone()
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
                    check.sub_state = CheckSubState::SslHelloRunning {
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
        let mut buf = [0u8; 4096];
        let mut eof = false;
        loop {
            match check.xprt.recv(sock.as_fd(), &mut buf) {
                Ok(Io::Done(n)) => {
                    recv_buf.extend_from_slice(&buf[..n]);
                }
                Ok(Io::WouldBlock) => break,
                Ok(Io::Eof | Io::Closed) | Err(_) => {
                    eof = true;
                    break;
                }
            }
        }

        if recv_buf.is_empty() {
            if !eof {
                fdtab.clear_ready(raw_fd, true, false);
                check.sub_state = CheckSubState::SslHelloRunning {
                    phase,
                    send_offset,
                    recv_buf,
                };
                return Ok(CheckStep::pending(Some(check.exp)));
            }
            cleanup_check_socket(check, fdtab, poller);
            let event = check.on_failure_full(
                "L6RSP",
                "Layer6 invalid response",
                duration,
                None,
                Some("TCPCHK got an empty response at step 2".to_string()),
            );
            let next = check.schedule_next(now);
            check.next_check = next;
            return Ok(CheckStep {
                next: Some(next),
                event,
            });
        }

        cleanup_check_socket(check, fdtab, poller);
        let first_byte = recv_buf[0];
        let event = if first_byte == 0x15 || first_byte == 0x16 {
            check.on_success_full(
                "L6OK",
                "Layer6 check passed",
                duration,
                None,
                None,
            )
        } else {
            check.on_failure_full(
                "L6RSP",
                "Layer6 invalid response",
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
        assert_eq!(format_l4_connect_error(&refused), "ECONNREFUSED returned by OS");
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
}
