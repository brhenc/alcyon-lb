// SPDX-License-Identifier: GPL-2.0-or-later
//
// HAProxy configuration parser, ported to Rust.
// Derived from HAProxy 1.0 - 3.5 by Willy Tarreau <willy@meta-x.org>.

#![allow(clippy::struct_excessive_bools)]

use std::net::SocketAddr;
use std::time::Duration;

/// Full `HAProxy` configuration containing one or more proxy sections.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    /// Optional global settings.
    pub global: Option<GlobalSection>,
    /// Optional defaults settings.
    pub defaults: Option<DefaultsSection>,
    /// List of proxy listen sections in order of definition (`HAProxy` 1.0 style).
    pub listens: Vec<ListenSection>,
    /// List of frontend sections (`HAProxy` 1.1+ style).
    pub frontends: Vec<FrontendSection>,
    /// List of backend sections (`HAProxy` 1.1+ style).
    pub backends: Vec<BackendSection>,
}

/// Global section configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GlobalSection {
    /// Number of worker threads.
    pub nbthread: Option<u32>,
    /// Runtime admin socket path.
    pub stats_socket: Option<String>,
    /// Permissions mode for admin socket.
    pub stats_socket_mode: Option<u32>,
    /// Privilege level for admin socket.
    pub stats_socket_level: Option<String>,
    /// Maximum rewrite size in bytes.
    pub maxrewrite: Option<usize>,
    /// Buffer size in bytes.
    pub bufsize: Option<usize>,
    /// Syslog targets declared here. Proxy sections inherit these with `log global`,
    /// which is how the canonical `HAProxy` configuration declares logging.
    pub logs: Vec<LogConfig>,
}

/// Defaults section configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DefaultsSection {
    /// Operating mode (tcp, http).
    pub mode: Option<Mode>,
    /// Configured timeouts.
    pub timeouts: TimeoutConfig,
    /// Whether syslog logging is forwarded to global targets.
    pub log_global: bool,
    /// Syslog targets declared in `defaults`, inherited by every proxy that declares none.
    pub logs: Vec<LogConfig>,
    /// `option log-health-checks` in `defaults`.
    pub log_health_checks: bool,
}

/// Unified timeouts configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimeoutConfig {
    pub connect: Option<Duration>,
    pub client: Option<Duration>,
    pub server: Option<Duration>,
    pub http_request: Option<Duration>,
    pub http_keep_alive: Option<Duration>,
    pub check: Option<Duration>,
    pub queue: Option<Duration>,
    pub tunnel: Option<Duration>,
    pub tarpit: Option<Duration>,
}

/// Bind configuration for frontend listeners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindConfig {
    pub addr: SocketAddr,
    pub ssl: bool,
    pub crt: Vec<String>,
    pub alpn: Vec<String>,
    pub accept_proxy: bool,
    pub accept_proxy_v2: bool,
}

/// Default server options applied to all servers in a backend.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DefaultServerConfig {
    pub check: bool,
    pub inter: Option<Duration>,
    pub fall: Option<u32>,
    pub rise: Option<u32>,
    pub send_proxy: bool,
    pub send_proxy_v2: bool,
    pub maxconn: Option<u32>,
}

/// Modern TCP-request connection action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpReqConnAction {
    TrackSc0 { expr: String, table: Option<String> },
    TrackSc1 { expr: String, table: Option<String> },
    TrackSc2 { expr: String, table: Option<String> },
    SilentDrop,
    Reject,
    Accept,
}

/// Rule pairing a TCP-request connection action with an optional condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpReqConnRule {
    pub action: TcpReqConnAction,
    pub cond: Option<AclCondition>,
}

/// Modern HTTP-request action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpReqAction {
    TrackSc0 {
        expr: String,
        table: Option<String>,
    },
    TrackSc1 {
        expr: String,
        table: Option<String>,
    },
    TrackSc2 {
        expr: String,
        table: Option<String>,
    },
    Return {
        status: u16,
        content_type: Option<String>,
        lf_string: Option<String>,
    },
    Deny {
        deny_status: Option<u16>,
    },
    Allow,
    SetHeader {
        name: String,
        fmt: String,
    },
    AddHeader {
        name: String,
        fmt: String,
    },
    DelHeader {
        name: String,
    },
    ReplaceHeader {
        name: String,
        regex: String,
        repl: String,
    },
    ReplaceValue {
        name: String,
        regex: String,
        repl: String,
    },
    SetPath {
        fmt: String,
    },
    ReplacePath {
        regex: String,
        repl: String,
    },
    SetPathq {
        fmt: String,
    },
    ReplacePathq {
        regex: String,
        repl: String,
    },
    SetQuery {
        fmt: String,
    },
    SetUri {
        fmt: String,
    },
    SetMethod {
        fmt: String,
    },
    SetSrc {
        expr: String,
    },
    SetDst {
        expr: String,
    },
    Redirect {
        location: Option<String>,
        scheme: Option<String>,
        prefix: Option<String>,
        code: Option<u16>,
    },
    StrictMode {
        on: bool,
    },
    SetVar {
        var_name: String,
        expr: String,
    },
    UnsetVar {
        var_name: String,
    },
    NormalizeUri {
        normalizer: String,
        full: bool,
        strict: bool,
    },
    SetTimeout {
        timeout_type: String,
        timeout_val: String,
    },
    Auth,
    Capture {
        expr: String,
        len: Option<usize>,
        id: Option<usize>,
    },
}

/// Rule pairing an HTTP-request action with an optional condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpReqRule {
    pub action: HttpReqAction,
    pub cond: Option<AclCondition>,
}

/// Modern HTTP-response action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpResAction {
    SetHeader { name: String, fmt: String },
    AddHeader { name: String, fmt: String },
    DelHeader { name: String },
    SetStatus { status: u16 },
}

/// Rule pairing an HTTP-response action with an optional condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResRule {
    pub action: HttpResAction,
    pub cond: Option<AclCondition>,
}

/// Modern HTTP-after-response action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpAfterResAction {
    SetHeader { name: String, fmt: String },
    AddHeader { name: String, fmt: String },
    DelHeader { name: String },
}

/// Rule pairing an HTTP-after-response action with an optional condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpAfterResRule {
    pub action: HttpAfterResAction,
    pub cond: Option<AclCondition>,
}

/// A `listen` proxy section combining frontend and backend.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ListenSection {
    /// Proxy name / identifier.
    pub name: String,
    /// Listening socket address (IPv4).
    pub addr: SocketAddr,
    /// Operating mode (tcp, http, health).
    pub mode: Mode,
    /// Whether this proxy is disabled.
    pub disabled: bool,
    /// Cookie name for HTTP session persistence.
    pub cookie: Option<String>,
    /// Connect timeout in milliseconds / Duration.
    pub contimeout: Option<Duration>,
    /// Client timeout in milliseconds / Duration.
    pub clitimeout: Option<Duration>,
    /// Server timeout in milliseconds / Duration.
    pub srvtimeout: Option<Duration>,
    /// Modern structured timeouts.
    pub timeouts: TimeoutConfig,
    /// Number of connection retries before failing over (default: 3).
    pub retries: u32,
    /// Whether reconnection to dispatch address is enabled on error.
    pub redisp: bool,
    /// Maximum concurrent connections for this proxy (default: 2000).
    pub maxconn: u32,
    /// Grace time in milliseconds / Duration before stopping.
    pub grace: Option<Duration>,
    /// Default dispatch address to connect to.
    pub dispatch: Option<SocketAddr>,
    /// Known backend servers.
    pub servers: Vec<Server>,
    /// Syslog logging destinations (up to 2).
    pub logs: Vec<LogConfig>,
    /// `log global`: inherit the targets declared in the `global` section.
    pub log_global: bool,
    /// `option log-health-checks`: log every check whose health counter moved, not only
    /// the transitions between UP and DOWN.
    pub log_health_checks: bool,
    /// Client header regex rewrite rules (up to 10).
    pub cliexp: Vec<HeaderExp>,
    /// Server header regex rewrite rules (up to 10).
    pub srvexp: Vec<HeaderExp>,
    /// Declared ACL rules.
    pub acls: Vec<AclRule>,
    /// Dynamic switching rules (`use_backend <name> [if|unless <acl_cond>]`).
    pub use_backends: Vec<UseBackendRule>,
    /// Default backend name to forward traffic to.
    pub default_backend: Option<String>,
    /// Load balancing algorithm.
    pub balance: BalanceAlgorithm,
    /// Stick table configuration.
    pub stick_table: Option<StickTableConfigAst>,
    /// Stick rules.
    pub stick_rules: Vec<StickRule>,
    /// Modern TCP-request connection rules.
    pub tcp_req_conn_rules: Vec<TcpReqConnRule>,
    /// Modern HTTP-request rules.
    pub http_req_rules: Vec<HttpReqRule>,
    /// Modern HTTP-response rules.
    pub http_res_rules: Vec<HttpResRule>,
    /// Modern HTTP-after-response rules.
    pub http_after_res_rules: Vec<HttpAfterResRule>,
    /// Whether this listen section accepts PROXY protocol (v1 or v2).
    pub accept_proxy: bool,
    /// Whether this listen section strictly requires PROXY protocol v2.
    pub accept_proxy_v2: bool,
    /// Forwardfor header options.
    pub forwardfor: Option<String>,
    /// Originalto header options.
    pub originalto: Option<String>,
    /// Default server options applied to all servers in this listen section.
    pub default_server: Option<DefaultServerConfig>,
    /// Stats applet and dashboard configuration.
    pub stats: StatsConfig,
}

/// Stats configuration options for a proxy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StatsConfig {
    pub enable: bool,
    pub uri: Option<String>,
    pub refresh: Option<Duration>,
    pub admin: bool,
    pub admin_cond: Option<AclCondition>,
    pub show_legends: bool,
    pub show_desc: Option<String>,
    pub show_node: Option<String>,
    pub raw_timeouts: TimeoutConfig,
    pub forwardfor: Option<String>,
    pub originalto: Option<String>,
    pub maxrewrite: Option<usize>,
}

impl Default for ListenSection {
    fn default() -> Self {
        Self {
            name: String::new(),
            addr: SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
            mode: Mode::Tcp,
            disabled: false,
            cookie: None,
            contimeout: None,
            clitimeout: None,
            srvtimeout: None,
            timeouts: TimeoutConfig::default(),
            retries: 3,
            redisp: false,
            maxconn: 2000,
            grace: None,
            dispatch: None,
            default_server: None,
            servers: Vec::new(),
            logs: Vec::new(),
            log_global: false,
            log_health_checks: false,
            cliexp: Vec::new(),
            srvexp: Vec::new(),
            acls: Vec::new(),
            use_backends: Vec::new(),
            default_backend: None,
            balance: BalanceAlgorithm::RoundRobin,
            stick_table: None,
            stick_rules: Vec::new(),
            tcp_req_conn_rules: Vec::new(),
            http_req_rules: Vec::new(),
            http_res_rules: Vec::new(),
            http_after_res_rules: Vec::new(),
            accept_proxy: false,
            accept_proxy_v2: false,
            forwardfor: None,
            originalto: None,
            stats: StatsConfig::default(),
        }
    }
}

/// A `frontend` proxy section.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct FrontendSection {
    /// Frontend name / identifier.
    pub name: String,
    /// Listening socket address (primary/legacy).
    pub bind: Option<SocketAddr>,
    /// Multiple bind listeners with SSL/ALPN/PROXY protocol options.
    pub binds: Vec<BindConfig>,
    /// Operating mode (tcp, http, health).
    pub mode: Mode,
    /// Whether this frontend is disabled.
    pub disabled: bool,
    /// Client timeout in milliseconds / Duration.
    pub clitimeout: Option<Duration>,
    /// Structured timeouts.
    pub timeouts: TimeoutConfig,
    /// Maximum concurrent connections for this proxy (default: 2000).
    pub maxconn: u32,
    /// Default backend name to forward traffic to.
    pub default_backend: Option<String>,
    /// Dynamic switching rules (`use_backend <name> [if|unless <acl_cond>]`).
    pub use_backends: Vec<UseBackendRule>,
    /// Declared ACL rules.
    pub acls: Vec<AclRule>,
    /// Client header regex rewrite rules.
    pub cliexp: Vec<HeaderExp>,
    /// Syslog logging destinations.
    pub logs: Vec<LogConfig>,
    /// `log global`: inherit the targets declared in the `global` section.
    pub log_global: bool,
    /// `option log-health-checks`: log every check whose health counter moved, not only
    /// the transitions between UP and DOWN.
    pub log_health_checks: bool,
    /// Stick table configuration.
    pub stick_table: Option<StickTableConfigAst>,
    /// Stick rules.
    pub stick_rules: Vec<StickRule>,
    /// Modern TCP-request connection rules.
    pub tcp_req_conn_rules: Vec<TcpReqConnRule>,
    /// Modern HTTP-request rules.
    pub http_req_rules: Vec<HttpReqRule>,
    /// Modern HTTP-response rules.
    pub http_res_rules: Vec<HttpResRule>,
    /// Modern HTTP-after-response rules.
    pub http_after_res_rules: Vec<HttpAfterResRule>,
    /// Whether this frontend accepts PROXY protocol (v1 or v2).
    pub accept_proxy: bool,
    /// Whether this frontend strictly requires PROXY protocol v2.
    pub accept_proxy_v2: bool,
    /// Forwardfor header options.
    pub forwardfor: Option<String>,
    /// Originalto header options.
    pub originalto: Option<String>,
    /// Stats applet and dashboard configuration.
    pub stats: StatsConfig,
}

impl Default for FrontendSection {
    fn default() -> Self {
        Self {
            name: String::new(),
            bind: None,
            binds: Vec::new(),
            mode: Mode::Tcp,
            disabled: false,
            clitimeout: None,
            timeouts: TimeoutConfig::default(),
            maxconn: 2000,
            default_backend: None,
            use_backends: Vec::new(),
            acls: Vec::new(),
            cliexp: Vec::new(),
            logs: Vec::new(),
            log_global: false,
            log_health_checks: false,
            stick_table: None,
            stick_rules: Vec::new(),
            tcp_req_conn_rules: Vec::new(),
            http_req_rules: Vec::new(),
            http_res_rules: Vec::new(),
            http_after_res_rules: Vec::new(),
            accept_proxy: false,
            accept_proxy_v2: false,
            forwardfor: None,
            originalto: None,
            stats: StatsConfig::default(),
        }
    }
}

/// A `backend` proxy section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendSection {
    /// Backend name / identifier.
    pub name: String,
    /// Syslog targets. `log` is valid in every proxy section, backends included.
    pub logs: Vec<LogConfig>,
    /// `log global`: inherit the targets declared in the `global` section.
    pub log_global: bool,
    /// `option log-health-checks`: log every check whose health counter moved, not only
    /// the transitions between UP and DOWN.
    pub log_health_checks: bool,
    /// Operating mode (tcp, http, health).
    pub mode: Mode,
    /// Whether this backend is disabled.
    pub disabled: bool,
    /// Load balancing algorithm.
    pub balance: BalanceAlgorithm,
    /// Cookie name for HTTP session persistence.
    pub cookie: Option<String>,
    /// Connect timeout in milliseconds / Duration.
    pub contimeout: Option<Duration>,
    /// Server timeout in milliseconds / Duration.
    pub srvtimeout: Option<Duration>,
    /// Structured timeouts.
    pub timeouts: TimeoutConfig,
    /// Number of connection retries before failing over (default: 3).
    pub retries: u32,
    /// Whether reconnection to dispatch address is enabled on error.
    pub redisp: bool,
    /// Default dispatch address to connect to.
    pub dispatch: Option<SocketAddr>,
    /// Default server options applied to all servers.
    pub default_server: Option<DefaultServerConfig>,
    /// Known backend servers.
    pub servers: Vec<Server>,
    /// Server header regex rewrite rules.
    pub srvexp: Vec<HeaderExp>,
    /// Declared ACL rules.
    pub acls: Vec<AclRule>,
    /// Stick table configuration.
    pub stick_table: Option<StickTableConfigAst>,
    /// Stick rules.
    pub stick_rules: Vec<StickRule>,
    /// Modern HTTP-request rules.
    pub http_req_rules: Vec<HttpReqRule>,
    /// Modern HTTP-response rules.
    pub http_res_rules: Vec<HttpResRule>,
    /// Modern HTTP-after-response rules.
    pub http_after_res_rules: Vec<HttpAfterResRule>,
    /// Forwardfor header options.
    pub forwardfor: Option<String>,
    /// Originalto header options.
    pub originalto: Option<String>,
    /// Stats applet and dashboard configuration.
    pub stats: StatsConfig,
}

impl Default for BackendSection {
    fn default() -> Self {
        Self {
            name: String::new(),
            logs: Vec::new(),
            log_global: false,
            log_health_checks: false,
            mode: Mode::Tcp,
            disabled: false,
            balance: BalanceAlgorithm::RoundRobin,
            cookie: None,
            contimeout: None,
            srvtimeout: None,
            timeouts: TimeoutConfig::default(),
            retries: 3,
            redisp: false,
            dispatch: None,
            default_server: None,
            servers: Vec::new(),
            srvexp: Vec::new(),
            acls: Vec::new(),
            stick_table: None,
            stick_rules: Vec::new(),
            http_req_rules: Vec::new(),
            http_res_rules: Vec::new(),
            http_after_res_rules: Vec::new(),
            forwardfor: None,
            originalto: None,
            stats: StatsConfig::default(),
        }
    }
}

/// Operating mode for a proxy listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// TCP stream proxy (default).
    #[default]
    Tcp,
    /// HTTP proxy with cookie / header rewriting support.
    Http,
    /// Health check responder (replies OK and closes).
    Health,
}

/// Load balancing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BalanceAlgorithm {
    /// Round-robin across active servers (default).
    #[default]
    RoundRobin,
    /// Source IP hash.
    Source,
    /// URI hash.
    Uri,
}

/// Dynamic backend switching rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseBackendRule {
    /// Destination backend name.
    pub backend: String,
    /// Optional conditional expression.
    pub cond: Option<AclCondition>,
}

/// ACL condition with `if` or `unless` and multiple ACL terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclCondition {
    /// True for `if`, false for `unless`.
    pub is_if: bool,
    /// ACL terms (e.g. `is_static !is_local` or `{ path_beg /api/ }`).
    pub terms: Vec<AclTerm>,
}

/// Single term within an ACL condition expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclTerm {
    /// Whether the term is negated with `!`.
    pub negated: bool,
    /// Name or inline expression of the ACL to evaluate.
    pub name: String,
}

/// Declared ACL rule (`acl <name> <expr>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRule {
    /// ACL name (e.g. `is_static`).
    pub name: String,
    /// Raw sample expression & matcher pattern (e.g. `path_beg /static` or `req.hdr(Host),lower -m str example.com`).
    pub expr: String,
}

/// Stick table configuration in AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StickTableConfigAst {
    pub key_type: String,
    pub size: usize,
    pub expire: Duration,
    pub store_fields: Vec<String>,
}

/// Stick rule type and sample expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StickRule {
    pub rule_type: StickRuleType,
    pub expr: String,
}

/// Type of stick rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StickRuleType {
    StickOn,
    StickMatch,
    StickStoreRequest,
    StickStoreResponse,
    TrackSc0,
    TrackSc1,
    TrackSc2,
}

/// Backend server definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// Server identifier (e.g. cookie value or name).
    pub id: String,
    /// Server address and port.
    pub addr: SocketAddr,
    /// Whether health checks are enabled.
    pub check: bool,
    /// Health check interval.
    pub inter: Option<Duration>,
    /// Consecutive failures before marking DOWN.
    pub fall: Option<u32>,
    /// Consecutive successes before marking UP.
    pub rise: Option<u32>,
    /// Whether to prepend PROXY v1 header when forwarding to this server.
    pub send_proxy: bool,
    /// Whether to prepend PROXY v2 header when forwarding to this server.
    pub send_proxy_v2: bool,
    /// Server load balancing weight.
    pub weight: Option<u32>,
    /// Server connection limit.
    pub maxconn: Option<u32>,
    /// Whether this server is a backup server.
    pub backup: bool,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            id: String::new(),
            addr: SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
            check: false,
            inter: None,
            fall: None,
            rise: None,
            send_proxy: false,
            send_proxy_v2: false,
            weight: None,
            maxconn: None,
            backup: false,
        }
    }
}

impl Server {
    #[must_use]
    pub fn new(id: impl Into<String>, addr: SocketAddr) -> Self {
        Self {
            id: id.into(),
            addr,
            check: false,
            inter: None,
            fall: None,
            rise: None,
            send_proxy: false,
            send_proxy_v2: false,
            weight: None,
            maxconn: None,
            backup: false,
        }
    }
}

/// Syslog destination configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogConfig {
    /// Where the lines go.
    pub target: LogTarget,
    /// Syslog facility.
    pub facility: LogFacility,
    /// Optional syslog log level.
    pub level: Option<LogLevel>,
    /// `len <n>`: maximum line length, truncated beyond it.
    ///
    /// `HAProxy` defaults to 1024 and accepts 80..=65535. A line longer than this is cut
    /// rather than split, because a syslog datagram has no continuation.
    pub max_len: usize,
    /// `format <fmt>`: the wire format, as written. Only `rfc3164` is emitted today.
    pub format: Option<String>,
}

/// Where a `log` line sends its output.
///
/// `HAProxy` treats `stdout` and `stderr` as aliases for `fd@1` and `fd@2`
/// (`src/log.c`), which is how a container or a systemd unit collects logs without a
/// syslog daemon. Parsing them as an address rejected the canonical configuration -- it
/// accounted for 19 reg-test failures, all from one line in a shared include.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogTarget {
    /// A syslog server over UDP.
    Udp(SocketAddr),
    /// An already-open file descriptor: `fd@<n>`, `stdout`, `stderr`.
    Fd(i32),
    /// A unix datagram socket path.
    Unix(String),
}

impl LogTarget {
    /// The UDP address, if this is one. Used where only a network target makes sense.
    #[must_use]
    pub const fn udp_addr(&self) -> Option<SocketAddr> {
        match self {
            LogTarget::Udp(a) => Some(*a),
            _ => None,
        }
    }
}

/// Syslog facilities supported by `HAProxy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFacility {
    Kern,
    User,
    Mail,
    Daemon,
    Auth,
    Syslog,
    Lpr,
    News,
    Uucp,
    Cron,
    Auth2,
    Ftp,
    Ntp,
    Audit,
    Alert,
    Cron2,
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
}

/// Syslog log levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Emerg,
    Alert,
    Crit,
    Err,
    Warning,
    Notice,
    Info,
    Debug,
}

/// Regular expression search and replacement rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderExp {
    /// Regular expression pattern to match.
    pub regex: String,
    /// Replacement string.
    pub replacement: String,
}
