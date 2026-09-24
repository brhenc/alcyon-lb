// SPDX-License-Identifier: GPL-2.0-or-later
//
// HAProxy configuration parser, ported to Rust.
// Derived from HAProxy 1.0 - 3.5 by Willy Tarreau <willy@meta-x.org>.

#![allow(clippy::struct_excessive_bools)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{LazyLock, RwLock};
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
    /// Buffer size in bytes (`tune.bufsize`).
    pub bufsize: Option<usize>,
    /// Small buffer size in bytes (`tune.bufsize.small`).
    pub bufsize_small: Option<usize>,
    /// Large buffer size in bytes (`tune.bufsize.large`).
    pub bufsize_large: Option<usize>,
    /// Maximum total streams per HTTP/2 connection (`tune.h2.fe.max-total-streams`). Default: 0 (unlimited).
    pub h2_max_total_streams: Option<usize>,
    /// Glitches threshold before graceful GOAWAY and hard close (`tune.h2.fe.glitches-threshold`). Default: 0 (disabled).
    pub h2_glitches_threshold: Option<usize>,
    /// Global maximum connection limit.
    pub maxconn: Option<u32>,
    /// Background daemon mode.
    pub daemon: bool,
    /// Master-worker mode.
    pub master_worker: bool,
    /// User name for privilege dropping.
    pub user: Option<String>,
    /// Group name for privilege dropping.
    pub group: Option<String>,
    /// Chroot directory.
    pub chroot: Option<String>,
    /// Pidfile path.
    pub pidfile: Option<String>,
    /// Hard stop timeout on reload/exit.
    pub hard_stop_after: Option<Duration>,
    /// Max SSL connection limit.
    pub maxsslconn: Option<u32>,
    /// Default SSL bind ciphers.
    pub ssl_default_bind_ciphers: Option<String>,
    /// Default SSL bind options.
    pub ssl_default_bind_options: Option<String>,
    /// Default SSL server ciphers.
    pub ssl_default_server_ciphers: Option<String>,
    /// Default SSL server options.
    pub ssl_default_server_options: Option<String>,
    /// Syslog targets declared here. Proxy sections inherit these with `log global`,
    /// which is how the canonical `HAProxy` configuration declares logging.
    pub logs: Vec<LogConfig>,
    /// Global variables initialized at startup via `set-var` and `set-var-fmt`.
    pub set_vars: Vec<GlobalSetVar>,
}

/// Global variable initialized at startup via `set-var` or `set-var-fmt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalSetVar {
    /// Variable name (e.g. `proc.foo`).
    pub name: String,
    /// Expression or format string.
    pub expr: String,
    /// Whether this variable uses format-string interpolation (`set-var-fmt`).
    pub is_fmt: bool,
}

/// Defaults section configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DefaultsSection {
    /// Operating mode (tcp, http).
    pub mode: Option<Mode>,
    /// Configured timeouts.
    pub timeouts: TimeoutConfig,
    /// Default retries count.
    pub retries: Option<u32>,
    /// Default redispatch flag.
    pub redisp: bool,
    /// Default maxconn.
    pub maxconn: Option<u32>,
    /// Default load balancing algorithm.
    pub balance: Option<BalanceAlgorithm>,
    /// Default cookie name.
    pub cookie: Option<String>,
    /// Default server options.
    pub default_server: Option<DefaultServerConfig>,
    /// Default stats configuration.
    pub stats: StatsConfig,
    /// Whether syslog logging is forwarded to global targets.
    pub log_global: bool,
    /// Syslog targets declared in `defaults`, inherited by every proxy that declares none.
    pub logs: Vec<LogConfig>,
    /// `option log-health-checks` in `defaults`.
    pub log_health_checks: bool,
    /// Default TCP request inspection delay.
    pub tcp_req_inspect_delay: Option<Duration>,
    /// Default HTTP connection reuse strategy (`http-reuse`).
    pub http_reuse: Option<HttpReuse>,
    /// Default HTTP check configuration (`option httpchk`).
    pub httpchk: Option<HttpChkConfig>,
    /// Default custom HTTP check directives (`http-check`).
    pub http_checks: Vec<HttpCheckAction>,
    /// Default custom TCP check directives (`tcp-check`).
    pub tcp_checks: Vec<TcpCheckAction>,
    /// Default TCP check mode enabled (`option tcp-check`).
    pub tcp_check: bool,
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
    pub quic: bool,
    pub ssl: bool,
    pub crt: Vec<String>,
    pub alpn: Vec<String>,
    pub proto: Option<String>,
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
    pub check_port: Option<u16>,
    pub check_proto: Option<String>,
    pub check_ssl: bool,
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
    SetSrc { expr: String },
    SetDst { expr: String },
    DoLog,
}

/// Rule pairing a TCP-request connection action with an optional condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpReqConnRule {
    pub action: TcpReqConnAction,
    pub cond: Option<AclCondition>,
}

/// Modern TCP-request session action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpReqSessionAction {
    TrackSc0 { expr: String, table: Option<String> },
    TrackSc1 { expr: String, table: Option<String> },
    TrackSc2 { expr: String, table: Option<String> },
    SetVar { var_name: String, expr: String },
    SetVarFmt { var_name: String, fmt: String },
    UnsetVar { var_name: String },
    SetSrc { expr: String },
    SetDst { expr: String },
    SilentDrop,
    Reject,
    Accept,
    AttachSrv { name: String },
    DoLog,
    ScIncGpc0 { sc: u8 },
    ScIncGpc1 { sc: u8 },
    ScSetGpt0 { sc: u8, expr: String },
}

/// Rule pairing a TCP-request session action with an optional condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpReqSessionRule {
    pub action: TcpReqSessionAction,
    pub cond: Option<AclCondition>,
}

/// Modern TCP-request content action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpReqContentAction {
    TrackSc0 { expr: String, table: Option<String> },
    TrackSc1 { expr: String, table: Option<String> },
    TrackSc2 { expr: String, table: Option<String> },
    SetVar { var_name: String, expr: String },
    SetVarFmt { var_name: String, fmt: String },
    UnsetVar { var_name: String },
    SetSrc { expr: String },
    SetDst { expr: String },
    SilentDrop,
    Reject,
    Accept,
    SwitchModeHttp { proto: Option<String> },
    ScIncGpc0 { sc: u8 },
    ScIncGpc1 { sc: u8 },
    ScSetGpt0 { sc: u8, expr: String },
    DoLog,
    UseService { service: String },
    Lua { name: String },
}

/// Rule pairing a TCP-request content action with an optional condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpReqContentRule {
    pub action: TcpReqContentAction,
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
    SetVarFmt {
        var_name: String,
        fmt: String,
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
    ScIncGpc0 {
        sc: u8,
    },
    ScIncGpc1 {
        sc: u8,
    },
    ScSetGpt0 {
        sc: u8,
        expr: String,
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
    /// TCP-request inspect delay.
    pub tcp_req_inspect_delay: Option<Duration>,
    /// Modern TCP-request connection rules.
    pub tcp_req_conn_rules: Vec<TcpReqConnRule>,
    /// Modern TCP-request session rules.
    pub tcp_req_session_rules: Vec<TcpReqSessionRule>,
    /// Modern TCP-request content rules.
    pub tcp_req_content_rules: Vec<TcpReqContentRule>,
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
    /// HTTP connection reuse strategy (`http-reuse`).
    pub http_reuse: Option<HttpReuse>,
    /// Stats applet and dashboard configuration.
    pub stats: StatsConfig,
    /// HTTP check configuration (`option httpchk`).
    pub httpchk: Option<HttpChkConfig>,
    /// Custom HTTP check directives (`http-check`).
    pub http_checks: Vec<HttpCheckAction>,
    /// Custom TCP check directives (`tcp-check`).
    pub tcp_checks: Vec<TcpCheckAction>,
    /// TCP check mode enabled (`option tcp-check`).
    pub tcp_check: bool,
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
            tcp_req_inspect_delay: None,
            tcp_req_conn_rules: Vec::new(),
            tcp_req_session_rules: Vec::new(),
            tcp_req_content_rules: Vec::new(),
            http_req_rules: Vec::new(),
            http_res_rules: Vec::new(),
            http_after_res_rules: Vec::new(),
            accept_proxy: false,
            accept_proxy_v2: false,
            http_reuse: None,
            forwardfor: None,
            originalto: None,
            stats: StatsConfig::default(),
            httpchk: None,
            http_checks: Vec::new(),
            tcp_checks: Vec::new(),
            tcp_check: false,
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
    /// TCP-request inspect delay.
    pub tcp_req_inspect_delay: Option<Duration>,
    /// Modern TCP-request connection rules.
    pub tcp_req_conn_rules: Vec<TcpReqConnRule>,
    /// Modern TCP-request session rules.
    pub tcp_req_session_rules: Vec<TcpReqSessionRule>,
    /// Modern TCP-request content rules.
    pub tcp_req_content_rules: Vec<TcpReqContentRule>,
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
            tcp_req_inspect_delay: None,
            tcp_req_conn_rules: Vec::new(),
            tcp_req_session_rules: Vec::new(),
            tcp_req_content_rules: Vec::new(),
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
    /// TCP-request inspect delay.
    pub tcp_req_inspect_delay: Option<Duration>,
    /// Modern TCP-request content rules.
    pub tcp_req_content_rules: Vec<TcpReqContentRule>,
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
    /// HTTP connection reuse strategy (`http-reuse`).
    pub http_reuse: Option<HttpReuse>,
    /// Stats applet and dashboard configuration.
    pub stats: StatsConfig,
    /// HTTP check configuration (`option httpchk`).
    pub httpchk: Option<HttpChkConfig>,
    /// Custom HTTP check directives (`http-check`).
    pub http_checks: Vec<HttpCheckAction>,
    /// Custom TCP check directives (`tcp-check`).
    pub tcp_checks: Vec<TcpCheckAction>,
    /// TCP check mode enabled (`option tcp-check`).
    pub tcp_check: bool,
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
            tcp_req_inspect_delay: None,
            tcp_req_content_rules: Vec::new(),
            http_req_rules: Vec::new(),
            http_res_rules: Vec::new(),
            http_after_res_rules: Vec::new(),
            forwardfor: None,
            originalto: None,
            http_reuse: None,
            stats: StatsConfig::default(),
            httpchk: None,
            http_checks: Vec::new(),
            tcp_checks: Vec::new(),
            tcp_check: false,
        }
    }
}

/// Connection reuse mode for backends (`http-reuse`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpReuse {
    Never,
    #[default]
    Safe,
    Aggressive,
    Always,
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
    /// Least connections.
    Leastconn,
    /// Static round-robin.
    StaticRr,
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
    /// Custom port for health checks (`check-port` / `port`).
    pub check_port: Option<u16>,
    /// Protocol for health checks (`check-proto`).
    pub check_proto: Option<String>,
    /// Whether health checks use SSL (`check-ssl`).
    pub check_ssl: bool,
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
            check_port: None,
            check_proto: None,
            check_ssl: false,
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
            check_port: None,
            check_proto: None,
            check_ssl: false,
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

/// Configuration for `option httpchk [<method>] <uri> [<version>] [<host>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpChkConfig {
    pub method: Option<String>,
    pub uri: Option<String>,
    pub version: Option<String>,
    pub host: Option<String>,
}

/// Action in an `http-check` rule list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpCheckAction {
    Connect {
        addr: Option<SocketAddr>,
        port: Option<u16>,
        send_proxy: bool,
    },
    Send {
        method: Option<String>,
        uri: Option<String>,
        version: Option<String>,
        headers: Vec<(String, String)>,
        body: Option<String>,
    },
    Expect {
        pattern: HttpCheckExpectPattern,
        negate: bool,
    },
    Comment(String),
    DisableOn404,
    SendState,
    SetVar {
        var_name: String,
        expr: String,
    },
    UnsetVar {
        var_name: String,
    },
}

/// Pattern to expect in an `http-check expect` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpCheckExpectPattern {
    Status(Vec<u16>),
    StatusRange(u16, u16),
    String(String),
    RStatus(String),
    RString(String),
    Hdr {
        name: String,
        match_type: MatchType,
        value: Option<String>,
        value_match_type: MatchType,
    },
    Fhdr {
        name: String,
        match_type: MatchType,
        value: Option<String>,
        value_match_type: MatchType,
    },
}

/// Match type for header expectation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MatchType {
    #[default]
    Str,
    Beg,
    End,
    Sub,
    Reg,
}

/// Action in a `tcp-check` rule list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpCheckAction {
    Connect {
        port: Option<u16>,
        send_proxy: bool,
    },
    Send(Vec<u8>),
    Expect {
        pattern: TcpCheckExpectPattern,
        negate: bool,
        min_recv: Option<usize>,
        comment: Option<String>,
    },
    Comment(String),
}

/// Pattern to expect in a `tcp-check expect` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpCheckExpectPattern {
    String(String),
    Binary(Vec<u8>),
    RString(String),
}

/// Fully resolved health check configuration for a backend server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedCheckConfig {
    TcpConnect,
    Http(ResolvedHttpCheck),
    TcpSteps(Vec<ResolvedTcpStep>),
}

/// Resolved HTTP health check parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHttpCheck {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub host: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub send_state: bool,
    pub expect_rules: Vec<ResolvedHttpExpectRule>,
    pub check_port: Option<u16>,
    pub send_proxy: bool,
}

/// Single expectation rule for an HTTP health check response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHttpExpectRule {
    pub pattern: ResolvedHttpExpectPattern,
    pub negate: bool,
}

/// Pattern to match against an HTTP health check response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedHttpExpectPattern {
    Status(Vec<u16>),
    StatusRange(u16, u16),
    String(String),
    RStatus(String),
    RString(String),
    Hdr {
        name: String,
        match_type: MatchType,
        value: Option<String>,
        value_match_type: MatchType,
    },
    Fhdr {
        name: String,
        match_type: MatchType,
        value: Option<String>,
        value_match_type: MatchType,
    },
}

/// Single step in a multi-step TCP health check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedTcpStep {
    Connect {
        port: Option<u16>,
        send_proxy: bool,
    },
    Send(Vec<u8>),
    Expect {
        pattern: ResolvedTcpExpectPattern,
        negate: bool,
        min_recv: usize,
        comment: Option<String>,
    },
    Comment(String),
}

/// Pattern to match against TCP received data in a TCP health check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedTcpExpectPattern {
    String(String),
    Binary(Vec<u8>),
    RString(String),
}

impl From<&HttpCheckExpectPattern> for ResolvedHttpExpectPattern {
    fn from(pattern: &HttpCheckExpectPattern) -> Self {
        match pattern {
            HttpCheckExpectPattern::Status(codes) => Self::Status(codes.clone()),
            HttpCheckExpectPattern::StatusRange(low, high) => Self::StatusRange(*low, *high),
            HttpCheckExpectPattern::String(s) => Self::String(s.clone()),
            HttpCheckExpectPattern::RStatus(s) => Self::RStatus(s.clone()),
            HttpCheckExpectPattern::RString(s) => Self::RString(s.clone()),
            HttpCheckExpectPattern::Hdr {
                name,
                match_type,
                value,
                value_match_type,
            } => Self::Hdr {
                name: name.clone(),
                match_type: *match_type,
                value: value.clone(),
                value_match_type: *value_match_type,
            },
            HttpCheckExpectPattern::Fhdr {
                name,
                match_type,
                value,
                value_match_type,
            } => Self::Fhdr {
                name: name.clone(),
                match_type: *match_type,
                value: value.clone(),
                value_match_type: *value_match_type,
            },
        }
    }
}

impl From<&TcpCheckExpectPattern> for ResolvedTcpExpectPattern {
    fn from(pattern: &TcpCheckExpectPattern) -> Self {
        match pattern {
            TcpCheckExpectPattern::String(s) => Self::String(s.clone()),
            TcpCheckExpectPattern::Binary(b) => Self::Binary(b.clone()),
            TcpCheckExpectPattern::RString(r) => Self::RString(r.clone()),
        }
    }
}

impl ResolvedHttpExpectRule {
    #[must_use]
    pub fn matches(&self, status: u16, headers: &[(String, String)], body: &[u8]) -> bool {
        let pattern_matched = match &self.pattern {
            ResolvedHttpExpectPattern::Status(codes) => codes.contains(&status),
            ResolvedHttpExpectPattern::StatusRange(low, high) => status >= *low && status <= *high,
            ResolvedHttpExpectPattern::RStatus(pattern) => {
                let status_str = status.to_string();
                regex::Regex::new(pattern).is_ok_and(|re| re.is_match(&status_str))
            }
            ResolvedHttpExpectPattern::String(s) => {
                let body_str = String::from_utf8_lossy(body);
                body_str.contains(s.as_str())
            }
            ResolvedHttpExpectPattern::RString(pattern) => {
                let body_str = String::from_utf8_lossy(body);
                regex::Regex::new(pattern).is_ok_and(|re| re.is_match(&body_str))
            }
            ResolvedHttpExpectPattern::Hdr {
                name,
                match_type,
                value,
                value_match_type,
            }
            | ResolvedHttpExpectPattern::Fhdr {
                name,
                match_type,
                value,
                value_match_type,
            } => {
                let name_matches = |hname: &str| -> bool {
                    match match_type {
                        MatchType::Str => hname.eq_ignore_ascii_case(name),
                        MatchType::Beg => {
                            hname.to_ascii_lowercase().starts_with(&name.to_ascii_lowercase())
                        }
                        MatchType::End => {
                            hname.to_ascii_lowercase().ends_with(&name.to_ascii_lowercase())
                        }
                        MatchType::Sub => {
                            hname.to_ascii_lowercase().contains(&name.to_ascii_lowercase())
                        }
                        MatchType::Reg => regex::Regex::new(name).is_ok_and(|re| re.is_match(hname)),
                    }
                };

                let val_matches = |hval: &str, target_val: &str| -> bool {
                    match value_match_type {
                        MatchType::Str => {
                            hval.split(',').any(|part| part.trim().eq_ignore_ascii_case(target_val))
                                || hval.eq_ignore_ascii_case(target_val)
                                || hval.contains(target_val)
                        }
                        MatchType::Beg => hval.split(',').any(|part| part.trim().starts_with(target_val)) || hval.starts_with(target_val),
                        MatchType::End => hval.split(',').any(|part| part.trim().ends_with(target_val)) || hval.ends_with(target_val),
                        MatchType::Sub => hval.contains(target_val),
                        MatchType::Reg => regex::Regex::new(target_val).is_ok_and(|re| re.is_match(hval)),
                    }
                };

                headers.iter().any(|(hname, hval)| {
                    if name_matches(hname) {
                        if let Some(target_val) = value {
                            val_matches(hval, target_val)
                        } else {
                            true
                        }
                    } else {
                        false
                    }
                })
            }
        };

        if self.negate {
            !pattern_matched
        } else {
            pattern_matched
        }
    }
}

impl ResolvedTcpExpectPattern {
    #[must_use]
    pub fn matches(&self, data: &[u8]) -> bool {
        match self {
            ResolvedTcpExpectPattern::String(s) => {
                let needle = s.as_bytes();
                if needle.is_empty() {
                    true
                } else {
                    data.windows(needle.len()).any(|w| w == needle)
                }
            }
            ResolvedTcpExpectPattern::Binary(b) => {
                if b.is_empty() {
                    true
                } else {
                    data.windows(b.len()).any(|w| w == b.as_slice())
                }
            }
            ResolvedTcpExpectPattern::RString(pattern) => {
                let data_str = String::from_utf8_lossy(data);
                regex::Regex::new(pattern).is_ok_and(|re| re.is_match(&data_str))
            }
        }
    }
}

static RESOLVED_CHECKS: LazyLock<RwLock<HashMap<(usize, usize), ResolvedCheckConfig>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

static ADDR_CHECKS: LazyLock<RwLock<HashMap<SocketAddr, ResolvedCheckConfig>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

pub fn register_resolved_check(proxy_idx: usize, server_idx: usize, check: ResolvedCheckConfig) {
    if let Ok(mut map) = RESOLVED_CHECKS.write() {
        map.insert((proxy_idx, server_idx), check);
    }
}

pub fn register_resolved_check_for_addr(addr: SocketAddr, check: ResolvedCheckConfig) {
    if let Ok(mut map) = ADDR_CHECKS.write() {
        map.insert(addr, check);
    }
}

pub fn clear_resolved_checks() {
    if let Ok(mut map) = RESOLVED_CHECKS.write() {
        map.clear();
    }
    if let Ok(mut map) = ADDR_CHECKS.write() {
        map.clear();
    }
}

#[must_use]
pub fn get_resolved_check_config(
    proxy_idx: usize,
    server_idx: usize,
    addr: SocketAddr,
) -> Option<ResolvedCheckConfig> {
    if let Ok(map) = RESOLVED_CHECKS.read() {
        if let Some(cfg) = map.get(&(proxy_idx, server_idx)) {
            return Some(cfg.clone());
        }
    }
    if let Ok(map) = ADDR_CHECKS.read() {
        if let Some(cfg) = map.get(&addr) {
            return Some(cfg.clone());
        }
    }
    None
}
