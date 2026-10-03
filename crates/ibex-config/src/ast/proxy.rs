// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![allow(clippy::struct_excessive_bools)]

#[allow(unused_imports)]
use super::*;

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
    /// Default hashing method for hash-based balancing algorithms (`hash-type`).
    pub hash_type: Option<HashType>,
    /// Default affinity-preservation mode for hash-based algorithms (`hash-preserve-affinity`).
    pub hash_preserve_affinity: Option<HashPreserveAffinity>,
    /// Default HTTP check configuration (`option httpchk`).
    pub httpchk: Option<HttpChkConfig>,
    /// Protocol-specific check configuration (`option redis-check`, `option smtpchk`, etc.).
    pub proto_check: Option<ProtoCheckConfig>,
    /// Optional name for named defaults sections (`defaults <name>`).
    pub name: Option<String>,
    /// Default custom HTTP check directives (`http-check`).
    pub http_checks: Vec<HttpCheckAction>,
    /// Default custom TCP check directives (`tcp-check`).
    pub tcp_checks: Vec<TcpCheckAction>,
    /// Default TCP check mode enabled (`option tcp-check`).
    pub tcp_check: bool,
    /// Default HTTP request rules (`http-request`).
    pub http_req_rules: Vec<HttpReqRule>,
    /// Default HTTP response rules (`http-response`).
    pub http_res_rules: Vec<HttpResRule>,
    /// Default HTTP after-response rules (`http-after-response`).
    pub http_after_res_rules: Vec<HttpAfterResRule>,
    /// Default TCP request connection rules (`tcp-request connection`).
    pub tcp_req_conn_rules: Vec<TcpReqConnRule>,
    /// Default TCP request session rules (`tcp-request session`).
    pub tcp_req_session_rules: Vec<TcpReqSessionRule>,
    /// Default TCP request content rules (`tcp-request content`).
    pub tcp_req_content_rules: Vec<TcpReqContentRule>,
    /// Default TCP response inspection delay.
    pub tcp_res_inspect_delay: Option<Duration>,
    /// Default TCP response content rules (`tcp-response content`).
    pub tcp_res_content_rules: Vec<TcpReqContentRule>,
    /// Default custom error pages (`errorfile`/`errorfiles`), keyed by status code.
    pub error_files: HashMap<u16, Vec<u8>>,
    /// Default `http-error` overrides, keyed by status code.
    pub error_replies: HashMap<u16, ErrorPageSource>,
    /// Default log tag (`log-tag`).
    pub log_tag: Option<std::sync::Arc<str>>,
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
    /// `monitor-uri <uri>`: requests for this URI are answered by the proxy itself, for
    /// an external load balancer's health probe (`src/http_ana.c`).
    pub monitor_uri: Option<String>,
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
    /// TCP-response inspect delay.
    pub tcp_res_inspect_delay: Option<Duration>,
    /// Modern TCP-response content rules.
    pub tcp_res_content_rules: Vec<TcpReqContentRule>,
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
    /// Hashing method for hash-based balancing algorithms (`hash-type`).
    pub hash_type: Option<HashType>,
    /// Affinity-preservation mode for hash-based algorithms (`hash-preserve-affinity`).
    pub hash_preserve_affinity: Option<HashPreserveAffinity>,
    /// Stats applet and dashboard configuration.
    pub stats: StatsConfig,
    /// HTTP check configuration (`option httpchk`).
    pub httpchk: Option<HttpChkConfig>,
    /// Protocol-specific check configuration (`option redis-check`, `option smtpchk`, etc.).
    pub proto_check: Option<ProtoCheckConfig>,
    /// Custom HTTP check directives (`http-check`).
    pub http_checks: Vec<HttpCheckAction>,
    /// Custom TCP check directives (`tcp-check`).
    pub tcp_checks: Vec<TcpCheckAction>,
    /// TCP check mode enabled (`option tcp-check`).
    pub tcp_check: bool,
    /// Custom error pages (`errorfile`/`errorfiles`), keyed by status code.
    pub error_files: HashMap<u16, Vec<u8>>,
    /// `http-error` overrides, keyed by status code.
    pub error_replies: HashMap<u16, ErrorPageSource>,
    /// Log tag (`log-tag`).
    pub log_tag: Option<std::sync::Arc<str>>,
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
            monitor_uri: None,
            default_backend: None,
            balance: BalanceAlgorithm::RoundRobin,
            stick_table: None,
            stick_rules: Vec::new(),
            tcp_req_inspect_delay: None,
            tcp_req_conn_rules: Vec::new(),
            tcp_req_session_rules: Vec::new(),
            tcp_req_content_rules: Vec::new(),
            tcp_res_inspect_delay: None,
            tcp_res_content_rules: Vec::new(),
            http_req_rules: Vec::new(),
            http_res_rules: Vec::new(),
            http_after_res_rules: Vec::new(),
            accept_proxy: false,
            accept_proxy_v2: false,
            http_reuse: None,
            hash_type: None,
            hash_preserve_affinity: None,
            forwardfor: None,
            originalto: None,
            stats: StatsConfig::default(),
            httpchk: None,
            proto_check: None,
            http_checks: Vec::new(),
            tcp_checks: Vec::new(),
            tcp_check: false,
            error_files: HashMap::new(),
            error_replies: HashMap::new(),
            log_tag: None,
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
    /// `monitor-uri <uri>`: requests for this URI are answered by the proxy itself, for
    /// an external load balancer's health probe (`src/http_ana.c`).
    pub monitor_uri: Option<String>,
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
    /// Custom error pages (`errorfile`/`errorfiles`), keyed by status code.
    pub error_files: HashMap<u16, Vec<u8>>,
    /// `http-error` overrides, keyed by status code.
    pub error_replies: HashMap<u16, ErrorPageSource>,
    /// Log tag (`log-tag`).
    pub log_tag: Option<std::sync::Arc<str>>,
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
            monitor_uri: None,
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
            error_files: HashMap::new(),
            error_replies: HashMap::new(),
            log_tag: None,
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
    /// TCP-response inspect delay.
    pub tcp_res_inspect_delay: Option<Duration>,
    /// Modern TCP-response content rules.
    pub tcp_res_content_rules: Vec<TcpReqContentRule>,
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
    /// Hashing method for hash-based balancing algorithms (`hash-type`).
    pub hash_type: Option<HashType>,
    /// Affinity-preservation mode for hash-based algorithms (`hash-preserve-affinity`).
    pub hash_preserve_affinity: Option<HashPreserveAffinity>,
    /// Stats applet and dashboard configuration.
    pub stats: StatsConfig,
    /// HTTP check configuration (`option httpchk`).
    pub httpchk: Option<HttpChkConfig>,
    /// Protocol-specific check configuration (`option redis-check`, `option smtpchk`, etc.).
    pub proto_check: Option<ProtoCheckConfig>,
    /// Custom HTTP check directives (`http-check`).
    pub http_checks: Vec<HttpCheckAction>,
    /// Custom TCP check directives (`tcp-check`).
    pub tcp_checks: Vec<TcpCheckAction>,
    /// TCP check mode enabled (`option tcp-check`).
    pub tcp_check: bool,
    /// Custom error pages (`errorfile`/`errorfiles`), keyed by status code.
    pub error_files: HashMap<u16, Vec<u8>>,
    /// `http-error` overrides, keyed by status code.
    pub error_replies: HashMap<u16, ErrorPageSource>,
    /// Log tag (`log-tag`).
    pub log_tag: Option<std::sync::Arc<str>>,
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
            tcp_res_inspect_delay: None,
            tcp_res_content_rules: Vec::new(),
            http_req_rules: Vec::new(),
            http_res_rules: Vec::new(),
            http_after_res_rules: Vec::new(),
            forwardfor: None,
            originalto: None,
            http_reuse: None,
            hash_type: None,
            hash_preserve_affinity: None,
            stats: StatsConfig::default(),
            httpchk: None,
            proto_check: None,
            http_checks: Vec::new(),
            tcp_checks: Vec::new(),
            tcp_check: false,
            error_files: HashMap::new(),
            error_replies: HashMap::new(),
            log_tag: None,
        }
    }
}

