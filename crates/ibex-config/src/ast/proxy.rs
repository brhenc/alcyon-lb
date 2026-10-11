// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![allow(clippy::struct_excessive_bools)]

#[allow(unused_imports)]
use super::*;

/// Defaults section configuration.
/// The connection mode `option http-keep-alive`, `http-server-close` and `httpclose` choose
/// (`PR_O_HTTP_MODE`); the last one in a section wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpMode {
    #[default]
    KeepAlive,
    /// Each request on its own server connection, asked to close; the client connection stays.
    ServerClose,
    /// As `ServerClose` on the server side, and the client connection closes after each
    /// response when the frontend has it.
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DefaultsSection {
    /// Operating mode (tcp, http).
    pub mode: Option<Mode>,
    /// Configured timeouts.
    pub timeouts: TimeoutConfig,
    /// Default retries count.
    pub retries: Option<u32>,
    /// `retry-on`, as the `RE_*` bits; `None` is the default, `RE_CONN_FAILED`.
    pub retry_on: Option<u32>,
    /// Default redispatch flag.
    pub redisp: bool,
    /// `option redispatch <interval>`: retries between redispatches (`redispatch_after`);
    /// negative counts back from the last retry, the default `-1` redispatches on it.
    pub redisp_after: i32,
    /// Default maxconn.
    pub maxconn: Option<u32>,
    /// `default_backend`, inherited by the frontends and listens that name none.
    pub default_backend: Option<String>,
    /// Default load balancing algorithm.
    pub balance: Option<BalanceAlgorithm>,
    /// The `cookie` line, inherited by the backends and listens that have none.
    pub cookie: Option<CookieConfig>,
    /// Default server options.
    pub default_server: Option<DefaultServerConfig>,
    /// Default stats configuration.
    pub stats: StatsConfig,
    /// Whether syslog logging is forwarded to global targets.
    pub log_global: bool,
    /// Syslog targets declared in `defaults`, inherited by every proxy that declares none.
    pub logs: Vec<LogConfig>,
    /// `option log-health-checks` in `defaults`.
    /// `log-format`, or the default chosen by `option httplog` / `option tcplog`.
    pub log_format: Option<LogFormatSpec>,
    /// `unique-id-format`: the transaction's unique ID, built when first used.
    pub unique_id_format: Option<String>,
    /// `error-log-format`: the line for a connection that fails before a stream exists
    /// (a failed TLS handshake, a refused PROXY header, a request the mux refuses).
    pub error_log_format: Option<String>,
    /// `unique-id-header`: the request header the unique ID is sent to the server in.
    pub unique_id_header: Option<String>,
    pub log_health_checks: bool,
    /// `option http-buffer-request`: wait for the request body before the rules run (as
    /// an implicit `http-request wait-for-body` ahead of them).
    pub buffer_request: bool,
    /// `option abortonclose` (`Some(true)`), `no option abortonclose` (`Some(false)`), or
    /// neither: then on for an HTTP stream, as `HAProxy` has it (`proxy_abrt_close_def`).
    pub abortonclose: Option<bool>,
    /// `option h1-case-adjust-bogus-client` ([`H1_ADJ_CLIENT`]) and `-server` ([`H1_ADJ_SERVER`]).
    pub h1_adjust: u8,
    /// The last of `option http-keep-alive`, `http-server-close` and `httpclose`.
    pub http_mode: HttpMode,
    /// `option persist`: a server a cookie or stick table names is used even when it is down.
    pub persist: bool,
    /// `option dontlognull`: no log line for a connection that carried nothing.
    pub dontlognull: bool,
    /// `option http-ignore-probes`: a connection that sends nothing before it closes or
    /// times out is sent nothing, not logged and not counted.
    pub http_ignore_probes: bool,
    /// `option dontlog-normal`, `option log-separate-errors` and `option logasap`, as the
    /// `LOG_OPT_*` bits.
    pub log_opts: u8,
    /// `option forwardfor` in `defaults`: the `except` network, empty for none.
    pub forwardfor: Option<String>,
    /// `option forwardfor ... if-none` (without it, `HAProxy` adds the header always).
    pub forwardfor_if_none: bool,
    /// `option forwarded`: the RFC 7239 header parameters to add; `None` when it is off.
    pub forwarded: Option<Box<Forwarded>>,
    /// `option originalto` in `defaults`: the `except` network, empty for none.
    pub originalto: Option<String>,
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
    pub tcp_res_content_rules: Vec<TcpResContentRule>,
    /// Default custom error pages (`errorfile`/`errorfiles`), keyed by status code.
    pub error_files: HashMap<u16, Vec<u8>>,
    /// Default `http-error` overrides, keyed by status code.
    pub error_replies: HashMap<u16, ErrorPageSource>,
    /// Default log tag (`log-tag`).
    pub log_tag: Option<std::sync::Arc<str>>,
}

/// A backend's `cookie <name> [options]` line (`ck_opts`, `cookie_*` in HAProxy's
/// `struct proxy`). A later line replaces it whole, as HAProxy resets them all.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CookieConfig {
    pub name: String,
    pub rewrite: bool,
    pub indirect: bool,
    pub insert: bool,
    pub prefix: bool,
    pub nocache: bool,
    pub postonly: bool,
    pub preserve: bool,
    pub httponly: bool,
    pub secure: bool,
    /// Every `domain`, joined as HAProxy joins them: `a; domain=b`.
    pub domain: Option<String>,
    /// Every `attr`, joined with `; `.
    pub attrs: Option<String>,
    /// Seconds; 0 is unset.
    pub maxidle: u32,
    pub maxlife: u32,
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

/// The socket options a `bind` line sets on its listening sockets (T207).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SocketTuning {
    /// `backlog <n>`: the `listen()` backlog; `None` keeps the runtime default.
    pub backlog: Option<u32>,
    /// `v6only` (`Some(true)`) / `v4v6` (`Some(false)`): `IPV6_V6ONLY` on an IPv6 address.
    pub v6only: Option<bool>,
    /// `tcp-ut <delay>`: `TCP_USER_TIMEOUT`.
    pub tcp_user_timeout: Option<Duration>,
    /// `cc <algo>`: `TCP_CONGESTION`.
    pub congestion: Option<String>,
    /// `mss <n>`: `TCP_MAXSEG`.
    pub mss: Option<u32>,
}

/// Bind configuration for frontend listeners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindConfig {
    /// Socket options from the `bind` line; `None` when it sets none (boxed: a frontend
    /// and a bind are paid for 60,000 times over in `request_allocations`).
    pub sock: Option<Box<SocketTuning>>,
    /// The configuration line of the `bind` (0 for one made in code), for the messages that
    /// name it.
    pub line: usize,
    pub addr: SocketAddr,
    pub quic: bool,
    pub ssl: bool,
    pub crt: Vec<String>,
    pub alpn: Vec<String>,
    pub proto: Option<String>,
    pub accept_proxy: bool,
    pub accept_proxy_v2: bool,
    /// `name <n>`: what `so_name` reads on connections this bind accepted.
    pub name: Option<String>,
    /// `id <n>`: the listener's explicit numeric id, what `so_id` reads. `None` takes the
    /// next free one in the proxy.
    pub id: Option<u32>,
    /// `ssl-min-ver`, also `force-tlsvN` / `no-tlsvN`, and `ssl-default-bind-options` where the line says nothing.
    pub min_ver: Option<TlsVersion>,
    /// `ssl-max-ver`, likewise.
    pub max_ver: Option<TlsVersion>,
}

/// A `listen` proxy section combining frontend and backend.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ListenSection {
    /// Proxy name / identifier.
    pub name: String,
    /// Address of the first `bind` line (what the proxy reports as its address).
    pub addr: SocketAddr,
    /// Every `bind` line, with its TLS settings. Empty only for a section built in code
    /// that sets `addr` alone: that is one plaintext bind on `addr`.
    pub binds: Vec<BindConfig>,
    /// Operating mode (tcp, http, health).
    pub mode: Mode,
    /// Whether this proxy is disabled.
    pub disabled: bool,
    /// `description <text>`: free text shown on the stats page above the proxy's table (`px->desc`).
    pub description: Option<String>,
    /// `id <n>`: the proxy's explicit numeric id (`HAProxy` `PR_O_FORCED_ID`); `None` takes the next free one.
    pub id: Option<u32>,
    /// The `cookie` line: HTTP session persistence.
    pub cookie: Option<CookieConfig>,
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
    /// `retry-on`, as the `RE_*` bits: what a failed attempt is retried on.
    pub retry_on: u32,
    /// Whether reconnection to dispatch address is enabled on error.
    pub redisp: bool,
    /// `option redispatch <interval>`: retries between redispatches (`redispatch_after`);
    /// negative counts back from the last retry, the default `-1` redispatches on it.
    pub redisp_after: i32,
    /// Maximum concurrent connections for this proxy; 0 when not set, which is the global `maxconn`.
    pub maxconn: u32,
    /// Default dispatch address to connect to.
    pub dispatch: Option<SocketAddr>,
    /// Known backend servers.
    pub servers: Vec<Server>,
    /// The explicit `id` and the initial health of some of the servers.
    pub server_extras: ServerExtras,
    /// Syslog logging destinations (up to 2).
    pub logs: Vec<LogConfig>,
    /// `log global`: inherit the targets declared in the `global` section.
    pub log_global: bool,
    /// `option log-health-checks`: log every check whose health counter moved, not only
    /// the transitions between UP and DOWN.
    /// `log-format`, or the default chosen by `option httplog` / `option tcplog`.
    pub log_format: Option<LogFormatSpec>,
    /// `unique-id-format`: the transaction's unique ID, built when first used.
    pub unique_id_format: Option<String>,
    /// `error-log-format`: the line for a connection that fails before a stream exists
    /// (a failed TLS handshake, a refused PROXY header, a request the mux refuses).
    pub error_log_format: Option<String>,
    /// `unique-id-header`: the request header the unique ID is sent to the server in.
    pub unique_id_header: Option<String>,
    /// `capture request header`, in declaration order.
    pub req_header_captures: Vec<HeaderCapture>,
    /// `capture response header`, in declaration order.
    pub res_header_captures: Vec<HeaderCapture>,
    pub log_health_checks: bool,
    /// `option http-buffer-request`: wait for the request body before the rules run (as
    /// an implicit `http-request wait-for-body` ahead of them).
    pub buffer_request: bool,
    /// `option abortonclose` (`Some(true)`), `no option abortonclose` (`Some(false)`), or
    /// neither: then on for an HTTP stream, as `HAProxy` has it (`proxy_abrt_close_def`).
    pub abortonclose: Option<bool>,
    /// `option h1-case-adjust-bogus-client` ([`H1_ADJ_CLIENT`]) and `-server` ([`H1_ADJ_SERVER`]).
    pub h1_adjust: u8,
    /// The last of `option http-keep-alive`, `http-server-close` and `httpclose`.
    pub http_mode: HttpMode,
    /// `option persist`: a server a cookie or stick table names is used even when it is down.
    pub persist: bool,
    /// `option dontlognull`: no log line for a connection that carried nothing.
    pub dontlognull: bool,
    /// `option http-ignore-probes`: a connection that sends nothing before it closes or
    /// times out is sent nothing, not logged and not counted.
    pub http_ignore_probes: bool,
    /// `option dontlog-normal`, `option log-separate-errors` and `option logasap`, as the
    /// `LOG_OPT_*` bits.
    pub log_opts: u8,
    /// Client header regex rewrite rules (up to 10).
    pub cliexp: Vec<HeaderExp>,
    /// Server header regex rewrite rules (up to 10).
    pub srvexp: Vec<HeaderExp>,
    /// Declared ACL rules.
    pub acls: Vec<AclRule>,
    /// Dynamic switching rules (`use_backend <name> [if|unless <acl_cond>]`).
    pub use_backends: Vec<UseBackendRule>,
    /// `force-be-switch if|unless <cond>`: when one matches, `use_backend` and
    /// `default_backend` may pick a backend that is disabled.
    pub force_be_switch: Vec<AclCondition>,
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
    pub tcp_res_content_rules: Vec<TcpResContentRule>,
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
    /// `option forwardfor ... if-none` (without it, `HAProxy` adds the header always).
    pub forwardfor_if_none: bool,
    /// `option forwarded`: the RFC 7239 header parameters to add; `None` when it is off.
    pub forwarded: Option<Box<Forwarded>>,
    /// Originalto header options.
    pub originalto: Option<String>,
    /// Default server options applied to all servers in this listen section.
    pub default_server: Option<DefaultServerConfig>,
    /// `use-server <server> if|unless <cond>` rules, in order.
    pub use_servers: Vec<UseServerRule>,
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
    /// This section has `http-check` rules or `option httpchk` of its own, so none of the
    /// defaults' were kept (`HAProxy` hands a proxy the defaults' rule set only when it
    /// has none).
    pub http_check_own: bool,
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
    pub show_desc: Option<Box<str>>,
    pub show_node: Option<Box<str>>,
    pub raw_timeouts: TimeoutConfig,
    pub forwardfor: Option<String>,
    /// `option forwardfor ... if-none` (without it, `HAProxy` adds the header always).
    pub forwardfor_if_none: bool,
    /// `option forwarded`: the RFC 7239 header parameters to add; `None` when it is off.
    pub forwarded: Option<Box<Forwarded>>,
    pub originalto: Option<String>,
    pub maxrewrite: Option<usize>,
    /// `option accept-unsafe-violations-in-http-request`: a `#` in the request target (and a
    /// forbidden character in an absolute-form authority) is let through, not refused.
    pub accept_unsafe_request: bool,
    /// `option accept-unsafe-violations-in-http-response` (and its deprecated alias
    /// `accept-invalid-http-response`): what `ibex_proto::response_head` lets through from a
    /// server under the option (T275).
    pub accept_unsafe_response: bool,
}

impl Default for ListenSection {
    fn default() -> Self {
        Self {
            name: String::new(),
            addr: SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
            binds: Vec::new(),
            mode: Mode::Tcp,
            disabled: false,
            id: None,
            description: None,
            cookie: None,
            contimeout: None,
            clitimeout: None,
            srvtimeout: None,
            timeouts: TimeoutConfig::default(),
            retries: 3,
            retry_on: RE_CONN_FAILED,
            redisp: false,
            redisp_after: -1,
            maxconn: 0,
            dispatch: None,
            default_server: None,
            use_servers: Vec::new(),
            servers: Vec::new(),
            server_extras: ServerExtras::default(),
            logs: Vec::new(),
            log_global: false,
            log_format: None,
            unique_id_format: None,
            error_log_format: None,
            unique_id_header: None,
            req_header_captures: Vec::new(),
            res_header_captures: Vec::new(),
            log_health_checks: false,
            buffer_request: false,
            abortonclose: None,
            h1_adjust: 0,
            http_mode: HttpMode::KeepAlive,
            persist: false,
            dontlognull: false,
            http_ignore_probes: false,
            log_opts: 0,
            cliexp: Vec::new(),
            srvexp: Vec::new(),
            acls: Vec::new(),
            use_backends: Vec::new(),
            force_be_switch: Vec::new(),
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
            forwardfor_if_none: false,
            forwarded: None,
            originalto: None,
            stats: StatsConfig::default(),
            httpchk: None,
            proto_check: None,
            http_checks: Vec::new(),
            http_check_own: false,
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
    /// `description <text>`: free text shown on the stats page above the proxy's table (`px->desc`).
    pub description: Option<String>,
    /// `id <n>`: the proxy's explicit numeric id (`HAProxy` `PR_O_FORCED_ID`); `None` takes the next free one.
    pub id: Option<u32>,
    /// Client timeout in milliseconds / Duration.
    pub clitimeout: Option<Duration>,
    /// Structured timeouts.
    pub timeouts: TimeoutConfig,
    /// Maximum concurrent connections for this proxy; 0 when not set, which is the global `maxconn`.
    pub maxconn: u32,
    /// Default backend name to forward traffic to.
    pub default_backend: Option<String>,
    /// Dynamic switching rules (`use_backend <name> [if|unless <acl_cond>]`).
    pub use_backends: Vec<UseBackendRule>,
    /// `force-be-switch if|unless <cond>`: when one matches, `use_backend` and
    /// `default_backend` may pick a backend that is disabled.
    pub force_be_switch: Vec<AclCondition>,
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
    /// `log-format`, or the default chosen by `option httplog` / `option tcplog`.
    pub log_format: Option<LogFormatSpec>,
    /// `unique-id-format`: the transaction's unique ID, built when first used.
    pub unique_id_format: Option<String>,
    /// `error-log-format`: the line for a connection that fails before a stream exists
    /// (a failed TLS handshake, a refused PROXY header, a request the mux refuses).
    pub error_log_format: Option<String>,
    /// `unique-id-header`: the request header the unique ID is sent to the server in.
    pub unique_id_header: Option<String>,
    /// `capture request header`, in declaration order.
    pub req_header_captures: Vec<HeaderCapture>,
    /// `capture response header`, in declaration order.
    pub res_header_captures: Vec<HeaderCapture>,
    pub log_health_checks: bool,
    /// `option http-buffer-request`: wait for the request body before the rules run (as
    /// an implicit `http-request wait-for-body` ahead of them).
    pub buffer_request: bool,
    /// The last of `option http-keep-alive`, `http-server-close` and `httpclose`.
    pub http_mode: HttpMode,
    /// `option dontlognull`: no log line for a connection that carried nothing.
    pub dontlognull: bool,
    /// `option http-ignore-probes`: a connection that sends nothing before it closes or
    /// times out is sent nothing, not logged and not counted.
    pub http_ignore_probes: bool,
    /// `option h1-case-adjust-bogus-client` ([`H1_ADJ_CLIENT`]).
    pub h1_adjust: u8,
    /// `option dontlog-normal`, `option log-separate-errors` and `option logasap`, as the
    /// `LOG_OPT_*` bits.
    pub log_opts: u8,
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
    /// `option forwardfor ... if-none` (without it, `HAProxy` adds the header always).
    pub forwardfor_if_none: bool,
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
            id: None,
            description: None,
            clitimeout: None,
            timeouts: TimeoutConfig::default(),
            maxconn: 0,
            default_backend: None,
            use_backends: Vec::new(),
            force_be_switch: Vec::new(),
            monitor_uri: None,
            acls: Vec::new(),
            cliexp: Vec::new(),
            logs: Vec::new(),
            log_global: false,
            log_format: None,
            unique_id_format: None,
            error_log_format: None,
            unique_id_header: None,
            req_header_captures: Vec::new(),
            res_header_captures: Vec::new(),
            log_health_checks: false,
            buffer_request: false,
            http_mode: HttpMode::KeepAlive,
            dontlognull: false,
            http_ignore_probes: false,
            h1_adjust: 0,
            log_opts: 0,
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
            forwardfor_if_none: false,
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
    /// `log-format`, or the default chosen by `option httplog` / `option tcplog`.
    pub log_format: Option<LogFormatSpec>,
    /// `unique-id-format`: the transaction's unique ID, built when first used.
    pub unique_id_format: Option<String>,
    /// `unique-id-header`: the request header the unique ID is sent to the server in.
    pub unique_id_header: Option<String>,
    pub log_health_checks: bool,
    /// `option http-buffer-request`: wait for the request body before the rules run (as
    /// an implicit `http-request wait-for-body` ahead of them).
    pub buffer_request: bool,
    /// `option abortonclose` (`Some(true)`), `no option abortonclose` (`Some(false)`), or
    /// neither: then on for an HTTP stream, as `HAProxy` has it (`proxy_abrt_close_def`).
    pub abortonclose: Option<bool>,
    /// `option h1-case-adjust-bogus-client` ([`H1_ADJ_CLIENT`]) and `-server` ([`H1_ADJ_SERVER`]).
    pub h1_adjust: u8,
    /// The last of `option http-keep-alive`, `http-server-close` and `httpclose`.
    pub http_mode: HttpMode,
    /// `option persist`: a server a cookie or stick table names is used even when it is down.
    pub persist: bool,
    /// Operating mode (tcp, http, health).
    pub mode: Mode,
    /// Whether this backend is disabled.
    pub disabled: bool,
    /// `description <text>`: free text shown on the stats page above the proxy's table (`px->desc`).
    pub description: Option<String>,
    /// `id <n>`: the proxy's explicit numeric id (`HAProxy` `PR_O_FORCED_ID`); `None` takes the next free one.
    pub id: Option<u32>,
    /// Load balancing algorithm.
    pub balance: BalanceAlgorithm,
    /// The `cookie` line: HTTP session persistence.
    pub cookie: Option<CookieConfig>,
    /// Connect timeout in milliseconds / Duration.
    pub contimeout: Option<Duration>,
    /// Server timeout in milliseconds / Duration.
    pub srvtimeout: Option<Duration>,
    /// Structured timeouts.
    pub timeouts: TimeoutConfig,
    /// Number of connection retries before failing over (default: 3).
    pub retries: u32,
    /// `retry-on`, as the `RE_*` bits: what a failed attempt is retried on.
    pub retry_on: u32,
    /// Whether reconnection to dispatch address is enabled on error.
    pub redisp: bool,
    /// `option redispatch <interval>`: retries between redispatches (`redispatch_after`);
    /// negative counts back from the last retry, the default `-1` redispatches on it.
    pub redisp_after: i32,
    /// Default dispatch address to connect to.
    pub dispatch: Option<SocketAddr>,
    /// Default server options applied to all servers.
    pub default_server: Option<DefaultServerConfig>,
    /// `use-server <server> if|unless <cond>` rules, in order.
    pub use_servers: Vec<UseServerRule>,
    /// Known backend servers.
    pub servers: Vec<Server>,
    /// The explicit `id` and the initial health of some of the servers.
    pub server_extras: ServerExtras,
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
    pub tcp_res_content_rules: Vec<TcpResContentRule>,
    /// Modern HTTP-request rules.
    pub http_req_rules: Vec<HttpReqRule>,
    /// Modern HTTP-response rules.
    pub http_res_rules: Vec<HttpResRule>,
    /// Modern HTTP-after-response rules.
    pub http_after_res_rules: Vec<HttpAfterResRule>,
    /// Forwardfor header options.
    pub forwardfor: Option<String>,
    /// `option forwardfor ... if-none` (without it, `HAProxy` adds the header always).
    pub forwardfor_if_none: bool,
    /// `option forwarded`: the RFC 7239 header parameters to add; `None` when it is off.
    pub forwarded: Option<Box<Forwarded>>,
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
    /// This section has `http-check` rules or `option httpchk` of its own, so none of the
    /// defaults' were kept (`HAProxy` hands a proxy the defaults' rule set only when it
    /// has none).
    pub http_check_own: bool,
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
            log_format: None,
            unique_id_format: None,
            unique_id_header: None,
            log_health_checks: false,
            buffer_request: false,
            abortonclose: None,
            h1_adjust: 0,
            http_mode: HttpMode::KeepAlive,
            persist: false,
            mode: Mode::Tcp,
            disabled: false,
            id: None,
            description: None,
            balance: BalanceAlgorithm::RoundRobin,
            cookie: None,
            contimeout: None,
            srvtimeout: None,
            timeouts: TimeoutConfig::default(),
            retries: 3,
            retry_on: RE_CONN_FAILED,
            redisp: false,
            redisp_after: -1,
            dispatch: None,
            default_server: None,
            use_servers: Vec::new(),
            servers: Vec::new(),
            server_extras: ServerExtras::default(),
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
            forwardfor_if_none: false,
            forwarded: None,
            originalto: None,
            http_reuse: None,
            hash_type: None,
            hash_preserve_affinity: None,
            stats: StatsConfig::default(),
            httpchk: None,
            proto_check: None,
            http_checks: Vec::new(),
            http_check_own: false,
            tcp_checks: Vec::new(),
            tcp_check: false,
            error_files: HashMap::new(),
            error_replies: HashMap::new(),
            log_tag: None,
        }
    }
}


/// `option dontlog-normal`: a stream that did not fail logs nothing.
pub const LOG_OPT_DONTLOG_NORMAL: u8 = 1;
/// `option log-separate-errors`: a failed stream is logged at level `err`.
pub const LOG_OPT_SEPARATE_ERRORS: u8 = 2;
/// `option logasap`: the line is sent when the response head is, not at the end.
pub const LOG_OPT_ASAP: u8 = 4;

/// `h1_adjust` bit: `option h1-case-adjust-bogus-client` (the response to the client).
pub const H1_ADJ_CLIENT: u8 = 1;
/// `h1_adjust` bit: `option h1-case-adjust-bogus-server` (the request to the server).
pub const H1_ADJ_SERVER: u8 = 2;

/// The `LOG_OPT_*` bit of the option `name`, 0 for any other.
#[must_use]
pub fn log_opt_bit(name: &str) -> u8 {
    match name {
        "dontlog-normal" => LOG_OPT_DONTLOG_NORMAL,
        "log-separate-errors" => LOG_OPT_SEPARATE_ERRORS,
        "logasap" => LOG_OPT_ASAP,
        _ => 0,
    }
}

/// `retry-on` bits, `HAProxy`'s `PR_RE_*`.
pub const RE_CONN_FAILED: u32 = 0x0000_0001;
/// `empty-response`: the server closed with nothing sent back.
pub const RE_DISCONNECTED: u32 = 0x0000_0002;
/// `response-timeout`: `timeout server` ran out before any response.
pub const RE_TIMEOUT: u32 = 0x0000_0004;
/// `0rtt-rejected`.
pub const RE_EARLY_ERROR: u32 = 0x0001_0000;
/// `junk-response`: something that is not a complete HTTP response head.
pub const RE_JUNK_RESPONSE: u32 = 0x0002_0000;
/// The statuses `retry-on` takes, with their bits.
pub const RE_STATUSES: [(u16, u32); 12] = [
    (401, 0x0008),
    (403, 0x0010),
    (404, 0x0020),
    (408, 0x0040),
    (421, 0x0080),
    (425, 0x0100),
    (429, 0x0200),
    (500, 0x0400),
    (501, 0x0800),
    (502, 0x1000),
    (503, 0x2000),
    (504, 0x4000),
];
/// Any of the status bits.
pub const RE_STATUS_MASK: u32 = 0x7ff8;
