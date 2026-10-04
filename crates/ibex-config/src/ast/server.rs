// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![allow(clippy::struct_excessive_bools)]

#[allow(unused_imports)]
use super::*;

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
    /// `pool-max-conn`.
    pub pool_max_conn: Option<i32>,
    pub check_port: Option<u16>,
    pub check_proto: Option<&'static str>,
    /// The TLS keywords (`ssl`, `verify`, `sni`, `check-ssl`, ...).
    pub ssl: ServerSsl,
    /// `proxy-v2-options unique-id`.
    pub proxy_v2_unique_id: bool,
    pub weight: Option<u32>,
    pub backup: bool,
    pub cookie: Option<String>,
    /// `disabled` / `enabled`: servers declared after start in maintenance.
    pub disabled: bool,
    /// `track [<proxy>/]<server>`, as written.
    pub track: Option<Box<str>>,
}

/// `verify none|required` on a server line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslVerify {
    None,
    Required,
}

/// A TLS protocol version rustls speaks (`ssl-min-ver`, `ssl-max-ver`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

/// The TLS settings of a `server` line (`src/cfgparse-ssl.c`), for the data path and
/// for the health checks. Everything here is accepted without `ssl` too, as `HAProxy`
/// does: it applies once `ssl` (data path) or `check-ssl` (checks) turns TLS on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerSsl {
    /// `ssl`: the data path is TLS. `no-ssl` undoes an inherited one.
    pub ssl: bool,
    /// `verify none|required`. `None` is `HAProxy`'s default, `required`, which needs a
    /// `ca-file` or the configuration is refused.
    pub verify: Option<SslVerify>,
    /// `ca-file <path>`: the trust anchors. `@system-ca` is the system's bundle.
    pub ca_file: Option<String>,
    /// `crl-file <path>`.
    pub crl_file: Option<String>,
    /// `crt <path>`: the client certificate and its key, in one PEM file.
    pub crt: Option<String>,
    /// `sni <expr>`: a sample expression giving the name to send.
    pub sni: Option<String>,
    /// `no-sni-auto`: without `sni`, do not send the request's Host header as SNI.
    pub no_sni_auto: bool,
    /// `verifyhost <name>`: the name the certificate is checked against when no SNI is sent.
    pub verifyhost: Option<String>,
    /// `alpn <protos>`, as written, in order.
    pub alpn: Vec<String>,
    /// `ssl-min-ver`, also `force-tlsv1x` / `no-tlsv12`.
    pub min_ver: Option<TlsVersion>,
    /// `ssl-max-ver`, also `force-tlsv1x` / `no-tlsv13`.
    pub max_ver: Option<TlsVersion>,
    /// `no-ssl-reuse`: no session resumption.
    pub no_reuse: bool,
    /// `check-ssl` (`Some(true)`), `no-check-ssl` (`Some(false)`); `None` follows `ssl`
    /// unless the check has its own `port`.
    pub check_ssl: Option<bool>,
    /// `check-sni <name>`.
    pub check_sni: Option<String>,
    /// `check-alpn <protos>`.
    pub check_alpn: Vec<String>,
    /// `no-check-sni-auto`: without `check-sni`, do not send the `http-check` Host header.
    pub no_check_sni_auto: bool,
}

impl ServerSsl {
    /// Whether the health checks of a server with this configuration and `check_port`
    /// use TLS: `check-ssl` says so; otherwise they follow `ssl` unless the check has a
    /// port of its own (`init_srv_check`, `src/check.c`).
    #[must_use]
    pub fn check_uses_tls(&self, check_port: Option<u16>) -> bool {
        match self.check_ssl {
            Some(explicit) => explicit,
            None => self.ssl && check_port.is_none(),
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
    /// First server (in declaration order) with a free slot.
    First,
    /// Random draw over the weighted server set. The value is the number of
    /// draws (`random(N)`; bare `random` is `N == 2`, matching HAProxy).
    Random(u32),
}

/// Hashing method for hash-based balancing algorithms (`hash-type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashType {
    /// Weighted modulo over the hash value (default).
    #[default]
    MapBased,
    /// Consistent hashing ring: minimal remapping when a server's
    /// eligibility changes, and the point where `hash-preserve-affinity`
    /// takes effect.
    Consistent,
}

/// When a hash-based algorithm keeps sending a key to the same server after
/// that server is no longer able to take the request immediately
/// (`hash-preserve-affinity`). Only meaningful with `hash-type consistent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashPreserveAffinity {
    /// Always preserve affinity: keep using the hashed server regardless of
    /// its load (default, matches HAProxy).
    #[default]
    Always,
    /// Preserve affinity until the hashed server reaches `maxconn`, then
    /// move on to the next server on the ring.
    MaxConn,
}

/// Dynamic backend switching rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseBackendRule {
    /// Destination backend name.
    pub backend: String,
    /// Optional conditional expression.
    pub cond: Option<AclCondition>,
}

/// `use-server <server> if|unless <cond>`: the rule picks the server, bypassing the
/// balance algorithm (`process_server_rules`, `src/stream.c`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseServerRule {
    /// The server's name, in the backend the rule is in.
    pub server: String,
    /// The condition; `use-server` requires one.
    pub cond: AclCondition,
}

/// What a section knows about some of its servers beyond the `Server`s themselves. Kept
/// apart, as `(index in the section's servers, value)` for those that have one, so a
/// backend of 60,000 servers does not pay for them in every `Server`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerExtras {
    /// `id <n>` (`SRV_F_FORCED_ID`): the server's explicit numeric id, what `srv_id` and
    /// the `sid` column of `show stat` report.
    pub puid: Vec<(u32, u32)>,
    /// What `show servers state` reports as `srv_check_health` while no check runs on the
    /// server, when that is not 0; see `parse_server`.
    pub init_health: Vec<(u32, u32)>,
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
    /// `pool-max-conn`: the most idle connections kept for this server; -1 is unlimited
    /// (the default), 0 keeps none, not even for the next request of the same client.
    pub pool_max_conn: i32,
    /// Whether this server is a backup server.
    pub backup: bool,
    /// Custom port for health checks (`port`).
    pub check_port: Option<u16>,
    /// Protocol for health checks (`check-proto`).
    pub check_proto: Option<&'static str>,
    /// The TLS keywords (`ssl`, `verify`, `sni`, `check-ssl`, ...), boxed and absent for
    /// a plaintext server so 60,000 of them stay cheap (`request_allocations`).
    pub ssl: Option<Box<ServerSsl>>,
    /// `proxy-v2-options unique-id`: the stream's unique ID goes in the PROXY v2 header
    /// (TLV `PP2_TYPE_UNIQUE_ID`).
    pub proxy_v2_unique_id: bool,
    /// The value of the persistence cookie that selects this server (`cookie <value>`).
    pub cookie: Option<String>,
    /// `disabled`: the server starts in maintenance and takes no traffic until the CLI's
    /// `enable server` brings it back.
    pub disabled: bool,
    /// `track [<proxy>/]<server>`, as written.
    pub track: Option<Box<str>>,
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
            pool_max_conn: -1,
            backup: false,
            check_port: None,
            check_proto: None,
            ssl: None,
            proxy_v2_unique_id: false,
            cookie: None,
            disabled: false,
            track: None,
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
            pool_max_conn: -1,
            backup: false,
            check_port: None,
            check_proto: None,
            ssl: None,
            proxy_v2_unique_id: false,
            cookie: None,
            disabled: false,
            track: None,
        }
    }
}

