// SPDX-License-Identifier: GPL-2.0-or-later
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
    pub check_port: Option<u16>,
    pub check_proto: Option<String>,
    pub check_ssl: bool,
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

