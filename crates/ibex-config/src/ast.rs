// SPDX-License-Identifier: GPL-2.0-or-later
//
// HAProxy 1.0 configuration parser, ported to Rust.
// Derived from HAProxy 1.0.2 (haproxy.c) by Willy Tarreau <willy@meta-x.org>.

use std::net::SocketAddr;
use std::time::Duration;

/// Full `HAProxy` 1.0 configuration containing one or more proxy sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// List of proxy listen sections in order of definition.
    pub listens: Vec<ListenSection>,
}

/// A `listen` proxy section.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Client header regex rewrite rules (up to 10).
    pub cliexp: Vec<HeaderExp>,
    /// Server header regex rewrite rules (up to 10).
    pub srvexp: Vec<HeaderExp>,
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

/// Backend server definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// Server identifier (e.g. cookie value or name).
    pub id: String,
    /// Server address and port.
    pub addr: SocketAddr,
}

/// Syslog destination configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogConfig {
    /// Syslog server address (default port: 514).
    pub addr: SocketAddr,
    /// Syslog facility.
    pub facility: LogFacility,
    /// Optional syslog log level.
    pub level: Option<LogLevel>,
}

/// Syslog facilities supported by `HAProxy` 1.0.2.
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
