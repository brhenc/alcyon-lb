// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![allow(clippy::struct_excessive_bools)]

#[allow(unused_imports)]
use super::*;

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
        /// `uri-lf`: `uri` is a log-format.
        uri_lf: bool,
        version: Option<String>,
        /// `hdr <name> <fmt>`: every value is a log-format.
        headers: Vec<(String, String)>,
        body: Option<String>,
        /// `body-lf`: `body` is a log-format.
        body_lf: bool,
    },
    Expect {
        pattern: HttpCheckExpectPattern,
        negate: bool,
        /// `min-recv`; -1 when not given.
        min_recv: i64,
        comment: Option<String>,
    },
    Comment(String),
    SendState,
    SetVar {
        var_name: String,
        expr: String,
    },
    UnsetVar {
        var_name: String,
    },
}

/// A header name or value pattern of `http-check expect hdr` / `fhdr`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HdrPattern {
    pub text: String,
    /// `name-lf` / `value-lf`: `text` is a log-format, rendered when the rule runs.
    pub lf: bool,
    pub mt: MatchType,
}

/// Pattern to expect in an `http-check expect` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpCheckExpectPattern {
    /// `status`: inclusive ranges.
    Status(Vec<(u16, u16)>),
    RStatus(String),
    /// `string` / `rstring`: matched against the response body.
    String(String),
    StringLf(String),
    RString(String),
    /// `hdr` (the comma-separated values of each header) or `fhdr` (`full`: each header's
    /// whole value).
    Hdr {
        full: bool,
        name: HdrPattern,
        value: Option<HdrPattern>,
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
        comment: Option<String>,
    },
    Send(Vec<u8>),
    Expect {
        pattern: TcpCheckExpectPattern,
        negate: bool,
        min_recv: Option<i64>,
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

/// Version for `option mysql-check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MysqlCheckVersion {
    #[default]
    Post41,
    Pre41,
    Post80,
}

/// Protocol-specific health check configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoCheckConfig {
    Redis,
    Smtp {
        cmd: Option<String>,
    },
    Ldap,
    Mysql {
        user: Option<String>,
        version: MysqlCheckVersion,
    },
    Pgsql {
        user: String,
    },
    SslHello,
}

/// Fully resolved health check configuration for a backend server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedCheckConfig {
    TcpConnect,
    Http(ResolvedHttpCheck),
    TcpSteps(Vec<ResolvedTcpStep>),
    Redis,
    Smtp(Option<String>),
    Ldap,
    Mysql {
        user: Option<String>,
        version: MysqlCheckVersion,
    },
    Pgsql {
        user: String,
    },
    SslHello,
}

/// Resolved HTTP health check parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHttpCheck {
    pub method: String,
    pub uri: String,
    /// `uri` is a log-format (`uri-lf`); otherwise it is sent as written.
    pub uri_lf: bool,
    pub version: String,
    pub host: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    /// `body` is a log-format (`body-lf`).
    pub body_lf: bool,
    /// The rule set has a request to send. Without one `HAProxy` connects and sends
    /// nothing (a backend that has `http-check expect` rules only).
    pub has_send: bool,
    pub send_state: bool,
    /// `set-var` / `unset-var` rules before the first `expect`: run when the request is
    /// built, with no response to read (`HAProxy` runs them as it reaches them, and the
    /// response is read by the first `expect`).
    pub pre_rules: Vec<ResolvedHttpRule>,
    /// The rules after the request, in order: run against the response.
    pub rules: Vec<ResolvedHttpRule>,
    pub check_port: Option<u16>,
    pub send_proxy: bool,
    /// `http-check connect addr`: where the check connects.
    pub connect_addr: Option<SocketAddr>,
}

/// A rule run on a response, or a variable rule run before the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedHttpRule {
    Expect(ResolvedHttpExpectRule),
    SetVar { var_name: String, expr: String },
    UnsetVar { var_name: String },
}

/// Single expectation rule for an HTTP health check response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHttpExpectRule {
    pub pattern: HttpCheckExpectPattern,
    pub negate: bool,
    pub min_recv: i64,
    pub comment: Option<String>,
}

/// Single step in a multi-step TCP health check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedTcpStep {
    Connect {
        port: Option<u16>,
        send_proxy: bool,
        /// The `connect` HAProxy adds when the rules do not start with one: it is step 0
        /// in the failure messages and the rules after it are numbered from 1.
        implicit: bool,
        /// The port of the `tcp-check connect port` rule itself, which the failure
        /// message names (`port` also folds in the server's `port`/`check_port`).
        rule_port: Option<u16>,
        comment: Option<String>,
    },
    Send(Vec<u8>),
    Expect {
        pattern: ResolvedTcpExpectPattern,
        negate: bool,
        /// `min-recv`; -1 when not given: a mismatch is then never conclusive before the
        /// end of the response.
        min_recv: i64,
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

impl From<&TcpCheckExpectPattern> for ResolvedTcpExpectPattern {
    fn from(pattern: &TcpCheckExpectPattern) -> Self {
        match pattern {
            TcpCheckExpectPattern::String(s) => Self::String(s.clone()),
            TcpCheckExpectPattern::Binary(b) => Self::Binary(b.clone()),
            TcpCheckExpectPattern::RString(r) => Self::RString(r.clone()),
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

