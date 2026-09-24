// SPDX-License-Identifier: GPL-2.0-or-later
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

