// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/sample.c and src/acl.c (matchers).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Sample Matchers (`-m str`, `beg`, `end`, `sub`, `reg`, `int`, `ip`, `len`, `found`).

use crate::cast::cast;
use crate::sample::{Sample, SampleType};
use regex::Regex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Supported matcher methods.
#[derive(Debug, Clone)]
pub enum Matcher {
    /// Matches exact string equality (optionally case-insensitive).
    Str {
        target: String,
        case_insensitive: bool,
    },
    /// Matches prefix.
    Beg {
        prefix: String,
        case_insensitive: bool,
    },
    /// Matches suffix.
    End {
        suffix: String,
        case_insensitive: bool,
    },
    /// Matches substring.
    Sub { sub: String, case_insensitive: bool },
    /// Matches regular expression.
    Reg(Regex),
    /// Matches integer comparison.
    Int { op: IntOp, value: i64 },
    /// Matches IP address exact.
    Ip(IpAddr),
    /// Matches IPv4 CIDR network (`network_ip`, mask).
    IpCidrV4 { network: u32, mask: u32 },
    /// Matches IPv6 CIDR network (`network_ip`, mask).
    IpCidrV6 { network: u128, mask: u128 },
    /// Matches length.
    Len(usize),
    /// Matches if sample exists / is found.
    Found,
}

/// Integer comparison operators for matchers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}

impl Matcher {
    /// Compiles a matcher pattern from method name and pattern string.
    ///
    /// # Errors
    /// Returns an error if the pattern is invalid for the specified method.
    pub fn compile(method: &str, pattern: &str) -> Result<Self, String> {
        Self::compile_with_flags(method, pattern, false)
    }

    /// Compiles a matcher pattern with case-insensitivity flag.
    ///
    /// # Errors
    /// Returns an error if the pattern is invalid for the specified method.
    #[allow(clippy::too_many_lines)]
    pub fn compile_with_flags(
        method: &str,
        pattern: &str,
        case_insensitive: bool,
    ) -> Result<Self, String> {
        match method {
            "str" | "exact" => Ok(Matcher::Str {
                target: if case_insensitive {
                    pattern.to_lowercase()
                } else {
                    pattern.to_string()
                },
                case_insensitive,
            }),
            "beg" | "prefix" => Ok(Matcher::Beg {
                prefix: if case_insensitive {
                    pattern.to_lowercase()
                } else {
                    pattern.to_string()
                },
                case_insensitive,
            }),
            "end" | "suffix" => Ok(Matcher::End {
                suffix: if case_insensitive {
                    pattern.to_lowercase()
                } else {
                    pattern.to_string()
                },
                case_insensitive,
            }),
            "sub" => Ok(Matcher::Sub {
                sub: if case_insensitive {
                    pattern.to_lowercase()
                } else {
                    pattern.to_string()
                },
                case_insensitive,
            }),
            "reg" => {
                let re_str = if case_insensitive {
                    format!("(?i){pattern}")
                } else {
                    pattern.to_string()
                };
                Regex::new(&re_str)
                    .map(Matcher::Reg)
                    .map_err(|e| e.to_string())
            }
            "found" => Ok(Matcher::Found),
            "len" => {
                let l = pattern.parse::<usize>().map_err(|e| e.to_string())?;
                Ok(Matcher::Len(l))
            }
            "ip" => {
                if let Some((ip_str, prefix_str)) = pattern.split_once('/') {
                    let prefix: u32 = prefix_str
                        .trim()
                        .parse()
                        .map_err(|e: std::num::ParseIntError| e.to_string())?;

                    if let Ok(v4) = ip_str.trim().parse::<Ipv4Addr>() {
                        if prefix > 32 {
                            return Err(format!("Invalid CIDR prefix: {prefix} (max 32 for IPv4)"));
                        }
                        let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
                        let network = u32::from(v4) & mask;
                        Ok(Matcher::IpCidrV4 { network, mask })
                    } else if let Ok(v6) = ip_str.trim().parse::<Ipv6Addr>() {
                        if prefix > 128 {
                            return Err(format!(
                                "Invalid CIDR prefix: {prefix} (max 128 for IPv6)"
                            ));
                        }
                        let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
                        let network = u128::from(v6) & mask;
                        Ok(Matcher::IpCidrV6 { network, mask })
                    } else {
                        Err(format!("Invalid IP address in CIDR pattern: {pattern}"))
                    }
                } else {
                    let ip = pattern
                        .trim()
                        .parse::<IpAddr>()
                        .map_err(|e| e.to_string())?;
                    Ok(Matcher::Ip(ip))
                }
            }
            "int" | "eq" => {
                let val = pattern.parse::<i64>().map_err(|e| e.to_string())?;
                Ok(Matcher::Int {
                    op: IntOp::Eq,
                    value: val,
                })
            }
            "gt" => {
                let val = pattern.parse::<i64>().map_err(|e| e.to_string())?;
                Ok(Matcher::Int {
                    op: IntOp::Gt,
                    value: val,
                })
            }
            "ge" => {
                let val = pattern.parse::<i64>().map_err(|e| e.to_string())?;
                Ok(Matcher::Int {
                    op: IntOp::Ge,
                    value: val,
                })
            }
            "lt" => {
                let val = pattern.parse::<i64>().map_err(|e| e.to_string())?;
                Ok(Matcher::Int {
                    op: IntOp::Lt,
                    value: val,
                })
            }
            "le" => {
                let val = pattern.parse::<i64>().map_err(|e| e.to_string())?;
                Ok(Matcher::Int {
                    op: IntOp::Le,
                    value: val,
                })
            }
            other => Err(format!("Unknown matcher method '{other}'")),
        }
    }

    /// Evaluates whether the sample matches this matcher pattern.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn matches(&self, sample: &Sample) -> bool {
        match self {
            Matcher::Found => true,
            Matcher::Str {
                target,
                case_insensitive,
            } => {
                if let Some(Sample::Str(s)) = cast(sample.clone(), SampleType::Str) {
                    if *case_insensitive {
                        s.to_lowercase() == *target
                    } else {
                        s == *target
                    }
                } else {
                    false
                }
            }
            Matcher::Beg {
                prefix,
                case_insensitive,
            } => {
                if let Some(Sample::Str(s)) = cast(sample.clone(), SampleType::Str) {
                    if *case_insensitive {
                        s.to_lowercase().starts_with(prefix)
                    } else {
                        s.starts_with(prefix)
                    }
                } else {
                    false
                }
            }
            Matcher::End {
                suffix,
                case_insensitive,
            } => {
                if let Some(Sample::Str(s)) = cast(sample.clone(), SampleType::Str) {
                    if *case_insensitive {
                        s.to_lowercase().ends_with(suffix)
                    } else {
                        s.ends_with(suffix)
                    }
                } else {
                    false
                }
            }
            Matcher::Sub {
                sub,
                case_insensitive,
            } => {
                if let Some(Sample::Str(s)) = cast(sample.clone(), SampleType::Str) {
                    if *case_insensitive {
                        s.to_lowercase().contains(sub)
                    } else {
                        s.contains(sub)
                    }
                } else {
                    false
                }
            }
            Matcher::Reg(regex) => {
                if let Some(Sample::Str(s)) = cast(sample.clone(), SampleType::Str) {
                    regex.is_match(&s)
                } else {
                    false
                }
            }
            Matcher::Len(expected_len) => {
                if let Some(Sample::Str(s)) = cast(sample.clone(), SampleType::Str) {
                    s.len() == *expected_len
                } else {
                    false
                }
            }
            Matcher::Int { op, value } => {
                if let Some(Sample::Sint(val)) = cast(sample.clone(), SampleType::Sint) {
                    match op {
                        IntOp::Eq => val == *value,
                        IntOp::Ne => val != *value,
                        IntOp::Gt => val > *value,
                        IntOp::Ge => val >= *value,
                        IntOp::Lt => val < *value,
                        IntOp::Le => val <= *value,
                    }
                } else {
                    false
                }
            }
            Matcher::Ip(target_ip) => match target_ip {
                IpAddr::V4(target_v4) => {
                    if let Some(Sample::Ipv4(ip)) = cast(sample.clone(), SampleType::Ipv4) {
                        ip == *target_v4
                    } else {
                        false
                    }
                }
                IpAddr::V6(target_v6) => {
                    if let Some(Sample::Ipv6(ip)) = cast(sample.clone(), SampleType::Ipv6) {
                        ip == *target_v6
                    } else {
                        false
                    }
                }
            },
            Matcher::IpCidrV4 { network, mask } => {
                if let Some(Sample::Ipv4(ip)) = cast(sample.clone(), SampleType::Ipv4) {
                    (u32::from(ip) & mask) == *network
                } else {
                    false
                }
            }
            Matcher::IpCidrV6 { network, mask } => {
                if let Some(Sample::Ipv6(ip)) = cast(sample.clone(), SampleType::Ipv6) {
                    (u128::from(ip) & mask) == *network
                } else {
                    false
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matchers() {
        let smp = Sample::Str("https://example.com/api/v1".into());
        let matcher_beg = Matcher::compile("beg", "https://").unwrap();
        let matcher_sub = Matcher::compile("sub", "example").unwrap();
        let matcher_end = Matcher::compile("end", "/v1").unwrap();
        let matcher_regex = Matcher::compile("reg", r"/api/v\d+").unwrap();

        assert!(matcher_beg.matches(&smp));
        assert!(matcher_sub.matches(&smp));
        assert!(matcher_end.matches(&smp));
        assert!(matcher_regex.matches(&smp));

        let smp_int = Sample::Sint(42);
        let m_greater = Matcher::compile("gt", "40").unwrap();
        let m_less = Matcher::compile("lt", "50").unwrap();
        assert!(m_greater.matches(&smp_int));
        assert!(m_less.matches(&smp_int));
    }
}
