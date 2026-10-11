// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/sample.c and src/acl.c (matchers).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Sample Matchers (`-m str`, `beg`, `end`, `sub`, `reg`, `int`, `ip`, `len`, `found`).

use crate::cast::cast;
use crate::sample::{Sample, SampleType};
use ibex_regex::UserRegex as Regex;
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
    /// Matches an integer range (`pat_parse_int`: `5`, `1:5`, `:5`, `5:`).
    IntRange(IntRange),
    /// Matches a pattern as a whole word of the sample (`match_word`: `dir` is
    /// delimited by `/` and `?`, `dom` by `/`, `?`, `.` and `:`).
    Word {
        pattern: Vec<u8>,
        delimiters: &'static [u8],
        case_insensitive: bool,
    },
    /// Matches if any of the patterns of the list matches (`pat_match_*` walks the whole
    /// pattern list of an expression, and the first hit wins).
    Any(Vec<Matcher>),
    /// The patterns of an ACL's `-f` file, as the runtime CLI has left them.
    File(std::sync::Arc<crate::patref::FileMatcher>),
    /// Matches IP address exact.
    Ip(IpAddr),
    /// Matches IPv4 CIDR network (`network_ip`, mask).
    IpCidrV4 { network: u32, mask: u32 },
    /// Matches IPv6 CIDR network (`network_ip`, mask).
    IpCidrV6 { network: u128, mask: u128 },
    /// Matches length (a number or a range, as `pat_match_len`).
    Len(IntRange),
    /// Matches binary / hex payload.
    Bin(Vec<u8>),
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

/// An integer range, either end of which may be open (`pat_parse_int`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntRange {
    pub min: Option<i64>,
    pub max: Option<i64>,
}

impl IntRange {
    /// Parses `5` (`5:5`), `1:5`, `:5` or `5:`; `-` separates like `:` does.
    ///
    /// # Errors
    /// Returns an error if the text is not a number or a valid range.
    pub fn parse(text: &str) -> Result<Self, String> {
        let bad = || format!("'{text}' is not a valid number range");
        let num = |t: &str| t.parse::<i64>().map_err(|_| bad());
        let Some(sep) = text.find([':', '-']) else {
            let n = text.parse::<i64>().map_err(|_| format!("'{text}' is not a number"))?;
            return Ok(IntRange { min: Some(n), max: Some(n) });
        };
        let (lo, hi) = (&text[..sep], &text[sep + 1..]);
        match (lo.is_empty(), hi.is_empty()) {
            (true, true) => Err(bad()),
            (true, false) => Ok(IntRange { min: None, max: Some(num(hi)?) }),
            (false, true) => Ok(IntRange { min: Some(num(lo)?), max: None }),
            (false, false) => {
                let (min, max) = (num(lo)?, num(hi)?);
                if min > max {
                    return Err(bad());
                }
                Ok(IntRange { min: Some(min), max: Some(max) })
            }
        }
    }

    fn contains(&self, v: i64) -> bool {
        self.min.is_none_or(|m| m <= v) && self.max.is_none_or(|m| v <= m)
    }
}

/// `match_word` (`src/pattern.c`): `pattern`, stripped of delimiters at both ends, must be
/// a whole word of `smp`, a word being what lies between two delimiters.
pub(crate) fn match_word(smp: &[u8], pattern: &[u8], delimiters: &[u8], icase: bool) -> bool {
    let mut p = pattern;
    while let [first, rest @ ..] = p {
        if !delimiters.contains(first) {
            break;
        }
        p = rest;
    }
    while let [rest @ .., last] = p {
        if !delimiters.contains(last) {
            break;
        }
        p = rest;
    }
    if p.len() > smp.len() {
        return false;
    }
    let same = |a: &[u8], b: &[u8]| if icase { a.eq_ignore_ascii_case(b) } else { a == b };
    let mut may_match = true;
    for c in 0..=(smp.len() - p.len()) {
        if delimiters.contains(&smp[c]) {
            may_match = true;
            continue;
        }
        if !may_match {
            continue;
        }
        let end = c + p.len();
        if same(&smp[c..end], p) && (end == smp.len() || delimiters.contains(&smp[end])) {
            return true;
        }
        may_match = false;
    }
    false
}

impl Matcher {
    /// The shortest sample this matcher can accept, for deciding whether to wait for more
    /// payload; a list answers with its shortest pattern.
    #[must_use]
    pub fn min_pattern_len(&self) -> usize {
        match self {
            Matcher::Str { target, .. } => target.len(),
            Matcher::Beg { prefix, .. } => prefix.len(),
            Matcher::End { suffix, .. } => suffix.len(),
            Matcher::Sub { sub, .. } => sub.len(),
            Matcher::Bin(target) => target.len(),
            Matcher::Any(list) => list.iter().map(Matcher::min_pattern_len).min().unwrap_or(1),
            Matcher::File(f) => f.min_pattern_len(),
            _ => 1,
        }
    }

    /// Whether a non-match on a payload that may still grow is not final: an unanchored
    /// substring, a suffix or a regex can match once more bytes arrive.
    #[must_use]
    pub fn may_match_later(&self, ends_with_newline: bool) -> bool {
        match self {
            Matcher::Sub { .. } => !ends_with_newline,
            Matcher::End { .. } | Matcher::Reg(_) => true,
            Matcher::Any(list) => list.iter().any(|m| m.may_match_later(ends_with_newline)),
            Matcher::File(f) => f.may_match_later(ends_with_newline),
            _ => false,
        }
    }

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
                Regex::new_nocapture(&re_str)
                    .map(Matcher::Reg)
                    .map_err(|e| e.to_string())
            }
            "found" => Ok(Matcher::Found),
            "bin" => {
                // `parse_binary`: whole bytes written as hex digits, in the pattern's own
                // word. The length is checked first, then each digit.
                let hex_str = pattern.trim().replace(' ', "");
                let digits = hex_str.as_bytes();
                if digits.len() % 2 != 0 {
                    return Err("an even number of hex digit is expected".to_string());
                }
                let mut bytes = Vec::with_capacity(digits.len() / 2);
                for pair in digits.chunks_exact(2) {
                    let nibble = |b: u8| {
                        char::from(b).to_digit(16).ok_or_else(|| format!("an hex digit is expected (found '{}')", char::from(b)))
                    };
                    let (hi, lo) = (nibble(pair[0])?, nibble(pair[1])?);
                    bytes.push(u8::try_from(hi * 16 + lo).unwrap_or(0));
                }
                Ok(Matcher::Bin(bytes))
            }
            "len" => Ok(Matcher::Len(IntRange::parse(pattern)?)),
            "dir" | "dom" => Ok(Matcher::Word {
                pattern: pattern.as_bytes().to_vec(),
                delimiters: if method == "dir" { b"/?" } else { b"/?.:" },
                case_insensitive,
            }),
            "ip" => (|| {
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
            })()
            // `HAProxy`'s wording, whatever made the address or its prefix unusable.
            .map_err(|_: String| format!("'{pattern}' is not a valid IPv4 or IPv6 address")),
            "int" => Ok(Matcher::IntRange(IntRange::parse(pattern)?)),
            "eq" => {
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
            other => Err(format!("unknown matching method '{other}' when parsing ACL expression")),
        }
    }

    /// Evaluates whether the sample matches this matcher pattern.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn matches(&self, sample: &Sample) -> bool {
        match self {
            Matcher::Found => true,
            Matcher::Any(list) => list.iter().any(|m| m.matches(sample)),
            Matcher::File(f) => f.matches(sample),
            Matcher::Word { pattern, delimiters, case_insensitive } => {
                matches!(cast(sample.clone(), SampleType::Str),
                    Some(Sample::Str(s)) if match_word(s.as_bytes(), pattern, delimiters, *case_insensitive))
            }
            Matcher::IntRange(range) => {
                matches!(cast(sample.clone(), SampleType::Sint), Some(Sample::Sint(v)) if range.contains(v))
            }
            Matcher::Str {
                target,
                case_insensitive,
            } => {
                if let Some(Sample::Str(s)) = cast(sample.clone(), SampleType::Str) {
                    if *case_insensitive {
                        s.eq_ignore_ascii_case(target)
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
            Matcher::Len(range) => {
                if let Some(Sample::Str(s)) = cast(sample.clone(), SampleType::Str) {
                    i64::try_from(s.len()).is_ok_and(|n| range.contains(n))
                } else {
                    false
                }
            }
            Matcher::Bin(target) => {
                if let Some(Sample::Bin(b)) = cast(sample.clone(), SampleType::Bin) {
                    b == *target
                } else if let Some(Sample::Str(s)) = cast(sample.clone(), SampleType::Str) {
                    s.as_bytes() == target.as_slice()
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

    /// `match_word`: delimiters at either end of the pattern are dropped, a pattern longer
    /// than the sample never matches, a word is what lies between delimiters.
    #[test]
    fn words_are_delimited() {
        let dir = |p: &str, s: &str| Matcher::compile("dir", p).unwrap().matches(&Sample::Str(s.into()));
        assert!(dir("/a/", "/x/a/y"));
        assert!(dir("a", "a"));
        assert!(!dir("/a/", "/x/ab/y"));
        assert!(!dir("longer", "a"));
        assert!(!dir("a", "/xa/"));
        assert!(Matcher::compile_with_flags("dom", "A.B", true).unwrap().matches(&Sample::Str("x.a.b:80".into())));
        assert!(!Matcher::compile_with_flags("dom", "A.B", false).unwrap().matches(&Sample::Str("x.a.b".into())));
    }

    #[test]
    fn a_list_knows_its_shortest_pattern() {
        let m = |method: &str, p: &str| Matcher::compile(method, p).unwrap();
        assert_eq!(m("str", "abc").min_pattern_len(), 3);
        assert_eq!(m("beg", "ab").min_pattern_len(), 2);
        assert_eq!(m("end", "a").min_pattern_len(), 1);
        assert_eq!(m("bin", "0a0b").min_pattern_len(), 2);
        assert_eq!(m("int", "5").min_pattern_len(), 1);
        assert_eq!(Matcher::Any(vec![m("sub", "abc"), m("beg", "de")]).min_pattern_len(), 2);
        assert_eq!(Matcher::Any(Vec::new()).min_pattern_len(), 1);
    }

    #[test]
    fn int_ranges_follow_pat_parse_int() {
        assert_eq!(IntRange::parse("5").unwrap(), IntRange { min: Some(5), max: Some(5) });
        assert_eq!(IntRange::parse("1-5").unwrap(), IntRange { min: Some(1), max: Some(5) });
        assert_eq!(IntRange::parse(":5").unwrap(), IntRange { min: None, max: Some(5) });
        assert_eq!(IntRange::parse("5:").unwrap(), IntRange { min: Some(5), max: None });
        for bad in ["", ":", "x", "1:x", "x:1", "5:1"] {
            assert!(IntRange::parse(bad).is_err(), "{bad:?}");
        }
    }
}
