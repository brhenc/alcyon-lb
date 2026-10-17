// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/http_ana.c, src/http_htx.c and src/sample.c (the `rfc7239_*`
// converters and `option forwarded`). Copyright (C) 2000-2026 Willy Tarreau and HAProxy
// contributors. See LICENSE.

//! RFC 7239 `Forwarded` header values: the `rfc7239_*` converters, and the value
//! formatting `option forwarded` uses. Each rule here was measured on `HAProxy`
//! 3.5-dev8-885761-29 (see `tests/rfc7239.rs`).

use std::net::Ipv4Addr;
use std::str::FromStr;

use crate::registry::Registry;
use crate::sample::{Sample, SampleType, TypeSpec};
use crate::ConvDesc;

fn is_obf_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

/// `_` and at least one more character of `[A-Za-z0-9._-]`.
fn is_obf(s: &str) -> bool {
    s.len() >= 2 && s.starts_with('_') && s[1..].chars().all(is_obf_char)
}

fn is_tchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

/// The inside of an IPv6 literal: hexadecimal groups only, no embedded IPv4, no zone.
fn is_ipv6_literal(s: &str) -> bool {
    let groups = |part: &str| -> Option<usize> {
        if part.is_empty() {
            return Some(0);
        }
        let mut n = 0;
        for g in part.split(':') {
            if g.is_empty() || g.len() > 4 || !g.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            n += 1;
        }
        Some(n)
    };
    match s.split_once("::") {
        Some((l, r)) => matches!((groups(l), groups(r)), (Some(a), Some(b)) if a + b <= 7),
        None => groups(s) == Some(8),
    }
}

/// A port, 1 to 65535 (leading zeros allowed).
fn is_port(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) && s.trim_start_matches('0').len() <= 5 && s.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n))
}

/// `nodename [ ":" node-port ]`, as `(name, port)`; the name keeps its brackets.
fn split_node(s: &str) -> Option<(&str, Option<&str>)> {
    let (name, port) = if let Some(rest) = s.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        if !is_ipv6_literal(inner) {
            return None;
        }
        (&s[..inner.len() + 2], match after {
            "" => None,
            _ => Some(after.strip_prefix(':')?),
        })
    } else {
        match s.split_once(':') {
            Some((n, p)) => (n, Some(p)),
            None => (s, None),
        }
    };
    if !name.starts_with('[') && !(name == "unknown" || is_obf(name) || Ipv4Addr::from_str(name).is_ok()) {
        return None;
    }
    if let Some(p) = port {
        if !(is_port(p) || is_obf(p)) {
            return None;
        }
    }
    Some((name, port))
}

/// `uri-host [ ":" port ]` as `HAProxy` accepts it, the empty host included.
#[must_use]
pub fn valid_host(s: &str) -> bool {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let Some((inner, after)) = rest.split_once(']') else { return false };
        if !is_ipv6_literal(inner) {
            return false;
        }
        match after {
            "" => return true,
            _ => ("[", after.strip_prefix(':')),
        }
    } else {
        match s.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (s, None),
        }
    };
    if host == "[" && port.is_none() {
        return false;
    }
    if host != "[" {
        let mut prev = '.';
        for c in host.chars() {
            if !(c.is_ascii_alphanumeric() || c == '.' || c == '-') || (c == '-' && prev == '.') {
                return false;
            }
            prev = c;
        }
    }
    port.is_none_or(is_port)
}

type Pair<'a> = (&'a str, String);

fn split_outside_quotes(s: &str, sep: char) -> Option<Vec<&str>> {
    let mut parts = Vec::new();
    let (mut start, mut quoted) = (0, false);
    for (i, c) in s.char_indices() {
        if c == '"' {
            quoted = !quoted;
        } else if c == sep && !quoted {
            parts.push(&s[start..i]);
            start = i + 1;
        }
    }
    if quoted {
        return None;
    }
    parts.push(&s[start..]);
    Some(parts)
}

fn parse_pair(pair: &str) -> Option<Pair<'_>> {
    let (name, value) = pair.split_once('=')?;
    let (content, quoted) = if let Some(inner) = value.strip_prefix('"') {
        let inner = inner.strip_suffix('"')?;
        if inner.contains(['"', '\\']) {
            return None;
        }
        (inner, true)
    } else {
        if value.is_empty() || !value.chars().all(is_tchar) {
            return None;
        }
        (value, false)
    };
    let ok = match name {
        "for" | "by" => split_node(content).is_some(),
        "host" => valid_host(content),
        "proto" => !quoted && matches!(content, "http" | "https"),
        _ => false,
    };
    ok.then(|| (name, content.to_string()))
}

fn parse_element(element: &str) -> Option<Vec<Pair<'_>>> {
    let mut pairs: Vec<Pair<'_>> = Vec::new();
    for part in split_outside_quotes(element, ';')? {
        let pair = parse_pair(part)?;
        if pairs.iter().any(|(n, _)| *n == pair.0) {
            return None;
        }
        pairs.push(pair);
    }
    Some(pairs)
}

/// The elements of a `Forwarded` value; empty ones are skipped, except as the last.
fn parse(s: &str) -> Option<Vec<Vec<Pair<'_>>>> {
    let parts = split_outside_quotes(s, ',')?;
    let last = parts.len() - 1;
    let mut out: Vec<Vec<_>> = Vec::new();
    for (i, part) in parts.into_iter().enumerate() {
        let part = part.trim_matches([' ', '\t']);
        if part.is_empty() {
            if i == last {
                return None;
            }
            continue;
        }
        let elem = parse_element(part)?;
        out.push(elem);
    }
    // HAProxy requires that if any element contains `for`, the first element must contain it.
    if out.len() > 1 {
        let any_for = out.iter().any(|e| e.iter().any(|(n,_)| *n == "for"));
        if any_for && !out[0].iter().any(|(n,_)| *n == "for") {
            return None;
        }
    }
    Some(out)
}

/// `rfc7239_is_valid`: whether `s` is a well formed `Forwarded` value.
#[must_use]
pub fn is_valid(s: &str) -> bool {
    parse(s).is_some()
}

/// `rfc7239_field(<name>)`: the value of `name` in the last element, unquoted.
#[must_use]
pub fn field(s: &str, name: &str) -> Option<String> {
    let elements = parse(s)?;
    elements.last()?.iter().find(|(n, _)| *n == name).map(|(_, v)| v.clone())
}

/// `rfc7239_n2nn`: the node name of a node, an IPv6 address without its brackets.
#[must_use]
pub fn n2nn(node: &str) -> Option<String> {
    let (name, _) = split_node(node)?;
    Some(name.strip_prefix('[').and_then(|n| n.strip_suffix(']')).unwrap_or(name).to_string())
}

/// `rfc7239_n2np`: the port of a node.
#[must_use]
pub fn n2np(node: &str) -> Option<String> {
    split_node(node)?.1.map(str::to_string)
}

/// `rfc7239_nn`: a node name from an address, or an obfuscated one from a string.
#[must_use]
pub fn nn(smp: &Sample) -> Option<String> {
    match smp {
        Sample::Ipv4(a) => Some(a.to_string()),
        Sample::Ipv6(a) => Some(format!("[{a}]")),
        Sample::Str(s) if !s.is_empty() && s.chars().all(is_obf_char) => Some(format!("_{s}")),
        _ => None,
    }
}

/// `rfc7239_np`: a node port from an integer, or an obfuscated one from a string.
#[must_use]
pub fn np(smp: &Sample) -> Option<String> {
    match smp {
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        Sample::Sint(n) => Some((*n as u32).to_string()),
        Sample::Str(s) if !s.is_empty() && s.chars().all(is_obf_char) => Some(format!("_{s}")),
        _ => None,
    }
}

/// The node name `option forwarded ... for-expr/by-expr` writes for a sample: an address as
/// it is, `unknown` or an already obfuscated name kept, any other name obfuscated, and
/// `unknown` for what cannot be one.
#[must_use]
pub fn node_from_sample(smp: Option<&Sample>) -> String {
    const UNKNOWN: &str = "unknown";
    match smp {
        Some(Sample::Ipv4(a)) => a.to_string(),
        Some(Sample::Ipv6(a)) => format!("[{a}]"),
        Some(Sample::Sint(n)) => format!("_{n}"),
        Some(Sample::Str(s)) => {
            if s == UNKNOWN || Ipv4Addr::from_str(s).is_ok() || is_obf(s) {
                s.clone()
            } else if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')).filter(|i| is_ipv6_literal(i)) {
                format!("[{inner}]")
            } else if !s.is_empty() && s.chars().all(is_obf_char) {
                format!("_{s}")
            } else {
                UNKNOWN.to_string()
            }
        }
        _ => UNKNOWN.to_string(),
    }
}

/// The port `option forwarded ... for_port-expr/by_port-expr` writes for a sample; none when
/// there is no sample or it cannot be one.
#[must_use]
pub fn port_from_sample(smp: Option<&Sample>) -> Option<String> {
    match smp? {
        Sample::Sint(n) if (1..=65535).contains(n) => Some(n.to_string()),
        Sample::Sint(n) => Some(format!("_{n}")),
        Sample::Str(s) if is_port(s) || is_obf(s) => Some(s.clone()),
        Sample::Str(s) if !s.is_empty() && s.chars().all(is_obf_char) => Some(format!("_{s}")),
        _ => None,
    }
}

pub(crate) fn register(reg: &mut Registry) {
    reg.register_converter(ConvDesc {
        name: "rfc7239_is_valid",
        in_type: TypeSpec::Exact(SampleType::Str),
        out_type: TypeSpec::Exact(SampleType::Bool),
        func: |smp, _| if let Sample::Str(s) = smp { Some(Sample::Bool(is_valid(&s))) } else { None },
    });
    reg.register_converter(ConvDesc {
        name: "rfc7239_field",
        in_type: TypeSpec::Exact(SampleType::Str),
        out_type: TypeSpec::Exact(SampleType::Str),
        func: |smp, args| if let Sample::Str(s) = smp { field(&s, args.first()?).map(Sample::Str) } else { None },
    });
    reg.register_converter(ConvDesc {
        name: "rfc7239_n2nn",
        in_type: TypeSpec::Exact(SampleType::Str),
        out_type: TypeSpec::Exact(SampleType::Str),
        func: |smp, _| if let Sample::Str(s) = smp { n2nn(&s).map(Sample::Str) } else { None },
    });
    reg.register_converter(ConvDesc {
        name: "rfc7239_n2np",
        in_type: TypeSpec::Exact(SampleType::Str),
        out_type: TypeSpec::Exact(SampleType::Str),
        func: |smp, _| if let Sample::Str(s) = smp { n2np(&s).map(Sample::Str) } else { None },
    });
    reg.register_converter(ConvDesc {
        name: "rfc7239_nn",
        in_type: TypeSpec::Any,
        out_type: TypeSpec::Exact(SampleType::Str),
        func: |smp, _| nn(&smp).map(Sample::Str),
    });
    reg.register_converter(ConvDesc {
        name: "rfc7239_np",
        in_type: TypeSpec::Any,
        out_type: TypeSpec::Exact(SampleType::Str),
        func: |smp, _| np(&smp).map(Sample::Str),
    });
}
