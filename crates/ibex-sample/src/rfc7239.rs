// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/http_ana.c, src/http_htx.c and src/sample.c (the `rfc7239_*`
// converters and `option forwarded`). Copyright (C) 2000-2026 Willy Tarreau and HAProxy
// contributors. See LICENSE.

//! RFC 7239 `Forwarded` header values: the `rfc7239_*` converters, and the value
//! formatting `option forwarded` uses. Each rule here was measured on `HAProxy`
//! 3.5-dev8-885761-29 (see `tests/rfc7239.rs`).

use std::net::{Ipv4Addr, Ipv6Addr};
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

// `http_validate_7239_header()` and the `http_7239_extract_*()` helpers of src/http_ext.c,
// ported as they are: one forwarded-element, parameters separated by ';' with no whitespace,
// each of for/by/host/proto at most once, and the scan stops as soon as all four are
// validated, whatever follows. Every helper consumes from `b` at `*i`; only ASCII is consumed,
// so every position is a char boundary of the `&str` the bytes come from.

const FWD_FOR: u8 = 1;
const FWD_BY: u8 = 2;
const FWD_HOST: u8 = 4;
const FWD_PROTO: u8 = 8;
const FWD_ALL: u8 = FWD_FOR | FWD_BY | FWD_HOST | FWD_PROTO;

/// The parameters `http_validate_7239_header()` validated, and their raw values.
#[derive(Default)]
struct Forwarded<'a> {
    steps: u8,
    nfor: &'a str,
    nby: &'a str,
    host: &'a str,
    proto: &'static str,
}

/// `http_7239_extract_port()`: 1 to 65535, in digits.
fn extract_port(b: &[u8], i: &mut usize) -> bool {
    let mut port = 0u32;
    let mut it = *i;
    while it < b.len() && b[it].is_ascii_digit() {
        port = port * 10 + u32::from(b[it] - b'0');
        if port > 65535 {
            return false;
        }
        it += 1;
    }
    if port == 0 {
        return false;
    }
    *i = it;
    true
}

/// `http_7239_extract_obfs()`: at least one of `[A-Za-z0-9._-]`.
fn extract_obfs(b: &[u8], i: &mut usize) -> bool {
    let start = *i;
    while *i < b.len() && b[*i] != b';' && (b[*i].is_ascii_alphanumeric() || matches!(b[*i], b'.' | b'-' | b'_')) {
        *i += 1;
    }
    *i > start
}

/// The longest run of `ok` bytes from `*i`, at most `max` long, as text.
fn take_run(b: &[u8], i: usize, max: usize, ok: impl Fn(u8) -> bool) -> &str {
    let n = b[i..].iter().take(max).take_while(|&&c| ok(c)).count();
    std::str::from_utf8(&b[i..i + n]).unwrap_or("")
}

/// `http_7239_extract_ipv4()`: up to 15 digits and dots that `inet_pton()` takes.
fn extract_ipv4(b: &[u8], i: &mut usize) -> bool {
    let ip4 = take_run(b, *i, 15, |c| c.is_ascii_digit() || c == b'.');
    if Ipv4Addr::from_str(ip4).is_err() {
        return false;
    }
    *i += ip4.len();
    true
}

/// `http_7239_extract_ipv6()`, at a `[`: up to 45 alphanumerics and colons, a `]`, and an
/// address `inet_pton()` takes.
fn extract_ipv6(b: &[u8], i: &mut usize) -> bool {
    let at = *i + 1;
    let ip6 = take_run(b, at, 45, |c| c.is_ascii_alphanumeric() || c == b':');
    let end = at + ip6.len();
    if b.get(end) != Some(&b']') || Ipv6Addr::from_str(ip6).is_err() {
        return false;
    }
    *i = end + 1;
    true
}

/// `http_7239_extract_host()`: a name of alphanumerics and dots (possibly empty), or a
/// bracketed IPv6 address when quoted; a port only when quoted.
fn extract_host(b: &[u8], i: &mut usize, quoted: bool) -> bool {
    if *i >= b.len() {
        return false;
    }
    if quoted && b[*i] == b'[' {
        if !extract_ipv6(b, i) {
            return false;
        }
    } else {
        while *i < b.len() && (b[*i].is_ascii_alphanumeric() || b[*i] == b'.') {
            *i += 1;
        }
    }
    if *i >= b.len() || b[*i] != b':' {
        return true;
    }
    if !quoted {
        return false;
    }
    *i += 1;
    extract_port(b, i)
}

/// `http_7239_extract_nodename()`: `_obfs`, `unknown`, a bracketed IPv6 address when quoted, or
/// an IPv4 address.
fn extract_nodename(b: &[u8], i: &mut usize, quoted: bool) -> bool {
    match b.get(*i) {
        None | Some(0) => false,
        Some(b'_') => {
            *i += 1;
            extract_obfs(b, i)
        }
        Some(b'u') => {
            if !b[*i..].starts_with(b"unknown") {
                return false;
            }
            *i += 7;
            true
        }
        Some(b'[') if quoted => extract_ipv6(b, i),
        Some(_) => extract_ipv4(b, i),
    }
}

/// `http_7239_extract_node()`: a node name, then `:` and a port (digits or `_obfs`) only when
/// quoted.
fn extract_node(b: &[u8], i: &mut usize, quoted: bool) -> bool {
    if !extract_nodename(b, i, quoted) {
        return false;
    }
    if *i >= b.len() || b[*i] != b':' {
        return true;
    }
    if !quoted {
        return false;
    }
    *i += 1;
    match b.get(*i) {
        None => false,
        Some(b'_') => {
            *i += 1;
            extract_obfs(b, i)
        }
        Some(_) => extract_port(b, i),
    }
}

/// `http_validate_7239_header(hdr, FORWARDED_HEADER_ALL, ctx)`; `None` where it returns 0.
fn validate(hdr: &str) -> Option<Forwarded<'_>> {
    let b = hdr.as_bytes();
    let mut f = Forwarded::default();
    let mut i = 0;
    let mut first = true;
    while i < b.len() && f.steps != FWD_ALL {
        if first {
            first = false;
        } else if b[i] == b';' {
            i += 1;
        } else {
            return None;
        }
        let rest = &b[i..];
        let has = |step: u8, name: &[u8]| f.steps & step == 0 && rest.len() > name.len() && rest.starts_with(name);
        // a quote opens the value of for, by and host; it must close right after it
        let quote = |i: &mut usize| {
            let q = b.get(*i) == Some(&b'"');
            *i += usize::from(q);
            q
        };
        let (step, quoted) = if has(FWD_FOR, b"for=") || has(FWD_BY, b"by=") {
            let step = if rest[0] == b'f' { FWD_FOR } else { FWD_BY };
            i += if step == FWD_FOR { 4 } else { 3 };
            let quoted = quote(&mut i);
            let start = i;
            if !extract_node(b, &mut i, quoted) {
                return None;
            }
            if step == FWD_FOR {
                f.nfor = &hdr[start..i];
            } else {
                f.nby = &hdr[start..i];
            }
            (step, quoted)
        } else if has(FWD_HOST, b"host=") {
            i += 5;
            let quoted = quote(&mut i);
            let start = i;
            if !extract_host(b, &mut i, quoted) {
                return None;
            }
            f.host = &hdr[start..i];
            (FWD_HOST, quoted)
        } else if has(FWD_PROTO, b"proto=") {
            // only http and https, never quoted
            i += 6;
            if !b[i..].starts_with(b"http") {
                return None;
            }
            i += 4;
            f.proto = if b.get(i) == Some(&b's') {
                i += 1;
                "https"
            } else {
                "http"
            };
            (FWD_PROTO, false)
        } else {
            return None;
        };
        if quoted {
            if b.get(i) != Some(&b'"') {
                return None;
            }
            i += 1;
        }
        f.steps |= step;
    }
    (f.steps != 0).then_some(f)
}

/// What `HAProxy`'s `req.hdr()` would hand the converter for the value `s`: the last
/// comma-separated value (`http_find_hdr_value_end()`: commas inside a quoted string, with
/// its backslash pairs, do not count), without its surrounding whitespace. A value without a
/// comma is left as it is.
///
/// Ibex's `req.hdr()` returns the whole line, so the converters pick the last value here to
/// keep `req.hdr(forwarded),rfc7239_field(for)` answering as on `HAProxy`. The cost is
/// `req.fhdr()`: `HAProxy` validates the whole line there, and any comma before the fourth
/// parameter makes it invalid. Remove this once `req.hdr()` splits values itself.
fn last_value(s: &str) -> &str {
    let (mut quoted, mut qdpair, mut last) = (false, false, None);
    for (at, c) in s.bytes().enumerate() {
        if qdpair {
            qdpair = false;
        } else if quoted {
            match c {
                b'\\' => qdpair = true,
                b'"' => quoted = false,
                _ => {}
            }
        } else if c == b'"' {
            quoted = true;
        } else if c == b',' {
            last = Some(at);
        }
    }
    last.map_or(s, |at| s[at + 1..].trim_matches([' ', '\t']))
}

/// `rfc7239_is_valid`: whether `s` is a well formed `Forwarded` value.
#[must_use]
pub fn is_valid(s: &str) -> bool {
    validate(last_value(s)).is_some()
}

/// `rfc7239_field(<name>)`: the raw value of `name` (for, by, host or proto), unquoted, when it
/// was validated.
#[must_use]
pub fn field(s: &str, name: &str) -> Option<String> {
    let f = validate(last_value(s))?;
    let (step, value) = match name {
        "for" => (FWD_FOR, f.nfor),
        "by" => (FWD_BY, f.nby),
        "host" => (FWD_HOST, f.host),
        "proto" => (FWD_PROTO, f.proto),
        _ => return None,
    };
    (f.steps & step != 0).then(|| value.to_string())
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
