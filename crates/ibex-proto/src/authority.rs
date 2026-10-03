// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The request authority against `Host`, checked and normalised as HAProxy's H1 parser
//! does it (tasks/T93).
//!
//! Three steps, each from HAProxy 3.5:
//!
//! 1. A repeated `Host` with the same value (compared without case) is dropped; with a
//!    different value the request is invalid (`src/h1.c`, `h1_parse_msg_hdrs`).
//! 2. An authority-form or absolute-form target is checked against `Host`
//!    (`h1_validate_connect_authority`, `h1_validate_mismatch_authority`). A CONNECT
//!    `Host` carrying a default port has it removed.
//! 3. An absolute-form target is normalised by its scheme (`src/http_htx.c`,
//!    `http_scheme_based_normalize`, RFC 3986 section 6.3.2): a default or empty port is
//!    dropped from the authority and every `Host` is set to the authority's host, and an
//!    empty path becomes `/` (except for OPTIONS).
//!
//! The helpers are transcriptions of `http_get_host_port`, `http_is_default_port`,
//! `http_parse_scheme` and `http_parse_authority` in `src/http.c`.

use crate::htx::{HtxBlockType, HtxSlice, HtxSliceRef};
use std::io;

fn invalid(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

/// `http_authority_has_forbidden_char` (`include/haproxy/http.h`): a byte outside `!`..`~`,
/// or one of `, # / ? @ \`, or a bracket that is not the delimiter of an IP literal (`[`
/// first, `]` last or before a colon), or a bracket left open.
fn has_forbidden_char(v: &[u8]) -> bool {
    let mut brackets = false;
    for (i, &c) in v.iter().enumerate() {
        if c < 0x21 || c > 0x7e || matches!(c, b',' | b'#' | b'/' | b'?' | b'@' | b'[' | b'\\' | b']') {
            if (c == b'[' && i == 0) || (c == b']' && (i == v.len() - 1 || v[i + 1] == b':')) {
                brackets = !brackets;
            } else {
                return true;
            }
        }
    }
    brackets
}

/// `http_get_host_port`: the port after the last `:` when only digits follow it. `None`
/// when there is no such `:`, `Some("")` when the `:` ends the value.
fn host_port(host: &str) -> Option<&str> {
    let b = host.as_bytes();
    if b.is_empty() {
        return None;
    }
    let digits = b.iter().rev().take_while(|c| c.is_ascii_digit()).count();
    let colon = b.len().checked_sub(digits + 1)?;
    (b[colon] == b':').then(|| &host[colon + 1..])
}

/// `host` without its `:port`, when [`host_port`] found one.
fn strip_port<'a>(host: &'a str, port: Option<&str>) -> &'a str {
    port.map_or(host, |p| &host[..host.len() - p.len() - 1])
}

/// `http_is_default_port`. An empty port is a default one. Without a scheme (CONNECT)
/// both 80 and 443 are; with one, 80 for `http://` and 443 for `https://`.
fn is_default_port(scheme: Option<&str>, port: &str) -> bool {
    if port.is_empty() {
        return true;
    }
    match scheme {
        None => port == "443" || port == "80",
        Some(s) => {
            (port == "443" && s.eq_ignore_ascii_case("https://"))
                || (port == "80" && s.eq_ignore_ascii_case("http://"))
        }
    }
}

/// `http_parse_scheme`: the scheme with its `://`, if the target starts with one.
fn parse_scheme(uri: &str) -> Option<&str> {
    let b = uri.as_bytes();
    if !b.first()?.is_ascii_alphabetic() {
        return None;
    }
    let n = 1 + b[1..]
        .iter()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
        .count();
    b[n..].starts_with(b"://").then(|| &uri[..n + 3])
}

/// `http_parse_authority` with `no_userinfo`: the authority (from after the last `@`) and
/// where it starts, and the rest of the target (the path, possibly empty).
fn parse_authority(rest: &str) -> (usize, &str, &str) {
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let start = rest[..end].rfind('@').map_or(0, |at| at + 1);
    (start, &rest[start..end], &rest[end..])
}

/// `h1_validate_connect_authority`. On success, the value `Host` must be given, when it
/// is to be normalised.
fn validate_connect(authority: &str, host: Option<&str>) -> io::Result<Option<String>> {
    let uri_port = host_port(authority).filter(|p| !p.is_empty()).ok_or_else(|| invalid("CONNECT authority without a port"))?;
    let uri_host = strip_port(authority, Some(uri_port));
    let Some(host_hdr) = host else { return Ok(None) };
    let hport = host_port(host_hdr);
    let h = strip_port(host_hdr, hport);
    match hport {
        Some(p) if !p.is_empty() => {
            if !h.eq_ignore_ascii_case(uri_host) || p != uri_port {
                return Err(invalid("Host does not match the CONNECT authority"));
            }
            Ok(is_default_port(None, uri_port).then(|| h.to_string()))
        }
        _ => {
            if !is_default_port(None, uri_port) || !h.eq_ignore_ascii_case(uri_host) {
                return Err(invalid("Host does not match the CONNECT authority"));
            }
            Ok(None)
        }
    }
}

/// `h1_validate_mismatch_authority`: whether an authority and a `Host` that differ as text
/// still name the same thing, one carrying the scheme's default port and the other none.
fn mismatch_is_equivalent(scheme: &str, authority: &str, host_hdr: &str) -> bool {
    let uport = host_port(authority);
    let uhost = strip_port(authority, uport);
    let hport = host_port(host_hdr);
    let h = strip_port(host_hdr, hport);
    if uport.is_none() && hport.is_none() {
        return false;
    }
    if uport.is_some_and(|p| !is_default_port(Some(scheme), p)) || hport.is_some_and(|p| !is_default_port(Some(scheme), p)) {
        return false;
    }
    uhost.eq_ignore_ascii_case(h)
}

/// The value of block `i` when it is a `Host` header.
fn host_value<'a>(view: &HtxSliceRef<'a>, i: usize) -> Option<&'a [u8]> {
    if view.block_type(i) != Some(HtxBlockType::Header) {
        return None;
    }
    let desc = view.read_desc(i);
    let (start, name_len, value_len) = (desc.addr as usize, desc.name_len as usize, desc.value_len as usize);
    let buf = view.buf();
    buf[start..start + name_len]
        .eq_ignore_ascii_case(b"host")
        .then(|| &buf[start + name_len..start + name_len + value_len])
}

/// Applies the three steps to a parsed request head. Returns whether it was rewritten,
/// so the caller forwards the head from the HTX rather than the bytes received.
///
/// # Errors
/// The request is invalid (HAProxy answers 400): two `Host` values that differ, a CONNECT
/// target without a port, or an authority that does not match `Host`.
pub fn check_and_normalize(htx: &mut HtxSlice<'_>, accept_unsafe: bool) -> io::Result<bool> {
    let mut rewritten = false;

    // 1. Host headers of this message: the first is kept, a repeat of it dropped. Read in
    // place, so a request in origin-form -- nearly all of them -- allocates nothing here
    // (`tests/htx_allocation.rs`).
    let first = (0..htx.num_blocks())
        .rev()
        .find(|&i| htx.block_type(i) == Some(HtxBlockType::ReqLine))
        .map_or(0, |i| i + 1);
    let mut host_at: Option<usize> = None;
    for i in first..htx.num_blocks() {
        let view = htx.as_ref();
        let Some(value) = host_value(&view, i) else { continue };
        match host_at {
            None => host_at = Some(i),
            Some(h) => {
                if !host_value(&view, h).is_some_and(|kept| kept.eq_ignore_ascii_case(value)) {
                    return Err(invalid("two Host headers that differ"));
                }
                htx.remove_block(i);
                rewritten = true;
            }
        }
    }

    // A `#` anywhere in the target is an invalid request line (`h1_headers_to_hdr_list`,
    // `http_msg_rquri2`); it is checked first so that no form of target escapes it.
    if !accept_unsafe && htx.req_line().is_some_and(|r| r.uri.contains('#')) {
        return Err(invalid("a fragment in the request target"));
    }
    // The first `Host` of any request (`h1_parse_msg_hdrs`).
    if let Some(i) = host_at {
        if has_forbidden_char(host_value(&htx.as_ref(), i).unwrap_or_default()) {
            return Err(invalid("a forbidden character in Host"));
        }
    }

    let (method, uri) = match htx.req_line() {
        Some(r) if !(r.uri.starts_with('/') || r.uri.starts_with('*') || r.uri.is_empty()) => {
            (r.method.to_string(), r.uri.to_string())
        }
        _ => return Ok(rewritten),
    };
    let host: Option<String> = match host_at {
        Some(i) => Some(
            std::str::from_utf8(host_value(&htx.as_ref(), i).unwrap_or_default())
                .map_err(|_| invalid("Host is not UTF-8"))?
                .to_string(),
        ),
        None => None,
    };
    let host_idx: Vec<usize> = host_at.into_iter().collect();
    let connect = method.eq_ignore_ascii_case("CONNECT");

    // 2. The authority against Host.
    let Some(scheme) = parse_scheme(&uri) else {
        if !connect {
            return Err(invalid("a target without a scheme on a method other than CONNECT"));
        }
        let (_, authority, _) = parse_authority(&uri);
        if !accept_unsafe && has_forbidden_char(authority.as_bytes()) {
            return Err(invalid("a forbidden character in the CONNECT authority"));
        }
        if let Some(h) = validate_connect(authority, host.as_deref())? {
            for &i in &host_idx {
                htx.replace_block_value(i, h.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
            }
            rewritten = true;
        }
        return Ok(rewritten);
    };
    if connect {
        return Err(invalid("CONNECT with an absolute-form target"));
    }
    let rest = &uri[scheme.len()..];
    let (auth_at, authority, path) = parse_authority(rest);
    if !accept_unsafe && has_forbidden_char(authority.as_bytes()) {
        return Err(invalid("a forbidden character in the request authority"));
    }
    if let Some(h) = host.as_deref() {
        if !authority.eq_ignore_ascii_case(h) && !mismatch_is_equivalent(scheme, authority, h) {
            return Err(invalid("Host does not match the request authority"));
        }
    }

    // 3. Scheme-based normalisation.
    let port = host_port(authority);
    let (norm_host, mut normalize) = match port {
        Some(p) if is_default_port(Some(scheme), p) => (strip_port(authority, port), true),
        _ => (authority, false),
    };
    let path = if path.is_empty() && !method.eq_ignore_ascii_case("OPTIONS") {
        normalize = true;
        "/"
    } else {
        path
    };
    if normalize {
        let prefix = &uri[..scheme.len() + auth_at];
        let new_uri = format!("{prefix}{norm_host}{path}");
        let norm_host = norm_host.to_string();
        htx.set_uri(&new_uri).map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
        for &i in &host_idx {
            htx.replace_block_value(i, norm_host.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
        }
        rewritten = true;
    }
    Ok(rewritten)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_matches_http_get_host_port() {
        assert_eq!(host_port("hostname"), None);
        assert_eq!(host_port("hostname:"), Some(""));
        assert_eq!(host_port("hostname:80"), Some("80"));
        assert_eq!(host_port(":80"), Some("80"));
        assert_eq!(host_port("80"), None);
        assert_eq!(host_port("[::1]"), None);
        assert_eq!(host_port("[::1]:443"), Some("443"));
        assert_eq!(host_port(""), None);
    }

    #[test]
    fn scheme_and_authority_split_as_haproxy_does() {
        assert_eq!(parse_scheme("http://a/b"), Some("http://"));
        assert_eq!(parse_scheme("hostname:80"), None);
        assert_eq!(parse_authority("toto:poue@hostname:80/c1"), (10, "hostname:80", "/c1"));
        assert_eq!(parse_authority("hostname?a=b"), (0, "hostname", "?a=b"));
        assert_eq!(parse_authority(":"), (0, ":", ""));
        assert_eq!(parse_scheme("127.0.0.1:443"), None, "a target starting with a digit has no scheme");
        assert_eq!(parse_scheme("[::1]:443"), None);
    }

    fn check(method: &str, uri: &str) -> io::Result<bool> {
        let mut buf = [0u8; 1024];
        let mut htx = HtxSlice::new(&mut buf);
        htx.push_req_line(method, uri, "HTTP/1.1").unwrap();
        htx.push_header("host", "h:80").unwrap();
        htx.push_eoh().unwrap();
        check_and_normalize(&mut htx, false)
    }

    /// The H1 request-line parser refuses these two before this runs; `HAProxy`'s
    /// `h1_parse_msg_hdrs` refuses them here too, and so does this, for a caller that
    /// builds the HTX some other way.
    #[test]
    fn a_target_whose_form_does_not_fit_the_method_is_refused() {
        assert!(check("GET", "h:80").is_err(), "authority-form is for CONNECT only");
        assert!(check("CONNECT", "http://h:80/").is_err(), "CONNECT takes no scheme");
        assert!(matches!(check("CONNECT", "h:80"), Ok(true)), "control: Host loses the default port");
        assert!(matches!(check("GET", "/"), Ok(false)), "control: origin-form is left alone");
    }
}
