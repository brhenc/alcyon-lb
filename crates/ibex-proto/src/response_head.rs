// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The HTTP/1 response head as `HAProxy` parses it (`h1_headers_to_hdr_list` in `src/h1.c`,
//! `h1_process_res_vsn` and `h1_postparse_res_hdrs` in `src/h1_htx.c`, the transfer-coding
//! and websocket checks of `h1_process_headers` in `src/mux_h1.c`), and the head it writes
//! to the client from what it parsed (T275).
//!
//! `accept_unsafe` is `option accept-unsafe-violations-in-http-response` (`PR_O2_RSPBUG_OK`,
//! `err_pos == -1` in the parser). It relaxes exactly: a header name with a character that
//! is not a token (the header is dropped), a NUL in a value, an empty `Transfer-Encoding` or
//! an empty or repeated `chunked` coding, a version other than `HTTP/<digit>.<digit>` (still
//! made of `A-Z`, digits, `.` and `/`), a status of more than three digits, a `101` websocket
//! answer without `Sec-WebSocket-Accept`. Everything else this refuses, it refuses either way.

use std::borrow::Cow;

/// What the response head is.
#[derive(Debug, PartialEq, Eq)]
pub enum ResponseHead {
    /// `HAProxy` refuses it: a 502 to the client, `PH--`.
    Invalid,
    Valid {
        /// The status code as parsed.
        status: u16,
        /// When `HAProxy` would not write the head as the server sent it.
        rewrite: Option<Rewrite>,
        /// The server connection must close after this response (`H1_MF_CONN_CLO`): both
        /// `Transfer-Encoding` and `Content-Length`, or `Transfer-Encoding` in HTTP/1.0.
        close_server: bool,
    },
}

/// A head written again.
#[derive(Debug, PartialEq, Eq)]
pub struct Rewrite {
    /// What goes to the client.
    pub head: Vec<u8>,
    /// What `HAProxy`'s HTX holds of it, as an HTTP/1 head (what `%B` counts): the reason
    /// as the server wrote it, `Transfer-Encoding` as it came.
    pub held: Vec<u8>,
}

/// `HTTP_IS_TOKEN`: RFC 7230 tchar.
const fn is_token(c: u8) -> bool {
    matches!(c, b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~')
        || c.is_ascii_alphanumeric()
}

/// `HTTP_IS_VER_TOKEN`: upper-case letters, digits, `.` and `/`.
const fn is_ver(c: u8) -> bool {
    matches!(c, b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'/')
}

const fn is_spht(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

const fn is_crlf(c: u8) -> bool {
    c == b'\r' || c == b'\n'
}

/// One header as parsed: the name as written, the value cleaned (folds joined with spaces,
/// blanks around it trimmed), and whether the line was already `name: value\r\n`.
struct Header<'a> {
    name: &'a [u8],
    value: Cow<'a, [u8]>,
    canonical: bool,
}

/// The pieces of a parsed head.
struct Parsed<'a> {
    version: &'a [u8],
    code: &'a [u8],
    status: u16,
    reason: &'a [u8],
    /// The start line and its line end were `version SP code SP reason CRLF`, reason not
    /// empty, with nothing before it.
    canonical_start: bool,
}

/// The value of a header line starting at `*i` (just after the colon), up to and past its
/// line end and any folded continuation, with whether the line was `: value\r\n` already
/// (one space, nothing to trim, no fold, CRLF). `None`: refused.
fn parse_value<'a>(h: &'a [u8], i: &mut usize, accept_unsafe: bool) -> Option<(Cow<'a, [u8]>, bool)> {
    let start = *i;
    let mut owned: Option<Vec<u8>> = None;
    let mut seg = start;
    loop {
        while *i < h.len() && !is_crlf(h[*i]) {
            if h[*i] == 0 && !accept_unsafe {
                return None;
            }
            *i += 1;
        }
        let line_end = *i;
        let crlf = match h.get(*i) {
            Some(b'\r') if h.get(*i + 1) == Some(&b'\n') => {
                *i += 2;
                true
            }
            Some(b'\n') => {
                *i += 1;
                false
            }
            _ => return None,
        };
        if h.get(*i).copied().is_some_and(is_spht) {
            // A folded line: CR and LF become spaces and the value goes on.
            let o = owned.get_or_insert_with(Vec::new);
            o.extend_from_slice(&h[seg..line_end]);
            o.extend_from_slice(if crlf { b"  " } else { b" " });
            seg = *i;
            continue;
        }
        let Some(mut o) = owned else {
            let raw = &h[start..line_end];
            let canonical = crlf
                && (raw == b" " || (raw.len() >= 2 && raw[0] == b' ' && !is_spht(raw[1]) && !is_spht(raw[raw.len() - 1])));
            return Some((Cow::Borrowed(raw.trim_ascii()), canonical));
        };
        o.extend_from_slice(&h[seg..line_end]);
        return Some((Cow::Owned(o.trim_ascii().to_vec()), false));
    }
}

/// Parses the head; each header goes to `header` in order, `None` for one `accept_unsafe`
/// drops (a bad name). Nothing is collected here: the well-formed head is checked without
/// allocating (`fast_check`).
fn parse<'a>(h: &'a [u8], accept_unsafe: bool, mut header: impl FnMut(Option<Header<'a>>)) -> Option<Parsed<'a>> {
    let mut i = 0;
    let mut canonical_start = true;
    // Empty lines ahead of the status line are skipped.
    loop {
        match h.get(i) {
            Some(b'\n') => i += 1,
            Some(b'\r') if h.get(i + 1) == Some(&b'\n') => i += 2,
            Some(b'\r') => return None,
            _ => break,
        }
        canonical_start = false;
    }
    // The version: `HTTP_IS_TOKEN` for its first character, `HTTP_IS_VER_TOKEN` after.
    let v0 = i;
    if !h.get(i).copied().is_some_and(is_token) {
        return None;
    }
    while h.get(i).copied().is_some_and(is_ver) {
        i += 1;
    }
    if i == v0 || !h.get(i).copied().is_some_and(is_spht) {
        return None;
    }
    let version = &h[v0..i];
    let http_version = version.len() == 8
        && version.starts_with(b"HTTP/")
        && version[5].is_ascii_digit()
        && version[6] == b'.'
        && version[7].is_ascii_digit();
    if !http_version && !accept_unsafe {
        return None;
    }
    if h[i] != b' ' || h.get(i + 1).copied().is_some_and(is_spht) {
        canonical_start = false;
    }
    while h.get(i).copied().is_some_and(is_spht) {
        i += 1;
    }
    // The status: digits, then a blank or the line end. More than three digits only under
    // the option, and not past what `uint16_t` takes.
    let c0 = i;
    let mut status: u32 = 0;
    while let Some(&c) = h.get(i).filter(|c| c.is_ascii_digit()) {
        if i - c0 >= 3 && (!accept_unsafe || status >= (u32::from(u16::MAX) - 9) / 10) {
            return None;
        }
        status = status * 10 + u32::from(c - b'0');
        i += 1;
    }
    if i == c0 {
        return None;
    }
    let code = &h[c0..i];
    let reason = match h.get(i) {
        Some(&c) if is_spht(c) => {
            if c != b' ' || h.get(i + 1).copied().is_some_and(is_spht) {
                canonical_start = false;
            }
            while h.get(i).copied().is_some_and(is_spht) {
                i += 1;
            }
            let r0 = i;
            while h.get(i).is_some_and(|c| !is_crlf(*c)) {
                i += 1;
            }
            &h[r0..i]
        }
        Some(&c) if is_crlf(c) => &h[i..i],
        _ => return None,
    };
    if reason.is_empty() {
        canonical_start = false;
    }
    match h.get(i) {
        Some(b'\r') if h.get(i + 1) == Some(&b'\n') => i += 2,
        Some(b'\n') => {
            i += 1;
            canonical_start = false;
        }
        _ => return None,
    }
    loop {
        match h.get(i) {
            Some(b'\r') if h.get(i + 1) == Some(&b'\n') => break,
            Some(b'\n') => {
                // The head ends with a bare LF: rewritten.
                canonical_start = false;
                break;
            }
            Some(_) => {}
            None => return None,
        }
        let n0 = i;
        let mut bad_name = false;
        loop {
            let c = *h.get(i)?;
            if is_token(c) {
                i += 1;
            } else if c == b':' {
                break;
            } else if !accept_unsafe || c == b'\n' {
                return None;
            } else {
                bad_name = true;
                i += 1;
            }
        }
        if i == n0 {
            return None;
        }
        let name = &h[n0..i];
        i += 1;
        let (value, canonical) = parse_value(h, &mut i, accept_unsafe)?;
        header(if bad_name { None } else { Some(Header { name, value, canonical }) });
    }
    Some(Parsed { version, code, status: u16::try_from(status).ok()?, reason, canonical_start })
}

/// `http_find_hdr_value_end`: the next comma outside a quoted string, or the end.
fn value_end(v: &[u8], mut s: usize) -> usize {
    let mut quoted = false;
    while s < v.len() {
        match v[s] {
            b'\\' if quoted => s += 1,
            b'"' => quoted = !quoted,
            b',' if !quoted => return s,
            _ => {}
        }
        s += 1;
    }
    v.len()
}

/// `h1_parse_xfer_enc_header`, step for step: `Err(())` for an error the option may hide,
/// after updating the flags. `te_chunked` (a `chunked` was seen), `chnk` (the last coding
/// is `chunked`) and `other` (another coding) carry over from one header to the next.
fn parse_te(value: &[u8], xfer_enc: &mut bool, te_chunked: &mut bool, chnk: &mut bool, other: &mut bool) -> Result<(), ()> {
    if value.is_empty() {
        return Err(());
    }
    *xfer_enc = true;
    let mut ret = Ok(());
    let e = value.len();
    let mut w = 0;
    while w < e {
        if is_spht(value[w]) || is_crlf(value[w]) {
            w += 1;
            continue;
        }
        let n = value_end(value, w);
        if n + 1 == e {
            // A comma at the end: the last value is empty.
            ret = Err(());
        }
        let word = value[w..n].trim_ascii_end();
        *chnk = false;
        if word.is_empty() {
            ret = Err(());
        } else if word.eq_ignore_ascii_case(b"chunked") {
            if *te_chunked {
                ret = Err(());
            }
            *te_chunked = true;
            *chnk = true;
        } else {
            *other = true;
        }
        w = n + 1;
    }
    ret
}

/// `http_parse_cont_len_header`: the value of one `Content-Length` header against what an
/// earlier one said. `Err`: refused, whatever the option. `Ok(n)`: the length.
fn parse_cl(value: &[u8], prev: Option<u64>) -> Result<u64, ()> {
    let mut check = prev;
    let mut last = None;
    for word in value.split(|&c| c == b',') {
        let word = word.trim_ascii();
        if word.is_empty() || !word.iter().all(u8::is_ascii_digit) {
            return Err(());
        }
        let mut n: u64 = 0;
        for &c in word {
            n = n.checked_mul(10).and_then(|n| n.checked_add(u64::from(c - b'0'))).ok_or(())?;
        }
        if check.is_some_and(|p| p != n) {
            return Err(());
        }
        check = Some(n);
        last = Some(n);
    }
    last.ok_or(())
}

/// `H1_MF_VER_11` of a response: the version is `HTTP/<d>.<d>` and at least 1.1. A version
/// that is not `HTTP/<d>.<d>` (let through by the option) is not.
#[must_use]
pub fn is_http11(head: &[u8]) -> bool {
    let v = head.split(|&c| is_spht(c) || is_crlf(c)).next().unwrap_or_default();
    v.len() == 8
        && v.starts_with(b"HTTP/")
        && v[5].is_ascii_digit()
        && v[6] == b'.'
        && v[7].is_ascii_digit()
        && (v[5] > b'1' || (v[5] == b'1' && v[7] >= b'1'))
}

/// The common case without allocating: a well-formed head `HAProxy` writes as it came.
/// `Some(Valid { rewrite: None, .. })` only when `check_response_head`'s full pass would say
/// the same; `None` for anything else (refused, rewritten, or in doubt), which the full pass
/// then decides. Everything that sets `dirty` there, or refuses, makes this give up.
fn fast_check(head: &[u8], accept_unsafe: bool) -> Option<ResponseHead> {
    let (mut xfer_enc, mut te_chunked, mut chnk, mut te_other) = (false, false, false, false);
    let mut cl: Option<u64> = None;
    let (mut conn_upg, mut upg_ws, mut ws_accept) = (false, false, false);
    let (mut te_count, mut first_te_chunked) = (0usize, false);
    let mut give_up = false;
    let p = parse(head, accept_unsafe, |h| {
        if give_up {
            return;
        }
        let Some(h) = h.filter(|h| h.canonical) else {
            give_up = true;
            return;
        };
        if h.name.eq_ignore_ascii_case(b"transfer-encoding") {
            if parse_te(&h.value, &mut xfer_enc, &mut te_chunked, &mut chnk, &mut te_other).is_err() && !accept_unsafe {
                give_up = true;
            }
            te_count += 1;
            if te_count == 1 {
                first_te_chunked = &*h.value == b"chunked";
            }
        } else if h.name.eq_ignore_ascii_case(b"content-length") {
            // Written again unless it is the only one and already `n` as `n.to_string()`.
            let v = &*h.value;
            let canonical = !v.is_empty() && v.iter().all(u8::is_ascii_digit) && (v.len() == 1 || v[0] != b'0');
            match parse_cl(v, cl) {
                Ok(n) if cl.is_none() && canonical => cl = Some(n),
                _ => give_up = true,
            }
        } else if h.name.eq_ignore_ascii_case(b"connection")
            && h.value.split(|&c| c == b',').any(|w| w.trim_ascii().eq_ignore_ascii_case(b"upgrade"))
        {
            conn_upg = true;
        } else if h.name.eq_ignore_ascii_case(b"upgrade")
            && h.value.split(|&c| c == b',').any(|w| w.trim_ascii().eq_ignore_ascii_case(b"websocket"))
        {
            upg_ws = true;
        } else if h.name.eq_ignore_ascii_case(b"sec-websocket-accept") {
            ws_accept = true;
        }
    })?;
    if give_up || !p.canonical_start || te_other || (p.status == 101 && conn_upg && upg_ws && !ws_accept && !accept_unsafe) {
        return None;
    }
    let http11 = is_http11(p.version);
    let close_server = xfer_enc && (cl.is_some() || !http11);
    let bodyless = (100..200).contains(&p.status) || p.status == 204;
    let drop_cl = (xfer_enc && cl.is_some()) || bodyless;
    if drop_cl && cl.is_some() {
        return None;
    }
    let keep_te = chnk && !bodyless;
    if te_count > 0 && (!keep_te || te_count > 1 || !first_te_chunked) {
        return None;
    }
    Some(ResponseHead::Valid { status: p.status, rewrite: None, close_server })
}

/// Parses a response head (the bytes up to and including the empty line that ends it).
#[must_use]
pub fn check_response_head(head: &[u8], accept_unsafe: bool) -> ResponseHead {
    fast_check(head, accept_unsafe).unwrap_or_else(|| full_check(head, accept_unsafe))
}

/// `check_response_head` the long way, building the head written again when there is one.
fn full_check(head: &[u8], accept_unsafe: bool) -> ResponseHead {
    let mut headers = Vec::new();
    let Some(p) = parse(head, accept_unsafe, |h| headers.push(h)) else {
        return ResponseHead::Invalid;
    };
    let (mut xfer_enc, mut te_chunked, mut chnk, mut te_other) = (false, false, false, false);
    let mut cl: Option<u64> = None;
    let mut dirty = !p.canonical_start;
    let (mut conn_upg, mut upg_ws, mut ws_accept) = (false, false, false);
    // What each kept header becomes: `None` dropped, else its (possibly cleaned) value.
    let mut out: Vec<Option<Cow<'_, [u8]>>> = Vec::with_capacity(headers.len());
    for h in &headers {
        let Some(h) = h else {
            dirty = true;
            out.push(None);
            continue;
        };
        if !h.canonical {
            dirty = true;
        }
        if h.name.eq_ignore_ascii_case(b"transfer-encoding") {
            if parse_te(&h.value, &mut xfer_enc, &mut te_chunked, &mut chnk, &mut te_other).is_err() && !accept_unsafe {
                return ResponseHead::Invalid;
            }
            out.push(Some(h.value.clone()));
        } else if h.name.eq_ignore_ascii_case(b"content-length") {
            let Ok(n) = parse_cl(&h.value, cl) else {
                return ResponseHead::Invalid;
            };
            if cl.is_some() {
                // A duplicate that agrees: dropped.
                dirty = true;
                out.push(None);
                continue;
            }
            cl = Some(n);
            let clean = n.to_string();
            if clean.as_bytes() != &*h.value {
                dirty = true;
                out.push(Some(Cow::Owned(clean.into_bytes())));
            } else {
                out.push(Some(h.value.clone()));
            }
        } else {
            if h.name.eq_ignore_ascii_case(b"connection")
                && h.value.split(|&c| c == b',').any(|w| w.trim_ascii().eq_ignore_ascii_case(b"upgrade"))
            {
                conn_upg = true;
            } else if h.name.eq_ignore_ascii_case(b"upgrade")
                && h.value.split(|&c| c == b',').any(|w| w.trim_ascii().eq_ignore_ascii_case(b"websocket"))
            {
                upg_ws = true;
            } else if h.name.eq_ignore_ascii_case(b"sec-websocket-accept") {
                ws_accept = true;
            }
            out.push(Some(h.value.clone()));
        }
    }
    // An unknown transfer coding is refused (`H1_MF_TE_OTHER`), the option or not.
    if te_other {
        return ResponseHead::Invalid;
    }
    if p.status == 101 && conn_upg && upg_ws && !ws_accept && !accept_unsafe {
        return ResponseHead::Invalid;
    }
    let http11 = is_http11(p.version);
    let mut close_server = false;
    let mut drop_cl = false;
    if xfer_enc {
        if cl.is_some() {
            close_server = true;
            drop_cl = true;
        } else if !http11 {
            close_server = true;
        }
    }
    // No body: neither header goes on (`h1_postparse_res_hdrs`, and the output side for
    // `Transfer-Encoding`).
    let bodyless = (100..200).contains(&p.status) || p.status == 204;
    if bodyless {
        drop_cl = true;
    }
    // What HTX holds of the head, for `%B` (`h1_headers_to_hdr_list` and
    // `h1_postparse_res_hdrs`): the bad names, the repeated `Content-Length` and the
    // `Content-Length` next to `Transfer-Encoding` are gone; `Transfer-Encoding` is kept as
    // it came, but not on a 1xx or 204; the reason is as the server wrote it.
    let mut held = Vec::with_capacity(out.len());
    for (h, v) in headers.iter().zip(out.iter_mut()) {
        let is_cl = h.as_ref().is_some_and(|h| h.name.eq_ignore_ascii_case(b"content-length"));
        if drop_cl && is_cl && v.is_some() {
            dirty = true;
            *v = None;
        }
        let is_te = h.as_ref().is_some_and(|h| h.name.eq_ignore_ascii_case(b"transfer-encoding"));
        held.push(if is_te && bodyless { None } else { v.clone() });
    }
    // `Transfer-Encoding` goes out once, as `chunked`, when the last coding is `chunked`.
    let keep_te = chnk && !bodyless;
    let mut te_written = false;
    for (h, v) in headers.iter().zip(out.iter_mut()) {
        let (Some(h), Some(value)) = (h, v.as_mut()) else { continue };
        if h.name.eq_ignore_ascii_case(b"transfer-encoding") {
            if !keep_te || te_written {
                dirty = true;
                *v = None;
            } else {
                te_written = true;
                if &**value != b"chunked" {
                    dirty = true;
                    *value = Cow::Borrowed(b"chunked");
                }
            }
        }
    }
    if !dirty {
        return ResponseHead::Valid { status: p.status, rewrite: None, close_server };
    }
    let render = |reason: &[u8], values: &[Option<Cow<'_, [u8]>>]| {
        let mut o = Vec::with_capacity(head.len() + 16);
        o.extend_from_slice(p.version);
        o.push(b' ');
        o.extend_from_slice(p.code);
        o.push(b' ');
        o.extend_from_slice(reason);
        o.extend_from_slice(b"\r\n");
        for (h, v) in headers.iter().zip(values) {
            if let (Some(h), Some(v)) = (h, v) {
                o.extend_from_slice(h.name);
                o.extend_from_slice(b": ");
                o.extend_from_slice(v);
                o.extend_from_slice(b"\r\n");
            }
        }
        o.extend_from_slice(b"\r\n");
        o
    };
    let reason: &[u8] = if p.reason.is_empty() { crate::actions::status_reason_phrase(p.status).as_bytes() } else { p.reason };
    let rewrite = Rewrite { head: render(reason, &out), held: render(p.reason, &held) };
    ResponseHead::Valid { status: p.status, rewrite: Some(rewrite), close_server }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rw(head: &[u8], accept: bool) -> Option<Vec<u8>> {
        match check_response_head(head, accept) {
            ResponseHead::Valid { rewrite, .. } => rewrite.map(|r| r.head),
            ResponseHead::Invalid => panic!("refused: {}", head.escape_ascii()),
        }
    }

    #[test]
    fn a_canonical_head_is_left_alone() {
        assert_eq!(rw(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-A: b c\r\n\r\n", false), None);
        assert_eq!(rw(b"HTTP/1.1 200 OK\r\n\r\n", false), None);
        assert_eq!(rw(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", false), None);
    }

    #[test]
    fn what_is_rewritten() {
        assert_eq!(rw(b"HTTP/1.1 200\r\nX-A:v \r\n\r\n", false).unwrap(), b"HTTP/1.1 200 OK\r\nX-A: v\r\n\r\n");
        assert_eq!(rw(b"HTTP/1.1 200 OK\nX-A: a\n\tb\n\n", false).unwrap(), b"HTTP/1.1 200 OK\r\nX-A: a \tb\r\n\r\n");
        assert_eq!(
            rw(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n", false).unwrap(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        );
        assert_eq!(rw(b"HTTP/1.1 200 OK\r\nX-A:\r\n\r\n", false).unwrap(), b"HTTP/1.1 200 OK\r\nX-A: \r\n\r\n");
    }

    #[test]
    fn what_the_option_relaxes() {
        for head in [
            &b"HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n"[..],
            b"HTTP/1.1 200 OK\r\nX-A: a\0b\r\n\r\n",
            b"FOO/1.1 200 OK\r\n\r\n",
            b"HTTP/1.1 2000 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding:\r\n\r\n",
        ] {
            assert_eq!(check_response_head(head, false), ResponseHead::Invalid, "{}", head.escape_ascii());
            assert!(matches!(check_response_head(head, true), ResponseHead::Valid { .. }), "{}", head.escape_ascii());
        }
        for head in [
            &b"HTTP/1.1 200 OK\r\nX-A: a\rb\r\n\r\n"[..],
            b"HTTP/1.1 200 OK\r\nNoColon\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n: v\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            b"HTTP/1.x 200 OK\r\n\r\n",
            b"HTTP/1.1 2x0 OK\r\n\r\n",
            b"HTTP/1.1\r\n\r\n",
            b"HTTP/1.1 99999 OK\r\n\r\n",
        ] {
            assert_eq!(check_response_head(head, true), ResponseHead::Invalid, "{}", head.escape_ascii());
        }
    }

    /// The allocation-free path answers only when the full pass agrees, and leaves every
    /// head the full pass writes again (or refuses) to it.
    #[test]
    fn the_fast_path_agrees_with_the_full_pass() {
        let heads: &[&[u8]] = &[
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-A: b c\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\n",
            b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: CHUNKED\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 100 Continue\r\n\r\n",
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 7\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 007\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 7,7\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nContent-Length: 7\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: x\r\n\r\n",
            b"\r\nHTTP/1.1 200 OK\r\n\r\n",
            b"HTTP/1.1  200 OK\r\n\r\n",
            b"HTTP/1.1 200\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-A: v\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-A: v\r\n\n",
            b"HTTP/1.1 200 OK\r\nX-A:v\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-A: a\r\n b\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked,\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: , chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n",
            b"FOO/1.1 200 OK\r\n\r\n",
            b"HTTP/1.1 2000 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-A: a\0b\r\n\r\n",
        ];
        for &head in heads {
            for accept in [false, true] {
                if let Some(fast) = fast_check(head, accept) {
                    assert_eq!(fast, full_check(head, accept), "{} accept={accept}", head.escape_ascii());
                    assert!(matches!(fast, ResponseHead::Valid { rewrite: None, .. }));
                } else {
                    assert!(
                        !matches!(full_check(head, accept), ResponseHead::Valid { rewrite: None, .. }),
                        "the fast path gave up on a head left as it came: {} accept={accept}",
                        head.escape_ascii()
                    );
                }
            }
        }
    }
}
