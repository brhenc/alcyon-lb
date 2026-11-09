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
// `Valid` carries the index on the stack (E2): a box would be an allocation a response.
#[allow(clippy::large_enum_variant)]
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
        /// The head as parsed, for the readings after this one (E2): only for a head left
        /// as it came (`rewrite` is `None`), all ASCII, of at most [`RSP_FIELDS`] fields.
        index: Option<RspHead>,
    },
}

/// The most fields a [`RspHead`] indexes: a head with more is read the long way.
pub const RSP_FIELDS: usize = 32;

/// One field of a [`RspHead`]: the line `name: value\r\n` at `at..end` of the head, the
/// colon at `colon`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RspField {
    pub at: u32,
    pub colon: u32,
    pub end: u32,
}

impl RspField {
    /// The name as it is in `head` (the head the field was indexed in).
    #[must_use]
    pub fn name<'a>(&self, head: &'a [u8]) -> &'a [u8] {
        &head[self.at as usize..self.colon as usize]
    }

    /// The value: the line is `name: value\r\n`, nothing to trim.
    #[must_use]
    pub fn value<'a>(&self, head: &'a [u8]) -> &'a [u8] {
        &head[self.colon as usize + 2..self.end as usize - 2]
    }
}

/// A response head parsed once (E2, `docs/design/quic-transport-2026-11-01.md` section 3):
/// what the proxy reads of it after [`check_response_head`] (the status, the version, the
/// field lines) without walking its bytes again. A head the index holds is canonical: a
/// `version SP code SP reason CRLF` start line and `name: value CRLF` lines, ASCII. The
/// offsets are of the head it was made from; an edit of the head keeps them only through
/// [`RspHead::cut_line`] and [`RspHead::add_line`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RspHead {
    /// The status code.
    pub status: u16,
    /// `H1_MF_VER_11` ([`is_http11`] of the start line).
    pub http11: bool,
    /// A field is named `Upgrade`: the websocket reading has something to read.
    pub upgrade: bool,
    /// The start line, its CRLF included.
    pub start: u32,
    /// The head, its blank line included.
    pub len: u32,
    n: u8,
    fields: [RspField; RSP_FIELDS],
}

impl RspHead {
    fn new() -> Self {
        Self { status: 0, http11: false, upgrade: false, start: 0, len: 0, n: 0, fields: [RspField::default(); RSP_FIELDS] }
    }

    /// The index of a head the h2 server codec writes as it writes it (X3b-2): `HTTP/1.1`,
    /// `status`, a start line of `start` bytes; the fields follow ([`Self::push_written`]),
    /// then [`Self::len`].
    pub(crate) fn written(status: u16, start: u32) -> Self {
        Self { status, http11: true, start, ..Self::new() }
    }

    /// A canonical field line `name: value\r\n` written at `at..end`, its colon at `colon`.
    /// False when the index is full ([`RSP_FIELDS`]): the head is then not indexed.
    pub(crate) fn push_written(&mut self, at: u32, colon: u32, end: u32) -> bool {
        let n = usize::from(self.n);
        if n == RSP_FIELDS {
            return false;
        }
        self.fields[n] = RspField { at, colon, end };
        self.n += 1;
        true
    }

    /// The field lines, in order.
    #[must_use]
    pub fn fields(&self) -> &[RspField] {
        &self.fields[..usize::from(self.n)]
    }

    /// The line at `at..next` was cut from the head. One that is no field line of it leaves
    /// an index of no head: its length is no head's ([`Self::len`] `u32::MAX`), which a
    /// reader checks against the head before it reads the index.
    pub fn cut_line(&mut self, at: usize, next: usize) {
        let n = usize::from(self.n);
        let found = (self.len != u32::MAX).then(|| self.fields[..n].iter().position(|f| f.at as usize == at && f.end as usize == next)).flatten();
        let Some(i) = found else {
            self.len = u32::MAX;
            return;
        };
        let gone = u32::try_from(next - at).unwrap_or(u32::MAX);
        self.fields.copy_within(i + 1..n, i);
        self.n -= 1;
        for f in &mut self.fields[i..n - 1] {
            f.at -= gone;
            f.colon -= gone;
            f.end -= gone;
        }
        self.len -= gone;
    }

    /// A line `name: value\r\n` of `len` bytes, its colon `colon` bytes in, was put after
    /// the last field line. With no room for it, the index is of no head ([`Self::cut_line`]).
    pub fn add_line(&mut self, colon: usize, len: usize) {
        let n = usize::from(self.n);
        let (Ok(colon), Ok(len), true) = (u32::try_from(colon), u32::try_from(len), n < RSP_FIELDS && u32::try_from(len).ok().and_then(|l| self.len.checked_add(l)).is_some_and(|l| l != u32::MAX)) else {
            self.len = u32::MAX;
            return;
        };
        let at = self.len - 2;
        self.fields[n] = RspField { at, colon: at + colon, end: at + len };
        self.n += 1;
        self.len += len;
    }
}

/// An HTTP/1 response head (status line and fields, the blank line or not) as the h2 and
/// h3 muxes write it to their clients: the status (the second word of the first line), and
/// each line with a colon as its name and its value as octets (blanks trimmed), as `HAProxy`
/// sends a field whatever bytes it holds (E2: Alcyon read the head as lossy text, and a byte
/// that is not UTF-8 went as U+FFFD; T581: nothing of it is read as UTF-8). `None`: no status.
#[must_use]
pub fn mux_head_lines(head: &[u8]) -> Option<(u16, impl Iterator<Item = (&[u8], &[u8])>)> {
    count_head_scan();
    mux_head_lines_uncounted(head)
}

/// [`mux_head_lines`], not counted as a pass over the head (what a debug build checks an
/// index against).
#[must_use]
pub fn mux_head_lines_uncounted(head: &[u8]) -> Option<(u16, impl Iterator<Item = (&[u8], &[u8])>)> {
    let mut lines = head.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let code = lines.next()?.split(u8::is_ascii_whitespace).filter(|w| !w.is_empty()).nth(1)?;
    let status = status_of_word(code)?;
    Some((
        status,
        lines.filter_map(|l| {
            let colon = l.iter().position(|&b| b == b':')?;
            Some((l[..colon].trim_ascii(), l[colon + 1..].trim_ascii()))
        }),
    ))
}

/// `str::parse::<u16>` of a word, on its bytes: an optional `+`, then decimal digits that fit.
fn status_of_word(w: &[u8]) -> Option<u16> {
    let d = w.strip_prefix(b"+").unwrap_or(w);
    if d.is_empty() || !d.iter().all(u8::is_ascii_digit) {
        return None;
    }
    d.iter().try_fold(0u16, |n, &c| n.checked_mul(10)?.checked_add(u16::from(c - b'0')))
}

#[cfg(debug_assertions)]
thread_local! {
    static HEAD_SCANS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// A pass over the bytes of a response head was made (debug builds; nothing in release):
/// a test pins that a response head is walked once (E2).
#[inline]
pub fn count_head_scan() {
    #[cfg(debug_assertions)]
    HEAD_SCANS.with(|c| c.set(c.get() + 1));
}

/// The passes [`count_head_scan`] counted on this thread (0 in release builds).
#[must_use]
pub fn head_scans() -> u64 {
    #[cfg(debug_assertions)]
    return HEAD_SCANS.with(std::cell::Cell::get);
    #[cfg(not(debug_assertions))]
    0
}

#[cfg(debug_assertions)]
thread_local! {
    static PARSES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The response heads [`check_response_head_with`] parsed as HTTP/1 on this thread (debug
/// builds; 0 in release): a test pins that an h2 server's response head, which the codec
/// indexes as it writes it, is not parsed again (X3b-2).
#[must_use]
pub fn response_parses() -> u64 {
    #[cfg(debug_assertions)]
    return PARSES.with(std::cell::Cell::get);
    #[cfg(not(debug_assertions))]
    0
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
pub(crate) const fn is_token(c: u8) -> bool {
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
    /// The line starts here, the colon is at `colon`, the next line at `end`.
    at: usize,
    colon: usize,
    end: usize,
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

/// Header lines a response head may carry, as a request's
/// ([`crate::h1::MAX_REQUEST_HEADERS`], 100): 101 are a 502 logged `PH--` (T285).
const MAX_RESPONSE_HEADERS: usize = crate::h1::MAX_REQUEST_HEADERS as usize;

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
    let mut lines = 0;
    loop {
        match h.get(i) {
            Some(b'\r') if h.get(i + 1) == Some(&b'\n') => break,
            Some(b'\n') => {
                // The head ends with a bare LF: rewritten.
                canonical_start = false;
                break;
            }
            // A head with no blank line at its end runs out in the name loop below.
            _ => {}
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
        let colon = i;
        i += 1;
        let (value, canonical) = parse_value(h, &mut i, accept_unsafe)?;
        lines += usize::from(!crate::h1::uncounted(name, &value));
        if lines > MAX_RESPONSE_HEADERS {
            return None;
        }
        header(if bad_name { None } else { Some(Header { at: n0, colon, end: i, name, value, canonical }) });
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
fn fast_check(head: &[u8], accept_unsafe: bool, mut field: impl FnMut(usize, usize, usize)) -> Option<ResponseHead> {
    let (mut xfer_enc, mut te_chunked, mut chnk, mut te_other) = (false, false, false, false);
    let mut cl: Option<u64> = None;
    let (mut conn_upg, mut upg_ws, mut ws_accept) = (false, false, false);
    let (mut te_count, mut first_te_chunked) = (0usize, false);
    let mut give_up = false;
    let mut ix = RspHead::new();
    // Indexed only when the offsets fit and every byte is ASCII.
    let mut indexed = u32::try_from(head.len()).is_ok() && head.is_ascii();
    let p = parse(head, accept_unsafe, |h| {
        if give_up {
            return;
        }
        let Some(h) = h.filter(|h| h.canonical) else {
            give_up = true;
            return;
        };
        if indexed {
            let n = usize::from(ix.n);
            if n < RSP_FIELDS {
                field(h.at, h.colon, h.end);
                // In range: the head's length fits `u32`.
                #[allow(clippy::cast_possible_truncation)]
                let f = RspField { at: h.at as u32, colon: h.colon as u32, end: h.end as u32 };
                ix.fields[n] = f;
                ix.n += 1;
                ix.upgrade |= h.name.eq_ignore_ascii_case(b"upgrade");
            } else {
                indexed = false;
            }
        }
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
    let index = indexed.then(|| {
        ix.status = p.status;
        ix.http11 = http11;
        // A canonical start line ends with its CRLF at the first line feed.
        #[allow(clippy::cast_possible_truncation)]
        {
            ix.start = (p.reason.as_ptr() as usize - head.as_ptr() as usize + p.reason.len() + 2) as u32;
            ix.len = head.len() as u32;
        }
        ix
    });
    Some(ResponseHead::Valid { status: p.status, rewrite: None, close_server, index })
}

/// Parses a response head (the bytes up to and including the empty line that ends it).
#[must_use]
pub fn check_response_head(head: &[u8], accept_unsafe: bool) -> ResponseHead {
    check_response_head_with(head, accept_unsafe, |_, _, _| {})
}

/// [`check_response_head`], `field(at, colon, end)` called in its pass for each field line
/// of the index it makes, in order (X3: what the caller reads of the fields is read then,
/// not in a second walk). The calls stand only when the result has an index: a head that
/// is not indexed may have had some of its lines given before the check gave up on it.
pub fn check_response_head_with(head: &[u8], accept_unsafe: bool, field: impl FnMut(usize, usize, usize)) -> ResponseHead {
    count_head_scan();
    #[cfg(debug_assertions)]
    PARSES.with(|c| c.set(c.get() + 1));
    fast_check(head, accept_unsafe, field).unwrap_or_else(|| full_check(head, accept_unsafe))
}

/// [`check_response_head`], not counted (what a debug build checks an index the h2 server
/// codec made against, X3b-2).
#[must_use]
pub fn check_response_head_uncounted(head: &[u8], accept_unsafe: bool) -> ResponseHead {
    fast_check(head, accept_unsafe, |_, _, _| {}).unwrap_or_else(|| full_check(head, accept_unsafe))
}

/// `check_response_head` the long way, building the head written again when there is one.
#[cold]
#[inline(never)]
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
        return ResponseHead::Valid { status: p.status, rewrite: None, close_server, index: None };
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
    ResponseHead::Valid { status: p.status, rewrite: Some(rewrite), close_server, index: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(head: &[u8]) -> Option<RspHead> {
        match check_response_head(head, false) {
            ResponseHead::Valid { index, .. } => index,
            ResponseHead::Invalid => None,
        }
    }

    /// E2: a head left as it came is indexed (status, version, its field lines), and the
    /// index follows a line cut out of it and one put in before the blank line. A head that
    /// is written again, is not ASCII, or has more fields than the index holds, is not.
    #[test]
    fn a_head_left_as_it_came_is_indexed() {
        let head = b"HTTP/1.1 200 OK\r\nX-A: a\r\nConnection: keep-alive\r\nContent-Length: 2\r\nX-E: \r\n\r\n";
        let mut ix = index(head).expect("indexed");
        assert_eq!((ix.status, ix.http11, ix.upgrade, ix.start, ix.len as usize), (200, true, false, 17, head.len()));
        let fields = |ix: &RspHead, h: &[u8]| ix.fields().iter().map(|f| (f.name(h).to_vec(), f.value(h).to_vec())).collect::<Vec<_>>();
        assert_eq!(
            fields(&ix, head),
            [(&b"X-A"[..], &b"a"[..]), (b"Connection", b"keep-alive"), (b"Content-Length", b"2"), (b"X-E", b"")].map(|(n, v)| (n.to_vec(), v.to_vec()))
        );
        let c = ix.fields()[1];
        let mut cut = head[..c.at as usize].to_vec();
        cut.extend_from_slice(&head[c.end as usize..]);
        let mut missed = ix;
        missed.cut_line(c.at as usize, c.end as usize + 1);
        assert_eq!(missed.len, u32::MAX, "a line the index does not hold leaves it of no head");
        ix.cut_line(c.at as usize, c.end as usize);
        let line = b"connection: close\r\n";
        let mut added = cut[..cut.len() - 2].to_vec();
        added.extend_from_slice(line);
        added.extend_from_slice(b"\r\n");
        ix.add_line(10, line.len());
        assert_eq!(ix.len as usize, added.len());
        assert_eq!(fields(&ix, &added), fields(&index(&added).expect("indexed"), &added));
        assert!(index(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n").expect("indexed").upgrade);
        assert_eq!(index(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n").map(|ix| ix.http11), Some(false));
        for head in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 02\r\n\r\n"[..],
            b"HTTP/1.1 200 OK\r\nX-A: caf\xc3\xa9\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-A: a\xffb\r\n\r\n",
        ] {
            assert_eq!(index(head), None, "{}", head.escape_ascii());
        }
        let mut many = b"HTTP/1.1 200 OK\r\n".to_vec();
        for i in 0..=RSP_FIELDS {
            many.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        many.extend_from_slice(b"\r\n");
        assert_eq!(index(&many), None);
        let mut full = RspHead::new();
        full.n = u8::try_from(RSP_FIELDS).unwrap();
        full.len = 4;
        full.add_line(10, 19);
        assert_eq!(full.len, u32::MAX, "no room: of no head");
        assert_eq!(index(b"garbage\r\n\r\n"), None);
    }

    fn valid(head: &[u8], accept: bool) -> Option<Option<Vec<u8>>> {
        match check_response_head(head, accept) {
            ResponseHead::Valid { rewrite, .. } => Some(rewrite.map(|r| r.head)),
            ResponseHead::Invalid => None,
        }
    }

    fn rw(head: &[u8], accept: bool) -> Option<Vec<u8>> {
        valid(head, accept).expect("refused")
    }

    /// Measured on HAProxy 3.5-dev8, with and without `option accept-unsafe-violations-in-http-
    /// response`: empty lines (LF alone too) ahead of the status line are skipped (200); a lone CR,
    /// a blank, no status, or nothing but a status line is a 502.
    #[test]
    fn the_start_of_the_head() {
        for accept in [false, true] {
            assert_eq!(
                rw(b"\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", accept).unwrap(),
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            );
            for head in [
                &b"\rHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..],
                b" HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                b"HTTP/1.1 OK\r\nContent-Length: 0\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n",
            ] {
                assert_eq!(valid(head, accept), None, "{} accept={accept}", head.escape_ascii());
                assert!(fast_check(head, accept, |_, _, _| {}).is_none_or(|r| r == ResponseHead::Invalid));
            }
        }
    }

    /// `http_find_hdr_value_end`: a comma inside a quoted string, an escaped quote included, does
    /// not end a `Transfer-Encoding` word (one word, so no empty one between two commas). HAProxy
    /// answers 502 to any coding but `chunked` in a response, so the wire cannot tell: this is
    /// held to the function.
    #[test]
    fn a_quoted_comma_does_not_end_a_coding() {
        let run = |v: &[u8]| {
            let (mut xfer, mut te, mut chnk, mut other) = (false, false, false, false);
            let r = parse_te(v, &mut xfer, &mut te, &mut chnk, &mut other);
            (r, other)
        };
        assert_eq!(run(b"\"x,,y\""), (Ok(()), true));
        assert_eq!(run(b"\"x\\\",,y\""), (Ok(()), true));
        assert_eq!(run(b"x,,y"), (Err(()), true));
        assert_eq!(value_end(b"a\\,b", 0), 2, "a backslash outside quotes escapes nothing");
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
                if let Some(mut fast) = fast_check(head, accept, |_, _, _| {}) {
                    if let ResponseHead::Valid { index, .. } = &mut fast {
                        *index = None;
                    }
                    assert_eq!(fast, full_check(head, accept), "{} accept={accept}", head.escape_ascii());
                    assert!(matches!(fast, ResponseHead::Valid { rewrite: None, .. }));
                } else {
                    let left_as_it_came = matches!(full_check(head, accept), ResponseHead::Valid { rewrite: None, .. });
                    assert!(!left_as_it_came, "the fast path gave up on a head left as it came: {} accept={accept}", head.escape_ascii());
                }
            }
        }
    }
}
