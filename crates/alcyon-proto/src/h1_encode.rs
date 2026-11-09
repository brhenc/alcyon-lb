// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The HTTP/1 encoder of a message head (X5, `docs/design/htx-engine-2026-11-01.md` §2.3):
//! the port of `h1_make_reqline`, `h1_make_stline`, `h1_make_headers` and `h1_make_eoh`
//! (src/mux_h1.c) over an HTX, the copying one or X1's in-place one (names as they were
//! received, a value read through its descriptor's `aux` gap).
//!
//! The encoder owns the framing: `transfer-encoding` once and only as `chunked`, and only
//! when the message is; `content-length` once; `connection` written from the stream's mode,
//! its `keep-alive`/`close` tokens the encoder's own (`H1_MF_CLEAN_CONN_HDR`); `upgrade`
//! without `h2c`/`h2`; `te` reduced to `trailers`; and at the end of the head the
//! `content-length: 0` of a request whose length a rule removed, the `transfer-encoding:
//! chunked` of a message without a length, the `connection` token and the websocket key.
//!
//! Header names: as stored (the received case, D-E) unless `lowercase`
//! (`tune.alcyon.h1-lowercase-headers on`, HAProxy's HTX names), then the `h1-case-adjust`
//! map on top of either (`h1_format_htx_hdr`, h1_htx.c). The encoder allocates nothing and
//! walks the blocks once.

use std::collections::HashMap;
use std::ops::{BitOr, BitOrAssign};

use crate::htx::{write_latin1, HtxBlockType, HtxError, HtxSliceRef, HTX_BLK_FL_LATIN1};

/// The message the head is: a request (to a server) or a response (to a client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1Dir {
    Request,
    Response,
}

/// The connection mode of the stream (`H1S_F_WANT_KAL`/`_CLO`/`_TUN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnMode {
    KeepAlive,
    Close,
    Tunnel,
}

/// The request's method as the encoder needs it (`h1s->meth`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1Method {
    Head,
    Connect,
    Other,
}

impl H1Method {
    #[must_use]
    pub fn of(method: &[u8]) -> Self {
        match method {
            b"HEAD" => Self::Head,
            b"CONNECT" => Self::Connect,
            _ => Self::Other,
        }
    }
}

/// The start-line flags of the message (`HTX_SL_F_*`, include/haproxy/htx-t.h:128-144) the
/// encoder reads: what the parse found of its framing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SlFlags(u16);

impl SlFlags {
    pub const NONE: Self = Self(0);
    /// The size of the payload is known (a length, chunked, or none to come).
    pub const XFER_LEN: Self = Self(0x0002);
    /// A `transfer-encoding` was received.
    pub const XFER_ENC: Self = Self(0x0004);
    /// A `content-length` was received.
    pub const CLEN: Self = Self(0x0008);
    /// The payload is chunked.
    pub const CHNK: Self = Self(0x0010);
    /// No body (a length of 0, or a request with neither header).
    pub const BODYLESS: Self = Self(0x0040);
    /// The response to this request has no body (only for a request).
    pub const BODYLESS_RESP: Self = Self(0x2000);

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for SlFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for SlFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// How the stream stands when the head is written, and how to write the names.
#[derive(Debug, Clone, Copy)]
pub struct H1EncodeOpts<'a> {
    pub dir: H1Dir,
    /// The stream's mode before this message: for a request to a server, keep-alive unless
    /// the server side is already closing; for a response, what the client's request decided
    /// (`h1_set_cli_conn_mode`'s first pass: an HTTP/1.0 request without `keep-alive`, a
    /// `close` token, a request with both a length and `transfer-encoding`).
    pub want: ConnMode,
    /// Request: `option http-server-close` on the frontend or the backend, or `option
    /// httpclose` on the backend (`PR_O_HTTP_SCL`/`PR_O_HTTP_CLO`). Response: `option
    /// httpclose` on the frontend.
    pub http_close: bool,
    /// Request: `option http-pretend-keepalive` (`PR_O2_FAKE_KA`).
    pub pretend_keepalive: bool,
    /// The proxy is stopping: a keep-alive stream closes.
    pub stopping: bool,
    pub sl: SlFlags,
    /// The head is the whole message (`HTX_BLK_FL_EOM` on the EOH block).
    pub eom: bool,
    /// Response: the request was HTTP/1.1 or later.
    pub req_ver_11: bool,
    /// Response: the request's method (a request reads its own line).
    pub req_meth: H1Method,
    /// `tune.alcyon.h1-lowercase-headers on`: every name in lower case, as HAProxy.
    pub lowercase: bool,
    /// The `h1-case-adjust` map, for a proxy with `option h1-case-adjust-bogus-client`
    /// (response) or `-server` (request): lower-case name to the name to write.
    pub case_map: Option<&'a HashMap<String, String>>,
    /// The websocket key to add to a handshake that has none (request: a fresh
    /// `sec-websocket-key`; response: the `sec-websocket-accept` of the request's key).
    pub ws_key: Option<&'a [u8]>,
}

impl H1EncodeOpts<'_> {
    /// A head as it stands with nothing decided yet: keep-alive, no option.
    #[must_use]
    pub fn new(dir: H1Dir, sl: SlFlags, lowercase: bool) -> Self {
        Self {
            dir,
            want: ConnMode::KeepAlive,
            http_close: false,
            pretend_keepalive: false,
            stopping: false,
            sl,
            eom: false,
            req_ver_11: true,
            req_meth: H1Method::Other,
            lowercase,
            case_map: None,
            ws_key: None,
        }
    }
}

/// What the encoder wrote, and what it decided of the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H1Encoded {
    /// The bytes of `out` written: the head, and the last chunk of an empty chunked message.
    pub len: usize,
    /// The stream's mode after the head (`h1_process_output_conn_mode`).
    pub want: ConnMode,
    /// The body goes chunked.
    pub chunked: bool,
    /// The length the head announces, when it does.
    pub body_len: Option<u64>,
    /// A request whose length was removed: `content-length: 0` written and no body to send.
    pub bodyless_req: bool,
}

// `h1m->flags` (include/haproxy/h1.h) the encoder keeps.
const M_RESP: u32 = 1 << 0;
const M_VER_11: u32 = 1 << 1;
const M_XFER_LEN: u32 = 1 << 2;
const M_CLEN: u32 = 1 << 3;
const M_CHNK: u32 = 1 << 4;
const M_XFER_ENC: u32 = 1 << 5;
const M_CONN_KAL: u32 = 1 << 6;
const M_CONN_CLO: u32 = 1 << 7;
const M_CONN_UPG: u32 = 1 << 8;
const M_UPG_WEBSOCKET: u32 = 1 << 9;
// `h1s->flags`.
const S_HAVE_CLEN: u32 = 1 << 0;
const S_HAVE_CHNK: u32 = 1 << 1;
const S_HAVE_O_CONN: u32 = 1 << 2;
const S_HAVE_WS_KEY: u32 = 1 << 3;
const S_BODYLESS_RESP: u32 = 1 << 4;
const S_BODYLESS_REQ: u32 = 1 << 5;
/// The flags `h1_make_eoh` reads to tell a message that goes chunked.
const MASK: u32 = M_VER_11 | M_RESP | M_CLEN | M_CHNK | M_XFER_LEN;

/// `HTTP_IS_LWS`.
const fn is_lws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

/// `http_find_hdr_value_end`: the next comma of `v` from `at` outside a quoted string.
fn value_end(v: &[u8], mut at: usize) -> usize {
    let (mut quoted, mut qdpair) = (false, false);
    while at < v.len() {
        let c = v[at];
        if qdpair {
            qdpair = false;
        } else if quoted {
            if c == b'\\' {
                qdpair = true;
            } else if c == b'"' {
                quoted = false;
            }
        } else if c == b'"' {
            quoted = true;
        } else if c == b',' {
            return at;
        }
        at += 1;
    }
    at
}

/// `http_parse_cont_len_header`: the canonical value's range in `v` and the length, `None`
/// for a value that is not a list of the same number (or not `prev` when `prev` is set).
fn parse_content_length(v: &[u8], prev: Option<u64>) -> Option<(std::ops::Range<usize>, u64)> {
    let (mut at, e) = (0, v.len());
    let mut check = prev;
    loop {
        if at >= e {
            return None;
        }
        if is_lws(v[at]) {
            at += 1;
            continue;
        }
        let mut start = at;
        let mut cl: u64 = 0;
        let mut n = at;
        while n < e && v[n].is_ascii_digit() {
            if cl == 0 && n > start {
                start = n;
            }
            cl = cl.checked_mul(10)?.checked_add(u64::from(v[n] - b'0'))?;
            n += 1;
        }
        if n == at {
            return None;
        }
        let word = start..n;
        while n < e && is_lws(v[n]) {
            n += 1;
        }
        if n < e && v[n] != b',' {
            return None;
        }
        if check.is_some_and(|p| p != cl) {
            return None;
        }
        if n == e {
            return Some((word, cl));
        }
        at = n + 1;
        check = Some(cl);
    }
}

/// The output cursor.
struct Out<'o> {
    out: &'o mut [u8],
    at: usize,
}

impl Out<'_> {
    #[inline]
    fn put(&mut self, b: &[u8]) -> Result<(), HtxError> {
        let end = self.at + b.len();
        self.out.get_mut(self.at..end).ok_or(HtxError::BufferTooSmall)?.copy_from_slice(b);
        self.at = end;
        Ok(())
    }

    /// A name, in the case the options say (`h1_format_htx_hdr`'s map on top).
    #[inline]
    fn name(&mut self, n: &[u8], o: &H1EncodeOpts<'_>) -> Result<(), HtxError> {
        let start = self.at;
        self.put(n)?;
        if o.lowercase || o.case_map.is_some() {
            let w = &mut self.out[start..self.at];
            w.make_ascii_lowercase();
            match o.case_map.and_then(|m| std::str::from_utf8(w).ok().and_then(|k| m.get(k))) {
                // `h1-case-adjust` differs from the name in case only (the parser checks it).
                Some(to) if to.len() == w.len() => w.copy_from_slice(to.as_bytes()),
                _ if !o.lowercase => w.copy_from_slice(n),
                _ => {}
            }
        }
        Ok(())
    }

    /// A header line the encoder adds.
    fn line(&mut self, n: &[u8], v: &[u8], o: &H1EncodeOpts<'_>) -> Result<(), HtxError> {
        self.name(n, o)?;
        self.put(b": ")?;
        self.put(v)?;
        self.put(b"\r\n")
    }

    /// The elements of the list `v` that `keep` keeps, rewritten as `h1_parse_connection_header`
    /// and `h1_parse_upgrade_header` (with `H1_MF_CLEAN_CONN_HDR`) rewrite it: as they came
    /// while nothing was dropped, then joined by `,`. The bytes written.
    fn list(&mut self, v: &[u8], mut keep: impl FnMut(&[u8]) -> bool) -> Result<usize, HtxError> {
        let start = self.at;
        let (mut len, mut p, mut i) = (0, 0, 0);
        while i < v.len() {
            if is_lws(v[i]) {
                i += 1;
                continue;
            }
            let n = value_end(v, i);
            let mut we = n;
            while we > i && is_lws(v[we - 1]) {
                we -= 1;
            }
            let word = &v[i..we];
            if keep(word) {
                if len == p {
                    self.put(&v[p..n])?;
                    len = n;
                } else {
                    if len > 0 {
                        self.put(b",")?;
                        len += 1;
                    }
                    self.put(word)?;
                    len += word.len();
                }
            }
            p = n;
            i = n + 1;
        }
        Ok(self.at - start)
    }
}

/// The version as the line writes it (`h1_format_htx_reqline`/`_stline`: from 1.1 up,
/// `HTTP/1.1`), and whether it is 1.1 or later (`h1_parse_req_vsn`). Alcyon's HTX of an
/// HTTP/2 or HTTP/3 request says `HTTP/2`/`HTTP/3` where HAProxy's says `HTTP/2.0`.
fn version(v: &[u8]) -> (&[u8], bool) {
    if crate::h1::version_is_11(v) || v == b"HTTP/2" || v == b"HTTP/3" {
        (b"HTTP/1.1", true)
    } else {
        (v, false)
    }
}

#[cfg(debug_assertions)]
thread_local! {
    static HEAD_WRITES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Message heads written out of an HTX as HTTP/1 text on this thread, by [`h1_encode_head`] or
/// [`HtxSliceRef::write_h1_wire`] (debug builds; 0 in release): X4 pins that an HTTP/2 or
/// HTTP/3 request head is written once, at the server send.
#[must_use]
pub fn head_writes() -> u64 {
    #[cfg(debug_assertions)]
    return HEAD_WRITES.with(std::cell::Cell::get);
    #[cfg(not(debug_assertions))]
    0
}

/// Counts one [`head_writes`].
#[inline]
pub(crate) fn note_head_write() {
    #[cfg(debug_assertions)]
    HEAD_WRITES.with(|c| c.set(c.get() + 1));
}

/// The head of `htx` as HTTP/1.1 into `out` (`h1_make_reqline`/`h1_make_stline`,
/// `h1_make_headers`, `h1_make_eoh`): its start line, its headers up to the EOH block in
/// order, the framing and `connection` headers the stream needs, the blank line, and for a
/// chunked message that is all in its head, the last chunk.
///
/// # Errors
/// [`HtxError::BufferTooSmall`] when `out` cannot hold the head (nothing is cut short: the
/// caller makes room and calls again); [`HtxError::InvalidData`] for an HTX that does not
/// start with the start line of `dir`, has no EOH, or holds an invalid `content-length`
/// (`h1_make_headers`' processing error).
#[allow(clippy::too_many_lines)]
pub fn h1_encode_head(htx: HtxSliceRef<'_>, o: &H1EncodeOpts<'_>, out: &mut [u8]) -> Result<H1Encoded, HtxError> {
    note_head_write();
    let buf = htx.buf();
    let mut w = Out { out, at: 0 };
    let mut m: u32 = 0;
    let mut s: u32 = 0;
    let mut want = o.want;
    let mut body_len: u64 = 0;
    let resp = o.dir == H1Dir::Response;
    let mut status: u16 = 0;
    let meth;
    let mut blocks = 0..htx.num_blocks();

    // The start line, the first block that is not a tombstone.
    let first = blocks.by_ref().map(|i| htx.read_desc(i)).find(|d| d.blk_type != HtxBlockType::Unused).ok_or(HtxError::InvalidData)?;
    if resp {
        if first.blk_type != HtxBlockType::ResLine {
            return Err(HtxError::InvalidData);
        }
        let raw = &buf[first.addr as usize..first.addr as usize + first.value_len as usize];
        let sp1 = memchr::memchr(b' ', raw).ok_or(HtxError::InvalidData)?;
        let rest = &raw[sp1 + 1..];
        let (code, reason) = match memchr::memchr(b' ', rest) {
            Some(sp2) => (&rest[..sp2], rest[sp2 + 1..].trim_ascii()),
            None => (rest, &b""[..]),
        };
        status = first.name_len;
        let (v, v11) = version(&raw[..sp1]);
        w.put(v)?;
        w.put(b" ")?;
        w.put(code)?;
        w.put(b" ")?;
        w.put(if reason.is_empty() { crate::actions::status_reason_phrase(status).as_bytes() } else { reason })?;
        w.put(b"\r\n")?;
        meth = o.req_meth;
        m |= M_RESP | if v11 { M_VER_11 } else { 0 };
        if o.sl.contains(SlFlags::XFER_LEN) {
            m |= M_XFER_LEN;
            if o.sl.contains(SlFlags::CHNK) {
                m |= M_CHNK;
            } else if o.sl.contains(SlFlags::CLEN) {
                m |= M_CLEN;
            }
            if o.sl.contains(SlFlags::XFER_ENC) {
                m |= M_XFER_ENC;
            }
        }
        if status < 200 {
            s |= S_HAVE_O_CONN;
        } else if meth == H1Method::Head || status == 204 || status == 304 {
            s |= S_BODYLESS_RESP;
        }
    } else {
        if first.blk_type != HtxBlockType::ReqLine {
            return Err(HtxError::InvalidData);
        }
        let line = htx.req_line_bytes().ok_or(HtxError::InvalidData)?;
        let (v, v11) = version(line.version);
        w.put(line.method)?;
        w.put(b" ")?;
        w.put(line.uri)?;
        w.put(b" ")?;
        w.put(v)?;
        w.put(b"\r\n")?;
        meth = H1Method::of(line.method);
        m |= M_XFER_LEN | if v11 { M_VER_11 } else { 0 };
        if o.sl.contains(SlFlags::CHNK) {
            m |= M_CHNK;
        } else if o.sl.contains(SlFlags::CLEN) {
            m |= M_CLEN;
        }
        if o.sl.contains(SlFlags::XFER_ENC) {
            m |= M_XFER_ENC;
        }
        if o.sl.contains(SlFlags::BODYLESS) && m & M_CLEN == 0 {
            m = (m & !M_CHNK) | M_CLEN;
            s |= S_HAVE_CLEN;
        }
    }
    let bodyless_status = resp && (status < 200 || status == 204);

    // `h1_make_headers`: each header up to the EOH block.
    let mut eoh = None;
    for i in blocks {
        let d = htx.read_desc(i);
        match d.blk_type {
            HtxBlockType::Header => {}
            HtxBlockType::Eoh => {
                eoh = Some(d);
                break;
            }
            HtxBlockType::Unused => continue,
            _ => return Err(HtxError::InvalidData),
        }
        let n = &buf[d.name_range()];
        let mut v = &buf[d.value_range()];
        if n.first() == Some(&b':') {
            continue;
        }
        let mut have = 0;
        let line_start = w.at;
        // The framing names, told apart by their length first (no compare for the others).
        match n.len() {
            17 if n.eq_ignore_ascii_case(b"transfer-encoding") => {
                if bodyless_status || m & M_CHNK == 0 || s & S_HAVE_CHNK != 0 {
                    continue;
                }
                v = b"chunked";
                have = S_HAVE_CHNK;
            }
            14 if n.eq_ignore_ascii_case(b"content-length") => {
                let prev = (s & S_HAVE_CLEN != 0).then_some(body_len);
                let (word, len) = parse_content_length(v, prev).ok_or(HtxError::InvalidData)?;
                if len == 0 && bodyless_status {
                    m |= M_CLEN;
                }
                if m & M_CLEN == 0 || s & S_HAVE_CLEN != 0 {
                    continue;
                }
                v = &v[word];
                body_len = len;
                have = S_HAVE_CLEN;
            }
            10 if n.eq_ignore_ascii_case(b"connection") => {
                w.name(n, o)?;
                w.put(b": ")?;
                let kept = w.list(v, |word| {
                    if word.eq_ignore_ascii_case(b"keep-alive") {
                        m |= M_CONN_KAL;
                        return false;
                    }
                    if word.eq_ignore_ascii_case(b"close") {
                        m |= M_CONN_CLO;
                        return false;
                    }
                    if word.eq_ignore_ascii_case(b"upgrade") {
                        m |= M_CONN_UPG;
                    }
                    true
                })?;
                if kept == 0 {
                    w.at = line_start;
                } else {
                    w.put(b"\r\n")?;
                }
                continue;
            }
            7 if n.eq_ignore_ascii_case(b"upgrade") => {
                w.name(n, o)?;
                w.put(b": ")?;
                let kept = w.list(v, |word| {
                    if word.eq_ignore_ascii_case(b"websocket") {
                        m |= M_UPG_WEBSOCKET;
                    }
                    !(word.eq_ignore_ascii_case(b"h2c") || word.eq_ignore_ascii_case(b"h2"))
                })?;
                if kept == 0 {
                    w.at = line_start;
                } else {
                    w.put(b"\r\n")?;
                }
                continue;
            }
            20 if resp && n.eq_ignore_ascii_case(b"sec-websocket-accept") => s |= S_HAVE_WS_KEY,
            17 if !resp && n.eq_ignore_ascii_case(b"sec-websocket-key") => s |= S_HAVE_WS_KEY,
            2 if n.eq_ignore_ascii_case(b"te") => {
                // `istist(v, "trailers")`, then nothing but a `,` may follow it.
                let at = memchr::memmem::find(v, b"trailers");
                if at.is_none_or(|a| v.len() - a > 8 && v[a + 8] != b',') {
                    continue;
                }
                v = b"trailers";
            }
            _ => {}
        }
        w.name(n, o)?;
        w.put(b": ")?;
        if d.flags & HTX_BLK_FL_LATIN1 != 0 && have == 0 {
            w.at = write_latin1(w.out, w.at, v)?;
        } else {
            w.put(v)?;
        }
        w.put(b"\r\n")?;
        s |= have;
    }
    let eoh = eoh.ok_or(HtxError::InvalidData)?;
    let eom = o.eom || eoh.flags & crate::htx::HTX_BLK_FL_EOM != 0;

    // `h1_make_eoh`: a length or `transfer-encoding` a rule removed.
    if (m & M_CLEN != 0 && s & S_HAVE_CLEN == 0) || (m & M_CHNK != 0 && s & S_HAVE_CHNK == 0) {
        // One of the two written: the length frames it. (HAProxy also has the other case, a
        // length removed beside a written `transfer-encoding`; the start line never has both
        // `CHNK` and `CLEN` here, `CHNK` wins at the line, so it cannot happen.)
        if s & S_HAVE_CLEN != 0 {
            m &= !(M_XFER_ENC | M_CHNK);
        } else if resp {
            m &= !(M_XFER_LEN | M_XFER_ENC | M_CLEN | M_CHNK);
            s &= !(S_HAVE_CLEN | S_HAVE_CHNK);
        } else {
            w.line(b"content-length", b"0", o)?;
            m = (m & !(M_XFER_ENC | M_CHNK)) | M_CLEN;
            s = (s & !S_HAVE_CHNK) | S_HAVE_CLEN | S_BODYLESS_REQ;
            body_len = 0;
        }
    }

    // `connection`, from the mode.
    if s & S_HAVE_O_CONN == 0 {
        if m & (M_XFER_ENC | M_CLEN) == (M_XFER_ENC | M_CLEN) {
            // T-E + C-L (`h1-do-not-close-on-insecure-transfer-encoding` is not ported).
            m &= !M_CLEN;
            want = ConnMode::Close;
        } else if m & (M_VER_11 | M_XFER_ENC) == M_XFER_ENC {
            want = ConnMode::Close;
        } else if m & M_CLEN != 0 && body_len != 0 && eom && (!resp || s & S_BODYLESS_RESP == 0) {
            want = ConnMode::Close;
        }
        let v = conn_value(o, m, &mut want, status, meth);
        if !v.is_empty() {
            w.line(b"connection", v, o)?;
        }
    }

    // `transfer-encoding: chunked` for a message without a length.
    let connect_ok = meth == H1Method::Connect && (200..300).contains(&status);
    if (meth != H1Method::Connect && !resp && m & MASK == M_VER_11 | M_XFER_LEN)
        || (resp && status >= 200 && s & S_BODYLESS_RESP == 0 && !connect_ok && m & MASK == M_VER_11 | M_RESP | M_XFER_LEN)
    {
        m |= M_CHNK;
    }
    if m & M_CHNK != 0 && s & S_HAVE_CHNK == 0 {
        w.line(b"transfer-encoding", b"chunked", o)?;
        s |= S_HAVE_CHNK;
    }

    // The websocket key of a handshake that has none.
    if s & S_HAVE_WS_KEY == 0 && m & (M_CONN_UPG | M_UPG_WEBSOCKET) == (M_CONN_UPG | M_UPG_WEBSOCKET) {
        if let Some(key) = o.ws_key {
            w.line(if resp { b"sec-websocket-accept" } else { b"sec-websocket-key" }, key, o)?;
        }
    }

    // The end of the head.
    if !resp && meth == H1Method::Connect {
        w.put(b"\r\n")?;
    } else if resp && (connect_ok || status == 101) {
        w.put(b"\r\n")?;
        want = ConnMode::Tunnel;
        m &= !(M_XFER_LEN | M_CLEN | M_CHNK);
    } else if resp && status < 200 && (status == 100 || status >= 102) {
        w.put(b"\r\n")?;
    } else if eom {
        let last_chunk = m & M_CHNK != 0 && (!resp || s & S_BODYLESS_RESP == 0);
        w.put(if last_chunk { b"\r\n0\r\n\r\n" } else { b"\r\n" })?;
    } else {
        w.put(b"\r\n")?;
    }

    Ok(H1Encoded {
        len: w.at,
        want,
        chunked: m & M_CHNK != 0,
        body_len: (m & M_CLEN != 0).then_some(body_len),
        bodyless_req: s & S_BODYLESS_REQ != 0,
    })
}

/// `h1_process_output_conn_mode`: the mode after this head (`h1_set_srv_conn_mode` for a
/// request, `h1_set_cli_conn_mode` for a response, their output pass) and the `connection`
/// token to write (`h1_update_req_conn_value`/`h1_update_res_conn_value`), empty for none.
fn conn_value(o: &H1EncodeOpts<'_>, m: u32, want: &mut ConnMode, status: u16, meth: H1Method) -> &'static [u8] {
    if o.dir == H1Dir::Response {
        if (meth == H1Method::Connect && (200..300).contains(&status)) || status == 101 {
            *want = ConnMode::Tunnel;
        } else if *want == ConnMode::KeepAlive && (m & M_XFER_LEN == 0 || m & M_CONN_CLO != 0 || (m & M_CONN_KAL == 0 && o.http_close)) {
            *want = ConnMode::Close;
        }
    } else if m & M_CONN_CLO != 0 || (m & M_CONN_KAL == 0 && o.http_close) {
        *want = ConnMode::Close;
    }
    if *want == ConnMode::KeepAlive && o.stopping {
        *want = ConnMode::Close;
    }
    if *want == ConnMode::Tunnel || m & M_CONN_UPG != 0 {
        return b"";
    }
    let v11 = m & M_VER_11 != 0;
    let kal = *want == ConnMode::KeepAlive || (o.dir == H1Dir::Request && o.pretend_keepalive);
    match (kal, o.dir) {
        (true, H1Dir::Request) if !v11 => b"keep-alive",
        (true, H1Dir::Response) if !v11 || !o.req_ver_11 => b"keep-alive",
        (false, _) if v11 => b"close",
        _ => b"",
    }
}
