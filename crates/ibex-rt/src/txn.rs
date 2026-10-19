// SPDX-License-Identifier: GPL-2.0-or-later
// The message states follow HAProxy's `enum h1_state` / `http_msg` (include/haproxy/
// http_ana-t.h) and RFC 9112 section 6.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! One HTTP transaction: where its request and its response are (design 010).
//!
//! The byte movers in [`crate::proxy`] forward only the bytes a [`MsgState`] says belong
//! to the message in flight. Bytes after the end of a request -- the next pipelined
//! request -- stay in the buffer until this transaction ends; a response is held until
//! the engine has processed its head. "Where is this transaction" is answered here, by
//! state, instead of being inferred from buffer occupancy and socket states.

use crate::proxy::find_eoh;

/// How a message body is delimited (RFC 9112 section 6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// No body: a request without `Content-Length` or `Transfer-Encoding`, a response to
    /// HEAD, a 1xx, 204 or 304.
    None,
    Length(u64),
    Chunked,
    /// A response with no length: it ends when the server closes.
    UntilClose,
    /// `101 Switching Protocols`, or a 2xx to CONNECT: no longer HTTP.
    Tunnel,
}

/// Where forwarding is within one message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgState {
    /// A response whose head has not arrived or not been processed yet: none of it may be
    /// forwarded. (A request is never in this state; its head is parsed before the
    /// transaction exists.)
    Waiting,
    /// The head is in the buffer, processed, and not yet forwarded in full. `left` is what
    /// remains of it, 0 until it is first measured; then the body, framed by `body`.
    Head { left: usize, body: Framing },
    Body(Body),
    Done,
    Tunnel,
    /// The body violated its own framing (a malformed chunk). Nothing more is forwarded,
    /// and the connection cannot be reused.
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body {
    Length(u64),
    Chunked(Chunk),
    UntilClose,
}

/// Position inside a chunked body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chunk {
    /// In the chunk size, `digits` hex digits of it read so far.
    Size { size: u64, digits: u8 },
    /// Blanks after the size.
    SizeWs { size: u64 },
    /// In a chunk extension, `len` bytes of it so far; inside a quoted string, and just
    /// after a backslash in one.
    Ext { size: u64, len: u16, quote: bool, escape: bool },
    SizeLf { size: u64 },
    Data(u64),
    DataCr,
    DataLf,
    /// At the start of a line of the trailer section, `fields` complete fields and `len`
    /// bytes of it so far.
    Trailer { len: u16, fields: u8 },
    /// In a trailer field's name, `pos` bytes of it; `forbidden` the names of
    /// [`FORBIDDEN_TRAILERS`] it may still be.
    TrailerName { len: u16, fields: u8, pos: u8, forbidden: u8 },
    TrailerValue { len: u16, fields: u8 },
    /// A CR ended a trailer field's value.
    TrailerValueLf { len: u16, fields: u8 },
    /// A CR began the blank line that ends the trailer section.
    TrailerEndLf,
}

const CHUNK_START: Chunk = Chunk::Size { size: 0, digits: 0 };

/// The longest chunk extension accepted (the trailer section has its own cap,
/// [`MAX_TRAILER_SECTION`]). `HAProxy` parses a chunk-size line only once it is all in the
/// buffer: with the default `tune.bufsize` (16384), a 16300-byte extension passes and a
/// 16330-byte one does not (3.5-dev8). Past that it relays nothing more of the message.
/// Without a cap, a server that sends an extension or trailers for ever had them relayed
/// for ever (893 MB in 6 s, T248).
const MAX_CHUNK_LINE: u16 = 16 * 1024;

/// The largest trailer section accepted, its fields with their line ends. `HAProxy` holds
/// the section in HTX with the blocks around it, whole: with the default `tune.bufsize`, a
/// field of 16315 bytes of value passes and one of 16320 does not, with the rest of the
/// message in the buffer or not (3.5-dev8, T281). The section of the first is 16322 bytes.
const MAX_TRAILER_SECTION: u16 = 16323;

/// The most trailer fields accepted: `tune.http.maxhdr` (101) less one, as for a head.
/// `HAProxy` 3.5-dev8 relays 100 and answers 502 to 101.
const MAX_TRAILER_FIELDS: u8 = 100;

/// The fields that frame or route a message, which `HAProxy` refuses in a trailer section
/// (`http_trailers_to_htx`, src/http_htx.c). At most 8, one bit each.
const FORBIDDEN_TRAILERS: [&[u8]; 8] =
    [b"host", b"content-length", b"connection", b"proxy-connection", b"keep-alive", b"upgrade", b"te", b"transfer-encoding"];

/// A chunk size of 2^52 or more: `HAProxy`'s `h1_parse_chunk_size` refuses it, so that a
/// peer reading sizes as floating-point numbers is never fed one it rounds.
const CHUNK_SIZE_LIMIT: u64 = 1 << 52;

/// A token character (RFC 9110 section 5.6.2), as a field name is made of.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

impl Chunk {
    /// Whether forwarding may stop here: the start of a chunk-size line, or inside chunk
    /// data. A chunk-size line is forwarded only once it is complete, and the last-chunk
    /// line only with the whole trailer section after it, as `HAProxy` parses each only once
    /// it is all in its buffer: a trailer section it refuses, or that does not fit, relays
    /// none of it (T281, review r2#9: Ibex relayed the last-chunk line and up to 100 fields).
    fn at_boundary(self) -> bool {
        matches!(self, Chunk::Size { digits: 0, .. } | Chunk::Data(_) | Chunk::DataCr)
    }

    /// A chunk extension, or a trailer section, as long as it may be: one more byte of it
    /// is refused.
    fn over_cap(self) -> bool {
        match self {
            Chunk::Ext { len, .. } => len >= MAX_CHUNK_LINE,
            Chunk::Trailer { len, .. }
            | Chunk::TrailerName { len, .. }
            | Chunk::TrailerValue { len, .. }
            | Chunk::TrailerValueLf { len, .. } => len >= MAX_TRAILER_SECTION,
            _ => false,
        }
    }

    /// In the trailer section, after the last-chunk line.
    fn in_trailer(self) -> bool {
        matches!(
            self,
            Chunk::Trailer { .. } | Chunk::TrailerName { .. } | Chunk::TrailerValue { .. } | Chunk::TrailerValueLf { .. } | Chunk::TrailerEndLf
        )
    }

    /// Scans `data`; returns how many bytes belong to the body and the state after them:
    /// `Ok(Some(_))` wants more, `Ok(None)` is the end of the message, `Err` is a framing
    /// violation (the bytes counted are the valid ones before it).
    ///
    /// With `whole_lines`, the bytes counted stop at the last line boundary
    /// ([`Self::at_boundary`]) and the state is the one there: the rest is scanned again
    /// when more has arrived. A violation counts only up to the boundary before it.
    ///
    /// The syntax is `HAProxy`'s (`h1_parse_chunk_size`, and the header parser for the
    /// trailer section): the size 1 or more hex digits, below 2^52, then blanks, then an
    /// extension of non-control characters with balanced quotes, ended by CRLF; data then
    /// CRLF; trailer fields with a token name, a colon and no NUL or lone CR in the value,
    /// none of [`FORBIDDEN_TRAILERS`], each line ended by CRLF or LF (tasks/T276, V&V VV-2).
    ///
    /// `pay` gains what `HAProxy` counts of the body in its HTX message: the data bytes, and
    /// one more for the end of the message (`HTX_BLK_EOT`).
    #[allow(clippy::too_many_lines)]
    fn scan(mut self, data: &[u8], pay: &mut u64, whole_lines: bool) -> (usize, Result<Option<Chunk>, ()>) {
        let mut i = 0;
        let mut commit = (0, self, *pay);
        while i < data.len() {
            if let Chunk::Data(n) = self {
                let take = usize::try_from(n).unwrap_or(usize::MAX).min(data.len() - i);
                *pay += take as u64;
                i += take;
                let left = n - take as u64;
                self = if left == 0 { Chunk::DataCr } else { Chunk::Data(left) };
                commit = (i, self, *pay);
                continue;
            }
            let b = data[i];
            i += 1;
            let end_of_size = |size: u64| if size == 0 { Chunk::Trailer { len: 0, fields: 0 } } else { Chunk::Data(size) };
            let next = match self {
                Chunk::Size { size, digits } => match b {
                    b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                        let size = (size << 4) | u64::from(char::from(b).to_digit(16).unwrap_or(0));
                        if size >= CHUNK_SIZE_LIMIT {
                            Err(())
                        } else {
                            Ok(Chunk::Size { size, digits: digits.saturating_add(1) })
                        }
                    }
                    _ if digits == 0 => Err(()),
                    b' ' | b'\t' => Ok(Chunk::SizeWs { size }),
                    b';' => Ok(Chunk::Ext { size, len: 1, quote: false, escape: false }),
                    b'\r' => Ok(Chunk::SizeLf { size }),
                    _ => Err(()),
                },
                Chunk::SizeWs { size } => match b {
                    b' ' | b'\t' => Ok(Chunk::SizeWs { size }),
                    b';' => Ok(Chunk::Ext { size, len: 1, quote: false, escape: false }),
                    b'\r' => Ok(Chunk::SizeLf { size }),
                    _ => Err(()),
                },
                Chunk::Ext { len, .. } if len >= MAX_CHUNK_LINE => Err(()),
                Chunk::Ext { size, len, quote, escape } => match b {
                    // A control character ends the extension: it must be the CR of its
                    // CRLF, outside any quoted string.
                    b'\r' if !quote && !escape => Ok(Chunk::SizeLf { size }),
                    _ if (b < 0x20 && b != b'\t') || b == 0x7f => Err(()),
                    _ if escape => Ok(Chunk::Ext { size, len: len + 1, quote, escape: false }),
                    b'\\' if quote => Ok(Chunk::Ext { size, len: len + 1, quote, escape: true }),
                    b'\\' => Err(()),
                    b'"' => Ok(Chunk::Ext { size, len: len + 1, quote: !quote, escape: false }),
                    _ => Ok(Chunk::Ext { size, len: len + 1, quote, escape }),
                },
                Chunk::SizeLf { size } => match b {
                    b'\n' => Ok(end_of_size(size)),
                    _ => Err(()),
                },
                Chunk::DataCr => match b {
                    b'\r' => Ok(Chunk::DataLf),
                    _ => Err(()),
                },
                Chunk::DataLf => match b {
                    b'\n' => Ok(CHUNK_START),
                    _ => Err(()),
                },
                Chunk::Trailer { len, .. }
                | Chunk::TrailerName { len, .. }
                | Chunk::TrailerValue { len, .. }
                | Chunk::TrailerValueLf { len, .. }
                    if len >= MAX_TRAILER_SECTION =>
                {
                    Err(())
                }
                Chunk::Trailer { len, fields } => match b {
                    b'\r' => Ok(Chunk::TrailerEndLf),
                    b'\n' => {
                        *pay += 1;
                        return (i, Ok(None));
                    }
                    // An obs-fold continues the field before it.
                    b' ' | b'\t' if fields > 0 => Ok(Chunk::TrailerValue { len: len + 1, fields: fields - 1 }),
                    _ if fields >= MAX_TRAILER_FIELDS => Err(()),
                    _ if is_tchar(b) => Ok(Chunk::TrailerName { len: len + 1, fields, pos: 0, forbidden: 0xff }.name_byte(b)),
                    _ => Err(()),
                },
                Chunk::TrailerName { len, fields, pos, forbidden } => match b {
                    b':' => {
                        let exact = FORBIDDEN_TRAILERS.iter().enumerate().any(|(k, n)| forbidden & (1 << k) != 0 && n.len() == usize::from(pos));
                        if exact {
                            Err(())
                        } else {
                            Ok(Chunk::TrailerValue { len: len + 1, fields })
                        }
                    }
                    _ if is_tchar(b) => Ok(Chunk::TrailerName { len: len + 1, fields, pos, forbidden }.name_byte(b)),
                    _ => Err(()),
                },
                Chunk::TrailerValue { len, fields } => match b {
                    b'\r' => Ok(Chunk::TrailerValueLf { len: len + 1, fields }),
                    b'\n' => Ok(Chunk::Trailer { len: len + 1, fields: fields + 1 }),
                    0 => Err(()),
                    _ => Ok(Chunk::TrailerValue { len: len + 1, fields }),
                },
                Chunk::TrailerValueLf { len, fields } => match b {
                    b'\n' => Ok(Chunk::Trailer { len: len + 1, fields: fields + 1 }),
                    _ => Err(()),
                },
                Chunk::TrailerEndLf => match b {
                    b'\n' => {
                        *pay += 1;
                        return (i, Ok(None));
                    }
                    _ => Err(()),
                },
                Chunk::Data(_) => unreachable!("handled above"),
            };
            match next {
                Ok(c) => {
                    self = c;
                    if c.at_boundary() {
                        commit = (i, c, *pay);
                    }
                }
                Err(()) if whole_lines => {
                    *pay = commit.2;
                    return (commit.0, Err(()));
                }
                Err(()) => return (i - 1, Err(())),
            }
        }
        if whole_lines {
            *pay = commit.2;
            return (commit.0, Ok(Some(commit.1)));
        }
        (i, Ok(Some(self)))
    }

    /// A trailer name that has just gained `b`: the forbidden names it may still be.
    fn name_byte(self, b: u8) -> Chunk {
        let Chunk::TrailerName { len, fields, pos, mut forbidden } = self else { return self };
        let lower = b.to_ascii_lowercase();
        for (k, n) in FORBIDDEN_TRAILERS.iter().enumerate() {
            if n.get(usize::from(pos)) != Some(&lower) {
                forbidden &= !(1 << k);
            }
        }
        Chunk::TrailerName { len, fields, pos: pos.saturating_add(1), forbidden }
    }
}

impl MsgState {
    /// The state a message starts in once its head is processed.
    #[must_use]
    pub fn head(body: Framing) -> Self {
        MsgState::Head { left: 0, body }
    }

    /// Consumes the bytes of `data` that belong to this message, from its current
    /// position, and returns how many there were. The rest of `data` is not this
    /// message's.
    pub fn advance(&mut self, data: &[u8]) -> usize {
        self.advance_counted(data, &mut 0)
    }

    /// [`Self::advance`], adding to `pay` the bytes of body `HAProxy` counts in the HTX
    /// message (see [`htx_head_size`]): the payload without its framing.
    pub fn advance_counted(&mut self, data: &[u8], pay: &mut u64) -> usize {
        let mut used = 0;
        loop {
            match *self {
                MsgState::Waiting | MsgState::Done | MsgState::Error => return used,
                MsgState::Tunnel => return data.len(),
                MsgState::Body(Body::UntilClose) => {
                    *pay += (data.len() - used) as u64;
                    return data.len();
                }
                MsgState::Head { left, body } => {
                    let left = if left == 0 {
                        match find_eoh(&data[used..]) {
                            Some((h, e)) => h + e,
                            None => return used,
                        }
                    } else {
                        left
                    };
                    let n = left.min(data.len() - used);
                    used += n;
                    if n < left {
                        *self = MsgState::Head { left: left - n, body };
                        return used;
                    }
                    *self = match body {
                        Framing::None | Framing::Length(0) => MsgState::Done,
                        Framing::Length(n) => MsgState::Body(Body::Length(n)),
                        Framing::Chunked => MsgState::Body(Body::Chunked(CHUNK_START)),
                        Framing::UntilClose => MsgState::Body(Body::UntilClose),
                        Framing::Tunnel => MsgState::Tunnel,
                    };
                }
                MsgState::Body(Body::Length(n)) => {
                    let avail = (data.len() - used) as u64;
                    if avail < n {
                        *self = MsgState::Body(Body::Length(n - avail));
                        *pay += avail;
                        return data.len();
                    }
                    *pay += n;
                    used += usize::try_from(n).unwrap_or(usize::MAX);
                    *self = MsgState::Done;
                }
                MsgState::Body(Body::Chunked(c)) => {
                    let (n, next) = c.scan(&data[used..], pay, true);
                    used += n;
                    *self = match next {
                        Ok(Some(c)) => MsgState::Body(Body::Chunked(c)),
                        Ok(None) => MsgState::Done,
                        Err(()) => MsgState::Error,
                    };
                    return used;
                }
            }
        }
    }

    /// For a body being re-framed (an HTTP/1 response sent as HTTP/2 DATA): moves this
    /// state through `data`, which starts at the body's current position, appending the
    /// payload bytes (chunk framing removed) to `out` until `out` holds `limit` of them,
    /// and returns how many bytes of `data` were consumed. Framing bytes with no payload
    /// after them, such as the last-chunk and trailer, are consumed even at the limit, so
    /// a body whose payload has all been taken reaches [`MsgState::Done`] without more
    /// room being made. Only a body state moves; any other consumes nothing.
    pub fn take_body(&mut self, data: &[u8], limit: usize, out: &mut Vec<u8>) -> usize {
        let start = out.len();
        let room = |out: &Vec<u8>| limit.saturating_sub(out.len() - start);
        match *self {
            MsgState::Body(Body::UntilClose) => {
                let n = data.len().min(room(out));
                out.extend_from_slice(&data[..n]);
                n
            }
            MsgState::Body(Body::Length(left)) => {
                let n = usize::try_from(left).unwrap_or(usize::MAX).min(data.len()).min(room(out));
                out.extend_from_slice(&data[..n]);
                *self = if n as u64 == left { MsgState::Done } else { MsgState::Body(Body::Length(left - n as u64)) };
                n
            }
            MsgState::Body(Body::Chunked(mut c)) => {
                let mut i = 0;
                while i < data.len() {
                    if let Chunk::Data(left) = c {
                        let n = usize::try_from(left).unwrap_or(usize::MAX).min(data.len() - i).min(room(out));
                        if n == 0 {
                            break;
                        }
                        out.extend_from_slice(&data[i..i + n]);
                        i += n;
                        let left = left - n as u64;
                        c = if left == 0 { Chunk::DataCr } else { Chunk::Data(left) };
                        continue;
                    }
                    let (n, next) = c.scan(&data[i..=i], &mut 0, false);
                    i += n;
                    match next {
                        Ok(Some(next)) => c = next,
                        Ok(None) => {
                            *self = MsgState::Done;
                            return i;
                        }
                        Err(()) => {
                            *self = MsgState::Error;
                            return i;
                        }
                    }
                }
                *self = MsgState::Body(Body::Chunked(c));
                i
            }
            _ => 0,
        }
    }

    /// Measures a head whose length is not known yet, once it is final, so the window is
    /// a subtraction from then on rather than a scan for the blank line on every query.
    pub fn measure_head(&mut self, data: &[u8]) {
        self.measure_head_by(|| find_eoh(data));
    }

    /// [`Self::measure_head`] of a head whose end `eoh` finds: a buffer that knows it
    /// (`Buf::eoh`) does not look for it again.
    pub fn measure_head_by(&mut self, eoh: impl FnOnce() -> Option<(usize, usize)>) {
        if let MsgState::Head { left: 0, body } = *self {
            if let Some((h, e)) = eoh() {
                *self = MsgState::Head { left: h + e, body };
            }
        }
    }

    /// Records that the first `n` bytes of `data` -- which starts at this message's
    /// current position and is what [`Self::window`] measured -- were forwarded. A head
    /// is measured on all of `data` first: a partial send may stop inside it.
    pub fn consume(&mut self, data: &[u8], n: usize) {
        self.consume_counted(data, n, &mut 0);
    }

    /// [`Self::consume`], adding to `pay` what [`Self::advance_counted`] counts.
    pub fn consume_counted(&mut self, data: &[u8], n: usize, pay: &mut u64) {
        self.measure_head(data);
        let used = self.advance_counted(&data[..n], pay);
        debug_assert_eq!(used, n, "forwarded past the end of the message");
    }

    /// What the body bytes of `data` (from this message's current position) hold, without
    /// moving: a framing violation, a line or trailer section past its cap, or a line held
    /// back until the rest of it is here. Only a chunked body holds anything back.
    #[must_use]
    pub fn check_body(&self, data: &[u8]) -> BodyCheck {
        let mut s = *self;
        let used = s.advance(data);
        let broken = s == MsgState::Error;
        if broken {
            // The state at the last line boundary before the violation.
            s = *self;
            s.advance(&data[..used]);
        }
        let MsgState::Body(Body::Chunked(mut c)) = s else {
            return if broken { BodyCheck::Broken } else { BodyCheck::Fine };
        };
        // What is past the last line boundary is one partial line (a chunk-size line, or the
        // last-chunk line and its trailer section): no chunk data, no end of the message.
        for i in used..data.len() {
            let Ok(next) = c.scan(&data[i..=i], &mut 0, false).1 else {
                return if c.over_cap() { BodyCheck::TooLarge { trailer: c.in_trailer() } } else { BodyCheck::Broken };
            };
            let Some(next) = next else { return BodyCheck::Fine };
            c = next;
        }
        if used == data.len() {
            BodyCheck::Fine
        } else {
            BodyCheck::Held { at: used, trailer: c.in_trailer() }
        }
    }

    /// Whether this message is held whole, its head included, until more of it arrives: its
    /// head is not sent yet, and `data` (`cap` bytes or more) ends in its trailer section.
    /// `HAProxy` moves the head out of its input buffer into HTX and reads on, so it knows
    /// whether the section fits before the head goes anywhere: a 16320-byte trailer field
    /// behind a head is refused whole (a 502, or no request at all), a 15000-byte one behind
    /// 2000 bytes of data passes (T281). The buffer holding `data` is made larger meanwhile
    /// ([`Self::check_body`] refuses the section past its cap before that is full).
    #[must_use]
    pub fn holds_trailer(&self, data: &[u8], cap: usize) -> bool {
        data.len() >= cap
            && matches!(self, MsgState::Head { body: Framing::Chunked, .. })
            && matches!(self.check_body(data), BodyCheck::Held { trailer: true, .. })
    }

    /// How many bytes at the front of `data` belong to this message, without moving.
    #[must_use]
    ///
    /// None of `data` when the body breaks its framing in it: `HAProxy` parses what it read
    /// before it forwards any, and forwards nothing of a read in which the parse fails
    /// (a chunk `5\r\nhelloXX` after the head relays no `hello`; T281).
    pub fn window(&self, data: &[u8]) -> usize {
        let mut s = *self;
        let n = s.advance(data);
        if s == MsgState::Error {
            0
        } else {
            n
        }
    }

    #[must_use]
    pub fn is_done(&self) -> bool {
        *self == MsgState::Done
    }

    /// Where in `data` -- which starts at this message's current position -- the first
    /// trailer line ended by a lone LF is, if any. `HAProxy` accepts such a line and
    /// forwards it ended by CRLF; the proxy rewrites it before forwarding, so the next hop
    /// is never handed line ends it may read otherwise (tasks/T276).
    #[must_use]
    pub fn trailer_bare_lf(&self, data: &[u8]) -> Option<usize> {
        let mut i = 0;
        let mut c = match *self {
            MsgState::Head { left, body: Framing::Chunked } => {
                i = if left == 0 { find_eoh(data).map(|(h, e)| h + e)? } else { left };
                CHUNK_START
            }
            MsgState::Body(Body::Chunked(c)) => c,
            _ => return None,
        };
        while i < data.len() {
            if let Chunk::Data(n) = c {
                let take = usize::try_from(n).unwrap_or(usize::MAX).min(data.len() - i);
                i += take;
                c = if take as u64 == n { Chunk::DataCr } else { Chunk::Data(n - take as u64) };
                continue;
            }
            if data[i] == b'\n' && matches!(c, Chunk::Trailer { .. } | Chunk::TrailerValue { .. }) {
                return Some(i);
            }
            match c.scan(&data[i..=i], &mut 0, false) {
                (1, Ok(Some(next))) => c = next,
                _ => return None,
            }
            i += 1;
        }
        None
    }

    /// Rewrites in place each whole chunk-size line of `data` -- which starts at this
    /// message's current position -- the way `HAProxy` writes it out of HTX: the size in
    /// upper-case hex without leading zeros, no blanks, no extension (`0005;a=b` is `5`,
    /// `a` is `A`). Returns the new length of `data`; the bytes past it are stale.
    ///
    /// A size line is never forwarded until it is whole ([`Chunk::at_boundary`]), so no
    /// line is rewritten after any of it has gone. A partial line, the bytes from a framing
    /// violation on, and what follows the end of the message (a pipelined request) are
    /// kept as they are; the violation is [`Self::check_body`]'s to judge. Nothing moves
    /// until a line has shrunk: per chunk, the cost is a scan of its size line.
    ///
    /// With `drop_trailers` (`option http-drop-request-trailers`, `-response-`), a trailer
    /// section that is whole in `data` is cut to the blank line that ends the message, as
    /// `HAProxy` skips the trailer blocks when it writes the message out; one that is not
    /// whole yet is left as it is, to be cut when the rest of it has come (the section is
    /// never forwarded in parts, see [`Chunk::at_boundary`]).
    pub fn canonical_chunk_lines(&self, data: &mut [u8], drop_trailers: bool) -> usize {
        let mut i = 0;
        let mut c = match *self {
            MsgState::Head { left, body: Framing::Chunked } => {
                i = if left == 0 {
                    match find_eoh(data) {
                        Some((h, e)) => h + e,
                        None => return data.len(),
                    }
                } else {
                    left
                };
                CHUNK_START
            }
            MsgState::Body(Body::Chunked(c)) => c,
            _ => return data.len(),
        };
        // `w` trails `i` by what the lines rewritten so far have shed.
        let mut w = i;
        let keep_rest = |data: &mut [u8], i: usize, w: usize| {
            if w != i {
                data.copy_within(i.., w);
            }
            w + data.len() - i
        };
        while i < data.len() {
            if let Chunk::Data(n) = c {
                let take = usize::try_from(n).unwrap_or(usize::MAX).min(data.len() - i);
                if w != i {
                    data.copy_within(i..i + take, w);
                }
                i += take;
                w += take;
                c = if take as u64 == n { Chunk::DataCr } else { Chunk::Data(n - take as u64) };
                continue;
            }
            if matches!(c, Chunk::Trailer { len: 0, fields: 0 }) {
                if drop_trailers {
                    // The last-chunk line is behind us: all of the section, or none of it.
                    let mut pay = 0;
                    return match c.scan(&data[i..], &mut pay, false) {
                        // Only a blank line (`\r\n`, or a lone `\n` that cannot be widened in place).
                        (n, Ok(None)) if n <= 2 => keep_rest(data, i, w),
                        (n, Ok(None)) => {
                            data[w..w + 2].copy_from_slice(b"\r\n");
                            i += n;
                            w += 2;
                            keep_rest(data, i, w)
                        }
                        _ => keep_rest(data, i, w),
                    };
                }
                // A trailer section held whole is written out as HAProxy writes its HTX
                // trailers (T363f); a partial one is left for when it is whole.
                if let (n, Ok(None)) = c.scan(&data[i..], &mut 0, false) {
                    w += normalize_trailer_section(data, i, n, w);
                    return keep_rest(data, i + n, w);
                }
            }
            if c != CHUNK_START {
                // The CRLF after a chunk's data, or the trailer section.
                let b = data[i];
                match c.scan(&[b], &mut 0, false) {
                    (1, Ok(next)) => {
                        // T302: HAProxy writes trailer names lowercased.
                        data[w] = if matches!(next, Some(Chunk::TrailerName { .. })) { b.to_ascii_lowercase() } else { b };
                        i += 1;
                        w += 1;
                        match next {
                            Some(next) => c = next,
                            None => return keep_rest(data, i, w),
                        }
                    }
                    _ => return keep_rest(data, i, w),
                }
                continue;
            }
            // A size line: scanned whole, then written as HAProxy would.
            let mut j = i;
            let mut s = c;
            let size = loop {
                let Some(&b) = data.get(j) else { return keep_rest(data, i, w) };
                j += 1;
                match s.scan(&[b], &mut 0, false) {
                    (1, Ok(Some(next))) => {
                        if let Chunk::SizeLf { size } = s {
                            c = next;
                            break size;
                        }
                        s = next;
                    }
                    _ => return keep_rest(data, i, w),
                }
            };
            let mut line = [0u8; 18];
            let len = chunk_size_line(size, &mut line);
            let line = &line[..len];
            if w != i || &data[i..j] != line {
                data[w..w + line.len()].copy_from_slice(line);
            }
            w += line.len();
            i = j;
        }
        w
    }
}

/// Rewrites the trailer section `data[from..from + len]` (whole, and valid per [`Chunk::scan`])
/// to `data[to..]`, `to <= from`, the way `HAProxy` writes trailers out of HTX
/// (`h1_headers_to_hdr_list` then `h1_format_htx_trailers`): the name in lower case, a fold
/// (`CRLF` or `LF` then a blank) made of blanks, the value without the blanks around it
/// and `: ` between them, `CRLF` at the end of the line. Returns the bytes written.
///
/// The output never outgrows the input, so it is written in place: where `HAProxy` adds a
/// byte the input has not got (`x:v`, `x:`, a line ended by a lone LF) it is left out, the
/// field meaning the same. Nothing is allocated.
fn normalize_trailer_section(data: &mut [u8], from: usize, len: usize, to: usize) -> usize {
    let is_blank = |b: u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n');
    let end = from + len;
    let (mut r, mut w) = (from, to);
    loop {
        // The blank line ends the section.
        if data[r] == b'\n' || data[r..end] == *b"\r\n" {
            let n = end - r;
            data.copy_within(r..end, w);
            return w + n - to;
        }
        let name_len = data[r..end].iter().position(|&b| b == b':').unwrap_or(0);
        // The value runs to a line end that no blank follows.
        let vs = r + name_len + 1;
        let mut le = vs;
        while data[le] != b'\n' || matches!(data[le + 1], b' ' | b'\t') {
            le += 1;
        }
        let line_end = le + 1;
        let mut ve = if le > vs && data[le - 1] == b'\r' { le - 1 } else { le };
        let mut vb = vs;
        while vb < ve && is_blank(data[vb]) {
            vb += 1;
        }
        while ve > vb && is_blank(data[ve - 1]) {
            ve -= 1;
        }
        let value_len = ve - vb;
        let room = line_end - r;
        // `name: value\r\n`, else without the space, else ended by a lone LF.
        let (space, crlf) = if name_len + 2 + value_len + 2 <= room {
            (true, true)
        } else if name_len + 1 + value_len + 2 <= room {
            (false, true)
        } else {
            (false, false)
        };
        data[r..r + name_len].make_ascii_lowercase();
        data.copy_within(r..r + name_len, w);
        // The value moves before the colon and the space are written: with room to spare
        // they may stand where its first byte was.
        let vo = w + name_len + 1 + usize::from(space);
        data.copy_within(vb..ve, vo);
        for b in &mut data[vo..vo + value_len] {
            if *b == b'\r' || *b == b'\n' {
                *b = b' ';
            }
        }
        data[w + name_len] = b':';
        if space {
            data[w + name_len + 1] = b' ';
        }
        let mut o = vo + value_len;
        if crlf {
            data[o] = b'\r';
            o += 1;
        }
        data[o] = b'\n';
        o += 1;
        r = line_end;
        w = o;
    }
}

/// Writes the size line of a chunk of `size` bytes at the front of `out` as `HAProxy`
/// does (`h1_append_chunk_size`): upper-case hex without leading zeros, then CRLF.
/// Returns its length, at most 18 (16 digits and the CRLF).
pub fn chunk_size_line(size: u64, out: &mut [u8]) -> usize {
    let digits = (64 - size.leading_zeros()).div_ceil(4).max(1) as usize;
    for (k, d) in out[..digits].iter_mut().enumerate() {
        *d = b"0123456789ABCDEF"[((size >> (4 * (digits - 1 - k))) & 0xf) as usize];
    }
    out[digits..digits + 2].copy_from_slice(b"\r\n");
    digits + 2
}

/// What [`MsgState::check_body`] finds in the bytes of a body that are here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyCheck {
    /// Nothing wrong, and nothing held back.
    Fine,
    /// The body violates its framing.
    Broken,
    /// A chunk extension, or a trailer section (`trailer`), is longer than it may be.
    TooLarge { trailer: bool },
    /// A chunk-size line, or the last-chunk line and the trailer section after it
    /// (`trailer`), from offset `at`, is held back until its end arrives.
    Held { at: usize, trailer: bool },
}

impl BodyCheck {
    /// Whether the body cannot go on in a buffer of `cap` bytes holding `len`: it is broken,
    /// or a trailer section held back fills the buffer, so the end it waits for has no room
    /// to arrive (`tune.bufsize` below the cap). A chunk-size line that fills the buffer is
    /// waited on, as `HAProxy` 3.5-dev8 does, until a time-out: a 20000-byte extension
    /// behind a request head that went out draws the server's answer, not a close (T281).
    #[must_use]
    pub fn stuck(self, len: usize, cap: usize) -> bool {
        match self {
            BodyCheck::Broken | BodyCheck::TooLarge { .. } => true,
            BodyCheck::Held { at, trailer } => trailer && at == 0 && len >= cap,
            BodyCheck::Fine => false,
        }
    }
}

/// Where `http-request` rules are held for a body: the rule list (the frontend's or the
/// backend's), the rule to run next, and when the wait ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyWait {
    pub backend: bool,
    pub rule: usize,
    pub deadline: ibex_sched::Tick,
    /// A `tarpit`, not a `wait-for-body`: the request is held until `deadline` whatever the
    /// client does, and `timeout client` does not apply meanwhile.
    pub tarpit: bool,
    /// The backend's `tcp-request content` rules wait for their `inspect-delay` (`backend`
    /// is set, `rule` is unused): the frontend's rules and the routing are not run again.
    pub inspect: bool,
}

/// Where `http-response` rules are held for a body: the rule list (the backend's, then
/// the frontend's), the rule to run next, and when the wait ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RspWait {
    pub list: usize,
    pub rule: usize,
    pub deadline: ibex_sched::Tick,
    /// The backend's `tcp-response content` rules wait for the end of their
    /// `inspect-delay` (`WAIT_END`); `list` and `rule` are unused.
    pub inspect: bool,
}

/// How much of a message body `data` holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyProgress {
    /// The body goes on beyond `data`.
    Partial,
    /// `data` holds the whole body (and perhaps what follows it).
    Complete,
    /// The body violates its framing.
    Error,
}

/// Reads the body of a message framed `framing` from `data`, the bytes after its head:
/// the body's own bytes, chunk framing removed, are appended to `out`.
pub fn read_body(framing: Framing, data: &[u8], out: &mut Vec<u8>) -> BodyProgress {
    let mut state = match framing {
        Framing::None | Framing::Length(0) | Framing::Tunnel => return BodyProgress::Complete,
        Framing::Length(n) => MsgState::Body(Body::Length(n)),
        Framing::Chunked => MsgState::Body(Body::Chunked(CHUNK_START)),
        Framing::UntilClose => MsgState::Body(Body::UntilClose),
    };
    state.take_body(data, usize::MAX, out);
    match state {
        MsgState::Done => BodyProgress::Complete,
        MsgState::Error => BodyProgress::Error,
        _ => BodyProgress::Partial,
    }
}

/// The header fields of a raw head, in order, an obs-fold continuation line joined to the
/// field it continues. A line that is neither a field nor a continuation is skipped, and a
/// continuation still joins the last field before it. Borrowed from the head: only a folded
/// field is copied.
#[derive(Clone)]
struct Fields<'a> {
    lines: std::iter::Peekable<std::str::Split<'a, char>>,
}

fn fields(head: &str) -> Fields<'_> {
    let mut lines = head.split('\n').peekable();
    lines.next();
    Fields { lines }
}

impl<'a> Iterator for Fields<'a> {
    type Item = (&'a str, std::borrow::Cow<'a, str>);

    fn next(&mut self) -> Option<Self::Item> {
        let line = |l: &'a str| l.strip_suffix('\r').unwrap_or(l);
        let is_fold = |l: &str| l.starts_with([' ', '\t']);
        // The next field line; continuations before the first field have nothing to join.
        let (k, v) = loop {
            let l = line(self.lines.next()?);
            if is_fold(l) {
                continue;
            }
            if let Some((k, v)) = l.split_once(':') {
                break (k.trim(), v.trim());
            }
        };
        let mut value = std::borrow::Cow::Borrowed(v);
        // Up to the next field line: continuations join this one, other lines are skipped.
        while let Some(&next) = self.lines.peek() {
            let l = line(next);
            if is_fold(l) {
                let o = value.to_mut();
                o.push(' ');
                o.push_str(l.trim());
            } else if l.contains(':') {
                break;
            }
            self.lines.next();
        }
        Some((k, value))
    }
}

/// The body length every `Content-Length` line of a head gives, read as `HAProxy`'s
/// `http_parse_cont_len_header` reads it: each line a comma-separated list of decimal
/// values, all equal. `None` without one, or when they do not agree on one value (a head
/// the parser refuses).
fn content_length<K: AsRef<str>, V: AsRef<str>>(fields: impl Iterator<Item = (K, V)>) -> Option<u64> {
    let mut len = None;
    for (_, v) in fields.filter(|(k, _)| k.as_ref().eq_ignore_ascii_case("content-length")) {
        let v = v.as_ref();
        if v.ends_with(',') {
            return None;
        }
        for word in v.split(',').map(|w| w.trim_matches([' ', '\t'])) {
            if word.is_empty() || !word.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let n = word.parse::<u64>().ok()?;
            if len.is_some_and(|l| l != n) {
                return None;
            }
            len = Some(n);
        }
    }
    len
}

/// The `Transfer-Encoding` lines of a head, all of them, as one list.
fn codings<K: AsRef<str>, V: AsRef<str>>(fields: impl Iterator<Item = (K, V)>, is_response: bool) -> ibex_proto::h1::TransferCodings {
    ibex_proto::h1::TransferCodings::of(fields, is_response)
}

/// How a request body is framed, from its head. A request without a length has no body
/// (RFC 9112 section 6.3, rule 7). `Transfer-Encoding` wins over `Content-Length`; the
/// proxy removes the `Content-Length` of such a request before this is asked.
///
/// Every `Transfer-Encoding` and `Content-Length` line counts, as for the next hop: the
/// first one alone framed `gzip` and `chunked` on two lines as a request without a body,
/// and its body as the client's next request (tasks/T276, V&V VV-1). A head whose lines
/// disagree is refused by the parser before this is asked.
#[must_use]
pub fn request_framing(head: &[u8]) -> Framing {
    match framing_fields(head) {
        Some(f) => request_framing_of(f.te(), f.cl()),
        None => request_framing_general(head),
    }
}

/// [`request_framing`] from the `Transfer-Encoding` and `Content-Length` fields of a head.
fn request_framing_of<K: AsRef<str>, V: AsRef<str>>(te: impl Iterator<Item = (K, V)>, cl: impl Iterator<Item = (K, V)>) -> Framing {
    if codings(te, false).present {
        // Without a final `chunked` the request has no length and is refused (400);
        // were it to get here, chunked is the reading that forwards nothing unframed.
        return Framing::Chunked;
    }
    match content_length(cl) {
        Some(0) | None => Framing::None,
        Some(n) => Framing::Length(n),
    }
}

/// [`request_framing`] read through [`fields`], for any head.
#[cold]
#[inline(never)]
fn request_framing_general(head: &[u8]) -> Framing {
    let head = String::from_utf8_lossy(head);
    request_framing_of(fields(&head), fields(&head))
}

/// How a response body is framed, from its head and the request it answers.
#[must_use]
pub fn response_framing(head: &str, req_method: Option<&str>, status: u16) -> Framing {
    if let Some(f) = response_framing_before_fields(req_method, status) {
        return f;
    }
    match framing_fields(head.as_bytes()) {
        Some(f) => response_body_framing(f.te(), f.cl()),
        None => response_framing_general(head),
    }
}

/// The framing of a response its status or its request's method settles, whatever its
/// headers say.
fn response_framing_before_fields(req_method: Option<&str>, status: u16) -> Option<Framing> {
    let is = |m: &str| req_method.is_some_and(|r| r.eq_ignore_ascii_case(m));
    if status == 101 || (is("CONNECT") && (200..300).contains(&status)) {
        return Some(Framing::Tunnel);
    }
    if is("HEAD") || (100..200).contains(&status) || status == 204 || status == 304 {
        return Some(Framing::None);
    }
    None
}

/// [`response_body_framing`] read through [`fields`], for any head.
#[cold]
#[inline(never)]
fn response_framing_general(head: &str) -> Framing {
    response_body_framing(fields(head), fields(head))
}

/// How a response with a body is framed, from its `Transfer-Encoding` and `Content-Length`
/// fields.
fn response_body_framing<K: AsRef<str>, V: AsRef<str>>(te: impl Iterator<Item = (K, V)>, cl: impl Iterator<Item = (K, V)>) -> Framing {
    let te = codings(te, true);
    if te.present {
        return if te.chunked_last { Framing::Chunked } else { Framing::UntilClose };
    }
    match content_length(cl) {
        Some(n) => Framing::Length(n),
        None => Framing::UntilClose,
    }
}

/// Whether `str::trim` trims this byte of an ASCII string (`char::is_whitespace`: unlike
/// `u8::is_ascii_whitespace`, with the vertical tab).
const fn ws(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ')
}

/// `str::trim_start` of ASCII bytes.
fn ascii_trim_start(s: &[u8]) -> &[u8] {
    &s[s.iter().position(|&b| !ws(b)).unwrap_or(s.len())..]
}

/// `str::trim_end` of ASCII bytes.
fn ascii_trim_end(s: &[u8]) -> &[u8] {
    &s[..s.iter().rposition(|&b| !ws(b)).map_or(0, |z| z + 1)]
}

/// `s.split(|&b| b == b'\n')`, the line ends found with `memchr` (T433).
fn split_lf(s: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = Some(s);
    std::iter::from_fn(move || {
        let r = rest?;
        if let Some(i) = memchr::memchr(b'\n', r) {
            rest = Some(&r[i + 1..]);
            Some(&r[..i])
        } else {
            rest = None;
            Some(r)
        }
    })
}

/// `str::trim` of ASCII bytes.
fn ascii_trim(s: &[u8]) -> &[u8] {
    ascii_trim_end(ascii_trim_start(s))
}

/// The `Transfer-Encoding` and `Content-Length` fields of a head, as [`fields`] reads them.
struct FramingFields<'a> {
    te: [&'a str; 4],
    n_te: usize,
    cl: [&'a str; 4],
    n_cl: usize,
}

impl<'a> FramingFields<'a> {
    fn te(&self) -> impl Iterator<Item = (&'a str, &'a str)> + '_ {
        self.te[..self.n_te].iter().map(|v| ("transfer-encoding", *v))
    }

    fn cl(&self) -> impl Iterator<Item = (&'a str, &'a str)> + '_ {
        self.cl[..self.n_cl].iter().map(|v| ("content-length", *v))
    }
}

/// The values of the `Transfer-Encoding` and `Content-Length` fields of a head in one pass
/// over its bytes, without the general reading of [`fields`] for every line: a line whose
/// name cannot be either (its first byte is not a `c` or a `t`) is not read further. The
/// values are the ones [`fields`] gives (the same lines, trimmed the same way), on the heads
/// this answers for; `None` for the others, which go through [`fields`]: a folded line
/// (joined to the field before it), a line of either kind with a byte outside ASCII (which
/// `str::trim` might trim, and which the lossy reading of a request head replaces), or more
/// than four lines of one kind.
fn framing_fields(head: &[u8]) -> Option<FramingFields<'_>> {
    fn trim(s: &[u8]) -> &str {
        std::str::from_utf8(ascii_trim(s)).unwrap_or_default()
    }
    let mut out = FramingFields { te: [""; 4], n_te: 0, cl: [""; 4], n_cl: 0 };
    let mut at = memchr::memchr(b'\n', head)? + 1;
    while at <= head.len() {
        let end = memchr::memchr(b'\n', &head[at..]).map_or(head.len(), |n| at + n);
        let raw = &head[at..end];
        at = end + 1;
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        if matches!(line.first(), Some(b' ' | b'\t')) {
            return None; // a fold
        }
        let Some(first) = line.iter().position(|&b| !ws(b)) else { continue };
        if line[first] >= 0x80 {
            return None; // might be trimmed
        }
        if !matches!(line[first] | 0x20, b'c' | b't') {
            continue;
        }
        if !line.is_ascii() {
            return None;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else { continue };
        let (name, value) = (trim(&line[..colon]), &line[colon + 1..]);
        let (slot, n) = if name.eq_ignore_ascii_case("transfer-encoding") {
            (&mut out.te, &mut out.n_te)
        } else if name.eq_ignore_ascii_case("content-length") {
            (&mut out.cl, &mut out.n_cl)
        } else {
            continue;
        };
        *slot.get_mut(*n)? = trim(value);
        *n += 1;
    }
    Some(out)
}

/// Whether a head asks for the connection to close after this message: `Connection:
/// close`, or HTTP/1.0 without `Connection: keep-alive`.
#[must_use]
pub fn head_wants_close(head: &str) -> bool {
    if head.is_ascii() {
        head_wants_close_ascii(head.as_bytes())
    } else {
        head_wants_close_general(head)
    }
}

/// [`head_wants_close_general`] of an ASCII head, on its bytes, in one pass for both tokens.
fn head_wants_close_ascii(head: &[u8]) -> bool {
    let (mut close, mut keep_alive) = (false, false);
    let mut lines = split_lf(head);
    let first = lines.next().unwrap_or_default();
    for l in lines {
        let Some(colon) = l.iter().position(|&b| b == b':') else { continue };
        if !ascii_trim(&l[..colon]).eq_ignore_ascii_case(b"connection") {
            continue;
        }
        for t in l[colon + 1..].split(|&b| b == b',').map(ascii_trim) {
            close |= t.eq_ignore_ascii_case(b"close");
            keep_alive |= t.eq_ignore_ascii_case(b"keep-alive");
        }
    }
    close || (first.windows(8).any(|w| w == b"HTTP/1.0") && !keep_alive)
}

/// [`head_wants_close`] of any head.
#[cold]
#[inline(never)]
fn head_wants_close_general(head: &str) -> bool {
    let has = |token: &str| {
        head.split('\n').skip(1).any(|l| {
            l.split_once(':').is_some_and(|(k, v)| {
                k.trim().eq_ignore_ascii_case("connection")
                    && v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token))
            })
        })
    };
    let first = head.split('\n').next().unwrap_or("");
    has("close") || (first.contains("HTTP/1.0") && !has("keep-alive"))
}

/// Whether a `Connection` value lists `token`.
#[must_use]
pub fn connection_has(value: &str, token: &str) -> bool {
    value.split(',').any(|t| t.trim().eq_ignore_ascii_case(token))
}

/// The tokens of the `Connection` headers of a message that `HAProxy` acts on.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ConnTokens {
    pub keep_alive: bool,
    pub close: bool,
    pub upgrade: bool,
}

/// What `HAProxy` leaves of one `Connection` value (`h1_parse_connection_header`, with
/// `H1_MF_CLEAN_CONN_HDR`): the `keep-alive` and `close` tokens are taken out, the others
/// stay, joined by `,`. `None` when nothing is left and the header goes; a value without
/// either token is returned as it was. With `drop_upgrade`, an `upgrade` token goes too (a
/// request without an `Upgrade` header). `tokens` collects what was seen.
#[must_use]
pub fn clean_connection_value(value: &str, drop_upgrade: bool, tokens: &mut ConnTokens) -> Option<String> {
    let mut kept: Vec<&str> = Vec::new();
    let mut changed = false;
    for t in value.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        if t.eq_ignore_ascii_case("keep-alive") {
            tokens.keep_alive = true;
            changed = true;
        } else if t.eq_ignore_ascii_case("close") {
            tokens.close = true;
            changed = true;
        } else if t.eq_ignore_ascii_case("upgrade") && drop_upgrade {
            changed = true;
        } else {
            tokens.upgrade |= t.eq_ignore_ascii_case("upgrade");
            kept.push(t);
        }
    }
    if !changed {
        return Some(value.trim().to_string());
    }
    (!kept.is_empty()).then(|| kept.join(","))
}

/// The `Connection` token `HAProxy` adds to a request it forwards to a server
/// (`h1_update_req_conn_value`): `close` for an HTTP/1.1 request whose server connection is
/// to close, `keep-alive` for an HTTP/1.0 one whose connection is not. Nothing for a
/// request that upgrades.
#[must_use]
pub fn request_connection_token(close: bool, http11: bool, upgrade: bool) -> Option<&'static str> {
    match (upgrade, close, http11) {
        (true, ..) | (false, true, false) | (false, false, true) => None,
        (false, true, true) => Some("close"),
        (false, false, false) => Some("keep-alive"),
    }
}

/// The `Connection` token added to a response sent to the client
/// (`h1_update_res_conn_value`): `keep-alive` when the connection stays open and either the
/// server's response or the client's request is not HTTP/1.1, `close` when it is to close
/// and the response is HTTP/1.1. Nothing for a tunnel or a response that upgrades.
#[must_use]
pub fn response_connection_token(close: bool, rsp_http11: bool, req_http11: bool, upgrade: bool) -> Option<&'static str> {
    if upgrade {
        return None;
    }
    if close {
        rsp_http11.then_some("close")
    } else {
        (!(rsp_http11 && req_http11)).then_some("keep-alive")
    }
}

/// Whether a `Connection` value holds nothing but `keep-alive` and `close` tokens, which
/// all go: the header is removed whole.
#[must_use]
pub fn connection_is_plain(value: &str) -> bool {
    if value.is_ascii() {
        return value.as_bytes().split(|&b| b == b',').map(ascii_trim).all(|t| t.is_empty() || t.eq_ignore_ascii_case(b"keep-alive") || t.eq_ignore_ascii_case(b"close"));
    }
    value.split(',').map(str::trim).all(|t| t.is_empty() || t.eq_ignore_ascii_case("keep-alive") || t.eq_ignore_ascii_case("close"))
}

/// The `Connection` headers of a head, found without copying it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ConnScan {
    /// How many there are.
    pub count: usize,
    /// Every one of them is plain ([`connection_is_plain`]).
    pub plain: bool,
    /// Where the first one is: from the start of its line to the start of the next.
    pub first: (usize, usize),
}

/// Looks for the `Connection` headers of a head (one pass over the bytes, no allocation).
#[must_use]
pub fn scan_connection(head: &[u8]) -> ConnScan {
    const NAME: &[u8] = b"connection";
    let mut out = ConnScan { plain: true, ..ConnScan::default() };
    let Some(first_eol) = memchr::memchr(b'\n', head) else { return out };
    let mut at = first_eol + 1;
    while at < head.len() {
        let end = memchr::memchr(b'\n', &head[at..]).map_or(head.len(), |n| at + n + 1);
        let line = &head[at..end];
        if line.len() > NAME.len() && (line[0] | 0x20) == b'c' && line[..NAME.len()].eq_ignore_ascii_case(NAME) {
            let rest = line[NAME.len()..].trim_ascii_start();
            if rest.first() == Some(&b':') {
                if out.count == 0 {
                    out.first = (at, end);
                }
                out.count += 1;
                out.plain &= std::str::from_utf8(&rest[1..]).is_ok_and(connection_is_plain);
            }
        }
        if matches!(line[0], b'\r' | b'\n') {
            break; // the blank line that ends the head
        }
        at = end;
    }
    out
}

/// [`rewrite_response_connection`] on a list of headers.
pub fn apply_response_connection(hdrs: &mut Vec<(String, String)>, rsp_http11: bool, close: bool, req_http11: bool, tunnel: bool) {
    let mut tokens = ConnTokens::default();
    hdrs.retain_mut(|(k, v)| {
        if !k.eq_ignore_ascii_case("connection") {
            return true;
        }
        match clean_connection_value(v, false, &mut tokens) {
            Some(c) => {
                *v = c;
                true
            }
            None => false,
        }
    });
    if !tunnel {
        if let Some(tok) = response_connection_token(close, rsp_http11, req_http11, tokens.upgrade) {
            hdrs.push(("Connection".to_string(), tok.to_string()));
        }
    }
}

/// The head of a response with its `Connection` headers as `HAProxy` forwards them:
/// `keep-alive` and `close` taken out of each, and the token the connection's state calls
/// for ([`response_connection_token`]) added as a last header. `None` if the head stays as
/// it is.
#[must_use]
pub fn rewrite_response_connection(head: &str, close: bool, req_http11: bool, tunnel: bool) -> Option<String> {
    let rsp_http11 = head.starts_with("HTTP/1.1");
    let mut out = String::with_capacity(head.len() + 24);
    let mut tokens = ConnTokens::default();
    let mut changed = false;
    let mut end = usize::MAX;
    for (i, line) in head.split_inclusive('\n').enumerate() {
        let bare = line.trim_end_matches(['\r', '\n']);
        if i > 0 && bare.is_empty() {
            end = out.len();
            out.push_str(line);
            break;
        }
        match bare.split_once(':') {
            Some((name, value)) if i > 0 && name.trim().eq_ignore_ascii_case("connection") => {
                let eol = &line[bare.len()..];
                match clean_connection_value(value, false, &mut tokens) {
                    Some(v) if v == value.trim() => out.push_str(line),
                    Some(v) => {
                        out.push_str(name);
                        out.push_str(": ");
                        out.push_str(&v);
                        out.push_str(eol);
                        changed = true;
                    }
                    None => changed = true,
                }
            }
            _ => out.push_str(line),
        }
    }
    if end == usize::MAX {
        return None; // no end of head
    }
    if !tunnel {
        if let Some(tok) = response_connection_token(close, rsp_http11, req_http11, tokens.upgrade) {
            let nl = if head.contains("\r\n") { "\r\n" } else { "\n" };
            out.insert_str(end, &format!("Connection: {tok}{nl}"));
            changed = true;
        }
    }
    changed.then_some(out)
}

/// The status of a response head, 0 if the status line does not parse.
#[must_use]
pub fn status_of(head: &str) -> u16 {
    head.split('\n')
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.trim().parse().ok())
        .unwrap_or(0)
}


/// Whether the request line in `buf` is one `HAProxy` answers with a 400 (T286, T291): a byte
/// its parser refuses, or a version that is not `HTTP/<digit>.<digit>`, missing, or followed
/// by anything, however long the line is. Its parser refuses the first byte that cannot
/// belong where it is, so this holds before the line feed is in, and before the head is
/// known to be too big for a 414 or a 431. Without `accept-unsafe-violations-in-http-request`
/// (the proxy passes its own setting to [`ibex_proto::h1::scan_request_line`]).
#[must_use]
pub fn request_version_invalid(buf: &[u8]) -> bool {
    ibex_proto::h1::scan_request_line(buf, false) == ibex_proto::h1::ReqLineScan::Invalid
}

/// Whether the request line in `buf` is one `HAProxy` answers with a 414 (T282): once its
/// line feed is in, the start-line block (the 40 bytes of an HTX, the 20 of the block and the
/// method, target and version) does not fit `bufsize`; with no line feed yet, the buffer
/// holds `bufsize - 56` bytes or more (the point at which it draws a 431 once the request
/// line is complete). Measured on 3.5-dev8, `bufsize` 4096 and 16384 (`tasks/T282`).
#[must_use]
pub fn request_line_too_long(buf: &[u8], bufsize: usize) -> bool {
    let Some(lf) = buf.iter().position(|&b| b == b'\n') else {
        return buf.len() + 56 >= bufsize;
    };
    let line = buf[..lf].strip_suffix(b"\r").unwrap_or(&buf[..lf]);
    let strings = match line.iter().position(|&b| b == b' ') {
        Some(m) => {
            let rest = &line[m + 1..];
            let (target, version) = rest.iter().rposition(|&b| b == b' ').map_or((rest, &rest[rest.len()..]), |v| (&rest[..v], &rest[v + 1..]));
            m + target.trim_ascii().len() + version.trim_ascii().len()
        }
        None => return false,
    };
    60 + strings > bufsize
}

/// `htx_head_cost_and_size` of a response head (T265): the same accounting, with the start line read
/// as a status line.
#[must_use]
pub fn htx_response_head_cost(head: &[u8]) -> usize {
    head_cost(head, false)
}

fn head_cost(head: &[u8], request: bool) -> usize {
    htx_head_cost_and_size_of(head, request).0
}

/// What the proxy needs to know of a message head, read in one walk over its lines (T436),
/// the way `HAProxy`'s `h1_headers_to_hdr_list` records `h1m->flags` as it parses: every
/// reading below gave its own pass over the head before (`htx_head_size`, `head_wants_close`,
/// `request_framing` / `response_framing`, `scan_connection`), five in all with `find_eoh`.
///
/// Read only from an ASCII head whose lines are all plain `name: value` lines up to the blank
/// line that ends it: no fold, no line without a colon, no blank around a name, nothing after
/// the blank line. On such a head every one of those readings splits the lines the same way,
/// so each fact here is what its own reading gives ([`HeadFacts::scan`] checks that in debug
/// builds); any other head is `None`, and the caller reads it the old way.
///
/// The facts are of the head as scanned: a caller that edits the head (a rule, a rewrite)
/// before it reads one of them reads the head again instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadFacts {
    /// [`htx_head_size`].
    pub size: u64,
    /// The header blocks the head keeps in HTX (for [`htx_head_cost_and_size`]).
    pub headers: usize,
    /// A `Connection` header lists `close`.
    pub conn_close: bool,
    /// A `Connection` header lists `keep-alive`.
    pub conn_keep_alive: bool,
    /// The start line holds `HTTP/1.0` (what [`head_wants_close`] looks for).
    pub http10: bool,
    /// [`scan_connection`].
    pub conn: ConnScan,
    /// The body framing `Transfer-Encoding` and `Content-Length` give ([`request_framing`],
    /// or [`response_framing`] past its status and method cases); `None` with more than four
    /// lines of either, which the general reading takes.
    pub framing: Option<Framing>,
}

impl HeadFacts {
    /// The facts of `head` (start line through the blank line), a request head or a response
    /// head; `None` for a head they are not read from (see [`HeadFacts`]).
    #[must_use]
    pub fn scan(head: &[u8], request: bool) -> Option<Self> {
        let facts = Self::scan_plain(head, request);
        #[cfg(debug_assertions)]
        if let Some(f) = facts {
            f.check(head, request);
        }
        facts
    }

    fn scan_plain(head: &[u8], request: bool) -> Option<Self> {
        if !head.is_ascii() {
            return None;
        }
        let nl = memchr::memchr(b'\n', head)?;
        let first_raw = &head[..nl];
        let first = first_raw.strip_suffix(b"\r").unwrap_or(first_raw);
        let strings = if request {
            let sp = first.iter().position(|&b| b == b' ')?;
            let (method, rest) = (&first[..sp], &first[sp + 1..]);
            let (target, version) = rest.iter().rposition(|&b| b == b' ').map_or((rest, &b""[..]), |v| (&rest[..v], &rest[v + 1..]));
            method.len() + ascii_trim(target).len() + ascii_trim(version).len()
        } else {
            let (version, rest) = first.iter().position(|&b| b == b' ').map_or((first, &b""[..]), |sp| (&first[..sp], &first[sp + 1..]));
            let rest = ascii_trim_start(rest);
            let (status, reason) = rest.split_at(rest.len().min(3));
            version.len() + status.len() + ascii_trim(reason).len()
        };
        let mut f = HeadFacts {
            size: 20 + strings as u64 + 1,
            headers: 0,
            conn_close: false,
            conn_keep_alive: false,
            http10: first_raw.windows(8).any(|w| w == b"HTTP/1.0"),
            conn: ConnScan { plain: true, ..ConnScan::default() },
            framing: None,
        };
        let mut ff = FramingFields { te: [""; 4], n_te: 0, cl: [""; 4], n_cl: 0 };
        let mut many = false;
        let mut at = nl + 1;
        loop {
            let end = at + memchr::memchr(b'\n', &head[at..])?;
            let raw = &head[at..end];
            let line = raw.strip_suffix(b"\r").unwrap_or(raw);
            let next = end + 1;
            if line.is_empty() {
                if next != head.len() {
                    return None; // more after the blank line
                }
                break;
            }
            let colon = memchr::memchr(b':', line)?;
            let name = &line[..colon];
            if name.first().is_none_or(|&b| ws(b)) || name.last().is_some_and(|&b| ws(b)) {
                return None; // a fold, or blanks around the name
            }
            let value = ascii_trim(&line[colon + 1..]);
            f.headers += 1;
            let mut len = value.len();
            if name.len() == 10 && name.eq_ignore_ascii_case(b"connection") {
                if f.conn.count == 0 {
                    f.conn.first = (at, next);
                }
                f.conn.count += 1;
                let (mut kept, mut chars, mut dropped) = (0, 0, false);
                for t in value.split(|&b| b == b',').map(ascii_trim).filter(|t| !t.is_empty()) {
                    let close = t.eq_ignore_ascii_case(b"close");
                    let keep_alive = t.eq_ignore_ascii_case(b"keep-alive");
                    f.conn_close |= close;
                    f.conn_keep_alive |= keep_alive;
                    f.conn.plain &= close || keep_alive;
                    if close || keep_alive || t.eq_ignore_ascii_case(b"upgrade") {
                        dropped = true;
                    } else {
                        kept += 1;
                        chars += t.len();
                    }
                }
                if dropped && kept == 0 {
                    // Gone from the HTX message: no block, no data.
                    f.headers -= 1;
                    at = next;
                    continue;
                }
                if dropped {
                    len = chars + kept - 1;
                }
            } else if name.len() == 14 && name.eq_ignore_ascii_case(b"content-length") {
                let v = std::str::from_utf8(value).unwrap_or_default();
                match ff.cl.get_mut(ff.n_cl) {
                    Some(slot) => *slot = v,
                    None => many = true,
                }
                ff.n_cl += 1;
            } else if name.len() == 17 && name.eq_ignore_ascii_case(b"transfer-encoding") {
                let v = std::str::from_utf8(value).unwrap_or_default();
                match ff.te.get_mut(ff.n_te) {
                    Some(slot) => *slot = v,
                    None => many = true,
                }
                ff.n_te += 1;
            }
            f.size += (name.len() + len) as u64;
            at = next;
        }
        if !many {
            f.framing = Some(if request { request_framing_of(ff.te(), ff.cl()) } else { response_body_framing(ff.te(), ff.cl()) });
        }
        Some(f)
    }

    /// The facts against the readings they stand for, each of which reads the head again.
    #[cfg(debug_assertions)]
    fn check(&self, head: &[u8], request: bool) {
        let text = String::from_utf8_lossy(head);
        debug_assert_eq!(Some(self.size), htx_head_size_general(head, request), "size of {text:?}");
        debug_assert_eq!(self.cost(), head_cost_of(head, Some(self.size)), "cost of {text:?}");
        debug_assert_eq!(self.wants_close(), head_wants_close_general(&text), "close of {text:?}");
        debug_assert_eq!(self.conn, scan_connection(head), "Connection of {text:?}");
        if let Some(framing) = self.framing {
            let general = if request { request_framing_general(head) } else { response_framing_general(&text) };
            debug_assert_eq!(framing, general, "framing of {text:?}");
        }
    }

    /// What the head takes of the buffer once in HTX ([`htx_head_cost_and_size`]).
    #[must_use]
    pub fn cost(&self) -> usize {
        cost_of(usize::try_from(self.size).unwrap_or(usize::MAX), self.headers)
    }

    /// [`head_wants_close`].
    #[must_use]
    pub fn wants_close(&self) -> bool {
        self.conn_close || (self.http10 && !self.conn_keep_alive)
    }

    /// [`response_framing`] of the response head these are the facts of, `None` when the
    /// general reading has to say.
    #[must_use]
    pub fn response_framing(&self, req_method: Option<&str>, status: u16) -> Option<Framing> {
        response_framing_before_fields(req_method, status).or(self.framing)
    }
}

/// [`head_cost`] and [`htx_head_size`] of a head: an ASCII head in one walk over its lines
/// (T433: the block count re-split every line the size had split), any other on its own.
fn htx_head_cost_and_size_of(head: &[u8], request: bool) -> (usize, Option<u64>) {
    if let Some(f) = HeadFacts::scan(head, request) {
        return (f.cost(), Some(f.size));
    }
    if head.is_ascii() {
        if let Some((size, headers)) = htx_head_size_and_headers_ascii(head, request) {
            return (cost_of(usize::try_from(size).unwrap_or(usize::MAX), headers), Some(size));
        }
    }
    let size = htx_head_size(head, request);
    (head_cost_of(head, size), size)
}

/// The HTX cost of `data` bytes in `headers` header blocks, with the start line and the end
/// of headers.
fn cost_of(data: usize, headers: usize) -> usize {
    data.saturating_add(40 + 8 * (2 + headers))
}

/// [`head_cost`] of a head whose [`htx_head_size`] is `size`.
#[cold]
#[inline(never)]
fn head_cost_of(head: &[u8], size: Option<u64>) -> usize {
    // A `Connection` header left with no token is not in the HTX message at all, so it has
    // no block either (as `htx_head_size` leaves it out of the data).
    let headers = head
        .split(|&b| b == b'\n')
        .skip(1)
        .take_while(|l| !l.is_empty() && *l != b"\r")
        .filter(|l| !connection_emptied(l))
        .count();
    cost_of(size.map_or(head.len(), |n| usize::try_from(n).unwrap_or(usize::MAX)), headers)
}

/// Whether a header line is a `Connection` whose tokens are all ones HTX drops (`close`,
/// `keep-alive`, `upgrade`), with at least one: the header is then gone from the message.
fn connection_emptied(line: &[u8]) -> bool {
    // Every header line of every head comes here: only a name starting with `c` can be
    // `connection` (the name is trimmed at its end only), so the rest go without a colon
    // search (T433: the search cost ~860 instructions per proxied request).
    if line.len() < 11 || line[0] | 0x20 != b'c' {
        return false;
    }
    let Some(colon) = line.iter().position(|&b| b == b':') else { return false };
    if !ascii_trim_end(&line[..colon]).eq_ignore_ascii_case(b"connection") {
        return false;
    }
    let mut any = false;
    for t in line[colon + 1..].split(|&b| b == b',').map(ascii_trim).filter(|t| !t.is_empty()) {
        if !(t.eq_ignore_ascii_case(b"close") || t.eq_ignore_ascii_case(b"keep-alive") || t.eq_ignore_ascii_case(b"upgrade")) {
            return false;
        }
        any = true;
    }
    any
}

/// What a request head takes of `HAProxy`'s buffer once parsed into HTX, which is what
/// `tune.bufsize - tune.maxrewrite` is held against: the data (`htx_head_size`), the 40
/// bytes of `struct htx`, and an 8-byte `struct htx_blk` for each of the start line, the
/// headers and the end of headers (`HTX_BUF_OVERHEAD` and `struct htx_blk`,
/// `include/haproxy/htx-t.h`). Measured by bisecting the size of the head on 3.5-dev8
/// (`tasks/T87`): with `bufsize 4096` and `maxrewrite 1024`, `GET / HTTP/1.1` and one
/// 2953-byte header is the largest accepted. A head that is not UTF-8 is counted on the
/// wire, plus the 40 bytes.
///
/// Returned with [`htx_head_size`] of the same head, read once.
#[must_use]
pub fn htx_head_cost_and_size(head: &[u8]) -> (usize, Option<u64>) {
    htx_head_cost_and_size_of(head, true)
}

/// [`htx_response_head_cost`] and [`htx_head_size`] of a response head, read once.
#[must_use]
pub fn htx_response_head_cost_and_size(head: &[u8]) -> (usize, Option<u64>) {
    htx_head_cost_and_size_of(head, false)
}

/// The size `HAProxy` gives a message head in its HTX representation, which is what `%U`
/// (request) and `%B` (response) count with the body that follows it: the 20 bytes of the
/// start-line block, the three strings of the start line (method, target, version; or
/// version, status, reason -- the reason as written, none if none), the name and value of
/// each header (the value without its blanks: no colon, no CRLF), and one byte for the end
/// of the headers. A `Connection` header loses its `close`, `keep-alive` and `upgrade`
/// tokens, the others stay joined by `,`, and it is gone when none is left.
///
/// `None` if the head is not UTF-8, which the caller counts on the wire.
#[must_use]
pub fn htx_head_size(head: &[u8], request: bool) -> Option<u64> {
    if head.is_ascii() {
        htx_head_size_ascii(head, request)
    } else {
        htx_head_size_general(head, request)
    }
}

/// [`htx_head_size_general`] of an ASCII head, on its bytes.
fn htx_head_size_ascii(head: &[u8], request: bool) -> Option<u64> {
    htx_head_size_and_headers_ascii(head, request).map(|(size, _)| size)
}

/// [`htx_head_size_ascii`], with the number of header lines that keep a block in the HTX
/// message: every line up to the blank one, but a `Connection` header left with no token
/// (`connection_emptied`), which is gone from the message and from the data.
fn htx_head_size_and_headers_ascii(head: &[u8], request: bool) -> Option<(u64, usize)> {
    let mut lines = split_lf(head).map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let first = lines.next()?;
    let strings = if request {
        let sp = first.iter().position(|&b| b == b' ')?;
        let (method, rest) = (&first[..sp], &first[sp + 1..]);
        let (target, version) = rest.iter().rposition(|&b| b == b' ').map_or((rest, &b""[..]), |v| (&rest[..v], &rest[v + 1..]));
        method.len() + ascii_trim(target).len() + ascii_trim(version).len()
    } else {
        let (version, rest) = first.iter().position(|&b| b == b' ').map_or((first, &b""[..]), |sp| (&first[..sp], &first[sp + 1..]));
        let rest = ascii_trim_start(rest);
        let (status, reason) = rest.split_at(rest.len().min(3));
        version.len() + status.len() + ascii_trim(reason).len()
    };
    let mut size = 20 + strings as u64 + 1;
    let mut headers = 0;
    for line in lines {
        if line.is_empty() {
            break;
        }
        headers += 1;
        let Some(colon) = line.iter().position(|&b| b == b':') else { continue };
        let (name, value) = (ascii_trim_end(&line[..colon]), ascii_trim(&line[colon + 1..]));
        let len = if name.eq_ignore_ascii_case(b"connection") {
            let known = |t: &[u8]| t.eq_ignore_ascii_case(b"close") || t.eq_ignore_ascii_case(b"keep-alive") || t.eq_ignore_ascii_case(b"upgrade");
            let mut kept = 0;
            let mut chars = 0;
            let mut dropped = false;
            for t in value.split(|&b| b == b',').map(ascii_trim).filter(|t| !t.is_empty()) {
                if known(t) {
                    dropped = true;
                } else {
                    kept += 1;
                    chars += t.len();
                }
            }
            if !dropped {
                value.len()
            } else if kept == 0 {
                headers -= 1;
                continue;
            } else {
                chars + kept - 1
            }
        } else {
            value.len()
        };
        size += (name.len() + len) as u64;
    }
    Some((size, headers))
}

/// [`htx_head_size`] of any head.
#[cold]
#[inline(never)]
fn htx_head_size_general(head: &[u8], request: bool) -> Option<u64> {
    let head = std::str::from_utf8(head).ok()?;
    let mut lines = head.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let first = lines.next()?;
    let strings = if request {
        let (method, rest) = first.split_once(' ')?;
        let (target, version) = rest.rsplit_once(' ').unwrap_or((rest, ""));
        method.len() + target.trim().len() + version.trim().len()
    } else {
        let (version, rest) = first.split_once(' ').unwrap_or((first, ""));
        let rest = rest.trim_start();
        let (status, reason) = rest.split_at(rest.len().min(3));
        version.len() + status.len() + reason.trim().len()
    };
    let mut size = 20 + strings as u64 + 1;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else { continue };
        let (name, value) = (name.trim_end(), value.trim());
        let len = if name.eq_ignore_ascii_case("connection") {
            let known = |t: &str| ["close", "keep-alive", "upgrade"].iter().any(|k| t.eq_ignore_ascii_case(k));
            let mut kept = 0;
            let mut chars = 0;
            let mut dropped = false;
            for t in value.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                if known(t) {
                    dropped = true;
                } else {
                    kept += 1;
                    chars += t.len();
                }
            }
            if !dropped {
                value.len()
            } else if kept == 0 {
                continue;
            } else {
                chars + kept - 1
            }
        } else {
            value.len()
        };
        size += (name.len() + len) as u64;
    }
    Some(size)
}

/// One request and its response.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct HttpTxn {
    pub req: MsgState,
    pub rsp: MsgState,
    /// The response in flight is interim (1xx other than 101); a final one follows it.
    pub rsp_interim: bool,
    /// The final response's status, 0 before there is one.
    pub status: u16,
    /// `http-request` rules have run and the request is routed (or answered).
    pub req_rules_done: bool,
    /// A `wait-for-body` the request rules are held at: where they resume, and until when.
    pub body_wait: Option<BodyWait>,
    /// The request body as it was when the wait ended (decoded: chunk framing removed),
    /// what `req.body` reads in the rules after the wait.
    pub req_body: Option<Vec<u8>>,
    /// A `wait-for-body` the response rules are held at.
    pub rsp_wait: Option<RspWait>,
    /// The proxy is answering this request itself; nothing is read from a server.
    pub local: bool,
    /// The local reply replaced a server response that was complete (`http-response return`):
    /// the server connection goes back to the pool all the same.
    pub keeps_srv: bool,
    /// The one decision to close the client connection once this transaction ends.
    pub close_after: bool,
    /// The client's request is HTTP/1.1 (the response's `Connection` header depends on it).
    /// The version on the request line as major * 10 + minor (`HTTP/1.1` is 11), 255 until it
    /// is read; `req.ver` reads it after the head's HTX is released (T371).
    pub req_version: u8,
    pub req_http11: bool,
    /// The server may keep its connection once this response is done.
    pub srv_reusable: bool,
    /// The client asked for a HEAD. The response is framed by the method the server
    /// answered (a rule may have rewritten it), and the client gets its head alone.
    pub client_head: bool,
    /// The request went out on a server connection that had already carried one
    /// (`HAProxy`'s `SF_SRV_REUSED`). If it closes before any response, the client
    /// connection is closed with nothing sent, so the client retries.
    pub srv_reused: bool,
    /// That happened: the request was lost on a reused server connection and the client is
    /// closed unanswered (`abort_keep_alive`). `HAProxy` sets its status to 0 there, which
    /// drops its log line and its response counters (T229).
    pub keepalive_lost: bool,
    /// A reply owed to the client that the byte layer could not produce itself (it has no
    /// access to the error pages): a request that failed to parse.
    pub error: Option<u16>,
    /// That reply is not written: the client connection closes with nothing sent, and the
    /// status is only logged (`HAProxy` on a request trailer section past its cap, T281).
    pub quiet: bool,
    /// The response was cut short (the server went away mid-body, or a tunnel side
    /// closed): what arrived is delivered and the connection closes.
    pub aborted: bool,
    /// What the request's cookies told the backend's `cookie` persistence, which the
    /// response needs (`SF_DIRECT`, `cookie_first_date`, `cookie_last_date`).
    pub ck: crate::cookie::CookieTxn,
    /// What `%U` and `%B` count: the HTX message `HAProxy` parsed of the request and of
    /// the server's response, as received (see [`htx_head_size`]). `None` until the head
    /// has been measured, or where it is not (an HTTP/2 client's request).
    pub req_htx: Option<u64>,
    pub rsp_htx: Option<u64>,
    /// `http-request disable-l7-retry` ran for this request (`TX_D_L7_RETRY`).
    pub l7_off: bool,
    /// A retry on the server's answer (`retry-on <status>`): the request as it was sent.
    pub l7: L7Retry,
}

/// Where a request stands for a retry on what the server answers (`TX_L7_RETRY` and the
/// `l7_buffer`).
#[derive(Debug, Default)]
pub enum L7Retry {
    /// Not a candidate: the backend does not retry on a response, or nothing armed it.
    #[default]
    Off,
    /// A candidate; the request is copied when it is first sent.
    Armed,
    /// The request did not fit, or was not whole when it was first sent: no retry.
    Dead,
    /// The request as it was sent, and where its message state stood before.
    Saved(Box<L7Snapshot>),
}

/// What a retry on a response replays.
#[derive(Debug)]
pub struct L7Snapshot {
    pub bytes: Vec<u8>,
    pub req_state: MsgState,
}

impl HttpTxn {
    /// A transaction for a request whose head has just been parsed.
    #[must_use]
    pub fn new(req_body: Framing, close_after: bool) -> Self {
        HttpTxn {
            req: MsgState::head(req_body),
            rsp: MsgState::Waiting,
            rsp_interim: false,
            status: 0,
            req_rules_done: false,
            body_wait: None,
            req_body: None,
            rsp_wait: None,
            local: false,
            keeps_srv: false,
            close_after,
            req_http11: true,
            req_version: 255,
            srv_reusable: true,
            srv_reused: false,
            keepalive_lost: false,
            client_head: false,
            error: None,
            quiet: false,
            aborted: false,
            ck: crate::cookie::CookieTxn::default(),
            req_htx: None,
            rsp_htx: None,
            l7_off: false,
            l7: L7Retry::Off,
        }
    }

    /// Records that the first `n` bytes of `data` -- the request, from its current position --
    /// were consumed, and what `%U` counts of them.
    pub fn request_consumed(&mut self, data: &[u8], n: usize) {
        let mut pay = 0;
        self.req.consume_counted(data, n, &mut pay);
        if let Some(t) = self.req_htx.as_mut() {
            *t += pay;
        }
    }

    /// A transaction for a request that could not be parsed: it is answered with
    /// `status` and the connection closes.
    #[must_use]
    pub fn failed(status: u16) -> Self {
        HttpTxn {
            req: MsgState::Done,
            req_rules_done: true,
            close_after: true,
            srv_reusable: false,
            error: Some(status),
            ..HttpTxn::new(Framing::None, true)
        }
    }

    /// Whether the server side may be read: a response is expected and not complete.
    #[must_use]
    pub fn reads_server(&self) -> bool {
        !self.local && self.error.is_none() && !matches!(self.rsp, MsgState::Done | MsgState::Error)
    }

    /// Records the first `n` bytes of `rep` as delivered to the client. An interim
    /// response, once delivered, makes room for the next head.
    pub fn response_sent(&mut self, rep: &[u8], n: usize) {
        let mut pay = 0;
        self.rsp.consume_counted(rep, n, &mut pay);
        // A reply the proxy made in place of the server's response is not counted: `%B`
        // is the message the server sent.
        if let Some(t) = self.rsp_htx.as_mut().filter(|_| !self.local) {
            *t += pay;
        }
        if self.rsp.is_done() && self.rsp_interim {
            self.rsp = MsgState::Waiting;
            self.rsp_interim = false;
        }
    }

    /// How much of `rep` may go to the client now: the current response and nothing
    /// after it, and of a response to a HEAD, the head alone.
    #[must_use]
    pub fn client_window(&self, rep: &[u8]) -> usize {
        match self.rsp {
            MsgState::Head { left, .. } if self.client_head => {
                MsgState::Head { left, body: Framing::None }.window(rep)
            }
            MsgState::Body(_) if self.client_head => 0,
            rsp => rsp.window(rep),
        }
    }

    /// The body of a response to a HEAD, which the client does not get: how much of
    /// `rep` it covers, recorded as delivered. The caller drops those bytes.
    pub fn skip_head_body(&mut self, rep: &[u8]) -> usize {
        if !self.client_head || !matches!(self.rsp, MsgState::Body(_)) {
            return 0;
        }
        let n = self.rsp.window(rep);
        self.rsp.consume(rep, n);
        n
    }

    /// Both messages are complete: the transaction can end once output has drained.
    #[must_use]
    pub fn finished(&self) -> bool {
        self.rsp.is_done() && (self.req.is_done() || self.close_after)
    }
}

/// `HTTP/<digit>.<digit>`, the version of the request line the parser accepts, by major * 10 + minor.
static VERSION_TEXT: [[u8; 8]; 100] = {
    let mut t = [[0u8; 8]; 100];
    let mut i = 0;
    while i < 100 {
        #[allow(clippy::cast_possible_truncation)]
        let (major, minor) = (b'0' + (i / 10) as u8, b'0' + (i % 10) as u8);
        t[i] = [b'H', b'T', b'T', b'P', b'/', major, b'.', minor];
        i += 1;
    }
    t
};

/// The text of a version kept as `HttpTxn::req_version`.
#[must_use]
pub fn version_text(v: u8) -> Option<&'static str> {
    VERSION_TEXT.get(usize::from(v)).and_then(|t| std::str::from_utf8(t).ok())
}

/// The version a request line ends in (`1.1` is 11), `None` when its last three bytes are not
/// `<digit>.<digit>`: `HttpTxn::req_version` then stays unknown.
#[must_use]
pub fn version_digits(ver: &[u8]) -> Option<u8> {
    let [.., major @ b'0'..=b'9', b'.', minor @ b'0'..=b'9'] = ver else { return None };
    Some((major - b'0') * 10 + (minor - b'0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_lf_splits_as_split_does() {
        for s in [&b""[..], b"\n", b"\n\n", b"a", b"a\n", b"\na", b"ab\ncd\n\nef", b"GET / HTTP/1.1\r\nHost: a-long-enough-host-name.example\r\nX-Forwarded-For: 192.0.2.1\r\n\r\n"] {
            assert_eq!(split_lf(s).collect::<Vec<_>>(), s.split(|&b| b == b'\n').collect::<Vec<_>>(), "{s:?}");
        }
    }

    #[test]
    fn only_a_connection_header_of_dropped_tokens_is_emptied() {
        for (line, emptied) in [
            (&b"Connection: close\r"[..], true),
            (b"connection:keep-alive, Upgrade", true),
            (b"CONNECTION : close", true),
            (b"Connection: close, x-foo", false),
            (b"Connection:", false),
            (b"Connection: , ", false),
            (b"Connectio: close", false),
            (b"Xconnection: close", false),
            (b"Content-Length: 5\r", false),
            (b"c", false),
            (b"", false),
            (b"Host: connection: close", false),
        ] {
            assert_eq!(connection_emptied(line), emptied, "{:?}", String::from_utf8_lossy(line));
        }
    }

    #[test]
    fn the_version_is_the_two_digits_around_the_dot() {
        assert_eq!(version_digits(b"HTTP/1.1"), Some(11));
        assert_eq!(version_digits(b"HTTP/2.0"), Some(20));
        assert_eq!(version_digits(b"HTTP/1.x"), None);
        assert_eq!(version_digits(b"/ HTTP11"), None);
        assert_eq!(version_digits(b"1."), None);
    }

    fn fwd(state: MsgState, data: &[u8]) -> (usize, MsgState) {
        let mut s = state;
        let n = s.advance(data);
        (n, s)
    }

    #[test]
    fn a_body_is_read_as_far_as_it_is_here() {
        let mut out = Vec::new();
        assert_eq!(read_body(Framing::Length(10), b"abcde", &mut out), BodyProgress::Partial);
        assert_eq!(out, b"abcde");
        out.clear();
        assert_eq!(read_body(Framing::Length(4), b"abcdNEXT", &mut out), BodyProgress::Complete);
        assert_eq!(out, b"abcd");
        out.clear();
        assert_eq!(read_body(Framing::None, b"NEXT", &mut out), BodyProgress::Complete);
        assert!(out.is_empty());
        out.clear();
        assert_eq!(read_body(Framing::UntilClose, b"abc", &mut out), BodyProgress::Partial);
        assert_eq!(out, b"abc");
    }

    #[test]
    fn a_chunked_body_is_read_without_its_framing() {
        let mut out = Vec::new();
        assert_eq!(read_body(Framing::Chunked, b"5\r\nhello\r\n3\r\nab", &mut out), BodyProgress::Partial);
        assert_eq!(out, b"helloab");
        out.clear();
        assert_eq!(
            read_body(Framing::Chunked, b"5;x=1\r\nhello\r\n0\r\nT: 1\r\n\r\nNEXT", &mut out),
            BodyProgress::Complete
        );
        assert_eq!(out, b"hello");
        out.clear();
        assert_eq!(read_body(Framing::Chunked, b"zz\r\n", &mut out), BodyProgress::Error);
    }

    /// Chunk trailers are bounded as a whole (`MAX_TRAILER_SECTION`): a name, a value, a line end
    /// or a field boundary past it is an error, wherever it falls. HAProxy 3.5-dev8 refuses a
    /// 17000-byte trailer name or value (the connection is closed with no response) and forwards a
    /// 15000-byte one; `X-T: ` with a 16315-byte value passes and with 16320 does not (T281), so
    /// with `T: ` the limit falls between 16317 and 16322.
    #[test]
    fn a_chunk_trailer_past_the_line_limit_is_an_error() {
        let trailers = |t: &[u8]| {
            let mut body = b"0\r\n".to_vec();
            body.extend_from_slice(t);
            body.extend_from_slice(b"\r\n\r\nNEXT");
            read_body(Framing::Chunked, &body, &mut Vec::new())
        };
        let value = |n: usize| [b"T: ".as_slice(), &vec![b'v'; n]].concat();
        assert_eq!(trailers(&value(15000)), BodyProgress::Complete);
        assert_eq!(trailers(&[vec![b'T'; 17000], b": 1".to_vec()].concat()), BodyProgress::Error);
        assert_eq!(trailers(&value(17000)), BodyProgress::Error);
        // The limit falls at the value, its CR, its LF or the blank line's CR.
        let first_error = (16300..16400).find(|&n| trailers(&value(n)) == BodyProgress::Error).expect("an error");
        assert!((16317..=16322).contains(&first_error), "{first_error}");
        for n in first_error..16400 {
            assert_eq!(trailers(&value(n)), BodyProgress::Error, "value of {n} bytes");
        }
        // Many small fields add up, and the next byte after the one that crossed is refused.
        let fields = (0..20).map(|k| format!("T{k}: {}\r\n", "v".repeat(1000))).collect::<String>();
        assert_eq!(trailers(fields.trim_end().as_bytes()), BodyProgress::Error);
    }

    /// `http_parse_cont_len_header`: measured on HAProxy 3.5-dev8 (the Content-Length checks of
    /// tests/it/http_check_reply_framing.rs): a list of one repeated number is a length, a trailing
    /// comma, a sign or two numbers are not.
    #[test]
    fn content_length_lines_must_agree_on_one_digits_only_value() {
        let cl = |lines: &str| content_length(fields(&format!("HTTP/1.1 200 OK\r\n{lines}\r\n")));
        assert_eq!(cl("Content-Length: 5"), Some(5));
        assert_eq!(cl("Content-Length: 5, 5\r\nCONTENT-LENGTH: 5"), Some(5));
        assert_eq!(cl("Host: x"), None);
        assert_eq!(cl("Content-Length: 5,"), None);
        assert_eq!(cl("Content-Length: +5"), None);
        assert_eq!(cl("Content-Length: 5,,5"), None);
        assert_eq!(cl("Content-Length: 5, 3"), None);
        assert_eq!(cl("Content-Length: 5\r\nContent-Length: 3"), None);
    }

    #[test]
    fn a_length_body_ends_at_its_length_and_leaves_the_next_request() {
        let req = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloGET /next HTTP/1.1\r\n\r\n";
        let (n, s) = fwd(MsgState::head(Framing::Length(5)), req);
        assert_eq!(&req[..n], b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello");
        assert_eq!(s, MsgState::Done);
    }

    #[test]
    fn a_body_split_across_calls() {
        let mut s = MsgState::head(Framing::Length(10));
        assert_eq!(s.advance(b"H\r\n\r\n12345"), 10);
        assert_eq!(s, MsgState::Body(Body::Length(5)));
        assert_eq!(s.advance(b"678"), 3);
        assert_eq!(s.advance(b"90extra"), 2);
        assert!(s.is_done());
    }

    #[test]
    fn a_head_split_across_sends() {
        let buf = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nGET /next";
        let head_len = buf.len() - 9;
        let mut s = MsgState::head(Framing::None);
        assert_eq!(s.window(buf), head_len);
        s.consume(buf, 5);
        assert_eq!(s, MsgState::Head { left: head_len - 5, body: Framing::None });
        assert_eq!(s.window(&buf[5..]), head_len - 5);
        s.consume(&buf[5..], head_len - 5);
        assert!(s.is_done());
    }

    #[test]
    fn a_chunked_body_with_extensions_and_trailers() {
        let body = b"H\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-T: 1\r\n\r\nNEXT";
        let (n, s) = fwd(MsgState::head(Framing::Chunked), body);
        assert_eq!(&body[n..], b"NEXT");
        assert_eq!(s, MsgState::Done);
    }

    #[test]
    fn a_chunked_body_one_byte_at_a_time() {
        // As the proxy feeds it: what has arrived and not been forwarded, one byte more
        // each time. A chunk-size line moves only once it is complete (T276).
        let body = b"H\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let mut s = MsgState::head(Framing::Chunked);
        let mut at = 0;
        for end in 1..=body.len() {
            assert!(!s.is_done(), "done early at byte {end}");
            at += s.advance(&body[at..end]);
        }
        assert!(s.is_done());
        assert_eq!(at, body.len());
    }

    #[test]
    fn a_chunk_size_line_moves_only_once_complete() {
        let mut s = MsgState::head(Framing::Chunked);
        assert_eq!(s.advance(b"H\r\n\r\n5;ext"), 5);
        assert_eq!(s.advance(b"5;ext\r"), 0);
        assert_eq!(s.advance(b"5;ext\r\nhel"), 10);
        assert_eq!(s, MsgState::Body(Body::Chunked(Chunk::Data(2))));
    }

    /// The last-chunk line and the trailer section move together, once the section is
    /// all here (T281, review r2#9).
    #[test]
    fn a_trailer_section_moves_only_once_complete() {
        let body = b"H\r\n\r\n5\r\nhello\r\n0\r\nX-A: 1\r\nX-B: 2\r\n";
        let s = MsgState::head(Framing::Chunked);
        assert_eq!(s.window(body), 15, "up to the last-chunk line");
        let whole = [&body[..], b"\r\n"].concat();
        assert_eq!(s.window(&whole), whole.len());
        assert_eq!(s.check_body(body), BodyCheck::Held { at: 15, trailer: true });
        assert_eq!(s.check_body(b"H\r\n\r\n5;ext"), BodyCheck::Held { at: 5, trailer: false });
        assert_eq!(s.check_body(&whole), BodyCheck::Fine);
    }

    /// Nothing of a read in which the body breaks its framing moves; why it broke is told
    /// apart, and a section held from the front of a full buffer is stuck.
    #[test]
    fn a_broken_body_moves_nothing_and_says_why() {
        let s = MsgState::head(Framing::Chunked);
        assert_eq!(s.window(b"H\r\n\r\n5\r\nhelloXX\r\n"), 0);
        assert_eq!(s.check_body(b"H\r\n\r\n5\r\nhelloXX\r\n"), BodyCheck::Broken);
        let big = [&b"H\r\n\r\n0\r\nX-T: "[..], &[b'a'; 16400]].concat();
        assert_eq!(s.window(&big), 0);
        assert_eq!(s.check_body(&big), BodyCheck::TooLarge { trailer: true });
        let fits = [&b"H\r\n\r\n0\r\nX-T: "[..], &[b'a'; 16300], b"\r\n\r\n"].concat();
        assert_eq!(s.check_body(&fits), BodyCheck::Fine);
        let ext = [&b"H\r\n\r\n1;"[..], &[b'e'; 16400]].concat();
        assert_eq!(s.check_body(&ext), BodyCheck::TooLarge { trailer: false });
        assert!(BodyCheck::Held { at: 0, trailer: true }.stuck(16384, 16384));
        assert!(!BodyCheck::Held { at: 10, trailer: true }.stuck(16384, 16384));
        assert!(!BodyCheck::Held { at: 0, trailer: false }.stuck(100, 16384));
        assert!(!BodyCheck::Held { at: 0, trailer: false }.stuck(16384, 16384), "an extension is waited on");
        assert!(s.holds_trailer(&[&b"H\r\n\r\n0\r\nX-T: "[..], &[b'a'; 16300]].concat(), 16300));
        assert!(!s.holds_trailer(&fits, 16300));
    }

    #[test]
    fn a_malformed_chunk_size_is_an_error() {
        for bad in [&b"H\r\n\r\nzz\r\n"[..], b"H\r\n\r\n\r\n", b"H\r\n\r\n11111111111111111\r\n", b"H\r\n\r\n2\r\nabX"] {
            let (_, s) = fwd(MsgState::head(Framing::Chunked), bad);
            assert_eq!(s, MsgState::Error, "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn bare_lf_is_refused_but_in_the_trailer_section() {
        // HAProxy 3.5-dev8 answers 400 to a size line, an extension or a chunk's data ended
        // by LF alone, and accepts a trailer line and the blank line after the trailers
        // ended so (T276, V&V VV-2).
        for bad in [&b"H\r\n\r\n5\nhello\r\n0\r\n\r\n"[..], b"H\r\n\r\n5;x\nhello\r\n0\r\n\r\n", b"H\r\n\r\n5\r\nhello\n0\r\n\r\n", b"H\r\n\r\n0\n\n"] {
            let (_, s) = fwd(MsgState::head(Framing::Chunked), bad);
            assert_eq!(s, MsgState::Error, "{:?}", String::from_utf8_lossy(bad));
        }
        for body in [&b"H\r\n\r\n0\r\nX: y\n\nNEXT"[..], b"H\r\n\r\n0\r\n\nNEXT"] {
            let (n, s) = fwd(MsgState::head(Framing::Chunked), body);
            assert_eq!((&body[n..], s), (&b"NEXT"[..], MsgState::Done), "{:?}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn chunk_syntax_is_haproxys() {
        let ok: [&[u8]; 6] = [b"0005\r\nhello\r\n0\r\n\r\n", b"5 \t;a=\"b \\\" c\";d\r\nhello\r\n0\r\n\r\n", b"fffffffffffff\r\n", b"0\r\nX-T: 1\r\n  more\r\n\r\n", b"0\r\nHosts: y\r\n\r\n", b"0\r\nTE-x: y\r\n\r\n"];
        for body in ok {
            let data = [&b"H\r\n\r\n"[..], body].concat();
            let (_, s) = fwd(MsgState::head(Framing::Chunked), &data);
            assert_ne!(s, MsgState::Error, "{:?}", String::from_utf8_lossy(body));
        }
        let bad: [&[u8]; 14] = [
            b"10000000000000\r\n", b"+5\r\n", b"0x5\r\n", b"5 x\r\n", b"5;a\x01\r\n", b"5;\"a\r\n", b"5;a\\b\r\n",
            b"5\r\nhelloX", b"0\r\nbogus\r\n\r\n", b"0\r\n: v\r\n\r\n", b"0\r\nX T: 1\r\n\r\n",
            b"0\r\ncontent-LENGTH: 1\r\n\r\n", b"0\r\nTE: x\r\n\r\n", b"0\r\nX: a\rb\r\n\r\n",
        ];
        for body in bad {
            let data = [&b"H\r\n\r\n"[..], body].concat();
            let (_, s) = fwd(MsgState::head(Framing::Chunked), &data);
            assert_eq!(s, MsgState::Error, "{:?}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn a_trailer_line_ended_by_lf_is_found() {
        let s = MsgState::head(Framing::Chunked);
        assert_eq!(s.trailer_bare_lf(b"H\r\n\r\n1\r\n\n\r\n0\r\nX: 1\n\r\n"), Some(18));
        assert_eq!(s.trailer_bare_lf(b"H\r\n\r\n0\r\n\n"), Some(8));
        assert_eq!(s.trailer_bare_lf(b"H\r\n\r\n0\r\nX: 1\r\n\r\n"), None);
    }

    #[test]
    fn framing_reads_every_line() {
        let req = |h: &str| request_framing(format!("POST / HTTP/1.1\r\n{h}\r\n").as_bytes());
        assert_eq!(req("Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n"), Framing::Chunked);
        assert_eq!(req("Content-Length: 3, 3\r\n"), Framing::Length(3));
        assert_eq!(req("Content-Length: 3\r\nContent-Length: 3\r\n"), Framing::Length(3));
        assert_eq!(req("Transfer-Encoding:\r\n chunked\r\n"), Framing::Chunked);
        let rsp = |h: &str| response_framing(&format!("HTTP/1.1 200 OK\r\n{h}\r\n"), Some("GET"), 200);
        assert_eq!(rsp("Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n"), Framing::Chunked);
        assert_eq!(rsp("Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n"), Framing::UntilClose);
        assert_eq!(rsp("Content-Length: 5, 5\r\n"), Framing::Length(5));
        assert_eq!(rsp("Content-Length: 5\r\nContent-Length: 2\r\n"), Framing::UntilClose);
        assert_eq!(rsp("Transfer-Encoding:\r\n chunked\r\n"), Framing::Chunked);
    }

    #[test]
    fn every_malformed_line_end_is_an_error() {
        for bad in [
            &b"H\r\n\r\n\n"[..],         // a size line with no digits
            b"H\r\n\r\n5\rX",            // CR not followed by LF after a size
            b"H\r\n\r\n5\r\nhello\rX", // after the data
            b"H\r\n\r\n0\r\nX: y\rZ",  // after a trailer line
        ] {
            let (_, s) = fwd(MsgState::head(Framing::Chunked), bad);
            assert_eq!(s, MsgState::Error, "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn a_head_without_its_end_moves_nothing() {
        let mut s = MsgState::head(Framing::None);
        assert_eq!(s.advance(b"GET / HTTP/1.1\r\nHost"), 0);
        assert_eq!(s, MsgState::head(Framing::None));
    }

    #[test]
    fn a_head_can_open_a_tunnel() {
        let (n, s) = fwd(MsgState::head(Framing::Tunnel), b"HTTP/1.1 101 Switching\r\n\r\nraw bytes");
        assert_eq!((n, s), (35, MsgState::Tunnel));
    }

    #[test]
    fn waiting_forwards_nothing_and_tunnel_everything() {
        assert_eq!(MsgState::Waiting.window(b"HTTP/1.1 200 OK\r\n\r\n"), 0);
        assert_eq!(MsgState::Tunnel.window(b"anything"), 8);
        assert_eq!(MsgState::head(Framing::UntilClose).window(b"H\r\n\r\nbody"), 9);
    }

    #[test]
    fn response_framing_follows_rfc_9112() {
        let h = |s: &str| format!("HTTP/1.1 200 OK\r\n{s}\r\n");
        assert_eq!(response_framing(&h("Content-Length: 3\r\n"), Some("GET"), 200), Framing::Length(3));
        assert_eq!(response_framing(&h("Content-Length: 3\r\n"), Some("HEAD"), 200), Framing::None);
        assert_eq!(response_framing(&h(""), Some("GET"), 204), Framing::None);
        assert_eq!(response_framing(&h(""), Some("GET"), 304), Framing::None);
        assert_eq!(response_framing(&h(""), Some("GET"), 103), Framing::None);
        assert_eq!(response_framing(&h(""), Some("GET"), 101), Framing::Tunnel);
        assert_eq!(response_framing(&h(""), Some("CONNECT"), 200), Framing::Tunnel);
        assert_eq!(response_framing(&h("Transfer-Encoding: gzip, chunked\r\n"), Some("GET"), 200), Framing::Chunked);
        assert_eq!(response_framing(&h("Transfer-Encoding: gzip\r\n"), Some("GET"), 200), Framing::UntilClose);
        assert_eq!(response_framing(&h(""), Some("GET"), 200), Framing::UntilClose);
    }

    /// The HTX cost of a head, as the separate size and block passes counted it before T433
    /// fused them: the reference the one-pass accounting must keep giving.
    fn reference_head_cost(head: &[u8], request: bool) -> usize {
        fn emptied(line: &[u8]) -> bool {
            let Some(colon) = line.iter().position(|&b| b == b':') else { return false };
            if !ascii_trim_end(&line[..colon]).eq_ignore_ascii_case(b"connection") {
                return false;
            }
            let mut any = false;
            for t in line[colon + 1..].split(|&b| b == b',').map(ascii_trim).filter(|t| !t.is_empty()) {
                if !(t.eq_ignore_ascii_case(b"close") || t.eq_ignore_ascii_case(b"keep-alive") || t.eq_ignore_ascii_case(b"upgrade")) {
                    return false;
                }
                any = true;
            }
            any
        }
        let size = htx_head_size_general(head, request);
        let blocks = 2 + head.split(|&b| b == b'\n').skip(1).take_while(|l| !l.is_empty() && *l != b"\r").filter(|l| !emptied(l)).count();
        let data = size.map_or(head.len(), |n| usize::try_from(n).unwrap_or(usize::MAX));
        data.saturating_add(40 + 8 * blocks)
    }

    /// T433: the HTX cost and size of request and response heads, read in one pass, are the
    /// ones the separate passes gave, on ASCII, UTF-8 and non-UTF-8 heads.
    #[test]
    fn one_pass_head_cost_matches_the_separate_passes() {
        let starts = [
            "GET / HTTP/1.1", "GET /a%20b HTTP/1.0", "GET  /x  HTTP/1.1 ", "GET", "GET /", "\u{b}GET /\u{c} HTTP/1.0\u{b}",
            "HTTP/1.1 200 OK", "HTTP/1.0 204", "HTTP/1.1  301 \u{b}Moved \t", "HTTP/1.1", "HTTP/1.1 2", "", "GET /\u{e9} HTTP/1.1",
        ];
        let lines = [
            "", "Host: x\r\n", "Connection: close\r\n", "connection: Keep-Alive\r\n", "Connection :  te, close ,\r\n",
            "Connection: upgrade, foo,, bar\r\n", "Connection: keep-alive, close\r\n", "\u{b}Connection\u{b}: close\u{c}\r\n",
            "Connection: \r\n", "X-Connection: close\r\n", "Connection close\r\n", "Content-Length: 5\n", " folded: close\r\n",
            "Connection: close\r\r\n", "Upgrade:websocket\r\n", "\r\nConnection: close\r\n", "\nX: 1\r\n", "\r\r\nX: 2\r\n",
            "Connection:keep-alive\u{a0}\r\n", "Connection: \u{85}close\r\n", "X-\u{e9}: v\r\n", "CONNECTION:UPGRADE\r\n",
            "Connection: ,\r\n", "c\r\n", "connection\r\n", "Connectionx: close\r\n", "nocolon\r\n", ":\r\n",
        ];
        let mut heads: Vec<Vec<u8>> = Vec::new();
        for st in starts {
            for a in lines {
                for b in lines {
                    heads.push(format!("{st}\r\n{a}{b}\r\n").into_bytes());
                    heads.push(format!("{st}\n{a}{b}").into_bytes());
                }
            }
        }
        for h in [&b"GET / HTTP/1.1\r\nX: \xff\r\nConnection: close\r\n\r\n"[..], b"HTTP/1.1 200 OK\r\nConnection: close\xff\r\n\r\n", b"\xff\r\n\r\n"] {
            heads.push(h.to_vec());
        }
        for h in &heads {
            assert_eq!(htx_head_cost_and_size(h), (reference_head_cost(h, true), htx_head_size_general(h, true)), "{:?}", String::from_utf8_lossy(h));
            assert_eq!(htx_response_head_cost(h), reference_head_cost(h, false), "{:?}", String::from_utf8_lossy(h));
        }
    }

    /// The readings of an ASCII head on its bytes give what the readings of any head give.
    #[test]
    fn ascii_head_readings_match_the_general_ones() {
        let starts = [
            "GET / HTTP/1.1", "GET /a%20b HTTP/1.0", "GET  /x  HTTP/1.1 ", "GET", "GET /", "\u{b}GET /\u{c} HTTP/1.0\u{b}",
            "HTTP/1.1 200 OK", "HTTP/1.0 204", "HTTP/1.1  301 \u{b}Moved \t", "HTTP/1.1", "HTTP/1.1 2", "",
        ];
        let lines = [
            "", "Host: x\r\n", "Connection: close\r\n", "connection: Keep-Alive\r\n", "Connection :  te, close ,\r\n",
            "Connection: upgrade, foo,, bar\r\n", "Connection: keep-alive, close\r\n", "\u{b}Connection\u{b}: close\u{c}\r\n",
            "Connection: \r\n", "X-Connection: close\r\n", "Connection close\r\n", "Content-Length: 5\n", " folded: close\r\n",
            "Connection: close\r\r\n", "Upgrade:websocket\r\n", "\r\nConnection: close\r\n", "\nX: 1\r\n",
            "Connection:keep-alive\u{a0}\r\n", "Connection: \u{85}close\r\n", "X-\u{e9}: v\r\n",
        ];
        let mut scanned = 0;
        for st in starts {
            for a in lines {
                for b in lines {
                    let head = format!("{st}\r\n{a}{b}\r\n");
                    let h = head.as_bytes();
                    for request in [true, false] {
                        assert_eq!(htx_head_size(h, request), htx_head_size_general(h, request), "{head:?} {request}");
                    }
                    assert_eq!(head_wants_close(&head), head_wants_close_general(&head), "{head:?}");
                    // T436: the one-pass facts check themselves against these readings.
                    for request in [true, false] {
                        if let Some(f) = HeadFacts::scan(h, request) {
                            assert_eq!(f.wants_close(), head_wants_close_general(&head), "{head:?}");
                            scanned += 1;
                        }
                    }
                    for v in [a, b] {
                        let v = v.split_once(':').map_or(v, |(_, v)| v);
                        let general = v.split(',').map(str::trim).all(|t| t.is_empty() || t.eq_ignore_ascii_case("keep-alive") || t.eq_ignore_ascii_case("close"));
                        assert_eq!(connection_is_plain(v), general, "{v:?}");
                    }
                }
            }
        }
        assert!(scanned > 1000, "the facts were read from {scanned} heads only");
    }

    /// The one-pass reading of the framing fields gives what the general one gives, on the
    /// heads it answers for, and leaves the others to it.
    #[test]
    fn framing_fast_path_reads_as_fields() {
        let lines = [
            "", "Host: x\r\n", "Content-Length: 5\r\n", "content-length:5 \r\n", "Content-Length: 5, 5\r\n",
            "Content-Length: 5\r\nContent-Length: 6\r\n", "Content-Length: 0\r\n", "Content-Length: +5\r\n",
            "Content-Length:\r\n", "Transfer-Encoding: chunked\r\n", "transfer-encoding: gzip\r\n",
            "Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n", "Transfer-Encoding:\r\n chunked\r\n",
            "Transfer-Encoding: gzip,\r\n\tchunked\r\n", "\u{a0}Content-Length: 7\r\n", "\u{b}Content-Length: 7\r\n",
            "\u{c}transfer-encoding: chunked\r\n", "Content-Length\u{85}: 7\r\n", "Content-Length: 7\u{a0}\r\n",
            "Cookie: \u{e9}\r\n", "Content-Length 7\r\n", "X: 1\r\nContent-Length: 4\r\n", "Content-Length : 3 \r\r\n",
            "TE: x\r\n", "Content-Length: 1\r\nContent-Length: 1\r\nContent-Length: 1\r\nContent-Length: 1\r\nContent-Length: 1\r\n",
            "Content-Length: 4\n", "junk\r\n Content-Length: 9\r\n",
        ];
        for a in lines {
            for b in lines {
                let req = format!("POST / HTTP/1.1\r\n{a}{b}\r\n");
                assert_eq!(request_framing(req.as_bytes()), request_framing_general(req.as_bytes()), "{req:?}");
                let rsp = format!("HTTP/1.1 200 OK\r\n{a}{b}\r\n");
                assert_eq!(response_framing(&rsp, Some("GET"), 200), response_body_framing(fields(&rsp), fields(&rsp)), "{rsp:?}");
                if let Some(f) = HeadFacts::scan(req.as_bytes(), true) {
                    assert_eq!(f.framing.unwrap_or_else(|| request_framing_general(req.as_bytes())), request_framing(req.as_bytes()), "{req:?}");
                }
                if let Some(f) = HeadFacts::scan(rsp.as_bytes(), false) {
                    assert_eq!(f.response_framing(Some("GET"), 200).unwrap_or_else(|| response_framing_general(&rsp)), response_framing(&rsp, Some("GET"), 200), "{rsp:?}");
                    assert_eq!(f.response_framing(Some("HEAD"), 200), Some(Framing::None));
                }
            }
        }
        // Not UTF-8: read lossily, as before.
        for head in [&b"POST / HTTP/1.1\r\nContent-Length: 5\xff\r\n\r\n"[..], b"POST / HTTP/1.1\r\nX: \xff\r\nContent-Length: 5\r\n\r\n"] {
            assert_eq!(request_framing(head), request_framing_general(head));
        }
        assert_eq!(request_framing(b"POST / HTTP/1.1\r\nX: \xff\r\nContent-Length: 5\r\n\r\n"), Framing::Length(5));
    }

    #[test]
    fn fields_join_folds_without_copying_the_rest() {
        let got: Vec<(&str, std::borrow::Cow<'_, str>)> =
            fields("GET / HTTP/1.1\r\n \tlost\r\nA:  1 \r\n b \r\njunk\r\n\tc\r\nB:2\r\n\r\n").collect();
        assert_eq!(got, [("A", "1 b c".into()), ("B", "2".into())]);
        assert!(matches!(got[1].1, std::borrow::Cow::Borrowed(_)));
        assert_eq!(
            request_framing(b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip,\r\n chunked\r\n\r\n"),
            Framing::Chunked
        );
        assert_eq!(response_framing("HTTP/1.1 200 OK\r\nContent-Length: 5,\r\n 5\r\n\r\n", None, 200), Framing::Length(5));
    }

    #[test]
    fn request_framing_and_close() {
        assert_eq!(request_framing(b"POST / HTTP/1.1\r\ncontent-length: 7\r\n\r\n"), Framing::Length(7));
        assert_eq!(request_framing(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), Framing::Chunked);
        assert_eq!(request_framing(b"GET / HTTP/1.1\r\n\r\n"), Framing::None);
        assert!(head_wants_close("GET / HTTP/1.1\r\nConnection: Close\r\n\r\n"));
        assert!(head_wants_close("GET / HTTP/1.0\r\n\r\n"));
        assert!(!head_wants_close("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n"));
        assert!(!head_wants_close("GET / HTTP/1.1\r\n\r\n"));
    }

    #[test]
    fn an_interim_response_makes_room_for_the_final_one() {
        let mut t = HttpTxn::new(Framing::None, false);
        t.rsp = MsgState::head(Framing::None);
        t.rsp_interim = true;
        let rep = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200";
        t.response_sent(rep, 25);
        assert_eq!(t.rsp, MsgState::Waiting);
        assert!(!t.rsp_interim);
    }

    #[test]
    fn take_body_unframes_a_chunked_body_and_stops_at_the_limit() {
        let mut s = MsgState::Body(Body::Chunked(CHUNK_START));
        let wire = b"5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n";
        let mut out = Vec::new();
        let n = s.take_body(wire, 6, &mut out);
        assert_eq!(out, b"helloa");
        assert!(matches!(s, MsgState::Body(Body::Chunked(Chunk::Data(2)))));
        let n2 = s.take_body(&wire[n..], 100, &mut out);
        assert_eq!(out, b"helloabc");
        assert_eq!(n + n2, wire.len());
        assert_eq!(s, MsgState::Done);
    }

    #[test]
    fn take_body_with_no_room_still_consumes_the_closing_framing() {
        let mut s = MsgState::Body(Body::Chunked(Chunk::DataCr));
        let mut out = Vec::new();
        assert_eq!(s.take_body(b"\r\n0\r\n\r\n", 0, &mut out), 7);
        assert!(out.is_empty());
        assert_eq!(s, MsgState::Done);
    }

    #[test]
    fn take_body_refuses_a_malformed_chunk_and_moves_nothing_else() {
        let mut s = MsgState::Body(Body::Chunked(CHUNK_START));
        let mut out = Vec::new();
        s.take_body(b"zz\r\n", 10, &mut out);
        assert_eq!(s, MsgState::Error);
        let mut w = MsgState::Waiting;
        assert_eq!(w.take_body(b"abc", 10, &mut out), 0);
    }

    #[test]
    fn take_body_length_and_until_close() {
        let mut s = MsgState::Body(Body::Length(4));
        let mut out = Vec::new();
        assert_eq!(s.take_body(b"abcdefg", 100, &mut out), 4);
        assert_eq!((out.as_slice(), s), (&b"abcd"[..], MsgState::Done));
        let mut u = MsgState::Body(Body::UntilClose);
        out.clear();
        assert_eq!(u.take_body(b"xyz", 2, &mut out), 2);
        assert_eq!(out, b"xy");
        assert_eq!(u, MsgState::Body(Body::UntilClose));
    }

    /// What `canonical_chunk_lines` leaves of `data` from state `s`.
    fn canonical(s: MsgState, data: &[u8]) -> Vec<u8> {
        let mut d = data.to_vec();
        let n = s.canonical_chunk_lines(&mut d, false);
        d.truncate(n);
        d
    }

    /// T381: a whole trailer section is cut to the blank line; a partial one is left alone;
    /// what follows the message stays.
    #[test]
    fn a_trailer_section_is_cut_when_whole() {
        let drop = |data: &[u8]| {
            let mut d = data.to_vec();
            let n = MsgState::Body(Body::Chunked(CHUNK_START)).canonical_chunk_lines(&mut d, true);
            d.truncate(n);
            d
        };
        assert_eq!(drop(b"5\r\nhello\r\n0\r\nx-a: 1\r\ny: 2\r\n\r\nGET /"), b"5\r\nhello\r\n0\r\n\r\nGET /");
        assert_eq!(drop(b"0\r\n\r\n"), b"0\r\n\r\n");
        assert_eq!(drop(b"0\r\nx-a: 1\n\n"), b"0\r\n\r\n");
        assert_eq!(drop(b"0\r\nx-a: 1\r\n"), b"0\r\nx-a: 1\r\n", "not whole yet");
        assert_eq!(drop(b"0\r\nhost: 1\r\n\r\n"), b"0\r\nhost: 1\r\n\r\n", "a refused section is the check's to judge");
    }

    /// Size lines as `HAProxy` writes them (T302): extensions and blanks dropped, upper-case
    /// hex without leading zeros; a partial line, a violation and what follows the message
    /// left as they are.
    #[test]
    fn chunk_lines_are_rewritten_as_haproxy_writes_them() {
        let chunked = MsgState::head(Framing::Chunked);
        let head = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        let msg = [&head[..], b"0005;a=b\r\nhello\r\na ; x=\"y;z\"\r\n0123456789\r\n00;e\r\nT: 1\r\n\r\nGET / HTTP/1.1\r\n\r\n"].concat();
        let want = [&head[..], b"5\r\nhello\r\nA\r\n0123456789\r\n0\r\nt: 1\r\n\r\nGET / HTTP/1.1\r\n\r\n"].concat();
        assert_eq!(canonical(chunked, &msg), want);
        // The head measured already.
        let mut measured = chunked;
        measured.measure_head(&msg);
        assert_eq!(canonical(measured, &msg), want);
        // A head not whole yet, and a body that is not chunked: untouched.
        assert_eq!(canonical(chunked, b"POST / HTTP/1.1\r\n5;x\r\n"), b"POST / HTTP/1.1\r\n5;x\r\n");
        assert_eq!(canonical(MsgState::Body(Body::Length(9)), b"5;x\r\nhello"), b"5;x\r\nhello");
        // From inside a chunk's data; a partial line after a rewritten one, kept as it is.
        assert_eq!(canonical(MsgState::Body(Body::Chunked(Chunk::Data(3))), b"abc\r\n4;x\r\nabcd\r\n0;y"), b"abc\r\n4\r\nabcd\r\n0;y");
        // A violation, and all after it, kept as it is.
        assert_eq!(canonical(MsgState::Body(Body::Chunked(CHUNK_START)), b"1;x\r\nZ\r\n1;\x01\r\n"), b"1\r\nZ\r\n1;\x01\r\n");
        assert_eq!(canonical(MsgState::Body(Body::Chunked(CHUNK_START)), b"1;x\r\nZX1\r\n"), b"1\r\nZX1\r\n");
        // A canonical body is not moved; a lower-case size is only upper-cased.
        assert_eq!(canonical(MsgState::Body(Body::Chunked(CHUNK_START)), b"1F\r\n"), b"1F\r\n");
        assert_eq!(canonical(MsgState::Body(Body::Chunked(CHUNK_START)), b"1f\r\n"), b"1F\r\n");
        let mut line = [0u8; 18];
        let n = chunk_size_line((1 << 52) - 1, &mut line);
        assert_eq!(&line[..n], b"FFFFFFFFFFFFF\r\n");
    }

    /// T302: trailer names are lowercased.
    #[test]
    fn trailer_names_are_lowercased_in_chunked_lines() {
        let chunked = MsgState::head(Framing::Chunked);
        let head = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        let msg = [&head[..], b"3\r\nabc\r\n0\r\nX-T: V\r\n\r\nNEXT"].concat();
        let want = [&head[..], b"3\r\nabc\r\n0\r\nx-t: V\r\n\r\nNEXT"].concat();
        assert_eq!(canonical(chunked, &msg), want);
    }

    #[test]
    fn a_close_is_added_as_the_last_header_with_the_line_ends_the_head_has() {
        // Exact bytes: `contains` passed while the header was glued onto the previous one
        // ("Content-Length: 2Connection: close") and a blank line was added.
        assert_eq!(
            rewrite_response_connection("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", true, true, false).as_deref(),
            Some("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n")
        );
        assert_eq!(
            rewrite_response_connection("HTTP/1.1 200 OK\nContent-Length: 2\n\n", true, true, false).as_deref(),
            Some("HTTP/1.1 200 OK\nContent-Length: 2\nConnection: close\n\n")
        );
    }

    #[test]
    fn keep_alive_is_taken_out_of_a_response_and_the_others_stay() {
        let head = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n\r\n";
        assert_eq!(rewrite_response_connection(head, false, true, false).as_deref(), Some("HTTP/1.1 200 OK\r\nKeep-Alive: timeout=5\r\n\r\n"));
        let head = "HTTP/1.1 200 OK\r\nConnection: x-foo, Keep-Alive\r\n\r\n";
        assert_eq!(rewrite_response_connection(head, false, true, false).as_deref(), Some("HTTP/1.1 200 OK\r\nConnection: x-foo\r\n\r\n"));
        // Nothing to take out, nothing to add: the head is left alone.
        assert_eq!(rewrite_response_connection("HTTP/1.1 200 OK\r\nConnection: upgrade\r\n\r\n", false, true, false), None);
    }

    #[test]
    fn the_connection_token_added_follows_the_versions_and_the_state() {
        assert_eq!(response_connection_token(false, true, true, false), None);
        assert_eq!(response_connection_token(false, true, false, false), Some("keep-alive"));
        assert_eq!(response_connection_token(false, false, true, false), Some("keep-alive"));
        assert_eq!(response_connection_token(true, true, true, false), Some("close"));
        assert_eq!(response_connection_token(true, false, true, false), None);
        assert_eq!(request_connection_token(true, true, false), Some("close"));
        assert_eq!(request_connection_token(false, false, false), Some("keep-alive"));
        assert_eq!(request_connection_token(true, false, false), None);
        assert_eq!(request_connection_token(true, true, true), None);
    }

    #[test]
    fn a_connection_header_of_keep_alive_and_close_only_is_plain() {
        assert!(connection_is_plain(" Keep-Alive , close"));
        assert!(!connection_is_plain("keep-alive, upgrade"));
        let none = scan_connection(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!((none.count, none.plain), (0, true));
        let one = b"HTTP/1.1 200 OK\r\nA: b\r\nconnection : close\r\nC: d\r\n\r\n";
        let s = scan_connection(one);
        assert_eq!((s.count, s.plain), (1, true));
        assert_eq!(&one[s.first.0..s.first.1], b"connection : close\r\n");
        let two = scan_connection(b"HTTP/1.1 200 OK\r\nConnection: close\r\nConnection: te\r\n\r\n");
        assert_eq!((two.count, two.plain), (2, false));
        // Another header that starts with the name is not one.
        assert_eq!(scan_connection(b"HTTP/1.1 200 OK\r\nConnection-Id: close\r\n\r\n").count, 0);
        // A body that looks like a header is not one.
        assert_eq!(scan_connection(b"HTTP/1.1 200 OK\r\n\r\nConnection: close\r\n").count, 0);
    }

    #[test]
    fn a_list_of_headers_is_cleaned_like_a_head() {
        let mut h = vec![("Connection".to_string(), "x-foo, keep-alive".to_string()), ("Connection".to_string(), "close".to_string())];
        apply_response_connection(&mut h, true, false, true, false);
        assert_eq!(h, vec![("Connection".to_string(), "x-foo".to_string())]);
        let mut h = vec![("Connection".to_string(), "upgrade".to_string())];
        apply_response_connection(&mut h, true, false, true, false);
        assert_eq!(h, vec![("Connection".to_string(), "upgrade".to_string())], "an upgrade is left alone");
        let mut h = Vec::new();
        apply_response_connection(&mut h, true, true, true, false);
        assert_eq!(h, vec![("Connection".to_string(), "close".to_string())]);
        apply_response_connection(&mut Vec::new(), true, false, true, true);
    }

    #[test]
    fn a_head_without_an_end_is_left_alone() {
        assert_eq!(rewrite_response_connection("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n", false, true, false), None);
    }
    /// Writes `section` (after a last-chunk line) through [`MsgState::canonical_chunk_lines`].
    fn trailers_of(section: &[u8]) -> Vec<u8> {
        let mut body = [b"0\r\n".as_slice(), section].concat();
        let n = MsgState::Body(Body::Chunked(CHUNK_START)).canonical_chunk_lines(&mut body, false);
        body.truncate(n);
        body
    }

    #[test]
    fn a_trailer_field_that_would_grow_is_written_in_place() {
        // HAProxy writes `x-a: v`; the byte it adds is not made room for.
        assert_eq!(trailers_of(b"X-A:v\r\n\r\n"), b"0\r\nx-a:v\r\n\r\n");
        assert_eq!(trailers_of(b"X-A:\r\n\r\n"), b"0\r\nx-a:\r\n\r\n");
        // Slack in the line is used for it.
        assert_eq!(trailers_of(b"X-A:v  \r\n\r\n"), b"0\r\nx-a: v\r\n\r\n");
    }

    #[test]
    fn a_trailer_section_not_whole_is_not_trimmed() {
        // `v  w` must not lose its blanks when `w` has not arrived yet.
        assert_eq!(trailers_of(b"x-a: v  "), b"0\r\nx-a: v  ");
        assert_eq!(trailers_of(b"x-a: v  \r\n"), b"0\r\nx-a: v  \r\n");
    }

    #[test]
    fn trailer_fields_are_trimmed_folded_and_lowercased() {
        assert_eq!(trailers_of(b"X-A: a\r\n b\r\nX-B:\t c \r\n\r\n"), b"0\r\nx-a: a   b\r\nx-b: c\r\n\r\n");
        // A pipelined request after the message is left as it is.
        assert_eq!(trailers_of(b"X-A:  v\r\n\r\nGET / HTTP/1.1\r\n\r\n"), b"0\r\nx-a: v\r\n\r\nGET / HTTP/1.1\r\n\r\n");
    }
    #[test]
    fn a_trailer_line_ended_by_a_lone_lf_has_no_room_for_the_space() {
        assert_eq!(trailers_of(b"X-A:v\n\r\n"), b"0\r\nx-a:v\n\r\n");
    }
}
