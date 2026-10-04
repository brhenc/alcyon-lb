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
    Size { size: u64, digits: u8 },
    Ext { size: u64 },
    SizeLf { size: u64 },
    Data(u64),
    DataCr,
    DataLf,
    /// In the trailer section; `empty` while the current line has no bytes yet.
    Trailer { empty: bool },
    TrailerLf { empty: bool },
}

const CHUNK_START: Chunk = Chunk::Size { size: 0, digits: 0 };

impl Chunk {
    /// Scans `data`; returns how many bytes belong to the body and the state after them:
    /// `Ok(Some(_))` wants more, `Ok(None)` is the end of the message, `Err` is a framing
    /// violation (the bytes counted are the valid ones before it).
    fn scan(mut self, data: &[u8]) -> (usize, Result<Option<Chunk>, ()>) {
        let mut i = 0;
        while i < data.len() {
            if let Chunk::Data(n) = self {
                let take = usize::try_from(n).unwrap_or(usize::MAX).min(data.len() - i);
                i += take;
                let left = n - take as u64;
                self = if left == 0 { Chunk::DataCr } else { Chunk::Data(left) };
                continue;
            }
            let b = data[i];
            i += 1;
            let end_of_size = |size: u64, digits: u8| -> Result<Chunk, ()> {
                match (digits, size) {
                    (0, _) => Err(()),
                    (_, 0) => Ok(Chunk::Trailer { empty: true }),
                    (_, n) => Ok(Chunk::Data(n)),
                }
            };
            let next = match self {
                Chunk::Size { size, digits } => match b {
                    b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                        // 16 hex digits fill a u64; one more is an overflow, not a size.
                        if digits >= 16 {
                            Err(())
                        } else {
                            let d = u64::from(char::from(b).to_digit(16).unwrap_or(0));
                            Ok(Chunk::Size { size: (size << 4) | d, digits: digits + 1 })
                        }
                    }
                    b';' | b' ' | b'\t' if digits > 0 => Ok(Chunk::Ext { size }),
                    b'\r' if digits > 0 => Ok(Chunk::SizeLf { size }),
                    b'\n' => end_of_size(size, digits),
                    _ => Err(()),
                },
                Chunk::Ext { size } => match b {
                    b'\r' => Ok(Chunk::SizeLf { size }),
                    b'\n' => end_of_size(size, 1),
                    _ => Ok(Chunk::Ext { size }),
                },
                Chunk::SizeLf { size } => match b {
                    b'\n' => end_of_size(size, 1),
                    _ => Err(()),
                },
                Chunk::DataCr => match b {
                    b'\r' => Ok(Chunk::DataLf),
                    b'\n' => Ok(CHUNK_START),
                    _ => Err(()),
                },
                Chunk::DataLf => match b {
                    b'\n' => Ok(CHUNK_START),
                    _ => Err(()),
                },
                Chunk::Trailer { empty } => match b {
                    b'\r' => Ok(Chunk::TrailerLf { empty }),
                    b'\n' if empty => return (i, Ok(None)),
                    b'\n' => Ok(Chunk::Trailer { empty: true }),
                    _ => Ok(Chunk::Trailer { empty: false }),
                },
                Chunk::TrailerLf { empty } => match b {
                    b'\n' if empty => return (i, Ok(None)),
                    b'\n' => Ok(Chunk::Trailer { empty: true }),
                    _ => Err(()),
                },
                Chunk::Data(_) => unreachable!("handled above"),
            };
            match next {
                Ok(c) => self = c,
                Err(()) => return (i - 1, Err(())),
            }
        }
        (i, Ok(Some(self)))
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
        let mut used = 0;
        loop {
            match *self {
                MsgState::Waiting | MsgState::Done | MsgState::Error => return used,
                MsgState::Tunnel | MsgState::Body(Body::UntilClose) => return data.len(),
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
                        return data.len();
                    }
                    used += usize::try_from(n).unwrap_or(usize::MAX);
                    *self = MsgState::Done;
                }
                MsgState::Body(Body::Chunked(c)) => {
                    let (n, next) = c.scan(&data[used..]);
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
                    let (n, next) = c.scan(&data[i..=i]);
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
        if let MsgState::Head { left: 0, body } = *self {
            if let Some((h, e)) = find_eoh(data) {
                *self = MsgState::Head { left: h + e, body };
            }
        }
    }

    /// Records that the first `n` bytes of `data` -- which starts at this message's
    /// current position and is what [`Self::window`] measured -- were forwarded. A head
    /// is measured on all of `data` first: a partial send may stop inside it.
    pub fn consume(&mut self, data: &[u8], n: usize) {
        self.measure_head(data);
        let used = self.advance(&data[..n]);
        debug_assert_eq!(used, n, "forwarded past the end of the message");
    }

    /// How many bytes at the front of `data` belong to this message, without moving.
    #[must_use]
    pub fn window(&self, data: &[u8]) -> usize {
        let mut s = *self;
        s.advance(data)
    }

    #[must_use]
    pub fn is_done(&self) -> bool {
        *self == MsgState::Done
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

/// Header value of `name` in a raw head, the first occurrence.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split('\n').skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn chunked(head: &str) -> bool {
    header(head, "transfer-encoding")
        .is_some_and(|v| v.rsplit(',').next().is_some_and(|last| last.trim().eq_ignore_ascii_case("chunked")))
}

/// How a request body is framed, from its head. A request without a length has no body
/// (RFC 9112 section 6.3, rule 7). `Transfer-Encoding` wins over `Content-Length`; the
/// proxy removes the `Content-Length` of such a request before this is asked.
#[must_use]
pub fn request_framing(head: &[u8]) -> Framing {
    let head = String::from_utf8_lossy(head);
    if chunked(&head) {
        return Framing::Chunked;
    }
    match header(&head, "content-length").and_then(|v| v.parse::<u64>().ok()) {
        Some(0) | None => Framing::None,
        Some(n) => Framing::Length(n),
    }
}

/// How a response body is framed, from its head and the request it answers.
#[must_use]
pub fn response_framing(head: &str, req_method: Option<&str>, status: u16) -> Framing {
    let is = |m: &str| req_method.is_some_and(|r| r.eq_ignore_ascii_case(m));
    if status == 101 || (is("CONNECT") && (200..300).contains(&status)) {
        return Framing::Tunnel;
    }
    if is("HEAD") || (100..200).contains(&status) || status == 204 || status == 304 {
        return Framing::None;
    }
    if header(head, "transfer-encoding").is_some() {
        return if chunked(head) { Framing::Chunked } else { Framing::UntilClose };
    }
    match header(head, "content-length").and_then(|v| v.parse::<u64>().ok()) {
        Some(n) => Framing::Length(n),
        None => Framing::UntilClose,
    }
}

/// Whether a head asks for the connection to close after this message: `Connection:
/// close`, or HTTP/1.0 without `Connection: keep-alive`.
#[must_use]
pub fn head_wants_close(head: &str) -> bool {
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

/// The status of a response head, 0 if the status line does not parse.
#[must_use]
pub fn status_of(head: &str) -> u16 {
    head.split('\n')
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.trim().parse().ok())
        .unwrap_or(0)
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
    /// The one decision to close the client connection once this transaction ends.
    pub close_after: bool,
    /// The server may keep its connection once this response is done.
    pub srv_reusable: bool,
    /// The client asked for a HEAD. The response is framed by the method the server
    /// answered (a rule may have rewritten it), and the client gets its head alone.
    pub client_head: bool,
    /// The request went out on a server connection that had already carried one
    /// (`HAProxy`'s `SF_SRV_REUSED`). If it closes before any response, the client
    /// connection is closed with nothing sent, so the client retries.
    pub srv_reused: bool,
    /// A reply owed to the client that the byte layer could not produce itself (it has no
    /// access to the error pages): a request that failed to parse.
    pub error: Option<u16>,
    /// The response was cut short (the server went away mid-body, or a tunnel side
    /// closed): what arrived is delivered and the connection closes.
    pub aborted: bool,
    /// What the request's cookies told the backend's `cookie` persistence, which the
    /// response needs (`SF_DIRECT`, `cookie_first_date`, `cookie_last_date`).
    pub ck: crate::cookie::CookieTxn,
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
            close_after,
            srv_reusable: true,
            srv_reused: false,
            client_head: false,
            error: None,
            aborted: false,
            ck: crate::cookie::CookieTxn::default(),
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
        self.rsp.consume(rep, n);
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let body = b"H\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let mut s = MsgState::head(Framing::Chunked);
        assert_eq!(s.advance(body.as_slice().split_at(5).0), 5);
        for (i, b) in body[5..].iter().enumerate() {
            assert!(!s.is_done(), "done early at byte {i}");
            assert_eq!(s.advance(std::slice::from_ref(b)), 1);
        }
        assert!(s.is_done());
    }

    #[test]
    fn a_malformed_chunk_size_is_an_error() {
        for bad in [&b"H\r\n\r\nzz\r\n"[..], b"H\r\n\r\n\r\n", b"H\r\n\r\n11111111111111111\r\n", b"H\r\n\r\n2\r\nabX"] {
            let (_, s) = fwd(MsgState::head(Framing::Chunked), bad);
            assert_eq!(s, MsgState::Error, "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn bare_lf_chunk_framing_is_accepted() {
        // Sizes, data ends and the last line ended by LF alone; an extension ended by LF; a
        // trailer line ended by LF before the blank one.
        for body in [
            &b"H\r\n\r\n5\nhello\n0\n\nNEXT"[..],
            b"H\r\n\r\n5;x\nhello\r\n0\r\n\r\nNEXT",
            b"H\r\n\r\n0\r\nX: y\n\nNEXT",
        ] {
            let (n, s) = fwd(MsgState::head(Framing::Chunked), body);
            assert_eq!((&body[n..], s), (&b"NEXT"[..], MsgState::Done), "{:?}", String::from_utf8_lossy(body));
        }
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
}
