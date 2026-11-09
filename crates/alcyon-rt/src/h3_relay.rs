// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The HTTP/3 request stream as the stream engine sees it (T130).
//!
//! An HTTP/3 request is handed to the engine the way an HTTP/2 stream is: as the HTTP/1
//! message its HTX converts to (`to_h1_wire`), which the engine parses and runs through the
//! same request analysers, backend selection and server connection as any other request.
//! The QUIC listener writes that message into one end of a socket pair and the engine
//! adopts the other end as a client connection of the frontend; what the engine answers on
//! it is converted back into HEADERS and DATA frames here.
//!
//! Everything that crosses from HTTP/3 into HTTP/1 is checked first, because the H1 parser
//! on the other side would take a CR LF in a field value, or a body longer than its
//! `content-length`, as the start of another request.

use alcyon_proto::h3::parse_varint;
use alcyon_proto::htx::HtxBlock;
use alcyon_proto::mux_h3;
use alcyon_proto::qpack;

use crate::txn::Framing;

const FRAME_DATA: u64 = 0x00;
const FRAME_HEADERS: u64 = 0x01;

/// Connection-specific fields, malformed in an HTTP/3 request (RFC 9114 section 4.2) and
/// dropped from an HTTP/1 response before it is framed for HTTP/3.
const HOP_BY_HOP: [&str; 5] = ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"];

/// One complete frame at the start of `buf`: its type, payload range and total length.
/// `Ok(None)` when it has not fully arrived.
///
/// # Errors
/// A frame length that cannot be represented.
pub fn next_frame(buf: &[u8]) -> Result<Option<(u64, std::ops::Range<usize>, usize)>, ()> {
    let mut off = 0usize;
    let Ok(ty) = parse_varint(buf, &mut off) else { return Ok(None) };
    let Ok(len) = parse_varint(buf, &mut off) else { return Ok(None) };
    let len = usize::try_from(len).map_err(|_| ())?;
    let end = off.checked_add(len).ok_or(())?;
    if end > buf.len() {
        return Ok(None);
    }
    Ok(Some((ty, off..end, end)))
}

/// The request's HEADERS field section and the offset just past it. Unknown (grease)
/// frames before it are skipped; DATA before HEADERS is malformed (RFC 9114 section 4.1).
///
/// # Errors
/// A malformed frame sequence.
pub fn first_headers(buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>, ()> {
    let mut off = 0usize;
    while let Some((ty, range, end)) = next_frame(&buf[off..])? {
        match ty {
            FRAME_HEADERS => return Ok(Some((buf[off + range.start..off + range.end].to_vec(), off + end))),
            FRAME_DATA => return Err(()),
            _ => off += end,
        }
    }
    Ok(None)
}

/// How the request body is framed towards the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReqBody {
    /// Exactly this many bytes are still to come (a `content-length`).
    Length(u64),
    /// Length unknown when the head went out: chunked.
    Chunked,
}

/// Why a request has no HTTP/1 head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadError {
    /// The field section does not decode: close the connection with
    /// `QPACK_DECOMPRESSION_FAILED` (RFC 9204 section 2.2.3), as `HAProxy` does (measured on
    /// 3.5-dev7 +QUIC for a required insert count of 1, T454).
    Decompression,
    /// The request is malformed (RFC 9114 section 4.1.2): reset the stream with
    /// `H3_MESSAGE_ERROR` and answer nothing, as `HAProxy`'s `h3_req_headers_to_htx` does.
    /// Includes a field with a byte that is not UTF-8 (T454; `qpack::text_of`).
    Message,
}

/// The HTTP/1 head of an HTTP/3 request.
pub struct RequestHead {
    pub head: Vec<u8>,
    pub body: ReqBody,
    pub method_head: bool,
}

/// Builds the HTTP/1 head for a decoded field section. `known_body` is the body length when
/// the whole request is already here (FIN seen): checked against a `content-length`; without
/// one the body still goes chunked, as `HAProxy` 3.5-dev7 with QUIC forwards it (measured,
/// T511), and a bodyless request (`Some(0)`) gets no framing field.
///
/// # Errors
/// [`HeadError`]: `Decompression` for a field section that does not decode, `Message` for a
/// malformed request.
pub fn request_head(field_section: &[u8], known_body: Option<u64>) -> Result<RequestHead, HeadError> {
    let fields = qpack::decode_qpack_static(field_section).map_err(|_| HeadError::Decompression)?;
    // The checks HTTP/2 makes (T449), on the fields as decoded: a name that is no lowercase
    // token, a value with CR, LF or NUL, `:path`, `:authority`, `host`, `:scheme` and
    // `:method` that `HAProxy` refuses, connection-specific fields. T454: a byte that is not
    // UTF-8 is a NUL by now (`qpack::text_of`), so it ends here.
    match alcyon_proto::h2::check_request_fields(fields.iter().map(|f| (f.name.as_bytes(), f.value.as_bytes())), false) {
        Ok(false) => {}
        Ok(true) | Err(_) => return Err(HeadError::Message),
    }
    // RFC 9114 section 4.3.1: `:authority` or `host` is mandatory for http(s).
    if !fields.iter().any(|f| f.name == ":authority" || f.name == "host") {
        return Err(HeadError::Message);
    }
    let blocks = alcyon_proto::h3::headers_to_htx(fields).map_err(|_| HeadError::Message)?;
    let mut head = Vec::with_capacity(256);
    let mut content_length: Option<u64> = None;
    let mut method_head = false;
    let mut cookies: Vec<String> = Vec::new();
    for block in &blocks {
        match block {
            HtxBlock::ReqLine(rl) => {
                let m = rl.method.as_str();
                // The method and the URI (an empty `:path` too) were checked above.
                method_head = m == "HEAD";
                head.extend_from_slice(format!("{m} {} HTTP/1.1\r\n", rl.uri).as_bytes());
            }
            HtxBlock::Header(h) => {
                let name = h.name.as_str();
                if name == "content-length" {
                    let v = content_length_value(&h.value).ok_or(HeadError::Message)?;
                    if content_length.is_some_and(|c| c != v) {
                        return Err(HeadError::Message);
                    }
                    // Written once, as the number it stands for, after the other fields:
                    // the server reads the length the DATA frames are held to, not a
                    // spelling of it (`HAProxy` keeps the cleaned value).
                    content_length = Some(v);
                    continue;
                }
                // HTTP/3 may split cookies over several fields; HTTP/1 wants one
                // (RFC 9114 section 4.2.1).
                if name == "cookie" {
                    cookies.push(h.value.clone());
                    continue;
                }
                head.extend_from_slice(name.as_bytes());
                head.extend_from_slice(b": ");
                head.extend_from_slice(h.value.as_bytes());
                head.extend_from_slice(b"\r\n");
            }
            _ => {}
        }
    }
    if !cookies.is_empty() {
        head.extend_from_slice(format!("cookie: {}\r\n", cookies.join("; ")).as_bytes());
    }
    let body = match (content_length, known_body) {
        (Some(cl), Some(n)) if cl != n => return Err(HeadError::Message),
        (Some(cl), _) => {
            head.extend_from_slice(format!("content-length: {cl}\r\n").as_bytes());
            ReqBody::Length(cl)
        }
        (None, Some(0)) => ReqBody::Length(0),
        // A body without `content-length` goes chunked, also when all of it came with the
        // head (measured on `HAProxy` 3.5-dev7 with QUIC, T511).
        (None, Some(_) | None) => {
            head.extend_from_slice(b"transfer-encoding: chunked\r\n");
            ReqBody::Chunked
        }
    };
    head.extend_from_slice(b"\r\n");
    Ok(RequestHead { head, body, method_head })
}

/// A `content-length` value as `HAProxy`'s `http_parse_cont_len_header` reads it: digits
/// only, or a comma list of one repeated number. `+5`, `0x5`, an empty element or two
/// different numbers are not a length.
fn content_length_value(v: &str) -> Option<u64> {
    let mut len = None;
    for word in v.split(',').map(|w| w.trim_matches([' ', '\t'])) {
        if word.is_empty() || !word.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n: u64 = word.parse().ok()?;
        if len.is_some_and(|l| l != n) {
            return None;
        }
        len = Some(n);
    }
    len
}

/// Total DATA payload in `buf` if it holds only complete frames, else `None`.
#[must_use]
pub fn complete_body_len(mut buf: &[u8]) -> Option<u64> {
    let mut n = 0u64;
    while !buf.is_empty() {
        let (ty, range, end) = next_frame(buf).ok()??;
        if ty == FRAME_DATA {
            n += range.len() as u64;
        }
        buf = &buf[end..];
    }
    Some(n)
}

/// The request body on its way to the engine: how it is framed for HTTP/1, and the frame
/// the client is in the middle of. A DATA frame is forwarded as its bytes arrive, so a
/// client cannot make the listener buffer a whole frame of whatever length it announces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyState {
    pub mode: ReqBody,
    /// The frame in progress: whether it is DATA, and how many payload bytes are left.
    frame: Option<(bool, u64)>,
}

impl BodyState {
    #[must_use]
    pub const fn new(mode: ReqBody) -> Self {
        Self { mode, frame: None }
    }

    /// Moves what `rx` holds of the body into `out`, framed for HTTP/1. Other frames
    /// (trailers, grease) are skipped.
    ///
    /// # Errors
    /// The request is malformed: more DATA than its `content-length`, or a bad frame.
    pub fn take(&mut self, rx: &mut Vec<u8>, out: &mut Vec<u8>) -> Result<(), ()> {
        let mut used = 0;
        loop {
            if let Some((is_data, left)) = self.frame {
                let n = usize::try_from(left).unwrap_or(usize::MAX).min(rx.len() - used);
                if n == 0 {
                    break;
                }
                if is_data {
                    self.forward(&rx[used..used + n], out)?;
                }
                used += n;
                let left = left - n as u64;
                self.frame = (left > 0).then_some((is_data, left));
                continue;
            }
            let mut off = used;
            let Ok(ty) = parse_varint(rx, &mut off) else { break };
            let Ok(len) = parse_varint(rx, &mut off) else { break };
            used = off;
            // A DATA frame is held to the `content-length` when its header arrives, before
            // any of its payload goes on (`HAProxy` adds the frame length to the total
            // first): the part of an oversized frame that would complete the length must
            // not reach the server as a whole request (RFC 9114 section 4.1.2).
            if ty == FRAME_DATA && matches!(self.mode, ReqBody::Length(left) if len > left) {
                return Err(());
            }
            self.frame = (len > 0).then_some((ty == FRAME_DATA, len));
        }
        rx.drain(..used);
        Ok(())
    }

    fn forward(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
        match &mut self.mode {
            ReqBody::Length(left) => {
                let n = payload.len() as u64;
                if n > *left {
                    return Err(());
                }
                *left -= n;
                out.extend_from_slice(payload);
            }
            ReqBody::Chunked => {
                out.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
                out.extend_from_slice(payload);
                out.extend_from_slice(b"\r\n");
            }
        }
        Ok(())
    }

    /// The end of the request body, once the client finished its stream and `take` has
    /// consumed everything.
    ///
    /// # Errors
    /// The stream ended inside a frame or before the announced `content-length`.
    pub fn end(&self, rx: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
        if self.frame.is_some() || !rx.is_empty() {
            return Err(());
        }
        match self.mode {
            ReqBody::Length(0) => Ok(()),
            ReqBody::Length(_) => Err(()),
            ReqBody::Chunked => {
                out.extend_from_slice(b"0\r\n\r\n");
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RespState {
    Head,
    Length(u64),
    ChunkSize,
    ChunkData(u64),
    ChunkDataEnd,
    Trailers,
    UntilClose,
    Done,
}

/// The engine's HTTP/1 response, converted to HTTP/3 frames as it arrives.
pub struct ResponseConv {
    state: RespState,
    buf: Vec<u8>,
    head_request: bool,
    /// The HEADERS frame went out: an error past this point can only cut the stream.
    pub head_sent: bool,
}

/// Bounds what is buffered while a head or a chunk-size line is incomplete.
const MAX_HEAD: usize = 64 * 1024;

impl ResponseConv {
    #[must_use]
    pub const fn new(head_request: bool) -> Self {
        Self { state: RespState::Head, buf: Vec::new(), head_request, head_sent: false }
    }

    #[must_use]
    pub fn is_done(&self) -> bool {
        self.state == RespState::Done
    }

    /// Converts `data`, appending HTTP/3 frames to `out`.
    ///
    /// # Errors
    /// The response cannot be parsed.
    pub fn feed(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
        self.buf.extend_from_slice(data);
        let mut pos = 0usize;
        loop {
            let rest = &self.buf[pos..];
            match self.state {
                RespState::Done => {
                    pos = self.buf.len();
                    break;
                }
                RespState::Head => {
                    let Some(end) = rest.windows(4).position(|w| w == b"\r\n\r\n") else {
                        if rest.len() > MAX_HEAD {
                            return Err(());
                        }
                        break;
                    };
                    let head = std::str::from_utf8(&rest[..end]).map_err(|_| ())?;
                    pos += end + 4;
                    let state = Self::on_head(self.head_request, head, out)?;
                    // An interim response leaves the state at `Head`: nothing went out.
                    self.head_sent |= state != RespState::Head;
                    self.state = state;
                }
                RespState::Length(left) => {
                    if rest.is_empty() {
                        break;
                    }
                    let n = rest.len().min(usize::try_from(left).unwrap_or(usize::MAX));
                    push_data(out, &rest[..n]);
                    pos += n;
                    let left = left - n as u64;
                    self.state = if left == 0 { RespState::Done } else { RespState::Length(left) };
                }
                RespState::UntilClose => {
                    push_data(out, rest);
                    pos = self.buf.len();
                    break;
                }
                RespState::ChunkSize => {
                    let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") else {
                        if rest.len() > MAX_HEAD {
                            return Err(());
                        }
                        break;
                    };
                    let line = std::str::from_utf8(&rest[..eol]).map_err(|_| ())?;
                    let hex = line.split(';').next().unwrap_or("").trim();
                    let size = u64::from_str_radix(hex, 16).map_err(|_| ())?;
                    pos += eol + 2;
                    self.state = if size == 0 { RespState::Trailers } else { RespState::ChunkData(size) };
                }
                RespState::ChunkData(left) => {
                    if rest.is_empty() {
                        break;
                    }
                    let n = rest.len().min(usize::try_from(left).unwrap_or(usize::MAX));
                    push_data(out, &rest[..n]);
                    pos += n;
                    let left = left - n as u64;
                    self.state = if left == 0 { RespState::ChunkDataEnd } else { RespState::ChunkData(left) };
                }
                RespState::ChunkDataEnd => {
                    if rest.len() < 2 {
                        break;
                    }
                    if &rest[..2] != b"\r\n" {
                        return Err(());
                    }
                    pos += 2;
                    self.state = RespState::ChunkSize;
                }
                RespState::Trailers => {
                    // Trailer fields are dropped; the message ends at the empty line.
                    let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") else {
                        if rest.len() > MAX_HEAD {
                            return Err(());
                        }
                        break;
                    };
                    pos += eol + 2;
                    if eol == 0 {
                        self.state = RespState::Done;
                    }
                }
            }
        }
        self.buf.drain(..pos);
        Ok(())
    }

    /// The engine closed its side. A response delimited by the close ends here.
    ///
    /// # Errors
    /// The response was cut short.
    pub fn eof(&mut self) -> Result<(), ()> {
        match self.state {
            RespState::UntilClose | RespState::Done => {
                self.state = RespState::Done;
                Ok(())
            }
            _ => Err(()),
        }
    }

    fn on_head(head_request: bool, head: &str, out: &mut Vec<u8>) -> Result<RespState, ()> {
        let mut lines = head.split("\r\n");
        let status_line = lines.next().ok_or(())?;
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().ok_or(())?;
        if !version.starts_with("HTTP/1.") {
            return Err(());
        }
        let status: u16 = parts.next().ok_or(())?.parse().map_err(|_| ())?;
        // Interim responses are not relayed; the final one follows.
        if (100..200).contains(&status) && status != 101 {
            return Ok(RespState::Head);
        }
        let mut fields = vec![(":status".to_string(), status.to_string())];
        for line in lines {
            let Some((n, v)) = line.split_once(':') else { return Err(()) };
            let name = n.trim().to_ascii_lowercase();
            let value = v.trim();
            if name == "content-length" && content_length_value(value).is_none() {
                return Err(());
            }
            if HOP_BY_HOP.contains(&name.as_str()) {
                continue;
            }
            fields.push((name, value.to_string()));
        }
        // Framed as the engine framed it for its HTTP/1 client: every `Transfer-Encoding`
        // line as one list, chunked only when `chunked` is the last coding (T281).
        let method = head_request.then_some("HEAD");
        let framing = crate::txn::response_framing(head, method, status);
        if !matches!(framing, Framing::Length(_) | Framing::None) {
            fields.retain(|(n, _)| n != "content-length");
        }
        let section = mux_h3::encode_field_section(&fields);
        mux_h3::encode_frame(out, FRAME_HEADERS, &section);
        Ok(match framing {
            Framing::None | Framing::Length(0) => RespState::Done,
            Framing::Length(n) => RespState::Length(n),
            Framing::Chunked => RespState::ChunkSize,
            Framing::UntilClose | Framing::Tunnel => RespState::UntilClose,
        })
    }
}

fn push_data(out: &mut Vec<u8>, payload: &[u8]) {
    if !payload.is_empty() {
        mux_h3::encode_frame(out, FRAME_DATA, payload);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `http_parse_cont_len_header`: a list of one repeated number is a length; two numbers, a
    /// sign or an empty element are not.
    #[test]
    fn a_content_length_list_must_repeat_one_digits_only_number() {
        assert_eq!(content_length_value("5"), Some(5));
        assert_eq!(content_length_value("5, 5"), Some(5));
        assert_eq!(content_length_value("5, 3"), None);
        assert_eq!(content_length_value("+5"), None);
        assert_eq!(content_length_value("5,"), None);
    }

    fn frame_bytes(ty: u64, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        mux_h3::encode_frame(&mut v, ty, payload);
        v
    }

    fn frames(mut b: &[u8]) -> Vec<(u64, Vec<u8>)> {
        let mut v = Vec::new();
        while let Some((t, r, end)) = next_frame(b).expect("frame") {
            v.push((t, b[r].to_vec()));
            b = &b[end..];
        }
        v
    }

    #[test]
    fn chunked_response_becomes_data_frames() {
        let mut c = ResponseConv::new(false);
        let mut out = Vec::new();
        c.feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-A: b\r\n\r\n5\r\nhel", &mut out).expect("feed");
        c.feed(b"lo\r\n0\r\n\r\n", &mut out).expect("feed");
        assert!(c.is_done());
        let f = frames(&out);
        assert_eq!(f.len(), 3);
        assert_eq!(f[0].0, FRAME_HEADERS);
        let mut body = Vec::new();
        for (_, p) in &f[1..] {
            body.extend_from_slice(p);
        }
        assert_eq!(body, b"hello");
    }

    #[test]
    fn interim_and_close_delimited() {
        let mut c = ResponseConv::new(false);
        let mut out = Vec::new();
        c.feed(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\nabc", &mut out).expect("feed");
        assert!(!c.is_done());
        c.eof().expect("eof");
        assert_eq!(frames(&out).len(), 2);
    }

    #[test]
    fn a_cut_response_is_an_error() {
        let mut c = ResponseConv::new(false);
        let mut out = Vec::new();
        c.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", &mut out).expect("feed");
        assert!(c.eof().is_err());
    }

    #[test]
    fn a_body_longer_than_its_length_is_refused() {
        let mut rx = Vec::new();
        mux_h3::encode_frame(&mut rx, FRAME_DATA, b"0123456789");
        let mut body = BodyState::new(ReqBody::Length(4));
        let mut out = Vec::new();
        assert!(body.take(&mut rx, &mut out).is_err());
    }

    #[test]
    fn crlf_in_a_value_is_refused() {
        let fields = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "x".to_string()),
            (":path".to_string(), "/".to_string()),
            ("x-a".to_string(), "a\r\nx-b: c".to_string()),
        ];
        let section = mux_h3::encode_field_section(&fields);
        assert_eq!(request_head(&section, Some(0)).err(), Some(HeadError::Message));
    }

    fn req(extra: &[(&str, &str)]) -> Vec<u8> {
        let mut fields: Vec<(String, String)> = [(":method", "POST"), (":scheme", "https"), (":authority", "x"), (":path", "/p")]
            .iter()
            .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
            .collect();
        fields.extend(extra.iter().map(|(n, v)| ((*n).to_string(), (*v).to_string())));
        mux_h3::encode_field_section(&fields)
    }

    fn head_of(extra: &[(&str, &str)], known: Option<u64>) -> Result<(String, ReqBody), HeadError> {
        request_head(&req(extra), known).map(|h| (String::from_utf8(h.head).expect("utf8"), h.body))
    }

    #[test]
    fn the_request_head_says_how_the_body_follows() {
        let (h, b) = head_of(&[], None).expect("head");
        assert!(h.starts_with("POST /p HTTP/1.1\r\nhost: x\r\n") && h.ends_with("transfer-encoding: chunked\r\n\r\n"), "{h}");
        assert_eq!(b, ReqBody::Chunked);
        // All of a body without `content-length` here with its head: still chunked, as
        // `HAProxy` 3.5-dev7 with QUIC forwards it (measured, T511).
        let (h, b) = head_of(&[], Some(5)).expect("head");
        assert!(h.ends_with("transfer-encoding: chunked\r\n\r\n") && !h.contains("content-length"), "{h}");
        assert_eq!(b, ReqBody::Chunked);
        let (h, b) = head_of(&[], Some(0)).expect("head");
        assert!(!h.contains("content-length") && !h.contains("chunked"), "{h}");
        assert_eq!(b, ReqBody::Length(0));
        let (h, b) = head_of(&[("content-length", "3"), ("content-length", "3")], None).expect("head");
        assert_eq!(h.matches("content-length").count(), 1, "{h}");
        assert_eq!(b, ReqBody::Length(3));
        let (h, _) = head_of(&[("cookie", "a=1"), ("cookie", "b=2")], Some(0)).expect("head");
        assert!(h.contains("cookie: a=1; b=2\r\n"), "{h}");
        assert!(head_of(&[("te", "trailers")], Some(0)).is_ok());
    }

    #[test]
    fn a_malformed_request_is_refused() {
        for extra in [
            &[("content-length", "3"), ("content-length", "4")][..],
            &[("content-length", "x")],
            &[("connection", "close")],
            &[("transfer-encoding", "chunked")],
            &[("te", "gzip")],
            &[("bad name", "a")],
        ] {
            assert_eq!(head_of(extra, None).err(), Some(HeadError::Message), "{extra:?}");
        }
        // An upper-case name, as a literal (the encoder lower-cases what it is given).
        let mut upper = req(&[]);
        upper.extend_from_slice(&[0x24, b'X', b'-', b'U', b'p', 0x01, b'a']);
        assert_eq!(request_head(&upper, Some(0)).err(), Some(HeadError::Message));
        assert_eq!(head_of(&[("content-length", "3")], Some(4)).err(), Some(HeadError::Message));
        let bad_path = mux_h3::encode_field_section(&[
            (":method".into(), "GET".into()),
            (":scheme".into(), "https".into()),
            (":authority".into(), "x".into()),
            (":path".into(), "/a b".into()),
        ]);
        assert_eq!(request_head(&bad_path, Some(0)).err(), Some(HeadError::Message));
        assert_eq!(request_head(&[0xff], Some(0)).err(), Some(HeadError::Decompression));
    }

    #[test]
    fn frames_before_and_around_the_headers() {
        let mut buf = Vec::new();
        mux_h3::encode_frame(&mut buf, 0x21, b"grease");
        mux_h3::encode_frame(&mut buf, FRAME_HEADERS, b"hdr");
        let (h, after) = first_headers(&buf).expect("ok").expect("complete");
        assert_eq!((h.as_slice(), after), (&b"hdr"[..], buf.len()));
        assert_eq!(first_headers(&buf[..buf.len() - 1]), Ok(None));
        assert_eq!(first_headers(&[0x01]), Ok(None), "a length not arrived yet");
        let mut data_first = Vec::new();
        mux_h3::encode_frame(&mut data_first, FRAME_DATA, b"x");
        assert!(first_headers(&data_first).is_err());
        assert_eq!(complete_body_len(&data_first), Some(1));
        assert_eq!(complete_body_len(&data_first[..1]), None);
    }

    #[test]
    fn a_body_of_unknown_length_is_chunked() {
        let mut rx = Vec::new();
        mux_h3::encode_frame(&mut rx, FRAME_DATA, b"abc");
        mux_h3::encode_frame(&mut rx, 0x21, b"grease");
        mux_h3::encode_frame(&mut rx, FRAME_DATA, b"");
        let mut body = BodyState::new(ReqBody::Chunked);
        let mut out = Vec::new();
        // A byte at a time: a frame is forwarded as it arrives.
        let all = std::mem::take(&mut rx);
        for b in &all {
            rx.push(*b);
            body.take(&mut rx, &mut out).expect("body");
        }
        body.end(&rx, &mut out).expect("end");
        assert_eq!(out, b"1\r\na\r\n1\r\nb\r\n1\r\nc\r\n0\r\n\r\n");
        assert!(rx.is_empty());
        assert!(BodyState::new(ReqBody::Length(2)).end(&[], &mut out).is_err(), "cut short");
        let mut mid = BodyState::new(ReqBody::Chunked);
        let mut part = frame_bytes(FRAME_DATA, b"abcdef");
        part.truncate(4);
        mid.take(&mut part, &mut out).expect("part");
        assert!(mid.end(&part, &mut out).is_err(), "ended inside a frame");
        assert!(BodyState::new(ReqBody::Chunked).end(&[0x00], &mut out).is_err(), "a frame header cut short");
    }

    #[test]
    fn a_response_that_cannot_be_parsed_is_an_error() {
        let bad: [&[u8]; 6] = [
            b"SPDY/3 200 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nno-colon\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\naXX",
            b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n",
            b"HTTP/1.1 abc OK\r\n\r\n",
        ];
        for b in bad {
            let mut out = Vec::new();
            assert!(ResponseConv::new(false).feed(b, &mut out).is_err(), "{:?}", String::from_utf8_lossy(b));
        }
        let huge = vec![b'a'; MAX_HEAD + 1];
        for prefix in [&b""[..], b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n"] {
            let mut c = ResponseConv::new(false);
            let mut out = Vec::new();
            c.feed(prefix, &mut out).expect("prefix");
            assert!(c.feed(&huge, &mut out).is_err());
        }
    }

    #[test]
    fn bodyless_responses_end_at_the_head() {
        for (head_req, raw) in [
            (true, &b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"[..]),
            (false, b"HTTP/1.1 204 No Content\r\n\r\n"),
            (false, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        ] {
            let mut c = ResponseConv::new(head_req);
            let mut out = Vec::new();
            c.feed(raw, &mut out).expect("feed");
            assert!(c.is_done());
            c.feed(b"ignored", &mut out).expect("after the end");
            assert_eq!(frames(&out).len(), 1);
        }
        // Chunked with trailers, fed a byte at a time.
        let mut c = ResponseConv::new(false);
        let mut out = Vec::new();
        for b in b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 9\r\n\r\n2\r\nok\r\n0\r\nX-T: 1\r\n\r\n" {
            c.feed(&[*b], &mut out).expect("feed");
        }
        assert!(c.is_done());
        c.eof().expect("eof after the end");
    }
}

