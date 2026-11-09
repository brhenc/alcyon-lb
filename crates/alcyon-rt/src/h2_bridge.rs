// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The bridge between an HTTP/2 stream and the HTTP/1 transaction that serves it (T280).
//!
//! An HTTP/2 stream is served by the ordinary HTTP/1 stream machinery: its request head is
//! written into a session's `req` buffer as HTTP/1.1 and its DATA follow, and the response
//! the server writes into `rep` goes back to the client as HEADERS and DATA frames. These
//! functions are that conversion, over the mux, the stream's [`H2ActiveStream`] and the
//! buffers, without the rest of the session: the side of the mux (the client connection)
//! and the side of the transaction (its buffers, server connection and log) are kept apart,
//! so that each stream can later have its own transaction beside the others on one
//! connection (`HAProxy`'s `h2s` and `struct stream`).

use crate::buf::Buf;
use crate::proxy::{find_eoh, H2ActiveStream, H2ReqBody, TcpSession};
use crate::raw;
use crate::txn::{self, HttpTxn, MsgState};
use alcyon_proto::endpoint::ScState;
use alcyon_proto::h2::{HeadFacts, TextHead};
use alcyon_proto::htx::{HtxBlock, RxHead};
use alcyon_proto::htx_mux::{HtxMux, HtxStream, MuxReset};
use alcyon_proto::mux_h2::H2MuxContext;
use std::os::fd::AsFd;

/// A stream taken from the mux to be served: everything its transaction starts from.
pub struct H2Dispatch {
    pub stream: H2ActiveStream,
    /// The request head, as the mux kept it.
    pub head: DispatchHead,
    /// What `%U` counts of the head.
    pub req_htx: u64,
    /// The line `%r` prints, when the frontend keeps it.
    pub request_line: Option<String>,
    /// A request `HAProxy` answers 400 without contacting a server
    /// ([`alcyon_proto::H2StreamCtx::bad_request`]).
    pub bad_request: bool,
    /// The mux could get no memory for the head's blocks: the stream is answered 500 (S5).
    pub no_memory: bool,
    /// The `content-length` the forwarded head gets in place of the client's: one whose
    /// length was not written once in its canonical form (`5, 5`, `005`, twice: `HAProxy` 3.5-dev7 forwards
    /// `content-length: 5`, T509).
    pub add_len: Option<u64>,
}

/// The request head of a stream taken to be served.
pub enum DispatchHead {
    /// CP2: the HTX blocks the h2 mux wrote from the decoded fields
    /// ([`alcyon_proto::h2::write_request_htx`]), in the memory that becomes the stream's
    /// `htx_buf` ([`Buf::adopt`]), what the writer said of them, and the length of the
    /// `scheme://authority` written after them (the log line's), and the protocol version the
    /// log line ends with.
    Htx { rx: RxHead, facts: HeadFacts, abs_len: usize, version: &'static str },
    /// A head the HTTP/1 checks refuse (a `:path` that is not UTF-8, a blank in it under the
    /// relaxed option, a CONNECT, too many header lines), as the text it goes out as; the
    /// bridge forwards it on the stream's `req` buffer, as the HTTP/1 path forwards a head it
    /// does not parse ([`start_request`], T437, E1).
    Text(Box<TextHead>),
    /// No head: the mux got no memory for it ([`H2Dispatch::no_memory`]), the stream is
    /// answered 500.
    None,
}

/// Takes the lowest stream of the connection that has its whole request head and has not
/// been served yet, and marks it served. `None` when there is none.
pub fn dispatch_next(h2: &mut H2MuxContext, keep_request_line: bool) -> Option<H2Dispatch> {
    let stream_id = *h2.streams.keys().find(|&&id| {
        h2.streams.get(&id).is_some_and(|st| {
            !st.dispatched
                && st.state != alcyon_proto::H2StreamState::Closed
                && !matches!(st.state, alcyon_proto::H2StreamState::Reset(_))
                && st.rx_htx.blocks().iter().any(|b| matches!(b, HtxBlock::Eoh))
        })
    })?;
    let stream = h2.streams.get_mut(&stream_id)?;
    stream.dispatched = true;
    // The head goes to the server as HTTP/1.1, and the body follows as the DATA frames
    // come (`pump_request_body`): with the length the client gave, else chunked, as
    // `HAProxy` writes it.
    let has_data = stream.rx_htx.blocks().iter().any(|b| matches!(b, HtxBlock::Data(_) | HtxBlock::RawData(_) | HtxBlock::Trailer(_)));
    // An extended CONNECT's DATA are the tunnel's, which no framing goes with.
    // Every `content-length` the mux took is one length (E1), which it keeps.
    let chunked = !stream.ext_connect && stream.req_content_length.is_none() && (has_data || !stream.rx_htx.is_eom());
    let first_body = stream.rx_htx.blocks().iter().position(|b| matches!(b, HtxBlock::Eoh)).map_or(stream.rx_htx.blocks().len(), |i| i + 1);
    // `%U`, and the line `%r` prints, are those of the message the client sent:
    // `transfer-encoding: chunked` is added on output only, so the rules do not see it
    // either (only the forwarded head has it). The chunked end the forwarded body is
    // counted with (+1 when it is consumed) is not in `HAProxy`'s message unless trailers
    // precede it.
    let (head, add_len, req_htx, request_line) = if let Some(rx) = stream.rx_head.take() {
        // The head as the mux wrote it (CP2a); the stream keeps none past this. The line
        // `%r` prints is written by `start_request`, from the blocks.
        let facts = stream.head_facts;
        let abs_len = stream.abs_len;
        let size = facts.log_size(abs_len, "HTTP/2.0");
        (DispatchHead::Htx { rx, facts, abs_len, version: "HTTP/2.0" }, None, size, None)
    } else if let Some(t) = stream.text_head.take() {
        // The head as the mux kept it as text (T437); the stream keeps none past this.
        let request_line = keep_request_line.then(|| format!("{} {}{} HTTP/2.0", t.method(), t.abs, t.uri()));
        let size = t.facts.log_size(t.abs.len(), "HTTP/2.0");
        let add_len = t.add_len;
        (DispatchHead::Text(t), add_len, size, request_line)
    } else {
        // Every head the mux takes is blocks, text, or the stream's `no_memory`.
        debug_assert!(stream.no_memory);
        (DispatchHead::None, None, 0, None)
    };
    let req_htx = req_htx.saturating_sub(u64::from(chunked));
    Some(H2Dispatch {
        stream: H2ActiveStream {
            id: stream_id,
            body: H2ReqBody { cursor: first_body, off: 0, chunked, ..H2ReqBody::default() },
            chunk_out: chunked,
        },
        head,
        req_htx,
        request_line,
        bad_request: stream.bad_request,
        no_memory: stream.no_memory,
        add_len,
    })
}

/// [`dispatch_next`] for any mux the bridge drives (T509): the stream the mux says may be
/// served next, marked served. `version` is what `%r` prints after the target. A stream id
/// past `u32` (2^30 requests on one connection) is refused, as the stream entries count
/// in `u32`.
pub fn dispatch_mux<M: HtxMux>(mux: &mut M, keep_request_line: bool, version: &'static str) -> Option<H2Dispatch> {
    let id = mux.next_dispatch()?;
    let Ok(id32) = u32::try_from(id) else {
        mux.reset(id, MuxReset::Refused);
        return None;
    };
    let stream = mux.stream_mut(id)?;
    stream.set_dispatched();
    let blocks = stream.rx_htx().blocks();
    let has_data = blocks.iter().any(|b| matches!(b, HtxBlock::Data(_) | HtxBlock::RawData(_) | HtxBlock::Trailer(_)));
    let first_body = blocks.iter().position(|b| matches!(b, HtxBlock::Eoh)).map_or(blocks.len(), |i| i + 1);
    let eom = stream.rx_htx().is_eom();
    let cl = stream.content_length();
    let bad_request = stream.bad_request();
    if let Some((rx, facts, abs_len)) = stream.take_rx_head() {
        // The head as the mux wrote it (CP2b): framed as an h2 one is.
        let chunked = cl.is_none() && (has_data || !eom);
        let size = facts.log_size(abs_len, version);
        return Some(H2Dispatch {
            stream: H2ActiveStream {
                id: id32,
                body: H2ReqBody { cursor: first_body, off: 0, chunked, ..H2ReqBody::default() },
                chunk_out: chunked,
            },
            head: DispatchHead::Htx { rx, facts, abs_len, version },
            req_htx: size.saturating_sub(u64::from(chunked)),
            request_line: None,
            bad_request,
            no_memory: false,
            add_len: None,
        });
    }
    let no_memory = stream.no_memory();
    let (head, add_len, size, request_line) = if let Some(t) = stream.take_text_head() {
        let request_line = keep_request_line.then(|| format!("{} {}{} {version}", t.method(), t.abs, t.uri()));
        let (add_len, size) = (t.add_len, t.facts.log_size(t.abs.len(), version));
        (DispatchHead::Text(t), add_len, size, request_line)
    } else {
        debug_assert!(no_memory);
        (DispatchHead::None, None, 0, None)
    };
    // A body without `content-length` goes chunked, also when all of it came with the head
    // (measured on `HAProxy` 3.5-dev7 with QUIC, T511).
    let chunked = cl.is_none() && add_len.is_none() && (has_data || !eom);
    let req_htx = size.saturating_sub(u64::from(chunked));
    Some(H2Dispatch {
        stream: H2ActiveStream {
            id: id32,
            body: H2ReqBody { cursor: first_body, off: 0, chunked, ..H2ReqBody::default() },
            chunk_out: chunked,
        },
        head,
        req_htx,
        request_line,
        bad_request,
        no_memory,
        add_len,
    })
}

/// A request head with `transfer-encoding: chunked` added as its last header, `at` being
/// the end of its last header line (where its blank line starts).
#[must_use]
pub fn chunked_head(head: &[u8], at: usize) -> Vec<u8> {
    let mut v = head[..at].to_vec();
    v.extend_from_slice(b"\r\ntransfer-encoding: chunked");
    v.extend_from_slice(&head[at..]);
    v
}

/// The start of a stream's transaction in the session that serves it, a child of the
/// connection's owner (T280): its head written as HTX from the fields the mux kept (E1: no
/// HTTP/1.1 text is written and parsed again), the head in `req` written once from the HTX,
/// the request's log fields, and the transaction. CP2: a head the mux wrote as blocks is adopted
/// as the stream's `htx_buf`; one the HTTP/1 checks refuse goes out as text ([`start_text`]).
pub fn start_request(sess: &mut TcpSession, d: H2Dispatch) {
    let chunked = d.stream.chunk_out;
    if let Some(c) = sess.h2_child_mut() {
        c.stream = d.stream;
    }
    sess.strm.log.request = Some(crate::txnlog::loop_now());
    match d.head {
        DispatchHead::Htx { rx, facts, abs_len, version } => {
            start_adopted(sess, rx, facts, abs_len, version, chunked);
            let no_mem = !sess.req.alloc_if_needed();
            start_txn(sess, adopted_framing(facts, chunked), adopted_req_htx(d.req_htx, facts), d.bad_request, no_mem);
        }
        DispatchHead::Text(head) => start_text(sess, &head, d.request_line.as_deref(), chunked, d.req_htx, d.bad_request, d.no_memory),
        DispatchHead::None => {
            // No memory for the head: the transaction is failed at once (S5), with nothing of
            // the request to log or forward.
            sess.req_ws = None;
            sess.req_headers = None;
            sess.req.clear();
            start_txn(sess, txn::Framing::None, d.req_htx, d.bad_request, true);
        }
    }
}

/// How a head written as blocks is framed: by its one canonical `content-length`, chunked, or
/// not at all (`0` is no body).
fn adopted_framing(facts: HeadFacts, chunked: bool) -> txn::Framing {
    match facts.content_length {
        _ if chunked => txn::Framing::Chunked,
        Some(len) if len > 0 => txn::Framing::Length(len as u64),
        _ => txn::Framing::None,
    }
}

/// `%U` of a head written as blocks, `req_htx` as the client sent it: the `content-length` the
/// HTX holds, one canonical value in place of the client's (`005`, `5, 5`, a repeat: `HAProxy`
/// 3.5-dev8 forwards and counts `5`), counted for the client's.
fn adopted_req_htx(req_htx: u64, facts: HeadFacts) -> u64 {
    match facts.content_length {
        Some(len) => (req_htx + ("content-length".len() + digits(len as u64)) as u64).saturating_sub(facts.cl_bytes as u64),
        None => req_htx,
    }
}

/// The number of decimal digits of `n`.
fn digits(n: u64) -> usize {
    n.max(1).ilog10() as usize + 1
}

/// [`start_request`] of a head the h2 mux wrote as HTX blocks into `rx` (CP2): the memory
/// becomes the stream's `htx_buf` as it is, and the log fields are read from its start line
/// (and the `scheme://authority` after its payload, `abs_len` bytes) before it does.
fn start_adopted(sess: &mut TcpSession, rx: RxHead, facts: HeadFacts, abs_len: usize, version: &str, chunked: bool) {
    {
        let htx = alcyon_proto::htx::HtxSliceRef::new(rx.bytes(), facts.blocks);
        // The writer wrote a start line of ASCII words (the HTTP/1 line check), and the
        // prefix of text: neither is missing.
        let line = (!facts.path_raw)
            .then(|| htx.req_line_sized(facts.method_len, facts.uri_len))
            .flatten()
            .or_else(|| htx.req_line())
            .unwrap_or(alcyon_proto::htx::RequestLineView { method: "", uri: "", version: "" });
        if sess.keep_request_line {
            // Text: the writer checked the scheme and the authority.
            let abs = String::from_utf8_lossy(&rx.bytes()[facts.tail..facts.tail + abs_len]);
            sess.strm.log.request_line.set_parts(&[line.method, " ", &abs, line.uri, " ", version]);
        }
        sess.req_method.set(line.method);
        sess.req_uri.set(line.uri);
        // An extended CONNECT to a websocket goes to the server with the `Sec-WebSocket-Key` an
        // HTTP/2 client does not send, which the server's accept must then answer
        // (`h1_process_mux` adds it to a handshake that has none, T505). The mux wrote it among
        // the headers, where the rules see it, as the key the HTTP/1 path writes is (`HAProxy`
        // adds it on output, after the headers the rules add).
        sess.req_ws = facts.ext_connect.then(|| head_ws(htx.header_blocks_where(|_| true).map(|(_, n, v)| (n, v)), facts.key_written)).flatten();
    }
    if !facts.ext_connect {
        sess.req_ws = None;
    }
    // A stream's previous list (the connection's spare, T437) is no list of this head's.
    sess.req_headers = None;
    let (tail, blocks) = (facts.tail, facts.blocks);
    sess.htx_buf = Buf::adopt(rx, tail, blocks);
    // The prefix is zeroed on release with the head (`tune.alcyon.zero-buffers`).
    sess.htx_buf.note_htx(tail + abs_len, 0);
    sess.req.clear();
    // The head waits here for a server connection (a stream held in the queue, or whose body
    // never comes, keeps it): a small buffer for a small head, which grows with the body.
    let key_line = if facts.key_written { "sec-websocket-key: \r\n".len() + 24 } else { 0 };
    let out_len = facts.wire_len() + key_line + if chunked { "transfer-encoding: chunked\r\n".len() } else { 0 };
    if out_len * 2 <= crate::buf::get_bufsize_small() && sess.req.raw_slice().is_empty() {
        sess.req = Buf::unallocated(crate::buf::BufClass::Small);
    }
    sess.htx_tail = tail;
    sess.htx_blocks = blocks;
    sess.has_htx = true;
    // The head is the HTX's alone until the send writes it (X4, `write_pending_head`):
    // the rules edit the blocks only, as for an edited HTTP/1 head (X2).
    sess.htx_modified = true;
    sess.req_head_pending = true;
    if let Some(c) = sess.h2_child_mut() {
        c.stream.body.head_room = out_len;
    }
}

/// The websocket state of a request head written as blocks (an extended CONNECT): its headers
/// read as `ReqWs::of` reads them; with `key_written` the mux made the `sec-websocket-key` the
/// head holds, which the server's `Sec-WebSocket-Accept` is not checked against (it is ours).
fn head_ws<'a>(headers: impl Iterator<Item = (&'a str, &'a str)>, key_written: bool) -> Option<Box<crate::websocket::ReqWs>> {
    let (mut ws, _) = crate::websocket::ReqWs::of(headers, false);
    if key_written {
        ws.sent_key = Some(ws.key);
        ws.key = [0; 24];
    }
    (ws != crate::websocket::ReqWs::default()).then(|| Box::new(ws))
}

/// [`start_request`] of a head the HTTP/1 checks refuse (text, [`TextHead`]): forwarded as the
/// text it is, in `req`, with `transfer-encoding: chunked` or the canonical `content-length`
/// in place of the client's. Nothing is written as HTX: the rules edit the list of its headers.
#[cold]
#[inline(never)]
fn start_text(sess: &mut TcpSession, head: &TextHead, request_line: Option<&str>, chunked: bool, d_req_htx: u64, bad_request: bool, head_no_mem: bool) {
    if sess.keep_request_line {
        sess.strm.log.request_line.set_opt(request_line);
    }
    sess.req_ws = head.facts.ext_connect.then(|| head_ws(head.text_headers(), head.facts.key_written)).flatten();
    sess.req_method.set(head.method());
    sess.req_uri.set(head.uri());
    // `%U` counts the digits the head goes with.
    let mut req_htx = d_req_htx;
    if let Some(n) = head.add_len {
        req_htx = (req_htx + ("content-length".len() + n.to_string().len()) as u64).saturating_sub(head.facts.cl_bytes as u64);
    }
    // The list a rule's edit writes the head from.
    copy_headers(sess.req_headers.get_or_insert_with(Vec::new), head.text_headers());
    sess.req.clear();
    // The head waits here for a server connection (a stream held in the queue, or whose body
    // never comes, keeps it): a small buffer for a small head, which grows with the body.
    let key_line = if head.facts.key_written { "sec-websocket-key: \r\n".len() + 24 } else { 0 };
    let out_len = head.facts.wire_len() + key_line + if chunked { "transfer-encoding: chunked\r\n".len() } else { 0 };
    if out_len * 2 <= crate::buf::get_bufsize_small() && sess.req.raw_slice().is_empty() {
        sess.req = Buf::unallocated(crate::buf::BufClass::Small);
    }
    let no_mem = head_no_mem || !sess.req.alloc_if_needed();
    let wire = framed_text(&head.wire, chunked, head.add_len);
    let n = copy_into(sess.req.writable(), &wire);
    sess.req.commit(n);
    let wire_req = sess.req.readable();
    let framing = find_eoh(wire_req).map_or(txn::Framing::None, |(h, e)| txn::request_framing(&wire_req[..h + e]));
    start_txn(sess, framing, req_htx, bad_request, no_mem);
}

/// The transaction of a stream whose head [`start_request`] took: framed by `framing`, `%U`
/// counting `req_htx` of the head; failed at once for a request `HAProxy` answers 400, or
/// when the memory its head needs could not be had (S5).
fn start_txn(sess: &mut TcpSession, framing: txn::Framing, req_htx: u64, bad_request: bool, no_mem: bool) {
    let mut txn = HttpTxn::new(framing, false);
    txn.req_htx = Some(req_htx);
    // The client's own method, as the HTTP/1 parser takes it: a reply the proxy makes to a
    // HEAD is its head alone (HEADERS with END_STREAM). Unset, the body of every local reply
    // went out as DATA after it, which a client takes for a protocol error (T580).
    txn.client_head = sess.req_method.as_deref().is_some_and(|m| m.eq_ignore_ascii_case("HEAD"));
    // Framed by the client's length, read again after the rules (T442): one a rule removed
    // goes as `content-length: 0` with no body. A body sent chunked has its
    // `transfer-encoding` on output only, which no rule sees.
    txn.req_len_hdrs = Some(txn::LenHdrs { clen: matches!(framing, txn::Framing::Length(_)), chnk: false });
    sess.strm.txn = Some(txn);
    sess.cli_state = ScState::Established;
    if bad_request {
        sess.fail_request(400);
    } else if no_mem {
        sess.fail_alloc();
    }
}

/// The head of an HTTP/2 or HTTP/3 request, held in its HTX since [`start_request`]
/// (`TcpSession::req_head_pending`), written as HTTP/1.1 at the front of `req`, ahead of the
/// body already moved there: once, at the server send, after the rules (X4), or first by
/// whatever reads `req` as text before it (a reply of the proxy's own). By the h1 encoder
/// (X5): a request without a length goes chunked, `transfer-encoding: chunked` after the other
/// headers, which no rule sees (`h1_make_eoh`, the encoder's flag); one with a length is
/// framed by it. The names are the client's, in lower case (HTTP/2, HTTP/3); the mode is
/// keep-alive, as the server side starts (the `connection` header is the engine's,
/// `rewrite_request_connection`). `lower` and `case_map` are the backend's
/// `tune.alcyon.h1-lowercase-headers` and `h1-case-adjust` map, applied as the names are
/// written (no pass over the text after). False, nothing written, for an HTX the encoder
/// refuses (a `content-length` a rule made invalid) and no HTX at all.
pub fn write_pending_head(sess: &mut TcpSession, lower: bool, case_map: Option<&std::collections::HashMap<String, String>>) -> bool {
    use alcyon_proto::h1_encode::{h1_encode_head, H1Dir, H1EncodeOpts, SlFlags};
    if !std::mem::take(&mut sess.req_head_pending) || !sess.has_htx {
        return false;
    }
    sess.htx_modified = false;
    if let Some(c) = sess.h2_child_mut() {
        c.stream.body.head_room = 0;
    }
    let htx = alcyon_proto::htx::HtxSliceRef::new(sess.htx_buf.raw_slice(), sess.htx_blocks);
    let chunked = sess.h2_active().is_some_and(|a| a.chunk_out);
    let sl = SlFlags::XFER_LEN
        | if chunked {
            SlFlags::NONE
        } else if htx.header_blocks_where(|n| n.eq_ignore_ascii_case(b"content-length")).next().is_some() {
            SlFlags::CLEN
        } else {
            SlFlags::BODYLESS
        };
    let mut opts = H1EncodeOpts::new(H1Dir::Request, sl, lower);
    opts.case_map = case_map;
    let mut refused = false;
    if sess.req.replace_head_with(0, |out| match h1_encode_head(htx, &opts, out) {
        Ok(e) => Some(e.len),
        Err(e) => {
            refused = e != alcyon_proto::htx::HtxError::BufferTooSmall;
            None
        }
    }) {
        return true;
    }
    if refused {
        return false;
    }
    // Larger than the buffer's free memory: into a `Vec` grown until it fits, which the
    // buffer then grows for.
    let mut wire = vec![0u8; 4096];
    loop {
        match h1_encode_head(htx, &opts, &mut wire) {
            Ok(e) => {
                wire.truncate(e.len);
                sess.req.replace_prefix(0, &wire);
                return true;
            }
            Err(alcyon_proto::htx::HtxError::BufferTooSmall) => wire.resize(wire.len() * 2, 0),
            Err(_) => return false,
        }
    }
}

/// `src` into `dst`, as much as fits: the bytes copied.
fn copy_into(dst: &mut [u8], src: &[u8]) -> usize {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    n
}

/// The text of a head the HTTP/1 parser refuses (a request `HAProxy` answers 400, a CONNECT),
/// with either `transfer-encoding: chunked` or the canonical `content-length` in place of the
/// client's.
fn framed_text(head: &[u8], chunked: bool, add_len: Option<u64>) -> Vec<u8> {
    let at = find_eoh(head).map_or(head.len(), |(h, _)| h);
    if chunked {
        return chunked_head(head, at);
    }
    let Some(n) = add_len else { return head.to_vec() };
    // The first of the client's `content-length` lines becomes the digits, the others go.
    let mut v = Vec::with_capacity(at + 40);
    let mut first = true;
    for (i, line) in head[..at].split(|&b| b == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let is_len = i > 0 && line.len() >= 15 && line[..15].eq_ignore_ascii_case(b"content-length:");
        if is_len && !first {
            continue;
        }
        if i > 0 {
            v.extend_from_slice(b"\r\n");
        }
        if is_len {
            first = false;
            v.extend_from_slice(format!("content-length: {n}").as_bytes());
        } else {
            v.extend_from_slice(line);
        }
    }
    v.extend_from_slice(&head[at..]);
    v
}

/// `hdrs` as a copy of `from`, the `String`s it has reused (T437).
fn copy_headers<'a>(hdrs: &mut Vec<(String, String)>, from: impl Iterator<Item = (&'a str, &'a str)>) {
    let mut n = 0;
    for (k, v) in from {
        copy_header(hdrs, &mut n, k, v);
    }
    hdrs.truncate(n);
}

/// `(k, v)` as the `*n`th entry of `hdrs`, in the `String`s it had there if any.
fn copy_header(hdrs: &mut Vec<(String, String)>, n: &mut usize, k: &str, v: &str) {
    if let Some((hk, hv)) = hdrs.get_mut(*n) {
        hk.clear();
        hk.push_str(k);
        hv.clear();
        hv.push_str(v);
    } else {
        hdrs.push((k.to_string(), v.to_string()));
    }
    *n += 1;
}

/// The DATA frames of a stream being served that have come since: moved into `req` as far
/// as it has room, the stream window credited as they are. Whether anything happened, and
/// what the trailers moved add to `%U`.
pub fn pump_request_body(h2: &mut H2MuxContext, active: &mut H2ActiveStream, req: &mut Buf) -> (bool, u64) {
    let Some(stream) = h2.streams.get_mut(&active.id) else {
        return (false, 0);
    };
    let mut changed = false;
    let body = &mut active.body;
    let (before, was_done) = (body.trailer_bytes, body.done);
    let taken = body.consumed;
    // The end of the message is news to the stream even when it wrote nothing (trailers
    // dropped after a length): the transaction may have been waiting for it.
    if pump_h2_body(&mut stream.rx_htx, body, req) || body.done != was_done {
        changed = true;
    }
    let taken = usize::try_from(body.consumed - taken).unwrap_or(usize::MAX);
    if taken > 0 {
        let id = stream.id;
        h2.rx_taken(id, taken);
        h2.resume();
    }
    // The client may send as much again as has moved on towards the server: a backed-up
    // server stops the grants, and so the client.
    let pending = body.consumed - body.credited;
    if pending >= 16384 && !body.done {
        body.credited += pending;
        h2.send_window_update(active.id, pending as u32);
        changed = true;
    }
    (changed, body.trailer_bytes - before)
}

/// [`pump_request_body`] for any mux the bridge drives (T509): the stream's DATA into `req`
/// as far as it has room, the mux told what was taken (h3: quinn credits the client's
/// window as the owner reads, so there is no window to grant here).
pub fn pump_request_body_mux<M: HtxMux>(mux: &mut M, active: &mut H2ActiveStream, req: &mut Buf) -> (bool, u64) {
    let id = u64::from(active.id);
    let Some(stream) = mux.stream_mut(id) else {
        return (false, 0);
    };
    let body = &mut active.body;
    let (before, was_done, taken) = (body.trailer_bytes, body.done, body.consumed);
    let changed = pump_htx_body(stream.rx_htx_mut(), body, req, M::GIVE_DATA) || body.done != was_done;
    let taken = usize::try_from(body.consumed - taken).unwrap_or(usize::MAX);
    if taken > 0 {
        mux.rx_taken(id, taken);
    }
    (changed, body.trailer_bytes - before)
}

/// The most trailer fields the bridge sends: the h1 parser accepts as many (`txn`).
const MAX_TRAILER_FIELDS: usize = 100;

/// The fields of a chunked trailer section (`name: value` lines ended by CRLF, a blank line
/// last, as `rewrite_rep_chunk_framing` leaves them) in `out`: how many. A field that is not
/// text is left out.
fn trailer_fields<'a>(section: &'a [u8], out: &mut [(&'a str, &'a str); MAX_TRAILER_FIELDS]) -> usize {
    let mut n = 0;
    for line in section.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else { continue };
        let value = line[colon + 1..].trim_ascii();
        if let (Ok(name), Ok(value), true) = (std::str::from_utf8(&line[..colon]), std::str::from_utf8(value), n < out.len()) {
            out[n] = (name, value);
            n += 1;
        }
    }
    n
}

/// The fields of a response head the engine indexed and kept up to date (E2), for the
/// client's HEADERS: what the mux read of the head as text, without reading it.
fn indexed_fields<'h>(head: &'h [u8], ix: &'h alcyon_proto::response_head::RspHead) -> impl Iterator<Item = (&'h [u8], &'h [u8])> {
    #[cfg(debug_assertions)]
    {
        // What the mux's own reading of the head gives (`send_h1_head`), names lowered.
        // Compared without allocating: the allocation tests count debug builds.
        let mut new = ix.fields().iter().map(|f| (f.name(head), f.value(head).trim_ascii()));
        let same = alcyon_proto::response_head::mux_head_lines_uncounted(head).is_some_and(|(status, mut lines)| {
            status == ix.status
                && lines.all(|(n, v)| new.next().is_some_and(|(nn, nv)| n.eq_ignore_ascii_case(nn) && !nn.iter().any(u8::is_ascii_uppercase) && v == nv))
                && new.next().is_none()
        });
        debug_assert!(same, "stale response head index of {:?}", String::from_utf8_lossy(head));
    }
    // A name is a token: its bytes go as they are (T581).
    ix.fields().iter().map(move |f| (f.name(head), f.value(head).trim_ascii()))
}

/// [`forward_response`] for any mux the bridge drives (T509), the DATA staged in `scratch`.
#[allow(clippy::too_many_arguments)]
pub fn forward_response_mux<M: HtxMux>(mux: &mut M, stream_id: u32, txn: &mut HttpTxn, rep: &mut Buf, srv_gone: bool, scratch: &mut Vec<u8>, late_trailers: &mut Option<alcyon_alloc::PoolBox<Vec<u8>>>, rsp_head: &mut Option<alcyon_proto::response_head::RspHead>) -> bool {
    let id = u64::from(stream_id);
    if txn.rsp == MsgState::Waiting || txn.rsp.is_done() {
        return false;
    }
    let data = rep.readable();
    let win = txn.rsp.window(data);
    if txn.rsp_interim {
        // An interim response (`100`, `103`) is a HEADERS frame without the end of the
        // stream; the final response follows (T520). One that is no head the mux can send
        // is dropped.
        let Some((h, _)) = find_eoh(data) else { return false };
        mux.send_interim(id, &data[..h]);
        txn.response_sent(data, win);
        rep.consume(win);
        return false;
    }
    if let MsgState::Head { body, .. } = txn.rsp {
        let Some((h, e)) = find_eoh(data) else { return false };
        let end_stream = matches!(body, txn::Framing::None | txn::Framing::Length(0));
        let sent = match rsp_head.take().filter(|ix| ix.len as usize == h + e) {
            Some(ix) => mux.send_head_fields(id, ix.status, indexed_fields(&data[..h + e], &ix), end_stream),
            None => mux.send_head(id, &data[..h], end_stream),
        };
        if sent {
            txn.rsp.consume(data, h + e);
            rep.consume(h + e);
            if !end_stream {
                return forward_response_mux(mux, stream_id, txn, rep, srv_gone, scratch, late_trailers, rsp_head);
            }
        }
        return false;
    }
    if !matches!(txn.rsp, MsgState::Body(_)) {
        mux.reset(id, MuxReset::Internal);
        txn.srv_reusable = false;
        txn.rsp = MsgState::Done;
        return false;
    }
    scratch.clear();
    let mut state = txn.rsp;
    // Already at the trailer section (it was not all here before): nothing to take first.
    let mut used = if state.at_trailer_section() { 0 } else { state.take_body_to_trailers(data, mux.data_budget(id), scratch) };
    // A chunked body's trailer section, once all of it is here: the trailers of the stream
    // (T520), or nothing but the end of the message.
    let mut trailers = &data[..0];
    if state.at_trailer_section() {
        if let Some(n) = state.trailer_section(&data[used..]) {
            trailers = &data[used..used + n];
            used += n;
            state = MsgState::Done;
        }
    }
    let end = state.is_done();
    if let Some(t) = txn.rsp_htx.as_mut().filter(|_| !txn.local) {
        *t += scratch.len() as u64 + u64::from(end && matches!(txn.rsp, MsgState::Body(txn::Body::Chunked(_))));
    }
    // Trailers an h2 server sent after a content-length body (T559): with the stream's end.
    let late = if end && trailers.len() <= 2 { late_trailers.take() } else { None };
    let trailers = late.as_deref().filter(|l| l.len() > 2).map_or(trailers, Vec::as_slice);
    if trailers.len() > 2 {
        // Not the blank line alone: the fields, on the stack (the common response has none).
        if !scratch.is_empty() {
            mux.send_data(id, scratch, false);
        }
        let mut fields = [("", ""); MAX_TRAILER_FIELDS];
        let n = trailer_fields(trailers, &mut fields);
        mux.send_trailers(id, &fields[..n]);
        // `%B` counts the trailers' names and values (HTX trailer blocks).
        if let Some(t) = txn.rsp_htx.as_mut().filter(|_| !txn.local) {
            *t += fields[..n].iter().map(|(k, v)| (k.len() + v.len()) as u64).sum::<u64>();
        }
    } else if !scratch.is_empty() || end {
        mux.send_data(id, scratch, end);
    }
    if used > 0 || end {
        txn.rsp = state;
        rep.consume(used);
    }
    if txn.rsp.is_done() || !srv_gone || !rep.is_empty() {
        return false;
    }
    txn.srv_reusable = false;
    let cut_short = if matches!(txn.rsp, MsgState::Body(txn::Body::UntilClose)) {
        mux.send_data(id, &[], true);
        false
    } else {
        mux.reset(id, MuxReset::Cancel);
        true
    };
    txn.rsp = MsgState::Done;
    cut_short
}

/// The response of a stream, as HEADERS then DATA frames, as much as the client's
/// flow-control windows take. `srv_gone`: the server side has ended. `true` when the
/// response was cut short by the server and the stream reset for it (`SD`).
pub fn forward_response(h2: &mut H2MuxContext, stream_id: u32, txn: &mut HttpTxn, rep: &mut Buf, srv_gone: bool, late_trailers: &mut Option<alcyon_alloc::PoolBox<Vec<u8>>>, rsp_head: &mut Option<alcyon_proto::response_head::RspHead>) -> bool {
    if txn.rsp == MsgState::Waiting || txn.rsp.is_done() {
        return false;
    }
    let data = rep.readable();
    let win = txn.rsp.window(data);
    if txn.rsp_interim {
        // An interim response (`100`, `103`) is a HEADERS frame without END_STREAM; the
        // final response follows (T520). One the mux cannot send is dropped.
        let Some((h, _)) = find_eoh(data) else { return false };
        h2.send_interim(stream_id, &data[..h]);
        txn.response_sent(data, win);
        rep.consume(win);
        return false;
    }
    if let MsgState::Head { body, .. } = txn.rsp {
        // The head goes out as HEADERS once all of it is here; the body follows as
        // DATA, as much as the client's windows take at a time.
        let Some((h, e)) = find_eoh(data) else { return false };
        let end_stream = matches!(body, txn::Framing::None | txn::Framing::Length(0));
        let sent = match rsp_head.take().filter(|ix| ix.len as usize == h + e) {
            Some(ix) => h2.send_head_fields(stream_id, ix.status, indexed_fields(&data[..h + e], &ix), end_stream),
            None => h2.send_h1_head(stream_id, &data[..h], end_stream),
        };
        if sent {
            txn.rsp.consume(data, h + e);
            rep.consume(h + e);
            // The body that came with the head goes out with it, in the same write: on
            // its own, a poller round later, it is a second write, and a second small
            // segment Nagle holds until the client's delayed ACK, ~40 ms a request (T186).
            if !end_stream {
                return forward_response(h2, stream_id, txn, rep, srv_gone, late_trailers, rsp_head);
            }
        }
        return false;
    }
    if txn.rsp == MsgState::Tunnel && h2.streams.get(&stream_id).is_some_and(|s| s.ext_connect) {
        // The tunnel of an extended CONNECT (RFC 8441): what the server sends goes as
        // DATA as the windows take it, and its close ends the stream.
        let n = h2.data_budget(stream_id).min(data.len());
        let sent = h2.send_data(stream_id, &data[..n], false);
        rep.consume(sent);
        if let Some(t) = txn.rsp_htx.as_mut() {
            *t += sent as u64;
        }
        if srv_gone && rep.is_empty() {
            // The stream is over once the client has ended too (`h2_request_open`).
            h2.send_data(stream_id, &[], true);
            txn.srv_reusable = false;
            txn.close_after = true;
            txn.rsp = MsgState::Done;
        }
        return false;
    }
    if !matches!(txn.rsp, MsgState::Body(_)) {
        // A body that broke its framing, or a tunnel (101, CONNECT) of a request that is
        // no extended CONNECT, which this conversion does not carry: the stream is reset
        // and the server is let go.
        h2.send_rst_stream(stream_id, alcyon_proto::h2::H2Error::InternalError);
        txn.srv_reusable = false;
        txn.rsp = MsgState::Done;
        return false;
    }
    // Staged in the connection's buffer, kept from one response to the next (T437).
    let mut out = std::mem::take(&mut h2.body_scratch);
    out.clear();
    let mut state = txn.rsp;
    // A chunked body's trailer section, once all of it is here, goes as a HEADERS frame
    // that ends the stream, after the DATA without END_STREAM (T549, as `h2s_snd_ftrl`).
    let mut used = if state.at_trailer_section() { 0 } else { state.take_body_to_trailers(data, h2.data_budget(stream_id), &mut out) };
    let mut trailers = &data[..0];
    if state.at_trailer_section() {
        if let Some(n) = state.trailer_section(&data[used..]) {
            trailers = &data[used..used + n];
            used += n;
            state = MsgState::Done;
        }
    }
    let end = state.is_done();
    if let Some(t) = txn.rsp_htx.as_mut().filter(|_| !txn.local) {
        // The payload, and the chunked body's end (see `htx_head_size`); not a reply
        // the proxy made in place of the server's response.
        *t += out.len() as u64 + u64::from(end && matches!(txn.rsp, MsgState::Body(txn::Body::Chunked(_))));
    }
    // Trailers an h2 server sent after a content-length body (T559): with the stream's end.
    let late = if end && trailers.len() <= 2 { late_trailers.take() } else { None };
    let trailers = late.as_deref().filter(|l| l.len() > 2).map_or(trailers, Vec::as_slice);
    if trailers.len() > 2 {
        if !out.is_empty() {
            h2.send_data(stream_id, &out, false);
        }
        let mut fields = [("", ""); MAX_TRAILER_FIELDS];
        let n = trailer_fields(trailers, &mut fields);
        h2.send_trailers(stream_id, &fields[..n]);
        // `%B` counts the trailers' names and values (HTX trailer blocks).
        if let Some(t) = txn.rsp_htx.as_mut().filter(|_| !txn.local) {
            *t += fields[..n].iter().map(|(k, v)| (k.len() + v.len()) as u64).sum::<u64>();
        }
    } else if !out.is_empty() || end {
        h2.send_data(stream_id, &out, end);
    }
    // Not past one frame's worth (and less once the connection is idle, `trim_idle`).
    if out.capacity() <= 16384 {
        h2.body_scratch = out;
    }
    if used > 0 || end {
        txn.rsp = state;
        rep.consume(used);
    }
    if txn.rsp.is_done() || !srv_gone || !rep.is_empty() {
        return false;
    }
    // The server is gone and everything it sent has been delivered.
    txn.srv_reusable = false;
    let cut_short = if matches!(txn.rsp, MsgState::Body(txn::Body::UntilClose)) {
        // The close is the end of this body.
        h2.send_data(stream_id, &[], true);
        false
    } else {
        // Cut short: the stream cannot be completed, so it is reset.
        h2.send_rst_stream(stream_id, alcyon_proto::h2::H2Error::Cancel);
        true
    };
    txn.rsp = MsgState::Done;
    cut_short
}

/// Whether the client (or the mux, for a stream error) has reset stream `id`.
#[must_use]
pub fn stream_is_reset(h2: &H2MuxContext, id: u32) -> bool {
    h2.streams.get(&id).is_some_and(|s| matches!(s.state, alcyon_proto::h2::H2StreamState::Reset(_)))
}

/// The transaction of a stream that was reset ends here: nothing more is sent on the
/// stream, the server connection is reset, and the log reads `400 ... CH--` waiting for
/// the response head with the request not all in (`400 ... CD--` with it all in, T521),
/// `CD--` during the body, `CQ` queued (`HAProxy` 3.5-dev8, T273 B).
/// What is left in either buffer is dropped, as it would be taken for the next stream's.
/// The caller ends the transaction. `false` when there is none.
pub fn abort_reset_stream(sess: &mut TcpSession) -> bool {
    let Some(txn) = sess.strm.txn.as_mut() else {
        return false;
    };
    let response_done = txn.rsp.is_done();
    let waiting = txn.rsp == MsgState::Waiting;
    // A request the client had sent whole is aborted in the data phase (`CD--`), one it was
    // still sending in the headers phase (`CH--`); both 400 while no response head came
    // (`HAProxy` 3.5-dev8 on h2, 3.5-dev7 on h2 and h3, T521).
    let request_done = txn.req.is_done();
    txn.srv_reusable = false;
    txn.rsp = MsgState::Done;
    if !response_done {
        // `SC_FL_NOLINGER`: closed when the transaction ends, the server connection is reset.
        if let Some(srv) = sess.srv.as_ref() {
            raw::abort_with_rst(srv.as_fd());
        }
        if sess.queue.leave() {
            sess.strm.log.queue.get_or_insert_with(crate::txnlog::loop_now);
            sess.strm.log.term = Some(*b"CQ");
        } else if txn.local {
            // A reply of the proxy's own keeps the status and ending it was given.
        } else if waiting {
            sess.strm.log.status = Some(400);
            sess.strm.log.term = Some(if request_done { *b"CD" } else { *b"CH" });
        } else {
            sess.strm.log.term = Some(*b"CD");
        }
    }
    sess.rep.clear();
    sess.req.clear();
    sess.srv_state = ScState::Closed;
    true
}

/// The HTTP/2 client's connection ended under a stream's transaction: a request all sent
/// and a response not all delivered is aborted (`CH--` with a 400 waiting for the response
/// head, `CD--` during the body), its server connection reset. `true` when it was; the
/// caller then closes the session.
pub fn abort_on_client_left(sess: &mut TcpSession) -> bool {
    // A request still coming is cut short by the caller; a reply of the proxy's own, a
    // response all in, or one already ending have nothing to abort.
    let Some(txn) = sess
        .strm
        .txn
        .as_ref()
        .filter(|t| t.req.is_done() && !(t.local || t.aborted || t.req == MsgState::Tunnel || t.rsp.is_done()))
    else {
        return false;
    };
    let waiting = txn.rsp == MsgState::Waiting;
    if let Some(srv) = sess.srv.as_ref() {
        raw::abort_with_rst(srv.as_fd());
    }
    if waiting {
        sess.strm.log.status = Some(400);
        sess.strm.log.term = Some(*b"CH");
    } else {
        sess.strm.log.term = Some(*b"CD");
    }
    sess.rep.clear();
    true
}

/// Writes what has come of an HTTP/2 request's body into `req`, as much as there is room
/// for: each DATA frame as it is, or as a chunk when the request has no length, and the
/// end as the last chunk. True if anything was written. A DATA block written out whole
/// is released: the stream holds only what is still to go (T195's 50 MB upload was held
/// until the stream ended).
pub(crate) fn pump_h2_body(msg: &mut alcyon_proto::htx::Htx, st: &mut H2ReqBody, req: &mut Buf) -> bool {
    pump_htx_body(msg, st, req, drop)
}

/// `req`'s free memory less the last `keep` bytes.
fn writable_less(req: &mut Buf, keep: usize) -> &mut [u8] {
    let w = req.writable();
    let n = w.len().saturating_sub(keep);
    &mut w[..n]
}

/// [`pump_h2_body`], a block written out whole given to `release` (T512: h3's pool).
fn pump_htx_body(msg: &mut alcyon_proto::htx::Htx, st: &mut H2ReqBody, req: &mut Buf, mut release: impl FnMut(Vec<u8>)) -> bool {
    let blocks = msg.blocks_mut();
    // The room the head takes once it is written (X4: it is in its HTX until the send), as
    // the head takes room in `HAProxy`'s channel buffer: a DATA frame that did not fit beside
    // it does not fit now either (T322's receive slots).
    let keep = st.head_room;
    let mut wrote = false;
    while !st.done && st.cursor < blocks.len() {
        match &blocks[st.cursor] {
            HtxBlock::Data(d) | HtxBlock::RawData(d) => {
                let rest = &d[st.off.min(d.len())..];
                if rest.is_empty() {
                    st.cursor += 1;
                    st.off = 0;
                    continue;
                }
                // A chunk's size line takes at most 8 bytes, with its two CRLFs.
                let framing = if st.chunked { 12 } else { 0 };
                // The head went into a small buffer (T312); a body takes a full one, else
                // it goes to the server a kilobyte at a time (4 uploads of 256 KB: 256
                // writes each, ~35 ms a round where `HAProxy` takes 7).
                req.promote_to_standard();
                let room = writable_less(req, keep);
                if room.len() <= framing {
                    break;
                }
                let n = rest.len().min(room.len() - framing);
                let at = if st.chunked {
                    crate::txn::chunk_size_line(n as u64, room)
                } else {
                    0
                };
                room[at..at + n].copy_from_slice(&rest[..n]);
                let mut len = at + n;
                if st.chunked {
                    room[len..len + 2].copy_from_slice(b"\r\n");
                    len += 2;
                }
                req.commit(len);
                wrote = true;
                st.off += n;
                st.consumed += n as u64;
                if st.off >= d.len() {
                    if let HtxBlock::Data(d) | HtxBlock::RawData(d) = &mut blocks[st.cursor] {
                        release(std::mem::take(d));
                    }
                    st.cursor += 1;
                    st.off = 0;
                }
            }
            HtxBlock::Trailer(h) => {
                // Trailers can follow only a chunked body: with a length they are dropped.
                if st.chunked && !st.drop_trailers {
                    let mut line = Vec::with_capacity(h.name.len() + h.value.len() + 7);
                    if !st.trailing {
                        line.extend_from_slice(b"0\r\n");
                    }
                    line.extend_from_slice(h.name.as_bytes());
                    line.extend_from_slice(b": ");
                    line.extend_from_slice(h.value.as_bytes());
                    line.extend_from_slice(b"\r\n");
                    let room = writable_less(req, keep);
                    if room.len() < line.len() {
                        break;
                    }
                    room[..line.len()].copy_from_slice(&line);
                    req.commit(line.len());
                    wrote = true;
                    st.trailing = true;
                }
                // Dropped or forwarded, `HAProxy` counts them.
                st.trailer_bytes += (h.name.len() + h.value.len()) as u64;
                st.cursor += 1;
            }
            HtxBlock::Eot => {
                if st.chunked && st.trailing {
                    let room = writable_less(req, keep);
                    if room.len() < 2 {
                        break;
                    }
                    room[..2].copy_from_slice(b"\r\n");
                    req.commit(2);
                    wrote = true;
                }
                st.trailer_bytes += 1;
                st.cursor += 1;
            }
            HtxBlock::Eom => {
                if st.chunked && !st.trailing {
                    let room = writable_less(req, keep);
                    if room.len() < 5 {
                        break;
                    }
                    room[..5].copy_from_slice(b"0\r\n\r\n");
                    req.commit(5);
                    wrote = true;
                }
                st.done = true;
            }
            _ => st.cursor += 1,
        }
    }
    wrote
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::Timeouts;
    use alcyon_proto::conn::ConnId;
    use std::os::unix::net::UnixStream;

    fn session() -> (TcpSession, UnixStream) {
        let (cli, peer) = UnixStream::pair().expect("pair");
        (TcpSession::new(cli.into(), Timeouts::default(), 0, alcyon_sched::Tick(1000)), peer)
    }

    /// A stream's session, the child of an HTTP/2 connection's (T280).
    fn child() -> (TcpSession, TcpSession, UnixStream) {
        let (mut owner, peer) = session();
        owner.h2_ctx = Some(Box::new(H2MuxContext::new(ConnId(0), true)));
        let stream = H2ActiveStream { id: 1, body: H2ReqBody::default(), chunk_out: false };
        let c = TcpSession::h2_child_of(&mut owner, (0, alcyon_sched::TaskRef::NONE), stream);
        (c, owner, peer)
    }

    fn dispatch(head: DispatchHead) -> H2Dispatch {
        H2Dispatch {
            stream: H2ActiveStream { id: 1, body: H2ReqBody::default(), chunk_out: false },
            head,
            req_htx: 7,
            request_line: None,
            bad_request: false,
            no_memory: false,
            add_len: None,
        }
    }

    #[test]
    fn trailer_fields_are_the_text_lines_with_a_colon_up_to_the_cap() {
        let mut out = [("", ""); MAX_TRAILER_FIELDS];
        let n = trailer_fields(b"x-a: 1\r\nno colon\r\nx-b:2\r\nx-\xff: 3\r\nx-c: \xff\r\nx-d:  4 \r\n\r\n", &mut out);
        assert_eq!(&out[..n], [("x-a", "1"), ("x-b", "2"), ("x-d", "4")]);
        let many: Vec<u8> = (0..MAX_TRAILER_FIELDS + 5).flat_map(|i| format!("x-{i}: v\r\n").into_bytes()).collect();
        assert_eq!(trailer_fields(&many, &mut out), MAX_TRAILER_FIELDS);
    }

    /// The decoded fields of a head, as the mux has them.
    fn decoded(fields: &[(&[u8], &[u8])]) -> alcyon_proto::hpack::DecodedFields {
        let mut enc = alcyon_proto::hpack::HpackEncoder::new();
        let mut block = Vec::new();
        for (n, v) in fields {
            enc.encode_field_bytes(n, v, &mut block);
        }
        let mut d = alcyon_proto::hpack::DecodedFields::default();
        alcyon_proto::hpack::HpackDecoder::new().decode_into(&block, &mut d).expect("decodes");
        d
    }

    /// The text of a head the HTTP/1 checks refuse, as the mux keeps it.
    fn text(fields: &[(&[u8], &[u8])]) -> DispatchHead {
        DispatchHead::Text(Box::new(alcyon_proto::h2::write_request_text(&decoded(fields), false, None).expect("a head the checks take")))
    }

    #[test]
    fn a_head_the_h1_parser_refuses_still_starts_the_transaction_without_parsed_htx() {
        let (mut s, _owner, _peer) = child();
        start_request(&mut s, dispatch(text(&[(b":method", b"G T"), (b":scheme", b"https"), (b":path", b"/p")])));
        assert!(!s.has_htx, "the parser refused the head: no HTX for the rules");
        assert_eq!(s.req.readable(), b"G T /p HTTP/1.1\r\n\r\n", "the head is in `req` as it came");
        assert_eq!((s.req_method.as_deref(), s.req_uri.as_deref()), (Some("G T"), Some("/p")));
        assert_eq!(s.strm.txn.as_ref().and_then(|t| t.req_htx), Some(7));
        assert_eq!(s.h2_active().map(|a| a.id), Some(1));
        assert_eq!(s.cli_state, ScState::Established);
        // The same with a head it takes: parsed for the rules.
        let (mut s, _owner, _peer) = child();
        let (rx, facts, abs_len) = written(&[(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/"), (b"host", b"x")]);
        start_request(&mut s, dispatch(DispatchHead::Htx { rx, facts, abs_len, version: "HTTP/2.0" }));
        assert!(s.has_htx, "a valid head is parsed");
        // X4: in its HTX alone until the send writes it, once.
        assert!(s.req.readable().is_empty() && s.req_head_pending, "no text before the send");
        assert!(write_pending_head(&mut s, false, None));
        assert_eq!(s.req.readable(), b"GET / HTTP/1.1\r\nhost: x\r\n\r\n");
        assert!(!s.req_head_pending && !write_pending_head(&mut s, false, None), "written once");
    }

    /// CP2b-2: the text of a head the checks refuse is forwarded with the canonical
    /// `content-length` in place of the client's (counted as `%U` counts it), the raw bytes of
    /// a path that is not UTF-8, and `transfer-encoding: chunked` for a body with no length.
    #[test]
    fn a_text_head_goes_out_framed_with_its_bytes() {
        let (mut s, _owner, _peer) = child();
        s.keep_request_line = true;
        let mut d = dispatch(text(&[(b":method", b"POST"), (b":scheme", b"https"), (b":path", b"/caf\xe9"), (b":authority", b"x"), (b"content-length", b"005")]));
        let DispatchHead::Text(t) = &d.head else { panic!("text") };
        d.add_len = t.add_len;
        d.request_line = Some("POST https://x/caf\u{f7e9} HTTP/2.0".to_string());
        start_request(&mut s, d);
        assert_eq!(s.req.readable(), b"POST /caf\xe9 HTTP/1.1\r\nhost: x\r\ncontent-length: 5\r\n\r\n");
        let txn = s.strm.txn.as_ref().expect("a transaction");
        assert_eq!(txn.req_htx, Some(7 - 3 + 1), "`005` counted as the `5` it goes out as");
        assert!(txn.req_len_hdrs.is_some_and(|l| l.clen));
        assert_eq!(s.strm.log.request_line.as_deref(), Some("POST https://x/caf\u{f7e9} HTTP/2.0"));
        assert_eq!((s.req_headers.as_ref().map(Vec::len), s.has_htx), (Some(2), false));

        let (mut s, _owner, _peer) = child();
        let mut d = dispatch(text(&[(b":method", b"POST"), (b":scheme", b"https"), (b":path", b"/a\xe9"), (b":authority", b"x")]));
        d.stream.chunk_out = true;
        start_request(&mut s, d);
        assert_eq!(s.req.readable(), b"POST /a\xe9 HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n");
    }

    /// CP2b-2: no head (no memory for it) fails the transaction at once, whatever came.
    #[test]
    fn no_head_fails_the_transaction_at_once() {
        let (mut s, _owner, _peer) = child();
        let mut d = dispatch(DispatchHead::None);
        d.no_memory = true;
        start_request(&mut s, d);
        assert!(!s.has_htx && s.req.readable().is_empty());
        assert!(s.strm.txn.as_ref().is_some_and(|t| t.req_htx == Some(7)));
    }

    /// The HTX blocks `write_request_htx` writes of `fields` into 1 KB, as the h2 mux does
    /// (CP2), with `https://x` after them.
    fn written(fields: &[(&[u8], &[u8])]) -> (RxHead, HeadFacts, usize) {
        let d = decoded(fields);
        let mut rx = RxHead::from_box(vec![0; 1024].into_boxed_slice());
        let facts = alcyon_proto::h2::write_request_htx(&d, &mut alcyon_proto::htx::HtxSlice::over(&mut rx), false).expect("written");
        rx.bytes_mut()[facts.tail..facts.tail + 9].copy_from_slice(b"https://x");
        (rx, facts, 9)
    }

    /// An h3 request's HEADERS frame (and, when `body` is not empty, one DATA frame).
    fn h3_request(method: &str, body: &[u8]) -> Vec<u8> {
        let f: Vec<(String, String)> = [(":method", method), (":scheme", "https"), (":authority", "x"), (":path", "/a")]
            .iter()
            .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
            .collect();
        let mut req = Vec::new();
        alcyon_proto::mux_h3::encode_frame(&mut req, 0x01, &alcyon_proto::mux_h3::encode_field_section(&f));
        if !body.is_empty() {
            alcyon_proto::mux_h3::encode_frame(&mut req, 0x00, body);
        }
        req
    }

    /// CP2b: an h3 head the mux wrote as blocks is dispatched as the same `DispatchHead::Htx`
    /// as h2's, with the h3 version on the log line and chunked framing for a body with no
    /// length; no memory for the blocks dispatches no head and says so (S5).
    #[test]
    fn an_h3_head_the_mux_wrote_is_dispatched_as_blocks() {
        let mut m = alcyon_proto::mux_h3::H3MuxContext::new();
        m.open_control(3);
        m.recv(0, &h3_request("GET", b""), true, 0).expect("request");
        m.recv(4, &h3_request("POST", b"hello"), false, 0).expect("request");
        let d = dispatch_mux(&mut m, true, "HTTP/3.0").expect("a stream");
        assert!(!d.no_memory && d.request_line.is_none() && d.add_len.is_none() && !d.stream.chunk_out);
        // `%U`: 20 + "GET" + "https://x" + "/a" + "HTTP/3.0" + 1 + "host" + "x".
        assert_eq!(d.req_htx, 20 + 3 + 9 + 2 + 8 + 1 + 5);
        let DispatchHead::Htx { version, abs_len, .. } = d.head else { panic!("blocks") };
        assert_eq!((version, abs_len), ("HTTP/3.0", 9));
        let d = dispatch_mux(&mut m, true, "HTTP/3.0").expect("a stream");
        assert!(d.stream.chunk_out, "a body with no length goes out chunked");
        assert_eq!(d.req_htx, 20 + 4 + 9 + 2 + 8 + 1 + 5 - 1);
        assert!(matches!(d.head, DispatchHead::Htx { .. }));

        fn none(_: usize) -> Option<RxHead> {
            None
        }
        m.take_rx_head = none;
        m.recv(8, &h3_request("GET", b""), true, 0).expect("request");
        let d = dispatch_mux(&mut m, true, "HTTP/3.0").expect("a stream");
        assert!(d.no_memory && matches!(d.head, DispatchHead::None));
    }

    /// CP2: a head the h2 mux wrote as blocks is the stream's `htx_buf`, the memory moved,
    /// not copied: its log line and method from its start line, framed and counted (`%U`) by
    /// the one canonical `content-length` the blocks hold in place of the client's `005`.
    #[test]
    fn a_head_the_mux_wrote_is_adopted_as_the_streams_htx() {
        let (rx, facts, abs_len) = written(&[(b":method", b"POST"), (b":scheme", b"https"), (b":path", b"/a"), (b":authority", b"x"), (b"content-length", b"005")]);
        let ptr = rx.bytes().as_ptr();
        let (mut s, _owner, _peer) = child();
        s.keep_request_line = true;
        let mut d = dispatch(DispatchHead::None);
        d.head = DispatchHead::Htx { rx, facts, abs_len, version: "HTTP/2.0" };
        start_request(&mut s, d);
        assert_eq!(s.htx_buf.raw_slice().as_ptr(), ptr, "adopted, not copied");
        assert!(s.has_htx && s.req_head_pending && s.req.readable().is_empty());
        assert_eq!((s.req_method.as_deref(), s.req_uri.as_deref()), (Some("POST"), Some("/a")));
        assert_eq!(s.strm.log.request_line.as_deref(), Some("POST https://x/a HTTP/2.0"));
        let txn = s.strm.txn.as_ref().expect("a transaction");
        // `content-length: 005` counted as the `content-length: 5` the HTX holds.
        assert_eq!(txn.req_htx, Some(7 - 2));
        assert!(txn.req_len_hdrs.is_some_and(|l| l.clen));
        assert!(write_pending_head(&mut s, false, None));
        assert_eq!(s.req.readable(), b"POST /a HTTP/1.1\r\nhost: x\r\ncontent-length: 5\r\n\r\n");

        // `content-length: 0` is no body; a request without one and no line kept logs none.
        let (rx, facts, abs_len) = written(&[(b":method", b"POST"), (b":scheme", b"https"), (b":path", b"/"), (b":authority", b"x"), (b"content-length", b"0")]);
        let (mut s, _owner, _peer) = child();
        let mut d = dispatch(DispatchHead::None);
        d.head = DispatchHead::Htx { rx, facts, abs_len, version: "HTTP/2.0" };
        start_request(&mut s, d);
        assert_eq!(s.strm.log.request_line.as_deref(), None);
        let txn = s.strm.txn.as_ref().expect("a transaction");
        assert_eq!(txn.req_htx, Some(7));
        assert!(txn.req_len_hdrs.is_some_and(|l| !l.clen));

        // Blocks with no start line (none the mux writes): no method, nothing read past them.
        let (rx, mut facts, _) = written(&[(b":method", b"GET"), (b":path", b"/")]);
        facts.blocks = 0;
        let (mut s, _owner, _peer) = child();
        s.keep_request_line = true;
        let mut d = dispatch(DispatchHead::None);
        d.head = DispatchHead::Htx { rx, facts, abs_len: 0, version: "HTTP/2.0" };
        start_request(&mut s, d);
        assert_eq!((s.req_method.as_deref(), s.strm.log.request_line.as_deref()), (Some(""), Some("  HTTP/2.0")));
    }

    #[test]
    fn a_stream_the_mux_no_longer_has_moves_no_body() {
        let mut h2 = H2MuxContext::new(ConnId(0), true);
        let mut active = H2ActiveStream { id: 9, body: H2ReqBody::default(), chunk_out: false };
        let mut req = Buf::with_capacity(64);
        let tx = h2.tx_buf.len();
        assert_eq!(pump_request_body(&mut h2, &mut active, &mut req), (false, 0));
        assert!(req.is_empty());
        assert_eq!(active.body.consumed, 0);
        assert_eq!(h2.tx_buf.len(), tx, "no WINDOW_UPDATE for it");
    }

    #[test]
    fn a_response_head_without_a_body_is_one_headers_frame_with_end_stream() {
        let mut h2 = H2MuxContext::new(ConnId(0), true);
        let mut txn = HttpTxn::new(txn::Framing::None, false);
        txn.rsp = MsgState::Head { left: 0, body: txn::Framing::None };
        let mut rep = Buf::with_capacity(256);
        assert!(rep.put(b"HTTP/1.1 204 No Content\r\nx-a: b\r\n\r\n"));
        let tx = h2.tx_buf.len();
        assert!(!forward_response(&mut h2, 1, &mut txn, &mut rep, false, &mut None, &mut None));
        assert!(rep.is_empty(), "the head was taken");
        let frame = &h2.tx_buf[tx..];
        assert!(frame.len() > 9, "a frame was queued");
        assert_eq!(frame[3], 1, "HEADERS");
        assert_eq!(frame[4] & 1, 1, "END_STREAM");
        assert_eq!(frame.len(), 9 + ((usize::from(frame[0]) << 16) | (usize::from(frame[1]) << 8) | usize::from(frame[2])), "and nothing after it");
    }

    #[test]
    fn a_head_that_is_no_response_head_is_held_and_sends_nothing() {
        let mut h2 = H2MuxContext::new(ConnId(0), true);
        let mut txn = HttpTxn::new(txn::Framing::None, false);
        txn.rsp = MsgState::Head { left: 0, body: txn::Framing::Length(5) };
        let mut rep = Buf::with_capacity(256);
        let head = b"garbage\r\n\r\n";
        assert!(rep.put(head));
        let tx = h2.tx_buf.len();
        assert!(!forward_response(&mut h2, 1, &mut txn, &mut rep, false, &mut None, &mut None));
        assert_eq!(rep.readable(), head, "nothing of it was taken");
        assert_eq!(txn.rsp, MsgState::Head { left: 0, body: txn::Framing::Length(5) });
        assert_eq!(h2.tx_buf.len(), tx, "no frame");
    }

    #[test]
    fn a_reset_with_no_transaction_changes_nothing() {
        let (mut s, _peer) = session();
        let state = s.srv_state;
        assert!(!abort_reset_stream(&mut s));
        assert!(s.strm.log.term.is_none());
        assert_eq!(s.srv_state, state);
    }
}
