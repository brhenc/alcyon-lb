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
use ibex_proto::endpoint::ScState;
use ibex_proto::htx::HtxBlock;
use ibex_proto::htx_mux::{HtxMux, HtxStream, MuxReset};
use ibex_proto::mux_h2::{H2MuxContext, H2ReqHead};
use std::os::fd::AsFd;

/// A stream taken from the mux to be served: everything its transaction starts from.
pub struct H2Dispatch {
    pub stream: H2ActiveStream,
    /// The request head as its checked fields, as the client sent them (without the
    /// `transfer-encoding: chunked` a request with no length goes out with), with its start
    /// line: memory of the connection's, given back once the transaction has started
    /// ([`start_request`], T437, E1).
    pub head: Box<H2ReqHead>,
    /// What `%U` counts of the head.
    pub req_htx: u64,
    /// The line `%r` prints, when the frontend keeps it.
    pub request_line: Option<String>,
    /// A request `HAProxy` answers 400 without contacting a server
    /// ([`ibex_proto::H2StreamCtx::bad_request`]).
    pub bad_request: bool,
    /// The `content-length` the forwarded head gets in place of the client's: one whose
    /// length was not written once in its canonical form (`5, 5`, `005`, twice: `HAProxy` 3.5-dev7 forwards
    /// `content-length: 5`, T509).
    pub add_len: Option<u64>,
}

/// Takes the lowest stream of the connection that has its whole request head and has not
/// been served yet, and marks it served. `None` when there is none.
pub fn dispatch_next(h2: &mut H2MuxContext, keep_request_line: bool) -> Option<H2Dispatch> {
    let stream_id = *h2.streams.keys().find(|&&id| {
        h2.streams.get(&id).is_some_and(|st| {
            !st.dispatched
                && st.state != ibex_proto::H2StreamState::Closed
                && !matches!(st.state, ibex_proto::H2StreamState::Reset(_))
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
    let chunked = !stream.ext_connect && stream.req_head.as_ref().and_then(|h| h.get_header("content-length")).is_none() && (has_data || !stream.rx_htx.is_eom());
    let first_body = stream.rx_htx.blocks().iter().position(|b| matches!(b, HtxBlock::Eoh)).map_or(stream.rx_htx.blocks().len(), |i| i + 1);
    // The head as the mux wrote it (T437); the stream keeps none past this.
    let head = stream.req_head.take()?;
    let add_len = added_len(&head, stream.req_content_length.map(|n| n as u64));
    // `%U`, and the line `%r` prints, are those of the message the client sent:
    // `transfer-encoding: chunked` is added on output only, so the rules do not see it
    // either (only the forwarded head has it). The chunked end the forwarded body is
    // counted with (+1 when it is consumed) is not in `HAProxy`'s message unless trailers
    // precede it.
    let req_htx = h2_head_size(&head).saturating_sub(u64::from(chunked));
    let request_line = (keep_request_line && head.has_line)
        .then(|| format!("{} {}{} HTTP/2.0", head.method(), head.abs_prefix().unwrap_or(""), head.uri()));
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
        add_len,
    })
}

/// [`dispatch_next`] for any mux the bridge drives (T509): the stream the mux says may be
/// served next, marked served. `version` is what `%r` prints after the target. A stream id
/// past `u32` (2^30 requests on one connection) is refused, as the stream entries count
/// in `u32`.
pub fn dispatch_mux<M: HtxMux>(mux: &mut M, keep_request_line: bool, version: &str) -> Option<H2Dispatch> {
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
    let head = stream.take_req_fields()?;
    let has_len = cl.is_some();
    // A body without `content-length` goes chunked, also when all of it came with the head
    // (measured on `HAProxy` 3.5-dev7 with QUIC, T511).
    let add_len = added_len(&head, cl);
    let chunked = !has_len && add_len.is_none() && (has_data || !eom);
    let req_htx = h2_head_size(&head).saturating_sub(u64::from(chunked));
    let request_line = (keep_request_line && head.has_line)
        .then(|| format!("{} {}{} {version}", head.method(), head.abs_prefix().unwrap_or(""), head.uri()));
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
        add_len,
    })
}

/// The length a head goes with in place of its `content-length` lines (`cl`, as the mux
/// read them) when they are not one line of its digits (`005`, `5, 5`, two lines): `HAProxy`
/// forwards the digits (3.5-dev7 with QUIC, T509; 3.5-dev8 over h2, E1). `None` when they are.
fn added_len(head: &H2ReqHead, cl: Option<u64>) -> Option<u64> {
    let mut lens = head.headers().filter(|(k, _)| k.eq_ignore_ascii_case(b"content-length"));
    let canonical = match (cl, lens.next(), lens.next()) {
        (Some(n), Some((_, v)), None) => {
            let v = std::str::from_utf8(v).unwrap_or("");
            (v.parse::<u64>().ok() == Some(n) && !v.starts_with('0')) || v == "0"
        }
        (None, None, _) => true,
        _ => false,
    };
    if canonical { None } else { cl }
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
/// the request's log fields, and the transaction. The head's memory is given back, for the
/// connection's next streams ([`H2MuxContext::give_back_head`]).
pub fn start_request(sess: &mut TcpSession, d: H2Dispatch) -> Box<H2ReqHead> {
    let chunked = d.stream.chunk_out;
    if let Some(c) = sess.h2_child_mut() {
        c.stream = d.stream;
    }
    if sess.keep_request_line {
        sess.log.request_line.set_opt(d.request_line.as_deref());
    }
    sess.log.request = Some(crate::txnlog::loop_now());
    // An extended CONNECT to a websocket goes to the server with the `Sec-WebSocket-Key`
    // an HTTP/2 client does not send, which the server's accept must then answer
    // (`h1_process_mux` adds it to a handshake that has none, T505). It is in the head the
    // rules see, as the key the HTTP/1 path writes is (`HAProxy` adds it on output, after
    // the headers the rules add).
    let (ws, key) = if d.head.ext_connect {
        crate::websocket::ReqWs::of(d.head.text_headers(), true)
    } else {
        (crate::websocket::ReqWs::default(), None)
    };
    sess.req_ws = (ws != crate::websocket::ReqWs::default()).then(|| Box::new(ws));
    let key_line = key.as_ref().map_or(0, |k| "sec-websocket-key: \r\n".len() + k.len());
    // The head as HTTP/1.1 text would be this long (the line, each field, the blank line).
    let wire_len = d.head.wire_len() + key_line;
    // A head of a few hundred bytes takes a small buffer, not a pooled 16 KB one that a held
    // stream would keep for its whole life (T312; `HAProxy` holds no buffer for one). A
    // rewrite that needs more makes room (`htx_reserve`), as for any HTX.
    let lines = d.head.fields.len() + 2 + usize::from(key.is_some());
    let need = wire_len + 64 + ibex_proto::htx::HTX_DESC_SIZE * (lines + 3);
    if need * 2 <= crate::buf::get_bufsize_small() && sess.htx_buf.raw_slice().is_empty() {
        sess.htx_buf = Buf::unallocated(crate::buf::BufClass::Small);
    }
    let raw = sess.htx_buf.htx_slice_mut();
    // A buffer that cannot be had fails this stream (S5), once its transaction is set up.
    let mut no_mem = raw.is_empty();
    let mut slice = ibex_proto::htx::HtxSlice::new(raw);
    let extra = key.as_deref().map(|k| ("sec-websocket-key", k));
    // The list the samples read once the HTX is let go, in the memory of the session's
    // (or, for a new stream, its connection's) previous list: the head's fields, copied as
    // they are written into the HTX (T437).
    let hdrs = sess.req_headers.get_or_insert_with(Vec::new);
    let mut n = 0;
    let parsed = slice.put_request_head(&d.head, extra, |k, v| copy_header(hdrs, &mut n, k, v)).is_ok();
    hdrs.truncate(n);
    let (tail, blocks) = (slice.tail_addr(), slice.num_blocks());
    let line = d.head.has_line;
    sess.req_method.set_opt(line.then(|| d.head.method()));
    sess.req_uri.set_opt(line.then(|| d.head.uri()));
    // `%U` counts the `content-length` the HTX holds, one canonical value in place of the
    // client's (`005`, `5, 5`, a repeat: `HAProxy` 3.5-dev8 forwards and counts `5`).
    let mut req_htx = d.req_htx;
    if parsed {
        if d.head.get_header("content-length").is_some() {
            let client: usize = d.head.headers().filter(|(n, _)| n.eq_ignore_ascii_case(b"content-length")).map(|(n, v)| n.len() + v.len()).sum();
            let kept: usize = slice.as_ref().header_blocks_where(|n| n.eq_ignore_ascii_case(b"content-length")).map(|(_, n, v)| n.len() + v.len()).sum();
            req_htx = (req_htx + kept as u64).saturating_sub(client as u64);
        }
    } else {
        // As above: `%U` counts the digits the head goes with.
        if let Some(n) = d.add_len {
            let client: usize = d.head.headers().filter(|(k, _)| k.eq_ignore_ascii_case(b"content-length")).map(|(k, v)| k.len() + v.len()).sum();
            req_htx = (req_htx + ("content-length".len() + n.to_string().len()) as u64).saturating_sub(client as u64);
        }
        // With no HTX, a rule's edit writes the head from this list: the key is in it.
        let hdrs = sess.req_headers.get_or_insert_with(Vec::new);
        copy_headers(hdrs, d.head.text_headers().chain(key.as_deref().map(|k| ("sec-websocket-key", k))));
    }
    sess.req.clear();
    // The head waits here for a server connection (a stream held in the queue, or whose body
    // never comes, keeps it): a small buffer for a small head, which grows with the body.
    let out_len = wire_len + if chunked { "transfer-encoding: chunked\r\n".len() } else { 0 };
    if out_len * 2 <= crate::buf::get_bufsize_small() && sess.req.raw_slice().is_empty() {
        sess.req = Buf::unallocated(crate::buf::BufClass::Small);
    }
    no_mem |= !sess.req.alloc_if_needed();
    if parsed {
        // The head written once, from the HTX, as a rule's edit writes it (`write_req_head`).
        let w = sess.req.writable();
        // The buffer is sized for the head (`out_len`); one it does not fit fails the stream
        // as a buffer that cannot be had does, rather than going out cut short.
        let n = slice.as_ref().write_h1_wire(w).unwrap_or(0);
        no_mem |= n == 0;
        // A request without a length goes chunked, the header after the others, which no
        // rule sees; without room for it the stream fails, not the framing.
        let te = chunked && n >= 2 && w.len() >= n - 2 + TE.len();
        no_mem |= chunked && !te;
        let n = if te {
            w[n - 2..n - 2 + TE.len()].copy_from_slice(TE);
            n - 2 + TE.len()
        } else {
            n
        };
        sess.req.commit(n);
    } else {
        let wire = text_wire(&d.head, key.as_deref(), chunked, d.add_len);
        let n = copy_into(sess.req.writable(), &wire);
        sess.req.commit(n);
    }
    // What a refused head wrote is zeroed on release like the rest (`tune.ibex.zero-buffers`).
    sess.htx_buf.note_htx(tail, blocks * ibex_proto::htx::HTX_DESC_SIZE);
    if parsed {
        sess.htx_tail = tail;
        sess.htx_blocks = blocks;
        sess.has_htx = true;
        sess.htx_modified = false;
    }
    let wire_req = sess.req.readable();
    let framing = find_eoh(wire_req).map_or(txn::Framing::None, |(h, e)| txn::request_framing(&wire_req[..h + e]));
    let mut txn = HttpTxn::new(framing, false);
    txn.req_htx = Some(req_htx);
    // Framed by the client's length, read again after the rules (T442): one a rule removed
    // goes as `content-length: 0` with no body. A body sent chunked has its
    // `transfer-encoding` on output only, which no rule sees.
    txn.req_len_hdrs = Some(txn::LenHdrs { clen: matches!(framing, txn::Framing::Length(_)), chnk: false });
    sess.txn = Some(txn);
    sess.cli_state = ScState::Established;
    if d.bad_request {
        sess.fail_request(400);
    } else if no_mem {
        sess.fail_alloc();
    }
    d.head
}

/// The last header of a request sent chunked, and the blank line.
const TE: &[u8] = b"transfer-encoding: chunked\r\n\r\n";

/// `src` into `dst`, as much as fits: the bytes copied.
fn copy_into(dst: &mut [u8], src: &[u8]) -> usize {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    n
}

/// The head as HTTP/1.1 text, for one the HTX cannot be written from (the HTTP/1 parser
/// refuses it: a request `HAProxy` answers 400, a CONNECT; nothing then reads its HTX): as
/// the bridge wrote every head before E1, the websocket key after the fields, then either
/// `transfer-encoding: chunked` or the canonical `content-length` in place of the client's.
#[cold]
#[inline(never)]
fn text_wire(head: &H2ReqHead, key: Option<&str>, chunked: bool, add_len: Option<u64>) -> Vec<u8> {
    let mut head = head.to_wire();
    if let Some(k) = key {
        let at = head.len() - 2;
        head.splice(at..at, [&b"sec-websocket-key: "[..], k.as_bytes(), b"\r\n"].concat());
    }
    let at = find_eoh(&head).map_or(head.len(), |(h, _)| h);
    if chunked {
        return chunked_head(&head, at);
    }
    let Some(n) = add_len else { return head };
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

/// [`forward_response`] for any mux the bridge drives (T509), the DATA staged in `scratch`.
pub fn forward_response_mux<M: HtxMux>(mux: &mut M, stream_id: u32, txn: &mut HttpTxn, rep: &mut Buf, srv_gone: bool, scratch: &mut Vec<u8>, late_trailers: &mut Option<ibex_alloc::PoolBox<Vec<u8>>>) -> bool {
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
        if mux.send_head(id, &data[..h], end_stream) {
            txn.rsp.consume(data, h + e);
            rep.consume(h + e);
            if !end_stream {
                return forward_response_mux(mux, stream_id, txn, rep, srv_gone, scratch, late_trailers);
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
pub fn forward_response(h2: &mut H2MuxContext, stream_id: u32, txn: &mut HttpTxn, rep: &mut Buf, srv_gone: bool, late_trailers: &mut Option<ibex_alloc::PoolBox<Vec<u8>>>) -> bool {
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
        if h2.send_h1_head(stream_id, &data[..h], end_stream) {
            txn.rsp.consume(data, h + e);
            rep.consume(h + e);
            // The body that came with the head goes out with it, in the same write: on
            // its own, a poller round later, it is a second write, and a second small
            // segment Nagle holds until the client's delayed ACK, ~40 ms a request (T186).
            if !end_stream {
                return forward_response(h2, stream_id, txn, rep, srv_gone, late_trailers);
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
        h2.send_rst_stream(stream_id, ibex_proto::h2::H2Error::InternalError);
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
        h2.send_rst_stream(stream_id, ibex_proto::h2::H2Error::Cancel);
        true
    };
    txn.rsp = MsgState::Done;
    cut_short
}

/// Whether the client (or the mux, for a stream error) has reset stream `id`.
#[must_use]
pub fn stream_is_reset(h2: &H2MuxContext, id: u32) -> bool {
    h2.streams.get(&id).is_some_and(|s| matches!(s.state, ibex_proto::h2::H2StreamState::Reset(_)))
}

/// The transaction of a stream that was reset ends here: nothing more is sent on the
/// stream, the server connection is reset, and the log reads `400 ... CH--` waiting for
/// the response head with the request not all in (`400 ... CD--` with it all in, T521),
/// `CD--` during the body, `CQ` queued (`HAProxy` 3.5-dev8, T273 B).
/// What is left in either buffer is dropped, as it would be taken for the next stream's.
/// The caller ends the transaction. `false` when there is none.
pub fn abort_reset_stream(sess: &mut TcpSession) -> bool {
    let Some(txn) = sess.txn.as_mut() else {
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
            sess.log.queue.get_or_insert_with(crate::txnlog::loop_now);
            sess.log.term = Some(*b"CQ");
        } else if txn.local {
            // A reply of the proxy's own keeps the status and ending it was given.
        } else if waiting {
            sess.log.status = Some(400);
            sess.log.term = Some(if request_done { *b"CD" } else { *b"CH" });
        } else {
            sess.log.term = Some(*b"CD");
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
        sess.log.status = Some(400);
        sess.log.term = Some(*b"CH");
    } else {
        sess.log.term = Some(*b"CD");
    }
    sess.rep.clear();
    true
}

/// What `%U` counts of an HTTP/2 request's head (`HAProxy`'s HTX: 20 bytes for the start
/// line, its three strings -- the target is `scheme://authority` and the path when the
/// request had both -- and each header's name and value, then the end of the headers).
fn h2_head_size(head: &H2ReqHead) -> u64 {
    // Every head dispatched has a start line: one without `:method` is reset (T437).
    20 + (head.method().len() + head.abs_prefix().map_or(0, str::len) + head.uri().len() + "HTTP/2.0".len()) as u64 + 1 + head.field_bytes as u64
}

/// Writes what has come of an HTTP/2 request's body into `req`, as much as there is room
/// for: each DATA frame as it is, or as a chunk when the request has no length, and the
/// end as the last chunk. True if anything was written. A DATA block written out whole
/// is released: the stream holds only what is still to go (T195's 50 MB upload was held
/// until the stream ended).
pub(crate) fn pump_h2_body(msg: &mut ibex_proto::htx::Htx, st: &mut H2ReqBody, req: &mut Buf) -> bool {
    pump_htx_body(msg, st, req, drop)
}

/// [`pump_h2_body`], a block written out whole given to `release` (T512: h3's pool).
fn pump_htx_body(msg: &mut ibex_proto::htx::Htx, st: &mut H2ReqBody, req: &mut Buf, mut release: impl FnMut(Vec<u8>)) -> bool {
    let blocks = msg.blocks_mut();
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
                let room = req.writable();
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
                    let room = req.writable();
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
                    let room = req.writable();
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
                    let room = req.writable();
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
    use ibex_proto::conn::ConnId;
    use std::os::unix::net::UnixStream;

    fn session() -> (TcpSession, UnixStream) {
        let (cli, peer) = UnixStream::pair().expect("pair");
        (TcpSession::new(cli.into(), Timeouts::default(), 0, ibex_sched::Tick(1000)), peer)
    }

    /// A stream's session, the child of an HTTP/2 connection's (T280).
    fn child() -> (TcpSession, TcpSession, UnixStream) {
        let (mut owner, peer) = session();
        owner.h2_ctx = Some(Box::new(H2MuxContext::new(ConnId(0), true)));
        let stream = H2ActiveStream { id: 1, body: H2ReqBody::default(), chunk_out: false };
        let c = TcpSession::h2_child_of(&mut owner, (0, ibex_sched::TaskRef::NONE), stream);
        (c, owner, peer)
    }

    fn dispatch(head: H2ReqHead) -> H2Dispatch {
        H2Dispatch {
            stream: H2ActiveStream { id: 1, body: H2ReqBody::default(), chunk_out: false },
            head: Box::new(head),
            req_htx: 7,
            request_line: None,
            bad_request: false,
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

    #[test]
    fn a_head_the_h1_parser_refuses_still_starts_the_transaction_without_parsed_htx() {
        let (mut s, _owner, _peer) = child();
        start_request(&mut s, dispatch(H2ReqHead::of("\x01\x02", "not", &[])));
        assert!(!s.has_htx, "the parser refused the head: no HTX for the rules");
        assert_eq!(s.req.readable(), b"\x01\x02 not HTTP/1.1\r\n\r\n", "the head is in `req` as it came");
        assert_eq!(s.txn.as_ref().and_then(|t| t.req_htx), Some(7));
        assert_eq!(s.h2_active().map(|a| a.id), Some(1));
        assert_eq!(s.cli_state, ScState::Established);
        // The same with a head it takes: parsed for the rules.
        let (mut s, _owner, _peer) = child();
        start_request(&mut s, dispatch(H2ReqHead::of("GET", "/", &[("host", "x")])));
        assert!(s.has_htx, "a valid head is parsed");
        assert_eq!(s.req.readable(), b"GET / HTTP/1.1\r\nhost: x\r\n\r\n");
    }

    /// E1: the HTX `put_request_head` writes from a head's fields is the one the HTTP/1
    /// parser made of the same head as text (what the bridge did before), and so is the
    /// head written from it; a head the parser refuses, `put_request_head` refuses.
    #[test]
    fn the_htx_written_from_the_fields_is_the_parsers_of_the_text() {
        let many: Vec<(String, String)> = (0..101).map(|i| (format!("x-{i}"), "v".to_string())).collect();
        let many = |n: usize| many[..n].iter().map(|(a, b)| (a.as_str(), b.as_str())).collect::<Vec<_>>();
        let heads: Vec<(H2ReqHead, Option<&str>)> = vec![
            (H2ReqHead::of("GET", "/", &[("host", "x")]), None),
            (H2ReqHead::of("POST", "/a?b=c", &[("host", "x"), ("content-length", "005"), ("x-b", "1")]), None),
            (H2ReqHead::of("POST", "/", &[("host", "x"), ("content-length", "5"), ("x-b", "1"), ("content-length", "5")]), None),
            (H2ReqHead::of("POST", "/", &[("host", "x"), ("content-length", "5, 5")]), None),
            (H2ReqHead::of("POST", "/", &[("host", "x"), ("content-length", "0")]), None),
            (H2ReqHead::of("POST", "/", &[("host", "x"), ("content-length", "abc")]), None),
            (H2ReqHead::of("POST", "/", &[("host", "x"), ("content-length", "5"), ("content-length", "6")]), None),
            (H2ReqHead::of("GET", "/", &[("host", "x"), ("te", "trailers"), ("x-u", "caf\u{e9}")]), None),
            (H2ReqHead::of("GET", "/", &[("host", "x"), ("upgrade", "websocket"), ("connection", "upgrade")]), Some("dGhlIHNhbXBsZSBub25jZQ==")),
            (H2ReqHead::of("GET", "/", &[("host", "x"), ("upgrade", "websocket"), ("connection", "upgrade")]), None),
            (H2ReqHead::of("GET", "/", &[("host", "x"), ("upgrade", "h2c, foo"), ("connection", "upgrade")]), None),
            (H2ReqHead::of("OPTIONS", "*", &[("host", "x")]), None),
            (H2ReqHead::of("CONNECT", "/", &[("host", "x:443")]), None),
            (H2ReqHead::of("GET", "/caf\u{e9}", &[("host", "x")]), None),
            (H2ReqHead::of("GET", "/a\x7f", &[("host", "x")]), None),
            (H2ReqHead::of("G T", "/", &[("host", "x")]), None),
            (H2ReqHead::of("GET", "/", &[("host", "x,y")]), None),
            (H2ReqHead::of("GET", "/", &many(100)), None),
            (H2ReqHead::of("GET", "/", &many(101)), None),
            (H2ReqHead::of("GET", "/", &[("host", "x"), ("connection", "close")]), None),
        ];
        for (head, key) in &heads {
            let mut text = head.to_wire();
            if let Some(k) = key {
                let at = text.len() - 2;
                text.splice(at..at, format!("sec-websocket-key: {k}\r\n").into_bytes());
            }
            let (mut a, mut b) = (vec![0u8; 16384], vec![0u8; 16384]);
            let mut put = ibex_proto::htx::HtxSlice::new(&mut a);
            let put_ok = put.put_request_head(head, key.map(|k| ("sec-websocket-key", k)), |_, _| {}).is_ok();
            let mut parsed = ibex_proto::htx::HtxSlice::new(&mut b);
            let parse_ok = ibex_proto::H1Parser::new(false).parse(&text, &mut parsed).is_ok();
            let shown = String::from_utf8_lossy(&text);
            assert_eq!(put_ok, parse_ok, "{shown}");
            if put_ok {
                assert_eq!(put.to_blocks(), parsed.to_blocks(), "{shown}");
                assert_eq!(put.to_h1_wire(), parsed.to_h1_wire(), "{shown}");
            }
        }
        // A value that is not UTF-8 is held as Latin-1, as the parser holds it.
        let mut head = H2ReqHead::of("GET", "/", &[("host", "x")]);
        let v = u32::try_from(head.bytes.len()).expect("short");
        head.bytes.extend_from_slice(b"x-ac\xe9");
        head.fields.push((v, v + 3, v + 5));
        let mut buf = vec![0u8; 4096];
        let mut put = ibex_proto::htx::HtxSlice::new(&mut buf);
        put.put_request_head(&head, None, |_, _| {}).expect("put");
        assert_eq!(put.to_h1_wire(), b"GET / HTTP/1.1\r\nhost: x\r\nx-a: c\xe9\r\n\r\n");
        assert!(put.last_header_is_latin1());
        // A cookie's blanks are kept (the parser trimmed them, the bridge put them back).
        let head = H2ReqHead::of("GET", "/", &[("host", "x"), ("cookie", " a=1;  b=2 ")]);
        let mut put = ibex_proto::htx::HtxSlice::new(&mut buf);
        put.put_request_head(&head, None, |_, _| {}).expect("put");
        assert_eq!(put.to_h1_wire(), b"GET / HTTP/1.1\r\nhost: x\r\ncookie:  a=1;  b=2 \r\n\r\n");
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
        assert!(!forward_response(&mut h2, 1, &mut txn, &mut rep, false, &mut None));
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
        assert!(!forward_response(&mut h2, 1, &mut txn, &mut rep, false, &mut None));
        assert_eq!(rep.readable(), head, "nothing of it was taken");
        assert_eq!(txn.rsp, MsgState::Head { left: 0, body: txn::Framing::Length(5) });
        assert_eq!(h2.tx_buf.len(), tx, "no frame");
    }

    #[test]
    fn a_reset_with_no_transaction_changes_nothing() {
        let (mut s, _peer) = session();
        let state = s.srv_state;
        assert!(!abort_reset_stream(&mut s));
        assert!(s.log.term.is_none());
        assert_eq!(s.srv_state, state);
    }
}
