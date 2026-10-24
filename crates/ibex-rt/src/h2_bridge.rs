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
use ibex_proto::mux_h2::{H2MuxContext, H2ReqHead};
use std::os::fd::AsFd;

/// A stream taken from the mux to be served: everything its transaction starts from.
pub struct H2Dispatch {
    pub stream: H2ActiveStream,
    /// The request head as HTTP/1.1, as the client sent it (without the
    /// `transfer-encoding: chunked` a request with no length goes out with), with its start
    /// line and headers: memory of the connection's, given back once the transaction has
    /// started ([`start_request`], T437).
    pub head: Box<H2ReqHead>,
    /// What `%U` counts of the head.
    pub req_htx: u64,
    /// The line `%r` prints, when the frontend keeps it.
    pub request_line: Option<String>,
    /// A request `HAProxy` answers 400 without contacting a server
    /// ([`ibex_proto::H2StreamCtx::bad_request`]).
    pub bad_request: bool,
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
    let chunked = stream.request_header("content-length").is_none() && (has_data || !stream.rx_htx.is_eom());
    let first_body = stream.rx_htx.blocks().iter().position(|b| matches!(b, HtxBlock::Eoh)).map_or(stream.rx_htx.blocks().len(), |i| i + 1);
    // The head as the mux wrote it (T437); the stream keeps none past this.
    let head = stream.req_head.take()?;
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
/// connection's owner (T280): its head in `req` (and parsed, for the rules), the request's
/// log fields, and the transaction. The head's memory is given back, for the connection's
/// next streams ([`H2MuxContext::give_back_head`]).
pub fn start_request(sess: &mut TcpSession, d: H2Dispatch) -> Box<H2ReqHead> {
    let chunked = d.stream.chunk_out;
    if let Some(c) = sess.h2_child_mut() {
        c.stream = d.stream;
    }
    if sess.keep_request_line {
        sess.log.request_line.set_opt(d.request_line.as_deref());
    }
    sess.log.request = Some(crate::txnlog::loop_now());
    let head = d.head.wire();
    let wire_req_buf: Vec<u8>;
    let wire_req: &[u8] = if chunked {
        let at = find_eoh(head).map_or(head.len(), |(h, _)| h);
        wire_req_buf = chunked_head(head, at);
        &wire_req_buf
    } else {
        head
    };
    // The built-in HTTP/1 parser (what `parser::build(ParserKind::H1)` boxes), on the stack.
    let mut p_stream = ibex_proto::H1Parser::new(false);
    // A head of a few hundred bytes takes a small buffer, not a pooled 16 KB one that a held
    // stream would keep for its whole life (T312; `HAProxy` holds no buffer for one). A
    // rewrite that needs more makes room (`htx_reserve`), as for any HTX.
    let lines = head.iter().filter(|&&b| b == b'\n').count();
    let need = head.len() + 64 + ibex_proto::htx::HTX_DESC_SIZE * (lines + 3);
    if need * 2 <= crate::buf::get_bufsize_small() && sess.htx_buf.raw_slice().is_empty() {
        sess.htx_buf = Buf::unallocated(crate::buf::BufClass::Small);
    }
    let raw = sess.htx_buf.htx_slice_mut();
    let mut slice = ibex_proto::htx::HtxSlice::new(raw);
    let parsed = p_stream.parse(head, &mut slice).is_ok();
    let (tail, blocks) = (slice.tail_addr(), slice.num_blocks());
    // What a refused head wrote is zeroed on release like the rest (`tune.ibex.zero-buffers`).
    sess.htx_buf.note_htx(tail, blocks * ibex_proto::htx::HTX_DESC_SIZE);
    if parsed {
        sess.htx_tail = tail;
        sess.htx_blocks = blocks;
        sess.has_htx = true;
        sess.htx_modified = false;
    }
    let line = d.head.has_line;
    sess.req_method.set_opt(line.then(|| d.head.method()));
    sess.req_uri.set_opt(line.then(|| d.head.uri()));
    // The list the samples read once the HTX is let go, in the memory of the session's
    // (or, for a new stream, its connection's) previous list.
    let hdrs = sess.req_headers.get_or_insert_with(Vec::new);
    copy_headers(hdrs, d.head.headers());
    sess.req.clear();
    // The head waits here for a server connection (a stream held in the queue, or whose body
    // never comes, keeps it): a small buffer for a small head, which grows with the body.
    if wire_req.len() * 2 <= crate::buf::get_bufsize_small() && sess.req.raw_slice().is_empty() {
        sess.req = Buf::unallocated(crate::buf::BufClass::Small);
    }
    let w = sess.req.writable();
    let n = wire_req.len().min(w.len());
    w[..n].copy_from_slice(&wire_req[..n]);
    sess.req.commit(n);
    let framing = find_eoh(wire_req).map_or(txn::Framing::None, |(h, e)| txn::request_framing(&wire_req[..h + e]));
    let mut txn = HttpTxn::new(framing, false);
    txn.req_htx = Some(d.req_htx);
    sess.txn = Some(txn);
    sess.cli_state = ScState::Established;
    if d.bad_request {
        sess.fail_request(400);
    }
    d.head
}

/// `hdrs` as a copy of `from`, the `String`s it has reused (T437).
fn copy_headers<'a>(hdrs: &mut Vec<(String, String)>, from: impl Iterator<Item = (&'a str, &'a str)>) {
    let mut n = 0;
    for (k, v) in from {
        if let Some((hk, hv)) = hdrs.get_mut(n) {
            hk.clear();
            hk.push_str(k);
            hv.clear();
            hv.push_str(v);
        } else {
            hdrs.push((k.to_string(), v.to_string()));
        }
        n += 1;
    }
    hdrs.truncate(n);
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

/// The response of a stream, as HEADERS then DATA frames, as much as the client's
/// flow-control windows take. `srv_gone`: the server side has ended. `true` when the
/// response was cut short by the server and the stream reset for it (`SD`).
pub fn forward_response(h2: &mut H2MuxContext, stream_id: u32, txn: &mut HttpTxn, rep: &mut Buf, srv_gone: bool) -> bool {
    if txn.rsp == MsgState::Waiting || txn.rsp.is_done() {
        return false;
    }
    let data = rep.readable();
    let win = txn.rsp.window(data);
    if txn.rsp_interim {
        // An HTTP/1 interim response has no place in this conversion; it is dropped.
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
                return forward_response(h2, stream_id, txn, rep, srv_gone);
            }
        }
        return false;
    }
    if !matches!(txn.rsp, MsgState::Body(_)) {
        // A body that broke its framing, or a tunnel (101, CONNECT), which this
        // conversion does not carry: the stream is reset and the server is let go.
        h2.send_rst_stream(stream_id, ibex_proto::h2::H2Error::InternalError);
        txn.srv_reusable = false;
        txn.rsp = MsgState::Done;
        return false;
    }
    // Staged in the connection's buffer, kept from one response to the next (T437).
    let mut out = std::mem::take(&mut h2.body_scratch);
    out.clear();
    let mut state = txn.rsp;
    let used = state.take_body(data, h2.data_budget(stream_id), &mut out);
    let end = state.is_done();
    if let Some(t) = txn.rsp_htx.as_mut().filter(|_| !txn.local) {
        // The payload, and the chunked body's end (see `htx_head_size`); not a reply
        // the proxy made in place of the server's response.
        *t += out.len() as u64 + u64::from(end && matches!(txn.rsp, MsgState::Body(txn::Body::Chunked(_))));
    }
    if !out.is_empty() || end {
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
/// the response head, `CD--` during the body, `CQ` queued (`HAProxy` 3.5-dev8, T273 B).
/// What is left in either buffer is dropped, as it would be taken for the next stream's.
/// The caller ends the transaction. `false` when there is none.
pub fn abort_reset_stream(sess: &mut TcpSession) -> bool {
    let Some(txn) = sess.txn.as_mut() else {
        return false;
    };
    let response_done = txn.rsp.is_done();
    let waiting = txn.rsp == MsgState::Waiting;
    txn.srv_reusable = false;
    txn.rsp = MsgState::Done;
    if !response_done {
        // `SC_FL_NOLINGER`: closed when the transaction ends, the server connection is reset.
        if let Some(srv) = sess.srv.as_ref() {
            raw::abort_with_rst(srv.as_fd());
        }
        if sess.queue.take().is_some() {
            sess.log.queue.get_or_insert_with(crate::txnlog::loop_now);
            sess.log.term = Some(*b"CQ");
        } else if txn.local {
            // A reply of the proxy's own keeps the status and ending it was given.
        } else if waiting {
            sess.log.status = Some(400);
            sess.log.term = Some(*b"CH");
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
                        *d = Vec::new();
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

    fn dispatch(head: &[u8]) -> H2Dispatch {
        H2Dispatch {
            stream: H2ActiveStream { id: 1, body: H2ReqBody::default(), chunk_out: false },
            head: Box::new(H2ReqHead::from_wire(std::str::from_utf8(head).expect("text"))),
            req_htx: 7,
            request_line: None,
            bad_request: false,
        }
    }

    #[test]
    fn a_head_the_h1_parser_refuses_still_starts_the_transaction_without_parsed_htx() {
        let (mut s, _owner, _peer) = child();
        let head = b"\x01\x02 not a request line\r\n\r\n";
        start_request(&mut s, dispatch(head));
        assert!(!s.has_htx, "the parser refused the head: no HTX for the rules");
        assert_eq!(s.req.readable(), head, "the head is in `req` as it came");
        assert_eq!(s.txn.as_ref().and_then(|t| t.req_htx), Some(7));
        assert_eq!(s.h2_active().map(|a| a.id), Some(1));
        assert_eq!(s.cli_state, ScState::Established);
        // The same with a head it takes: parsed for the rules.
        let (mut s, _owner, _peer) = child();
        start_request(&mut s, dispatch(b"GET / HTTP/1.1\r\nhost: x\r\n\r\n"));
        assert!(s.has_htx, "a valid head is parsed");
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
        assert!(!forward_response(&mut h2, 1, &mut txn, &mut rep, false));
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
        assert!(!forward_response(&mut h2, 1, &mut txn, &mut rep, false));
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
