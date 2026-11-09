// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! X5: the h1 encoder (`h1_make_reqline`/`h1_make_stline`/`h1_make_headers`/`h1_make_eoh`,
//! src/mux_h1.c). Each row is an HTX head as HAProxy's HTX holds it after its parse (names in
//! the case they arrived), the state the stream is in, and the bytes HAProxy 3.5-dev8
//! (`/home/bhenc/reference/haproxy/haproxy`) put on the wire for it, measured on 2026-11-01:
//! a listener per mode (`option http-server-close`, `option httpclose`, keep-alive, `proto h2`,
//! `http-request del-header content-length`) in front of a server that recorded what it got
//! and answered the row's response. `on` is HAProxy's output byte for byte
//! (`tune.alcyon.h1-lowercase-headers on`); `off` is the same with the names the encoder did
//! not write in the case they came in (D-E, the default).
//!
//! Every request row is encoded from two HTXs that must give the same bytes: the copying one
//! (`HtxSlice::new`, blocks pushed) and X1's in-place one (`H1Parser::index_head_in_place`
//! over the received head, the values read through the `aux` gap).

use alcyon_proto::h1_encode::{h1_encode_head, ConnMode, H1Dir, H1EncodeOpts, H1Method, SlFlags};
use alcyon_proto::htx::{HtxRegion, HtxSlice};
use alcyon_proto::H1Parser;

/// One row: the head, how the stream stands, HAProxy's bytes.
struct Row {
    name: &'static str,
    /// The head as HAProxy's HTX holds it, written as HTTP/1.1 text.
    head: &'static str,
    dir: H1Dir,
    want: ConnMode,
    http_close: bool,
    req_ver_11: bool,
    req_meth: H1Method,
    eom: bool,
    on: &'static str,
    off: &'static str,
    /// What the encoder says of the stream afterwards: its mode, whether the body is chunked.
    after: (ConnMode, bool),
}

const fn req(name: &'static str, head: &'static str, http_close: bool, eom: bool, on: &'static str, off: &'static str, after: (ConnMode, bool)) -> Row {
    Row { name, head, dir: H1Dir::Request, want: ConnMode::KeepAlive, http_close, req_ver_11: true, req_meth: H1Method::Other, eom, on, off, after }
}

#[allow(clippy::too_many_arguments)]
const fn rsp(
    name: &'static str,
    head: &'static str,
    want: ConnMode,
    http_close: bool,
    req_ver_11: bool,
    req_meth: H1Method,
    on: &'static str,
    off: &'static str,
    after: (ConnMode, bool),
) -> Row {
    Row { name, head, dir: H1Dir::Response, want, http_close, req_ver_11, req_meth, eom: false, on, off, after }
}

const KAL: ConnMode = ConnMode::KeepAlive;
const CLO: ConnMode = ConnMode::Close;
const TUN: ConnMode = ConnMode::Tunnel;
const OTHER: H1Method = H1Method::Other;

const OK_HEAD: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Srv-Case: A\r\n\r\n";

const ROWS: &[Row] = &[
    // --- the request, to the server ---
    req(
        "keep-alive",
        "GET / HTTP/1.1\r\nHost: a\r\nX-Row: kal\r\nX-Mixed-Case: v\r\n\r\n",
        false,
        true,
        "GET / HTTP/1.1\r\nhost: a\r\nx-row: kal\r\nx-mixed-case: v\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nX-Row: kal\r\nX-Mixed-Case: v\r\n\r\n",
        (KAL, false),
    ),
    req(
        "http-server-close (and httpclose: the same bytes to the server)",
        "GET / HTTP/1.1\r\nHost: a\r\nX-Row: scl\r\nX-Mixed-Case: v\r\n\r\n",
        true,
        true,
        "GET / HTTP/1.1\r\nhost: a\r\nx-row: scl\r\nx-mixed-case: v\r\nconnection: close\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nX-Row: scl\r\nX-Mixed-Case: v\r\nconnection: close\r\n\r\n",
        (CLO, false),
    ),
    req(
        "an HTTP/1.0 client: the server is asked to keep the connection",
        "GET / HTTP/1.0\r\nHost: a\r\nX-Row: v10\r\nX-Mixed-Case: v\r\n\r\n",
        false,
        true,
        "GET / HTTP/1.0\r\nhost: a\r\nx-row: v10\r\nx-mixed-case: v\r\nconnection: keep-alive\r\n\r\n",
        "GET / HTTP/1.0\r\nHost: a\r\nX-Row: v10\r\nX-Mixed-Case: v\r\nconnection: keep-alive\r\n\r\n",
        (KAL, false),
    ),
    req(
        "an HTTP/1.0 client's keep-alive token is the encoder's to write",
        "GET / HTTP/1.0\r\nHost: a\r\nX-Row: v10ka\r\nX-Mixed-Case: v\r\nConnection: Keep-Alive\r\n\r\n",
        false,
        true,
        "GET / HTTP/1.0\r\nhost: a\r\nx-row: v10ka\r\nx-mixed-case: v\r\nconnection: keep-alive\r\n\r\n",
        "GET / HTTP/1.0\r\nHost: a\r\nX-Row: v10ka\r\nX-Mixed-Case: v\r\nconnection: keep-alive\r\n\r\n",
        (KAL, false),
    ),
    req(
        "other connection tokens stay",
        "GET / HTTP/1.1\r\nHost: a\r\nX-Row: closefoo\r\nX-Mixed-Case: v\r\nConnection: Foo\r\n\r\n",
        false,
        true,
        "GET / HTTP/1.1\r\nhost: a\r\nx-row: closefoo\r\nx-mixed-case: v\r\nconnection: Foo\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nX-Row: closefoo\r\nX-Mixed-Case: v\r\nConnection: Foo\r\n\r\n",
        (KAL, false),
    ),
    req(
        "content-length and transfer-encoding: chunked, the length gone at the parse",
        "POST / HTTP/1.1\r\nHost: a\r\nX-Row: clte\r\nX-Mixed-Case: v\r\nTransfer-Encoding: chunked\r\n\r\n",
        false,
        false,
        "POST / HTTP/1.1\r\nhost: a\r\nx-row: clte\r\nx-mixed-case: v\r\ntransfer-encoding: chunked\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nX-Row: clte\r\nX-Mixed-Case: v\r\nTransfer-Encoding: chunked\r\n\r\n",
        (KAL, true),
    ),
    req(
        "content-length",
        "POST / HTTP/1.1\r\nHost: a\r\nX-Row: post\r\nX-Mixed-Case: v\r\nContent-Length: 2\r\n\r\n",
        false,
        false,
        "POST / HTTP/1.1\r\nhost: a\r\nx-row: post\r\nx-mixed-case: v\r\ncontent-length: 2\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nX-Row: post\r\nX-Mixed-Case: v\r\nContent-Length: 2\r\n\r\n",
        (KAL, false),
    ),
    req(
        "te reduced to trailers",
        "GET / HTTP/1.1\r\nHost: a\r\nX-Row: te\r\nX-Mixed-Case: v\r\nTE: trailers, gzip\r\n\r\n",
        false,
        true,
        "GET / HTTP/1.1\r\nhost: a\r\nx-row: te\r\nx-mixed-case: v\r\nte: trailers\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nX-Row: te\r\nX-Mixed-Case: v\r\nTE: trailers\r\n\r\n",
        (KAL, false),
    ),
    req(
        "te without trailers goes",
        "GET / HTTP/1.1\r\nHost: a\r\nX-Row: tegz\r\nX-Mixed-Case: v\r\nTE: gzip\r\n\r\n",
        false,
        true,
        "GET / HTTP/1.1\r\nhost: a\r\nx-row: tegz\r\nx-mixed-case: v\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nX-Row: tegz\r\nX-Mixed-Case: v\r\n\r\n",
        (KAL, false),
    ),
    req(
        "websocket handshake, values as they came",
        "GET / HTTP/1.1\r\nHost: a\r\nX-Row: ws\r\nX-Mixed-Case: v\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        false,
        true,
        "GET / HTTP/1.1\r\nhost: a\r\nx-row: ws\r\nx-mixed-case: v\r\nconnection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nX-Row: ws\r\nX-Mixed-Case: v\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        (KAL, false),
    ),
    req(
        "HEAD",
        "HEAD / HTTP/1.1\r\nHost: a\r\nX-Row: head\r\nX-Mixed-Case: v\r\n\r\n",
        false,
        true,
        "HEAD / HTTP/1.1\r\nhost: a\r\nx-row: head\r\nx-mixed-case: v\r\n\r\n",
        "HEAD / HTTP/1.1\r\nHost: a\r\nX-Row: head\r\nX-Mixed-Case: v\r\n\r\n",
        (KAL, false),
    ),
    // --- the response, to the client ---
    rsp("keep-alive", OK_HEAD, KAL, false, true, OTHER, "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-srv-case: A\r\n\r\n", OK_HEAD, (KAL, false)),
    rsp(
        "httpclose",
        OK_HEAD,
        KAL,
        true,
        true,
        OTHER,
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-srv-case: A\r\nconnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Srv-Case: A\r\nconnection: close\r\n\r\n",
        (CLO, false),
    ),
    rsp(
        "an HTTP/1.0 client that did not ask to keep the connection (and a client's close, and CL+TE)",
        OK_HEAD,
        CLO,
        false,
        false,
        OTHER,
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-srv-case: A\r\nconnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Srv-Case: A\r\nconnection: close\r\n\r\n",
        (CLO, false),
    ),
    rsp(
        "an HTTP/1.0 client that asked to keep it",
        OK_HEAD,
        KAL,
        false,
        false,
        OTHER,
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-srv-case: A\r\nconnection: keep-alive\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Srv-Case: A\r\nconnection: keep-alive\r\n\r\n",
        (KAL, false),
    ),
    rsp(
        "101: tunnel, connection left alone",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        KAL,
        false,
        true,
        OTHER,
        "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        (TUN, false),
    ),
    rsp(
        "204 drops transfer-encoding",
        "HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\nX-A: b\r\n\r\n",
        KAL,
        false,
        true,
        OTHER,
        "HTTP/1.1 204 No Content\r\nx-a: b\r\n\r\n",
        "HTTP/1.1 204 No Content\r\nX-A: b\r\n\r\n",
        (KAL, false),
    ),
    rsp(
        "304 keeps its content-length",
        "HTTP/1.1 304 Not Modified\r\nContent-Length: 100\r\nETag: x\r\n\r\n",
        KAL,
        false,
        true,
        OTHER,
        "HTTP/1.1 304 Not Modified\r\ncontent-length: 100\r\netag: x\r\n\r\n",
        "HTTP/1.1 304 Not Modified\r\nContent-Length: 100\r\nETag: x\r\n\r\n",
        (KAL, false),
    ),
    rsp(
        "HEAD keeps the content-length",
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n",
        KAL,
        false,
        true,
        H1Method::Head,
        "HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n",
        (KAL, false),
    ),
    rsp(
        "no length: the client connection closes",
        "HTTP/1.1 200 OK\r\nX-A: b\r\n\r\n",
        KAL,
        false,
        true,
        OTHER,
        "HTTP/1.1 200 OK\r\nx-a: b\r\nconnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX-A: b\r\nconnection: close\r\n\r\n",
        (CLO, false),
    ),
    rsp(
        "chunked (the server's CL+TE, the length gone at the parse)",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        KAL,
        false,
        true,
        OTHER,
        "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        (KAL, true),
    ),
    rsp(
        "chunked to an HTTP/1.0 client that keeps the connection",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        KAL,
        false,
        false,
        OTHER,
        "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: keep-alive\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nconnection: keep-alive\r\n\r\n",
        (KAL, true),
    ),
    rsp(
        "an HTTP/1.0 server",
        "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n",
        KAL,
        false,
        true,
        OTHER,
        "HTTP/1.0 200 OK\r\ncontent-length: 2\r\nconnection: keep-alive\r\n\r\n",
        "HTTP/1.0 200 OK\r\nContent-Length: 2\r\nconnection: keep-alive\r\n\r\n",
        (KAL, false),
    ),
    rsp(
        "an empty reason is the status's",
        "HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n",
        KAL,
        false,
        true,
        OTHER,
        "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        (KAL, false),
    ),
];

/// The start line and fields of `head`, as text.
fn split(head: &str) -> (&str, Vec<(&str, &str)>) {
    let mut lines = head.strip_suffix("\r\n\r\n").expect("a head").split("\r\n");
    let line = lines.next().unwrap();
    let fields = lines.map(|l| l.split_once(": ").expect("a field")).collect();
    (line, fields)
}

/// The start-line flags HAProxy's parse gives the head (`h1m_htx_sl_flags`).
fn flags_of(row: &Row) -> SlFlags {
    let (line, fields) = split(row.head);
    let has = |n: &str| fields.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
    let clen = fields.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).map(|(_, v)| v.parse::<u64>().unwrap());
    let mut f = SlFlags::NONE;
    let status = if matches!(row.dir, H1Dir::Response) { &line[9..12] } else { "" };
    let bodyless_status = matches!(row.dir, H1Dir::Response) && (row.req_meth == H1Method::Head || status.starts_with('1') || status == "204" || status == "304");
    if status.starts_with('1') || status == "204" {
        // `h1_parse_msg_hdrs`: neither header frames a 1xx or a 204.
        f |= SlFlags::XFER_LEN | SlFlags::BODYLESS;
    } else if has("transfer-encoding") {
        f |= SlFlags::XFER_ENC | SlFlags::XFER_LEN | SlFlags::CHNK;
    } else if let Some(n) = clen {
        f |= SlFlags::XFER_LEN | SlFlags::CLEN;
        if n == 0 {
            f |= SlFlags::BODYLESS;
        }
    } else if matches!(row.dir, H1Dir::Request) || bodyless_status {
        f |= SlFlags::XFER_LEN | SlFlags::BODYLESS;
    }
    if matches!(row.dir, H1Dir::Request) && line.starts_with("HEAD ") {
        f |= SlFlags::BODYLESS_RESP;
    }
    f
}

fn opts(row: &Row, lowercase: bool) -> H1EncodeOpts<'static> {
    H1EncodeOpts {
        dir: row.dir,
        want: row.want,
        http_close: row.http_close,
        pretend_keepalive: false,
        stopping: false,
        sl: flags_of(row),
        eom: row.eom,
        req_ver_11: row.req_ver_11,
        req_meth: row.req_meth,
        lowercase,
        case_map: None,
        ws_key: None,
    }
}

/// The copying HTX of `head`.
fn copied(buf: &mut [u8], row: &Row) -> (usize, usize) {
    let (line, fields) = split(row.head);
    let mut s = HtxSlice::new(buf);
    let w: Vec<&str> = line.splitn(3, ' ').collect();
    match row.dir {
        H1Dir::Request => s.push_req_line_ascii(w[0].as_bytes(), w[1].as_bytes(), w[2].as_bytes()).unwrap(),
        H1Dir::Response => s.push_res_line(w[0], w[1].parse().unwrap(), w.get(2).copied().unwrap_or("")).unwrap(),
    }
    for (n, v) in fields {
        s.push_header(n, v).unwrap();
    }
    s.push_eoh().unwrap();
    (s.tail_addr(), s.num_blocks())
}

fn encode(row: &Row, buf: &[u8], blocks: usize, lowercase: bool) -> (String, ConnMode, bool) {
    let htx = alcyon_proto::htx::HtxSliceRef::new(buf, blocks);
    let mut out = vec![0u8; 4096];
    let r = h1_encode_head(htx, &opts(row, lowercase), &mut out).unwrap_or_else(|e| panic!("{}: {e:?}", row.name));
    (String::from_utf8(out[..r.len].to_vec()).unwrap(), r.want, r.chunked)
}

#[test]
fn every_row_is_haproxys_bytes_from_the_copying_htx() {
    for row in ROWS {
        let mut buf = vec![0u8; 4096];
        let (_, blocks) = copied(&mut buf, row);
        for (lowercase, expect) in [(true, row.on), (false, row.off)] {
            let (got, want, chunked) = encode(row, &buf, blocks, lowercase);
            assert_eq!(got, expect, "row {:?}, lowercase {lowercase}", row.name);
            assert_eq!((want, chunked), row.after, "row {:?}: the stream afterwards", row.name);
        }
    }
}

#[test]
fn every_request_row_is_the_same_from_the_in_place_htx() {
    for row in ROWS.iter().filter(|r| matches!(r.dir, H1Dir::Request)) {
        // Leading bytes, the received head, a reserve at the end (X1's layout).
        let mut buf = vec![0xAAu8; 4096];
        let at = 16;
        buf[at..at + row.head.len()].copy_from_slice(row.head.as_bytes());
        let region = HtxRegion { head_start: at, head_end: at + row.head.len(), reserve_start: 4096 - 1024 };
        let mut s = HtxSlice::over_received(&mut buf, region).unwrap();
        let mut p = H1Parser::new(false);
        p.index_head_in_place(&mut s).unwrap_or_else(|e| panic!("{}: {e}", row.name));
        let blocks = s.num_blocks();
        // The parser writes a `te` it reduces as `te: trailers` (h1.rs), in lower case.
        let off = row.off.replace("\r\nTE: trailers", "\r\nte: trailers");
        for (lowercase, expect) in [(true, row.on), (false, off.as_str())] {
            let (got, _, _) = encode(row, &buf, blocks, lowercase);
            assert_eq!(got, expect, "row {:?} in place, lowercase {lowercase}", row.name);
        }
        // The received head is not written: the names keep the case they came in.
        assert_eq!(&buf[at..at + row.head.len()], row.head.as_bytes(), "row {:?}", row.name);
    }
}

/// `http-request del-header content-length` on a POST: the encoder writes
/// `content-length: 0` and the body is not sent (`h1_make_eoh`, both headers missing).
#[test]
fn a_request_whose_length_a_rule_removed_goes_with_content_length_0() {
    let row = req(
        "delcl",
        "POST / HTTP/1.1\r\nHost: a\r\nX-Row: delcl\r\n\r\n",
        false,
        false,
        "POST / HTTP/1.1\r\nhost: a\r\nx-row: delcl\r\ncontent-length: 0\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nX-Row: delcl\r\ncontent-length: 0\r\n\r\n",
        (KAL, false),
    );
    let mut buf = vec![0u8; 4096];
    let (_, blocks) = copied(&mut buf, &row);
    let htx = alcyon_proto::htx::HtxSliceRef::new(&buf, blocks);
    let mut o = opts(&row, true);
    o.sl = SlFlags::XFER_LEN | SlFlags::CLEN; // the client's `Content-Length: 2`, removed
    let mut out = vec![0u8; 512];
    let r = h1_encode_head(htx, &o, &mut out).unwrap();
    assert_eq!(std::str::from_utf8(&out[..r.len]).unwrap(), row.on);
    assert!(r.bodyless_req, "the body is not sent");
    assert_eq!(r.body_len, Some(0));
}

/// An HTTP/2 request without a length (curl `-T -`, `proto h2`): HAProxy writes
/// `transfer-encoding: chunked` after the other headers.
#[test]
fn an_h2_request_without_a_length_goes_chunked() {
    let row = req(
        "h2",
        "PUT /up HTTP/2\r\nhost: 127.0.0.1:19504\r\nuser-agent: curl/8.18.0\r\naccept: */*\r\nx-row: h2\r\n\r\n",
        false,
        false,
        "PUT /up HTTP/1.1\r\nhost: 127.0.0.1:19504\r\nuser-agent: curl/8.18.0\r\naccept: */*\r\nx-row: h2\r\ntransfer-encoding: chunked\r\n\r\n",
        "",
        (KAL, true),
    );
    let mut buf = vec![0u8; 4096];
    let (_, blocks) = copied(&mut buf, &row);
    let htx = alcyon_proto::htx::HtxSliceRef::new(&buf, blocks);
    let mut o = opts(&row, true);
    o.sl = SlFlags::XFER_LEN;
    let mut out = vec![0u8; 512];
    let r = h1_encode_head(htx, &o, &mut out).unwrap();
    assert_eq!(std::str::from_utf8(&out[..r.len]).unwrap(), row.on);
    assert!(r.chunked);
}

/// `h1-case-adjust` applies on top of either setting (`h1_format_htx_hdr` looks the
/// lowercase name up), and a head that does not fit is refused, not cut.
#[test]
fn the_case_map_applies_and_a_short_buffer_is_refused() {
    let row = &ROWS[0];
    let mut buf = vec![0u8; 4096];
    let (_, blocks) = copied(&mut buf, row);
    let htx = alcyon_proto::htx::HtxSliceRef::new(&buf, blocks);
    let map: std::collections::HashMap<String, String> = [("x-mixed-case".to_string(), "X-MIXED-case".to_string())].into();
    for lowercase in [true, false] {
        let mut o = opts(row, lowercase);
        o.case_map = Some(&map);
        let mut out = vec![0u8; 512];
        let r = h1_encode_head(htx, &o, &mut out).unwrap();
        let got = std::str::from_utf8(&out[..r.len]).unwrap();
        assert!(got.contains("\r\nX-MIXED-case: v\r\n"), "{got}");
        assert_eq!(got.contains("\r\nhost: a"), lowercase, "{got}");
        let mut short = vec![0u8; r.len - 1];
        assert!(h1_encode_head(htx, &o, &mut short).is_err());
    }
}

/// The h2 bridge's send (`h2_bridge::start_request`) encodes where it wrote `write_h1_wire`
/// and spliced `transfer-encoding: chunked` in before the blank line: for the heads an
/// HTTP/2 or HTTP/3 client sends (lower-case names, the line as `HTTP/1.1`) the bytes are
/// the same (X5's differential row: the wire does not change).
#[test]
fn an_h2_head_encodes_as_write_h1_wire_wrote_it() {
    let heads: &[(&str, &str, &[(&str, &str)])] = &[
        ("GET", "/", &[("host", "127.0.0.1:8443"), ("user-agent", "h2load nghttp2/1.64.0")]),
        ("GET", "/a?b=c", &[("host", "x"), ("accept", "*/*"), ("cookie", "a=1; b=2"), ("te", "trailers")]),
        ("POST", "/up", &[("host", "x"), ("content-length", "5"), ("content-type", "text/plain")]),
        ("PUT", "/up", &[("host", "x"), ("x-a", "b")]),
    ];
    for (i, (method, uri, fields)) in heads.iter().enumerate() {
        let mut buf = vec![0u8; 4096];
        let mut s = HtxSlice::new(&mut buf);
        s.push_req_line_ascii(method.as_bytes(), uri.as_bytes(), b"HTTP/1.1").unwrap();
        for (n, v) in *fields {
            s.push_header(n, v).unwrap();
        }
        s.push_eoh().unwrap();
        let htx = s.as_ref();
        let mut old = vec![0u8; 4096];
        let n = htx.write_h1_wire(&mut old).unwrap();
        let has_len = fields.iter().any(|(n, _)| *n == "content-length");
        // The last head is a body without a length: chunked.
        let chunked = i == heads.len() - 1;
        let mut old = old[..n].to_vec();
        if chunked {
            old.splice(n - 2..n - 2, b"transfer-encoding: chunked\r\n".iter().copied());
        }
        let sl = SlFlags::XFER_LEN
            | if chunked {
                SlFlags::NONE
            } else if has_len {
                SlFlags::CLEN
            } else {
                SlFlags::BODYLESS
            };
        let mut out = vec![0u8; 4096];
        let r = h1_encode_head(htx, &H1EncodeOpts::new(H1Dir::Request, sl, false), &mut out).unwrap();
        assert_eq!(String::from_utf8_lossy(&out[..r.len]), String::from_utf8_lossy(&old), "head {i}");
        assert_eq!(r.chunked, chunked);
    }
}

/// The head of `line` + `fields` encoded with the options `f` makes of the defaults.
fn enc(dir: H1Dir, line: &str, fields: &[(&str, &str)], f: impl FnOnce(&mut H1EncodeOpts<'static>)) -> Result<(String, alcyon_proto::h1_encode::H1Encoded), alcyon_proto::htx::HtxError> {
    let mut buf = vec![0u8; 4096];
    let mut s = HtxSlice::new(&mut buf);
    let w: Vec<&str> = line.splitn(3, ' ').collect();
    match dir {
        H1Dir::Request => s.push_req_line_ascii(w[0].as_bytes(), w[1].as_bytes(), w[2].as_bytes()).unwrap(),
        H1Dir::Response => s.push_res_line(w[0], w[1].parse().unwrap(), w.get(2).copied().unwrap_or("")).unwrap(),
    }
    for (n, v) in fields {
        s.push_header(n, v).unwrap();
    }
    s.push_eoh().unwrap();
    let blocks = s.num_blocks();
    let mut o = H1EncodeOpts::new(dir, SlFlags::XFER_LEN | SlFlags::BODYLESS, true);
    f(&mut o);
    let htx = alcyon_proto::htx::HtxSliceRef::new(&buf, blocks);
    let mut out = vec![0u8; 4096];
    let r = h1_encode_head(htx, &o, &mut out)?;
    Ok((String::from_utf8_lossy(&out[..r.len]).into_owned(), r))
}

const GET11: &str = "GET / HTTP/1.1";
const REQ: H1Dir = H1Dir::Request;
const RSP: H1Dir = H1Dir::Response;

/// `h1_parse_connection_header`/`h1_parse_upgrade_header` with `H1_MF_CLEAN_CONN_HDR`: a list
/// as it came while nothing is dropped, then joined by `,`; a quoted comma is not a separator.
#[test]
fn connection_and_upgrade_lists_are_cleaned_as_haproxy_cleans_them() {
    let (h, r) = enc(REQ, GET11, &[("Connection", "foo, \"a,b\\\"c\", close, bar")], |_| {}).unwrap();
    assert_eq!(h, "GET / HTTP/1.1\r\nconnection: foo, \"a,b\\\"c\",bar\r\nconnection: close\r\n\r\n");
    assert_eq!(r.want, ConnMode::Close, "the client's close asks the server to close");
    let (h, _) = enc(REQ, GET11, &[("connection", "keep-alive")], |_| {}).unwrap();
    assert_eq!(h, "GET / HTTP/1.1\r\n\r\n", "a list of the encoder's tokens only goes");
    let (h, _) = enc(REQ, GET11, &[("connection", "x , close")], |_| {}).unwrap();
    assert_eq!(h, "GET / HTTP/1.1\r\nconnection: x \r\nconnection: close\r\n\r\n", "kept as it came up to its comma");
    // A handshake without a key, and none given: none written.
    let (h, _) = enc(REQ, GET11, &[("connection", "upgrade"), ("upgrade", "websocket")], |_| {}).unwrap();
    assert_eq!(h, "GET / HTTP/1.1\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n");
    let (h, _) = enc(REQ, GET11, &[("upgrade", "h2c")], |_| {}).unwrap();
    assert_eq!(h, "GET / HTTP/1.1\r\n\r\n");
    let (h, _) = enc(REQ, GET11, &[("upgrade", "h2c, websocket, h2")], |_| {}).unwrap();
    assert_eq!(h, "GET / HTTP/1.1\r\nupgrade: websocket\r\n\r\n");
    // A handshake without a key gets the caller's.
    let (h, _) = enc(REQ, GET11, &[("connection", "upgrade"), ("upgrade", "websocket")], |o| o.ws_key = Some(b"k==")).unwrap();
    assert_eq!(h, "GET / HTTP/1.1\r\nconnection: upgrade\r\nupgrade: websocket\r\nsec-websocket-key: k==\r\n\r\n");
    let (h, _) = enc(RSP, "HTTP/1.1 101 Switching", &[("connection", "upgrade"), ("upgrade", "websocket")], |o| o.ws_key = Some(b"acc")).unwrap();
    assert_eq!(h, "HTTP/1.1 101 Switching\r\nconnection: upgrade\r\nupgrade: websocket\r\nsec-websocket-accept: acc\r\n\r\n");
}

/// `http_parse_cont_len_header`: leading zeros trimmed, a list of one number kept as one,
/// anything else a processing error; a second header with the same number skipped.
#[test]
fn content_length_is_parsed_as_haproxy_parses_it() {
    let cl = |v: &str| enc(REQ, "POST / HTTP/1.1", &[("content-length", v)], |o| o.sl = SlFlags::XFER_LEN | SlFlags::CLEN);
    let (h, r) = cl("005").unwrap();
    assert_eq!(h, "POST / HTTP/1.1\r\ncontent-length: 5\r\n\r\n");
    assert_eq!(r.body_len, Some(5));
    assert_eq!(cl(" 7 , 7").unwrap().0, "POST / HTTP/1.1\r\ncontent-length: 7\r\n\r\n");
    for bad in ["", "  ", "5x", "5, 6", "x", "99999999999999999999999"] {
        assert!(cl(bad).is_err(), "{bad:?}");
    }
    let two = |b: &str| enc(REQ, "POST / HTTP/1.1", &[("content-length", "5"), ("Content-Length", b)], |o| o.sl = SlFlags::XFER_LEN | SlFlags::CLEN);
    assert_eq!(two("5").unwrap().0, "POST / HTTP/1.1\r\ncontent-length: 5\r\n\r\n");
    assert!(two("6").is_err());
    // A request whose head is its whole message, with a length: the server side closes
    // (`C-L but no data`).
    let (_, r) = enc(REQ, "POST / HTTP/1.1", &[("content-length", "5")], |o| {
        o.sl = SlFlags::XFER_LEN | SlFlags::CLEN;
        o.eom = true;
    })
    .unwrap();
    assert_eq!(r.want, ConnMode::Close);
}

/// The `h1_make_eoh` branches: chunked to the end, a removed `transfer-encoding`, T-E on a
/// 1.0 message, both headers, CONNECT, 1xx, the stopping proxy, `http-pretend-keepalive`.
#[test]
fn the_end_of_head_rules() {
    let chnk = SlFlags::XFER_LEN | SlFlags::XFER_ENC | SlFlags::CHNK;
    let (h, r) = enc(REQ, "POST / HTTP/1.1", &[("transfer-encoding", "chunked")], |o| {
        o.sl = chnk;
        o.eom = true;
    })
    .unwrap();
    assert_eq!(h, "POST / HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n");
    assert!(r.chunked);
    // Chunked by its flags, the header not written (a 204's), a length of 0 kept: the length
    // frames it (`h1_make_eoh`, one of the two headers present).
    let (h, r) = enc(RSP, "HTTP/1.1 204 No Content", &[("content-length", "0"), ("transfer-encoding", "chunked")], |o| o.sl = chnk).unwrap();
    assert_eq!(h, "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n");
    assert!(!r.chunked);
    // `transfer-encoding` received and a length kept (flags HAProxy's parse does not make,
    // which never keeps both): `h1_make_eoh` taken literally, the length dropped from the
    // framing, the server side closed, the body chunked.
    let (h, r) = enc(REQ, "POST / HTTP/1.1", &[("content-length", "3"), ("transfer-encoding", "chunked")], |o| o.sl = SlFlags::XFER_LEN | SlFlags::XFER_ENC | SlFlags::CLEN).unwrap();
    assert_eq!(h, "POST / HTTP/1.1\r\ncontent-length: 3\r\nconnection: close\r\ntransfer-encoding: chunked\r\n\r\n");
    assert_eq!(r.want, ConnMode::Close);
    // T-E on HTTP/1.0: close, no token.
    let (h, r) = enc(REQ, "POST / HTTP/1.0", &[("transfer-encoding", "chunked")], |o| o.sl = chnk).unwrap();
    assert_eq!(h, "POST / HTTP/1.0\r\ntransfer-encoding: chunked\r\n\r\n");
    assert_eq!(r.want, ConnMode::Close);
    // A response whose framing headers a rule removed: no length known, the client closes.
    let (h, r) = enc(RSP, "HTTP/1.1 200 OK", &[], |o| o.sl = chnk).unwrap();
    assert_eq!(h, "HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n");
    assert_eq!(r.want, ConnMode::Close);
    // CONNECT: no chunking, and its 2xx is a tunnel.
    let (h, _) = enc(REQ, "CONNECT a:443 HTTP/1.1", &[("host", "a:443")], |o| o.sl = SlFlags::XFER_LEN).unwrap();
    assert_eq!(h, "CONNECT a:443 HTTP/1.1\r\nhost: a:443\r\n\r\n");
    let (h, r) = enc(RSP, "HTTP/1.1 200 OK", &[], |o| {
        o.sl = SlFlags::NONE;
        o.req_meth = H1Method::of(b"CONNECT");
    })
    .unwrap();
    assert_eq!((h.as_str(), r.want), ("HTTP/1.1 200 OK\r\n\r\n", ConnMode::Tunnel));
    // 1xx: no `connection`, no framing.
    let (h, _) = enc(RSP, "HTTP/1.1 100 Continue", &[("transfer-encoding", "chunked")], |o| o.sl = SlFlags::XFER_LEN).unwrap();
    assert_eq!(h, "HTTP/1.1 100 Continue\r\n\r\n");
    // A response to HEAD with a chunked header, its head the whole message: no last chunk.
    let (h, _) = enc(RSP, "HTTP/1.1 200 OK", &[("transfer-encoding", "chunked")], |o| {
        o.sl = chnk;
        o.req_meth = H1Method::of(b"HEAD");
        o.eom = true;
    })
    .unwrap();
    assert_eq!(h, "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n");
    // A stopping proxy closes; `http-pretend-keepalive` keeps the token of a 1.0 request.
    let (h, _) = enc(REQ, GET11, &[], |o| o.stopping = true).unwrap();
    assert_eq!(h, "GET / HTTP/1.1\r\nconnection: close\r\n\r\n");
    let (h, _) = enc(REQ, "GET / HTTP/1.0", &[], |o| {
        o.http_close = true;
        o.pretend_keepalive = true;
    })
    .unwrap();
    assert_eq!(h, "GET / HTTP/1.0\r\nconnection: keep-alive\r\n\r\n");
    let (h, _) = enc(RSP, "HTTP/1.1 200 OK", &[("content-length", "0")], |o| {
        o.sl = SlFlags::XFER_LEN | SlFlags::CLEN;
        o.stopping = true;
    })
    .unwrap();
    assert_eq!(h, "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
}

/// `te`: kept as `trailers` only when `trailers` ends the value or a `,` follows it; a
/// pseudo-header is never written; a Latin-1 value goes as its bytes; a removed block is
/// skipped; an HTX that is not a head of the direction is refused.
#[test]
fn the_other_fields_and_what_is_refused() {
    let te = |v: &str| enc(REQ, GET11, &[("te", v)], |_| {}).unwrap().0;
    assert_eq!(te("trailers,gzip"), "GET / HTTP/1.1\r\nte: trailers\r\n\r\n");
    assert_eq!(te("trailersx"), "GET / HTTP/1.1\r\n\r\n");
    let (h, _) = enc(REQ, GET11, &[(":authority", "x"), ("x-a", "b")], |_| {}).unwrap();
    assert_eq!(h, "GET / HTTP/1.1\r\nx-a: b\r\n\r\n");
    assert!(enc(REQ, GET11, &[], |o| o.dir = RSP).is_err(), "a request line is not a response's");
    assert!(enc(RSP, "HTTP/1.1 200 OK", &[], |o| o.dir = REQ).is_err(), "nor a status line a request's");

    let mut buf = vec![0u8; 4096];
    let mut s = HtxSlice::new(&mut buf);
    s.push_req_line_ascii(b"GET", b"/", b"HTTP/1.1").unwrap();
    s.push_header_latin1("x-l", b"caf\xe9").unwrap();
    s.push_header("x-gone", "1").unwrap();
    s.push_header("x-kept", "2").unwrap();
    let blocks_without_eoh = s.num_blocks();
    s.push_eoh().unwrap();
    s.push_header("x-after", "eoh").unwrap();
    s.remove_block(2);
    let blocks = s.num_blocks();
    let o = H1EncodeOpts::new(REQ, SlFlags::XFER_LEN | SlFlags::BODYLESS, false);
    let mut out = vec![0u8; 512];
    let r = h1_encode_head(alcyon_proto::htx::HtxSliceRef::new(&buf, blocks), &o, &mut out).unwrap();
    assert_eq!(&out[..r.len], b"GET / HTTP/1.1\r\nx-l: caf\xe9\r\nx-kept: 2\r\n\r\n");
    // A status line without a reason (no space after the code): the status's reason.
    let mut raw = vec![0u8; 256];
    raw[..12].copy_from_slice(b"HTTP/1.1 204");
    let descs = [
        alcyon_proto::HtxBlockDesc { blk_type: alcyon_proto::HtxBlockType::ResLine, flags: 0, name_len: 204, addr: 0, value_len: 12, aux: 0 },
        alcyon_proto::HtxBlockDesc { blk_type: alcyon_proto::HtxBlockType::Eoh, flags: 0, name_len: 0, addr: 12, value_len: 0, aux: 0 },
    ];
    for (i, d) in descs.iter().enumerate() {
        let at = raw.len() - (i + 1) * alcyon_proto::htx::HTX_DESC_SIZE;
        d.write_bytes((&mut raw[at..at + alcyon_proto::htx::HTX_DESC_SIZE]).try_into().unwrap());
    }
    let r = h1_encode_head(alcyon_proto::htx::HtxSliceRef::new(&raw, 2), &H1EncodeOpts::new(RSP, SlFlags::XFER_LEN | SlFlags::BODYLESS, true), &mut out).unwrap();
    assert_eq!(&out[..r.len], b"HTTP/1.1 204 No Content\r\n\r\n");
    // A body block before the end of the head is not a head.
    let mut buf2 = vec![0u8; 1024];
    let mut s = HtxSlice::new(&mut buf2);
    s.push_req_line_ascii(b"GET", b"/", b"HTTP/1.1").unwrap();
    s.push_data(b"x").unwrap();
    s.push_eoh().unwrap();
    let n = s.num_blocks();
    assert!(h1_encode_head(alcyon_proto::htx::HtxSliceRef::new(&buf2, n), &o, &mut out).is_err(), "data before the EOH");
    // Without its EOH (the blocks before it) the head is not whole.
    assert!(h1_encode_head(alcyon_proto::htx::HtxSliceRef::new(&buf, blocks_without_eoh), &o, &mut out).is_err(), "no EOH");
    assert!(h1_encode_head(alcyon_proto::htx::HtxSliceRef::new(&buf, 0), &o, &mut out).is_err(), "an empty HTX");
}
