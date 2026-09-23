// SPDX-License-Identifier: GPL-2.0-or-later

//! RFC 7230 §3.3.3: `Transfer-Encoding` overrides `Content-Length`, and the
//! `Content-Length` must be removed before forwarding.
//!
//! Found by differential fuzzing against `HAProxy` 3.5 and confirmed by hand. Before this
//! fix Ibex forwarded **both** framing headers plus the trailing smuggled byte, while
//! `HAProxy` stripped `Content-Length`, dropped the byte, and refused connection reuse.
//! Forwarding both headers is the canonical CL.TE desync: we frame by chunked encoding,
//! a backend honouring `Content-Length` frames differently, and the disagreement is the
//! attack.

use ibex_proto::h1::H1Parser;
use ibex_proto::htx::{HtxBuffer, HtxSlice};

/// The exact vector verified against `HAProxy` 3.5.
const CL_TE: &[u8] = b"POST /smuggle HTTP/1.1\r\nHost: example.com\r\n\
Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX";

const TE_CL: &[u8] = b"POST /smuggle HTTP/1.1\r\nHost: example.com\r\n\
Transfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX";

fn parse(input: &[u8]) -> (H1Parser, HtxBuffer) {
    let mut p = H1Parser::new(false);
    let mut h = HtxBuffer::new();
    let _ = h.with_slice_mut(|s| p.parse(input, s));
    (p, h)
}

#[test]
fn content_length_is_removed_when_transfer_encoding_is_present() {
    let (p, htx) = parse(CL_TE);
    assert!(p.is_chunked, "Transfer-Encoding must win");
    assert_eq!(
        p.content_length, None,
        "Content-Length must be discarded, not merely ignored"
    );
    assert_eq!(
        htx.get_header("content-length"),
        None,
        "Content-Length must be removed from the message we forward. Leaving it in \
         lets the backend frame the request differently than we did, which is the \
         smuggling primitive itself"
    );
    assert!(
        htx.get_header("transfer-encoding").is_some(),
        "Transfer-Encoding must survive"
    );
}

#[test]
fn header_order_does_not_change_the_outcome() {
    // An implementation that picks whichever header it saw last is exploitable by
    // simply reordering them.
    let (p, htx) = parse(TE_CL);
    assert!(p.is_chunked);
    assert_eq!(p.content_length, None);
    assert_eq!(htx.get_header("content-length"), None);
}

#[test]
fn a_framing_conflict_forbids_connection_reuse() {
    let (p, _) = parse(CL_TE);
    assert!(p.framing_conflict, "the conflict must be recorded");
    assert!(
        p.connection_close,
        "trailing bytes after a framing conflict are of ambiguous ownership, so the \
         next request on this connection could be prefixed by them. `HAProxy` sets \
         'connection: close' here for exactly that reason"
    );
}

#[test]
fn content_length_alone_is_still_honoured() {
    // The fix must not break ordinary requests.
    let (p, htx) = parse(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello");
    assert!(!p.is_chunked);
    assert_eq!(p.content_length, Some(5));
    assert_eq!(htx.get_header("content-length"), Some("5"));
    assert!(!p.framing_conflict);
}

#[test]
fn chunked_alone_is_still_honoured() {
    let (p, htx) = parse(
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    );
    assert!(p.is_chunked);
    assert_eq!(p.content_length, None);
    assert!(htx.get_header("transfer-encoding").is_some());
    assert!(!p.framing_conflict, "no conflict when only one is present");
}

// ---- invalid and conflicting Content-Length ----------------------------------------

// Found by differential fuzzing and confirmed by hand: `HAProxy` 3.5 answers 400 Bad
// Request to `Content-Length: -5`, while Ibex answered 200 and left the body bytes
// unconsumed on the connection -- where they become the next request.

fn rejects(input: &[u8]) -> bool {
    let mut p = H1Parser::new(false);
    let mut buf = [0u8; 4096];
    let mut h = HtxSlice::new(&mut buf);
    p.parse(input, &mut h).is_err()
}

#[test]
fn negative_content_length_is_rejected() {
    assert!(
        rejects(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: -5\r\n\r\nhello"),
        "a negative Content-Length is unframeable; ignoring it leaves the body to be \
         read as the next request"
    );
}

#[test]
fn signed_positive_content_length_is_rejected() {
    // parse::<usize>() accepts a leading '+', so the obvious implementation lets this
    // through while `HAProxy` does not.
    assert!(rejects(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: +5\r\n\r\nhello"));
}

#[test]
fn non_numeric_content_length_is_rejected() {
    assert!(rejects(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: abc\r\n\r\nhello"));
    assert!(rejects(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: \r\n\r\nhello"));
    assert!(rejects(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5x\r\n\r\nhello"));
}

#[test]
fn conflicting_duplicate_content_lengths_are_rejected() {
    // Each hop may pick a different one: the other classic desync.
    assert!(rejects(
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello"
    ));
}

#[test]
fn agreeing_duplicate_content_lengths_are_accepted() {
    // RFC 9112 permits identical duplicates.
    assert!(!rejects(
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"
    ));
}

#[test]
fn ordinary_content_length_still_works() {
    assert!(!rejects(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello"));
    assert!(!rejects(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n"));
    assert!(!rejects(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n"));
}

#[test]
fn identical_comma_separated_content_lengths_are_accepted() {
    // RFC 9112 6.3: a list of identical values may be treated as that single value.
    // HAProxy 3.5 accepts `Content-Length: 5, 5` and forwards a 5-byte body.
    assert!(!rejects(
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5, 5\r\n\r\nhello"
    ));
}

#[test]
fn differing_comma_separated_content_lengths_are_rejected() {
    // Same desync as two conflicting headers, just spelled differently.
    assert!(rejects(
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5, 6\r\n\r\nhello"
    ));
}
