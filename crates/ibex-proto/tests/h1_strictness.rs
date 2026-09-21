// SPDX-License-Identifier: GPL-2.0-or-later

//! Inputs `HAProxy` 3.5 rejects that Ibex must also reject.
//!
//! Each case was verified by sending the exact bytes to a live `HAProxy` 3.5 and
//! recording its answer. Accepting what the reference refuses is the dangerous
//! direction for a proxy: it means Ibex will forward requests a `HAProxy`-fronted
//! backend would never have seen, and any framing it guesses at is a desync primitive.

use ibex_proto::h1::H1Parser;
use ibex_proto::htx::Htx;

fn rejects(input: &[u8]) -> bool {
    let mut p = H1Parser::new(false);
    let mut h = Htx::new();
    p.parse(input, &mut h).is_err()
}

fn accepts(input: &[u8]) -> bool {
    !rejects(input)
}

// ---- Transfer-Encoding ------------------------------------------------------------

#[test]
fn transfer_encoding_chunked_must_be_last() {
    // HAProxy 3.5 -> 400 Bad request
    assert!(rejects(
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, identity\r\n\r\n5\r\nhello"
    ));
}

#[test]
fn identity_is_not_a_valid_transfer_coding() {
    // HAProxy 3.5 -> 422 Unprocessable Content. `identity` was removed as a
    // transfer-coding in HTTP/1.1.
    assert!(rejects(
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: identity, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    ));
}

#[test]
fn unknown_transfer_coding_is_rejected() {
    // HAProxy 3.5 -> 400 Bad request. An encoding we cannot apply makes the message
    // unframeable; guessing is how hops end up disagreeing.
    assert!(rejects(
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: not-chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    ));
}

#[test]
fn repeated_chunked_is_rejected() {
    assert!(rejects(
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, chunked\r\n\r\n0\r\n\r\n"
    ));
}

#[test]
fn plain_chunked_still_works() {
    assert!(accepts(
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    ));
}

#[test]
fn chunked_with_a_known_preceding_coding_is_accepted() {
    // gzip then chunked is legal: chunked is last.
    assert!(accepts(
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n"
    ));
}

// ---- chunk framing ----------------------------------------------------------------

#[test]
fn signed_chunk_size_is_rejected() {
    // HAProxy 3.5 -> 400. `from_str_radix` accepts a leading '+', so `+5` would
    // otherwise parse as 5 -- and a size a peer reads differently is a desync.
    assert!(rejects(
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n"
    ));
}

#[test]
fn non_hex_chunk_size_is_rejected() {
    assert!(rejects(
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n"
    ));
}

#[test]
fn chunk_extensions_are_still_allowed() {
    // A ';'-delimited extension after the size is legal and must not be broken by the
    // stricter size check.
    assert!(accepts(
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\n\r\n"
    ));
}

#[test]
fn uppercase_hex_chunk_size_is_accepted() {
    assert!(accepts(
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n"
    ));
}

// ---- line terminators and folding ---------------------------------------------------

#[test]
fn bare_cr_is_not_a_line_terminator() {
    // HAProxy 3.5 -> 400 Bad request.
    assert!(rejects(
        b"GET /x HTTP/1.1\rHost: h\rX-H: v\r\r"
    ));
}

#[test]
fn obs_fold_without_a_preceding_header_is_rejected() {
    // HAProxy 3.5 -> 400. A continuation line must continue something; dropping it
    // silently means a hop that *does* attach it sees a different message.
    assert!(rejects(
        b"GET /x HTTP/1.1\r\n folded: value\r\nHost: h\r\n\r\n"
    ));
}

#[test]
fn obs_fold_after_a_header_still_works() {
    assert!(accepts(
        b"GET /x HTTP/1.1\r\nHost: h\r\nX-Long: one\r\n  two\r\n\r\n"
    ));
}
