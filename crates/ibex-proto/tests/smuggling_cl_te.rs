// SPDX-License-Identifier: GPL-2.0-or-later

//! RFC 7230 §3.3.3: `Transfer-Encoding` overrides `Content-Length`, and the
//! `Content-Length` must be removed before forwarding.
//!
//! Found by differential fuzzing against HAProxy 3.5 and confirmed by hand. Before this
//! fix Ibex forwarded **both** framing headers plus the trailing smuggled byte, while
//! HAProxy stripped `Content-Length`, dropped the byte, and refused connection reuse.
//! Forwarding both headers is the canonical CL.TE desync: we frame by chunked encoding,
//! a backend honouring `Content-Length` frames differently, and the disagreement is the
//! attack.

use ibex_proto::h1::H1Parser;
use ibex_proto::htx::Htx;

/// The exact vector verified against HAProxy 3.5.
const CL_TE: &[u8] = b"POST /smuggle HTTP/1.1\r\nHost: example.com\r\n\
Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX";

const TE_CL: &[u8] = b"POST /smuggle HTTP/1.1\r\nHost: example.com\r\n\
Transfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX";

fn parse(input: &[u8]) -> (H1Parser, Htx) {
    let mut p = H1Parser::new(false);
    let mut h = Htx::new();
    let _ = p.parse(input, &mut h);
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
         next request on this connection could be prefixed by them. HAProxy sets \
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
