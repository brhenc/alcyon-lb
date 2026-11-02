// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! CP2a-b: the end of a request head written by `write_request_htx` does not read the head's
//! blocks again when the fields written prove what the HTTP/1 parser's end of head looks for
//! (one `Host` at a known block, at most one canonical `Content-Length`, no `Upgrade`).
//! `ibex_proto::h1::head_walks` counts the passes (debug builds). The heads that need the
//! walk (several lengths, a padded one, an upgrade) still take it, and come out as before
//! (`htx_differential` compares every one of them with the HTTP/1 text path).

use ibex_proto::h2::write_request_htx;
use ibex_proto::hpack::{DecodedFields, HpackDecoder, HpackEncoder};
use ibex_proto::htx::HtxSlice;

fn decoded(fields: &[(&[u8], &[u8])]) -> DecodedFields {
    let mut enc = HpackEncoder::new();
    let mut block = Vec::new();
    for (n, v) in fields {
        enc.encode_field_bytes(n, v, &mut block);
    }
    let mut d = DecodedFields::default();
    HpackDecoder::new().decode_into(&block, &mut d).expect("decodes");
    d
}

/// Passes over the head's blocks made writing the request, and the length it came out with.
fn walks(more: &[(&[u8], &[u8])]) -> (u64, Option<usize>) {
    let mut f: Vec<(&[u8], &[u8])> = vec![(b":method", b"POST"), (b":scheme", b"https"), (b":path", b"/p"), (b":authority", b"a.test")];
    f.extend_from_slice(more);
    let mut mem = vec![0u8; 16384];
    let mut s = HtxSlice::new(&mut mem);
    let w0 = ibex_proto::h1::head_walks();
    let facts = write_request_htx(&decoded(&f), &mut s, false).expect("written");
    (ibex_proto::h1::head_walks() - w0, facts.content_length)
}

#[test]
fn a_head_with_one_host_and_one_length_is_not_walked() {
    if !cfg!(debug_assertions) {
        return;
    }
    assert_eq!(walks(&[]), (0, None), "the made host");
    assert_eq!(walks(&[(b"host", b"a.test")]), (0, None), "a host field");
    assert_eq!(walks(&[(b"content-length", b"5"), (b"x-a", b"1")]), (0, Some(5)), "one length");
    assert_eq!(walks(&[(b"content-length", b"0")]), (0, Some(0)), "length 0");
}

#[test]
fn a_head_with_an_odd_length_or_an_upgrade_is_walked() {
    if !cfg!(debug_assertions) {
        return;
    }
    let cl = |v: &'static [u8]| [(&b"content-length"[..], v)];
    for (what, fields) in [("two lengths", vec![(&b"content-length"[..], &b"5"[..]), (b"content-length", b"5")]), ("a list", cl(b"5, 5").to_vec()), ("padded", cl(b"005").to_vec())] {
        let (n, len) = walks(&fields);
        assert!(n >= 1, "{what}: {n} walks");
        assert_eq!(len, Some(5), "{what}");
    }
    let ext = [(&b":protocol"[..], &b"foo"[..])];
    let mut f: Vec<(&[u8], &[u8])> = vec![(b":method", b"CONNECT"), (b":scheme", b"https"), (b":path", b"/p"), (b":authority", b"a.test")];
    f.extend_from_slice(&ext);
    let mut mem = vec![0u8; 16384];
    let mut s = HtxSlice::new(&mut mem);
    let w0 = ibex_proto::h1::head_walks();
    write_request_htx(&decoded(&f), &mut s, false).expect("written");
    // The `Upgrade` lines are read as before (one pass); the head is not walked besides.
    assert_eq!(ibex_proto::h1::head_walks() - w0, 1);
}

/// A `#` in a path (let through by `accept-unsafe-violations-in-http-request`) is still a
/// fragment in the target the end of the head checks, as it is for the text path.
#[test]
fn a_fragment_let_through_by_relaxed_is_refused_by_the_end_of_the_head() {
    let f: Vec<(&[u8], &[u8])> = vec![(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/a#b"), (b":authority", b"a.test")];
    let mut mem = vec![0u8; 16384];
    let strict = write_request_htx(&decoded(&f), &mut HtxSlice::new(&mut mem), false);
    assert_eq!(strict, Err(ibex_proto::h2::HeadError::Refused("malformed field")));
    let relaxed = write_request_htx(&decoded(&f), &mut HtxSlice::new(&mut mem), true);
    assert_eq!(relaxed, Err(ibex_proto::h2::HeadError::Invalid));
}

/// CP2b-1: the request line is read back with the lengths the writer reports, without
/// splitting it, and agrees with the split; lengths that do not fit the line are refused.
#[test]
fn the_request_line_is_read_with_the_writers_lengths() {
    let f: Vec<(&[u8], &[u8])> = vec![(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/p?q=1"), (b":authority", b"a.test")];
    let mut mem = vec![0u8; 16384];
    let mut s = HtxSlice::new(&mut mem);
    let facts = write_request_htx(&decoded(&f), &mut s, false).expect("written");
    let (m, u) = (facts.method_len, facts.uri_len);
    let view = s.as_ref();
    let sized = view.req_line_sized(m, u).expect("sized");
    let split = view.req_line().expect("split");
    assert_eq!((sized.method, sized.uri, sized.version), (split.method, split.uri, split.version));
    assert_eq!((sized.method, sized.uri, sized.version), ("GET", "/p?q=1", "HTTP/1.1"));
    assert!(view.req_line_sized(m + 1, u).is_none(), "a method length off by one");
    assert!(view.req_line_sized(m, u + 1).is_none(), "a URI length off by one");
    assert!(view.req_line_sized(m, u + 20).is_none(), "a URI longer than the line");
    let mut empty = vec![0u8; 64];
    let e = HtxSlice::new(&mut empty);
    assert!(e.as_ref().req_line_sized(3, 1).is_none(), "no blocks");
    let mut hdr = vec![0u8; 256];
    let mut h = HtxSlice::new(&mut hdr);
    h.push_header("a", "b").unwrap();
    assert!(h.as_ref().req_line_sized(3, 1).is_none(), "first block is not a request line");
}
