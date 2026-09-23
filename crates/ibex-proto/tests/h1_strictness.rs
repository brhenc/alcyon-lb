// SPDX-License-Identifier: GPL-2.0-or-later

//! Inputs `HAProxy` 3.5 rejects that Ibex must also reject.
//!
//! Each case was verified by sending the exact bytes to a live `HAProxy` 3.5 and
//! recording its answer. Accepting what the reference refuses is the dangerous
//! direction for a proxy: it means Ibex will forward requests a `HAProxy`-fronted
//! backend would never have seen, and any framing it guesses at is a desync primitive.

use ibex_proto::h1::H1Parser;
use ibex_proto::htx::HtxSlice;

fn rejects(input: &[u8]) -> bool {
    let mut p = H1Parser::new(false);
    let mut buf = [0u8; 4096];
    let mut h = HtxSlice::new(&mut buf);
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

#[test]
fn obs_fold_preserves_whitespace_run_matching_haproxy() {
    // HAProxy 3.5 replaces preceding CRLF with 2 spaces and preserves the
    // continuation line's whitespace run ("foo\r\n bar" -> "foo   bar").
    let mut p = H1Parser::new(false);
    let mut buf = [0u8; 4096];
    let mut h = HtxSlice::new(&mut buf);
    let input = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Fold: foo\r\n bar\r\n\r\n";
    let res = p.parse(input, &mut h);
    assert!(res.is_ok(), "parse failed: {res:?}");

    let hdrs: Vec<(&str, &str)> = h.as_ref().headers().collect();
    let fold_hdr = hdrs.iter().find(|(n, _)| n.eq_ignore_ascii_case("x-fold"));
    assert!(fold_hdr.is_some(), "X-Fold header not found in {hdrs:?}");
    let (_, val) = fold_hdr.unwrap();
    assert_eq!(
        *val, "foo   bar",
        "obs-fold must preserve whitespace run matching HAProxy 3.5 ('foo   bar'), got: {val:?}"
    );
}

#[test]
fn obs_fold_five_shapes_oracle_parity() {
    let cases: &[(&[u8], &str, &str)] = &[
        (b"GET / HTTP/1.1\r\nHost: h\r\nX-F: foo\r\n bar   \r\n\r\n", "foo   bar", "trailing spaces on continuation line"),
        (b"GET / HTTP/1.1\r\nHost: h\r\nX-F: foo\r\n bar\t\r\n\r\n", "foo   bar", "trailing tab on continuation line"),
        (b"GET / HTTP/1.1\r\nHost: h\r\nX-F: foo  \r\n bar\r\n\r\n", "foo     bar", "trailing spaces on line 1 are interior to fold"),
        (b"GET / HTTP/1.1\r\nHost: h\r\nX-F:\r\n bar\r\n\r\n", "bar", "empty value on line 1 before fold"),
        (b"GET / HTTP/1.1\r\nHost: h\r\nX-F: foo\r\n   \r\n\r\n", "foo", "continuation line containing only whitespace"),
    ];

    for (input, expected, desc) in cases {
        let mut p = H1Parser::new(false);
        let mut buf = [0u8; 4096];
        let mut h = HtxSlice::new(&mut buf);
        let res = p.parse(input, &mut h);
        assert!(res.is_ok(), "parse failed for {desc}: {res:?}");
        let val = h.get_header("x-f").unwrap_or_else(|| panic!("X-F header missing for {desc}"));
        assert_eq!(
            val, *expected,
            "obs-fold shape '{desc}' mismatch with HAProxy 3.5 oracle"
        );
    }
}



#[test]
fn obs_fold_acl_sub_and_reg_matching() {
    // Check that Ibex ACL matchers (-m sub and -m reg) evaluate correctly against the
    // preserved whitespace run ("foo   bar" with 3 spaces).
    use ibex_sample::{Matcher, Sample};

    let mut p = H1Parser::new(false);
    let mut buf = [0u8; 4096];
    let mut h = HtxSlice::new(&mut buf);
    let input = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Fold: foo\r\n bar\r\n\r\n";
    let _ = p.parse(input, &mut h).expect("parse failed");

    let val = h.get_header("x-fold").expect("header present");
    assert_eq!(val, "foo   bar");
    let sample = Sample::Str(val.to_string());

    // -m sub matching via ibex-sample Matcher:
    let matcher_sub_exact = Matcher::compile("sub", "foo   bar").expect("compile sub matcher");
    assert!(matcher_sub_exact.matches(&sample), "-m sub 'foo   bar' must match");

    let matcher_sub_spaces = Matcher::compile("sub", "   ").expect("compile sub matcher");
    assert!(matcher_sub_spaces.matches(&sample), "-m sub '   ' (3 spaces) must match");

    let matcher_sub_collapsed = Matcher::compile("sub", "foo bar").expect("compile sub matcher");
    assert!(!matcher_sub_collapsed.matches(&sample), "-m sub 'foo bar' must NOT match");

    // -m reg matching via ibex-sample Matcher:
    let matcher_reg_three = Matcher::compile("reg", r"foo\x20{3}bar").expect("compile reg matcher");
    assert!(matcher_reg_three.matches(&sample), "-m reg 'foo\\x20{{3}}bar' must match");

    let matcher_reg_one = Matcher::compile("reg", r"foo\x20{1}bar").expect("compile reg matcher");
    assert!(!matcher_reg_one.matches(&sample), "-m reg 'foo\\x20{{1}}bar' must NOT match");

    let matcher_reg_any = Matcher::compile("reg", r"^foo\s+bar$").expect("compile reg matcher");
    assert!(matcher_reg_any.matches(&sample), "-m reg '^foo\\s+bar$' must match");
}



// ---- header field validation --------------------------------------------------------

#[test]
fn whitespace_before_colon_is_rejected() {
    // RFC 9112 5.1: a server MUST reject this with 400, and `HAProxy` 3.5 does. The
    // concrete hazard is `Content-Length : 5`, which a strict hop ignores and a
    // trimming hop honours -- so the two disagree on body length.
    assert!(rejects(b"GET /x HTTP/1.1\r\nHost: h\r\nX-Header : value\r\n\r\n"));
    assert!(rejects(b"GET /x HTTP/1.1\r\nHost: h\r\nX-Header\t: value\r\n\r\n"));
}

#[test]
fn nul_in_header_name_or_value_is_rejected() {
    // A NUL truncates the value for any downstream consumer that treats it as a
    // terminator, which is a per-hop difference.
    assert!(rejects(b"GET /x HTTP/1.1\r\nHost: h\r\nX-Foo\x00Bar: value\r\n\r\n"));
    assert!(rejects(b"GET /x HTTP/1.1\r\nHost: h\r\nX-Header: val\x00ue\r\n\r\n"));
}

#[test]
fn empty_header_name_is_rejected() {
    assert!(rejects(b"GET /x HTTP/1.1\r\nHost: h\r\n: value\r\n\r\n"));
}

#[test]
fn non_token_characters_in_header_name_are_rejected() {
    assert!(rejects(b"GET /x HTTP/1.1\r\nHost: h\r\nX Header: value\r\n\r\n"));
    assert!(rejects(b"GET /x HTTP/1.1\r\nHost: h\r\nX(Header): value\r\n\r\n"));
}

#[test]
fn ordinary_header_names_still_parse() {
    // The tchar set includes these, and rejecting them would break real traffic.
    assert!(accepts(
        b"GET /x HTTP/1.1\r\nHost: h\r\nX-Custom_Header.v2: value\r\nA1!#$%&'*+-.^_`|~: v\r\n\r\n"
    ));
}

#[test]
fn whitespace_around_chunk_size_is_rejected() {
    // RFC 9112 7.1 allows none, and ` 5 ` reads as 5 to a lenient hop.
    assert!(rejects(
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n 5 \r\nhello\r\n0\r\n\r\n"
    ));
}

// ---- Content-Length validation ------------------------------------------------------

#[test]
fn conflicting_duplicate_content_length_is_rejected() {
    assert!(rejects(
        b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello"
    ));
}

#[test]
fn conflicting_comma_content_length_is_rejected() {
    assert!(rejects(
        b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5, 6\r\n\r\nhello"
    ));
}
