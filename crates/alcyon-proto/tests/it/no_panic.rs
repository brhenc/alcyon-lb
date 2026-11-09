// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Inputs that used to reach an `unwrap()` in non-test code of `alcyon-proto` (P1).

use alcyon_proto::h1::H1Parser;
use alcyon_proto::htx::HtxSlice;

/// Two Content-Length headers whose values are not UTF-8. The parser skipped the value of
/// each (`continue`) but still flagged the pair as a duplicate, then unwrapped the
/// never-set length. The line scan refuses it first ("invalid Content-Length value"), which is
/// what makes the later `unwrap` unreachable; this guards that ordering. HAProxy answers 400.
#[test]
fn duplicate_content_length_with_non_utf8_values_is_refused_not_a_panic() {
    let input = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: \xff\xfe\r\nContent-Length: \xff\xfe\r\n\r\nx";
    let mut p = H1Parser::new(false);
    let mut buf = [0u8; 4096];
    let mut h = HtxSlice::new(&mut buf);
    assert!(p.parse(input, &mut h).is_err());
}
