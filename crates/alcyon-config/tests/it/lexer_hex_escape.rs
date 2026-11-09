// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `parse_line` refuses a `\x` not followed by two hex digits (PARSE_ERR_HEX). Measured
//! 2026-10-03 with `haproxy -c` (3.5-dev8-885761-29): `"a\xZZb"` and `"a\x4"` give
//! "truncated or invalid hexadecimal sequence at position 33" and exit 1. Inside single
//! quotes the backslash is literal, so `'a\xZZb'` loads.

use alcyon_config::parse_str;

fn with_value(v: &str) -> Result<alcyon_config::Config, alcyon_config::ConfigError> {
    parse_str(&format!(
        "frontend fe\n  mode http\n  bind 127.0.0.1:29000\n  http-request set-header x {v}\n"
    ))
}

#[test]
fn a_hex_escape_needs_two_hex_digits() {
    for bad in [r#""a\xZZb""#, r#""a\x4""#, r"a\xZ1", r"a\x", r#""a\x4g""#] {
        let e = with_value(bad).expect_err(&format!("HAProxy refuses `{bad}`"));
        assert!(
            e.to_string().contains("hexadecimal"),
            "the error for `{bad}` should name the hex sequence, got: {e}"
        );
    }
}

#[test]
fn a_complete_hex_escape_and_a_single_quoted_one_load() {
    for ok in [r#""a\x41b""#, r"a\x4a", r"'a\xZZb'", r#""a\x41""#] {
        with_value(ok).unwrap_or_else(|e| panic!("HAProxy accepts `{ok}`: {e}"));
    }
}
