// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The string-to-integer cast, as `HAProxy`'s `c_str2int` (`src/sample.c`) does it with
//! `read_int64` (`src/tools.c`): an optional `-` or `+`, then the leading decimal digits;
//! anything after them is ignored, no whitespace is skipped, no `0x` prefix is read, a
//! value out of range saturates, and only an empty string fails the cast.
//!
//! Measured against `HAProxy` 3.5-dev8-885761-29, 2026-10-03, with
//! `lf-string "%[req.hdr(x-n),add(1)]"` (and `urlp(n),url_dec,add(1)` for the leading
//! space and tab, which a header value cannot carry because the parser strips them):
//!
//! | input                    | `add(1)`              |
//! |--------------------------|-----------------------|
//! | `abc`                    | 1                     |
//! | `12abc`                  | 13                    |
//! | (empty)                  | (no value)            |
//! | `+5`                     | 6                     |
//! | `-3x`                    | -2                    |
//! | `-`, `+`                 | 1                     |
//! | `7`                      | 8                     |
//! | `"12 "`                  | 13                    |
//! | `0x10`                   | 1                     |
//! | `" 12"`, `" -3"`, `"\t"` | 1                     |
//! | `9223372036854775807`, `9223372036854775808`, `99999999999999999999` | 9223372036854775807 |
//! | `-9223372036854775808`, `-9223372036854775809`, `-99999999999999999999` | -9223372036854775807 (`i64::MIN + 1`) |
//!
//! and with `req.hdr(x-n) -m int 0`: matches `abc`, `-`, `0x10`; not `12abc`, `7`, an
//! empty value. `req.hdr(x-n) -m int gt 5`: matches `12abc`, `7`,
//! `99999999999999999999`; not `abc`, `+5`, `-3x`, `0x10`, an empty value.

use ibex_sample::{cast, Matcher, Sample, SampleType};

fn str2int(s: &str) -> Option<i64> {
    match cast(Sample::Str(s.to_string()), SampleType::Sint) {
        Some(Sample::Sint(n)) => Some(n),
        None => None,
        Some(other) => panic!("a string cast to sint gave {other:?}"),
    }
}

#[test]
fn a_string_casts_to_its_leading_integer_as_haproxy_reads_it() {
    let cases: &[(&str, Option<i64>)] = &[
        ("abc", Some(0)),
        ("12abc", Some(12)),
        ("", None),
        ("+5", Some(5)),
        ("-3x", Some(-3)),
        ("-", Some(0)),
        ("+", Some(0)),
        ("7", Some(7)),
        ("0x10", Some(0)),
        (" 12", Some(0)),
        (" -3", Some(0)),
        ("\t", Some(0)),
        ("12 ", Some(12)),
        ("9223372036854775807", Some(i64::MAX)),
        ("9223372036854775808", Some(i64::MAX)),
        ("99999999999999999999", Some(i64::MAX)),
        ("-9223372036854775808", Some(i64::MIN)),
        ("-9223372036854775809", Some(i64::MIN)),
        ("-99999999999999999999", Some(i64::MIN)),
    ];
    let wrong: Vec<String> = cases
        .iter()
        .filter_map(|&(input, want)| {
            let got = str2int(input);
            (got != want).then(|| format!("{input:?}: HAProxy gives {want:?}, Ibex gave {got:?}"))
        })
        .collect();
    assert!(wrong.is_empty(), "string-to-integer cast differs from HAProxy's c_str2int:\n{}", wrong.join("\n"));
}

#[test]
fn integer_matching_casts_a_string_sample_as_haproxy_does() {
    let eq0 = Matcher::compile("int", "0").expect("-m int 0");
    let gt5 = Matcher::compile("gt", "5").expect("-m int gt 5");
    let cases: &[(&str, bool, bool)] = &[
        // (sample, matches `-m int 0`, matches `-m int gt 5`)
        ("abc", true, false),
        ("-", true, false),
        ("0x10", true, false),
        ("12abc", false, true),
        ("7", false, true),
        ("99999999999999999999", false, true),
        ("+5", false, false),
        ("-3x", false, false),
        // An empty value fails the cast, so it matches nothing, not even 0.
        ("", false, false),
    ];
    let wrong: Vec<String> = cases
        .iter()
        .filter_map(|&(input, want_eq0, want_gt5)| {
            let smp = Sample::Str(input.to_string());
            let got = (eq0.matches(&smp), gt5.matches(&smp));
            (got != (want_eq0, want_gt5)).then(|| {
                format!("{input:?}: HAProxy (int 0, gt 5) = {:?}, Ibex = {got:?}", (want_eq0, want_gt5))
            })
        })
        .collect();
    assert!(wrong.is_empty(), "integer matching of a string sample differs from HAProxy:\n{}", wrong.join("\n"));
}
