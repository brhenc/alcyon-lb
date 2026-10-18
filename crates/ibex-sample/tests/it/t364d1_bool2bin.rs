// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Verifier's hidden test (T364 D1). Every row measured on HAProxy 3.5-dev8-885761-29, 2026-10-18:
//! `http-request return ... lf-string "%[<fetch>,<converters>]"`, the answer is the text HAProxy prints.

use ibex_sample::{cast, Registry, Sample, SampleContext, SampleType};

/// (fetch, its argument, converters, HAProxy's text). `hex` prints upper case.
type Conv = (&'static str, &'static [&'static str]);
const ROWS: &[(&str, &str, &[Conv], &str)] = &[
    ("bool", "1", &[("hex", &[])], "0000000000000001"),
    ("bool", "0", &[("hex", &[])], "0000000000000000"),
    ("int", "5", &[("hex", &[])], "0000000000000005"),
    ("int", "0", &[("hex", &[])], "0000000000000000"),
    ("int", "-1", &[("hex", &[])], "FFFFFFFFFFFFFFFF"),
    ("int", "5", &[("bool", &[]), ("hex", &[])], "0000000000000001"),
    ("int", "0", &[("bool", &[]), ("hex", &[])], "0000000000000000"),
    ("int", "300", &[("bool", &[]), ("hex", &[])], "0000000000000001"),
    ("str", "0", &[("bool", &[]), ("hex", &[])], "0000000000000000"),
    ("str", "abc", &[("bool", &[]), ("hex", &[])], "0000000000000000"),
    ("bool", "1", &[("sha1", &[]), ("hex", &[])], "CB473678976F425D6EC1339838F11011007AD27D"),
    ("bool", "1", &[("base64", &[])], "AAAAAAAAAAE="),
    ("bool", "0", &[("crc32", &[])], "1696784233"),
    ("bool", "1", &[("bytes", &["7", "1"]), ("hex", &[])], "01"),
    ("bool", "1", &[("bytes", &["0", "7"]), ("hex", &[])], "00000000000000"),
    ("bool", "1", &[("bytes", &["3"]), ("hex", &[])], "0000000001"),
    ("bool", "1", &[("hex", &[]), ("length", &[])], "16"),
];

fn show(s: &Sample) -> String {
    match s {
        Sample::Str(t) => t.clone(),
        Sample::Sint(n) => n.to_string(),
        other => format!("{other:?}"),
    }
}

#[test]
fn bool_to_bin_is_eight_bytes_through_converters() {
    let reg = Registry::new();
    let ctx = SampleContext::default();
    let mut bad = Vec::new();
    for (fetch, arg, convs, want) in ROWS {
        let convs: Vec<(&str, Vec<String>)> =
            convs.iter().map(|(n, a)| (*n, a.iter().map(|s| (*s).to_string()).collect())).collect();
        let got = reg.eval(fetch, &[(*arg).to_string()], &convs, &ctx).map(|s| show(&s));
        if got.as_deref() != Some(*want) {
            let names: Vec<&str> = convs.iter().map(|c| c.0).collect();
            bad.push(format!("{fetch}({arg}),{}: HAProxy {want:?}, Ibex {got:?}", names.join(",")));
        }
    }
    assert!(bad.is_empty(), "{} of {} rows differ from HAProxy:\n{}", bad.len(), ROWS.len(), bad.join("\n"));
}

#[test]
fn bool_to_bin_cast_is_eight_big_endian_bytes() {
    assert_eq!(cast(Sample::Bool(true), SampleType::Bin), Some(Sample::Bin(vec![0, 0, 0, 0, 0, 0, 0, 1])));
    assert_eq!(cast(Sample::Bool(false), SampleType::Bin), Some(Sample::Bin(vec![0; 8])));
    // the neighbours stay as they are: sint -> bin is 8 bytes, bool -> str is the digit
    assert_eq!(cast(Sample::Sint(5), SampleType::Bin), Some(Sample::Bin(vec![0, 0, 0, 0, 0, 0, 0, 5])));
    assert_eq!(cast(Sample::Bool(true), SampleType::Str), Some(Sample::Str("1".into())));
}
