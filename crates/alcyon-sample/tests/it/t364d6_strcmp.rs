// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Verifier's hidden test (T364 D6). Every row measured on HAProxy 3.5-dev8-885761-29, 2026-10-18:
//! `http-request set-var(txn.v) str(%XX..),url_dec` then `%[str(%XX..),url_dec,strcmp(txn.v)]`.

use alcyon_regex::bytetext::bytes_to_text;
use alcyon_sample::registry::{set_current_vars, Registry};
use alcyon_sample::sample::Sample;
use std::collections::HashMap;

/// (input bytes as hex, the variable's bytes as hex, HAProxy's number).
const ROWS: &[(&str, &str, i64)] = &[
    ("", "", 0),
    ("", "61", -1),
    ("61", "", 1),
    ("61", "61", 0),
    ("61", "62", -1),
    ("62", "61", 1),
    ("61", "7a", -25),
    ("7a", "61", 25),
    ("616c706861", "62657461", -1),
    ("62657461", "62657461", 0),
    ("67616d6d61", "62657461", 5),
    ("616263", "61626364", -1),
    ("61626364", "616263", 1),
    ("616278", "61626364", 21),
    ("61626364", "616278", -21),
    ("616263", "616264", -1),
    ("414243", "616263", -32),
    ("616263", "414243", 32),
    ("5a65627261", "6170706c65", -7),
    ("e9", "65", 132),
    ("65", "e9", -132),
    ("ff", "61", 158),
    ("61", "ff", -158),
    ("80", "7f", 1),
    ("7f", "80", -1),
    ("c3a9", "65", 94),
    ("65", "c3a9", -94),
    ("c3a9", "c389", 32),
    ("c389", "c3a9", -32),
    ("ffff", "ff", 1),
    ("ff", "ffff", -1),
    ("80", "ff", -127),
    ("ff", "80", 127),
    ("612062", "615f62", -63),
    ("20", "7e", -94),
    ("7e", "20", 94),
    ("01", "ff", -254),
    ("ff", "01", 254),
    ("3132", "39", -8),
    ("39", "3132", 8),
    ("68656c6c6f20776f726c64", "68656c6c6f20576f726c64", 32),
    ("636166c3a9", "63616665", 94),
    ("63616665", "636166c3a9", -94),
    ("78e979", "78e97a", -1),
];

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len() / 2).map(|i| u8::from_str_radix(h.get(i * 2..i * 2 + 2).unwrap_or("00"), 16).unwrap_or(0)).collect()
}

#[test]
fn strcmp_gives_haproxys_number() {
    let reg = Registry::new();
    let conv = reg.get_converter("strcmp").expect("strcmp");
    let mut bad = Vec::new();
    for (input, var, want) in ROWS {
        let mut vars = HashMap::new();
        vars.insert("txn.v".to_string(), bytes_to_text(&unhex(var)));
        set_current_vars(vars);
        let got = (conv.func)(Sample::Str(bytes_to_text(&unhex(input))), &["txn.v".to_string()]);
        if got != Some(Sample::Sint(*want)) {
            bad.push(format!("bytes {input} strcmp bytes {var}: HAProxy {want}, Alcyon {got:?}"));
        }
    }
    assert!(bad.is_empty(), "{} of {} rows differ from HAProxy; the first ones:\n{}", bad.len(), ROWS.len(), bad.iter().take(12).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn strcmp_of_an_unset_variable_gives_no_sample() {
    set_current_vars(HashMap::new());
    let reg = Registry::new();
    let conv = reg.get_converter("strcmp").expect("strcmp");
    assert_eq!((conv.func)(Sample::Str("a".into()), &["txn.unset".to_string()]), None);
}
