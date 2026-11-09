// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `concat` writes into a trash chunk of `tune.bufsize` (T251 item 4). Measured on
//! `HAProxy 3.5-dev8-885761-29` with the default bufsize of 16384: `str(<16000 A>)`
//! concatenated with 381..416 bytes answers a string cut at 16383 bytes; with 417 bytes
//! or more (the parts larger than the 16416-byte trash pool) it answers no sample, so a
//! variable fed back into itself stops growing.

use alcyon_sample::registry::{Registry, SampleContext};
use alcyon_sample::sample::Sample;

fn concat_len(base: usize, add: usize) -> Option<usize> {
    let reg = Registry::new();
    let ctx = SampleContext::default();
    match reg.eval("str", &["A".repeat(base)], &[("concat", vec!["B".repeat(add)])], &ctx) {
        Some(Sample::Str(s)) => Some(s.len()),
        None => None,
        other => panic!("concat answered {other:?}"),
    }
}

#[test]
fn concat_is_cut_at_the_buffer_size() {
    assert_eq!(concat_len(16000, 381), Some(16381));
    assert_eq!(concat_len(16000, 383), Some(16383));
    assert_eq!(concat_len(16000, 384), Some(16383));
    assert_eq!(concat_len(16000, 416), Some(16383));
}

#[test]
fn concat_larger_than_the_trash_is_no_sample() {
    assert_eq!(concat_len(16000, 417), None);
    assert_eq!(concat_len(16000, 1000), None);
    assert_eq!(concat_len(1_000_000, 1), None);
}

/// The cut at bufsize - 1 falls inside a two-byte character: Alcyon keeps its strings valid
/// UTF-8 and cuts before that character (16382 bytes). `HAProxy` cuts the bytes (16383, half
/// a character); that is not measured here, and is a deliberate difference.
#[test]
fn concat_is_cut_before_a_character_the_buffer_size_splits() {
    let reg = Registry::new();
    let ctx = SampleContext::default();
    let got = reg.eval("str", &["A".repeat(16382)], &[("concat", vec!["\u{e9}".to_string()])], &ctx);
    assert_eq!(got, Some(Sample::Str("A".repeat(16382))));
}
