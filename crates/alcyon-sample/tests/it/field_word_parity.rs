// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T359f: `field` and `word` as `HAProxy` 3.5-dev8 (`src/sample.c` `sample_conv_field`, `sample_conv_word`).

use alcyon_sample::registry::Registry;
use alcyon_sample::sample::Sample;

fn eval(name: &str, input: &str, args: &[&str]) -> Option<String> {
    let reg = Registry::new();
    let conv = reg.get_converter(name).expect(name);
    let args: Vec<String> = args.iter().map(|&s| s.to_string()).collect();
    match (conv.func)(Sample::Str(input.into()), &args) {
        Some(Sample::Str(s)) => Some(s),
        None => None,
        Some(other) => Some(format!("{other:?}")),
    }
}

#[test]
fn field_1_colon_4294967297() {
    assert_eq!(eval("field", "a:b:c:d", &["1", ":", "4294967297"]), Some("a".to_string()));
}

#[test]
fn field_2_colon_4294967298() {
    assert_eq!(eval("field", "a:b:c:d", &["2", ":", "4294967298"]), Some("b:c".to_string()));
}

#[test]
fn field_2_colon_neg4294967295() {
    assert_eq!(eval("field", "a:b:c:d", &["2", ":", "-4294967295"]), Some("b".to_string()));
}

#[test]
fn word_1_colon_4294967297() {
    assert_eq!(eval("word", "a:b:c:d", &["1", ":", "4294967297"]), Some("a".to_string()));
}

#[test]
fn field_neg1_colon_2() {
    assert_eq!(eval("field", "a:b:c:d", &["-1", ":", "2"]), Some("c:d".to_string()));
}

#[test]
fn field_neg1_colon_3() {
    assert_eq!(eval("field", "a:b:c:d", &["-1", ":", "3"]), Some("b:c:d".to_string()));
}

#[test]
fn field_neg1_colon_0() {
    assert_eq!(eval("field", "a:b:c:d", &["-1", ":", "0"]), Some("a:b:c:d".to_string()));
}

#[test]
fn field_neg2_colon_neg1() {
    assert_eq!(eval("field", "a:b:c:d", &["-2", ":", "-1"]), Some("a:b:c".to_string()));
}

#[test]
fn word_neg1_colon_2() {
    assert_eq!(eval("word", "a:b:c:d", &["-1", ":", "2"]), Some("c:d".to_string()));
}

#[test]
fn word_neg2_colon_0() {
    assert_eq!(eval("word", "a:b:c:d", &["-2", ":", "0"]), Some("a:b:c".to_string()));
}

#[test]
fn field_2_colon_semicolon_of_a_semicolon_b_colon_c_semicolon_d() {
    assert_eq!(eval("field", "a;b:c;d", &["2", ":;"]), Some("b".to_string()));
}

#[test]
fn word_2_semicolon_colon_of_a_semicolon_b_colon_c_semicolon_d() {
    assert_eq!(eval("word", "a;b:c;d", &["2", ";:"]), Some("b".to_string()));
}

#[test]
fn field_5_colon_none() {
    assert_eq!(eval("field", "a:b:c:d", &["5", ":"]), None);
}

#[test]
fn field_neg5_colon_none() {
    assert_eq!(eval("field", "a:b:c:d", &["-5", ":"]), None);
}
