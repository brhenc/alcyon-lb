// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use ibex_sample::{Registry, Sample, SampleContext};
use std::io::Write;

#[test]
fn str_fetch_x_escape() {
    let reg = Registry::new();
    let ctx = SampleContext::default();

    // \xHH decoding
    let res = reg.eval("str", &["foo\\x41bar".to_string()], &[], &ctx);
    assert_eq!(res, Some(Sample::Str("fooAbar".to_string())));

    let res2 = reg.eval("str", &["foo\\x4".to_string()], &[], &ctx);
    assert_eq!(res2, Some(Sample::Str("foo\\x4".to_string())));

    let res3 = reg.eval("str", &["foo\\xZZbar".to_string()], &[], &ctx);
    assert_eq!(res3, Some(Sample::Str("foo\\xZZbar".to_string())));
}

#[test]
fn reverse_dom_edge_cases() {
    let reg = Registry::new();
    let ctx = SampleContext::default();

    let res = reg.eval("str", &[".".to_string()], &[("reverse_dom", vec![])], &ctx);
    assert_eq!(res, None); // HAProxy 3.5-dev8: "." has no reverse

    let res2 = reg.eval("str", &[".foo".to_string()], &[("reverse_dom", vec![])], &ctx);
    assert_eq!(res2, None);

    let res3 = reg.eval("str", &["foo..bar".to_string()], &[("reverse_dom", vec![])], &ctx);
    assert_eq!(res3, None);
}

#[test]
fn json_escape() {
    let reg = Registry::new();
    let ctx = SampleContext::default();

    // Test json string escape
    let s = "quote\" slash\\ ctrl\x08\x0c\n\r\t control\x01 \u{FFFD}";
    let res = reg.eval("str", &[s.to_string()], &[("json", vec![])], &ctx);
    assert_eq!(res, Some(Sample::Str("quote\\\" slash\\\\ ctrl\\b\\f\\n\\r\\t control\\u0001 \u{FFFD}".to_string())));
}

#[test]
fn json_query_escape() {
    let reg = Registry::new();
    let ctx = SampleContext::default();

    let json_input = r#"{"user\\name": "alice"}"#;
    let res = reg.eval("str", &[json_input.to_string()], &[("json_query", vec![r#"$.user\\name"#.to_string()])], &ctx);
    assert_eq!(res, Some(Sample::Str("alice".to_string())));
}

#[test]
fn json_converters_utf8() {
    let reg = Registry::new();
    let ctx = SampleContext::default();

    let bad_utf8 = "bad\u{FFFD}char";
    let res = reg.eval("str", &[bad_utf8.to_string()], &[("json", vec!["utf8".to_string()])], &ctx);
    assert_eq!(res, Some(Sample::Str("".to_string())));

    let res2 = reg.eval("str", &[bad_utf8.to_string()], &[("json", vec!["utf8s".to_string()])], &ctx);
    assert_eq!(res2, Some(Sample::Str("badchar".to_string())));
}

#[test]
fn json_query_extracts() {
    let reg = Registry::new();
    let ctx = SampleContext::default();

    let json_input = r#"{"user": {"name": "alice"}, "my.key": "bob"}"#;
    let res = reg.eval("str", &[json_input.to_string()], &[("json_query", vec!["$.user.name".to_string()])], &ctx);
    assert_eq!(res, Some(Sample::Str("alice".to_string())));

    let res2 = reg.eval("str", &[json_input.to_string()], &[("json_query", vec![r#"$.my\.key"#.to_string()])], &ctx);
    assert_eq!(res2, Some(Sample::Str("bob".to_string())));
}

#[test]
fn map_match_type_longest_match() {
    let path_buf = format!("/tmp/map_beg_table.{}.txt", std::process::id());
    let path = path_buf.as_str();
    let mut file = std::fs::File::create(path).unwrap();
    writeln!(file, "foo short\nfoob long").unwrap();

    let reg = Registry::new();
    let ctx = SampleContext::default();

    let res = reg.eval("str", &["foobaz".to_string()], &[("map_beg", vec![path.to_string()])], &ctx);
    assert_eq!(res, Some(Sample::Str("long".to_string())));

    let path_end_buf = format!("/tmp/map_end_table.{}.txt", std::process::id());
    let path_end = path_end_buf.as_str();
    let mut file_end = std::fs::File::create(path_end).unwrap();
    writeln!(file_end, "bar short\nobar long").unwrap();

    // `map_end` walks the file in order and takes the first entry that matches, not the
    // longest (HAProxy 3.5-dev8-885761-29 answers `short`, T251).
    let res_end = reg.eval("str", &["foobar".to_string()], &[("map_end", vec![path_end.to_string()])], &ctx);
    assert_eq!(res_end, Some(Sample::Str("short".to_string())));
}

#[test]
fn url_decodes_plus_to_space() {
    let reg = Registry::new();
    let ctx = SampleContext::default();

    let res = reg.eval("str", &["alice+bob".to_string()], &[("url_dec", vec!["1".to_string()])], &ctx);
    assert_eq!(res, Some(Sample::Str("alice bob".to_string())));

    let res2 = reg.eval("str", &["alice+bob".to_string()], &[("url_dec", vec![])], &ctx);
    assert_eq!(res2, Some(Sample::Str("alice+bob".to_string())));

    let res3 = reg.eval("str", &["?alice+bob".to_string()], &[("url_dec", vec![])], &ctx);
    assert_eq!(res3, Some(Sample::Str("?alice bob".to_string())));
}
