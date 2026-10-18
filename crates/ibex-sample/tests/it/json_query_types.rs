// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T363b: `json_query` gives `HAProxy`'s sample types (`src/sample.c` `sample_conv_json_query`):
//! `true`/`false` are a boolean (printed `1`/`0`, reg-test `converter/json_query.vtc`), a number with
//! `"int"` is an integer, and `null` or an object is no sample.

use ibex_sample::registry::Registry;
use ibex_sample::sample::Sample;

fn eval(input: &str, args: &[&str]) -> Option<Sample> {
    let reg = Registry::new();
    let conv = reg.get_converter("json_query").expect("json_query");
    let args: Vec<String> = args.iter().map(|&s| s.to_string()).collect();
    (conv.func)(Sample::Str(input.into()), &args)
}

#[test]
fn json_query_returns_haproxy_types() {
    let j = r#"{"t":true,"f":false,"i":41,"s":"x","n":null,"o":{"a":1},"a":[1,2]}"#;
    assert!(matches!(eval(j, &["$.t"]), Some(Sample::Bool(true))));
    assert!(matches!(eval(j, &["$.f"]), Some(Sample::Bool(false))));
    assert!(matches!(eval(j, &["$.i", "int"]), Some(Sample::Sint(41))));
    assert!(matches!(eval(j, &["$.s"]), Some(Sample::Str(s)) if s == "x"));
    assert!(eval(j, &["$.n"]).is_none(), "null is no sample");
    assert!(eval(j, &["$.o"]).is_none(), "an object is no sample");
    assert!(matches!(eval(j, &["$.a"]), Some(Sample::Str(s)) if s == "[1,2]"));
}
