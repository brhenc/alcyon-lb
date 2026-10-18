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

fn text(input: &str, args: &[&str]) -> Option<String> {
    match eval(input, args)? {
        Sample::Str(s) => Some(s),
        Sample::Sint(i) => Some(format!("int {i}")),
        Sample::Bool(b) => Some(format!("bool {b}")),
        _ => Some("other".into()),
    }
}

/// Every expectation measured on 3.5-dev8-885761-29 (`http-request return ... lf-string
/// "%[var(txn.b),json_query(...)]"`, body POSTed): the path is mjson's `$`, `.key`, `[n]`,
/// with a backslash taking the next key character literally; `/a`, `a`, `$.l.1` and an
/// index past the end give no sample.
#[test]
fn json_query_walks_mjson_paths() {
    let j = r#"{"a":1.5,"o":{"k":"v"},"l":[10,20,{"z":"zz"}],"d.x":"dot","t":true}"#;
    assert_eq!(text(j, &["$.o.k"]).as_deref(), Some("v"));
    assert_eq!(text(j, &["$.l[1]"]).as_deref(), Some("20"));
    assert_eq!(text(j, &["$.l[2].z"]).as_deref(), Some("zz"));
    assert_eq!(text(j, &[r"$.d\.x"]).as_deref(), Some("dot"));
    assert_eq!(text(j, &["$.t"]).as_deref(), Some("bool true"));
    for bad in ["/a", "a", "$", "$.l[7]", "$.l.1", "$.", "$.l[", "$.a.b", "$x"] {
        assert_eq!(text(j, &[bad]), None, "{bad}");
    }
    assert_eq!(text(r#"[5,[6,7]]"#, &["$[1]"]).as_deref(), Some("[6,7]"));
    assert_eq!(text(r#"[5,[6,7]]"#, &["$[1][0]", "int"]).as_deref(), Some("int 6"));
    assert_eq!(text(r#"{"a":{"b":4}}"#, &["$.a.b"]).as_deref(), Some("4"));
}

/// A number is printed with `%g` unless `int` is given, and `int` keeps +-(2^53-1).
#[test]
fn json_query_numbers_as_g_and_int() {
    let a = |body: &str, int: bool| text(body, if int { &["$.a", "int"] } else { &["$.a"] });
    for (body, g, int) in [
        (r#"{"a":1.5}"#, "1.5", Some("int 1")),
        (r#"{"a":12345678}"#, "1.23457e+07", Some("int 12345678")),
        (r#"{"a":-0.0000123}"#, "-1.23e-05", Some("int 0")),
        (r#"{"a":100000}"#, "100000", Some("int 100000")),
        (r#"{"a":1000000}"#, "1e+06", Some("int 1000000")),
        (r#"{"a":0.1}"#, "0.1", Some("int 0")),
        (r#"{"a":-5}"#, "-5", Some("int -5")),
        (r#"{"a":0}"#, "0", Some("int 0")),
        (r#"{"a":0.30000000000000004}"#, "0.3", Some("int 0")),
        (r#"{"a":9007199254740991}"#, "9.0072e+15", Some("int 9007199254740991")),
        (r#"{"a":-9007199254740991}"#, "-9.0072e+15", Some("int -9007199254740991")),
        (r#"{"a":9007199254740992}"#, "9.0072e+15", None),
        (r#"{"a":-9007199254740992}"#, "-9.0072e+15", None),
        (r#"{"a":12345678901234567890}"#, "1.23457e+19", None),
    ] {
        assert_eq!(a(body, false).as_deref(), Some(g), "{body}");
        assert_eq!(a(body, true).as_deref(), int, "{body} int");
    }
}
