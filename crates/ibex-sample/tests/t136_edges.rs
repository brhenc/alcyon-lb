// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Converter and fetch edges of T136: out-of-range indexes, bad units, long and
//! variable HMAC keys, and the load-time argument checks. Values measured on HAProxy
//! 3.5-dev8-885761-29.

use ibex_sample::registry::{check_converter_args, set_proc_var, Registry, SampleContext};
use ibex_sample::sample::Sample;

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|a| (*a).to_string()).collect()
}

#[test]
fn field_and_word_far_before_the_start_are_no_sample() {
    let reg = Registry::new();
    let ctx = SampleContext::default();
    assert_eq!(reg.eval("str", &s(&["a/b"]), &[("field", s(&["-9", "/"]))], &ctx), None);
    assert_eq!(reg.eval("str", &s(&["a b"]), &[("word", s(&["-9", " "]))], &ctx), None);
}

#[test]
fn unknown_units_give_no_sample() {
    let reg = Registry::new();
    let ctx = SampleContext { accept_date: Some((1, 2)), ..Default::default() };
    assert_eq!(reg.eval("date", &s(&["0", "bogus"]), &[], &ctx), None);
    assert_eq!(reg.eval("accept_date", &s(&["bogus"]), &[], &ctx), None);
    assert_eq!(reg.eval("accept_date", &s(&["us"]), &[], &ctx), Some(Sample::Sint(1_002_000)));
    assert_eq!(reg.eval("int", &s(&["0"]), &[("http_date", s(&["0", "bogus"]))], &ctx), None);
}

#[test]
fn hmac_key_from_a_proc_variable_or_longer_than_a_block() {
    let reg = Registry::new();
    let ctx = SampleContext::default();
    let key = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp+goaKjpA==";
    set_proc_var("proc.t136key", key.to_string());
    let want = "35b5eecff9febe9a0b8d5dda37a1783a4036ba6d";
    for k in [key, "proc.t136key"] {
        let got = reg.eval("str", &s(&["msg"]), &[("hmac", s(&["sha1", k])), ("hex", vec![]), ("lower", vec![])], &ctx);
        assert_eq!(got, Some(Sample::Str(want.to_string())), "key {k}");
    }
}

#[test]
fn converter_argument_checks_refuse_what_haproxy_refuses() {
    assert!(check_converter_args("hmac", &s(&["sha1", "a2V5", "x"])).is_some());
    assert!(check_converter_args("hmac", &s(&["sha1"])).is_some());
    assert!(check_converter_args("url_enc", &s(&["path"])).is_some());
    assert!(check_converter_args("url_enc", &s(&["query", "x"])).is_some());
    assert!(check_converter_args("url_enc", &s(&["query"])).is_none());
    assert!(check_converter_args("when", &s(&["bogus"])).is_some());
    assert!(check_converter_args("when", &s(&["!error"])).is_none());
}
