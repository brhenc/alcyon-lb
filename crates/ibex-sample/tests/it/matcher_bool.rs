// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `-m bool` (`PAT_MATCH_BOOL`, `pat_match_nothing`): the sample is cast to a `sint` and the
//! ACL matches when it is non-zero. Measured on 3.5-dev8-885761-29 with
//! `acl a <fetch> -m bool` and `http-request set-header X 1 if a`: `str(007)`, `str(5abc)`,
//! `str(-1)`, `int(1)`, `int(-1)`, `bool(1)`, `ipv4(10.1.2.3)`, `str(9223372036854775807)` and
//! `str(99999999999999999999)` match; `str(Abc)`, `str()`, `str(0x10)`, `int(0)`, `bool(0)`,
//! `ipv4(0.0.0.0)` do not. Patterns after `-m bool` are accepted and ignored (`pat_parse_nothing`).

use ibex_sample::{Expr, Matcher, Sample};
use std::net::Ipv4Addr;

fn m(s: &Sample) -> bool {
    Matcher::compile("bool", "").expect("-m bool is a matching method").matches(s)
}

fn st(s: &str) -> Sample {
    Sample::Str(s.to_string())
}

#[test]
fn a_string_matches_when_its_integer_cast_is_non_zero() {
    for (s, want) in [
        ("007", true),
        ("5abc", true),
        ("-1", true),
        ("9223372036854775807", true),
        ("99999999999999999999", true),
        ("Abc", false),
        ("", false),
        ("0x10", false),
        ("0", false),
    ] {
        assert_eq!(m(&st(s)), want, "str({s})");
    }
}

#[test]
fn integers_booleans_and_addresses() {
    assert!(m(&Sample::Sint(1)));
    assert!(m(&Sample::Sint(-1)));
    assert!(!m(&Sample::Sint(0)));
    assert!(m(&Sample::Bool(true)));
    assert!(!m(&Sample::Bool(false)));
    assert!(m(&Sample::Ipv4(Ipv4Addr::new(10, 1, 2, 3))));
    assert!(!m(&Sample::Ipv4(Ipv4Addr::new(0, 0, 0, 0))));
}

#[test]
fn patterns_after_the_method_are_accepted_and_ignored() {
    let e = Expr::parse("str(abc) -m bool xyz 1 2").expect("accepted");
    assert!(e.matcher.is_some());
    assert!(!e.matcher.as_ref().expect("m").matches(&st("abc")));
    let e = Expr::parse("str(1) -m bool xyz").expect("accepted");
    assert!(e.matcher.as_ref().expect("m").matches(&st("1")));
}

#[test]
fn the_expression_form_loads() {
    assert!(Expr::parse("int(1) -m bool").is_ok());
}
