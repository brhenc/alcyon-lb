// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A `.if` or `.elif` condition that does not parse: `HAProxy` 3.5-dev8-885761-29 names
//! the position of the first bad character, repeats the line and points at it with a caret
//! (`cfg_eval_condition`'s `errptr`, `src/cfgparse.c`). Every expected text below is what
//! `haproxy -c` printed, measured on 2026-10-04.

use ibex_config::parse_str;

fn error(directive: &str, cond: &str) -> String {
    let prefix = if directive == ".elif" { ".if 0\n" } else { "" };
    let cfg = format!("global\n{prefix}{directive} {cond}\n  maxconn 1\n.endif\n");
    parse_str(&cfg).expect_err("refused").message
}

#[test]
fn the_caret_points_at_the_first_bad_character() {
    let cases: &[(&str, &str)] = &[
        ("foo(1)", "unparsable conditional expression 'foo(1)' in '.if' at position 1:\n  .if foo(1)\n      ^"),
        ("streq(a,b) && foo", "unparsable conditional expression 'foo' in '.if' at position 15:\n  .if streq(a,b) && foo\n                    ^"),
        ("streq(a,b) &&", "unparsable conditional expression '&&' in '.if' at position 12:\n  .if streq(a,b) &&\n                 ^"),
        ("!(1", "expected ')' after conditional expression '!(1' in '.if' at position 1:\n  .if !(1\n      ^"),
        ("1 && (2", "expected ')' after conditional expression '(2' in '.if' at position 6:\n  .if 1 && (2\n           ^"),
        (
            "streq(a)",
            "missing arguments (got 1/2), type 'string' expected in argument 1 of predicate 'streq' used in conditional expression in '.if' at position 8:\n  .if streq(a)\n             ^",
        ),
        (
            "streq(a,b,c)",
            "expected ')' before ',c)' in argument 1 of predicate 'streq' used in conditional expression in '.if' at position 10:\n  .if streq(a,b,c)\n               ^",
        ),
        (
            "streq(a,b",
            "expected ')' in argument 1 of predicate 'streq' used in conditional expression in '.if' at position 10:\n  .if streq(a,b\n               ^",
        ),
        (
            "fips_mode(x)",
            "expected ')' before 'x)' in argument 0 of predicate 'fips_mode' used in conditional expression in '.if' at position 11:\n  .if fips_mode(x)\n                ^",
        ),
        (
            "version_atleast(",
            "expected ')' in argument 1 of predicate 'version_atleast' used in conditional expression in '.if' at position 17:\n  .if version_atleast(\n                      ^",
        ),
        ("1 ||", "unparsable conditional expression '1 ||' in '.if' at position 3:\n  .if 1 ||\n        ^"),
        ("1 2", "unexpected character '2' at the end of conditional expression '1 2' in '.if' at position 3:\n  .if 1 2\n        ^"),
        ("(1) x", "unexpected character 'x' at the end of conditional expression '(1) x' in '.if' at position 5:\n  .if (1) x\n          ^"),
        ("1 && || 1", "unparsable conditional expression '|| 1' in '.if' at position 6:\n  .if 1 && || 1\n           ^"),
        ("&& 1", "unparsable conditional expression '&& 1' in '.if' at position 1:\n  .if && 1\n      ^"),
        ("( )", "unparsable conditional expression ')' in '.if' at position 3:\n  .if ( )\n        ^"),
        ("!", "unparsable conditional expression '!' in '.if' at position 1:\n  .if !\n      ^"),
    ];
    for (cond, want) in cases {
        assert_eq!(error(".if", cond), *want, "`.if {cond}`");
    }
}

#[test]
fn an_elif_is_named_as_one() {
    assert_eq!(
        error(".elif", "foo(1)"),
        "unparsable conditional expression 'foo(1)' in '.elif' at position 1:\n  .elif foo(1)\n        ^"
    );
}
