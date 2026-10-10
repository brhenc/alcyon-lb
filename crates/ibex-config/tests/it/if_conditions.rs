// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `.if` / `.elif` conditions use the grammar of `cfg_eval_condition` (`src/cfgcond.c`), the
//! one `-cc` uses (T131). Every verdict below was measured on `haproxy -c` (3.5-dev8-885761-29)
//! with `.if <cond>` followed by `.alert yes`: `T` the alert fired, `F` it did not, `E` the
//! configuration was refused with an error pointing into the condition. Conditions whose
//! answer depends on the build or on the environment are left out; the quoting and
//! `$VAR` expansion of the line itself belong to the lexer and are not tested here.

use ibex_config::parse_str;

fn verdict(cond: &str, keyword: &str) -> char {
    let cfg = match keyword {
        ".if" => format!(".if {cond}\nbackend yes\n.else\nbackend no\n.endif\n"),
        _ => format!(".if 0\nbackend no\n{keyword} {cond}\nbackend yes\n.else\nbackend no\n.endif\n"),
    };
    match parse_str(&cfg) {
        Err(_) => 'E',
        Ok(c) if c.backends.first().is_some_and(|b| b.name == "yes") => 'T',
        Ok(_) => 'F',
    }
}

const CASES: &[(&str, char)] = &[
    ("1", 'T'),
    ("0", 'F'),
    ("-1000 && 200", 'T'),
    ("!5", 'F'),
    ("!!1", 'T'),
    ("! 0", 'T'),
    ("0x1", 'T'),
    ("010", 'T'),
    ("( 1 )", 'T'),
    ("(0||1)&&1", 'T'),
    ("", 'F'),
    ("version_atleast(2.4)", 'T'),
    ("version_atleast(1024)", 'F'),
    ("1&&!0&&!((streq(a,b)||!streq(a,a)&&1)||strneq(a,a))", 'T'),
    ("1   &&!   0&&    !((streq(a,b)||!streq(a,a)&&1)||strneq(a,a))", 'T'),
    ("1 && !0 && !((streq(a,b) || !streq(a,a) && 1) || strneq(a,b))", 'F'),
    ("streq(,)", 'T'),
    ("streq(a, a)", 'F'),
    ("streq( a ,a)", 'F'),
    ("strneq(a,b)", 'T'),
    ("strstr(abc,b)", 'T'),
    ("strstr(abc,z)", 'F'),
    ("defined( TESTVAR )", 'F'),
    ("defined(IBEX_T131_NOT_SET)", 'F'),
    ("fips_mode()", 'F'),
    ("feature(NOPE)", 'F'),
    ("200rrr", 'E'),
    ("08", 'E'),
    ("!(0))", 'E'),
    ("1 2", 'E'),
    ("1)", 'E'),
    ("(1", 'E'),
    ("1 ||", 'E'),
    ("||1", 'E'),
    ("1 &&", 'E'),
    ("!", 'E'),
    ("()", 'E'),
    ("- 1", 'E'),
    ("a", 'E'),
    ("foo(", 'E'),
    ("unknownfn(1)", 'E'),
    ("streq(a)", 'E'),
    ("streq(a,b,c)", 'E'),
    ("fips_mode( )", 'E'),
    ("feature(X,Y)", 'E'),
    ("feature (OPENSSL)", 'E'),
];

#[test]
fn if_follows_the_cfgcond_grammar() {
    let bad: Vec<_> = CASES.iter().filter(|(c, v)| verdict(c, ".if") != *v).map(|(c, v)| (c, v, verdict(c, ".if"))).collect();
    assert!(bad.is_empty(), "(condition, measured, ibex): {bad:?}");
}

#[test]
fn elif_follows_the_same_grammar() {
    let bad: Vec<_> = CASES.iter().filter(|(c, v)| verdict(c, ".elif") != *v).map(|(c, v)| (c, v, verdict(c, ".elif"))).collect();
    assert!(bad.is_empty(), "(condition, measured, ibex): {bad:?}");
}
