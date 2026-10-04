// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `ibex -cc <condition>`: exit 0 when true, 1 when false, 2 when the condition does not
//! evaluate. `reg-tests/startup/check_condition.vtc` runs it from a shell block.
//!
//! Measured on 2026-10-03 with `haproxy -cc` (`HAProxy` 3.5-dev8-885761-29), with
//! `TESTVAR=1 EMPTYV= SPC="a b"` in the environment. Only conditions whose answer does not
//! depend on the build are here: `feature()` and the version of the binary differ by design.
//!
//! What `HAProxy` does, and this table pins (`do_check_condition`, `src/haproxy.c`, and
//! `src/cfgcond.c`):
//!
//! * the argument goes through `parse_line` first: `$VAR` is expanded, quotes are removed
//!   (so a quoted comma still separates arguments), an unmatched quote exits 2;
//! * a term is an integer (`strtol` base 0, non-zero is true), `( expr )`, or a predicate,
//!   each optionally prefixed by `!`; `&&` binds tighter than `||`;
//! * an empty condition is false, not an error;
//! * predicate arguments are not trimmed: `streq(a, a)` is false.

use std::process::Command;

/// The binary under test; `IBEX_CC_BIN=/path/to/haproxy` runs this table against the oracle.
fn ibex_bin() -> std::path::PathBuf {
    std::env::var_os("IBEX_CC_BIN")
        .map_or_else(|| std::path::PathBuf::from(env!("CARGO_BIN_EXE_ibex")), Into::into)
}

fn run(args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(ibex_bin())
        .args(args)
        .env("TESTVAR", "1")
        .env("EMPTYV", "")
        .env("SPC", "a b")
        .output()
        .expect("run ibex -cc");
    (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// `(condition, exit code, text the error must contain)`.
const CASES: &[(&str, i32, &str)] = &[
    ("version_atleast(2.4)", 0, ""),
    ("version_atleast(1024)", 1, ""),
    ("streq(foo,'foo')", 0, ""),
    ("streq(\"foo bar\",'foo bar')", 0, ""),
    ("streq(foo,bar)", 1, ""),
    ("defined(TESTVAR) && streq(\"$TESTVAR\",\"1\")", 0, ""),
    ("defined(NOPE_X)", 1, ""),
    ("defined( TESTVAR )", 1, ""),
    ("1&&!0&&!((streq(a,b)||!streq(a,a)&&1)||strneq(a,a))", 0, ""),
    ("1   &&!   0&&    !((streq(a,b)||!streq(a,a)&&1)||strneq(a,a))", 0, ""),
    ("1 && !0 && !((streq(a,b) || !streq(a,a) && 1) || strneq(a,b))", 1, ""),
    ("1 && !0 && !((streq(a,a) || !streq(a,a) && 1) || strneq(a,a))", 1, ""),
    ("", 1, ""),
    (" ", 1, ""),
    ("-1000 && 200", 0, ""),
    ("0", 1, ""),
    ("1", 0, ""),
    ("!5", 1, ""),
    ("!!1", 0, ""),
    ("! 0", 0, ""),
    ("0x1", 0, ""),
    ("010", 0, ""),
    ("( 1 )", 0, ""),
    ("(0||1)&&1", 0, ""),
    ("\"1\"", 0, ""),
    ("'1 && 0'", 1, ""),
    ("200rrr", 2, "unexpected character 'r' at the end of conditional expression '200rrr'"),
    ("08", 2, "unexpected character '8' at the end"),
    ("!(0))", 2, "unexpected character ')' at the end"),
    ("1 2", 2, "unexpected character '2' at the end of conditional expression '1 2'"),
    ("1)", 2, "unexpected character ')' at the end"),
    ("(1", 2, "expected ')' after conditional expression"),
    ("streq(a,\"a)", 2, "Syntax Error in condition: Unmatched quote."),
    ("1 ||", 2, "unparsable conditional expression"),
    ("||1", 2, "unparsable conditional expression"),
    ("1 &&", 2, "unparsable conditional expression"),
    ("!", 2, "unparsable conditional expression"),
    ("()", 2, "unparsable conditional expression"),
    ("- 1", 2, "unparsable conditional expression '- 1'"),
    ("a", 2, "unparsable conditional expression 'a'"),
    ("foo(", 2, "unparsable conditional expression 'foo('"),
    ("unknownfn(1)", 2, "unparsable conditional expression 'unknownfn(1)'"),
    ("1 || foo(", 2, "unparsable conditional expression 'foo('"),
    ("streq(a)", 2, "missing arguments (got 1/2)"),
    ("streq(a,b,c)", 2, "expected ')' before ',c)' in argument 1 of predicate 'streq'"),
    ("streq(a\\,b,a,b)", 2, "expected ')' before ',a,b)'"),
    ("streq(a, a)", 1, ""),
    ("streq( a ,a)", 1, ""),
    ("streq(,)", 0, ""),
    ("streq(,a)", 1, ""),
    ("streq($TESTVAR,1)", 1, ""),
    ("streq(${TESTVAR},1)", 1, ""),
    ("streq(\"$EMPTYV\",)", 0, ""),
    ("streq($SPC,\"a b\")", 1, ""),
    ("streq(a  b,a b)", 0, ""),
    ("streq(a\\ b,a b)", 0, ""),
    ("strneq(a,b)", 0, ""),
    ("strneq(a,a)", 1, ""),
    ("strstr(abc,b)", 0, ""),
    ("strstr(abc,z)", 1, ""),
    ("version_atleast( 3.0 )", 0, ""),
    ("version_before(1.0)", 1, ""),
    ("fips_mode()", 1, ""),
    ("fips_mode( )", 2, "expected ')' before ' )' in argument 0 of predicate 'fips_mode'"),
    ("feature(X,Y)", 2, "expected ')' before ',Y)' in argument 1 of predicate 'feature'"),
    ("feature (OPENSSL)", 2, "unexpected character '(' at the end"),
    ("feature(NOPE)", 1, ""),
    ("feature( OPENSSL )", 1, ""),
    ("streq(\\x41,A)", 0, ""),
    ("streq(\"\\x41\",A)", 0, ""),
    ("streq(\\xZZ,'')", 2, "Truncated or invalid hexadecimal sequence"),
    ("streq(\\x4,'')", 2, "Truncated or invalid hexadecimal sequence"),
    ("streq(\"\\t\",'\t')", 0, ""),
    ("streq(\"\\n\\r\",'')", 1, ""),
    ("streq(\\a,a)", 1, ""),
    ("streq(\\a,'\\a')", 0, ""),
    ("streq(\\\\,'\\')", 0, ""),
    ("streq(\"\\$TESTVAR\",'$TESTVAR')", 0, ""),
    ("streq(\"\\q\",'q')", 1, ""),
    ("streq(\"\\q\",'\\q')", 0, ""),
    ("streq(\"${TESTVAR}\",1)", 0, ""),
    ("streq(\"${TESTVAR-d}\",1)", 0, ""),
    ("streq(\"${NOPE-d}\",d)", 0, ""),
    ("streq(\"$\",'$')", 2, "Unhandled error in condition"),
    ("streq(\"${TESTVAR\",'')", 2, "Unhandled error in condition"),
    ("streq(\"$1\",'')", 2, "Unhandled error in condition"),
    ("streq(\"${\",'')", 2, "Unhandled error in condition"),
    ("streq('a,a)", 2, "Unmatched quote"),
    ("+1", 0, ""),
    ("(", 2, "unparsable conditional expression"),
    ("!(", 2, "unparsable conditional expression"),
    ("1\\", 2, ""),
];

#[test]
fn conditions_evaluate_as_haproxy_evaluates_them() {
    let mut bad = Vec::new();
    for (cond, want, msg) in CASES {
        let (code, err) = run(&["-cc", cond]);
        if code != Some(*want) || !err.contains(msg) {
            bad.push(format!("{cond:?}: want exit {want} with {msg:?}, got {code:?} {err:?}"));
        }
    }
    assert!(bad.is_empty(), "{} of {} differ:\n{}", bad.len(), CASES.len(), bad.join("\n"));
}

/// `HAProxy` reads the whole command line first and evaluates once: the last `-cc` wins,
/// and other options do not get in the way.
#[test]
fn the_condition_is_evaluated_after_the_command_line_is_read() {
    assert_eq!(run(&["-cc", "1", "-cc", "0"]).0, Some(1));
    assert_eq!(run(&["-cc", "0", "-cc", "1"]).0, Some(0));
    assert_eq!(run(&["-cc", "1", "-f", "/dev/null"]).0, Some(0));
    assert_eq!(run(&["-cc", "0", "-c", "-f", "/dev/null"]).0, Some(1));
}
