// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The edges of `.if` conditions (T146b): how deep `.if` blocks and a condition may nest, a
//! backslash escape in a predicate's argument, an unprintable byte in the line an error
//! shows, and an `.elif` that is never evaluated.
//!
//! Every expectation was measured on `HAProxy 3.5-dev8-885761-29` with `-c`:
//! `.if` nests 99 deep (the 100th is "too many nested '.if', max is 100"); a condition
//! gives up at 1024 levels of the parser's recursion, which is 341 parentheses or 1023
//! `||` / `&&`; `\t`, `\r` and `\n` written `\\t` in a quoted or bare argument are the
//! control character; the line an error prints turns each byte that is not graphic into `?`
//! and is cut at 76 characters.

use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

fn check(body: &[u8]) -> (bool, String) {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(body).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(f.path()).output().expect("run");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn nested(n: usize) -> String {
    ".if 1\n".repeat(n) + &".endif\n".repeat(n)
}

fn parens(n: usize) -> String {
    format!(".if {}1{}\n.endif\n", "(".repeat(n), ")".repeat(n))
}

fn chain(op: &str, n: usize) -> String {
    format!(".if {}\n.endif\n", vec!["1"; n].join(op))
}

#[test]
fn the_hundredth_nested_if_is_refused() {
    assert!(check(nested(99).as_bytes()).0, "99 nested .if are accepted");
    let (ok, err) = check(nested(100).as_bytes());
    assert!(!ok && err.contains(":100]") && err.contains("too many nested '.if', max is 100."), "{err}");
}

#[test]
fn a_condition_nested_too_deep_is_unparsable() {
    assert!(check(parens(340).as_bytes()).0);
    let (ok, err) = check(parens(341).as_bytes());
    assert!(!ok && err.contains("unparsable conditional sub-expression '1)))") && err.contains("in '.if' at position 342:"), "{err}");
    // Shifted by one `&&`, the 341st parenthesis is entered with no depth left for its `expr`.
    let shifted = |n: usize| format!(".if 1&&{}1{}\n.alert hit\n.endif\n", "(".repeat(n), ")".repeat(n));
    let (ok, err) = check(shifted(340).as_bytes());
    assert!(!ok && err.contains("'hit'."), "{err}");
    let (ok, err) = check(shifted(341).as_bytes());
    assert!(!ok && err.contains("unparsable conditional expression '1)))") && err.contains("in '.if' at position 345:"), "{err}");
    for op in ["||", "&&"] {
        assert!(check(chain(op, 1022).as_bytes()).0, "{op} x1022");
        let (ok, err) = check(chain(op, 1023).as_bytes());
        assert!(!ok && err.contains("unparsable conditional expression '1' in '.if' at position 3067:"), "{op} x1023: {err}");
        let (ok, err) = check(chain(op, 1024).as_bytes());
        assert!(!ok && err.contains(&format!("unparsable conditional expression '1{op}1' in '.if' at position 3067:")), "{op} x1024: {err}");
    }
}

#[test]
fn a_backslash_escape_in_an_argument_is_the_control_character() {
    // `.alert` fails the load only when the condition is true.
    let hit = |expr: &str| {
        let (ok, err) = check(format!(".if {expr}\n.alert hit\n.endif\n").as_bytes());
        !ok && err.contains("'hit'.")
    };
    assert!(hit("streq(a\\\\tb,\"a\tb\")"), "\\t");
    assert!(hit("streq(a\\\\rb,\"a\rb\")"), "\\r");
    assert!(hit("streq(a\\\\nb,\"a\\\\nb\")"), "\\n");
    assert!(hit("streq(a\\\\ b,\"a b\")"), "an escaped space");
    assert!(hit("streq(a\\\\\\\\b,a\\\\b)"), "an escaped backslash");
    assert!(hit("streq(a\\\\zb,a\\\\zb)"), "a lone backslash");
    // Quotes the tokenizer let through (`\"` and `\'` in the file): a quoted comma or space
    // does not end the argument, and the other kind of quote is an ordinary character.
    assert!(hit("streq(a\\\"b,c\\\",a\\\"b,c\\\")"), "double quotes");
    assert!(hit("streq(a\\\"b,c\\\",\\'ab,c\\')"), "a double-quoted comma against a single-quoted one");
    assert!(hit("streq(\\'a\\\"b,c\\',\\'a\\\"b,c\\')"), "a double quote inside single quotes");
    assert!(hit("streq(a\\\"b c\\\",\\'ab c\\')"), "a quoted space");
    assert!(!hit("streq(a\\'b,c\\',ab)"), "a single-quoted comma is part of the argument");
    assert!(!hit("streq(a,b)"), "different strings");
}

#[test]
fn the_line_an_error_prints_has_no_unprintable_byte_and_is_cut() {
    let (ok, err) = check(b".if \xc3\xa9\n.endif\n");
    assert!(!ok && err.contains("unparsable conditional expression '\u{e9}' in '.if' at position 1:\n  .if ??\n      ^"), "{err}");
    let (ok, err) = check(b".if 1 \x01\n.endif\n");
    assert!(!ok && err.contains("in '.if' at position 3:\n  .if 1 ?\n        ^"), "{err}");
    let (ok, err) = check(format!(".if 1 2 {}\n.endif\n", "x".repeat(120)).as_bytes());
    let shown = format!("  .if 1 2 {}\n        ^", "x".repeat(72));
    assert!(!ok && err.contains(&shown), "{err}");
    let printed = shown.lines().next().unwrap_or("");
    assert!(err.lines().any(|l| l == printed), "the line is cut at 76 characters: {err}");
}

#[test]
fn an_elif_after_a_taken_branch_is_not_evaluated() {
    assert!(check(b".if 1\n.elif 2garbage(\n.endif\n").0);
}
