// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! How the arguments of a sample fetch or converter are cut into words (T341): HAProxy's
//! `make_arg_list` (src/arg.c). Blanks are kept, a quote toggles quoting wherever it is in
//! the argument and is dropped, and outside single quotes a backslash escapes `\`, a blank,
//! `"` and `'`, and makes `\r`, `\n`, `\t` the control characters; before anything else it
//! stays. An unquoted `,` or `)` ends the argument; parentheses do not nest.
//!
//! Before this, Alcyon trimmed every argument but `str`'s and kept quotes inside an argument,
//! so `jwt_verify(HS256, secret)` checked the key `secret` where HAProxy checks ` secret`:
//! a token signed with one key verified on one proxy and not on the other.
//!
//! Measured against HAProxy 3.5-dev8-885761-29, 2026-10-17, with
//! `http-request return status 200 content-type text/plain lf-string "[%[<expr>]]"` (the
//! expressions below are the text after the configuration's own unquoting):
//!
//! * `str( a b )` `[ a b ]`; `str(a),concat( x ,txn.v)` `[a x ]` (txn.v unset);
//!   `str(abc),regsub(b, X )` `[a X c]`; `str(abc),regsub( b,X)` `[abc]` (no ` b` in it)
//! * `str('a b'c)` `[a bc]`; `str(x'a)b'y)` `[xa)by]`; `str('a,b')` `[a,b]`
//! * `str(a\ b)` `[a b]`; `str(a\\b)` `[a\b]`; `str(a\qb)` `[a\qb]`; `str('a\\b')` `[a\\b]`;
//!   `str(a\'b)` `[a'b]`; `str(a\"b)` `[a"b]`
//! * `str(a\tb),hex` `[610962]`; `str(a\nb),hex` `[610A62]`; `str('a\tb'),hex` `[615C7462]`
//! * `str(a),concat(x,,y)` `[axy]`; `str()` `[]`; `str( )` `[ ]`
//! * `req.hdr(t),jwt_verify(HS256, secret)`: 1 for a token signed with ` secret`, 0 for one
//!   signed with `secret`
//! * refused: `str(a` "fetch method 'str' : expected ')'."; `str('a)` the same;
//!   `str(a),concat(b` "invalid arg 2 in converter 'concat' : expected ')'.";
//!   `str(a)x` "missing comma after fetch keyword."; `str(a),concat(b)y` "missing comma
//!   after converter 'concat'."; `str(1),add(var(txn.x))` refused (parentheses do not nest).

use alcyon_sample::expr::Expr;

fn args(expr: &str) -> Vec<Vec<String>> {
    let e = Expr::parse(expr).unwrap_or_else(|err| panic!("`{expr}` must parse: {err}"));
    let mut all = vec![e.fetch_args.clone()];
    all.extend(e.converters.iter().map(|(_, a)| a.clone()));
    all
}

fn v(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| (*w).to_string()).collect()
}

#[test]
fn blanks_in_an_argument_are_kept() {
    assert_eq!(args("str( a b )"), vec![v(&[" a b "])]);
    assert_eq!(args("str(a),concat( x ,txn.v)"), vec![v(&["a"]), v(&[" x ", "txn.v"])]);
    assert_eq!(args("str(abc),regsub(b, X )"), vec![v(&["abc"]), v(&["b", " X "])]);
    assert_eq!(args("str(abc),regsub( b,X)"), vec![v(&["abc"]), v(&[" b", "X"])]);
    assert_eq!(args("req.hdr(t),jwt_verify(HS256, secret)"), vec![v(&["t"]), v(&["HS256", " secret"])]);
    assert_eq!(args("str( )"), vec![v(&[" "])]);
}

#[test]
fn quotes_anywhere_in_an_argument_are_dropped() {
    assert_eq!(args("str('a b'c)"), vec![v(&["a bc"])]);
    assert_eq!(args("str(x'a)b'y)"), vec![v(&["xa)by"])]);
    assert_eq!(args("str('a,b')"), vec![v(&["a,b"])]);
    assert_eq!(args("str(\"a'b\")"), vec![v(&["a'b"])]);
}

#[test]
fn backslash_escapes_outside_single_quotes() {
    assert_eq!(args(r"str(a\ b)"), vec![v(&["a b"])]);
    assert_eq!(args(r"str(a\\b)"), vec![v(&[r"a\b"])]);
    assert_eq!(args(r"str(a\qb)"), vec![v(&[r"a\qb"])]);
    assert_eq!(args(r"str('a\\b')"), vec![v(&[r"a\\b"])]);
    assert_eq!(args(r"str(a\'b)"), vec![v(&["a'b"])]);
    assert_eq!(args(r#"str(a\"b)"#), vec![v(&["a\"b"])]);
    assert_eq!(args(r"str(a\tb)"), vec![v(&["a\tb"])]);
    assert_eq!(args(r"str(a\nb)"), vec![v(&["a\nb"])]);
    assert_eq!(args(r"str(a\rb)"), vec![v(&["a\rb"])]);
    assert_eq!(args(r"str('a\tb')"), vec![v(&[r"a\tb"])]);
    assert_eq!(args(r#"str("a\tb")"#), vec![v(&["a\tb"])]);
}

#[test]
fn empty_arguments() {
    assert_eq!(args("str(a),concat(x,,y)"), vec![v(&["a"]), v(&["x", "", "y"])]);
    assert_eq!(args("str()"), vec![v(&[])]);
}

#[test]
fn unclosed_arguments_and_trailing_text_are_refused() {
    let refused: &[(&str, &str)] = &[
        ("str(a", "fetch method 'str' : expected ')'"),
        ("str('a)", "fetch method 'str' : expected ')'"),
        ("str(a),concat(b", "invalid arg 2 in converter 'concat' : expected ')'"),
        ("str(a)x", "missing comma after fetch keyword"),
        ("str(a),concat(b)y", "missing comma after converter 'concat'"),
    ];
    for (expr, text) in refused {
        match Expr::parse(expr) {
            Ok(_) => panic!("`{expr}` must be refused"),
            Err(e) => assert!(e.contains(text), "`{expr}`: expected {text:?} in {e:?}"),
        }
    }
    assert!(Expr::parse("str(1),add(var(txn.x))").is_err(), "parentheses do not nest in an argument");
}
