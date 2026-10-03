// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use ibex_config::lexer::lex;
use ibex_config::preproc::preprocess;

#[test]
fn test_preproc() {
    let input = "
.if feature(THREAD)
  global
    thread-groups 1
.endif
";
    let lines = lex(input);
    let out = preprocess(lines).unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].tokens[0].text, "global");
    assert_eq!(out[1].tokens[0].text, "thread-groups");
}

#[test]
fn test_preproc_else() {
    let input = "
.if feature(UNKNOWN)
  global
    thread-groups 1
.else
  global
    thread-groups 2
.endif
";
    let lines = lex(input);
    let out = preprocess(lines).unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].tokens[0].text, "global");
    assert_eq!(out[1].tokens[0].text, "thread-groups");
    assert_eq!(out[1].tokens[1].text, "2");
}

#[test]
fn test_preproc_elif() {
    let input = "
.if feature(UNKNOWN)
  a
.elif feature(THREAD)
  b
.else
  c
.endif
";
    let lines = lex(input);
    let out = preprocess(lines).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].tokens[0].text, "b");
}

#[test]
fn test_preproc_nested() {
    let input = "
.if feature(THREAD)
  .if !feature(OPENSSL)
    a
  .endif
.endif
";
    let lines = lex(input);
    let out = preprocess(lines).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].tokens[0].text, "a");
}

#[test]
fn test_preproc_unterminated() {
    let input = ".if feature(THREAD)\n a";
    let lines = lex(input);
    let err = preprocess(lines).unwrap_err();
    assert_eq!(err.message, "non-terminated '.if' block.");
}

#[test]
fn test_preproc_unknown_predicate() {
    let input = ".if UNKNOWN(A)\n a\n.endif";
    let lines = lex(input);
    let err = preprocess(lines).unwrap_err();
    assert!(err.message.contains("unparsable"));
}


#[test]
fn test_balance_rr() {
    let input = "
    global
    .if feature(THREAD)
        thread-groups 1
    .endif
    defaults
        mode http
";
    let lines = lex(input);
    for line in &lines {
        println!("{:?}", line.tokens.iter().map(|t| &t.text).collect::<Vec<_>>());
    }
    preprocess(lines).unwrap();
}
