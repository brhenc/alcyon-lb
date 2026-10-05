// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! What `.if`, `.elif`, `.else` and `.endif` say when they are wrong (T146 item 21).
//!
//! Every text was measured on `HAProxy 3.5-dev8-885761-29` with `-c`, after the
//! "parsing [file:line]: " it starts with; the one for a bad condition ends with the position
//! of the byte the parser stopped at, the line, and a caret under it (`src/cfgparse.c` and
//! `src/cfgcond.c` read for the rest). A line longer than 76 characters (74 for `.elif`) is
//! cut around the position.

use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

fn stderr_of(body: &str) -> (bool, String) {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(body.as_bytes()).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn a_bad_condition_names_the_position_and_shows_it() {
    let cases: &[(&str, &str)] = &[
        (".if foo(bar)\n.endif\n", "unparsable conditional expression 'foo(bar)' in '.if' at position 1:\n  .if foo(bar)\n      ^"),
        (
            ".if feature(\n.endif\n",
            "expected ')' in argument 1 of predicate 'feature' used in conditional expression in '.if' at position 9:\n  .if feature(\n              ^",
        ),
        (
            ".if 1 +\n.endif\n",
            "unexpected character '+' at the end of conditional expression '1 +' in '.if' at position 3:\n  .if 1 +\n        ^",
        ),
        (".if (1\n.endif\n", "expected ')' after conditional expression '(1' in '.if' at position 1:\n  .if (1\n      ^"),
        (
            ".if 1 2\n.endif\n",
            "unexpected character '2' at the end of conditional expression '1 2' in '.if' at position 3:\n  .if 1 2\n        ^",
        ),
        (
            ".if streq(a)\n.endif\n",
            "missing arguments (got 1/2), type 'string' expected in argument 1 of predicate 'streq' used in conditional expression in '.if' at position 8:\n  .if streq(a)\n             ^",
        ),
        (".if !\n.endif\n", "unparsable conditional expression '!' in '.if' at position 1:\n  .if !\n      ^"),
        (".if 1 &&\n.endif\n", "unparsable conditional expression '&&' in '.if' at position 3:\n  .if 1 &&\n        ^"),
        (".if 1 ||| 2\n.endif\n", "unparsable conditional expression '| 2' in '.if' at position 5:\n  .if 1 ||| 2\n          ^"),
        (
            ".if 0\n.elif foo(bar)\n.endif\n",
            "unparsable conditional expression 'foo(bar)' in '.elif' at position 1:\n  .elif foo(bar)\n        ^",
        ),
        (
            ".if 0\n.elif 1 2\n.endif\n",
            "unexpected character '2' at the end of conditional expression '1 2' in '.elif' at position 3:\n  .elif 1 2\n          ^",
        ),
        (
            ".if 1 && feature(AAAAAAAAAA) && feature(BBBBBBBBBB) && feature(CCCCCCCCCCC) && feature(DDDDDDDDDD) && foo(x)\n.endif\n",
            "unparsable conditional expression 'foo(x)' in '.if' at position 99:\n  .if ...CCCCCCC) && feature(DDDDDDDDDD) && foo(x)...\n                                            ^",
        ),
        (
            ".if feature(AAAAAAAAAA) && feature(BBBBBBBBBB) && feature(CCCCCCCCCCC) && feature(DDDDDDDDDD) && feature(EEEEEEEEEEEEEE) && foo(x) || 1\n.endif\n",
            "unparsable conditional expression 'foo(x) || 1' in '.if' at position 121:\n  .if ...DDD) && feature(EEEEEEEEEEEEEE) && foo(x) || 1...\n                                            ^",
        ),
    ];
    let mut wrong = Vec::new();
    for (body, want) in cases {
        let (ok, err) = stderr_of(body);
        if ok || !err.contains(want) {
            wrong.push(format!("{body:?}: loaded={ok}\n  wanted {want:?}\n  stderr {err:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_structure_of_the_blocks_is_checked_as_haproxy_checks_it() {
    let cases: &[(&str, &str)] = &[
        (".elif 1\n", "lone '.elif' with no matching '.if'."),
        (".else\n", "lone '.else' with no matching '.if'."),
        (".endif\n", "lone '.endif' with no matching '.if'."),
        (".if 1\n", "non-terminated '.if' block."),
        (".if 1\n.else\n.else\n.endif\n", "'.else' after '.else' is not permitted."),
        (".if 1\n.else\n.elif 1\n.endif\n", "'.elif' after '.else' is not permitted."),
        (".if 1\n.else x\n.endif\n", "Unexpected argument 'x' for '.else'."),
        (".if 1\n.endif x\n", "Unexpected argument 'x' for '.endif'."),
        (".foo\n", "unknown directive '.foo'."),
        (".diag a b\n", "Unexpected argument 'b' for '.diag'. Use quotes if the message should contain spaces."),
    ];
    let mut wrong = Vec::new();
    for (body, want) in cases {
        let (ok, err) = stderr_of(body);
        if ok || !err.contains(want) {
            wrong.push(format!("{body:?}: loaded={ok}, wanted {want:?}, stderr {err:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    // Nothing in a block that is not taken is looked at (the nested `.if` has a bad condition).
    let (ok, err) = stderr_of(".if 0\n.if foo(\n.else\n.endif\n.elif 1\n.endif\n");
    assert!(ok, "{err}");
    // `.if` with nothing after it is false, as before.
    let (ok, err) = stderr_of(".if\n.endif\n");
    assert!(ok, "{err}");
}
