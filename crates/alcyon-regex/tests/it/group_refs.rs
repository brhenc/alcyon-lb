// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! References to capture groups that do not exist (T277, V&V VV-3).
//!
//! `fancy-regex` 0.19.2 compiles a conditional on a group number the pattern does not have,
//! `(?(2))`, and its matcher then indexes past the end of its slot array: a panic, and Alcyon
//! aborts the whole process. PCRE2 refuses such a pattern ("reference to non-existent
//! subpattern"), so `HAProxy` refuses the configuration. Measured with `haproxy -c` (3.5-dev8)
//! on `http-request replace-path <pattern> x`, where groups capture:
//!
//! * refused: `(?(2))`, `(?(2)a|b)`, `(a)(?(2)x)`, `(?(1)a|b)`, `(?(0)a)`, `(?(-1)a)`,
//!   `(?(n)b)`, `(?(R1)a)`, `(?(R&n)a)`, `(a)\2`, `\g{2}`, `(a)\g2`, `\k{x}`, `(?P=name)`
//! * accepted: `(a)(?(1)x)`, `(?(1)a)(b)`, `(?(+1)a)(b)`, `(a)(?(-1)x)`, `(a)\1`,
//!   `(?P<n>a)(?(n)b)`, `(?(<n>)b)(?<n>a)`, `(?(DEFINE)a)`, `(?(R)a)`

use alcyon_regex::UserRegex;

const NONEXISTENT: &str = "reference to non-existent subpattern";

#[test]
fn conditional_on_a_missing_group_is_refused() {
    for p in [
        "(?(2))",
        "(?(2)a|b)",
        "(?(1))",
        "(?(1)a|b)",
        "(a)(?(2)x)",
        "(?(0)a)",
        "(?(-1)a)",
        "(?(+5)a)(b)",
        "(?(3)(a)(b))",
        "(?(<1>)a)",
        "(?('2')a)",
        "(?(n)b)",
        "x(?(2)a|b)y",
        "(?i)(?(2)a)",
    ] {
        let err = UserRegex::new(p).expect_err(p).to_string();
        assert!(err.contains(NONEXISTENT), "`{p}`: {err}");
        let err = UserRegex::with_case(p, true).expect_err(p).to_string();
        assert!(err.contains(NONEXISTENT), "`{p}` (case-insensitive): {err}");
    }
}

#[test]
fn backreference_to_a_missing_group_is_refused() {
    for p in ["(a)\\2", "\\1", "(a)\\k<2>", "\\k<x>", "(?P=name)"] {
        assert!(UserRegex::new(p).is_err(), "`{p}` must be refused");
    }
}

#[test]
fn recursion_conditions_are_refused_as_unsupported() {
    // PCRE2 reads `(?(R...)` as "inside a recursion"; `fancy-regex` reads it as a condition
    // that the literal text matches. Alcyon refuses recursion already.
    for p in ["(?(R)a)", "(?(R1)a)", "(?(R&n)a)", "(?(VERSION>=10)a)"] {
        let err = UserRegex::new(p).expect_err(p).to_string();
        assert!(err.contains("not supported by Alcyon"), "`{p}`: {err}");
    }
}

#[test]
fn conditional_on_a_bare_group_name_is_refused_rather_than_misread() {
    // PCRE2 reads `(?(n)` as "group n is set"; `fancy-regex` as "the text `n` matches here".
    let err = UserRegex::new("(?P<n>a)(?(n)b)").expect_err("bare name").to_string();
    assert!(err.contains("(?(<n>)"), "{err}");
}

#[test]
fn conditional_on_an_existing_group_still_compiles_and_matches() {
    for (p, yes, no) in [
        ("^(a)?(?(1)x|y)$", "ax", "ay"),
        ("(?(1)a|b)(c)", "bc", "ac"),
        ("(?(+1)a|b)(c)", "bc", "ac"),
        ("(c)(?(-1)x|y)", "cx", "cy"),
        ("^(?<n>a)?(?(<n>)b|c)$", "ab", "a"),
        ("^(?<n>a)?(?('n')b|c)$", "c", "b"),
        ("(?(DEFINE)(a))(?(1)b|c)", "c", "zzz"),
        ("(a)\\1", "aa", "ab"),
    ] {
        let re = UserRegex::new(p).unwrap_or_else(|e| panic!("`{p}`: {e}"));
        assert!(re.is_match(yes), "`{p}` must match {yes:?}");
        assert!(!re.is_match(no), "`{p}` must not match {no:?}");
    }
}

#[test]
fn a_refused_pattern_is_never_matched() {
    // The crash itself: before the fix these compiled, and the match panicked.
    for p in ["(?(2))", "(?(+5)a)(b)", "(?('2')a)"] {
        if let Ok(re) = UserRegex::new(p) {
            let _ = re.is_match("/abc");
            panic!("`{p}` compiled and was matched");
        }
    }
}
