// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T316: the backtracking limit bounds a rule evaluation, not each search of it.
//!
//! `fancy-regex` counts backtracks per `run` (one search, all its start positions), so a
//! `replace_all` that searches again after each match paid the limit again at every match.
//! PCRE2 (`HAProxy` 3.5-dev8, no JIT) does the same per `pcre2_match` (default `match_limit`
//! 10 000 000), but `replace-header`/`replace-path` do a single match per value: only the
//! `regsub(...,g)` converter loops. Alcyon's loop shares one budget of
//! [`alcyon_regex::BACKTRACK_LIMIT`] steps; when it runs out the text is left unchanged.

use std::time::{Duration, Instant};

use alcyon_regex::UserRegex;

/// `(a*)*\1c|a` over `a`^16 `b` segments: every search costs about 16 ms (release) yet
/// finds its match (the `a` alternative) before the limit, so the old loop ran to the end.
const SLOW_PER_SEARCH: &str = r"(a*)*\1c|a";

fn segments(n: usize) -> String {
    format!("{}b", "a".repeat(16)).repeat(n)
}

/// The fuzz artifact `timeout-f1aa0b4d` (pattern; NULs of the text replaced by `x`, which a
/// header cannot carry), 180 bytes: 0.53 s in `replace_all` before T316.
const ARTIFACT_PATTERN: &str = "..+.+..+pjpP.\x0bk?+!.|m??mm\x0bmm|.?\x0b?m.@|\x01.fk?+!|.?Y\x0b?m.?\x0b?m!|.m??mm\x0bmm|.?\x0b?m.@|\x01.fk?+!|.+..+pjpP.\x0bk?+!.|m??mm\x0bmm|.?\x0b?m.@|\x01.fk?+!|.?Y\x0b?m.?\x0b?m!|.m??mm\x0bmm|.?\x0b?m.@|\x01.fk?+!|.?Y\x0b|\x01.fk?+!|.?Y\x0b?m.?\x0b?mmmmm|.?\x0b?m.mm|.?\x0b?";
const ARTIFACT_TEXT: &str = "xxxxxx\x08?+!|.?Y\x0bm\x0bmm|.?\x0b?m.@|\x01.fk?+!|.?Y\x0b?m.?\x0b?mmmmm|.?\x0b?\x0b?mmmmm|.?\x0b??Y\x0b|\x01.fk?+!|.?Y\x0b?m.?\x0b?mmmmm|.?\x0b?m.mm|.?\x0b?m.@|\x01.fk?+!|.?Y\x0bm\x0bmm|.?\x0b?m.@|\x01.fk?+!|.?Y\x0b?m.:\x0b?mmmmm|.?\x0b?\x0b?mmmmm|.?\x0b?m.";

#[test]
fn replace_all_shares_one_budget_across_its_searches() {
    let re = UserRegex::new(SLOW_PER_SEARCH).unwrap();
    assert!(re.is_backtracking());
    let text = segments(480); // 8 160 bytes
    let t0 = Instant::now();
    let out = re.replace_all(&text, "<$0>");
    let took = t0.elapsed();
    assert_eq!(out, text, "a budget that ran out leaves the text unchanged");
    assert!(took < Duration::from_secs(5), "replace_all took {took:?}");
}

#[test]
fn a_cheap_backtracking_replace_all_still_replaces_every_match() {
    // Look-behind sends the pattern to `fancy-regex`; each search costs a few steps.
    let re = UserRegex::new(r"(?<=a)b").unwrap();
    assert!(re.is_backtracking());
    let text = "ab".repeat(4000);
    assert_eq!(re.replace_all(&text, "X"), "aX".repeat(4000));
}

#[test]
fn the_artifact_pattern_is_bounded_on_a_header_sized_text() {
    let re = UserRegex::new(ARTIFACT_PATTERN).unwrap();
    for text in [ARTIFACT_TEXT.to_string(), format!("{ARTIFACT_TEXT} /index.html HTTP/1.1 abc").repeat(45)] {
        let t0 = Instant::now();
        let _ = re.replace_all(&text, "<$0>");
        let _ = re.captures(&text);
        let took = t0.elapsed();
        assert!(took < Duration::from_secs(5), "{} bytes took {took:?}", text.len());
    }
}

#[test]
fn nested_quantifier_still_no_match_for_a_single_search() {
    let re = UserRegex::new(r"^/(a+)+$").unwrap();
    assert!(!re.is_match(&format!("/{}!", "a".repeat(40))));
    let re = UserRegex::new(r"(a*)*\1c").unwrap();
    assert!(!re.is_match(&segments(1)));
}
