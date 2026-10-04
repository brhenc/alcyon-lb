// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The regular expressions an operator writes in a configuration.
//!
//! `HAProxy` compiles them with PCRE2. Ibex is memory-safe Rust and links no C regex
//! library, so a pattern is compiled with the `regex` crate first (linear time, no
//! backtracking) and only when `regex` refuses it is it compiled with `fancy-regex`, which
//! adds what a PCRE has and `regex` does not: look-around, back-references, atomic groups,
//! possessive quantifiers and the like. An ordinary pattern therefore keeps `regex`'s
//! guarantee of matching in time linear in the input.
//!
//! A `fancy-regex` pattern can backtrack without bound, so it runs under
//! [`BACKTRACK_LIMIT`]: a match that exceeds it is a non-match, silently, as `HAProxy`'s
//! PCRE2 match limit makes it (measured: `^/(a+)+$` against `/aaaa...ab` answers "no match"
//! at once). Nothing is logged per request.

#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::fmt;

/// The most backtracking steps a `fancy-regex` match may take before it is given up as a
/// non-match. `fancy-regex`'s own default, written down here so that an upgrade of the
/// crate cannot change it: measured at about 15 ms per request for `^/(a+)+(?=$)` on a
/// debug build, whatever the length of the path.
pub const BACKTRACK_LIMIT: usize = 1_000_000;

/// What a pattern holds that `regex` would take for something else, or that nothing here
/// can run.
struct Scan {
    /// A possessive quantifier: `regex` would accept it as an ordinary repetition.
    pcre_only: bool,
    /// A PCRE feature `fancy-regex` lacks, which `regex` would misread or refuse unclearly.
    unsupported: Option<&'static str>,
}

/// Walks `pattern` outside character classes looking for [`Scan`]'s tokens.
fn scan(pattern: &str) -> Scan {
    let mut out = Scan { pcre_only: false, unsupported: None };
    let b = pattern.as_bytes();
    let mut i = 0;
    let mut prev = 0u8; // the previous unescaped byte outside a class
    while i < b.len() {
        let c = b[i];
        match c {
            b'\\' => {
                if matches!(b.get(i + 1), Some(b'Q')) {
                    out.unsupported.get_or_insert("the \\Q...\\E literal quoting");
                }
                if matches!(b.get(i + 1), Some(b'X')) {
                    out.unsupported.get_or_insert("the \\X extended grapheme cluster");
                }
                i += 2;
                prev = b'a';
                continue;
            }
            b'[' => {
                // A class: to its closing bracket, `]` first being a literal.
                i += 1;
                if b.get(i) == Some(&b'^') {
                    i += 1;
                }
                if b.get(i) == Some(&b']') {
                    i += 1;
                }
                while i < b.len() && b[i] != b']' {
                    if b[i] == b'\\' {
                        i += 1;
                    } else if b[i] == b'[' && b.get(i + 1) == Some(&b':') {
                        if let Some(end) = pattern[i..].find(":]") {
                            i += end + 1;
                        }
                    }
                    i += 1;
                }
                i += 1;
                prev = b'a';
                continue;
            }
            b'+' if matches!(prev, b'*' | b'+' | b'?' | b'}') => out.pcre_only = true,
            b'(' if b.get(i + 1) == Some(&b'?') => {
                let rest = &b[i + 2..];
                match rest.first() {
                    Some(b'R' | b'0'..=b'9' | b'&') => {
                        out.unsupported.get_or_insert("recursion and subroutine calls");
                    }
                    Some(b'+' | b'-') if rest.get(1).is_some_and(u8::is_ascii_digit) => {
                        out.unsupported.get_or_insert("recursion and subroutine calls");
                    }
                    Some(b'P') if rest.get(1) == Some(&b'>') => {
                        out.unsupported.get_or_insert("recursion and subroutine calls");
                    }
                    Some(b'C') => {
                        out.unsupported.get_or_insert("callouts");
                    }
                    Some(b'|') => {
                        out.unsupported.get_or_insert("branch reset groups");
                    }
                    _ => {}
                }
                // The `?` of `(?` is not a quantifier.
                i += 2;
                prev = b'a';
                continue;
            }
            _ => {}
        }
        prev = c;
        i += 1;
    }
    out
}

/// A regular expression from the configuration.
#[derive(Clone)]
pub enum UserRegex {
    /// Compiled by `regex`: matches in time linear in the input.
    Linear(regex::Regex),
    /// Compiled by `fancy-regex`: the pattern uses a PCRE-only feature, and a match is
    /// bounded by [`BACKTRACK_LIMIT`].
    Backtracking(fancy_regex::Regex),
}

impl fmt::Debug for UserRegex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UserRegex({})", self.as_str())
    }
}

/// Why a pattern was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// The groups of one match.
pub enum Captures<'h> {
    Linear(regex::Captures<'h>),
    Backtracking(fancy_regex::Captures<'h, str>),
}

impl<'h> Captures<'h> {
    /// Group `i` (0 is the whole match), or `None` for a group that did not take part.
    #[must_use]
    pub fn get(&self, i: usize) -> Option<&'h str> {
        match self {
            Captures::Linear(c) => c.get(i).map(|m| m.as_str()),
            Captures::Backtracking(c) => c.get(i).map(|m| m.as_str()),
        }
    }

    /// The number of groups, the whole match included.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Captures::Linear(c) => c.len(),
            Captures::Backtracking(c) => c.len(),
        }
    }

    /// Never: the whole match is always there.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Appends `replacement` to `dst` with `$1`, `${1}` and `$name` expanded.
    pub fn expand(&self, replacement: &str, dst: &mut String) {
        match self {
            Captures::Linear(c) => c.expand(replacement, dst),
            Captures::Backtracking(c) => c.expand(replacement, dst),
        }
    }
}

impl UserRegex {
    /// Compiles `pattern`: with `regex`, and with `fancy-regex` only if `regex` refuses it.
    ///
    /// # Errors
    /// The reason, when neither can compile it (a syntax error, or a PCRE feature
    /// `fancy-regex` does not have).
    pub fn new(pattern: &str) -> Result<Self, Error> {
        Self::with_case(pattern, false)
    }

    /// As [`UserRegex::new`], matching without regard to case if `case_insensitive`.
    ///
    /// # Errors
    /// As [`UserRegex::new`].
    pub fn with_case(pattern: &str, case_insensitive: bool) -> Result<Self, Error> {
        let scan = scan(pattern);
        if let Some(what) = scan.unsupported {
            return Err(Error(format!("PCRE feature not supported by Ibex: {what} (see docs/differences.md)")));
        }
        // `regex` reads `a++` as `(a+)+` and `(?R)` as a flag, and so would accept what it
        // does not mean: a pattern with such a token goes to `fancy-regex` directly.
        if !scan.pcre_only {
            if let Ok(re) = regex::RegexBuilder::new(pattern).case_insensitive(case_insensitive).build() {
                return Ok(UserRegex::Linear(re));
            }
        }
        fancy_regex::RegexBuilder::new(pattern)
            .case_insensitive(case_insensitive)
            .backtrack_limit(BACKTRACK_LIMIT)
            .build()
            .map(UserRegex::Backtracking)
            // `fancy-regex` parses a superset of what `regex` does, so its message is the one
            // that says what is wrong with the pattern (`regex`'s would say that look-around
            // is not supported, of a pattern that fails for another reason).
            .map_err(|e| Error(e.to_string()))
    }

    /// The pattern.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            UserRegex::Linear(r) => r.as_str(),
            UserRegex::Backtracking(r) => r.as_str(),
        }
    }

    /// Whether this pattern needed `fancy-regex`.
    #[must_use]
    pub fn is_backtracking(&self) -> bool {
        matches!(self, UserRegex::Backtracking(_))
    }

    /// Whether `text` matches. A match that exceeds [`BACKTRACK_LIMIT`] does not.
    #[must_use]
    pub fn is_match(&self, text: &str) -> bool {
        match self {
            UserRegex::Linear(r) => r.is_match(text),
            UserRegex::Backtracking(r) => r.is_match(text).unwrap_or(false),
        }
    }

    /// The groups of the first match in `text`. A match that exceeds [`BACKTRACK_LIMIT`]
    /// is none.
    #[must_use]
    pub fn captures<'h>(&self, text: &'h str) -> Option<Captures<'h>> {
        match self {
            UserRegex::Linear(r) => r.captures(text).map(Captures::Linear),
            UserRegex::Backtracking(r) => r.captures(text).ok().flatten().map(Captures::Backtracking),
        }
    }

    /// `text` with the first match replaced by `replacement` (`$1`, `${1}`, `$name`; `$$`
    /// for a dollar). `text` itself when there is none.
    #[must_use]
    pub fn replace<'h>(&self, text: &'h str, replacement: &str) -> Cow<'h, str> {
        self.replacen(text, replacement, 1)
    }

    /// As [`UserRegex::replace`], for every match.
    #[must_use]
    pub fn replace_all<'h>(&self, text: &'h str, replacement: &str) -> Cow<'h, str> {
        self.replacen(text, replacement, usize::MAX)
    }

    fn replacen<'h>(&self, text: &'h str, replacement: &str, limit: usize) -> Cow<'h, str> {
        match self {
            UserRegex::Linear(r) => {
                if limit == 1 {
                    r.replace(text, replacement)
                } else {
                    r.replace_all(text, replacement)
                }
            }
            UserRegex::Backtracking(r) => {
                let mut out = String::new();
                let mut last = 0;
                let mut pos = 0;
                let mut n = 0;
                while n < limit && pos <= text.len() {
                    let Ok(Some(caps)) = r.captures_from_pos(text, pos) else { break };
                    let Some(m) = caps.get(0) else { break };
                    out.push_str(&text[last..m.start()]);
                    caps.expand(replacement, &mut out);
                    last = m.end();
                    n += 1;
                    pos = if m.end() == m.start() {
                        // An empty match: copy one character and go on after it.
                        match text[m.end()..].chars().next() {
                            Some(c) => {
                                out.push(c);
                                last = m.end() + c.len_utf8();
                                last
                            }
                            None => break,
                        }
                    } else {
                        m.end()
                    };
                }
                if n == 0 {
                    return Cow::Borrowed(text);
                }
                out.push_str(&text[last.min(text.len())..]);
                Cow::Owned(out)
            }
        }
    }

    /// `text` with every character that is special in a pattern escaped.
    #[must_use]
    pub fn escape(text: &str) -> String {
        regex::escape(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_pattern_is_linear() {
        let re = UserRegex::new("^/a+b$").unwrap();
        assert!(!re.is_backtracking());
        assert!(re.is_match("/aab"));
    }

    #[test]
    fn a_pcre_only_pattern_is_backtracking() {
        for p in ["a(?=b)", "(?<=a)b", r"(a)\1", "a++", "(?>a+)b"] {
            assert!(UserRegex::new(p).unwrap().is_backtracking(), "{p}");
        }
    }

    #[test]
    fn a_possessive_quantifier_is_possessive() {
        let re = UserRegex::new("^a++a").unwrap();
        assert!(!re.is_match("aaa"));
        assert!(UserRegex::new("^a+a").unwrap().is_match("aaa"));
        assert!(!UserRegex::new("^[+]++b").unwrap().is_backtracking() || UserRegex::new("^[+]++b").unwrap().is_match("+++b"));
        // a `+` after the `?` of `(?` or after an escaped quantifier is not possessive
        assert!(!UserRegex::new(r"(?i)a\++").unwrap().is_backtracking());
    }

    #[test]
    fn what_fancy_regex_lacks_is_refused_with_a_reason() {
        for p in ["(?R)", "(a)(?1)", r"\X", r"\Qa\E", "(?C)a", "(?|(a)|(b))"] {
            let e = UserRegex::new(p).unwrap_err().to_string();
            assert!(e.contains("not supported"), "{p}: {e}");
        }
    }

    #[test]
    fn classes_are_skipped_when_looking_for_possessive_quantifiers() {
        // a `+` inside or right after an escaped bracket of a class is not possessive
        for p in [r"[\]+]+x", "[]+]+x", "[^]+]+x", "[[:alpha:]+]+x", "[+*]"] {
            assert!(!UserRegex::new(p).unwrap().is_backtracking(), "{p}");
        }
        for p in ["[a]++b", "[[:alpha:]]++b", "[^]a]*+b", r"[\]]++b", r"\++"] {
            assert!(UserRegex::new(p).unwrap().is_backtracking() || p == r"\++", "{p}");
        }
    }

    #[test]
    fn every_recursion_spelling_is_refused() {
        for p in ["(?0)", "(?+1)", "(?-1)", "(?&n)", "(?P>n)", "a(?R)"] {
            let e = UserRegex::new(p).unwrap_err().to_string();
            assert!(e.contains("recursion"), "{p}: {e}");
        }
    }

    #[test]
    fn captures_and_replacements_through_both_engines() {
        for (p, linear) in [(r"(\w)(\d)", true), (r"(\w)(?=\d)(\d)?", false)] {
            let re = UserRegex::new(p).unwrap();
            assert_eq!(re.is_backtracking(), !linear, "{p}");
            assert_eq!(re.as_str(), p);
            assert!(format!("{re:?}").contains(p));
            let caps = re.captures("-a1-").unwrap();
            assert_eq!((caps.get(0), caps.get(1), caps.get(2)), (Some("a1"), Some("a"), Some("1")), "{p}");
            assert_eq!(caps.len(), 3);
            assert!(!caps.is_empty());
            let mut out = String::new();
            caps.expand("$2$1", &mut out);
            assert_eq!(out, "1a");
            assert!(re.captures("--").is_none());
            assert_eq!(re.replace("--", "x"), "--");
            assert_eq!(re.replace("a1b2", "<$1>"), "<a>b2");
            assert_eq!(re.replace_all("a1b2", "<$1>"), "<a><b>");
        }
    }

    #[test]
    fn case_insensitive_and_errors() {
        assert!(UserRegex::with_case("ab", true).unwrap().is_match("AB"));
        assert!(UserRegex::with_case("(?<=a)b", true).unwrap().is_match("AB"));
        let e = UserRegex::new("(a)(?<=a)\\2").unwrap_err();
        assert!(!e.to_string().is_empty());
        assert_eq!(e.clone(), e);
    }

    #[test]
    fn a_syntax_error_is_an_error() {
        assert!(UserRegex::new("(").is_err());
    }

    #[test]
    fn a_catastrophic_pattern_is_no_match() {
        let re = UserRegex::new("^(a+)+$").unwrap();
        let text = format!("{}b", "a".repeat(64));
        assert!(!re.is_match(&text));
    }

    #[test]
    fn replace_with_a_back_reference() {
        let re = UserRegex::new(r"(a)b\1").unwrap();
        assert_eq!(re.replace("xaba", "[$1]"), "x[a]");
        assert_eq!(re.replace_all("abaXaba", "-"), "-X-");
        assert_eq!(UserRegex::new("(?=a)").unwrap().replace_all("aa", "-"), "-a-a");
        assert_eq!(UserRegex::new("(?=)").unwrap().replace_all("ab", "-"), "-a-b-");
        assert_eq!(UserRegex::new("(?=)").unwrap().replace_all("", "-"), "-");
    }
}
