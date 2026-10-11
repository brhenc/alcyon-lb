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
                // `fancy-regex` compiles every `\\g<n>`, `\\g'n'` and `\\gN` as a subroutine call,
                // inlined: two `\\g0` took gigabytes (T242). PCRE2 reads the first two as
                // recursion, refused here as `(?R)` is.
                if b.get(i + 1) == Some(&b'g') && b.get(i + 2).is_some_and(|c| matches!(c, b'<' | b'\'' | b'0'..=b'9')) {
                    out.unsupported.get_or_insert("recursion and subroutine calls");
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

/// PCRE2's text for a reference to a group the pattern does not have.
const NONEXISTENT_GROUP: &str = "reference to non-existent subpattern";

/// Refuses the conditionals `fancy-regex` compiles but cannot run, or runs with another
/// meaning than PCRE2's (T277).
///
/// `fancy-regex` 0.19.2 checks that a back-reference names a group the pattern has, but not
/// a conditional: `(?(2))` compiles, and the first match indexes past the end of the
/// matcher's slots, a panic that aborts the process. PCRE2 refuses it ("reference to
/// non-existent subpattern"), as it does `(?(0)...)`.
///
/// A condition that is not a group reference, `(?(n)...)`, `(?(R)...)`, `(?(VERSION>=10)...)`,
/// is to `fancy-regex` a pattern that must match there; to PCRE2 a test on group `n`, on
/// recursion or on its version. Refused rather than run with the other meaning.
fn check_conditions(pattern: &str, captures_len: usize) -> Result<(), Error> {
    use fancy_regex::Expr;
    // It has just compiled, so it parses.
    let tree = Expr::parse_tree(pattern).map_err(|e| Error::from_fancy(&e))?;
    let mut stack = vec![&tree.expr];
    while let Some(e) = stack.pop() {
        match e {
            Expr::BackrefExistsCondition { group, .. }
            | Expr::Backref { group, .. }
                if *group == 0 || *group >= captures_len =>
            {
                return Err(Error(NONEXISTENT_GROUP.to_string(), None));
            }
            Expr::Conditional { condition, .. } if !matches!(**condition, Expr::BackrefExistsCondition { .. }) => {
                let text = literal_text(condition).unwrap_or_default();
                if text.starts_with('R') || text.starts_with("VERSION") {
                    return Err(Error(
                        "PCRE feature not supported by Ibex: recursion and version conditions (see docs/differences.md)".to_string(),
                        None,
                    ));
                }
                if tree.named_groups.contains_key(&text) {
                    return Err(Error(format!(
                        "PCRE feature not supported by Ibex: a condition on a bare group name, `(?({text})`; write `(?(<{text}>)` (see docs/differences.md)"
                    ), None));
                }
                return Err(Error(NONEXISTENT_GROUP.to_string(), None));
            }
            _ => {}
        }
        stack.extend(e.children_iter());
    }
    Ok(())
}

/// The text of a condition `fancy-regex` read as literal characters.
fn literal_text(e: &fancy_regex::Expr) -> Option<String> {
    use fancy_regex::Expr;
    match e {
        Expr::Literal { val, .. } => Some(val.clone()),
        Expr::Concat(parts) => parts.iter().map(literal_text).collect(),
        _ => None,
    }
}

/// `pattern` with every unnamed capturing group made non-capturing (`(` becomes `(?:`),
/// which is what `PCRE2_NO_AUTO_CAPTURE` does. `None` when there
/// is none (the pattern is used as it is).
fn without_auto_capture(pattern: &str) -> Option<String> {
    let b = pattern.as_bytes();
    let mut out = String::with_capacity(pattern.len() + 8);
    let mut changed = 0;
    let mut in_class = false;
    let mut i = 0;
    let mut from = 0; // start of the text not yet copied
    while i < b.len() {
        match b[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'[' if !in_class => {
                in_class = true;
                i += 1;
                if b.get(i) == Some(&b'^') {
                    i += 1;
                }
                if b.get(i) == Some(&b']') {
                    i += 1;
                }
                continue;
            }
            b'[' if b.get(i + 1) == Some(&b':') => {
                // `[:alpha:]` inside a class
                if let Some(end) = pattern[i + 2..].find(":]") {
                    i += end + 4;
                    continue;
                }
            }
            b']' if in_class => in_class = false,
            b'(' if !in_class => match b.get(i + 1) {
                Some(b'*') => {}
                Some(b'?') => {
                    // `(?<n>`, `(?P<n>` and `(?'n'` name a group and stay as they are.
                    // A condition `(?(1)` or `(?(<n>)`: its parenthesis is not a group.
                    if b.get(i + 2) == Some(&b'(') && b.get(i + 3) != Some(&b'?') {
                        if let Some(end) = pattern[i + 3..].find(')') {
                            i += end + 4;
                            continue;
                        }
                    }
                    i += 2;
                    continue;
                }
                _ => {
                    out.push_str(&pattern[from..=i]);
                    out.push_str("?:");
                    from = i + 1;
                    changed += 1;
                }
            },
            _ => {}
        }
        i += 1;
    }
    if changed == 0 {
        return None;
    }
    out.push_str(&pattern[from..]);
    Some(out)
}

thread_local! {
    static COMPILES:std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// How many patterns this thread has compiled ([`UserRegex::with_case`]): a test reads it
/// around a request to show that the data path compiles none.
#[must_use]
pub fn compiles_on_this_thread() -> u64 {
    COMPILES.with(std::cell::Cell::get)
}

/// How many different patterns one thread keeps compiled ([`UserRegex::cached`]): every
/// one is configuration text; the bound only stops other text from growing the cache.
const REGEX_CACHE_MAX: usize = 4096;

type RegexCache = std::collections::HashMap<Box<str>, Result<std::rc::Rc<UserRegex>, Error>>;

thread_local! {
    static REGEX_CACHE: std::cell::RefCell<RegexCache> = std::cell::RefCell::new(RegexCache::new());
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
pub struct Error(String, Option<usize>);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Where in the pattern PCRE2 would have put `erroffset` for this refusal, when the
    /// parser said where it stopped. `fancy-regex` reports the index of the character it
    /// could not use; PCRE2 reports the index after a character it refused to take, which
    /// is the same for an unclosed group or class and one more for a stray `)` or a
    /// quantifier with nothing to repeat (T274 J3). `None` for what `fancy-regex` or this
    /// crate refuse without a position.
    #[must_use]
    pub fn offset(&self) -> Option<usize> {
        self.1
    }

    /// The refusal of `fancy-regex`, with the offset PCRE2 would report.
    fn from_fancy(e: &fancy_regex::Error) -> Self {
        let offset = match e {
            fancy_regex::Error::ParseError(at, kind) => {
                let past = match kind {
                    fancy_regex::ParseError::TargetNotRepeatable => true,
                    fancy_regex::ParseError::GeneralParseError(why) => why == "end of string not reached",
                    _ => false,
                };
                Some(if past { at + 1 } else { *at })
            }
            _ => None,
        };
        if matches!(e, fancy_regex::Error::CompileError(k) if matches!(**k, fancy_regex::CompileError::InvalidBackref(_)))
            || matches!(e, fancy_regex::Error::ParseError(_, fancy_regex::ParseError::InvalidBackref))
        {
            return Error(NONEXISTENT_GROUP.to_string(), None);
        }
        Error(e.to_string(), offset)
    }
}

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

    /// [`UserRegex::new`], once per pattern and thread: the regex compiled the first time
    /// a rule uses it, as `HAProxy` compiles it once when the configuration loads
    /// (`regex_comp`). The data path calls this with configuration text, so after the first
    /// request nothing is compiled.
    ///
    /// # Errors
    /// As [`UserRegex::new`], the error remembered as well.
    pub fn cached(pattern: &str) -> Result<std::rc::Rc<Self>, Error> {
        if let Some(hit) = REGEX_CACHE.with(|c| c.borrow().get(pattern).cloned()) {
            return hit;
        }
        let compiled = Self::new(pattern).map(std::rc::Rc::new);
        REGEX_CACHE.with(|c| {
            let mut c = c.borrow_mut();
            if c.len() < REGEX_CACHE_MAX {
                c.insert(pattern.into(), compiled.clone());
            }
        });
        compiled
    }

    /// As [`UserRegex::new`], matching without regard to case if `case_insensitive`.
    ///
    /// # Errors
    /// As [`UserRegex::new`].
    pub fn with_case(pattern: &str, case_insensitive: bool) -> Result<Self, Error> {
        COMPILES.with(|n| n.set(n.get() + 1));
        let scan = scan(pattern);
        if let Some(what) = scan.unsupported {
            return Err(Error(format!("PCRE feature not supported by Ibex: {what} (see docs/differences.md)"), None));
        }
        // `regex` reads `a++` as `(a+)+` and `(?R)` as a flag, and so would accept what it
        // does not mean: a pattern with such a token goes to `fancy-regex` directly.
        if !scan.pcre_only {
            if let Ok(re) = regex::RegexBuilder::new(pattern).case_insensitive(case_insensitive).build() {
                return Ok(UserRegex::Linear(re));
            }
        }
        let re = fancy_regex::RegexBuilder::new(pattern)
            .case_insensitive(case_insensitive)
            .backtrack_limit(BACKTRACK_LIMIT)
            .build()
            // `fancy-regex` parses a superset of what `regex` does, so its message is the one
            // that says what is wrong with the pattern (`regex`'s would say that look-around
            // is not supported, of a pattern that fails for another reason).
            .map_err(|e| Error::from_fancy(&e))?;
        check_conditions(pattern, re.captures_len())?;
        Ok(UserRegex::Backtracking(re))
    }

    /// [`UserRegex::new`] as `HAProxy` compiles the regex of an ACL, of `map_reg` and of a
    /// health check `rstring`: with `PCRE2_NO_AUTO_CAPTURE`, so that only a named group
    /// captures and so counts for `\1` or `(?(1)..)`. `(a)\1` is refused ("reference to
    /// non-existent subpattern"), `(?<n>a)\1` is a back-reference to `n`. Captures are
    /// never read from such a regex.
    ///
    /// # Errors
    /// As [`UserRegex::new`], and the reference to a group the pattern does not capture.
    pub fn new_nocapture(pattern: &str) -> Result<Self, Error> {
        Self::with_case_nocapture(pattern, false)
    }

    /// [`UserRegex::new_nocapture`], matching without regard to case if `case_insensitive`.
    ///
    /// # Errors
    /// As [`UserRegex::new_nocapture`].
    pub fn with_case_nocapture(pattern: &str, case_insensitive: bool) -> Result<Self, Error> {
        let Some(plain) = without_auto_capture(pattern) else {
            return Self::with_case(pattern, case_insensitive);
        };
        match Self::with_case(&plain, case_insensitive) {
            Ok(re) => Ok(re),
            Err(_) => {
                // What the pattern says wrong as written is what PCRE2 says; if it is right
                // as written, only the reference to a group that no longer captures is left.
                Self::with_case(pattern, case_insensitive)?;
                Err(Error(NONEXISTENT_GROUP.to_string(), None))
            }
        }
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

    /// A recursion-level back-reference (`\k<n+0>`, Oniguruma's: `fancy-regex` refuses it as
    /// unimplemented, so `check_conditions` never sees one) and a conditional on a class are
    /// refused, as PCRE2 refuses both (measured on HAProxy 3.5-dev8: "subpattern name must start
    /// with a non-digit" and "subpattern name expected").
    #[test]
    fn oniguruma_only_references_and_class_conditions_are_refused() {
        for p in [r"(a)\k<2+0>", r"(a)\k<1+0>", r"(a)\k<0+0>", "(?([a-z])x|y)"] {
            assert!(UserRegex::new(p).is_err(), "`{p}` compiled");
        }
    }

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

    /// T242 (fuzz regex): `fancy-regex` reads every `\\g<n>`, `\\g'n'` and `\\gN` as a
    /// subroutine call and inlines it at compile time, so a 53-byte pattern with two `\\g0`
    /// took over 2 GB. PCRE2 (HAProxy) accepts `\\g<0>` as recursion, which Ibex refuses
    /// in its other spellings; `\\g0` it rejects outright.
    #[test]
    fn subroutine_calls_by_backslash_g_are_refused() {
        for p in [r"x\g<0>?", r"(a)\g'1'", r"(?<n>a)\g<n>", r"\g0", r"(a)|b\g1"] {
            let e = UserRegex::new(p).unwrap_err().to_string();
            assert!(e.contains("recursion"), "{p}: {e}");
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

#[cfg(test)]
mod nocapture_tests {
    use super::*;

    #[test]
    fn the_rewrite_touches_only_unnamed_capturing_groups() {
        let r = without_auto_capture;
        assert_eq!(r("(a)b"), Some("(?:a)b".into()));
        assert_eq!(r("((a))"), Some("(?:(?:a))".into()));
        assert_eq!(r("(a)(?<n>b)"), Some("(?:a)(?<n>b)".into()));
        // nothing to change
        assert_eq!(r("a(?:b)(?i)c"), None);
        assert_eq!(r(r"\(a\)"), None);
        assert_eq!(r("(*UTF8)a"), None);
        assert_eq!(r("[(]"), None);
        // classes: a leading `^` and `]` are literal, POSIX names are skipped
        assert_eq!(r("[^]](a)"), Some("[^]](?:a)".into()));
        assert_eq!(r("[]a](a)"), Some("[]a](?:a)".into()));
        assert_eq!(r("[[:alpha:](]+(a)"), Some("[[:alpha:](]+(?:a)".into()));
        assert_eq!(r("[[:x](a)"), Some("[[:x](?:a)".into()));
        // conditions: the parenthesis of `(?(1)` is not a group; an assertion condition is
        assert_eq!(r("(a)(?(1)b|c)"), Some("(?:a)(?(1)b|c)".into()));
        assert_eq!(r("(?(?=a)(b)|c)"), Some("(?(?=a)(?:b)|c)".into()));
        // an unterminated condition is left to the compiler to refuse
        assert_eq!(r("(?(1"), Some("(?(?:1".into()));
        assert_eq!(r("(?(<n>)(b)|c)"), Some("(?(<n>)(?:b)|c)".into()));
    }

    #[test]
    fn unnamed_groups_do_not_capture_but_named_ones_do() {
        assert!(UserRegex::new_nocapture(r"(a)\1").is_err_and(|e| e.to_string() == NONEXISTENT_GROUP));
        assert!(UserRegex::new_nocapture(r"(a)(?<n>b)\1").is_ok_and(|r| r.is_match("abb") && !r.is_match("aba")));
        assert!(UserRegex::new_nocapture(r"[(](a)(?:b)").is_ok_and(|r| r.is_match("(ab")));
        assert!(UserRegex::new_nocapture(r"\(a)").is_err());
        assert!(UserRegex::new_nocapture(r"(a").is_err_and(|e| e.to_string() != NONEXISTENT_GROUP));
        assert!(UserRegex::new(r"(a)\1").is_ok());
    }
}
