// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/cfgcond.c (cfg_eval_condition) and the `-cc` handling in
// src/haproxy.c. Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors.

//! Build-condition expressions, as `-cc` and `.if` evaluate them.
//!
//! `HAProxy`'s reg-tests gate themselves on what a build supports by running
//! `haproxy -cc '<expr>'` and skipping when it exits non-zero. Without this every one of
//! them skipped, and a skip is indistinguishable from a pass in a scoreboard -- 47 ssl
//! tests reported as "not applicable" when what was true is that nobody had asked.
//!
//! ## What Ibex answers, and why
//!
//! The answers are chosen to be honest about two different questions the reg-tests ask
//! with similar-looking predicates:
//!
//! - `feature(OPENSSL)` is used throughout the suite to mean *this build can terminate
//!   TLS*. Ibex can, so this is true. Tests that then use OpenSSL-specific configuration
//!   fail rather than skip, which is the information worth having.
//! - `ssllib_name_startswith(OpenSSL)` asks *which library*, and the answer is rustls.
//!   False. So do `openssl_version_atleast` and `awslc_api_atleast`, which ask about
//!   versions of a library that is not here.
//!
//! Reporting false for both would skip every TLS test and tell us nothing. Reporting
//! true for both would claim an API we do not have and produce failures that say
//! nothing about Ibex. The split keeps each answer to what it actually asserts.

/// The `HAProxy` version Ibex reports for `version_atleast`.
///
/// The project targets 3.5 compatibility, so gates below that should open and the
/// features behind them should be exercised. A test that then fails is a gap worth
/// seeing; a test that skips is a gap that stays hidden.
pub const REPORTED_VERSION: &str = "3.5.0";

/// Answers one `feature(X)` predicate.
fn feature(name: &str) -> bool {
    // OPENSSL is answered true because the suite uses it to mean "this build terminates
    // TLS", not "OpenSSL is linked in" -- see the module comment. RUSTLS names the
    // backend so a condition can ask which one directly.
    matches!(name, "OPENSSL" | "RUSTLS")
}

/// Compares dotted version strings, ignoring any `-dev`/`-rc` suffix.
///
/// `2.5-dev0` is treated as `2.5`: the suffix orders *below* the release in `HAProxy`, and
/// since Ibex reports a version well above every gate in the suite, resolving it either
/// way gives the same answer. Being explicit about the simplification beats a comparison
/// that looks exact and is not.
fn version_atleast(want: &str) -> bool {
    fn parts(v: &str) -> Vec<u32> {
        v.split(['-', '+'])
            .next()
            .unwrap_or(v)
            .split('.')
            .map(|p| p.parse().unwrap_or(0))
            .collect()
    }
    let have = parts(REPORTED_VERSION);
    let want = parts(want);
    for i in 0..have.len().max(want.len()) {
        let h = have.get(i).copied().unwrap_or(0);
        let w = want.get(i).copied().unwrap_or(0);
        if h != w {
            return h > w;
        }
    }
    true
}

/// Evaluates one predicate call.
fn predicate(name: &str, arg: &str) -> bool {
    match name {
        "feature" => feature(arg),
        "version_atleast" => version_atleast(arg),
        // Which library, not whether TLS exists. Ibex is not OpenSSL, AWS-LC or wolfSSL.
        "ssllib_name_startswith" => arg.eq_ignore_ascii_case("rustls"),
        // Every version of a library that is not linked in is "before" and never
        // "at least".
        "openssl_version_before" => true,
        // Versions of a library that is not linked in; no FIPS mode; no build-time
        // toggles exposed yet. An unknown predicate lands here too: false means the
        // gated test skips, which is the right answer for a feature we do not have and
        // for one upstream added that we have not seen.
        "streq" => {
            let (a, b) = arg.split_once(',').unwrap_or((arg, ""));
            a.trim() == b.trim()
        }
        "strneq" => {
            let (a, b) = arg.split_once(',').unwrap_or((arg, ""));
            a.trim() != b.trim()
        }
        _ => false,
    }
}

/// A recursive-descent evaluator over `!`, `&&`, `||` and parentheses.
struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            s: s.as_bytes(),
            i: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn eat(&mut self, tok: &[u8]) -> bool {
        self.skip_ws();
        if self.s[self.i..].starts_with(tok) {
            self.i += tok.len();
            return true;
        }
        false
    }

    /// `expr := and ( '||' and )*`
    fn expr(&mut self) -> Option<bool> {
        let mut v = self.and()?;
        loop {
            self.skip_ws();
            if self.eat(b"||") {
                // Both sides are evaluated: predicates here are pure and cheap, and
                // short-circuiting would hide a malformed right-hand side.
                let rhs = self.and()?;
                v = v || rhs;
            } else {
                return Some(v);
            }
        }
    }

    /// `and := unary ( '&&' unary )*`
    fn and(&mut self) -> Option<bool> {
        let mut v = self.unary()?;
        loop {
            self.skip_ws();
            if self.eat(b"&&") {
                let rhs = self.unary()?;
                v = v && rhs;
            } else {
                return Some(v);
            }
        }
    }

    /// `unary := '!' unary | '(' expr ')' | call`
    fn unary(&mut self) -> Option<bool> {
        self.skip_ws();
        if self.eat(b"!") {
            return Some(!self.unary()?);
        }
        if self.eat(b"(") {
            let v = self.expr()?;
            self.skip_ws();
            if !self.eat(b")") {
                return None;
            }
            return Some(v);
        }
        self.call()
    }

    /// `call := name '(' arg? ')'`
    fn call(&mut self) -> Option<bool> {
        self.skip_ws();
        let start = self.i;
        while self.i < self.s.len()
            && (self.s[self.i].is_ascii_alphanumeric() || self.s[self.i] == b'_')
        {
            self.i += 1;
        }
        if self.i == start {
            return None;
        }
        let name = std::str::from_utf8(&self.s[start..self.i]).ok()?;
        if !self.eat(b"(") {
            return None;
        }
        let arg_start = self.i;
        let mut depth = 0usize;
        while self.i < self.s.len() {
            match self.s[self.i] {
                b'(' => depth += 1,
                b')' if depth == 0 => break,
                b')' => depth -= 1,
                _ => {}
            }
            self.i += 1;
        }
        let arg = std::str::from_utf8(&self.s[arg_start..self.i]).ok()?.trim();
        if !self.eat(b")") {
            return None;
        }
        Some(predicate(name, arg))
    }
}

/// Evaluates a build-condition expression.
///
/// `None` for anything that does not parse, which the caller reports as an error rather
/// than as false -- a malformed condition silently meaning "no" is how a test ends up
/// skipped for a reason nobody notices.
#[must_use]
pub fn eval(expr: &str) -> Option<bool> {
    let mut p = Parser::new(expr);
    let v = p.expr()?;
    p.skip_ws();
    if p.i != p.s.len() {
        return None;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::{eval, version_atleast};

    #[test]
    fn version_comparison_handles_dev_suffixes_and_widths() {
        assert!(version_atleast("2.5-dev0"));
        assert!(version_atleast("3.0-dev0"));
        assert!(version_atleast("2.8"));
        assert!(version_atleast("3.5"));
        assert!(version_atleast("3.5.0"));
        assert!(!version_atleast("3.6"));
        assert!(!version_atleast("4.0-dev1"));
    }

    #[test]
    fn tls_is_reported_present_but_not_as_openssl() {
        // "can this build do TLS" -- yes.
        assert_eq!(eval("feature(OPENSSL)"), Some(true));
        // "is the library OpenSSL" -- no, and neither are the others.
        assert_eq!(eval("ssllib_name_startswith(OpenSSL)"), Some(false));
        assert_eq!(eval("ssllib_name_startswith(AWS-LC)"), Some(false));
        assert_eq!(eval("ssllib_name_startswith(wolfSSL)"), Some(false));
        assert_eq!(eval("ssllib_name_startswith(rustls)"), Some(true));
        assert_eq!(eval("openssl_version_atleast(1.1.1)"), Some(false));
    }

    #[test]
    fn features_we_do_not_have_are_false() {
        for f in ["LUA", "QUIC", "ZLIB", "SLZ", "LINUX_SPLICE", "OPENSSL_WOLFSSL"] {
            assert_eq!(eval(&format!("feature({f})")), Some(false), "{f}");
        }
    }

    /// The real expressions from the suite, with the answer each should give.
    #[test]
    fn the_expressions_the_reg_tests_actually_use() {
        let cases: &[(&str, bool)] = &[
            ("feature(OPENSSL)", true),
            ("version_atleast(2.5-dev0)", true),
            ("feature(LUA)", false),
            (
                "feature(QUIC) && !feature(QUIC_OPENSSL_COMPAT) && !feature(OPENSSL_WOLFSSL)",
                false,
            ),
            ("feature(ZLIB) || feature(SLZ)", false),
            ("feature(OPENSSL) && !ssllib_name_startswith(wolfSSL)", true),
            ("feature(OPENSSL) && openssl_version_atleast(1.1.1)", false),
            (
                "feature(OPENSSL) && ssllib_name_startswith(OpenSSL) && \
                 openssl_version_atleast(1.1.1) || feature(OPENSSL_AWSLC)",
                false,
            ),
            ("!fips_mode()", true),
            ("version_atleast(3.0-dev0) && feature(OPENSSL)", true),
        ];
        for (expr, want) in cases {
            assert_eq!(eval(expr), Some(*want), "{expr}");
        }
    }

    /// Precedence: `&&` binds tighter than `||`, and `!` tighter than both.
    #[test]
    fn precedence_and_parentheses() {
        assert_eq!(eval("feature(LUA) || feature(OPENSSL) && !fips_mode()"), Some(true));
        assert_eq!(eval("(feature(LUA) || feature(OPENSSL)) && fips_mode()"), Some(false));
        assert_eq!(eval("!(feature(LUA) && feature(OPENSSL))"), Some(true));
    }

    /// A malformed condition is an error, not a quiet false.
    #[test]
    fn unparseable_conditions_are_rejected() {
        for bad in ["feature(", "feature(X) &&", "&& feature(X)", "", "feature(X) junk", "()"] {
            assert_eq!(eval(bad), None, "{bad:?} should not parse");
        }
    }
}
