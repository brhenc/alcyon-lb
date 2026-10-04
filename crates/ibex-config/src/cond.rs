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

/// The predicates of `cond_predicates[]` (`src/cfgcond.c`) and how many arguments each takes.
const PREDICATES: &[(&str, usize)] = &[
    ("defined", 1),
    ("feature", 1),
    ("streq", 2),
    ("strneq", 2),
    ("strstr", 2),
    ("version_atleast", 1),
    ("version_before", 1),
    ("openssl_version_atleast", 1),
    ("openssl_version_before", 1),
    ("ssllib_name_startswith", 1),
    ("awslc_api_atleast", 1),
    ("awslc_api_before", 1),
    ("enabled", 1),
    ("fips_mode", 0),
];

/// What `enabled(<option>)` reads (`cfg_eval_cond_enabled`): the options of the global
/// section as read so far, so a `.if` sees the lines above it and no others. The defaults
/// are `HAProxy`'s on Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnabledOpts {
    pub poll: bool,
    pub epoll: bool,
    pub kqueue: bool,
    pub evports: bool,
    pub splice: bool,
    pub getaddrinfo: bool,
    pub reuseport: bool,
    pub fast_forward: bool,
    pub server_ssl_verify_none: bool,
}

impl Default for EnabledOpts {
    fn default() -> Self {
        Self {
            poll: true,
            epoll: true,
            kqueue: false,
            evports: false,
            splice: true,
            getaddrinfo: true,
            reuseport: true,
            fast_forward: true,
            server_ssl_verify_none: false,
        }
    }
}

impl EnabledOpts {
    /// Takes in one line of the `global` section: the keywords that switch an option off, and
    /// `ssl-server-verify`.
    pub fn global_line(&mut self, words: &[&str]) {
        match words {
            ["noepoll", ..] => self.epoll = false,
            ["nopoll", ..] => self.poll = false,
            ["nokqueue", ..] => self.kqueue = false,
            ["noevports", ..] => self.evports = false,
            ["nosplice", ..] => self.splice = false,
            ["nogetaddrinfo", ..] => self.getaddrinfo = false,
            ["noreuseport", ..] => self.reuseport = false,
            ["tune.disable-fast-forward", ..] => self.fast_forward = false,
            ["ssl-server-verify", v, ..] => self.server_ssl_verify_none = *v == "none",
            _ => {}
        }
    }

    fn enabled(&self, name: &str) -> bool {
        match name {
            "POLL" => self.poll,
            "EPOLL" => self.epoll,
            "KQUEUE" => self.kqueue,
            "EVPORTS" => self.evports,
            "SPLICE" => self.splice,
            "GETADDRINFO" => self.getaddrinfo,
            "REUSEPORT" => self.reuseport,
            "FAST-FORWARD" => self.fast_forward,
            "SERVER-SSL-VERIFY-NONE" => self.server_ssl_verify_none,
            _ => false,
        }
    }
}

/// Evaluates one predicate call. `args` holds as many strings as the predicate takes.
fn predicate(name: &str, args: &[String], opts: &EnabledOpts) -> bool {
    let a = args.first().map_or("", String::as_str);
    let b = args.get(1).map_or("", String::as_str);
    match name {
        "defined" => std::env::var_os(a).is_some(),
        "feature" => feature(a),
        "enabled" => opts.enabled(a),
        "streq" => a == b,
        "strneq" => a != b,
        "strstr" => a.contains(b),
        "version_atleast" => version_atleast(a.trim()),
        "version_before" => !version_atleast(a.trim()),
        // Which library, not whether TLS exists. Ibex is not OpenSSL, AWS-LC or wolfSSL.
        "ssllib_name_startswith" => a.eq_ignore_ascii_case("rustls"),
        // Every version of a library that is not linked in is "before" and never
        // "at least".
        "openssl_version_before" => true,
        // No FIPS mode and no AWS-LC: false means the gated test skips, which is the right
        // answer for a feature we do not have.
        _ => false,
    }
}

/// A recursive-descent parser over `!`, `&&`, `||`, parentheses, integers and predicates,
/// shaped like `cfg_parse_cond_expr` in `src/cfgcond.c`. Spaces and tabs separate tokens;
/// `&&` binds tighter than `||`. A term is evaluated as it is parsed and the whole
/// expression is always parsed, so a malformed right-hand side is an error even when the
/// left one decides the result.
struct Parser<'a> {
    s: &'a str,
    i: usize,
    opts: EnabledOpts,
}

/// A parse failure: `HAProxy`'s message, and the byte offset it points at (`errptr`).
struct CondErr {
    msg: String,
    at: usize,
}

/// `Ok(None)` is `HAProxy`'s "return 0": there is nothing here to parse, and whoever called
/// reports the whole expression as unparsable. `Err` carries a finished message.
type Parsed = Result<Option<bool>, CondErr>;

impl<'a> Parser<'a> {
    fn new(s: &'a str, opts: EnabledOpts) -> Self {
        Self { s, i: 0, opts }
    }

    fn rest(&self) -> &'a str {
        &self.s[self.i..]
    }

    fn eat(&mut self, tok: &str) -> bool {
        if self.rest().starts_with(tok) {
            self.i += tok.len();
            return true;
        }
        false
    }

    /// `at`, moved past any spaces and tabs.
    fn blanks(&self, mut at: usize) -> usize {
        while matches!(self.s.as_bytes().get(at), Some(b' ' | b'\t')) {
            at += 1;
        }
        at
    }

    fn unparsable(&self, what: &str, at: usize) -> CondErr {
        CondErr { msg: format!("unparsable conditional {what} '{}'", &self.s[at..]), at }
    }

    /// `expr := and ( '||' expr )?` (`cfg_parse_cond_expr`). `text` is where the expression
    /// starts and, on success, the first character it did not take.
    fn expr(&mut self, text: &mut usize) -> Parsed {
        let mut at = *text;
        if at >= self.s.len() {
            return Ok(None);
        }
        let Some(left) = self.and(&mut at)? else {
            return Err(self.unparsable("expression", at));
        };
        at = self.blanks(at);
        *text = at;
        if !self.s[at..].starts_with("||") {
            return Ok(Some(left));
        }
        at = self.blanks(at + 2);
        let Some(right) = self.expr(&mut at)? else { return Ok(None) };
        *text = at;
        Ok(Some(left || right))
    }

    /// `and := term ( '&&' and )?` (`cfg_parse_cond_and`).
    fn and(&mut self, text: &mut usize) -> Parsed {
        let mut at = *text;
        if at >= self.s.len() {
            return Ok(None);
        }
        let Some(left) = self.term(&mut at)? else {
            return Err(self.unparsable("sub-expression", at));
        };
        at = self.blanks(at);
        *text = at;
        if !self.s[at..].starts_with("&&") {
            return Ok(Some(left));
        }
        at = self.blanks(at + 2);
        let Some(right) = self.and(&mut at)? else { return Ok(None) };
        *text = at;
        Ok(Some(left && right))
    }

    /// `term := '!'* ( integer | '(' expr ')' | predicate )` (`cfg_parse_cond_term`).
    fn term(&mut self, text: &mut usize) -> Parsed {
        let start = *text;
        let mut at = self.blanks(start);
        if at >= self.s.len() {
            return Ok(None);
        }
        let mut neg = false;
        while self.s[at..].starts_with('!') {
            neg = !neg;
            at = self.blanks(at + 1);
        }

        self.i = at;
        if let Some(v) = self.integer() {
            *text = self.i;
            return Ok(Some((v != 0) != neg));
        }

        if self.s[at..].starts_with('(') {
            at = self.blanks(at + 1);
            let Some(v) = self.expr(&mut at)? else { return Err(self.unparsable("expression", start)) };
            at = self.blanks(at);
            if !self.s[at..].starts_with(')') {
                return Err(CondErr {
                    msg: format!("expected ')' after conditional expression '{}'", &self.s[start..]),
                    at: start,
                });
            }
            *text = self.blanks(at + 1);
            return Ok(Some(v != neg));
        }

        // The word ends at a blank or a parenthesis, and must be a predicate as a whole.
        let end = self.s[at..].find([' ', '(']).unwrap_or(self.s.len() - at);
        let word = &self.s[at..at + end];
        let Some(&(name, nargs)) = PREDICATES.iter().find(|(n, _)| *n == word) else {
            return Err(self.unparsable("expression", start));
        };
        self.i = at + end;
        let args = self.args(name, nargs)?;
        *text = self.i;
        Ok(Some(predicate(name, &args, &self.opts) != neg))
    }

    /// `strtol(s, &end, 0)`: optional sign, then `0x` hex, leading-`0` octal or decimal.
    /// Nothing is consumed when there are no digits.
    fn integer(&mut self) -> Option<i64> {
        let b = self.s.as_bytes();
        let mut j = self.i;
        let neg = match b.get(j) {
            Some(b'-') => { j += 1; true }
            Some(b'+') => { j += 1; false }
            _ => false,
        };
        let (radix, digits_at) = if b.get(j) == Some(&b'0')
            && matches!(b.get(j + 1), Some(b'x' | b'X'))
            && b.get(j + 2).is_some_and(u8::is_ascii_hexdigit)
        {
            (16, j + 2)
        } else if b.get(j) == Some(&b'0') {
            (8, j)
        } else {
            (10, j)
        };
        let mut k = digits_at;
        while b.get(k).is_some_and(|c| char::from(*c).is_digit(radix)) {
            k += 1;
        }
        if k == digits_at {
            // "0x" followed by no hex digit parses as the "0" alone, as `strtol` does; the
            // octal branch above already covers that, so only a lack of any digit is here.
            return None;
        }
        let v = i64::from_str_radix(&self.s[digits_at..k], radix).unwrap_or(i64::MAX);
        self.i = k;
        Some(if neg { -v } else { v })
    }

    /// The `( a, b )` after a predicate name: raw strings, split on `,`, closed by `)`, and
    /// never trimmed. Without a `(` the predicate gets empty strings.
    fn args(&mut self, name: &str, nargs: usize) -> Result<Vec<String>, CondErr> {
        let unclosed = |p: &Self, arg: usize| {
            let msg = if p.rest().is_empty() {
                format!("expected ')' in argument {arg} of predicate '{name}' used in conditional expression")
            } else {
                format!("expected ')' before '{}' in argument {arg} of predicate '{name}' used in conditional expression", p.rest())
            };
            CondErr { msg, at: p.i }
        };
        if !self.eat("(") {
            return Ok(vec![String::new(); nargs]);
        }
        let mut args = Vec::new();
        if nargs == 0 {
            if self.eat(")") {
                return Ok(args);
            }
            return Err(unclosed(self, 0));
        }
        loop {
            let end = self.rest().find([',', ')']).unwrap_or(self.rest().len());
            args.push(self.rest()[..end].to_string());
            self.i += end;
            if self.eat(")") {
                break;
            }
            if args.len() >= nargs || self.rest().is_empty() {
                return Err(unclosed(self, 1));
            }
            self.eat(",");
        }
        if args.len() < nargs {
            return Err(CondErr {
                msg: format!(
                    "missing arguments (got {}/{nargs}), type 'string' expected in argument {} of predicate '{name}' used in conditional expression",
                    args.len(),
                    args.len()
                ),
                at: self.i - 1,
            });
        }
        Ok(args)
    }
}

/// Evaluates a build-condition expression that has already been through [`unquote`].
///
/// `None` for anything that does not parse, which the caller reports as an error rather
/// than as false -- a malformed condition silently meaning "no" is how a test ends up
/// skipped for a reason nobody notices.
#[must_use]
pub fn eval(expr: &str) -> Option<bool> {
    eval_checked(expr, &EnabledOpts::default()).ok()
}

/// [`eval`] with the message `HAProxy` prints, and where it points.
fn eval_checked(expr: &str, opts: &EnabledOpts) -> Result<bool, CondErr> {
    let mut p = Parser::new(expr, *opts);
    let mut text = 0;
    let Some(v) = p.expr(&mut text)? else {
        return Err(CondErr { msg: format!("unparsable conditional expression '{expr}'"), at: text });
    };
    let at = p.blanks(text);
    if let Some(c) = expr[at..].chars().next() {
        return Err(CondErr {
            msg: format!("unexpected character '{c}' at the end of conditional expression '{expr}'"),
            at,
        });
    }
    Ok(v)
}

/// A `.if` / `.elif` condition (`cfg_eval_condition`): the words of the line, already split
/// and unquoted by the lexer, joined by single spaces. An empty condition is false.
/// `directive` is `.if` or `.elif`.
///
/// # Errors
///
/// The message `HAProxy` prints, when the condition does not parse: the problem, the position
/// of the first bad character, the line again and a caret under that character.
pub fn eval_if(expr: &str, directive: &str, opts: &EnabledOpts) -> Result<bool, String> {
    if expr.is_empty() {
        return Ok(false);
    }
    eval_checked(expr, opts).map_err(|e| {
        format!(
            "{} in '{directive}' at position {}:\n  {directive} {expr}\n  {}^",
            e.msg,
            e.at + 1,
            " ".repeat(e.at + directive.len() + 1)
        )
    })
}

/// The command-line half of `-cc`: what `parse_line` (`src/tools.c`) does to the argument
/// before the expression is parsed, as `do_check_condition` asks for it.
///
/// Words are separated by blanks and re-joined by single spaces. Single quotes are literal.
/// Double quotes keep blanks, expand `$VAR`, `${VAR}` and `${VAR-default}` from the
/// environment, and honour `\n \r \t \xHH \" \\ \$`; outside quotes `$` is an ordinary
/// character, `\xHH`, `\\` and `\ ` are escapes and any other `\c` stays as two characters.
fn unquote(raw: &str) -> Result<String, String> {
    const HEX: &str = "Syntax Error in condition: Truncated or invalid hexadecimal sequence.";
    const UNHANDLED: &str = "Unhandled error in condition, please report this to the developers.";
    let c: Vec<char> = raw.chars().collect();
    let mut out = String::new();
    let mut in_word = false;
    let mut pending_space = false;
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        if matches!(ch, ' ' | '\t' | '\n' | '\r') {
            if in_word {
                pending_space = true;
                in_word = false;
            }
            i += 1;
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        in_word = true;
        match ch {
            '\'' => {
                i += 1;
                while i < c.len() && c[i] != '\'' {
                    out.push(c[i]);
                    i += 1;
                }
                if i >= c.len() {
                    return Err("Syntax Error in condition: Unmatched quote.".into());
                }
                i += 1;
            }
            '"' => {
                i += 1;
                loop {
                    let Some(&d) = c.get(i) else {
                        return Err("Syntax Error in condition: Unmatched quote.".into());
                    };
                    i += 1;
                    match d {
                        '"' => break,
                        '\\' => i = escape(&c, i, true, &mut out, HEX)?,
                        '$' => i = expand_env(&c, i, &mut out, UNHANDLED)?,
                        _ => out.push(d),
                    }
                }
            }
            '\\' => i = escape(&c, i + 1, false, &mut out, HEX)?,
            _ => {
                out.push(ch);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// One backslash escape; `i` is the index after the backslash. Returns the index after it.
fn escape(c: &[char], i: usize, dquote: bool, out: &mut String, hex: &str) -> Result<usize, String> {
    let Some(&e) = c.get(i) else {
        out.push('\\');
        return Ok(i);
    };
    match e {
        'n' => out.push('\n'),
        'r' => out.push('\r'),
        't' => out.push('\t'),
        '\\' => out.push('\\'),
        ' ' if !dquote => out.push(' '),
        '"' | '$' if dquote => out.push(e),
        'x' => {
            let h: String = c.iter().skip(i + 1).take(2).collect();
            let Ok(v) = u8::from_str_radix(&h, 16) else { return Err(hex.into()) };
            if h.len() != 2 {
                return Err(hex.into());
            }
            out.push(char::from(v));
            return Ok(i + 3);
        }
        _ => {
            out.push('\\');
            out.push(e);
        }
    }
    Ok(i + 1)
}

/// `$VAR`, `${VAR}` or `${VAR-default}`; `i` is the index after the `$`.
fn expand_env(c: &[char], i: usize, out: &mut String, unhandled: &str) -> Result<usize, String> {
    let name_end = |from: usize| {
        let mut k = from;
        while c.get(k).is_some_and(|x| x.is_ascii_alphanumeric() || *x == '_') {
            k += 1;
        }
        k
    };
    if c.get(i) == Some(&'{') {
        let n = name_end(i + 1);
        let name: String = c[i + 1..n].iter().collect();
        let mut k = n;
        let mut default = None;
        if c.get(k) == Some(&'-') {
            let mut d = String::new();
            k += 1;
            while c.get(k).is_some_and(|x| *x != '}') {
                d.push(c[k]);
                k += 1;
            }
            default = Some(d);
        }
        if name.is_empty() || c.get(k) != Some(&'}') {
            return Err(unhandled.into());
        }
        out.push_str(&std::env::var(&name).ok().or(default).unwrap_or_default());
        return Ok(k + 1);
    }
    let n = name_end(i);
    let name: String = c[i..n].iter().collect();
    if name.is_empty() || name.starts_with(|x: char| x.is_ascii_digit()) {
        return Err(unhandled.into());
    }
    out.push_str(&std::env::var(&name).unwrap_or_default());
    Ok(n)
}

/// `-cc <condition>` as `HAProxy` answers it: `Ok(true)` exits 0, `Ok(false)` exits 1 and
/// `Err(message)` exits 2. An empty condition is false, not an error.
///
/// # Errors
///
/// The message to print, when the condition does not parse.
pub fn eval_cc(raw: &str) -> Result<bool, String> {
    let expr = unquote(raw)?;
    if expr.is_empty() {
        return Ok(false);
    }
    eval_checked(&expr, &EnabledOpts::default()).map_err(|e| format!("Failed to evaluate condition: {}", e.msg))
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
