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
    // backend so a condition can ask which one directly. THREAD is what `-vv` of the
    // reference says ("+THREAD"): Ibex runs worker threads.
    matches!(name, "OPENSSL" | "RUSTLS" | "THREAD")
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

/// Why a condition did not parse: `HAProxy`'s message and `errptr`, the byte of the
/// expression it was reading when it gave up (`.if` prints it as "at position N" and under a
/// caret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondError {
    pub msg: String,
    pub pos: usize,
}

/// `MAX_CFG_RECURSION` (`include/haproxy/defaults.h`).
const MAX_RECURSION: i32 = 1024;

/// `Ok(None)` is `HAProxy`'s "return 0": there is nothing here to parse, and whoever called
/// reports it. `Err` carries a finished message and where it happened.
type Parsed = Result<Option<bool>, CondError>;

/// A recursive-descent parser over `!`, `&&`, `||`, parentheses, integers and predicates,
/// a port of `cfg_parse_cond_expr`, `cfg_parse_cond_and` and `cfg_parse_cond_term`
/// (`src/cfgcond.c`) down to what each leaves in the text pointer when it fails, which is
/// where the error is reported. Spaces and tabs separate tokens; `&&` binds tighter than
/// `||`. A term is evaluated as it is parsed and the whole expression is always parsed, so a
/// malformed right-hand side is an error even when the left one decides the result.
struct Parser<'a> {
    s: &'a str,
    opts: EnabledOpts,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str, opts: EnabledOpts) -> Self {
        Self { s, opts }
    }

    fn byte(&self, i: usize) -> Option<u8> {
        self.s.as_bytes().get(i).copied()
    }

    fn rest(&self, i: usize) -> &'a str {
        self.s.get(i..).unwrap_or("")
    }

    fn blanks(&self, mut i: usize) -> usize {
        while matches!(self.byte(i), Some(b' ' | b'\t')) {
            i += 1;
        }
        i
    }

    fn err(&self, msg: String, pos: usize) -> CondError {
        CondError { msg, pos }
    }

    /// `expr := and ( '||' expr )?`
    fn expr(&self, text: &mut usize, depth: i32) -> Parsed {
        let mut i = *text;
        if i >= self.s.len() {
            return Ok(None);
        }
        if depth <= 0 {
            return Err(self.err(format!("unparsable conditional expression '{}'", self.rest(i)), i));
        }
        let left = self.and(&mut i, depth - 1)?;
        let Some(left) = left else {
            return Err(self.err(format!("unparsable conditional expression '{}'", self.rest(i)), i));
        };
        i = self.blanks(i);
        *text = i;
        if !self.rest(i).starts_with("||") {
            return Ok(Some(left));
        }
        i = self.blanks(i + 2);
        let Some(right) = self.expr(&mut i, depth - 1)? else { return Ok(None) };
        *text = i;
        Ok(Some(left || right))
    }

    /// `and := term ( '&&' and )?`
    fn and(&self, text: &mut usize, depth: i32) -> Parsed {
        let mut i = *text;
        if i >= self.s.len() {
            return Ok(None);
        }
        if depth <= 0 {
            return Err(self.err(format!("unparsable conditional sub-expression '{}'", self.rest(i)), i));
        }
        let left = self
            .term(&mut i, depth - 1)?
            .ok_or_else(|| self.err(format!("unparsable conditional sub-expression '{}'", self.rest(i)), i))?;
        i = self.blanks(i);
        *text = i;
        if !self.rest(i).starts_with("&&") {
            return Ok(Some(left));
        }
        i = self.blanks(i + 2);
        let Some(right) = self.and(&mut i, depth - 1)? else { return Ok(None) };
        *text = i;
        Ok(Some(left && right))
    }

    /// `term := '!'* ( integer | '(' expr ')' | predicate )`
    fn term(&self, text: &mut usize, depth: i32) -> Parsed {
        let start = *text;
        let mut i = self.blanks(start);
        if i >= self.s.len() {
            return Ok(None);
        }
        let unparsable = || self.err(format!("unparsable conditional expression '{}'", self.rest(start)), start);
        if depth <= 0 {
            return Err(unparsable());
        }
        let mut neg = false;
        while self.byte(i) == Some(b'!') {
            neg = !neg;
            i = self.blanks(i + 1);
        }

        if let Some((v, end)) = self.integer(i) {
            *text = end;
            return Ok(Some((v != 0) != neg));
        }

        if self.byte(i) == Some(b'(') {
            i = self.blanks(i + 1);
            let Some(v) = self.expr(&mut i, depth - 1)? else { return Err(unparsable()) };
            i = self.blanks(i);
            if self.byte(i) != Some(b')') {
                return Err(self.err(format!("expected ')' after conditional expression '{}'", self.rest(start)), start));
            }
            *text = self.blanks(i + 1);
            return Ok(Some(v != neg));
        }

        // The word ends at a blank or a parenthesis, and must be a predicate as a whole.
        let word_len = self.rest(i).find([' ', '(']).unwrap_or(self.rest(i).len());
        let word = &self.rest(i)[..word_len];
        let Some(&(name, nargs)) = PREDICATES.iter().find(|(n, _)| *n == word) else {
            return Err(unparsable());
        };
        match self.arg_list(i + word_len, nargs) {
            Ok((args, end)) => {
                *text = end;
                Ok(Some(predicate(name, &args, &self.opts) != neg))
            }
            Err((msg, err_arg, end)) => Err(self.err(
                format!("{msg} in argument {err_arg} of predicate '{name}' used in conditional expression"),
                end,
            )),
        }
    }

    /// `strtol(s, &end, 0)` at `i`: optional sign, then `0x` hex, leading-`0` octal or decimal,
    /// and where it ends. `None` when there are no digits.
    fn integer(&self, i: usize) -> Option<(i64, usize)> {
        let b = self.s.as_bytes();
        let mut j = i;
        let neg = match b.get(j) {
            Some(b'-') => {
                j += 1;
                true
            }
            Some(b'+') => {
                j += 1;
                false
            }
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
        Some((if neg { -v } else { v }, k))
    }

    /// `make_arg_list` (`src/arg.c`) for a predicate of `nbarg` string arguments, all of them
    /// mandatory: the `( a, b )` after its name, where an argument runs to the next `,` or
    /// `)` outside quotes and `\` `'` `"` and a space can be escaped. Without a `(` the
    /// arguments are empty. Returns the arguments and where the list ends, or HAProxy's
    /// message, the number of the argument it names, and where it stopped.
    fn arg_list(&self, from: usize, nbarg: usize) -> Result<(Vec<String>, usize), (String, usize, usize)> {
        let b = self.s.as_bytes();
        let mut i = from;
        let empty = self.byte(i) != Some(b'(');
        if !empty {
            i += 1;
        }
        let mut pos = 0;
        let mut args: Vec<String> = Vec::new();
        while nbarg > 0 && pos < nbarg {
            let mut out: Vec<u8> = Vec::new();
            let (mut squote, mut dquote) = (false, false);
            while !empty && i < b.len() {
                let c = b[i];
                if c == b'"' && !squote {
                    dquote = !dquote;
                    i += 1;
                } else if c == b'\'' && !dquote {
                    squote = !squote;
                    i += 1;
                } else if c == b'\\' && !squote && i + 1 < b.len() {
                    match b[i + 1] {
                        e @ (b'\\' | b' ' | b'"' | b'\'') => {
                            out.push(e);
                            i += 2;
                        }
                        b'r' => {
                            out.push(b'\r');
                            i += 2;
                        }
                        b'n' => {
                            out.push(b'\n');
                            i += 2;
                        }
                        b't' => {
                            out.push(b'\t');
                            i += 2;
                        }
                        _ => {
                            // A lone backslash.
                            out.push(b'\\');
                            i += 1;
                        }
                    }
                } else if !squote && !dquote && (c == b',' || c == b')') {
                    break;
                } else {
                    out.push(c);
                    i += 1;
                }
            }
            args.push(String::from_utf8_lossy(&out).into_owned());
            pos += 1;
            if empty || i >= b.len() || b[i] == b')' || pos >= nbarg {
                break;
            }
            i += 1; // the comma
        }
        if pos < nbarg {
            return Err((format!("missing arguments (got {pos}/{nbarg}), type 'string' expected"), pos, i));
        }
        if !empty {
            if b.get(i) == Some(&b')') {
                i += 1;
            } else {
                let word = self.rest(i);
                let msg = if word.is_empty() { "expected ')'".to_string() } else { format!("expected ')' before '{word}'") };
                // The empty argument before a missing parenthesis already counted for one.
                return Err((msg, if pos > 1 { pos - 1 } else { pos }, i));
            }
        }
        Ok((args, i))
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

/// `cfg_eval_condition`, with the message `HAProxy` prints and where it stopped. An empty
/// expression is false here; [`eval_checked`] refuses it.
fn eval_condition(expr: &str, opts: &EnabledOpts) -> Result<bool, CondError> {
    let p = Parser::new(expr, *opts);
    let mut text = 0;
    let Some(v) = p.expr(&mut text, MAX_RECURSION)? else {
        return Err(p.err(format!("unparsable conditional expression '{expr}'"), text));
    };
    text = p.blanks(text);
    if let Some(c) = p.rest(text).chars().next() {
        return Err(p.err(format!("unexpected character '{c}' at the end of conditional expression '{expr}'"), text));
    }
    Ok(v)
}

/// [`eval`] with the message `HAProxy` prints.
fn eval_checked(expr: &str, opts: &EnabledOpts) -> Result<bool, String> {
    if expr.is_empty() {
        return Err("unparsable conditional expression ''".to_string());
    }
    eval_condition(expr, opts).map_err(|e| e.msg)
}

/// A `.if` / `.elif` condition (`cfg_eval_condition`): the words of the line, already split
/// and unquoted by the lexer, joined by single spaces. An empty condition is false.
/// `directive` is `.if` or `.elif`.
///
/// # Errors
///
/// What `HAProxy` prints, when the condition does not parse: the message, and the byte
/// of `expr` it stopped at.
pub fn eval_if(expr: &str, opts: &EnabledOpts) -> Result<bool, CondError> {
    if expr.is_empty() {
        return Ok(false);
    }
    eval_condition(expr, opts)
}

/// `sanitize_for_printing` (`src/tools.c`): `line` cut to `width` characters around `pos`,
/// blanks as spaces and anything unprintable as `?`; the text, and where `pos` is in it.
fn sanitize_for_printing(line: &str, pos: usize, width: usize) -> (String, usize) {
    let bytes = line.as_bytes();
    let (mut shift, mut start, mut limit) = (0, 0, width);
    let mut out = String::new();
    if pos >= width {
        // Out of context: put `pos` in the middle.
        shift = pos - width / 2;
        start = shift + 3;
        limit = width - 3;
        out.push_str("...");
    }
    for &c in bytes.iter().skip(start) {
        if out.len() >= limit {
            break;
        }
        out.push(if c.is_ascii_whitespace() {
            ' '
        } else if c.is_ascii_graphic() {
            char::from(c)
        } else {
            '?'
        });
    }
    if limit < width {
        out.push_str("...");
    }
    (out, pos - shift)
}

/// The text `HAProxy` prints for a `.if` or `.elif` (`word`, with the leading dot) whose
/// condition `expr` failed to parse: the message, the position, the line and a caret under
/// the byte it stopped at (`cfg_parse` in `src/cfgparse.c`).
#[must_use]
pub fn describe_error(word: &str, expr: &str, e: &CondError) -> String {
    // `.if` shows 76 characters, `.elif` 74: what is left of an 80-column line.
    let width = if word == ".if" { 76 } else { 74 };
    let (shown, newpos) = sanitize_for_printing(expr, e.pos, width);
    let indent = newpos + word.len() + 2;
    format!("{} in '{word}' at position {}:\n  {word} {shown}\n  {:>indent$}", e.msg, e.pos + 1, "^")
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
    eval_checked(&expr, &EnabledOpts::default()).map_err(|e| format!("Failed to evaluate condition: {e}"))
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

    /// `haproxy -cc 'feature(THREAD)'` exits 0 on the reference binary (3.5-dev8-885761-29,
    /// "+THREAD" in `-vv`), and Ibex is multi-threaded: 407 lines of the reg-tests are
    /// `.if feature(THREAD)` around `thread-groups`, which Ibex accepts (T146 item 17).
    #[test]
    fn threads_are_reported_present() {
        assert_eq!(eval("feature(THREAD)"), Some(true));
        assert_eq!(eval("feature(THREAD) && feature(OPENSSL)"), Some(true));
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
