// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use super::*;

/// The largest timer `HAProxy` takes: ticks are signed 32-bit milliseconds
/// (`parse_time_err` returns `PARSE_TIME_OVER` above it).
pub(crate) const TIMER_MAX_MS: u64 = 0x7fff_ffff;

/// `(maximum value is ...)`, as most keywords word the overflow.
pub(crate) const TIMER_LIMIT: &str = "(maximum value is 2147483647 ms or ~24.8 days)";

/// A delay in milliseconds, refusing one over [`TIMER_MAX_MS`] with the generic text
/// `timer overflow in argument '<arg>' to '<keyword>' (maximum value is ...)`.
pub(crate) fn parse_timeout(token: &Token, keyword: &str) -> Result<Duration, ConfigError> {
    parse_timer(token, keyword, |arg| format!("timer overflow in argument '{arg}' to '{keyword}' {TIMER_LIMIT}"))
}

/// [`parse_timeout`] with the keyword's own overflow text (`overflow(arg)`): the server
/// keywords, `stick-table expire`, `inspect-delay`... word it differently.
pub(crate) fn parse_timer(token: &Token, keyword: &str, overflow: impl FnOnce(&str) -> String) -> Result<Duration, ConfigError> {
    let s = &token.text;
    let (num_str, factor) = if let Some(stripped) = s.strip_suffix("ms") {
        (stripped, 1u64)
    } else if let Some(stripped) = s.strip_suffix('s') {
        (stripped, 1000u64)
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, 60_000u64)
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, 3_600_000u64)
    } else if let Some(stripped) = s.strip_suffix('d') {
        (stripped, 86_400_000u64)
    } else {
        (s.as_str(), 1u64)
    };

    let all_digits = !num_str.is_empty() && num_str.bytes().all(|b| b.is_ascii_digit());
    let ms = match num_str.parse::<u64>() {
        Ok(n) => n.checked_mul(factor),
        // Digits only, too many for 64 bits: an overflow too.
        Err(_) if all_digits => None,
        Err(_) => {
            return Err(ConfigError::new(token.line, token.col, format!("<{keyword}> expects an integer <time_in_ms> as argument.")));
        }
    };
    match ms.filter(|ms| *ms <= TIMER_MAX_MS) {
        Some(ms) => Ok(Duration::from_millis(ms)),
        None => Err(ConfigError::new(token.line, token.col, overflow(s))),
    }
}

/// `tcp-request|tcp-response inspect-delay` in `<kind> '<name>'` (`proxy` or `defaults`).
pub(crate) fn parse_inspect_delay(token: &Token, dir: &str, kind: &str, name: &str) -> Result<Duration, ConfigError> {
    let kw = format!("tcp-{dir} inspect-delay");
    parse_timer(token, &kw, |a| {
        format!(
            "'{kw}' expects a positive delay in milliseconds, in {kind} '{name}' (timer overflow in '{a}', maximum value is 2147483647 ms or ~24.8 days)"
        )
    })
}

pub(crate) fn parse_u32(token: &Token, keyword: &str) -> Result<u32, ConfigError> {
    token.text.parse::<u32>().map_err(|_| {
        ConfigError::new(
            token.line,
            token.col,
            format!("<{keyword}> expects an integer argument."),
        )
    })
}

pub(crate) fn parse_u16(token: &Token, keyword: &str) -> Result<u16, ConfigError> {
    token.text.parse::<u16>().map_err(|_| {
        ConfigError::new(
            token.line,
            token.col,
            format!("<{keyword}> expects a 16-bit integer argument."),
        )
    })
}

pub(crate) fn parse_size(token: &Token) -> Result<usize, ConfigError> {
    let s = token.text.to_lowercase();
    let (num_str, multiplier) = if let Some(stripped) = s.strip_suffix('k') {
        (stripped, 1024)
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, 1024 * 1024)
    } else if let Some(stripped) = s.strip_suffix('g') {
        (stripped, 1024 * 1024 * 1024)
    } else {
        (s.as_str(), 1)
    };

    let base: usize = num_str.parse().map_err(|_| {
        ConfigError::new(
            token.line,
            token.col,
            format!("invalid size <{}>", token.text),
        )
    })?;

    Ok(base.saturating_mul(multiplier))
}


pub(crate) fn parse_hex_binary(hex: &str) -> Result<Vec<u8>, String> {
    let clean = hex.trim().replace(' ', "");
    if !clean.len().is_multiple_of(2) {
        return Err(format!("odd hex string length: {}", clean.len()));
    }
    // `str` slicing below needs ASCII; `from_str_radix` would take a leading `+`.
    if let Some(c) = clean.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(format!("an hex digit is expected (found '{c}')"));
    }
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16)
            .map_err(|e| format!("invalid hex byte '{}': {}", &clean[i..i + 2], e))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// [`validate_regex`] for the regexes `HAProxy` compiles with PCRE2_NO_AUTO_CAPTURE (ACLs,
/// health-check `rstring`/`rstatus`): `(a)\1` is refused there.
pub(crate) fn validate_regex_nocapture(token: &Token) -> Result<(), ConfigError> {
    alcyon_regex::UserRegex::new_nocapture(&token.text).map_err(|e| {
        ConfigError::new(token.line, token.col, format!("bad regular expression <{}>: {e}", token.text))
    })?;
    Ok(())
}

pub(crate) fn validate_regex(token: &Token) -> Result<(), ConfigError> {
    alcyon_regex::UserRegex::new(&token.text).map_err(|e| {
        ConfigError::new(
            token.line,
            token.col,
            format!("bad regular expression <{}>: {e}", token.text),
        )
    })?;
    Ok(())
}

