// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use super::*;

pub(crate) fn parse_timeout(token: &Token, keyword: &str) -> Result<Duration, ConfigError> {
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

    let ms: u64 = num_str.parse().map_err(|_| {
        ConfigError::new(
            token.line,
            token.col,
            format!("<{keyword}> expects an integer <time_in_ms> as argument."),
        )
    })?;

    Ok(Duration::from_millis(ms.saturating_mul(factor)))
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
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16)
            .map_err(|e| format!("invalid hex byte '{}': {}", &clean[i..i + 2], e))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

pub(crate) fn validate_regex(token: &Token) -> Result<(), ConfigError> {
    ibex_regex::UserRegex::new(&token.text).map_err(|e| {
        ConfigError::new(
            token.line,
            token.col,
            format!("bad regular expression <{}>: {e}", token.text),
        )
    })?;
    Ok(())
}

