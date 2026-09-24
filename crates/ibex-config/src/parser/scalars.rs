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

pub(crate) fn parse_usize(token: &Token, keyword: &str) -> Result<usize, ConfigError> {
    token.text.parse::<usize>().map_err(|_| {
        ConfigError::new(
            token.line,
            token.col,
            format!("<{keyword}> expects a positive integer argument."),
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

pub(crate) fn unescape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                match next {
                    'r' => {
                        out.push('\r');
                        chars.next();
                    }
                    'n' => {
                        out.push('\n');
                        chars.next();
                    }
                    't' => {
                        out.push('\t');
                        chars.next();
                    }
                    '0' => {
                        out.push('\0');
                        chars.next();
                    }
                    '\\' => {
                        out.push('\\');
                        chars.next();
                    }
                    ' ' => {
                        out.push(' ');
                        chars.next();
                    }
                    _ => {
                        out.push(c);
                    }
                }
            } else {
                out.push(c);
            }
        } else {
            out.push(c);
        }
    }
    out
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

pub(crate) fn parse_match_type(s: &str) -> MatchType {
    match s.to_ascii_lowercase().as_str() {
        "beg" => MatchType::Beg,
        "end" => MatchType::End,
        "sub" => MatchType::Sub,
        "reg" => MatchType::Reg,
        _ => MatchType::Str,
    }
}

#[allow(dead_code)]
pub(crate) fn validate_regex(token: &Token) -> Result<(), ConfigError> {
    regex::Regex::new(&token.text).map_err(|e| {
        ConfigError::new(
            token.line,
            token.col,
            format!("bad regular expression <{}>: {e}", token.text),
        )
    })?;
    Ok(())
}

