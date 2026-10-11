// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `Connection` and `Upgrade` header values as `HAProxy` reads them for a protocol
//! upgrade (`h1_parse_connection_header` and `h1_parse_upgrade_header` in src/h1.c).

/// The comma-separated elements of a header value, blanks around them trimmed, empty ones
/// skipped.
pub fn tokens(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(|t| t.trim_matches([' ', '\t'])).filter(|t| !t.is_empty())
}

/// An `Upgrade` value with `h2c` and `h2` taken out (an upgrade to HTTP/2 is not relayed), or
/// `None` when there is none to take out and the value goes on as it came. An empty string
/// when nothing is left: the header goes.
#[must_use]
pub fn clean_value(value: &str) -> Option<String> {
    let h2 = |t: &str| t.eq_ignore_ascii_case("h2c") || t.eq_ignore_ascii_case("h2");
    if !tokens(value).any(h2) {
        return None;
    }
    Some(tokens(value).filter(|t| !h2(t)).collect::<Vec<_>>().join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h2c_and_h2_are_taken_out() {
        assert_eq!(clean_value("websocket"), None);
        assert_eq!(clean_value("foo, bar"), None);
        assert_eq!(clean_value("h2c"), Some(String::new()));
        assert_eq!(clean_value("H2C, websocket , h2"), Some("websocket".into()));
        assert_eq!(clean_value("a, h2, b"), Some("a,b".into()));
    }
}
