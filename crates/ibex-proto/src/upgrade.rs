// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `Connection` and `Upgrade` header values as `HAProxy` reads them for a protocol
//! upgrade (`h1_parse_connection_header` and `h1_parse_upgrade_header` in src/h1.c).

/// The comma-separated elements of a header value, blanks around them trimmed, empty ones
/// skipped.
pub fn tokens(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(|t| t.trim_matches([' ', '\t'])).filter(|t| !t.is_empty())
}

/// An `Upgrade` value as `h1_parse_upgrade_header` rewrites it in place: `h2c` and `h2` are
/// taken out (an upgrade to HTTP/2 is not relayed), or `None` when there is none to take out
/// and the value goes on as it came. An empty string when nothing is left (or the value was
/// empty): the header goes.
///
/// The rewrite is HAProxy's, quirks included: while no word has been taken out, the value is
/// kept up to the end of the last word (the blanks after it too), and the words after the
/// first one taken out are joined by `,` alone (`foo , h2c , bar` becomes `foo ,bar`).
#[must_use]
pub fn clean_value(value: &str) -> Option<String> {
    let b = value.as_bytes();
    if b.is_empty() {
        return Some(String::new());
    }
    let lws = |c: u8| c == b' ' || c == b'\t';
    // `http_find_hdr_value_end`: the next comma outside a quoted string.
    let word_end = |mut s: usize| {
        let (mut quoted, mut pair) = (false, false);
        while s < b.len() {
            if pair {
                pair = false;
            } else if quoted {
                if b[s] == b'\\' {
                    pair = true;
                } else if b[s] == b'"' {
                    quoted = false;
                }
            } else if b[s] == b'"' {
                quoted = true;
            } else if b[s] == b',' {
                return s;
            }
            s += 1;
        }
        s
    };
    // `out_end` is `value->len` while the output is still a prefix of the input (`contiguous`),
    // `p` where the last word ended.
    let (mut out, mut contiguous, mut out_end, mut p) = (Vec::<u8>::new(), true, 0usize, 0usize);
    let mut at = 0usize;
    while at < b.len() {
        if lws(b[at]) {
            at += 1;
            continue;
        }
        let n = word_end(at);
        let mut word = &b[at..n];
        while let [rest @ .., last] = word {
            if !lws(*last) {
                break;
            }
            word = rest;
        }
        if word.eq_ignore_ascii_case(b"h2c") || word.eq_ignore_ascii_case(b"h2") {
            if contiguous {
                out.extend_from_slice(&b[..out_end]);
                contiguous = false;
            }
        } else if contiguous && out_end == p {
            out_end = n;
        } else {
            // Not contiguous here: while it is, `out_end == p` and the branch above is taken.
            if !out.is_empty() {
                out.push(b',');
            }
            out.extend_from_slice(word);
        }
        p = n;
        at = n + 1;
    }
    if contiguous {
        out.extend_from_slice(&b[..out_end]);
    }
    (out != b).then(|| String::from_utf8_lossy(&out).into_owned())
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
        assert_eq!(clean_value("foo , h2c , bar"), Some("foo ,bar".into()));
        assert_eq!(clean_value("h2c,foo"), Some("foo".into()));
        assert_eq!(clean_value("foo, h2c"), Some("foo".into()));
        assert_eq!(clean_value("h2c, h2"), Some(String::new()));
        assert_eq!(clean_value(""), Some(String::new()));
        // A comma inside a quoted string (with an escaped quote) does not end a word.
        assert_eq!(clean_value(r#""a,\"b,c", h2c"#), Some(r#""a,\"b,c""#.into()));
    }
}
