// SPDX-License-Identifier: GPL-2.0-or-later
//
// HAProxy 1.0 configuration parser, ported to Rust.
// Derived from HAProxy 1.0.2 (haproxy.c) by Willy Tarreau <willy@meta-x.org>.

/// A token extracted by the lexer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The string content of the token.
    pub text: String,
    /// 1-based line number in the source file.
    pub line: usize,
    /// 1-based column number where the token begins.
    pub col: usize,
}

/// A line containing zero or more tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// 1-based line number.
    pub line_number: usize,
    /// Tokens found on this line.
    pub tokens: Vec<Token>,
}

/// Lexes `HAProxy` configuration text into a list of non-empty tokenized lines.
///
/// Follows `HAProxy` 1.0.2 lexical conventions:
/// - Comments start with `#` or `;` and continue to the end of the line.
/// - Whitespace (spaces, tabs, form feeds) separates arguments.
/// - Backslash `\` escapes the subsequent character so spaces can be embedded in arguments.
/// - Blank lines and comment-only lines are omitted.
#[must_use]
pub fn lex(input: &str) -> Vec<Line> {
    let mut lines = Vec::new();

    for (line_idx, raw_line) in input.lines().enumerate() {
        let line_number = line_idx + 1;
        let tokens = lex_line(raw_line, line_number);
        if !tokens.is_empty() {
            lines.push(Line {
                line_number,
                tokens,
            });
        }
    }

    lines
}

/// Tokenizes a single line of input according to `HAProxy` rules.
fn lex_line(raw_line: &str, line_number: usize) -> Vec<Token> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = raw_line.chars().collect();
    let len = chars.len();
    let mut idx = 0;

    // Scan until comment or end of line (respecting quotes)
    let mut end_idx = len;
    let mut in_quote = None;
    let mut esc = false;
    for (i, &ch) in chars.iter().enumerate() {
        if esc {
            esc = false;
            continue;
        }
        if ch == '\\' {
            esc = true;
            continue;
        }
        if let Some(q) = in_quote {
            if ch == q {
                in_quote = None;
            }
        } else if ch == '"' || ch == '\'' {
            in_quote = Some(ch);
        // Only '#' starts a comment. HAProxy does **not** treat ';' as one -- verified
        // against 3.5-dev7, which rejects a ';' line with
        //   "unknown keyword ';' out of section."
        // Silently swallowing it would let a config that HAProxy refuses run on Ibex,
        // and a line the operator believed was a comment would simply vanish.
        } else if ch == '#' || ch == '\r' || ch == '\n' {
            end_idx = i;
            break;
        }
    }

    while idx < end_idx {
        // Skip whitespace
        while idx < end_idx && is_haproxy_space(chars[idx]) {
            idx += 1;
        }

        if idx >= end_idx {
            break;
        }

        // Start of a token (1-based column)
        let token_col = idx + 1;
        let mut token_text = String::new();
        let mut escaped = false;
        let mut quote_mode = None;

        while idx < end_idx {
            let ch = chars[idx];
            if let Some(q) = quote_mode {
                if escaped {
                    escaped = false;
                    token_text.push(ch);
                    idx += 1;
                } else if ch == '\\' {
                    escaped = true;
                    if idx + 1 < end_idx && chars[idx + 1] == q {
                        // Escaped quote: do not push backslash
                        idx += 1;
                    } else {
                        token_text.push(ch);
                        idx += 1;
                    }
                } else if ch == q {
                    quote_mode = None;
                    idx += 1;
                } else {
                    token_text.push(ch);
                    idx += 1;
                }
            } else if escaped {
                escaped = false;
                token_text.push(ch);
                idx += 1;
            } else if ch == '\\' {
                escaped = true;
                token_text.push(ch);
                idx += 1;
            } else if ch == '"' || ch == '\'' {
                quote_mode = Some(ch);
                idx += 1;
            } else if is_haproxy_space(ch) {
                break;
            } else {
                token_text.push(ch);
                idx += 1;
            }
        }

        tokens.push(Token {
            text: token_text,
            line: line_number,
            col: token_col,
        });
    }

    tokens
}

/// Checks whether a character is treated as whitespace by `HAProxy` 1.0.2 `isspace()`.
#[inline]
fn is_haproxy_space(ch: char) -> bool {
    ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\x0C' || ch == '\x0B'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lex_basic() {
        let input = "listen proxy1 0.0.0.0:3128\n\tmode http\n";
        let lines = lex(input);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].tokens.len(), 3);
        assert_eq!(lines[0].tokens[0].text, "listen");
        assert_eq!(lines[0].tokens[0].col, 1);
        assert_eq!(lines[0].tokens[1].text, "proxy1");
        assert_eq!(lines[0].tokens[1].col, 8);
        assert_eq!(lines[0].tokens[2].text, "0.0.0.0:3128");
        assert_eq!(lines[0].tokens[2].col, 15);

        assert_eq!(lines[1].tokens[0].text, "mode");
        assert_eq!(lines[1].tokens[0].col, 2);
        assert_eq!(lines[1].tokens[1].text, "http");
        assert_eq!(lines[1].tokens[1].col, 7);
    }

    #[test]
    fn test_lex_comments_and_blank_lines() {
        let input = "\n# Full comment line\n  listen p1 # inline comment\n\n";
        let lines = lex(input);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].line_number, 3);
        assert_eq!(lines[0].tokens.len(), 2);
        assert_eq!(lines[0].tokens[0].text, "listen");
        assert_eq!(lines[0].tokens[0].col, 3);
    }

    #[test]
    fn semicolon_is_not_a_comment() {
        // HAProxy 3.5 rejects a ';' line with "unknown keyword ';' out of section."
        // Treating it as a comment would accept configs the reference refuses, and a
        // line the operator believed was commented out would silently disappear.
        let lines = lex("; not a comment\n");
        assert_eq!(lines.len(), 1, "';' must produce a token line, not be skipped");
        assert_eq!(lines[0].tokens[0].text, ";");
    }

    #[test]
    fn test_lex_escaped_spaces() {
        let input = "cliexp ^(Host:\\ [^:]*).* Host:\\ \\1:80";
        let lines = lex(input);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].tokens.len(), 3);
        assert_eq!(lines[0].tokens[0].text, "cliexp");
        assert_eq!(lines[0].tokens[1].text, "^(Host:\\ [^:]*).*");
        assert_eq!(lines[0].tokens[2].text, "Host:\\ \\1:80");
    }

    #[test]
    fn test_lex_mixed_tabs_and_spaces() {
        let input = " \t server \t\t srv1 \t 10.0.0.1:8080 ";
        let lines = lex(input);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].tokens.len(), 3);
        assert_eq!(lines[0].tokens[0].text, "server");
        assert_eq!(lines[0].tokens[1].text, "srv1");
        assert_eq!(lines[0].tokens[2].text, "10.0.0.1:8080");
    }

    #[test]
    fn test_lex_quoted_strings() {
        let input = r#"http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
http-request return status 200 content-type "text/plain" lf-string "OK\n" if { path /healthz }"#;
        let lines = lex(input);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].tokens.len(), 4);
        assert_eq!(lines[0].tokens[0].text, "http-response");
        assert_eq!(lines[0].tokens[1].text, "set-header");
        assert_eq!(lines[0].tokens[2].text, "Strict-Transport-Security");
        assert_eq!(
            lines[0].tokens[3].text,
            "max-age=31536000; includeSubDomains"
        );

        assert_eq!(lines[1].tokens[0].text, "http-request");
        assert_eq!(lines[1].tokens[1].text, "return");
        assert_eq!(lines[1].tokens[2].text, "status");
        assert_eq!(lines[1].tokens[3].text, "200");
        assert_eq!(lines[1].tokens[4].text, "content-type");
        assert_eq!(lines[1].tokens[5].text, "text/plain");
        assert_eq!(lines[1].tokens[6].text, "lf-string");
        assert_eq!(lines[1].tokens[7].text, "OK\\n");
        assert_eq!(lines[1].tokens[8].text, "if");
        assert_eq!(lines[1].tokens[9].text, "{");
        assert_eq!(lines[1].tokens[10].text, "path");
        assert_eq!(lines[1].tokens[11].text, "/healthz");
        assert_eq!(lines[1].tokens[12].text, "}");
    }
}
