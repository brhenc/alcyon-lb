// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Milestone 1 scope (T164, `docs/milestones.md`): the features Ibex leaves out are refused
//! by name at parse time. A keyword the parser recognised and then dropped would leave the
//! operator believing it works (AGENTS.md section 5), so every line goes through
//! [`check`] before the section parsers see it. Listed in `docs/differences.md`.

use crate::error::ConfigError;
use crate::lexer::Token;

fn refuse(tok: &Token, what: &str) -> ConfigError {
    ConfigError::new(
        tok.line,
        tok.col,
        format!("'{what}' is not supported by Ibex (out of scope, see docs/differences.md)"),
    )
}

/// The `lua.*` name used in a sample expression `%[...]` of `text`, if any.
fn lua_in_expression(text: &str) -> Option<String> {
    let mut rest = text;
    while let Some(pos) = rest.find("%[") {
        let after = &rest[pos + 2..];
        let end = after.find(']').unwrap_or(after.len());
        for part in after[..end].split([',', ' ']) {
            if part.starts_with("lua.") {
                return Some(part.split('(').next().unwrap_or(part).to_string());
            }
        }
        rest = &after[end..];
    }
    None
}

/// Refuse `tokens` (one configuration line) when it uses a keyword out of M1 scope.
pub(crate) fn check(tokens: &[Token]) -> Result<(), ConfigError> {
    let Some(kw) = tokens.first() else { return Ok(()) };
    let name = kw.text.as_str();
    match name {
        "lua-load" | "lua-load-per-thread" | "lua-prepend-path" | "ssl-engine" | "ssl-mode-async" | "ssl-propquery"
        | "ssl-provider" | "ssl-provider-path" | "tune.ssl.async" | "filter" | "compression" | "use-service"
        | "use-fcgi-app" | "peers" | "cache" | "fcgi-app" => return Err(refuse(kw, name)),
        _ if name.starts_with("tune.lua.") => return Err(refuse(kw, name)),
        // an action of an HTTP rule (tcp-request already refuses `lua.*`: "lua actions require Lua support")
        "http-request" | "http-response" | "http-after-response" => {
            for tok in tokens.iter().skip(1).take(2) {
                if tok.text.starts_with("lua.") || tok.text == "cache-use" || tok.text == "cache-store" {
                    return Err(refuse(tok, &tok.text));
                }
            }
        }
        "stick-table" => {
            if let Some(tok) = tokens.iter().skip(1).find(|t| t.text == "peers") {
                return Err(refuse(tok, "stick-table ... peers"));
            }
        }
        _ => {}
    }
    for tok in tokens {
        if let Some(fetch) = lua_in_expression(&tok.text) {
            return Err(refuse(tok, &fetch));
        }
    }
    Ok(())
}
