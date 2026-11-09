// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `load-server-state-from-file` and `server-state-file-name` (T490), as `cfg_parse_listen`
//! (src/cfgparse-listen.c) reads them. The file itself is read by `alcyon-rt`
//! `server_state::apply` once the proxies are built.

use super::warn;
use crate::ast::global::WarnStyle;
use crate::ast::LoadServerState;
use crate::error::ConfigError;
use crate::lexer::Token;

/// `load-server-state-from-file global|local|none`; words after the first are not looked at.
pub(crate) fn parse_load(tokens: &[Token], kw: &Token) -> Result<LoadServerState, ConfigError> {
    let word = tokens.get(1).map_or("", |t| t.text.as_str());
    match word {
        "global" => Ok(LoadServerState::Global),
        "local" => Ok(LoadServerState::Local),
        "none" => Ok(LoadServerState::None),
        _ => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("'load-server-state-from-file' expects 'global', 'local' or 'none'. Got '{word}'"),
        )),
    }
}

/// `server-state-file-name [use-backend-name | <file>]` in the section `name`: no word, or
/// `use-backend-name`, is the section's name.
pub(crate) fn parse_file_name(tokens: &[Token], name: &str) -> Result<String, ConfigError> {
    if let Some(extra) = tokens.get(2) {
        return Err(ConfigError::new(
            extra.line,
            extra.col,
            format!("'server-state-file-name' cannot handle unexpected argument '{}'.", extra.text),
        ));
    }
    Ok(match tokens.get(1).map(|t| t.text.as_str()) {
        None | Some("" | "use-backend-name") => name.to_string(),
        Some(file) => file.to_string(),
    })
}

/// Either keyword in a frontend: checked, then `HAProxy`'s warning, and nothing kept.
pub(crate) fn in_frontend(tokens: &[Token], kw: &Token, frontend: &str) -> Result<(), ConfigError> {
    if kw.text == "load-server-state-from-file" {
        parse_load(tokens, kw)?;
    } else {
        parse_file_name(tokens, frontend)?;
    }
    warn::push(kw.line, WarnStyle::Spaced, &format!("'{}' ignored because frontend '{frontend}' has no backend capability.", kw.text));
    Ok(())
}

/// `server-state-file-name` in `defaults`: `HAProxy` accepts it and no backend inherits it
/// (measured), so Alcyon says it does nothing rather than drop it in silence (AGENTS.md §5).
pub(crate) fn file_name_in_defaults(tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    parse_file_name(tokens, "")?;
    warn::push(
        kw.line,
        WarnStyle::Spaced,
        "'server-state-file-name' is ignored in a 'defaults' section (as HAProxy does): set it in the backend.",
    );
    Ok(())
}
