// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use super::*;

pub(crate) fn parse_stats_directive(
    stats: &mut StatsConfig,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 {
        stats.enable = true;
        return Ok(());
    }
    match tokens[1].text.as_str() {
        "uri" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<stats uri> expects <path>.",
                ));
            }
            stats.enable = true;
            stats.uri = Some(tokens[2].text.clone());
            Ok(())
        }
        "refresh" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<stats refresh> expects <interval>.",
                ));
            }
            stats.refresh = Some(parse_timeout(&tokens[2], "stats refresh")?);
            Ok(())
        }
        "admin" => {
            stats.admin = true;
            if tokens.len() >= 4 && (tokens[2].text == "if" || tokens[2].text == "unless") {
                let cond = parse_acl_condition_from_tokens(&tokens[2..])?;
                stats.admin_cond = cond;
            }
            Ok(())
        }
        "show-legends" => {
            stats.show_legends = true;
            Ok(())
        }
        "show-desc" => {
            if tokens.len() >= 3 {
                stats.show_desc = Some(
                    tokens[2..]
                        .iter()
                        .map(|t| t.text.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                        .into(),
                );
            }
            Ok(())
        }
        "show-node" => {
            // No name: the host name, which the stats page looks up (stored as "").
            let name = tokens.get(2).map_or("", |t| t.text.as_str());
            if !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "'stats show-node' invalid node name - should be a stringwith digits(0-9), letters(A-Z, a-z), hyphen(-) or underscode(_).",
                ));
            }
            stats.show_node = Some(name.into());
            Ok(())
        }
        _ => {
            stats.enable = true;
            Ok(())
        }
    }
}

