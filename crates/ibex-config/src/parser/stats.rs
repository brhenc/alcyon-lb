// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use super::*;
use crate::ast::WarnStyle;

pub(crate) fn parse_stats_directive(
    stats: &mut StatsConfig,
    tokens: &[Token],
    kw: &Token,
    in_defaults: bool,
) -> Result<(), ConfigError> {
    if !in_defaults {
        stats.detach();
    }
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
            // The unit is seconds when none is given (`stats refresh 5` is 5s on HAProxy).
            let mut interval = tokens[2].clone();
            if interval.text.bytes().all(|b| b.is_ascii_digit()) {
                interval.text.push('s');
            }
            stats.refresh = Some(parse_timeout(&interval, "stats refresh")?);
            Ok(())
        }
        "admin" if in_defaults => Err(ConfigError::new(kw.line, kw.col, "'stats admin' not allowed in 'defaults' section.")),
        "http-request" if in_defaults => Err(ConfigError::new(kw.line, kw.col, "'stats' not allowed in 'defaults' section.")),
        "admin" => {
            stats.admin = true;
            if tokens.len() >= 4 && (tokens[2].text == "if" || tokens[2].text == "unless") {
                let cond = parse_acl_condition_from_tokens(&tokens[2..])?;
                stats.admin_rules.push(cond);
            } else {
                stats.admin_rules.push(None);
            }
            Ok(())
        }
        "show-legends" => {
            stats.show_legends = true;
            Ok(())
        }
        "show-desc" => {
            // No text: `global description`, which the stats page looks up (stored as "").
            stats.show_desc = Some(tokens[2.min(tokens.len())..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ").into());
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
        "enable" => {
            stats.enable = true;
            Ok(())
        }
        "auth" => {
            let Some(account) = tokens.get(2) else {
                return Err(ConfigError::new(kw.line, kw.col, "'auth' needs a user:password account."));
            };
            // `stats_add_auth`: the password is what follows the first colon, none is empty.
            let (user, pass) = account.text.split_once(':').unwrap_or((account.text.as_str(), ""));
            if stats.auth.get_or_insert_default().users.iter().any(|(u, _)| &**u == user) {
                warn::push(kw.line, WarnStyle::Spaced, &format!("uri auth: ignoring duplicated user '{user}'."));
            } else {
                stats.auth.get_or_insert_default().users.push((user.into(), pass.into()));
            }
            Ok(())
        }
        "realm" => {
            let Some(realm) = tokens.get(2) else {
                return Err(ConfigError::new(kw.line, kw.col, "'realm' needs an realm name."));
            };
            stats.auth.get_or_insert_default().realm = Some(realm.text.as_str().into());
            Ok(())
        }
        "hide-version" => {
            stats.auth.get_or_insert_default().show_version = false;
            Ok(())
        }
        "show-version" => {
            stats.auth.get_or_insert_default().show_version = true;
            Ok(())
        }
        "http-request" => {
            if stats.auth.get_or_insert_default().http_req_rules.last().is_some_and(|r| r.cond.is_none()) {
                warn::push(kw.line, WarnStyle::Tight, "previous 'stats' action has no condition attached, further entries are NOOP.");
            }
            let before = stats.auth.get_or_insert_default().http_req_rules.len();
            parse_http_req_rule(&mut stats.auth.get_or_insert_default().http_req_rules, &tokens[1..], kw)?;
            // The stats page answers allow, deny and auth; any other action would parse and do
            // nothing there (AGENTS.md rule 5).
            for r in &stats.auth.get_or_insert_default().http_req_rules[before..] {
                let plain = match &r.action {
                    HttpReqAction::Allow | HttpReqAction::Auth { .. } => true,
                    HttpReqAction::Deny { content_type, lf_string, error_page, .. } => {
                        content_type.is_none() && lf_string.is_none() && matches!(error_page, None | Some(ErrorPageSource::DefaultErrorfiles))
                    }
                    _ => false,
                };
                if !plain {
                    stats.auth.get_or_insert_default().http_req_rules.truncate(before);
                    return Err(ConfigError::new(
                        kw.line,
                        kw.col,
                        "'stats http-request' supports only 'allow', 'auth' and 'deny [deny_status <code>]' in Ibex.",
                    ));
                }
            }
            Ok(())
        }
        // HAProxy's, which Ibex does not implement: refused rather than dropped.
        w @ ("scope" | "show-modules") => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("'stats {w}' is not implemented: Ibex would serve the stats page without it."),
        )),
        w => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!(
                "unknown stats parameter '{w}', expects 'admin', 'uri', 'realm', 'auth', 'scope', 'enable', 'hide-version', \
                 'show-node', 'show-desc' , 'show-legends' or 'show-version'."
            ),
        )),
    }
}


/// `stats auth` becomes, as in HAProxy's `check_config_validity`, the rule
/// `http-request auth [realm <realm>] unless { http_auth(<its userlist>) }` appended to the
/// `stats http-request` rules, over a userlist of the accounts. `stats auth` or `realm`
/// together with `stats http-request` is refused.
pub(crate) fn finish_stats_auth(
    listens: &mut [ListenSection],
    frontends: &mut [FrontendSection],
    backends: &mut [BackendSection],
) -> Result<(), ConfigError> {
    let all = listens
        .iter_mut()
        .map(|p| (&p.name, &mut p.stats))
        .chain(frontends.iter_mut().map(|p| (&p.name, &mut p.stats)))
        .chain(backends.iter_mut().map(|p| (&p.name, &mut p.stats)));
    for (name, stats) in all {
        let Some(auth) = stats.auth.as_deref_mut() else { continue };
        if auth.users.is_empty() && auth.realm.is_none() {
            continue;
        }
        if !auth.http_req_rules.is_empty() {
            return Err(ConfigError::new(
                0,
                0,
                format!("proxy '{name}': stats 'auth'/'realm' and 'http-request' can't be used at the same time."),
            ));
        }
        if auth.users.is_empty() {
            continue;
        }
        let list = format!(".internal-stats-userlist.{name}");
        register_userlist(Userlist {
            name: list.clone(),
            users: auth
                .users
                .iter()
                .map(|(u, p)| UserlistUser { name: u.to_string(), password: Some(p.to_string()), password_is_hash: false, groups: Vec::new() })
                .collect(),
            ..Userlist::default()
        });
        auth.http_req_rules.push(HttpReqRule {
            action: HttpReqAction::Auth { realm: auth.realm.as_deref().map(str::to_string) },
            cond: Some(AclCondition {
                is_if: false,
                terms: vec![AclTerm { negated: false, name: format!("{{ http_auth({list}) }}") }],
            }),
            line: 0,
        });
    }
    Ok(())
}
