// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use super::*;

pub(crate) fn parse_stick_table(
    table: &mut Option<StickTableConfigAst>,
    tokens: &[Token],
    _kw: &Token,
) -> Result<(), ConfigError> {
    let mut key_type = "ip".to_string();
    let mut size = 100_000usize;
    let mut expire = Duration::from_secs(300);
    let mut store_fields = Vec::new();

    let mut i = 1;
    while i < tokens.len() {
        match tokens[i].text.as_str() {
            "type" => {
                i += 1;
                if i < tokens.len() {
                    key_type.clone_from(&tokens[i].text);
                }
            }
            "size" => {
                i += 1;
                if i < tokens.len() {
                    size = parse_size(&tokens[i])?;
                }
            }
            "expire" => {
                i += 1;
                if i < tokens.len() {
                    expire = parse_timeout(&tokens[i], "expire")?;
                }
            }
            "store" => {
                i += 1;
                if i < tokens.len() {
                    store_fields.extend(split_store_fields(&tokens[i].text));
                }
            }
            _ => {}
        }
        i += 1;
    }

    check_store_fields(&store_fields).map_err(|m| ConfigError::new(_kw.line, _kw.col, format!("stick-table: {m}")))?;

    *table = Some(StickTableConfigAst {
        key_type,
        size,
        expire,
        store_fields,
    });
    Ok(())
}

pub(crate) fn parse_stick_rule(
    rules: &mut Vec<StickRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text.is_empty() || tokens[2].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<stick> expects <action> and <sample> as arguments.",
        ));
    }
    let rule_type = match tokens[1].text.as_str() {
        "on" => StickRuleType::StickOn,
        "match" => StickRuleType::StickMatch,
        "store-request" => StickRuleType::StickStoreRequest,
        "store-response" => StickRuleType::StickStoreResponse,
        other => {
            return Err(ConfigError::new(
                tokens[1].line,
                tokens[1].col,
                format!("unknown stick action <{other}>"),
            ));
        }
    };
    let expr_tokens: Vec<&str> = tokens[2..].iter().map(|t| t.text.as_str()).collect();
    let expr = expr_tokens.join(" ");
    rules.push(StickRule { rule_type, expr });
    Ok(())
}

pub(crate) fn parse_track_rule(
    rules: &mut Vec<StickRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("<{}> expects <sample> as argument.", kw.text),
        ));
    }
    let rule_type = match kw.text.as_str() {
        "track-sc1" => StickRuleType::TrackSc1,
        "track-sc2" => StickRuleType::TrackSc2,
        _ => StickRuleType::TrackSc0,
    };
    let expr_tokens: Vec<&str> = tokens[1..].iter().map(|t| t.text.as_str()).collect();
    let expr = expr_tokens.join(" ");
    rules.push(StickRule { rule_type, expr });
    Ok(())
}


/// The data types of a `store` argument: split on the commas outside parentheses, so that
/// `gpc_rate(3,10s)` is one field.
fn split_store_fields(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut cur = String::new();
    for c in text.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    out.push(cur);
    out.into_iter().map(|f| f.trim().to_string()).filter(|f| !f.is_empty()).collect()
}

/// The `store` data types `HAProxy` knows (`stktable_data_types`), with what each takes in
/// parentheses: nothing, a period, a size, or a size and a period.
const STORE_TYPES: &[(&str, Arg)] = &[
    ("server_id", Arg::None),
    ("gpc0", Arg::None),
    ("gpc0_rate", Arg::Period),
    ("gpc1", Arg::None),
    ("gpc1_rate", Arg::Period),
    ("gpc", Arg::Array),
    ("gpc_rate", Arg::ArrayPeriod),
    ("gpt0", Arg::None),
    ("gpt", Arg::Array),
    ("conn_cnt", Arg::None),
    ("conn_cur", Arg::None),
    ("conn_rate", Arg::Period),
    ("sess_cnt", Arg::None),
    ("sess_rate", Arg::Period),
    ("http_req_cnt", Arg::None),
    ("http_req_rate", Arg::Period),
    ("http_err_cnt", Arg::None),
    ("http_err_rate", Arg::Period),
    ("http_fail_cnt", Arg::None),
    ("http_fail_rate", Arg::Period),
    ("bytes_in_cnt", Arg::None),
    ("bytes_in_rate", Arg::Period),
    ("bytes_out_cnt", Arg::None),
    ("bytes_out_rate", Arg::Period),
    ("glitch_cnt", Arg::None),
    ("glitch_rate", Arg::Period),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Arg {
    None,
    Period,
    Array,
    ArrayPeriod,
}

/// What `stktable_parse_type` and `parse_stick_table` refuse in a `store` list, in `HAProxy`'s
/// words (measured on 3.5-dev8-885761-29): an unknown type, a rate without its period, an array
/// of a size out of 1 to 100, and the legacy `gpc0`, `gpc1`, `gpt0` and their rates beside the
/// array form that overrides them. Dropping one the parser did not know would leave the operator
/// believing the table stores it.
fn check_store_fields(fields: &[String]) -> Result<(), String> {
    for f in fields {
        let (name, args) = f.split_once('(').map_or((f.as_str(), None), |(n, a)| (n, Some(a.trim_end_matches(')'))));
        let Some((_, kind)) = STORE_TYPES.iter().find(|(n, _)| *n == name) else {
            return Err(format!("unknown store option '{name}'."));
        };
        let missing = || format!("missing argument to store option '{name}'.");
        match (kind, args) {
            (Arg::None, _) => {}
            (_, None) => return Err(missing()),
            (Arg::Period, Some(a)) if a.is_empty() => return Err(missing()),
            (Arg::Array | Arg::ArrayPeriod, Some(a)) => {
                let size = a.split(',').next().unwrap_or("");
                if !matches!(size.parse::<usize>(), Ok(1..=100)) {
                    return Err(format!("array size is out of allowed range (1-100) for store option '{name}'."));
                }
                if *kind == Arg::ArrayPeriod && !a.contains(',') {
                    return Err(missing());
                }
            }
            _ => {}
        }
    }
    let has = |n: &[&str]| fields.iter().any(|f| n.contains(&f.split('(').next().unwrap_or("")));
    let clash = |array: &str, legacy: &[&str], shown: &str| {
        (has(&[array]) && has(legacy))
            .then(|| format!("simultaneous usage of '{array}' and '{shown}' in a same table is not permitted as '{array}' overrides '{shown}'."))
    };
    if let Some(m) = clash("gpc", &["gpc0", "gpc1"], "gpc[0/1]")
        .or_else(|| clash("gpc_rate", &["gpc0_rate", "gpc1_rate"], "gpc[0/1]_rate"))
        .or_else(|| clash("gpt", &["gpt0"], "gpt0"))
    {
        return Err(m);
    }
    Ok(())
}
