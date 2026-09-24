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
                    let fields: Vec<String> = tokens[i]
                        .text
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    store_fields.extend(fields);
                }
            }
            _ => {}
        }
        i += 1;
    }

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

