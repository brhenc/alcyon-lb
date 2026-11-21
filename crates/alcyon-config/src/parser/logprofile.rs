// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//
// `log-profile` sections, as parsed by `HAProxy`'s `cfg_parse_log_profile`
// (`src/log.c`): a named set of `on <step> [drop] [format <fmt>] [sd <sd_fmt>]`
// lines that a `log ... profile <name>` target uses for each step of a stream.

use crate::ast::{LogProfileSection, LogProfileStep, LogProfileStepKind};
use crate::error::ConfigError;
use crate::lexer::Token;

/// The characters a `log-profile` name may not hold, as `HAProxy`'s `invalid_char` says of a
/// `log-forward` name: letters, digits and `_`, `-`, `.`, `:` only.
fn invalid_char(name: &str) -> Option<char> {
    name.chars().find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':')))
}

/// `on <step> ...`: the multi-line error `HAProxy` prints for a step it does not know, the
/// seven native steps first and then the extra `do-log` origins in the order they register.
fn bad_step_error() -> String {
    let mut extra = String::new();
    for k in LogProfileStepKind::ALL.iter().skip(7) {
        if !extra.is_empty() {
            extra.push_str(", ");
        }
        extra.push_str(&format!("'{}'", k.name()));
    }
    format!(
        "'on' expects a log step.\n\
         expected values are: 'accept', 'request', 'connect', 'response', 'close', 'error' or 'any'.\n\
         Or one of the additional log steps: {extra}."
    )
}

/// The steps a name is one of; the seven native, then the extra `do-log` origins.
fn step_from_name(name: &str) -> Option<LogProfileStepKind> {
    LogProfileStepKind::ALL.iter().copied().find(|k| k.name() == name)
}

/// `log-profile <name>`: a new named section, refused when the name is taken or not a name.
///
/// A name `HAProxy` already knows is an error that names the line the first section was
/// declared at; the `Parsing [file:line]:` frame the message is printed in is the current
/// line's, added where the error is reported.
pub(crate) fn parse_log_profile_header(
    tokens: &[Token],
    kw: &Token,
    existing: &[LogProfileSection],
) -> Result<LogProfileSection, ConfigError> {
    let Some(name) = tokens.get(1).filter(|t| !t.text.is_empty()) else {
        return Err(ConfigError::new(kw.line, kw.col, "missing name for log-profile section."));
    };
    if let Some(c) = invalid_char(&name.text) {
        return Err(ConfigError::new(
            name.line,
            name.col,
            format!(
                "character '{c}' is not permitted in 'log-profile' name '{}'.",
                name.text
            ),
        ));
    }
    if let Some(prev) = existing.iter().find(|l| l.name == name.text).map(|l| l.line) {
        return Err(ConfigError::new(
            name.line,
            name.col,
            format!(
                "log-profile section '{}' has the same name as another log-profile section declared at line {prev}.",
                name.text
            ),
        ));
    }
    Ok(LogProfileSection {
        name: name.text.clone(),
        line: kw.line,
        log_tag: None,
        steps: Vec::new(),
        format_strings: Vec::new(),
    })
}

/// The `log-tag` and `on` lines of a section; anything else is refused as `HAProxy` does.
pub(crate) fn parse_log_profile_directive(
    section: &mut LogProfileSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    match kw.text.as_str() {
        "log-tag" => {
            let Some(tag) = tokens.get(1).filter(|t| !t.text.is_empty()) else {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "'log-tag' expects a tag for use in syslog.",
                ));
            };
            section.log_tag = Some(tag.text.clone());
            Ok(())
        }
        "on" => parse_on_line(section, tokens, kw),
        other => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("unknown keyword '{other}' in log-profile section."),
        )),
    }
}

/// `on <step> [drop] [format <fmt>] [sd <sd_fmt>]`, `HAProxy`'s step parse.
///
/// `drop` is only a word right after the step; a `format` or `sd` then clears it, so a line
/// that gives both keeps the format and drops nothing. A step named again reuses its entry:
/// the later `format`/`sd` replace the earlier, and `drop` is whatever the last line leaves.
fn parse_on_line(
    section: &mut LogProfileSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    let Some(step_tok) = tokens.get(1).filter(|t| !t.text.is_empty()) else {
        return Err(ConfigError::new(kw.line, kw.col, bad_step_error()));
    };
    let Some(step) = step_from_name(&step_tok.text) else {
        return Err(ConfigError::new(step_tok.line, step_tok.col, bad_step_error()));
    };

    let mut drop = false;
    let mut format = None;
    let mut sd = None;
    let mut parsed_formats = Vec::new();
    let mut i = 2usize;
    // The loop `HAProxy` runs: `drop` only as the first word, then `format`/`sd`, each
    // clearing `drop`; anything else, or a `format`/`sd` with no string, ends it and is an
    // error below.
    while i < tokens.len() {
        match tokens[i].text.as_str() {
            "drop" => {
                if i != 2 {
                    break;
                }
                drop = true;
                i += 1;
            }
            "format" => {
                let Some(fmt) = tokens.get(i + 1).filter(|t| !t.text.is_empty()) else {
                    return Err(ConfigError::new(
                        tokens[i].line,
                        tokens[i].col,
                        format!("'on {}' expects a logformat string.", step.name()),
                    ));
                };
                parsed_formats.push((tokens[i].line, fmt.text.clone()));
                format = Some(fmt.text.clone());
                drop = false;
                i += 2;
            }
            "sd" => {
                let Some(fmt) = tokens.get(i + 1).filter(|t| !t.text.is_empty()) else {
                    return Err(ConfigError::new(
                        tokens[i].line,
                        tokens[i].col,
                        format!("'on {}' expects a logformat string.", step.name()),
                    ));
                };
                parsed_formats.push((tokens[i].line, fmt.text.clone()));
                sd = Some(fmt.text.clone());
                drop = false;
                i += 2;
            }
            _ => break,
        }
    }
    if i == 2 || i < tokens.len() {
        // Nothing after the step, or a word the loop did not take.
        return Err(ConfigError::new(
            tokens[i.min(tokens.len() - 1)].line,
            tokens[i.min(tokens.len() - 1)].col,
            format!("'on {}' expects 'drop', 'format' or 'sd'.", step.name()),
        ));
    }

    section.format_strings.extend(parsed_formats);

    // A step named again replaces what the earlier line set: `HAProxy` re-parses the step's
    // entry, so the fields the new line gives win and the ones it does not give are cleared.
    match section.steps.iter_mut().find(|s| s.step == step) {
        Some(s) => {
            s.drop = drop;
            s.format = format;
            s.sd = sd;
        }
        None => section
            .steps
            .push(LogProfileStep { step, drop, format, sd }),
    }
    Ok(())
}
