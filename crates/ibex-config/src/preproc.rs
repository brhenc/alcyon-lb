// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use crate::lexer::Line;
use crate::error::ConfigError;
use crate::ast::DirectiveMessage;

fn parse_cond(s: &str) -> Result<bool, crate::cond::CondError> {
    crate::cond::eval_if(s)
}

/// Where a `.if` block stands (`enum nested_cond_state`, `src/cfgparse.c`): which of its
/// branches was taken, dropped, or skipped because the block it is in was.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Branch {
    IfTake,
    IfDrop,
    IfSkip,
    ElifTake,
    ElifDrop,
    ElifSkip,
    ElseTake,
    ElseDrop,
}

impl Branch {
    /// Whether the lines of this branch are left out.
    fn masked(self) -> bool {
        matches!(self, Self::IfDrop | Self::IfSkip | Self::ElifDrop | Self::ElifSkip | Self::ElseDrop)
    }

    /// Whether the branch is an `.else`: nothing may follow it but `.endif`.
    fn is_else(self) -> bool {
        matches!(self, Self::ElseTake | Self::ElseDrop)
    }

    /// Whether a branch before this one (an `.if` or `.elif`) was taken, or the block is
    /// skipped altogether: what follows is dropped without being looked at.
    fn settled(self) -> bool {
        matches!(self, Self::IfTake | Self::IfSkip | Self::ElifTake | Self::ElifSkip)
    }
}

/// `MAXNESTEDCONDS`: the deepest `.if` there can be (`include/haproxy/cfgcond-t.h`).
const MAX_NESTED_CONDS: usize = 100;

/// Preprocesses the tokenized lines, resolving `.if`, `.elif`, `.else`, `.endif` blocks.
///
/// # Errors
///
/// Returns [`ConfigError`] if:
/// - A conditional directive fails to parse or contains an unknown function
/// - A `.elif`, `.else`, or `.endif` directive occurs without a preceding `.if`, or a
///   `.elif` or `.else` comes after an `.else`
/// - An `.if` block remains unterminated at the end of the input
pub fn preprocess(lines: Vec<Line>) -> Result<Vec<Line>, ConfigError> {
    preprocess_with_messages(lines).map(|(out, _)| out)
}

/// [`preprocess`], and the `.warning` and `.notice` directives that were in force.
///
/// `.alert` is fatal, as in `HAProxy`; `.diag` says nothing unless diagnostics are asked
/// for (`-dD`), which Ibex does not have, so it is dropped. A directive takes at most one
/// argument, its message.
///
/// # Errors
///
/// As [`preprocess`], and for an `.alert` or a message directive with too many arguments.
pub fn preprocess_with_messages(lines: Vec<Line>) -> Result<(Vec<Line>, Vec<DirectiveMessage>), ConfigError> {
    let mut messages = Vec::new();
    let mut out = Vec::new();
    let mut blocks: Vec<Branch> = Vec::new();

    let last_line = lines.last().map_or(1, |l| l.line_number);

    for line in lines {
        if line.tokens.is_empty() {
            continue;
        }

        let first = line.tokens[0].text.as_str();
        let at = |col: usize, msg: String| ConfigError::new(line.line_number, col, msg);
        let words_after_first = || line.tokens[1..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");

        match first {
            ".if" => {
                if blocks.len() >= MAX_NESTED_CONDS {
                    return Err(at(line.tokens[0].col, format!("too many nested '.if', max is {MAX_NESTED_CONDS}.")));
                }
                // Inside a block that is left out, the condition is not evaluated.
                if blocks.last().is_some_and(|b| b.masked()) {
                    blocks.push(Branch::IfSkip);
                    continue;
                }
                let cond = words_after_first();
                let taken = parse_cond(&cond)
                    .map_err(|e| at(line.tokens[0].col, crate::cond::describe_error(".if", &cond, &e)))?;
                blocks.push(if taken { Branch::IfTake } else { Branch::IfDrop });
            }
            ".elif" => {
                let Some(&top) = blocks.last() else {
                    return Err(at(line.tokens[0].col, "lone '.elif' with no matching '.if'.".into()));
                };
                if top.is_else() {
                    return Err(at(line.tokens[0].col, "'.elif' after '.else' is not permitted.".into()));
                }
                let state = if top.settled() {
                    Branch::ElifSkip
                } else {
                    let cond = words_after_first();
                    let taken = parse_cond(&cond)
                        .map_err(|e| at(line.tokens[0].col, crate::cond::describe_error(".elif", &cond, &e)))?;
                    if taken { Branch::ElifTake } else { Branch::ElifDrop }
                };
                *blocks.last_mut().unwrap_or(&mut Branch::IfSkip) = state;
            }
            ".else" | ".endif" => {
                if let Some(extra) = line.tokens.get(1) {
                    return Err(at(extra.col, format!("Unexpected argument '{}' for '{first}'.", extra.text)));
                }
                let Some(&top) = blocks.last() else {
                    return Err(at(line.tokens[0].col, format!("lone '{first}' with no matching '.if'.")));
                };
                if first == ".endif" {
                    blocks.pop();
                } else if top.is_else() {
                    return Err(at(line.tokens[0].col, "'.else' after '.else' is not permitted.".into()));
                } else {
                    *blocks.last_mut().unwrap_or(&mut Branch::IfSkip) =
                        if top.settled() { Branch::ElseDrop } else { Branch::ElseTake };
                }
            }
            _ if blocks.last().is_some_and(|b| b.masked()) => {}
            ".diag" | ".notice" | ".warning" | ".alert" => {
                if let Some(extra) = line.tokens.get(2) {
                    return Err(at(
                        extra.col,
                        format!("Unexpected argument '{}' for '{first}'. Use quotes if the message should contain spaces.", extra.text),
                    ));
                }
                let text = line.tokens.get(1).map(|t| t.text.clone()).unwrap_or_default();
                match first {
                    ".alert" => return Err(at(line.tokens[0].col, format!("'{text}'."))),
                    ".diag" => {}
                    _ => messages.push(DirectiveMessage { warning: first == ".warning", line: line.line_number, text }),
                }
            }
            _ if first.starts_with('.') => {
                return Err(at(line.tokens[0].col, format!("unknown directive '{first}'.")));
            }
            _ => out.push(line),
        }
    }

    if !blocks.is_empty() {
        return Err(ConfigError::new(last_line, 1, "non-terminated '.if' block."));
    }

    Ok((out, messages))
}
