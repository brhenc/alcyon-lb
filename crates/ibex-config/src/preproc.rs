// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use crate::lexer::Line;
use crate::error::ConfigError;

fn parse_cond(s: &str) -> Result<bool, String> {
    crate::cond::eval_if(s)
}

/// Preprocesses the tokenized lines, resolving `.if`, `.elif`, `.else`, `.endif` blocks.
///
/// # Errors
///
/// Returns [`ConfigError`] if:
/// - A conditional directive fails to parse or contains an unknown function
/// - A `.elif`, `.else`, or `.endif` directive occurs without a preceding `.if`
/// - An `.if` block remains unterminated at the end of the input
pub fn preprocess(lines: Vec<Line>) -> Result<Vec<Line>, ConfigError> {
    let mut out = Vec::new();
    let mut if_stack: Vec<bool> = Vec::new();
    let mut if_done: Vec<bool> = Vec::new();

    let last_line = lines.last().map_or(1, |l| l.line_number);

    for line in lines {
        if line.tokens.is_empty() {
            continue;
        }

        let first = &line.tokens[0].text;
        
        match first.as_str() {
            ".if" => {
                let cond_str = line.tokens[1..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");
                let active = if_stack.last().copied().unwrap_or(true);
                let mut cond_val = false;
                if active {
                    cond_val = parse_cond(&cond_str).map_err(|e| ConfigError::new(line.line_number, line.tokens[0].col, e))?;
                }
                if_stack.push(active && cond_val);
                if_done.push(active && cond_val);
            }
            ".elif" => {
                let Some(done) = if_done.last_mut() else {
                    return Err(ConfigError::new(line.line_number, line.tokens[0].col, ".elif without .if"));
                };
                let active_parent = if if_stack.len() > 1 { if_stack[if_stack.len() - 2] } else { true };
                let cond_str = line.tokens[1..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");
                
                let mut cond_val = false;
                if active_parent && !*done {
                    cond_val = parse_cond(&cond_str).map_err(|e| ConfigError::new(line.line_number, line.tokens[0].col, e))?;
                }
                
                let Some(current_stack) = if_stack.last_mut() else {
                    return Err(ConfigError::new(line.line_number, line.tokens[0].col, ".elif without .if"));
                };
                if active_parent && !*done && cond_val {
                    *current_stack = true;
                    *done = true;
                } else {
                    *current_stack = false;
                }
            }
            ".else" => {
                let Some(done) = if_done.last_mut() else {
                    return Err(ConfigError::new(line.line_number, line.tokens[0].col, ".else without .if"));
                };
                let active_parent = if if_stack.len() > 1 { if_stack[if_stack.len() - 2] } else { true };
                
                let Some(current_stack) = if_stack.last_mut() else {
                    return Err(ConfigError::new(line.line_number, line.tokens[0].col, ".else without .if"));
                };
                if active_parent && !*done {
                    *current_stack = true;
                    *done = true;
                } else {
                    *current_stack = false;
                }
            }
            ".endif" => {
                if if_stack.is_empty() {
                    return Err(ConfigError::new(line.line_number, line.tokens[0].col, ".endif without .if"));
                }
                if_stack.pop();
                if_done.pop();
            }
            ".diag" | ".notice" | ".warning" | ".alert" => {
                // Informational directives are dropped from the parsed tree,
                // matching the instruction to skip them cleanly.
            }
            _ => {
                if if_stack.last().copied().unwrap_or(true) {
                    out.push(line);
                }
            }
        }
    }

    if !if_stack.is_empty() {
        return Err(ConfigError::new(last_line, 1, "non-terminated '.if' block."));
    }

    Ok(out)
}
