// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use crate::lexer::Line;
use crate::error::ConfigError;

fn parse_cond(s: &str, directive: &str, opts: &crate::cond::EnabledOpts) -> Result<bool, String> {
    crate::cond::eval_if(s, directive, opts)
}

/// The words that open a section: what ends the `global` one.
const SECTIONS: &[&str] = &[
    "global", "defaults", "frontend", "backend", "listen", "userlist", "peers", "resolvers", "ring", "cache",
    "mailers", "program", "http-errors", "fcgi-app", "log-forward", "crt-store", "acme", "traces", "vars",
];

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
    // What `enabled()` reads: the `global` lines read so far, in the branches taken.
    let mut opts = crate::cond::EnabledOpts::default();
    let mut in_global = false;

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
                    cond_val = parse_cond(&cond_str, ".if", &opts).map_err(|e| ConfigError::new(line.line_number, line.tokens[0].col, e))?;
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
                    cond_val = parse_cond(&cond_str, ".elif", &opts).map_err(|e| ConfigError::new(line.line_number, line.tokens[0].col, e))?;
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
                    if SECTIONS.contains(&first.as_str()) {
                        in_global = first == "global";
                    } else if in_global {
                        let words: Vec<&str> = line.tokens.iter().map(|t| t.text.as_str()).collect();
                        opts.global_line(&words);
                    }
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
