use crate::lexer::Line;
use crate::error::ConfigError;

/// Evaluates a condition string for a conditional block.
fn parse_cond(mut s: &str) -> Result<bool, String> {
    s = s.trim();
    if let Some(rest) = s.strip_prefix('!') {
        return Ok(!parse_cond(rest)?);
    }
    
    let paren_idx = s.find('(').ok_or_else(|| format!("unparsable conditional expression '{s}'"))?;
    let func_name = s[..paren_idx].trim();
    let end_idx = s.rfind(')').ok_or_else(|| format!("unparsable conditional expression '{s}'"))?;
    if end_idx < paren_idx {
        return Err(format!("unparsable conditional expression '{s}'"));
    }
    let args_str = &s[paren_idx + 1 .. end_idx];
    
    let args: Vec<&str> = args_str.split(',').map(str::trim).collect();
    
    match func_name {
        "feature" => {
            if args.len() != 1 { return Err("feature requires 1 argument".into()); }
            let feature = args[0];
            // Ibex supports THREAD. Others (QUIC, LUA, OPENSSL, etc.) are absent.
            Ok(feature == "THREAD")
        }
        "streq" => {
            if args.len() != 2 { return Err("streq requires 2 arguments".into()); }
            let a = expand_vars(args[0]);
            let b = expand_vars(args[1]);
            Ok(a == b)
        }
        "strneq" => {
            if args.len() != 2 { return Err("strneq requires 2 arguments".into()); }
            let a = expand_vars(args[0]);
            let b = expand_vars(args[1]);
            Ok(a != b)
        }
        "defined" => {
            if args.len() != 1 { return Err("defined requires 1 argument".into()); }
            let var = args[0];
            Ok(std::env::var(var).is_ok())
        }
        "ssllib_name_startswith" | "openssl_version_atleast" | "openssl_version_before" => {
            // Ibex uses rustls, so these OpenSSL specific features are absent.
            Ok(false)
        }
        _ => Err(format!("unparsable conditional expression '{s}'")),
    }
}

fn expand_vars(s: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '$' {
            i += 1;
            let mut var_name = String::new();
            let mut has_brace = false;
            if i < chars.len() && chars[i] == '{' {
                has_brace = true;
                i += 1;
            }
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                var_name.push(chars[i]);
                i += 1;
            }
            if has_brace && i < chars.len() && chars[i] == '}' {
                i += 1;
            }
            if let Ok(val) = std::env::var(&var_name) {
                out.push_str(&val);
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
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
