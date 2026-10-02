// SPDX-License-Identifier: GPL-2.0-or-later
//
// `errorfile`, `errorfiles`, `http-errors` and `http-error`: operator-supplied
// replacements for the pages Ibex (like HAProxy) generates itself for a denied request,
// a `http-request return`, or a request HAProxy could not otherwise satisfy.

use std::collections::HashMap;

use super::*;

/// Reads the full contents of an `errorfile <code> <file>`-style file argument, exactly as
/// `HAProxy` does: the file must exist and be readable at config time (files are read before
/// any chroot), and its bytes are kept verbatim -- an empty file (`/dev/null` is the
/// documented idiom) is a valid, deliberately empty response.
pub(crate) fn load_errorfile_bytes(path_tok: &Token) -> Result<Vec<u8>, ConfigError> {
    std::fs::read(&path_tok.text).map_err(|e| {
        ConfigError::new(
            path_tok.line,
            path_tok.col,
            format!("unable to load errorfile '{}': {e}", path_tok.text),
        )
    })
}

/// Parses `errorfile <code> <file>` (in `defaults`/`frontend`/`backend`/`listen`, or inside
/// an `http-errors` section, where `files` is that section's own table).
pub(crate) fn parse_errorfile_directive(
    files: &mut HashMap<u16, Vec<u8>>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 3 {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<errorfile> expects <code> and <file>",
        ));
    }
    let code = parse_u16(&tokens[1], "errorfile code")?;
    let bytes = load_errorfile_bytes(&tokens[2])?;
    files.insert(code, bytes);
    Ok(())
}

/// Parses `errorfiles <name> [<code> ...]`: imports some or all of the error pages
/// declared in the `http-errors <name>` section named `name` into `files`, overriding any
/// entry already present for the same code, exactly as `errorfile` would.
pub(crate) fn parse_errorfiles_directive(
    files: &mut HashMap<u16, Vec<u8>>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<errorfiles> expects an http-errors section name",
        ));
    }
    let name = &tokens[1].text;
    let section = http_errors_section(name).ok_or_else(|| {
        ConfigError::new(
            tokens[1].line,
            tokens[1].col,
            format!("unknown http-errors section '{name}'"),
        )
    })?;
    if tokens.len() > 2 {
        for tok in &tokens[2..] {
            let code = parse_u16(tok, "errorfiles code")?;
            if let Some(bytes) = section.get(&code) {
                files.insert(code, bytes.clone());
            }
        }
    } else {
        for (code, bytes) in section {
            files.insert(code, bytes);
        }
    }
    Ok(())
}

/// Parses `http-error status <code> [content-type <type>] [default-errorfiles |
/// errorfile <file> | errorfiles <name> | file <file> | lf-file <file> | string <str> |
/// lf-string <fmt>] [hdr <name> <fmt>]*`.
///
/// `default-errorfiles` removes any existing override for `<code>` rather than installing
/// one: a later error for that status falls back to `errorfile`/`errorfiles` for the
/// proxy, and ultimately to `HAProxy`'s built-in page, exactly as if `http-error` had never
/// mentioned that code.
pub(crate) fn parse_http_error_directive(
    replies: &mut HashMap<u16, ErrorPageSource>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text != "status" {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<http-error> expects 'status <code>' as argument",
        ));
    }
    let code = parse_u16(&tokens[2], "http-error status")?;
    let (content_type, lf_string, error_page) = parse_error_body_args(tokens, 3, tokens.len(), code)?;
    match error_page {
        Some(ErrorPageSource::DefaultErrorfiles) => {
            replies.remove(&code);
        }
        Some(raw @ ErrorPageSource::Raw(_)) => {
            replies.insert(code, raw);
        }
        Some(ErrorPageSource::Custom { .. }) => unreachable!(
            "parse_error_body_args never returns ErrorPageSource::Custom; only http-error \
             itself builds one, below"
        ),
        None => {
            replies.insert(code, ErrorPageSource::Custom { content_type, lf_string });
        }
    }
    Ok(())
}

/// Parses the arguments shared by `http-request return`, `http-request deny`, and
/// `http-error`: `content-type`, `hdr`, `string`/`lf-string`/`file`/`lf-file`, and the
/// page-selection keywords `default-errorfiles`/`errorfile`/`errorfiles`. `status` is
/// resolved by the caller (it may be needed before this point) and passed in as
/// `status_for_errorfiles`, since `errorfiles <name>` must pick a single status code out of
/// a whole section.
///
/// Returns the content-type, the encoded custom-header/body string (the existing
/// `\0HDR:`/`\0BODY:` convention `http-request return` already produces), and the page
/// source, if any of the page-selection keywords was given.
#[allow(clippy::type_complexity)]
pub(crate) fn parse_error_body_args(
    tokens: &[Token],
    start: usize,
    limit: usize,
    status_for_errorfiles: u16,
) -> Result<(Option<String>, Option<String>, Option<ErrorPageSource>), ConfigError> {
    let mut content_type = None;
    let mut lf_string = None;
    let mut custom_headers: Vec<(String, String)> = Vec::new();
    let mut error_page = None;
    let mut i = start;
    while i < limit {
        match tokens[i].text.as_str() {
            "status" | "deny_status" if i + 1 < limit => {
                i += 2;
            }
            "content-type" if i + 1 < limit => {
                content_type = Some(tokens[i + 1].text.clone());
                i += 2;
            }
            "lf-string" | "string" if i + 1 < limit => {
                lf_string = Some(tokens[i + 1].text.clone());
                i += 2;
            }
            "file" | "lf-file" if i + 1 < limit => {
                let path = &tokens[i + 1].text;
                lf_string = Some(std::fs::read_to_string(path).unwrap_or_default());
                i += 2;
            }
            "hdr" if i + 2 < limit => {
                custom_headers.push((tokens[i + 1].text.clone(), tokens[i + 2].text.clone()));
                i += 3;
            }
            "default-errorfiles" => {
                error_page = Some(ErrorPageSource::DefaultErrorfiles);
                i += 1;
            }
            "errorfile" if i + 1 < limit => {
                error_page = Some(ErrorPageSource::Raw(load_errorfile_bytes(&tokens[i + 1])?));
                i += 2;
            }
            "errorfiles" if i + 1 < limit => {
                let name = &tokens[i + 1].text;
                let bytes = http_errors_section_code(name, status_for_errorfiles).ok_or_else(|| {
                    ConfigError::new(
                        tokens[i + 1].line,
                        tokens[i + 1].col,
                        format!(
                            "http-errors section '{name}' has no errorfile for status {status_for_errorfiles}"
                        ),
                    )
                })?;
                error_page = Some(ErrorPageSource::Raw(bytes));
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    let final_lf_string = if custom_headers.is_empty() {
        lf_string
    } else {
        let mut enc = String::new();
        for (k, v) in custom_headers {
            let _ = writeln!(enc, "\0HDR:{k}:{v}");
        }
        if let Some(s) = lf_string {
            let _ = write!(enc, "\0BODY:{s}");
        }
        Some(enc)
    };

    Ok((content_type, final_lf_string, error_page))
}
