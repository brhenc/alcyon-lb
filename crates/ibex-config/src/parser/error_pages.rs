// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//
// `errorfile`, `errorfiles`, `http-errors` and `http-error`: operator-supplied
// replacements for the pages Ibex (like HAProxy) generates itself for a denied request,
// a `http-request return`, or a request HAProxy could not otherwise satisfy.

use std::collections::HashMap;

use super::*;

thread_local! {
    /// `tune.bufsize` as the parse has read it so far (`global` comes first): what a reply
    /// file or an errorfile is measured against.
    static BUFSIZE: std::cell::Cell<usize> = const { std::cell::Cell::new(16384) };
}

/// Starts a parse with `HAProxy`'s default buffer size.
pub(crate) fn reset_bufsize() {
    BUFSIZE.with(|c| c.set(16384));
}

/// `tune.bufsize` was set (already rounded).
pub(crate) fn set_bufsize(n: usize) {
    BUFSIZE.with(|c| c.set(n));
}

fn bufsize() -> usize {
    BUFSIZE.with(std::cell::Cell::get)
}

/// The body of a `file`/`lf-file` argument of `return`/`deny`/`http-error`
/// (`http_load_file`/`http_parse_http_reply`): it must open, and fit the buffer. `rule` is
/// whether a rule is being parsed, whose messages end with a dot.
fn load_reply_file(tok: &Token, rule: bool) -> Result<String, ConfigError> {
    let dot = if rule { "." } else { "" };
    let path = &tok.text;
    let bytes = std::fs::read(path)
        .map_err(|_| ConfigError::new(tok.line, tok.col, format!("error opening file '{path}'{dot}")))?;
    if bytes.len() > bufsize() {
        return Err(ConfigError::new(
            tok.line,
            tok.col,
            format!("file '{path}' exceeds the buffer size ({} > {}){dot}", bytes.len(), bufsize()),
        ));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Reads the full contents of an `errorfile <code> <file>`-style file argument, exactly as
/// `HAProxy` does: the file must exist and be readable at config time (files are read before
/// any chroot), and its bytes are kept verbatim -- an empty file (`/dev/null` is the
/// documented idiom) is a valid, deliberately empty response.
pub(crate) fn load_errorfile_bytes(path_tok: &Token) -> Result<Vec<u8>, ConfigError> {
    let bytes = std::fs::read(&path_tok.text).map_err(|e| {
        ConfigError::new(
            path_tok.line,
            path_tok.col,
            format!("unable to load errorfile '{}': {e}", path_tok.text),
        )
    })?;
    check_errorfile(&bytes).map_err(|msg| {
        ConfigError::new(path_tok.line, path_tok.col, format!("errorfile : '{}': {msg}", path_tok.text))
    })?;
    Ok(bytes)
}

/// What `http_str_to_htx` (`src/http_htx.c`) refuses in an errorfile: anything but an
/// HTTP response head -- a status line of an 8-character version and a 3-digit status,
/// header lines, the blank line -- and an interim status. The messages are `HAProxy`'s,
/// without the parser's error offset. Ibex loaded such a file and sent its bytes as the
/// reply, a status line no client can read.
const HTX_OVERHEAD: usize = 78;

fn check_errorfile(bytes: &[u8]) -> Result<(), String> {
    const UNPARSABLE: &str = "unable to parse headers";
    if bytes.is_empty() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(bytes);
    // `http_str_to_htx` parses what fits the buffer (a longer file is cut at it) into an
    // HTX message, whose own bookkeeping takes the first 78 bytes of it (measured: with the
    // default 16384, a `HTTP/1.0 400 Bad` file of 16306 bytes is refused, 16305 accepted;
    // 1970 and 1969 at `tune.bufsize 2048`).
    let fits = bytes.len() + HTX_OVERHEAD < bufsize();
    let end = [text.find("\r\n\r\n"), text.find("\n\n")].into_iter().flatten().min().ok_or(UNPARSABLE)?;
    let mut lines = text[..end].split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let mut status_line = lines.next().unwrap_or_default().splitn(3, ' ');
    let version = status_line.next().unwrap_or_default();
    let code = status_line.next().unwrap_or_default();
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UNPARSABLE.to_string());
    }
    let is_token = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?={}".contains(&b));
    if !lines.all(|l| l.split_once(':').is_some_and(|(name, _)| is_token(name))) {
        return Err(UNPARSABLE.to_string());
    }
    if version.len() != 8 {
        return Err(format!("invalid http version ({version})"));
    }
    let status: u16 = code.parse().unwrap_or(0);
    if status == 100 || (102..200).contains(&status) {
        return Err(format!("invalid http status code for an error message ({status})"));
    }
    if !fits {
        let head = end + if text[end..].starts_with("\r\n\r\n") { 4 } else { 2 };
        let what = if head + HTX_OVERHEAD >= bufsize() { "headers" } else { "payload" };
        return Err(format!("unable to add {what} into the HTX message"));
    }
    Ok(())
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

/// Parses `errorloc[302|303] <code> <url>`: like `HAProxy`, it builds the redirect as a
/// canned errorfile (302 `Found` for `errorloc`/`errorloc302`, 303 `See Other` for
/// `errorloc303`), so it reaches the data path the way an `errorfile` does.
pub(crate) fn parse_errorloc_directive(
    files: &mut HashMap<u16, Vec<u8>>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    let name = &kw.text;
    if tokens.len() < 3 {
        return Err(ConfigError::new(kw.line, kw.col, format!("{name} : expects <status_code> and <url> as arguments.")));
    }
    if tokens.len() > 3 {
        return Err(ConfigError::new(kw.line, kw.col, format!("{name} : expects exactly two arguments.")));
    }
    let code = tokens[1].text.parse::<u16>().unwrap_or(0);
    if !DEFAULT_PAGE_CODES.contains(&code) {
        return Err(ConfigError::new(
            tokens[1].line,
            tokens[1].col,
            format!("{name} : status code '{code}' not handled."),
        ));
    }
    let (status, reason) = if name == "errorloc303" { (303, "See Other") } else { (302, "Found") };
    let page = format!(
        "HTTP/1.1 {status} {reason}\r\ncache-control: no-cache\r\ncontent-length: 0\r\nlocation: {}\r\n\r\n",
        tokens[2].text
    );
    files.insert(code, page.into_bytes());
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

/// The codes `HAProxy` has a built-in page for (`http_err_codes`, `src/http.c`).
const DEFAULT_PAGE_CODES: [u16; 21] =
    [200, 400, 401, 403, 404, 405, 407, 408, 410, 413, 414, 421, 422, 425, 429, 431, 500, 501, 502, 503, 504];

/// `default-errorfiles` -- written, or implied by a `deny` with no body -- for a status
/// with no built-in page. `HAProxy` refuses the rule ("status code '418' not handled by
/// default with 'default-errorfiles' argument"); Ibex accepted it and sent an empty reply.
pub(crate) fn check_default_errorfiles(status: u16, at: &Token) -> Result<(), ConfigError> {
    if DEFAULT_PAGE_CODES.contains(&status) {
        Ok(())
    } else {
        Err(ConfigError::new(
            at.line,
            at.col,
            format!("status code '{status}' not handled by default with 'default-errorfiles' argument"),
        ))
    }
}

/// Parses a proxy's (or `defaults`') `errorfile`, `errorfiles` or `http-error` line.
///
/// The three fill what `HAProxy` keeps as one table per proxy, so for a given code the
/// last declaration wins whichever keyword made it: an `errorfile 403` after an
/// `http-error status 403` replaces it, and the reverse; `http-error ... default-errorfiles`
/// clears the code altogether. Ibex keeps the two kinds in two maps (`error_files`,
/// `error_replies`, the second consulted first), so each declaration removes the code
/// from the other map.
pub(crate) fn parse_proxy_error_page(
    files: &mut HashMap<u16, Vec<u8>>,
    replies: &mut HashMap<u16, ErrorPageSource>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    let mut set = HashMap::new();
    match kw.text.as_str() {
        "errorfile" => parse_errorfile_directive(&mut set, tokens, kw)?,
        "errorfiles" => parse_errorfiles_directive(&mut set, tokens, kw)?,
        "errorloc" | "errorloc302" | "errorloc303" => parse_errorloc_directive(&mut set, tokens, kw)?,
        _ => return parse_http_error_directive(files, replies, tokens, kw),
    }
    for (code, bytes) in set {
        replies.remove(&code);
        files.insert(code, bytes);
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
///
/// Whatever it sets or clears also removes `<code>` from the proxy's `errorfile` table
/// (`files`), so the later declaration wins. `errorfiles <name>` naming a section without
/// `<code>` is accepted, as `HAProxy` accepts it (with a warning), and changes nothing.
fn parse_http_error_directive(
    files: &mut HashMap<u16, Vec<u8>>,
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
    let (content_type, lf_string, error_page) = parse_error_body_args(tokens, 3, tokens.len(), code, None)?;
    match error_page {
        Some(ErrorPageSource::DefaultErrorfiles) => {
            replies.remove(&code);
        }
        Some(raw @ ErrorPageSource::Raw(_)) => {
            replies.insert(code, raw);
        }
        // `errorfiles <name>` whose section has no page for `code`: nothing changes.
        Some(ErrorPageSource::Custom { .. }) => return Ok(()),
        None => {
            replies.insert(code, ErrorPageSource::Custom { content_type, lf_string });
        }
    }
    files.remove(&code);
    Ok(())
}

/// Parses the arguments shared by `http-request return`, `http-request deny`, and
/// `http-error`: `content-type`, `hdr`, `string`/`lf-string`/`file`/`lf-file`, and the
/// page-selection keywords `default-errorfiles`/`errorfile`/`errorfiles`. `status` is
/// resolved by the caller (it may be needed before this point) and passed in as
/// `status_for_errorfiles`, since `errorfiles <name>` must pick a single status code out of
/// a whole section.
///
/// `owner` is the rule list and action when a rule line is being parsed (see the unknown-word
/// arm).
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
    owner: Option<(&str, &Token)>,
) -> Result<(Option<String>, Option<String>, Option<ErrorPageSource>), ConfigError> {
    let mut content_type = None;
    let mut lf_string = None;
    let mut custom_headers: Vec<(String, String)> = Vec::new();
    let mut error_page = None;
    // The last body given: (its keyword, whether it is a log-format, whether it is non-empty).
    let mut body: Option<(&Token, bool, bool)> = None;
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
            "lf-string" if i + 1 < limit => {
                body = Some((&tokens[i], true, true));
                lf_string = Some(tokens[i + 1].text.clone());
                i += 2;
            }
            // `string` and `file` are literal in HAProxy: only the `lf-` forms are log-formats.
            // The body is kept as a format, so a literal one has its `%` doubled.
            "string" if i + 1 < limit => {
                body = Some((&tokens[i], false, !tokens[i + 1].text.is_empty()));
                lf_string = Some(tokens[i + 1].text.replace('%', "%%"));
                i += 2;
            }
            "lf-file" if i + 1 < limit => {
                body = Some((&tokens[i], true, true));
                lf_string = Some(load_reply_file(&tokens[i + 1], owner.is_some())?);
                i += 2;
            }
            "file" if i + 1 < limit => {
                let text = load_reply_file(&tokens[i + 1], owner.is_some())?;
                body = Some((&tokens[i], false, !text.is_empty()));
                lf_string = Some(text.replace('%', "%%"));
                i += 2;
            }
            "hdr" if i + 2 < limit => {
                custom_headers.push((tokens[i + 1].text.clone(), tokens[i + 2].text.clone()));
                i += 3;
            }
            "default-errorfiles" => {
                check_default_errorfiles(status_for_errorfiles, &tokens[i])?;
                error_page = Some(ErrorPageSource::DefaultErrorfiles);
                i += 1;
            }
            "errorfile" if i + 1 < limit => {
                error_page = Some(ErrorPageSource::Raw(load_errorfile_bytes(&tokens[i + 1])?));
                i += 2;
            }
            "errorfiles" if i + 1 < limit => {
                let name = &tokens[i + 1].text;
                if http_errors_section(name).is_none() {
                    return Err(ConfigError::new(
                        tokens[i + 1].line,
                        tokens[i + 1].col,
                        format!("unknown http-errors section '{name}'"),
                    ));
                }
                // A section without a page for the status is accepted, as HAProxy accepts
                // it (with a warning): `deny`/`return` then send an empty reply -- the
                // status line and `content-length: 0` -- which is what an empty template
                // builds, and `http-error` leaves the code alone.
                error_page = Some(match http_errors_section_code(name, status_for_errorfiles) {
                    Some(bytes) => ErrorPageSource::Raw(bytes),
                    None => ErrorPageSource::Custom { content_type: None, lf_string: None },
                });
                i += 2;
            }
            // HAProxy refuses a word it does not know here (`'http-request deny' expects
            // either 'if' or 'unless' ...`, `http-error : unknown keyword ...`), and so
            // does Ibex: skipping it accepted a line whose argument then did nothing. A
            // keyword missing its value lands here too.
            other => {
                // A rule (`http-request deny`, `return`...) says what `HAProxy` says: the
                // word is where the condition should start. `http-error` has its own text.
                let msg = match owner {
                    Some((list, act)) => format!(
                        "'{list} {}' expects either 'if' or 'unless' followed by a condition but found '{other}'.",
                        act.text
                    ),
                    None => format!("unknown or incomplete argument '{other}'"),
                };
                return Err(ConfigError::new(tokens[i].line, tokens[i].col, msg));
            }
        }
    }

    // `HAProxy` (`http_parse_http_reply`) will not send a body of unknown type: a log-format
    // one needs `content-type` even when it is empty, a literal one when it is not (T341).
    if content_type.is_none() {
        let why = match body {
            Some((_, true, _)) => Some("a content type must be defined with a log-format payload"),
            Some((_, false, true)) => Some("a content type must be defined when non-empty payload is configured"),
            _ => None,
        };
        if let (Some((kw, ..)), Some(why)) = (body, why) {
            return Err(ConfigError::new(kw.line, kw.col, why));
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
