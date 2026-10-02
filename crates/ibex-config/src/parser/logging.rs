use super::*;
use crate::ast::LogSample;

/// Parses a `log` directive into `logs`, returning true for the `log global` form.
///
/// The grammar, from `src/log.c`:
///
/// ```text
/// log <target> [len <n>] [format <fmt>] [sample <ranges>:<size>] <facility> [<level>]
/// log global
/// ```
///
/// `log global` inherits whatever the `global` section declared, and is how essentially
/// every real `HAProxy` configuration turns logging on for a proxy.
pub(crate) fn parse_log(
    logs: &mut Vec<LogConfig>,
    tokens: &[Token],
    kw: &Token,
) -> Result<bool, ConfigError> {
    if tokens.len() >= 2 && tokens[1].text == "global" {
        return Ok(true);
    }
    if tokens.len() < 3 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<log> expects <address> and <facility> as arguments.",
        ));
    }
    if logs.len() >= 2 {
        return Err(ConfigError::new(kw.line, kw.col, "too many syslog servers"));
    }

    let target = parse_log_target(&tokens[1])?;

    // `len` and `format` sit between the target and the facility, in that order, and
    // both are optional -- so the facility is wherever those stop, not a fixed index.
    let mut i = 2;
    let mut max_len = 1024usize;
    let mut format = None;
    let mut sample = None;
    while i + 1 < tokens.len() {
        match tokens[i].text.as_str() {
            "len" => {
                let n: usize = tokens[i + 1].text.parse().map_err(|_| {
                    ConfigError::new(
                        tokens[i + 1].line,
                        tokens[i + 1].col,
                        format!("invalid log length '{}'", tokens[i + 1].text),
                    )
                })?;
                if !(80..=65535).contains(&n) {
                    return Err(ConfigError::new(
                        tokens[i + 1].line,
                        tokens[i + 1].col,
                        format!("invalid log length '{n}', must be between 80 and 65535"),
                    ));
                }
                max_len = n;
                i += 2;
            }
            "format" => {
                format = Some(tokens[i + 1].text.clone());
                i += 2;
            }
            "sample" => {
                sample = Some(Box::new(parse_log_sample(&tokens[i + 1])?));
                i += 2;
            }
            // Not implemented (`log-profile` sections). Refused rather than dropped, so a
            // config relying on it does not load as if it worked.
            "profile" => {
                return Err(ConfigError::new(
                    tokens[i].line,
                    tokens[i].col,
                    "'log ... profile' is not supported",
                ));
            }
            _ => break,
        }
    }

    let Some(fac_tok) = tokens.get(i) else {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<log> expects <address> and <facility> as arguments.",
        ));
    };
    let facility = parse_facility(fac_tok)?;
    let level = match tokens.get(i + 1) {
        Some(t) if !t.text.is_empty() => Some(parse_level(t)?),
        _ => None,
    };

    logs.push(LogConfig {
        target,
        facility,
        level,
        max_len,
        format,
        sample,
    });
    Ok(false)
}

/// Resolves a `log` target: an address, a file descriptor, or a unix socket.
///
/// `stdout` and `stderr` are aliases for `fd@1` and `fd@2` (`src/log.c`), which is how a
/// containerised or systemd-managed proxy logs without a syslog daemon anywhere.
pub(crate) fn parse_log_target(tok: &Token) -> Result<LogTarget, ConfigError> {
    let t = tok.text.as_str();
    match t {
        "stdout" => return Ok(LogTarget::Fd(1)),
        "stderr" => return Ok(LogTarget::Fd(2)),
        _ => {}
    }
    if let Some(n) = t.strip_prefix("fd@") {
        let fd: i32 = n.parse().map_err(|_| {
            ConfigError::new(tok.line, tok.col, format!("invalid file descriptor '{n}'"))
        })?;
        if fd < 0 {
            return Err(ConfigError::new(
                tok.line,
                tok.col,
                format!("invalid file descriptor '{fd}'"),
            ));
        }
        return Ok(LogTarget::Fd(fd));
    }
    if let Some(path) = t.strip_prefix("unix@") {
        return Ok(LogTarget::Unix(path.to_string()));
    }
    // A bare absolute path is a unix socket, as it is for `bind`.
    if t.starts_with('/') {
        return Ok(LogTarget::Unix(t.to_string()));
    }
    // `udp@` names the transport a bare address already implies (`src/log.c`).
    let (addr, is_quic) = match t.strip_prefix("udp@") {
        Some(rest) => parse_socket_addr(&Token { text: rest.to_string(), ..tok.clone() }, Some(514))?,
        None => parse_socket_addr(tok, Some(514))?,
    };
    if is_quic {
        return Err(ConfigError::new(tok.line, tok.col, "QUIC not supported for log targets".to_string()));
    }
    Ok(LogTarget::Udp(addr))
}

pub(crate) fn parse_facility(token: &Token) -> Result<LogFacility, ConfigError> {
    match token.text.as_str() {
        "kern" => Ok(LogFacility::Kern),
        "user" => Ok(LogFacility::User),
        "mail" => Ok(LogFacility::Mail),
        "daemon" => Ok(LogFacility::Daemon),
        "auth" => Ok(LogFacility::Auth),
        "syslog" => Ok(LogFacility::Syslog),
        "lpr" => Ok(LogFacility::Lpr),
        "news" => Ok(LogFacility::News),
        "uucp" => Ok(LogFacility::Uucp),
        "cron" => Ok(LogFacility::Cron),
        "auth2" => Ok(LogFacility::Auth2),
        "ftp" => Ok(LogFacility::Ftp),
        "ntp" => Ok(LogFacility::Ntp),
        "audit" => Ok(LogFacility::Audit),
        "alert" => Ok(LogFacility::Alert),
        "cron2" => Ok(LogFacility::Cron2),
        "local0" => Ok(LogFacility::Local0),
        "local1" => Ok(LogFacility::Local1),
        "local2" => Ok(LogFacility::Local2),
        "local3" => Ok(LogFacility::Local3),
        "local4" => Ok(LogFacility::Local4),
        "local5" => Ok(LogFacility::Local5),
        "local6" => Ok(LogFacility::Local6),
        "local7" => Ok(LogFacility::Local7),
        other => Err(ConfigError::new(
            token.line,
            token.col,
            format!("unknown log facility <{other}>"),
        )),
    }
}

pub(crate) fn parse_level(token: &Token) -> Result<LogLevel, ConfigError> {
    match token.text.as_str() {
        "emerg" => Ok(LogLevel::Emerg),
        "alert" => Ok(LogLevel::Alert),
        "crit" => Ok(LogLevel::Crit),
        "err" => Ok(LogLevel::Err),
        "warning" => Ok(LogLevel::Warning),
        "notice" => Ok(LogLevel::Notice),
        "info" => Ok(LogLevel::Info),
        "debug" => Ok(LogLevel::Debug),
        other => Err(ConfigError::new(
            token.line,
            token.col,
            format!("unknown log level <{other}>"),
        )),
    }
}

/// `log-tag <tag>`, in a proxy section or `defaults`: the syslog tag for this proxy's
/// lines, in place of the global one (`__send_log`, `src/log.c`).
pub(crate) fn parse_log_tag(tokens: &[Token], kw: &Token) -> Result<std::sync::Arc<str>, ConfigError> {
    match tokens.get(1) {
        Some(t) if !t.text.is_empty() => Ok(t.text.as_str().into()),
        _ => Err(ConfigError::new(kw.line, kw.col, "'log-tag' expects a tag for use in syslog")),
    }
}

/// `sample <ranges>:<size>`, refused where `HAProxy`'s `parse_logger` refuses it: a range
/// is `n` or `low-high` with `0 < low < high`, ranges may not overlap, and `size` is a
/// positive integer no smaller than the highest bound. A trailing comma is accepted, as
/// there. The ranges come back sorted.
fn parse_log_sample(tok: &Token) -> Result<LogSample, ConfigError> {
    let err = |msg: String| ConfigError::new(tok.line, tok.col, msg);
    let Some((ranges_str, size_str)) = tok.text.split_once(':') else {
        return Err(err("Missing sample size".into()));
    };
    let wrong_range = |r: &str| err(format!("wrong sample range '{r}'"));
    let positive = |s: &str| s.parse::<u32>().ok().filter(|&n| n > 0 && s.bytes().all(|b| b.is_ascii_digit()));
    let mut ranges: Vec<std::ops::RangeInclusive<u32>> = Vec::new();
    let ranges_body = ranges_str.strip_suffix(',').unwrap_or(ranges_str);
    for r in ranges_body.split(',') {
        let (low, high) = match r.split_once('-') {
            None => {
                let n = positive(r).ok_or_else(|| wrong_range(r))?;
                (n, n)
            }
            Some((l, h)) => {
                let low = positive(l).ok_or_else(|| wrong_range(r))?;
                let high = positive(h).filter(|&h| h > low).ok_or_else(|| wrong_range(r))?;
                (low, high)
            }
        };
        if ranges.iter().any(|o| o.contains(&low) || o.contains(&high)) {
            return Err(err("ranges are overlapping".into()));
        }
        ranges.push(low..=high);
    }
    let size = positive(size_str)
        .ok_or_else(|| err(format!("wrong sample size '{size_str}' for sample range '{ranges_str}'")))?;
    let max = ranges.iter().map(|r| *r.end()).max().unwrap_or(0);
    if size < max {
        return Err(err(format!(
            "sample size {size} should be greater or equal to {max} the maximum of the high ranges limits"
        )));
    }
    ranges.sort_by_key(|r| *r.start());
    Ok(LogSample { ranges, size })
}
