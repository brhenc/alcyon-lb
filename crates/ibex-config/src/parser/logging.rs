use super::*;

/// Parses a `log` directive into `logs`, returning true for the `log global` form.
///
/// `log global` inherits whatever the `global` section declared, and is how essentially
/// every real `HAProxy` configuration turns logging on for a proxy. It used to fall into
/// the argument check below and be rejected as "expects <address> and <facility>", so a
/// canonical config did not load at all.
/// Parses a `log` directive into `logs`, returning true for the `log global` form.
///
/// The grammar, from `src/log.c`:
///
/// ```text
/// log <target> [len <n>] [format <fmt>] <facility> [<level>]
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
    let (addr, is_quic) = parse_socket_addr(tok, Some(514))?;
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

