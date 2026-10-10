// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use super::*;

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_global_directive(
    global: &mut GlobalSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    match kw.text.as_str() {
        "nbthread" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<nbthread> expects an integer.",
                ));
            }
            global.nbthread = Some(parse_u32(&tokens[1], "nbthread")?);
            Ok(())
        }
        "log" => {
            // `log global` is meaningless here -- this *is* global -- and HAProxy
            // rejects it, so parse_log's inherit form is treated as an error.
            if parse_log(&mut global.logs, tokens, kw)? {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "'log global' is not valid in the global section",
                ));
            }
            Ok(())
        }
        "log-tag" => {
            // One argument only here (`alertif_too_many_args`); proxies take extras silently.
            if tokens.len() > 2 {
                return Err(ConfigError::new(kw.line, kw.col, "'log-tag' cannot handle unexpected argument"));
            }
            global.log_tag = Some(parse_log_tag(tokens, kw)?);
            Ok(())
        }
        "stats" => {
            // `HAProxy`'s texts (`cli_parse_global`, src/cli.c): until this arm existed the
            // line was accepted and dropped, and every CLI connection kept 60 s (T226).
            if tokens.len() >= 2 && tokens[1].text == "timeout" {
                let empty = Token { text: String::new(), ..tokens[1].clone() };
                let tok = tokens.get(2).unwrap_or(&empty);
                let d = parse_timeout(tok, "stats timeout").map_err(|_| {
                    let bad = tok.text.chars().find(|c| !c.is_ascii_digit()).map_or(String::new(), String::from);
                    ConfigError::new(tok.line, tok.col, format!("'stats timeout' : unexpected character '{bad}'"))
                })?;
                if d.is_zero() {
                    return Err(ConfigError::new(tok.line, tok.col, "'stats timeout' expects a positive value".to_string()));
                }
                global.stats_timeout = Some(d);
                return Ok(());
            }
            let sub = tokens.get(1).map_or("", |t| t.text.as_str());
            let arg = tokens.get(2).map_or("", |t| t.text.as_str());
            let at = tokens.get(2).or_else(|| tokens.get(1)).map_or((kw.line, kw.col), |t| (t.line, t.col));
            let refuse = |msg: String| Err(ConfigError::new(at.0, at.1, msg));
            match sub {
                "socket" if arg.is_empty() => {
                    return refuse("'stats socket' in global section expects an address or a path to a UNIX socket".to_string());
                }
                "socket" => {}
                // The same refusals as `HAProxy` (`atol`: a prefix of digits counts). Ibex has no
                // limit on CLI connections to apply, so a valid value is refused as well.
                "maxconn" => {
                    let digits: String = arg.trim_start().chars().take_while(char::is_ascii_digit).collect();
                    if digits.parse::<i64>().map_or(true, |n| n <= 0) {
                        return refuse("'stats maxconn' expects a positive value".to_string());
                    }
                    return refuse("'stats maxconn' is not supported by Ibex".to_string());
                }
                "calculate-max-counters" => {
                    return if arg.eq_ignore_ascii_case("on") {
                        Ok(()) // what HAProxy does without the line
                    } else if arg.eq_ignore_ascii_case("off") {
                        refuse("'stats calculate-max-counters off' is not supported by Ibex".to_string())
                    } else {
                        refuse(format!("'calculate-max-counters' only supports 'on' and 'off', received '{arg}'"))
                    };
                }
                "bind-process" => return refuse("'stats bind-process' is not supported anymore.".to_string()),
                _ => {
                    return refuse(format!(
                        "'stats' only supports 'socket', 'maxconn', 'bind-process', 'calculate-max-counters'  and 'timeout' (got '{sub}')"
                    ));
                }
            }
            if tokens.len() >= 3 {
                let path = stats_socket_path(&tokens[2])?;
                let mut sock = crate::ast::StatsSocket { path, ..Default::default() };
                let mut i = 3;
                while i < tokens.len() {
                    match tokens[i].text.as_str() {
                        "mode" if i + 1 < tokens.len() => {
                            i += 1;
                            let mode_val = u32::from_str_radix(&tokens[i].text, 8)
                                .or_else(|_| tokens[i].text.parse::<u32>())
                                .map_err(|_| {
                                    ConfigError::new(
                                        tokens[i].line,
                                        tokens[i].col,
                                        format!("invalid socket mode <{}>", tokens[i].text),
                                    )
                                })?;
                            sock.mode = Some(mode_val);
                        }
                        "level" if i + 1 < tokens.len() => {
                            i += 1;
                            if !matches!(tokens[i].text.as_str(), "user" | "operator" | "admin") {
                                return Err(ConfigError::new(
                                    tokens[i].line,
                                    tokens[i].col,
                                    format!(
                                        "'stats socket' : ''level' only supports 'user', 'operator', and 'admin' (got '{}')'",
                                        tokens[i].text
                                    ),
                                ));
                            }
                            sock.level = Some(tokens[i].text.clone());
                        }
                        // Until this arm existed, `expose-fd listeners` fell into the
                        // catch-all below and was accepted and dropped -- so a HAProxy
                        // config asking for hitless reload parsed cleanly and got none.
                        "expose-fd" => {
                            let what = tokens.get(i + 1).map(|t| t.text.as_str());
                            if what != Some("listeners") {
                                return Err(ConfigError::new(
                                    tokens[i].line,
                                    tokens[i].col,
                                    "'expose-fd' only supports 'listeners'".to_string(),
                                ));
                            }
                            i += 1;
                            sock.expose_fd = true;
                        }
                        _ => {}
                    }
                    i += 1;
                }
                // The first socket fills the fields every other part of Ibex reads; each
                // later one (in this section or another) is kept beside it.
                if global.stats_socket.is_none() {
                    global.stats_socket = Some(sock.path);
                    global.stats_socket_mode = sock.mode;
                    global.stats_socket_level = sock.level;
                    global.stats_socket_expose_fd = sock.expose_fd;
                } else {
                    global.extra_stats_sockets.push(sock);
                }
            }
            Ok(())
        }
        // `cfg_parse_idle_pool_shared` (src/server.c): Ibex has one thread group, so `full`
        // (every thread) and `on` (the threads of the group) are the same.
        "tune.idle-pool.shared" => {
            let arg = tokens.get(1).map_or("", |t| t.text.as_str());
            global.idle_pool_unshared = match arg {
                "full" | "on" => false,
                "off" => true,
                _ => {
                    return Err(ConfigError::new(
                        kw.line,
                        kw.col,
                        format!("'tune.idle-pool.shared' expects 'full', 'on' or 'off' but got '{arg}'."),
                    ));
                }
            };
            Ok(())
        }
        // `cfg_parse_pool_fd_ratio` (src/server.c): `atoi`, so text that is not a number is 0.
        "tune.pool-high-fd-ratio" | "tune.pool-low-fd-ratio" => {
            let name = kw.text.as_str();
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{name}' cannot handle unexpected argument '{}'.", extra.text)));
            }
            let arg = tokens.get(1).map(|t| t.text.as_str());
            let ratio = arg.map_or(-1, |a| {
                let t = a.trim_start();
                let (neg, digits) = match t.as_bytes().first() {
                    Some(b'-') => (true, &t[1..]),
                    Some(b'+') => (false, &t[1..]),
                    _ => (false, t),
                };
                let mut n: i64 = 0;
                for b in digits.bytes().take_while(u8::is_ascii_digit) {
                    n = (n * 10 + i64::from(b - b'0')).min(i64::from(i32::MAX));
                }
                if neg { -n } else { n }
            });
            let Ok(ratio) = u8::try_from(ratio).map_err(|_| ()).and_then(|r| if r <= 100 { Ok(r) } else { Err(()) }) else {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{name}' expects an integer argument between 0 and 100.")));
            };
            if name == "tune.pool-high-fd-ratio" {
                global.pool_high_fd_ratio = Some(ratio);
            } else {
                global.pool_low_fd_ratio = Some(ratio);
            }
            Ok(())
        }
        "tune.maxrewrite" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(kw.line, kw.col, "'tune.maxrewrite' expects an integer argument."));
            }
            let raw_val = tokens[1].text.parse::<usize>().map_err(|_| {
                ConfigError::new(tokens[1].line, tokens[1].col, format!("'tune.maxrewrite' expects an integer argument, got '{}'", tokens[1].text))
            })?;
            global.maxrewrite = Some(raw_val);
            Ok(())
        }
        "tune.bufsize" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(kw.line, kw.col, "'tune.bufsize' expects an integer argument."));
            }
            let raw_size = tokens[1].text.parse::<usize>().map_err(|_| {
                ConfigError::new(tokens[1].line, tokens[1].col, format!("'tune.bufsize' expects an integer argument, got '{}'", tokens[1].text))
            })?;
            if raw_size == 0 {
                return Err(ConfigError::new(tokens[1].line, tokens[1].col, "'tune.bufsize' expects a positive integer argument."));
            }
            if raw_size >= 268_435_456 {
                return Err(ConfigError::new(tokens[1].line, tokens[1].col, format!("'tune.bufsize' must be less than 268435456 bytes (256 MB), got {raw_size}")));
            }
            let rounded = (raw_size + 15) & !15;
            global.bufsize = Some(rounded);
            Ok(())
        }
        "tune.bufsize.small" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(kw.line, kw.col, "'tune.bufsize.small' expects an integer argument."));
            }
            let raw_size = tokens[1].text.parse::<usize>().map_err(|_| {
                ConfigError::new(tokens[1].line, tokens[1].col, format!("'tune.bufsize.small' expects an integer argument, got '{}'", tokens[1].text))
            })?;
            if raw_size == 0 {
                return Err(ConfigError::new(tokens[1].line, tokens[1].col, "'tune.bufsize.small' expects a positive integer argument."));
            }
            if raw_size >= 268_435_456 {
                return Err(ConfigError::new(tokens[1].line, tokens[1].col, format!("'tune.bufsize.small' must be less than 268435456 bytes (256 MB), got {raw_size}")));
            }
            let rounded = (raw_size + 15) & !15;
            global.bufsize_small = Some(rounded);
            Ok(())
        }
        "tune.bufsize.large" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(kw.line, kw.col, "'tune.bufsize.large' expects an integer argument."));
            }
            let raw_size = tokens[1].text.parse::<usize>().map_err(|_| {
                ConfigError::new(tokens[1].line, tokens[1].col, format!("'tune.bufsize.large' expects an integer argument, got '{}'", tokens[1].text))
            })?;
            if raw_size == 0 {
                return Err(ConfigError::new(tokens[1].line, tokens[1].col, "'tune.bufsize.large' expects a positive integer argument."));
            }
            if raw_size >= 268_435_456 {
                return Err(ConfigError::new(tokens[1].line, tokens[1].col, format!("'tune.bufsize.large' must be less than 268435456 bytes (256 MB), got {raw_size}")));
            }
            let rounded = (raw_size + 15) & !15;
            global.bufsize_large = Some(rounded);
            Ok(())
        }
        "tune.h2.fe.max-total-streams" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "'tune.h2.fe.max-total-streams' expects an integer argument.",
                ));
            }
            let val = tokens[1].text.parse::<usize>().map_err(|_| {
                ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!(
                        "'tune.h2.fe.max-total-streams' expects an integer argument, got '{}'",
                        tokens[1].text
                    ),
                )
            })?;
            global.h2_max_total_streams = Some(val);
            Ok(())
        }
        "tune.h2.fe.glitches-threshold" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "'tune.h2.fe.glitches-threshold' expects an integer argument.",
                ));
            }
            let val = tokens[1].text.parse::<usize>().map_err(|_| {
                ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!(
                        "'tune.h2.fe.glitches-threshold' expects an integer argument, got '{}'",
                        tokens[1].text
                    ),
                )
            })?;
            global.h2_glitches_threshold = Some(val);
            Ok(())
        }
        "tune.glitches.kill.cpu-usage" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                "'tune.glitches.kill.cpu-usage' is not supported (no CPU measurement subsystem in tree)",
            ))
        }
        "tune.h2.fe.max-rst-at-once" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                "'tune.h2.fe.max-rst-at-once' is not supported (resets-burst deprioritization is not implemented)",
            ))
        }
        "thread-groups" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "'thread-groups' expects an integer argument.",
                ));
            }
            let val = tokens[1].text.parse::<u32>().map_err(|_| {
                ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!(
                        "'thread-groups' expects an integer argument, got '{}'",
                        tokens[1].text
                    ),
                )
            })?;
            if val == 0 {
                return Err(ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    "'thread-groups' value must be between 1 and 32 (was 0)",
                ));
            }
            if val > 1 {
                return Err(ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!("'thread-groups' > 1 is not supported (got {val})"),
                ));
            }
            // val == 1: accepted as inert default (Ibex single thread group runtime model)
            Ok(())
        }
        "external-check" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                "'external-check' is not supported (external health checks are not implemented)",
            ))
        }
        "lua-load" | "lua-load-per-thread" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("'{}' is not supported (embedded Lua runtime is not implemented)", kw.text),
            ))
        }
        "httpclient.resolvers.disabled" | "httpclient.resolvers.prefer" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("'{}' is not supported (HTTP client resolvers are not implemented)", kw.text),
            ))
        }
        "maxconn" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "'maxconn' expects an integer argument.",
                ));
            }
            let val = tokens[1].text.parse::<u32>().map_err(|_| {
                ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!("'maxconn' expects an integer argument, got '{}'", tokens[1].text),
                )
            })?;
            global.maxconn = Some(val);
            Ok(())
        }
        "daemon" => {
            global.daemon = true;
            Ok(())
        }
        "master-worker" => {
            global.master_worker = true;
            Ok(())
        }
        "user" => {
            if tokens.len() >= 2 {
                global.user = Some(tokens[1].text.clone());
            }
            Ok(())
        }
        "group" => {
            if tokens.len() >= 2 {
                global.group = Some(tokens[1].text.clone());
            }
            Ok(())
        }
        "chroot" => {
            if tokens.len() >= 2 {
                global.chroot = Some(tokens[1].text.clone());
            }
            Ok(())
        }
        "pidfile" => {
            if tokens.len() >= 2 {
                global.pidfile = Some(tokens[1].text.clone());
            }
            Ok(())
        }
        "http-err-codes" | "http-fail-codes" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    format!("Missing status codes range for '{}'.", kw.text),
                ));
            }
            let (slot, mut set) = if kw.text == "http-err-codes" {
                (&mut global.http_err_codes, crate::ast::StatusCodeSet::default_err())
            } else {
                (&mut global.http_fail_codes, crate::ast::StatusCodeSet::default_fail())
            };
            // The list starts from what a previous line left, or the defaults.
            if let Some(prev) = slot {
                set = *prev;
            }
            for tok in &tokens[1..] {
                set.parse_arg(&kw.text, &tok.text).map_err(|m| ConfigError::new(tok.line, tok.col, m))?;
            }
            *slot = Some(set);
            Ok(())
        }
        "hard-stop-after" => {
            if tokens.len() >= 2 {
                global.hard_stop_after = Some(parse_timeout(&tokens[1], "hard-stop-after")?);
            }
            Ok(())
        }
        "maxsslconn" => {
            if tokens.len() >= 2 {
                global.maxsslconn = tokens[1].text.parse::<u32>().ok();
            }
            Ok(())
        }
        "ssl-default-bind-ciphers" => {
            if tokens.len() >= 2 {
                global.ssl_default_bind_ciphers = Some(tokens[1..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" "));
            }
            Ok(())
        }
        "ssl-default-bind-options" => {
            global.ssl_default_bind_versions = super::tls_versions::default_options_range(tokens, "ssl-default-bind-options")?;
            if tokens.len() >= 2 {
                global.ssl_default_bind_options = Some(tokens[1..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" "));
            }
            Ok(())
        }
        "ssl-default-server-ciphers" => {
            if tokens.len() >= 2 {
                global.ssl_default_server_ciphers = Some(tokens[1..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" "));
            }
            Ok(())
        }
        "ssl-default-server-options" => {
            global.ssl_default_server_versions = super::tls_versions::default_options_range(tokens, "ssl-default-server-options")?;
            if tokens.len() >= 2 {
                global.ssl_default_server_options = Some(tokens[1..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" "));
            }
            Ok(())
        }
        // Options that switch a poller or a kernel feature off. Ibex always polls with epoll and
        // does not splice, so they change nothing it does; what they change is the answer of
        // `enabled(...)` in the `.if` lines that follow them (`preproc.rs`).
        "noepoll" | "nopoll" | "nokqueue" | "noevports" | "nosplice" | "nogetaddrinfo" | "noreuseport" | "tune.disable-fast-forward" => {
            if let Some(extra) = tokens.get(1).filter(|t| !t.text.is_empty()) {
                return Err(ConfigError::new(
                    extra.line,
                    extra.col,
                    format!("'{}' cannot handle unexpected argument '{}'.", kw.text, extra.text),
                ));
            }
            Ok(())
        }
        "ssl-server-verify" => {
            // `ssl_parse_global_ssl_server_verify` (`src/cfgparse-ssl.c`): the messages of a
            // missing argument and of a wrong one are HAProxy's, odd as the first is.
            let Some(v) = tokens.get(1) else {
                return Err(ConfigError::new(kw.line, kw.col, "'ssl-server-verify' expects an integer argument."));
            };
            global.ssl_server_verify = Some(match v.text.as_str() {
                "none" => SslVerify::None,
                "required" => SslVerify::Required,
                _ => return Err(ConfigError::new(v.line, v.col, "'ssl-server-verify' expects 'none' or 'required' as argument.")),
            });
            Ok(())
        }
        "crt-base" | "ca-base" => {
            let Some(dir) = tokens.get(1) else {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    format!("global statement '{}' expects a directory path as an argument.", kw.text),
                ));
            };
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(
                    extra.line,
                    extra.col,
                    format!("'{}' cannot handle unexpected argument '{}'.", kw.text, extra.text),
                ));
            }
            let slot = if kw.text == "crt-base" { &mut global.crt_base } else { &mut global.ca_base };
            if slot.is_some() {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{}' already specified.", kw.text)));
            }
            *slot = Some(dir.text.clone());
            Ok(())
        }
        "set-var" => {
            if tokens.len() >= 3 {
                let var_name = tokens[1].text.clone();
                let expr = tokens[2..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");
                global.set_vars.push(GlobalSetVar {
                    name: var_name,
                    expr,
                    is_fmt: false,
                });
            }
            Ok(())
        }
        "set-var-fmt" => {
            if tokens.len() >= 3 {
                let var_name = tokens[1].text.clone();
                let expr = tokens[2..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");
                global.set_vars.push(GlobalSetVar {
                    name: var_name,
                    expr,
                    is_fmt: true,
                });
            }
            Ok(())
        }
        other if IGNORED_GLOBAL_KEYWORDS.iter().any(|(k, _)| *k == other) => Ok(()),
        _ => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("unknown keyword '{}' in 'global' section", kw.text),
        )),
    }
}


/// The unix path a `stats socket` address names, refusing what HAProxy refuses and what Ibex
/// does not implement (`str2sa_range`, src/tools.c; T222). Measured on 3.5-dev8-885761-29:
/// a name with no leading `/` and no `unix@` prefix is `host:port` (so `./x.sock` has "no
/// port specification"); the 97 byte limit counts after `unix@`; `abns@` allows 107.
/// TCP, abstract and `fd@` stats sockets are accepted by HAProxy; Ibex serves the CLI on
/// unix socket files only, so those are refused here rather than bound as a file named
/// after the address (AGENTS.md section 5).
fn stats_socket_path(tok: &Token) -> Result<String, ConfigError> {
    let arg = tok.text.as_str();
    let err = |m: String| ConfigError::new(tok.line, tok.col, format!("'stats socket' : {m}"));
    let too_long = |max: usize| err(format!("socket path '{arg}' too long (max {max})"));
    if let Some(rest) = arg.strip_prefix("unix@") {
        return if rest.len() > 97 { Err(too_long(97)) } else { Ok(rest.to_string()) };
    }
    if let Some(rest) = arg.strip_prefix("abns@") {
        if rest.len() > 107 {
            return Err(too_long(107));
        }
        return Err(err(format!("abstract unix sockets are not supported by Ibex in '{arg}'")));
    }
    if arg.starts_with('/') {
        return if arg.len() > 97 { Err(too_long(97)) } else { Ok(arg.to_string()) };
    }
    let spec = arg.split_once('@').map_or(arg, |(_, r)| r);
    if arg.starts_with("fd@") || arg.starts_with("sockpair@") {
        return Err(err(format!("file descriptor addresses are not supported by Ibex in '{arg}'")));
    }
    if !spec.contains(':') {
        return Err(err(format!("missing port specification in '{arg}'")));
    }
    Err(err(format!("TCP addresses are not supported by Ibex (the CLI listens on unix sockets only) in '{arg}'")))
}
