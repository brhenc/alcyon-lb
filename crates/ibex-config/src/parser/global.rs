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
            if tokens.len() >= 3 && tokens[1].text == "socket" {
                global.stats_socket = Some(tokens[2].text.clone());
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
                            global.stats_socket_mode = Some(mode_val);
                        }
                        "level" if i + 1 < tokens.len() => {
                            i += 1;
                            global.stats_socket_level = Some(tokens[i].text.clone());
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
                            global.stats_socket_expose_fd = true;
                        }
                        _ => {}
                    }
                    i += 1;
                }
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
            if tokens.len() >= 2 {
                global.ssl_default_server_options = Some(tokens[1..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" "));
            }
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

