// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use super::*;
use crate::ast::LoadWarning;

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
                let d = parse_timeout(tok, "stats timeout").map_err(|e| {
                    if e.message.starts_with("timer overflow") {
                        return e;
                    }
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
                // The same refusals as `HAProxy` (`atol`: a prefix of digits counts). The value
                // limits the live CLI connections (`Engine::set_cli_maxconn`, T239).
                "maxconn" => {
                    let digits: String = arg.trim_start().chars().take_while(char::is_ascii_digit).collect();
                    let n = digits.parse::<i64>().unwrap_or(0);
                    if n <= 0 {
                        return refuse("'stats maxconn' expects a positive value".to_string());
                    }
                    global.stats_maxconn = Some(u32::try_from(n).unwrap_or(u32::MAX));
                    return Ok(());
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
                let addr = stats_socket_addr(&tokens[2])?;
                let path = match &addr {
                    crate::ast::StatsAddr::Unix(p) => p.clone(),
                    other => other.name(),
                };
                let mut sock = crate::ast::StatsSocket { path, addr, ..Default::default() };
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
                    global.stats_socket_addr = Some(sock.addr);
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
        // `cfg_parse_quic_tune_setting` (src/cfgparse-quic.c, QUIC oracle 3.5-dev7): one
        // argument, `atoi` into an `unsigned int`, at least 1. So `-1` is 4294967295 and
        // `abc` is refused. Reaches `QuicEndpoint`'s Retry policy through `QuicConfig`.
        "tune.quic.fe.sec.retry-threshold" => {
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{}' cannot handle unexpected argument '{}'.", kw.text, extra.text)));
            }
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let n = tokens.get(1).map_or(0, |t| c_atoi(&t.text) as u32);
            if n < 1 {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{}' expects a positive integer.", kw.text)));
            }
            global.quic_retry_threshold = Some(u64::from(n));
            Ok(())
        }
        // `cfg_parse_quic_tune_setting`, as above (T525). Reach `QuicConfig` (the transport
        // parameter `initial_max_streams_bidi`) and the listener (`stream.max-total`) in
        // `engine.rs`, where the QUIC listener is built.
        "tune.quic.fe.stream.max-concurrent" | "tune.quic.fe.stream.max-total" => {
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{}' cannot handle unexpected argument '{}'.", kw.text, extra.text)));
            }
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let n = tokens.get(1).map_or(0, |t| c_atoi(&t.text) as u32);
            if n < 1 {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{}' expects a positive integer.", kw.text)));
            }
            if kw.text == "tune.quic.fe.stream.max-concurrent" {
                global.quic_stream_max_concurrent = Some(n);
            } else {
                global.quic_stream_max_total = Some(n);
            }
            Ok(())
        }
        // `cfg_parse_quic_time`: milliseconds, `parse_time_err`.
        "tune.quic.fe.max-idle-timeout" => {
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{}' cannot handle unexpected argument '{}'.", kw.text, extra.text)));
            }
            let text = tokens.get(1).map_or("", |t| t.text.as_str());
            let name = kw.text.as_str();
            match parse_time_ms_err(text) {
                Ok(ms) => global.quic_max_idle_timeout = Some(ms),
                Err(TimeMsErr::Over) => {
                    return Err(ConfigError::new(
                        kw.line,
                        kw.col,
                        format!("timer overflow in argument '{text}' to '{name}' (maximum value is 2147483647 ms or ~24.8 days)"),
                    ));
                }
                Err(TimeMsErr::Char(c)) => {
                    return Err(ConfigError::new(kw.line, kw.col, format!("unexpected character '{}' in '{name}'", if c == '\0' { String::new() } else { c.to_string() })));
                }
            }
            Ok(())
        }
        // `cfg_parse_quic_tune_on_off`. Read by `engine.rs`: off binds no UDP socket.
        "tune.quic.listen" => {
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{}' cannot handle unexpected argument '{}'.", kw.text, extra.text)));
            }
            global.quic_listen = match tokens.get(1).map(|t| t.text.as_str()) {
                Some("on") => Some(true),
                Some("off") => Some(false),
                _ => return Err(ConfigError::new(kw.line, kw.col, format!("'{}' expects 'on' or 'off'.", kw.text))),
            };
            Ok(())
        }
        // The oracle's other `tune.quic.*` keywords (congestion control, pacing, GSO, socket per
        // connection, buffers, the backend side). Ibex has nothing for them to tune: refused,
        // not parsed and dropped (AGENTS.md section 5). Listed in docs/differences.md.
        "tune.quic.mem.tx-max"
        | "tune.quic.sec.stateless-reset-rate"
        | "tune.quic.zero-copy-fwd-send"
        | "tune.quic.fe.cc.cubic-min-losses"
        | "tune.quic.fe.cc.hystart"
        | "tune.quic.fe.cc.max-frame-loss"
        | "tune.quic.fe.cc.max-win-size"
        | "tune.quic.fe.cc.reorder-ratio"
        | "tune.quic.fe.sec.glitches-threshold"
        | "tune.quic.fe.sock-per-conn"
        | "tune.quic.fe.stream.data-ratio"
        | "tune.quic.fe.stream.rxbuf"
        | "tune.quic.fe.tx.pacing"
        | "tune.quic.fe.tx.udp-gso"
        | "tune.quic.be.cc.cubic-min-losses"
        | "tune.quic.be.cc.hystart"
        | "tune.quic.be.cc.max-frame-loss"
        | "tune.quic.be.cc.max-win-size"
        | "tune.quic.be.cc.reorder-ratio"
        | "tune.quic.be.max-idle-timeout"
        | "tune.quic.be.sec.glitches-threshold"
        | "tune.quic.be.stream.data-ratio"
        | "tune.quic.be.stream.max-concurrent"
        | "tune.quic.be.stream.rxbuf"
        | "tune.quic.be.tx.pacing"
        | "tune.quic.be.tx.udp-gso" => Err(ConfigError::new(kw.line, kw.col, format!("'{}' is not supported by Ibex.", kw.text))),
        "tune.resolvers.cache-size" => {
            // Ibex-only (T489): the `do-resolve` answers each worker keeps, at least 1.
            let Some(t) = tokens.get(1) else {
                return Err(ConfigError::new(kw.line, kw.col, "'tune.resolvers.cache-size' expects a positive integer argument."));
            };
            match parse_u32(t, "tune.resolvers.cache-size") {
                Ok(n) if n > 0 => {
                    global.resolvers_cache_size = Some(n as usize);
                    Ok(())
                }
                _ => Err(ConfigError::new(kw.line, kw.col, "'tune.resolvers.cache-size' expects a positive integer argument.")),
            }
        }
        "tune.maxaccept" => {
            // `cfgparse-global.c`: `atol`, so `abc` is 0 (the default); only a value over
            // INT_MAX is refused (`max < -1` is commented out there); a second one is a
            // warning ("already specified. Continuing.") and the first stays.
            let Some(v) = tokens.get(1).filter(|t| !t.text.is_empty()) else {
                return Err(ConfigError::new(kw.line, kw.col, "'tune.maxaccept' expects an integer argument"));
            };
            let Ok(n) = i32::try_from(super::server_keywords::atol(&v.text)) else {
                return Err(ConfigError::new(kw.line, kw.col, "'tune.maxaccept' expects -1 or an integer from 0 to INT_MAX."));
            };
            if global.maxaccept.is_none() {
                global.maxaccept = Some(n);
            }
            Ok(())
        }
        "tune.vars.global-max-size"
        | "tune.vars.proc-max-size"
        | "tune.vars.sess-max-size"
        | "tune.vars.txn-max-size"
        | "tune.vars.reqres-max-size"
        | "tune.vars.check-max-size"
        | "tune.vars.from-map.max" => {
            // `vars_max_size` (src/vars.c): `strtol(args[1], &end, 10)` into an `unsigned int`; the
            // whole word must parse, so `12k` is refused, `-5` wraps and no word at all is 0.
            let name = kw.text.as_str();
            let word = tokens.get(1).map_or("", |t| t.text.as_str());
            let digits = word.strip_prefix(['-', '+']).unwrap_or(word);
            if !word.is_empty() && (digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit())) {
                return Err(ConfigError::new(kw.line, kw.col, format!("{name}: '{word}' is an invalid size")));
            }
            let mut n: i64 = 0;
            for b in digits.bytes() {
                n = n.saturating_mul(10).saturating_add(i64::from(b - b'0'));
            }
            if word.starts_with('-') {
                n = -n;
            }
            #[allow(clippy::cast_possible_truncation)] // the C assignment to `unsigned int`
            let v = n as u32;
            let l = &mut global.vars_limits;
            match name {
                "tune.vars.global-max-size" => l.global = v,
                "tune.vars.proc-max-size" => l.proc_ = v,
                "tune.vars.sess-max-size" => l.sess = v,
                "tune.vars.txn-max-size" => l.txn = v,
                "tune.vars.reqres-max-size" => l.reqres = v,
                "tune.vars.check-max-size" => l.check = v,
                _ => l.from_map_max = v,
            }
            Ok(())
        }
        "tune.memory.hot-size" => {
            // `mem_parse_global_hot_size` (src/pool.c): `too_many_args(1)`, then `atol` must be > 0.
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'tune.memory.hot-size' cannot handle unexpected argument '{}'.", extra.text)));
            }
            let n = tokens.get(1).map_or(0, |t| super::server_keywords::atol(&t.text));
            if n <= 0 {
                let at = tokens.get(1).unwrap_or(kw);
                return Err(ConfigError::new(at.line, at.col, "'tune.memory.hot-size' expects a strictly positive value."));
            }
            global.hot_size = Some(usize::try_from(n).unwrap_or(usize::MAX));
            Ok(())
        }
        "tune.fail-alloc" => {
            // `mem_parse_global_fail_alloc` (src/pool.c): `too_many_args(1)`, `atoi`, 0..=100.
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'tune.fail-alloc' cannot handle unexpected argument '{}'.", extra.text)));
            }
            let n = tokens.get(1).map_or(0, |t| super::server_keywords::atol(&t.text));
            let Ok(rate) = u8::try_from(n).map_err(|_| ()).and_then(|r| if r <= 100 { Ok(r) } else { Err(()) }) else {
                let at = tokens.get(1).unwrap_or(kw);
                return Err(ConfigError::new(at.line, at.col, "'tune.fail-alloc' expects a numeric value between 0 and 100."));
            };
            global.fail_alloc = Some(rate);
            Ok(())
        }
        "tune.buffers.limit" | "tune.buffers.reserve" => {
            // `cfg_parse_tune_buffers_limit` / `_reserve` (src/dynbuf.c): `too_many_args(1)`, `atoi`, >= 0.
            let name = kw.text.as_str();
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'{name}' cannot handle unexpected argument '{}'.", extra.text)));
            }
            let arg = tokens.get(1).map_or("", |t| t.text.as_str());
            let n = super::server_keywords::atol(arg);
            let at = tokens.get(1).unwrap_or(kw);
            if n < 0 {
                return Err(ConfigError::new(at.line, at.col, format!("'{name}' expects a non-negative number but got '{arg}'.")));
            }
            let n = usize::try_from(n).unwrap_or(usize::MAX);
            if name == "tune.buffers.reserve" {
                // Each thread's emergency buffers (S6b): `ibex_rt::buf::fill_emergency` at start,
                // taken by `Buf::alloc_for` when the pool refuses.
                global.buffers_reserve = Some(n);
                return Ok(());
            }
            global.buffers_limit = Some(if n == 0 { 0 } else { n.max(3) });
            Ok(())
        }
        "tune.memory.prealloc" => {
            // Ibex extension (T468): HAProxy 3.5-dev8 has no such keyword. Whether `maxconn` or
            // `-m` sizes it is checked at load (`ibex_rt::prealloc::check`), `-m` being on the
            // command line.
            let Some(arg) = tokens.get(1) else {
                return Err(ConfigError::new(kw.line, kw.col, "'tune.memory.prealloc' expects 'on' or 'off'."));
            };
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'tune.memory.prealloc' cannot handle unexpected argument '{}'.", extra.text)));
            }
            global.memory_prealloc = Some(match arg.text.as_str() {
                "on" => true,
                "off" => false,
                other => return Err(ConfigError::new(arg.line, arg.col, format!("'tune.memory.prealloc' expects 'on' or 'off', got '{other}'."))),
            });
            Ok(())
        }
        "tune.ibex.zero-buffers" => {
            let Some(arg) = tokens.get(1) else {
                return Err(ConfigError::new(kw.line, kw.col, "'tune.ibex.zero-buffers' expects 'on' or 'off'."));
            };
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'tune.ibex.zero-buffers' cannot handle unexpected argument '{}'.", extra.text)));
            }
            global.zero_buffers = Some(match arg.text.as_str() {
                "on" => true,
                "off" => false,
                other => return Err(ConfigError::new(arg.line, arg.col, format!("'tune.ibex.zero-buffers' expects 'on' or 'off', got '{other}'."))),
            });
            Ok(())
        }
        "tune.ibex.zero-on-free" => {
            let Some(arg) = tokens.get(1) else {
                return Err(ConfigError::new(kw.line, kw.col, "'tune.ibex.zero-on-free' expects 'off', 'soft' or 'hard'."));
            };
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'tune.ibex.zero-on-free' cannot handle unexpected argument '{}'.", extra.text)));
            }
            global.zero_on_free = Some(match arg.text.as_str() {
                "off" => crate::ast::ZeroOnFree::Off,
                "soft" => crate::ast::ZeroOnFree::Soft,
                "hard" => crate::ast::ZeroOnFree::Hard,
                other => return Err(ConfigError::new(arg.line, arg.col, format!("'tune.ibex.zero-on-free' expects 'off', 'soft' or 'hard', got '{other}'."))),
            });
            Ok(())
        }
        "tune.ibex.zero-spares" => {
            let Some(arg) = tokens.get(1) else {
                return Err(ConfigError::new(kw.line, kw.col, "'tune.ibex.zero-spares' expects 'on' or 'off'."));
            };
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'tune.ibex.zero-spares' cannot handle unexpected argument '{}'.", extra.text)));
            }
            global.zero_spares = Some(match arg.text.as_str() {
                "on" => true,
                "off" => false,
                other => return Err(ConfigError::new(arg.line, arg.col, format!("'tune.ibex.zero-spares' expects 'on' or 'off', got '{other}'."))),
            });
            Ok(())
        }
        "tune.ibex.ssl-zero-buffers" => {
            let Some(arg) = tokens.get(1) else {
                return Err(ConfigError::new(kw.line, kw.col, "'tune.ibex.ssl-zero-buffers' expects 'on', 'on-free' or 'off'."));
            };
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'tune.ibex.ssl-zero-buffers' cannot handle unexpected argument '{}'.", extra.text)));
            }
            global.ssl_zero_on_free = false;
            global.ssl_zero_buffers = Some(match arg.text.as_str() {
                "on" => true,
                "on-free" => {
                    global.ssl_zero_on_free = true;
                    true
                }
                "off" => false,
                other => return Err(ConfigError::new(arg.line, arg.col, format!("'tune.ibex.ssl-zero-buffers' expects 'on', 'on-free' or 'off', got '{other}'."))),
            });
            Ok(())
        }
        "tune.ibex.h3-path" => {
            let Some(arg) = tokens.get(1) else {
                return Err(ConfigError::new(kw.line, kw.col, "'tune.ibex.h3-path' expects 'relay' or 'mux'."));
            };
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'tune.ibex.h3-path' cannot handle unexpected argument '{}'.", extra.text)));
            }
            global.h3_mux = Some(match arg.text.as_str() {
                "mux" => true,
                "relay" => false,
                other => return Err(ConfigError::new(arg.line, arg.col, format!("'tune.ibex.h3-path' expects 'relay' or 'mux', got '{other}'."))),
            });
            Ok(())
        }
        // Q0 (Ibex-only): reach `QuicConfig::ack_frequency` in `engine.rs`, where the QUIC
        // listener is built, and from there `quinn_proto::TransportConfig`.
        "tune.ibex.quic-ack-frequency" => {
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'{}' cannot handle unexpected argument '{}'.", kw.text, extra.text)));
            }
            global.quic_ack_frequency = Some(match tokens.get(1).map(|t| t.text.as_str()) {
                Some("on") => true,
                Some("off") => false,
                Some(other) => return Err(ConfigError::new(kw.line, kw.col, format!("'{}' expects 'on' or 'off', got '{other}'.", kw.text))),
                None => return Err(ConfigError::new(kw.line, kw.col, format!("'{}' expects 'on' or 'off'.", kw.text))),
            });
            Ok(())
        }
        "tune.ibex.quic-ack-frequency-threshold" => {
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'{}' cannot handle unexpected argument '{}'.", kw.text, extra.text)));
            }
            let n = tokens.get(1).and_then(|t| t.text.parse::<u32>().ok()).filter(|n| *n <= 255);
            let Some(n) = n else {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{}' expects an integer from 0 to 255.", kw.text)));
            };
            global.quic_ack_frequency_threshold = Some(n);
            Ok(())
        }
        "tune.ibex.quic-ack-frequency-max-delay" => {
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'{}' cannot handle unexpected argument '{}'.", kw.text, extra.text)));
            }
            let ms = tokens.get(1).and_then(|t| parse_time_ms_err(&t.text).ok()).filter(|ms| (1..=16383).contains(ms));
            let Some(ms) = ms else {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{}' expects a time from 1ms to 16383ms.", kw.text)));
            };
            global.quic_ack_frequency_max_delay_ms = Some(ms);
            Ok(())
        }
        "tune.ibex.crypto-provider" => {
            const WANT: &str = "'tune.ibex.crypto-provider' expects 'ring' or 'ring-ibex'";
            let Some(arg) = tokens.get(1) else {
                return Err(ConfigError::new(kw.line, kw.col, format!("{WANT}.")));
            };
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'tune.ibex.crypto-provider' cannot handle unexpected argument '{}'.", extra.text)));
            }
            let Some(p) = crate::ast::TlsCryptoProvider::from_name(&arg.text) else {
                return Err(ConfigError::new(arg.line, arg.col, format!("{WANT}, got '{}'.", arg.text)));
            };
            global.crypto_provider = Some(p);
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
        // `h2_parse_max_concurrent_streams` (mux_h2.c): `atoi` (text is 0, a long wraps to int),
        // negative refused; 0 means "the other level" (fe -> global) at run time. Reaches
        // the data path as the SETTINGS value and the cap on the connection's streams
        // (`engine.rs` `global_h2_flood_config.max_concurrent_streams`).
        "tune.h2.max-concurrent-streams" | "tune.h2.fe.max-concurrent-streams" => {
            let name = kw.text.as_str();
            let fe = name == "tune.h2.fe.max-concurrent-streams";
            if let Some(extra) = tokens.get(2).filter(|_| !fe) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'{name}' cannot handle unexpected argument '{}'.", extra.text)));
            }
            let v = c_atoi(tokens.get(1).map_or("", |t| t.text.as_str()));
            let Ok(v) = u32::try_from(v) else {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{name}' expects a positive numeric value.")));
            };
            if fe {
                let mut i = 2;
                while let Some(opt) = tokens.get(i) {
                    let arg = tokens.get(i + 1).map_or("", |t| t.text.as_str());
                    let positive = |a: &str| c_atoi(a) > 0;
                    match opt.text.as_str() {
                        // The default: the load does not shrink the limit. Anything else
                        // would need the run-queue load, which Ibex does not compute.
                        "rq-load" if arg == "ignore" => {}
                        "rq-load" if arg == "auto" || positive(arg) => {
                            return Err(ConfigError::new(opt.line, opt.col, format!("'{name}' : 'rq-load {arg}' is not supported (the limit is not adjusted to the run-queue load); only 'rq-load ignore' is.")));
                        }
                        "rq-load" => {
                            return Err(ConfigError::new(kw.line, kw.col, format!("'{name}' expects a strictly positive run-queue length, or 'auto' or 'ignore'.")));
                        }
                        "min" if !positive(arg) => {
                            return Err(ConfigError::new(kw.line, kw.col, format!("'{name}' expects a strictly positive minimum number of streams'.")));
                        }
                        "min" if i64::from(v) < c_atoi(arg) => {
                            return Err(ConfigError::new(kw.line, kw.col, format!("'{name}' minimum number of streams ({}) cannot be higher than the maximum ({v})'.", u32::try_from(c_atoi(arg)).unwrap_or(0))));
                        }
                        "min" => {
                            return Err(ConfigError::new(opt.line, opt.col, format!("'{name}' : 'min {arg}' is not supported (it only matters with an 'rq-load' limit, which is not).")));
                        }
                        other => {
                            return Err(ConfigError::new(kw.line, kw.col, format!("'{name}' only supports 'rq-load' or 'min' after the numeric value, but found '{other}'.")));
                        }
                    }
                    i += 2;
                }
                global.h2_fe_max_concurrent_streams = Some(v);
            } else {
                global.h2_max_concurrent_streams = Some(v);
            }
            Ok(())
        }
        // `h2_parse_rxbuf` (mux_h2.c): a size. The budget of what a frontend connection holds
        // for its streams (`engine.rs` `global_h2_flood_config.rxbuf`, `H2MuxContext::rx_budget`).
        "tune.h2.fe.rxbuf" => {
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'tune.h2.fe.rxbuf' cannot handle unexpected argument '{}'.", extra.text)));
            }
            let Some(arg) = tokens.get(1) else {
                // `parse_size_err("")` stops at the NUL, which ends HAProxy's message there.
                return Err(ConfigError::new(kw.line, kw.col, "'tune.h2.fe.rxbuf': unexpected character '"));
            };
            // `parse_size_err`: digits, then one of k, m, g; the first other character is named.
            let t = arg.text.as_str();
            let digits = t.bytes().take_while(u8::is_ascii_digit).count();
            let rest = &t[digits..];
            if !matches!(rest.to_ascii_lowercase().as_str(), "" | "k" | "m" | "g") {
                let bad = if digits < t.len() && rest.len() > 1 && matches!(rest.as_bytes()[0] | 0x20, b'k' | b'm' | b'g') { &rest[1..] } else { rest };
                return Err(ConfigError::new(arg.line, arg.col, format!("'tune.h2.fe.rxbuf': unexpected character '{}' in size argument '{t}'.", bad.chars().next().unwrap_or('\0'))));
            }
            global.h2_fe_rxbuf = Some(super::scalars::parse_size(arg).unwrap_or(0));
            Ok(())
        }
        // HAProxy accepts it; Ibex opens no HTTP/2 connection to a server (`server ... proto h2`
        // is refused, requests go out as HTTP/1.1), so there is no stream to limit.
        "tune.h2.be.max-concurrent-streams" => Err(ConfigError::new(
            kw.line,
            kw.col,
            "'tune.h2.be.max-concurrent-streams' is not supported: Ibex speaks only HTTP/1.1 to servers, so there is no HTTP/2 connection to a server whose streams it could limit.",
        )),
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
        "dns-accept-family" => {
            // `cfg_parse_dns_accept_family` (measured on 3.5-dev8): `HAProxy` cuts the argument
            // in place at each comma, so the refusal names its first item whichever is wrong.
            if let Some(t) = tokens.get(2) {
                return Err(ConfigError::new(t.line, t.col, format!("'dns-accept-family' cannot handle unexpected argument '{}'.", t.text)));
            }
            let arg = tokens.get(1).map_or("", |t| t.text.as_str());
            let usage = || {
                let first = arg.split(',').next().unwrap_or("");
                ConfigError::new(kw.line, kw.col, format!("'dns-accept-family' expects a comma-delimited list of 'ipv4' and 'ipv6' but got '{first}'."))
            };
            if arg.is_empty() {
                return Err(usage());
            }
            let mut f = crate::ast::DnsAcceptFamily { ipv4: false, ipv6: false, auto: false };
            // `for (arg = ...; arg && *arg; arg = comma)`: a trailing comma ends the list.
            let mut rest = Some(arg);
            while let Some(a) = rest.filter(|a| !a.is_empty()) {
                let (item, next) = a.split_once(',').map_or((a, None), |(i, n)| (i, Some(n)));
                match item {
                    "ipv4" => f.ipv4 = true,
                    "ipv6" => f.ipv6 = true,
                    "auto" => f.auto = true,
                    _ => return Err(usage()),
                }
                rest = next;
            }
            global.dns_accept_family = f;
            Ok(())
        }
        "httpclient.resolvers.disabled" | "httpclient.resolvers.prefer" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("'{}' is not supported (HTTP client resolvers are not implemented)", kw.text),
            ))
        }
        "strict-limits" => {
            global.no_strict_limits = false;
            Ok(())
        }
        "no" if tokens.get(1).is_some_and(|t| t.text == "strict-limits") => {
            global.no_strict_limits = true;
            Ok(())
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
        // `cfg_parse_global` (src/cfgparse-global.c); reaches `show info` and the stats page
        // through `GlobalSection::node` / `description` (`ibex-rt` `stats.rs`).
        "node" => {
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'node' cannot handle unexpected argument '{}'.", extra.text)));
            }
            let name = tokens.get(1).map_or("", |t| t.text.as_str());
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')) {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "'node' requires valid node name - non-empty string with digits(0-9), letters(A-Z, a-z), dot(.), hyphen(-) or underscode(_).",
                ));
            }
            global.node = Some(name.to_string());
            Ok(())
        }
        "description" => {
            global.description = Some(parse_description(tokens, kw)?);
            Ok(())
        }
        "daemon" => {
            global.daemon = true;
            Ok(())
        }
        // Removed in HAProxy 3.5 (`cfg_parse_global`, src/cfgparse-global.c): the mode is
        // chosen on the command line (`-W`, `-Ws`), which `ibex` handles; accepting and
        // ignoring the keyword started a process with no master (VV-26).
        "master-worker" => {
            if tokens.get(1).is_some_and(|t| t.text == "no-exit-on-failure") {
                return Err(ConfigError::new(kw.line, kw.col, "'master-worker no-exit-on-failure' is only supported in master-worker mode. Use -W or -Ws in the startup script."));
            }
            Err(ConfigError::new(kw.line, kw.col, "support for 'master-worker' was removed in version 3.5. Use -W or -Ws in the startup script instead."))
        }
        // `HAProxy`'s `cfg_parse_global` (src/cfgparse-global.c): the names are resolved
        // here, so an unknown one fails `-c` as well; the ids are applied in `ibex-rt`
        // (`bin/ibex/identity.rs`) once every listener is bound.
        "user" | "group" | "uid" | "gid" => parse_identity(global, tokens, kw),
        "chroot" => {
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'chroot' cannot handle unexpected argument '{}'.", extra.text)));
            }
            let dir = tokens.get(1).map_or("", |t| t.text.as_str());
            if global.chroot.is_some() {
                global.load_warnings.push(LoadWarning { line: kw.line, alert: false, text: "'chroot' is already specified. Continuing.".into(), style: crate::ast::global::WarnStyle::SpacedBlank });
                return Ok(());
            }
            if dir.is_empty() {
                return Err(ConfigError::new(kw.line, kw.col, "'chroot' expects a directory as an argument."));
            }
            global.chroot = Some(dir.to_string());
            Ok(())
        }
        // `cfg_parse_global` (src/cfgparse-global.c): a second line is an alert that does not
        // fail the load, and words after the path are not looked at. Read by
        // `ibex-rt` `server_state::apply` when the proxies are built (T490).
        "server-state-file" | "server-state-base" => {
            let file = kw.text == "server-state-file";
            let slot = if file { &mut global.server_state_file } else { &mut global.server_state_base };
            if slot.is_some() {
                global.load_warnings.push(LoadWarning {
                    line: kw.line,
                    alert: true,
                    text: format!("'{}' already specified. Continuing.", kw.text),
                    style: crate::ast::global::WarnStyle::Spaced,
                });
                return Ok(());
            }
            match tokens.get(1).map(|t| t.text.as_str()).filter(|t| !t.is_empty()) {
                Some(path) => {
                    *slot = Some(path.to_string());
                    Ok(())
                }
                None if file => Err(ConfigError::new(kw.line, kw.col, "'server-state-file' expect one argument: a file path.")),
                None => Err(ConfigError::new(kw.line, kw.col, "'server-state-base' expects one argument: a directory path.")),
            }
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
        // `wdt_parse_warn_blocked` (src/wdt.c:209), its texts measured with `haproxy -c`.
        // Words after the time are ignored, as there.
        "warn-blocked-traffic-after" => {
            let name = "warn-blocked-traffic-after";
            let Some(arg) = tokens.get(1).filter(|t| !t.text.is_empty()) else {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{name}' expects <time> as argument between 1 and 1000 ms.")));
            };
            let ms = match parse_time_ms_err(&arg.text) {
                Ok(ms) => ms,
                Err(TimeMsErr::Over) => {
                    return Err(ConfigError::new(arg.line, arg.col, format!("timer overflow in argument '{}' to '{name}' (maximum value is 1000 ms)", arg.text)));
                }
                Err(TimeMsErr::Char(c)) => {
                    return Err(ConfigError::new(arg.line, arg.col, format!("unexpected character '{c}' in argument to <{name}>.")));
                }
            };
            if !(1..=1000).contains(&ms) {
                return Err(ConfigError::new(
                    arg.line,
                    arg.col,
                    format!("timer out of range in argument '{}' to '{name}' (value must be between 1 and 1000 ms)", arg.text),
                ));
            }
            global.warn_blocked_traffic_after = Some(Duration::from_millis(ms.into()));
            Ok(())
        }
        // Ibex only (an `ibex.` prefix cannot clash with a HAProxy keyword): the watchdog
        // (T361) keeps its warnings but does not abort the process.
        "ibex.watchdog-warn-only" => {
            if let Some(extra) = tokens.get(1) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'ibex.watchdog-warn-only' cannot handle unexpected argument '{}'.", extra.text)));
            }
            global.ibex_watchdog_warn_only = true;
            Ok(())
        }
        "hard-stop-after" => {
            if tokens.len() >= 2 {
                global.hard_stop_after = Some(parse_timeout(&tokens[1], "hard-stop-after")?);
            }
            Ok(())
        }
        // `HAProxy` limits concurrent TLS connections with it; Ibex has no such count, so a
        // limit is refused (T240). 0 (`atol`, so also a word) is no limit and loads.
        "maxsslconn" => {
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'maxsslconn' cannot handle unexpected argument '{}'.", extra.text)));
            }
            let Some(arg) = tokens.get(1).filter(|t| !t.text.is_empty()) else {
                return Err(ConfigError::new(kw.line, kw.col, "'maxsslconn' expects an integer argument."));
            };
            match super::server_keywords::atol(&arg.text) {
                0 => Ok(()),
                n if n < 0 => Err(ConfigError::new(arg.line, arg.col, "'maxsslconn' expects a positive numeric value.")),
                _ => Err(ConfigError::new(
                    arg.line,
                    arg.col,
                    "'maxsslconn' is not implemented in Ibex: TLS connections are limited by 'maxconn' only",
                )),
            }
        }
        // `ssl_parse_global_capture_buffer` over `ssl_parse_global_int` (src/cfgparse-ssl.c):
        // the alias warns first, then `too_many_args`, an empty argument, `atoi` (a word is 0)
        // and a negative value are refused, and only then a second occurrence of either name.
        "tune.ssl.capture-buffer-size" | "tune.ssl.capture-cipherlist-size" => {
            let name = kw.text.as_str();
            if name == "tune.ssl.capture-cipherlist-size" {
                global.load_warnings.push(LoadWarning {
                    line: kw.line,
                    alert: false,
                    text: "'tune.ssl.capture-cipherlist-size' is deprecated and will be removed in version 2.7. Please use 'tune.ssl.capture-buffer-size' instead.".into(),
                    style: crate::ast::global::WarnStyle::Tight,
                });
            }
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'{name}' cannot handle unexpected argument '{}'.", extra.text)));
            }
            let Some(arg) = tokens.get(1).filter(|t| !t.text.is_empty()) else {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{name}' expects an integer argument.")));
            };
            let Ok(size) = usize::try_from(c_atoi(&arg.text)) else {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{name}' expects a positive numeric value.")));
            };
            if global.tune_ssl_capture_configured {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{name}' is already configured.")));
            }
            global.tune_ssl_capture_buffer_size = size;
            global.tune_ssl_capture_configured = true;
            Ok(())
        }
        "ibex.ja4-compat" => {
            let name = kw.text.as_str();
            if let Some(extra) = tokens.get(2) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'{name}' cannot handle unexpected argument '{}'.", extra.text)));
            }
            let spec = match tokens.get(1).map(|t| t.text.as_str()) {
                Some("foxio") => false,
                Some("spec") => true,
                Some(other) => return Err(ConfigError::new(kw.line, kw.col, format!("'{name}' expects 'foxio' or 'spec', not '{other}'."))),
                None => return Err(ConfigError::new(kw.line, kw.col, format!("'{name}' expects 'foxio' or 'spec'."))),
            };
            if global.ibex_ja4_compat_configured {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{name}' already specified.")));
            }
            global.ibex_ja4_compat_spec = spec;
            global.ibex_ja4_compat_configured = true;
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
        // `mem_parse_global_no_mem_trim` (`src/pool.c`): no argument. Read by `Engine::new`,
        // which hands it to `ibex_alloc::set_trim_disabled`.
        "no-memory-trimming" => {
            if let Some(extra) = tokens.get(1).filter(|t| !t.text.is_empty()) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'no-memory-trimming' cannot handle unexpected argument '{}'.", extra.text)));
            }
            global.no_memory_trimming = true;
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
                    line: tokens[0].line,
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
                    line: tokens[0].line,
                });
            }
            Ok(())
        }
        // A test-only fault (T447): a debug build panics in the stream's run, a release build
        // refuses the keyword, so no deployed process can be made to.
        "ibex.debug.panic" => {
            global.debug_panic = Some(parse_debug_panic(tokens, kw, cfg!(debug_assertions))?);
            Ok(())
        }
        "expose-experimental-directives" => {
            super::acl_scope::allow_experimental();
            Ok(())
        }
        other if IGNORED_GLOBAL_KEYWORDS.iter().any(|(k, _)| *k == other) => Ok(()),
        // The change itself was made while the lines were read (`crate::preproc`), for the
        // `${VAR}` below to see it, and is replayed on the process by the caller
        // (`Config::env_ops`). This arm only refuses what `cfg_parse_global_env_opts` refuses.
        "setenv" | "presetenv" => {
            if let Some(extra) = tokens.get(3) {
                return Err(ConfigError::new(extra.line, extra.col, format!("'{}' cannot handle unexpected argument '{}'.", kw.text, extra.text)));
            }
            let arg = |i: usize| tokens.get(i).map_or("", |t| t.text.as_str());
            if arg(1).is_empty() {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{}' expects environment variable name.\n.", kw.text)));
            }
            if arg(2).is_empty() {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{}' expects environment variable value for '{}'.\n.", kw.text, arg(1))));
            }
            if !crate::env::valid_name(arg(1)) || arg(2).contains('\0') {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{}' failed on variable '{}' : Invalid argument.\n", kw.text, arg(1))));
            }
            Ok(())
        }
        "unsetenv" => {
            if tokens.len() < 2 || tokens[1].text.is_empty() {
                return Err(ConfigError::new(kw.line, kw.col, "'unsetenv' expects at least one variable name.\n"));
            }
            if let Some(t) = tokens[1..].iter().find(|t| !crate::env::valid_name(&t.text)) {
                return Err(ConfigError::new(kw.line, kw.col, format!("'unsetenv' failed on variable '{}' : Invalid argument.\n", t.text)));
            }
            Ok(())
        }
        "resetenv" => Ok(()),
        "h1-case-adjust" => {
            // `cfg_parse_h1_header_case_adjust`, src/mux_h1.c (measured on 3.5-dev8).
            if tokens.len() > 3 {
                return Err(ConfigError::new(
                    tokens[3].line,
                    tokens[3].col,
                    format!("'h1-case-adjust' cannot handle unexpected argument '{}'.", tokens[3].text),
                ));
            }
            let arg = |i: usize| tokens.get(i).map(|t| t.text.as_str()).filter(|a| !a.is_empty());
            let (Some(from), Some(to)) = (arg(1), arg(2)) else {
                return Err(ConfigError::new(kw.line, kw.col, "'h1-case-adjust' expects <from> and <to> as argument."));
            };
            add_h1_case_adjust(&mut global.h1_case_adjust, from, to).map_err(|m| ConfigError::new(kw.line, kw.col, m))
        }
        "h1-case-adjust-file" => {
            if tokens.len() > 2 {
                return Err(ConfigError::new(
                    tokens[2].line,
                    tokens[2].col,
                    format!("'h1-case-adjust-file' cannot handle unexpected argument '{}'.", tokens[2].text),
                ));
            }
            let Some(path) = tokens.get(1).map(|t| t.text.as_str()).filter(|a| !a.is_empty()) else {
                return Err(ConfigError::new(kw.line, kw.col, "'h1-case-adjust-file' expects <file> as argument."));
            };
            // `HAProxy` reads the file after the whole configuration is parsed (and only the
            // last `h1-case-adjust-file`); Ibex reads each at the keyword.
            load_h1_case_adjust_file(&mut global.h1_case_adjust, path).map_err(|m| ConfigError::new(kw.line, kw.col, m))
        }
        _ => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("unknown keyword '{}' in 'global' section", kw.text),
        )),
    }
}


/// What a `stats socket` address names, with `HAProxy`'s refusals (`str2sa_range`,
/// src/tools.c, called with `PA_O_RESOLVE | PA_O_PORT_OK | PA_O_PORT_MAND | PA_O_PORT_RANGE
/// | PA_O_STREAM`; T222, T246). Measured on 3.5-dev8-885761-29: a name with no leading `/`
/// and no `unix@` prefix is `host:port` (so `./x.sock` has "no port specification"); the 97
/// byte limit counts after `unix@`; `abns@` allows 107; the port is checked before the
/// address (`nosuchhost.invalid:0` is an "invalid port"). Port ranges, `fd@`, `sockpair@`
/// and `mptcp` are accepted by `HAProxy` and refused here, rather than bound as something
/// else (AGENTS.md section 5).
#[allow(clippy::too_many_lines)]
/// `ibex.debug.panic <request|response|request-locked> <path-prefix>`, a test-only fault
/// (T447). `allowed`: a debug build; a release build refuses it, so that no deployed process
/// can be made to panic.
fn parse_debug_panic(tokens: &[Token], kw: &Token, allowed: bool) -> Result<crate::ast::DebugPanic, ConfigError> {
    let usage = || ConfigError::new(kw.line, kw.col, "'ibex.debug.panic' expects 'request', 'response' or 'request-locked' and a path prefix.");
    if !allowed {
        return Err(ConfigError::new(kw.line, kw.col, "'ibex.debug.panic' is only available in debug builds."));
    }
    let (at_response, under_lock) = match tokens.get(1).map(|t| t.text.as_str()) {
        Some("request") => (false, false),
        Some("response") => (true, false),
        Some("request-locked") => (false, true),
        _ => return Err(usage()),
    };
    let path = tokens.get(2).filter(|_| tokens.len() == 3).ok_or_else(usage)?;
    Ok(crate::ast::DebugPanic { at_response, under_lock, path: path.text.clone() })
}

fn stats_socket_addr(tok: &Token) -> Result<crate::ast::StatsAddr, ConfigError> {
    use crate::ast::StatsAddr;
    use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
    #[derive(Clone, Copy, PartialEq)]
    enum Fam {
        Unix,
        Abns(bool),
        Any,
        V4,
        V6,
    }
    let arg = tok.text.as_str();
    let err = |m: String| ConfigError::new(tok.line, tok.col, format!("'stats socket' : {m}"));
    let unsupported = |what: &str| err(format!("{what} are not supported by Ibex for 'stats socket' in '{arg}'"));
    let mut rest = arg;
    let mut dgram = false;
    if let Some(r) = rest.strip_prefix("stream+") {
        rest = r;
    } else if let Some(r) = rest.strip_prefix("dgram+") {
        rest = r;
        dgram = true;
    } else if rest.starts_with("quic+") {
        return Err(unsupported("QUIC addresses"));
    }
    let prefixes: [(&str, Option<Fam>, bool); 20] = [
        ("unix@", Some(Fam::Unix), false),
        ("uxdg@", Some(Fam::Unix), true),
        ("uxst@", Some(Fam::Unix), false),
        ("abns@", Some(Fam::Abns(true)), false),
        ("abnsz@", Some(Fam::Abns(false)), false),
        ("ip@", Some(Fam::Any), false),
        ("ipv4@", Some(Fam::V4), false),
        ("ipv6@", Some(Fam::V6), false),
        ("tcp4@", Some(Fam::V4), false),
        ("udp4@", Some(Fam::V4), true),
        ("tcp6@", Some(Fam::V6), false),
        ("udp6@", Some(Fam::V6), true),
        ("tcp@", Some(Fam::Any), false),
        ("udp@", Some(Fam::Any), true),
        ("mptcp4@", None, false),
        ("mptcp6@", None, false),
        ("mptcp@", None, false),
        ("fd@", None, false),
        ("sockpair@", None, false),
        ("rhttp@", None, false),
    ];
    let mut fam = Fam::Any;
    let mut prefixed = false;
    for (p, f, dg) in prefixes {
        if let Some(r) = rest.strip_prefix(p) {
            let Some(f) = f else {
                return Err(match p {
                    "fd@" | "sockpair@" => unsupported("file descriptor addresses"),
                    "rhttp@" => unsupported("reverse HTTP addresses"),
                    _ => unsupported("MPTCP addresses"),
                });
            };
            rest = r;
            fam = f;
            dgram |= dg;
            prefixed = true;
            break;
        }
    }
    if rest.starts_with("quic4@") || rest.starts_with("quic6@") {
        return Err(unsupported("QUIC addresses"));
    }
    if !prefixed && rest.starts_with('/') {
        fam = Fam::Unix;
    }
    let not_acceptable = || err(format!("dgram-type address not acceptable in '{arg}'"));
    match fam {
        Fam::Unix | Fam::Abns(_) => {
            let max = if fam == Fam::Unix { 97 } else { 107 };
            if rest.len() > max {
                return Err(err(format!("socket path '{arg}' too long (max {max})")));
            }
            if dgram {
                return Err(not_acceptable());
            }
            return Ok(match fam {
                Fam::Abns(padded) => StatsAddr::Abstract { name: rest.to_string(), padded },
                _ => StatsAddr::Unix(rest.to_string()),
            });
        }
        Fam::Any | Fam::V4 | Fam::V6 => {}
    }
    // The port separator: the last ':' unless a ']' comes after it.
    let sep = rest.rfind([':', ']']).map(|i| (i, rest.as_bytes()[i]));
    let Some((colon, b':')) = sep else {
        return Err(err(format!("missing port specification in '{arg}'")));
    };
    let (host, port1) = (&rest[..colon], &rest[colon + 1..]);
    // `strtol`: digits only here (the first byte is checked), saturating like LONG_MAX.
    let strtol = |s: &str| -> Result<u64, ConfigError> {
        let digits = s.bytes().take_while(u8::is_ascii_digit).count();
        if let Some(c) = s[digits..].chars().next() {
            return Err(err(format!("invalid character '{c}' in port number '{s}' in '{arg}'")));
        }
        Ok(s.bytes().fold(0u64, |n, b| n.saturating_mul(10).saturating_add(u64::from(b - b'0'))))
    };
    let port = match port1.bytes().next() {
        None => return Err(err(format!("missing port specification in '{arg}'"))),
        Some(b'-' | b'+') => return Err(err(format!("port offset not permitted here in '{arg}'"))),
        Some(c) if !c.is_ascii_digit() => {
            let c = port1.chars().next().unwrap_or_default();
            return Err(err(format!("invalid character '{c}' in port number '{port1}' in '{arg}'")));
        }
        Some(_) => {
            let (lo, hi) = port1.split_once('-').unwrap_or((port1, port1));
            let (portl, porth) = (strtol(lo)?, strtol(hi)?);
            if !(1..=65535).contains(&portl) {
                return Err(err(format!("invalid port '{lo}'")));
            }
            if !(1..=65535).contains(&porth) {
                return Err(err(format!("invalid port '{hi}'")));
            }
            if portl > porth {
                return Err(err(format!("invalid port range '{portl}-{porth}'")));
            }
            if portl != porth || port1.contains('-') {
                return Err(unsupported("port ranges"));
            }
            u16::try_from(portl).unwrap_or(u16::MAX)
        }
    };
    let invalid = || err(format!("invalid address: '{host}' in '{arg}'"));
    // `str2ip2`: brackets, `::`, `*`/empty, literals, then a resolution.
    let lit = if host.starts_with('[') {
        if host.len() < 4 || !host.ends_with(']') {
            return Err(invalid());
        }
        &host[1..host.len() - 1]
    } else {
        host
    };
    let ip: IpAddr = if lit.is_empty() || lit == "*" {
        if fam == Fam::V6 { IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED) } else { IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED) }
    } else if let Ok(ip) = lit.parse::<IpAddr>() {
        ip
    } else {
        let valid_name = lit.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_');
        if !valid_name {
            return Err(invalid());
        }
        let found: Vec<SocketAddr> = (lit, 0).to_socket_addrs().map(Iterator::collect).unwrap_or_default();
        // `getaddrinfo` (`GTUNE_USE_GAI`, on by default): the first answer of the family.
        let pick = match fam {
            Fam::V4 => found.iter().find(|a| a.is_ipv4()),
            Fam::V6 => found.iter().find(|a| a.is_ipv6()),
            _ => found.first(),
        };
        pick.map(SocketAddr::ip).ok_or_else(invalid)?
    };
    let fits = match fam {
        Fam::V4 => ip.is_ipv4(),
        Fam::V6 => ip.is_ipv6(),
        _ => true,
    };
    if !fits {
        return Err(invalid());
    }
    if dgram {
        return Err(not_acceptable());
    }
    Ok(StatsAddr::Tcp(SocketAddr::new(ip, port)))
}

/// `add_hdr_case_adjust` (src/mux_h1.c): `to` differs from `from` in case only, `from` is new.
fn add_h1_case_adjust(table: &mut Vec<(String, String)>, from: &str, to: &str) -> Result<(), String> {
    if to.is_empty() {
        return Err("expect <to>".to_string());
    }
    if !from.eq_ignore_ascii_case(to) {
        return Err("<from> and <to> must not differ except the case".to_string());
    }
    if table.iter().any(|(f, _)| f == from) {
        return Err(format!("duplicate entry '{from}'"));
    }
    table.push((from.to_string(), to.to_string()));
    Ok(())
}

/// `cfg_h1_headers_case_adjust_postparser`: one `<from> <to>` per line, blanks around and `#`
/// comment lines ignored.
fn load_h1_case_adjust_file(table: &mut Vec<(String, String)>, path: &str) -> Result<(), String> {
    let text = std::fs::read(path).map_err(|_| format!("h1-headers-case-adjust-file '{path}': failed to open file."))?;
    let text = String::from_utf8_lossy(&text);
    for (i, line) in text.split_inclusive('\n').enumerate() {
        let line = line.trim_start_matches([' ', '\t']);
        if line.is_empty() || line.starts_with(['#', '\r', '\n']) {
            continue;
        }
        let key_end = line.find([' ', '\t', '\n', '\r']).unwrap_or(line.len());
        let (key, rest) = line.split_at(key_end);
        let value = rest.trim_start_matches([' ', '\t']);
        let value = value.split(['\n', '\r']).next().unwrap_or("").trim_end_matches([' ', '\t']);
        add_h1_case_adjust(table, key, value).map_err(|m| format!("h1-headers-case-adjust-file '{path}' : {m} at line {}.", i + 1))?;
    }
    Ok(())
}

/// `user`, `group`, `uid` and `gid`. A second one of a pair is an alert that does not fail
/// the load and keeps the first; a `uid` that is not a number is a warning and no uid.
#[allow(clippy::cast_possible_wrap)] // `(int)ha_user->pw_uid`, as HAProxy.
fn parse_identity(global: &mut GlobalSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    let name = kw.text.as_str();
    if let Some(extra) = tokens.get(2) {
        return Err(ConfigError::new(extra.line, extra.col, format!("'{name}' cannot handle unexpected argument '{}'.", extra.text)));
    }
    let arg = tokens.get(1).map_or("", |t| t.text.as_str());
    let is_user = matches!(name, "user" | "uid");
    let slot = if is_user { global.uid } else { global.gid };
    let mut note = |alert: bool, text: String| global.load_warnings.push(LoadWarning { line: kw.line, alert, text, style: crate::ast::global::WarnStyle::Spaced });
    if slot.is_some() {
        note(true, match name {
            "user" | "uid" => "user/uid already specified. Continuing.".into(),
            "group" => "gid/group was already specified. Continuing.".into(),
            _ => "group/gid already specified. Continuing.".into(),
        });
        return Ok(());
    }
    let id = match name {
        "uid" | "gid" => {
            if arg.is_empty() {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{name}' expects an integer argument.")));
            }
            let Some(id) = strl2irc(arg) else {
                let (what, instead) = if is_user { ("uid", "user") } else { ("gid", "group") };
                note(false, format!(
                    " {what}: string '{arg}' is not a number.\n   | You might want to use the '{instead}' parameter to use a system {instead} name."
                ));
                return Ok(());
            };
            id
        }
        _ => {
            // `getpwnam` / `getgrnam` with errno cleared: not found is `(0:Success)`.
            let found = if is_user {
                nix::unistd::User::from_name(arg).map(|u| u.map(|u| u.uid.as_raw()))
            } else {
                nix::unistd::Group::from_name(arg).map(|g| g.map(|g| g.gid.as_raw()))
            };
            if let Ok(Some(id)) = found {
                id as i32
            } else {
                let (errno, why) = found.err().map_or((0, "Success"), |e| (e as i32, e.desc()));
                let what = if is_user { "user" } else { "group" };
                return Err(ConfigError::new(kw.line, kw.col, format!("cannot find {what} id for '{arg}' ({errno}:{why})")));
            }
        }
    };
    if is_user {
        global.uid = Some(id);
    } else {
        global.gid = Some(id);
    }
    Ok(())
}

/// `strl2irc` (src/tools.c): an optional `-`, then digits, within an `int`. As there, a
/// byte below `'0'` is not refused (`j > 9` is the only test).
fn strl2irc(s: &str) -> Option<i32> {
    let (neg, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let mut i: i32 = 0;
    for b in digits.bytes() {
        let j = i32::from(b) - i32::from(b'0');
        if j > 9 {
            return None;
        }
        i = i.checked_mul(10)?;
        i = if neg { i.checked_sub(j)? } else { i.checked_add(j)? };
    }
    Some(i)
}

/// The text of a `description` line: the words joined by one space (`HAProxy` rebuilds it
/// from `args[]`), and an error when there are none.
pub(crate) fn parse_description(tokens: &[Token], kw: &Token) -> Result<String, ConfigError> {
    if tokens.len() < 2 {
        return Err(ConfigError::new(kw.line, kw.col, "'description' expects a string argument."));
    }
    Ok(tokens[1..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" "))
}

/// C's `atoi`: the leading integer of `s` (0 when there is none), read as `strtol` does and
/// then truncated to an `int`.
fn c_atoi(s: &str) -> i64 {
    let t = s.trim_start();
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let n = digits.bytes().take_while(u8::is_ascii_digit).fold(0i64, |a, d| a.saturating_mul(10).saturating_add(i64::from(d - b'0')));
    i64::from((if neg { -n } else { n }) as i32)
}

enum TimeMsErr {
    Over,
    Char(char),
}

/// A time in milliseconds as `parse_time_err(.., TIME_UNIT_MS)` (src/tools.c:2936) reads
/// it: digits, then `us` (rounded up), `ms`, `s`, `m`, `h` or `d`; none is milliseconds.
/// `HAProxy` warns about characters after the unit and takes the value: so does this, without
/// the warning.
fn parse_time_ms_err(text: &str) -> Result<u32, TimeMsErr> {
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return Err(TimeMsErr::Char(text.chars().next().unwrap_or('\0')));
    }
    let value: u128 = text[..digits].parse().unwrap_or(u128::MAX);
    let unit = &text[digits..];
    // (multiplier, divisor) from the unit to milliseconds.
    let (mul, div): (u128, u128) = if unit.is_empty() || unit.starts_with("ms") {
        (1, 1)
    } else if unit.starts_with("us") {
        (1, 1000)
    } else if unit.starts_with('s') {
        (1000, 1)
    } else if unit.starts_with('m') {
        (60_000, 1)
    } else if unit.starts_with('h') {
        (3_600_000, 1)
    } else if unit.starts_with('d') {
        (86_400_000, 1)
    } else {
        return Err(TimeMsErr::Char(unit.chars().next().unwrap_or('\0')));
    };
    let ms = value.saturating_mul(mul).saturating_add(div - 1) / div;
    u32::try_from(ms).ok().filter(|m| *m < 0x8000_0000).ok_or(TimeMsErr::Over)
}

#[cfg(test)]
mod debug_panic_tests {
    use super::parse_debug_panic;
    use crate::lexer::Token;

    fn toks(words: &[&str]) -> Vec<Token> {
        words.iter().map(|w| Token { text: (*w).to_string(), line: 1, col: 1 }).collect()
    }

    #[test]
    fn a_release_build_refuses_the_fault_and_a_debug_build_takes_it() {
        let t = toks(&["ibex.debug.panic", "response", "/boom"]);
        let e = parse_debug_panic(&t, &t[0], false).expect_err("release refuses");
        assert!(e.to_string().contains("only available in debug builds"), "{e}");
        let d = parse_debug_panic(&t, &t[0], true).expect("debug takes it");
        assert!(d.at_response && !d.under_lock && d.path == "/boom");
        let t = toks(&["ibex.debug.panic", "request-locked", "/x"]);
        assert!(parse_debug_panic(&t, &t[0], true).expect("locked").under_lock);
        for bad in [&["ibex.debug.panic"][..], &["ibex.debug.panic", "later", "/x"], &["ibex.debug.panic", "request"], &["ibex.debug.panic", "request", "/x", "more"]] {
            let t = toks(bad);
            assert!(parse_debug_panic(&t, &t[0], true).expect_err("usage").to_string().contains("expects"), "{bad:?}");
        }
    }
}
