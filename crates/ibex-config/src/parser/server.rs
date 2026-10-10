// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use super::*;

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_server(
    servers: &mut Vec<Server>,
    extras: &mut ServerExtras,
    default_server: Option<&DefaultServerConfig>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text.is_empty() || tokens[2].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<server> expects <name> and <addr:port> as arguments.",
        ));
    }
    // No port is port 0: the server connects to the stream's destination port
    // (`SRV_F_MAPPORTS`; see `connect_addr` in ibex-rt).
    let (addr, is_quic) = parse_socket_addr(&tokens[2], Some(0))?;
    if is_quic {
        return Err(ConfigError::new(kw.line, kw.col, "QUIC not supported for backend servers".to_string()));
    }
    let who = Some(tokens[1].text.as_str());
    let mut check = default_server.is_some_and(|d| d.check);
    let mut inter = default_server.and_then(|d| d.inter);
    let mut fastinter = default_server.and_then(|d| d.fastinter);
    let mut downinter = default_server.and_then(|d| d.downinter);
    let mut fall = default_server.and_then(|d| d.fall);
    let mut rise = default_server.and_then(|d| d.rise);
    let mut send_proxy = default_server.is_some_and(|d| d.send_proxy);
    let mut send_proxy_v2 = default_server.is_some_and(|d| d.send_proxy_v2);
    let mut maxconn = default_server.and_then(|d| d.maxconn);
    let mut pool_max_conn = default_server.and_then(|d| d.pool_max_conn).unwrap_or(-1);
    let mut pool_low_conn = default_server.and_then(|d| d.pool_low_conn).unwrap_or(0);
    let mut pool_purge_delay = default_server.and_then(|d| d.pool_purge_delay).unwrap_or(5000);
    let mut check_port = default_server.and_then(|d| d.check_port);
    let mut check_proto = default_server.and_then(|d| d.check_proto);
    let mut weight = default_server.and_then(|d| d.weight);
    let mut backup = default_server.is_some_and(|d| d.backup);
    let mut tfo = default_server.is_some_and(|d| d.tfo);
    let mut cookie = default_server.and_then(|d| d.cookie.clone());
    let mut proxy_v2_unique_id = default_server.is_some_and(|d| d.proxy_v2_unique_id);
    let mut ssl = default_server.map(|d| d.ssl.clone()).unwrap_or_default();
    let mut disabled = default_server.is_some_and(|d| d.disabled);
    let mut track = default_server.and_then(|d| d.track.clone());
    let mut puid = 0u32;
    let index = u32::try_from(servers.len()).unwrap_or(u32::MAX);
    // `srv_check_health` of a server nothing checks: the last `rise` given (`srv_settings_cpy`
    // copies the one of `default-server`, `srv_parse_check_rise` sets it again), 0 when there
    // is none, and for a server `disabled` after it.
    let mut health = if disabled { 0 } else { default_server.and_then(|d| d.rise).unwrap_or(0) };

    // Every keyword HAProxy knows is either implemented here or listed, with what Ibex
    // does about it, in `server_keywords.rs`. A keyword's argument is consumed with it.
    let mut i = 3;
    while i < tokens.len() {
        if let Some(last) = parse_server_ssl_keyword(&mut ssl, tokens, i, who)? {
            i = last + 1;
            continue;
        }
        match tokens[i].text.as_str() {
            "check" => check = true,
            "no-check" => check = false,
            "inter" => {
                inter = Some(parse_server_delay(server_kw_arg(tokens, i, who, "expects a delay as argument.")?, "inter", who)?);
                i += 1;
            }
            "fastinter" => {
                fastinter = Some(parse_server_delay(server_kw_arg(tokens, i, who, "expects a delay as argument.")?, "fastinter", who)?);
                i += 1;
            }
            "downinter" => {
                downinter = Some(parse_server_delay(server_kw_arg(tokens, i, who, "expects a delay as argument.")?, "downinter", who)?);
                i += 1;
            }
            "fall" => {
                fall = Some(parse_u32(server_kw_arg(tokens, i, who, "expects an integer argument.")?, "fall")?);
                i += 1;
            }
            "rise" => {
                let value = parse_u32(server_kw_arg(tokens, i, who, "expects an integer argument.")?, "rise")?;
                rise = Some(value);
                health = value;
                i += 1;
            }
            "send-proxy" => send_proxy = true,
            "no-send-proxy" => send_proxy = false,
            "send-proxy-v2" => send_proxy_v2 = true,
            "no-send-proxy-v2" => send_proxy_v2 = false,
            "weight" => {
                i += 1;
                if i < tokens.len() {
                    weight = Some(parse_u32(&tokens[i], "weight")?);
                }
            }
            "maxconn" => {
                i += 1;
                if i < tokens.len() {
                    maxconn = Some(parse_u32(&tokens[i], "maxconn")?);
                }
            }
            "pool-max-conn" => {
                pool_max_conn = parse_pool_max_conn(tokens, i, who)?;
                i += 1;
            }
            "pool-low-conn" => {
                pool_low_conn = parse_pool_low_conn(tokens, i, who)?;
                i += 1;
            }
            "pool-purge-delay" => {
                pool_purge_delay = parse_pool_purge_delay(tokens, i, who)?;
                i += 1;
            }
            "port" => {
                check_port = Some(parse_u16(server_kw_arg(tokens, i, who, "expects a port number as argument.")?, "port")?);
                i += 1;
            }
            "check-proto" => {
                check_proto = Some(parse_server_proto(tokens, i, who)?);
                i += 1;
            }
            "proto" => {
                parse_server_proto(tokens, i, who)?;
                i += 1;
            }
            "cookie" => {
                cookie = Some(server_kw_arg(tokens, i, who, "expects <value> as argument.")?.text.clone());
                i += 1;
            }
            "proxy-v2-options" => {
                i += 1;
                proxy_v2_unique_id |= parse_proxy_v2_options(tokens.get(i), kw)?;
            }
            "id" => {
                // `srv_parse_id`: `atol`, then 1 to `u32::MAX`; a name is 0.
                let arg = server_kw_arg(tokens, i, who, "expects an integer argument")?;
                let digits: String = arg.text.chars().take_while(char::is_ascii_digit).collect();
                let value = digits.parse::<u64>().unwrap_or(0);
                let Some(id) = u32::try_from(value).ok().filter(|&v| v >= 1) else {
                    return Err(ConfigError::new(
                        arg.line,
                        arg.col,
                        format!("'server {}' : 'id' : custom id has to be between 1 and 4294967295.", tokens[1].text),
                    ));
                };
                if let Some(other) = extras.puid.iter().find(|e| e.1 == id).and_then(|e| servers.get(e.0 as usize)) {
                    return Err(ConfigError::new(
                        arg.line,
                        arg.col,
                        format!("'server {}' : 'id' : custom id {id} already used by 'server {}'", tokens[1].text, other.id),
                    ));
                }
                puid = id;
                i += 1;
            }
            "tfo" => tfo = true,
            "no-tfo" => tfo = false,
            "backup" => backup = true,
            "no-backup" => backup = false,
            "disabled" => {
                disabled = true;
                health = 0;
            }
            "enabled" => {
                disabled = false;
                health = rise.unwrap_or(0);
            }
            "track" => {
                track = Some(server_kw_arg(tokens, i, who, "expects [<proxy>/]<server> as argument.")?.text.as_str().into());
                i += 1;
            }
            // What these turn on, Ibex never does: they leave the server as Ibex runs it.
            "stick" | "no-agent-check" | "no-check-send-proxy" | "no-check-reuse-pool"
            | "no-send-proxy-v2-ssl" | "no-send-proxy-v2-ssl-cn" => {}
            _ => i = unimplemented_server_keyword(tokens, i, who)?,
        }
        i += 1;
    }
    if let Some(prefix) = validate_server_ssl(&ssl, check_port, kw, who)? {
        // Whether this is an error waits for the global `ssl-server-verify` (`apply_ssl_server_verify`).
        extras.no_ca.push(crate::ast::NoCa {
            line: kw.line,
            col: kw.col,
            prefix,
            explicit: ssl.verify == Some(SslVerify::Required),
        });
    }

    // Kept apart from the server: a backend of 60,000 of them must stay small.
    if health != 0 {
        extras.init_health.push((index, health));
    }
    if puid != 0 {
        extras.puid.push((index, puid));
    }
    servers.push(Server {
        check_port,
        check_proto,
        // Boxed, and absent when no TLS keyword touched it, so a plaintext server is 8
        // bytes (`Server` embeds no TLS state): the memory-bound tests stay where they were.
        ssl: (ssl != ServerSsl::default()).then(|| Box::new(ssl)),
        proxy_v2_unique_id,
        id: tokens[1].text.clone(),
        addr,
        check,
        inter,
        fall,
        rise,
        send_proxy,
        send_proxy_v2,
        weight,
        maxconn,
        pool: {
            let pool = crate::ast::server::ServerPool {
                max_conn: pool_max_conn,
                low_conn: pool_low_conn,
                purge_delay: pool_purge_delay,
                fastinter_ms: fastinter.map_or(0, |d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX)),
                downinter_ms: downinter.map_or(0, |d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX)),
            };
            (pool != crate::ast::server::ServerPool::default()).then(|| Box::new(pool))
        },
        backup,
        tfo,
        cookie: cookie.map(String::into_boxed_str),
        disabled,
        track,
    });
    Ok(())
}

/// The TLS keywords of a server line (`src/cfgparse-ssl.c`). `Ok(Some(last))` when
/// `tokens[i]` is one, with the index of its last argument; `Ok(None)` when it is not.
///
/// What rustls cannot do is refused rather than approximated: it speaks TLS 1.2 and 1.3
/// only, so a line that pins an older version would describe a server Ibex can never
/// reach. `no-sslv3`, `no-tlsv10` and `no-tlsv11` are accepted because what they ask for
/// is already the case.
#[allow(clippy::too_many_lines)]
fn parse_server_ssl_keyword(
    ssl: &mut ServerSsl,
    tokens: &[Token],
    i: usize,
    who: Option<&str>,
) -> Result<Option<usize>, ConfigError> {
    let kw = &tokens[i];
    let prefix = server_prefix(who);
    let arg = |what: &str| server_kw_arg(tokens, i, who, what);
    let list = |t: &Token| t.text.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect::<Vec<_>>();
    let rustls_only = |what: &str| {
        Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("{prefix}'{}' is not supported: rustls speaks TLS 1.2 and 1.3 only, so {what}.", kw.text),
        ))
    };
    // HAProxy skips these on a default-server line with an alert; the configuration is valid.
    if who.is_none() && matches!(kw.text.as_str(), "no-sslv3" | "no-tlsv10" | "no-tlsv11" | "no-tlsv12" | "no-tlsv13") {
        eprintln!("[ibex] warning: '{}' option is not accepted in default-server sections; ignored", kw.text);
        return Ok(Some(i));
    }
    let last = match kw.text.as_str() {
        "ssl" => {
            ssl.ssl = true;
            i
        }
        "no-ssl" => {
            ssl.ssl = false;
            i
        }
        "verify" => {
            let v = arg(": missing parameter.")?;
            ssl.verify = Some(match v.text.as_str() {
                "none" => SslVerify::None,
                "required" => SslVerify::Required,
                other => {
                    return Err(ConfigError::new(
                        kw.line,
                        kw.col,
                        format!("{prefix}'verify' : unknown verify method '{other}', only 'none' and 'required' are supported."),
                    ))
                }
            });
            i + 1
        }
        "ca-file" => {
            ssl.ca_file = Some(arg(": missing CAfile path.")?.text.clone());
            i + 1
        }
        "crl-file" => {
            ssl.crl_file = Some(arg(": missing CRLfile path.")?.text.clone());
            i + 1
        }
        "crt" => {
            ssl.crt = Some(arg(": missing certificate file path.")?.text.clone());
            i + 1
        }
        "sni" => {
            ssl.sni = Some(arg(": missing sni expression.")?.text.clone());
            i + 1
        }
        "sni-auto" => {
            ssl.no_sni_auto = false;
            i
        }
        "no-sni-auto" => {
            ssl.no_sni_auto = true;
            i
        }
        "verifyhost" => {
            ssl.verifyhost = Some(arg(": missing hostname to verify against.")?.text.clone());
            i + 1
        }
        "alpn" => {
            ssl.alpn = list(arg(": missing the comma-delimited ALPN protocol suite.")?);
            i + 1
        }
        "check-alpn" => {
            ssl.check_alpn = list(arg(": missing the comma-delimited ALPN protocol suite.")?);
            i + 1
        }
        "check-sni" => {
            ssl.check_sni = Some(arg(": missing SNI.")?.text.clone());
            i + 1
        }
        "check-sni-auto" => {
            ssl.no_check_sni_auto = false;
            i
        }
        "no-check-sni-auto" => {
            ssl.no_check_sni_auto = true;
            i
        }
        "check-ssl" => {
            ssl.check_ssl = Some(true);
            i
        }
        "no-check-ssl" => {
            ssl.check_ssl = Some(false);
            i
        }
        "ssl-min-ver" => {
            ssl.min_ver = Some(parse_tls_version(arg(": missing the ssl/tls version.")?, who)?);
            i + 1
        }
        "ssl-max-ver" => {
            ssl.max_ver = Some(parse_tls_version(arg(": missing the ssl/tls version.")?, who)?);
            i + 1
        }
        "force-tlsv12" => {
            ssl.min_ver = Some(TlsVersion::Tls12);
            ssl.max_ver = Some(TlsVersion::Tls12);
            i
        }
        "force-tlsv13" => {
            ssl.min_ver = Some(TlsVersion::Tls13);
            ssl.max_ver = Some(TlsVersion::Tls13);
            i
        }
        "force-sslv3" | "force-tlsv10" | "force-tlsv11" => {
            return rustls_only("a server that only speaks that version cannot be reached");
        }
        "no-tlsv12" => {
            ssl.min_ver = Some(TlsVersion::Tls13);
            i
        }
        "no-tlsv13" => {
            ssl.max_ver = Some(TlsVersion::Tls12);
            i
        }
        // rustls never offers these: what the keyword asks for is already the case.
        "no-sslv3" | "no-tlsv10" | "no-tlsv11" => i,
        "ssl-reuse" => {
            ssl.no_reuse = false;
            i
        }
        "no-ssl-reuse" => {
            ssl.no_reuse = true;
            i
        }
        _ => return Ok(None),
    };
    Ok(Some(last))
}

/// `ssl-min-ver` / `ssl-max-ver`: `HAProxy` knows `SSLv3` and `TLSv1.0` to `TLSv1.3`
/// ("'TLSv1.4' : unknown ssl/tls version."); rustls speaks the last two.
fn parse_tls_version(t: &Token, who: Option<&str>) -> Result<TlsVersion, ConfigError> {
    let prefix = server_prefix(who);
    match t.text.as_str() {
        "TLSv1.2" => Ok(TlsVersion::Tls12),
        "TLSv1.3" => Ok(TlsVersion::Tls13),
        "SSLv3" | "TLSv1.0" | "TLSv1.1" => Err(ConfigError::new(
            t.line,
            t.col,
            format!(
                "{prefix}'{}' is not supported: rustls speaks TLS 1.2 and 1.3 only, so a server that needs it cannot be reached.",
                t.text
            ),
        )),
        other => Err(ConfigError::new(t.line, t.col, format!("{prefix}'{other}' : unknown ssl/tls version."))),
    }
}

/// What `HAProxy` checks once a server line is complete (`ssl_sock_prepare_srv_ctx`):
/// a TLS server, or a TLS check, verifies the certificate unless told not to, and that
/// needs trust anchors. The alert is `HAProxy`'s, and whether it is raised depends on the
/// global `ssl-server-verify`, which may come later in the file: `Ok(Some(start))` is a
/// line that needs a CA it has not got, with the start of the alert for
/// `apply_ssl_server_verify` to finish.
fn validate_server_ssl(ssl: &ServerSsl, check_port: Option<u16>, kw: &Token, who: Option<&str>) -> Result<Option<String>, ConfigError> {
    let prefix = server_prefix(who);
    let mut no_ca = None;
    if (ssl.ssl || ssl.check_uses_tls(check_port)) && ssl.verify != Some(SslVerify::None) && ssl.ca_file.is_none() {
        let turned_on = if ssl.ssl { "ssl" } else { "check-ssl" };
        no_ca = Some(format!("{prefix}'{turned_on}' : "));
    }
    if let (Some(min), Some(max)) = (ssl.min_ver, ssl.max_ver) {
        if min > max {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("{prefix}no TLS version is left between 'ssl-min-ver' and 'ssl-max-ver'."),
            ));
        }
    }
    Ok(no_ca)
}

/// `proto <mux>` and `check-proto <mux>`: the protocol spoken to the server. Ibex speaks
/// HTTP/1.1 and has no HTTP/2 mux towards servers, so `h2` is refused: a server that
/// speaks only h2 would refuse every request, and until T113 the keyword was a warning
/// that two reg-tests passed through by having both ends ignore it. `HAProxy` refuses a
/// protocol it has no mux for ("'proto' :  unknown MUX protocol 'h3'.").
fn parse_server_proto(tokens: &[Token], i: usize, server: Option<&str>) -> Result<&'static str, ConfigError> {
    let kw = &tokens[i];
    let value = &server_kw_arg(tokens, i, server, ": missing value.")?.text;
    let prefix = server_prefix(server);
    match value.as_str() {
        // The one protocol Ibex speaks to servers; a `&'static str` so `Server` stays the
        // size it was before `ssl` joined it (60,000 of them are measured).
        "h1" => Ok("h1"),
        "h2" => {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                format!(
                    "{prefix}'{}' : 'h2' is not supported: Ibex has no HTTP/2 mux towards servers and speaks \
                     HTTP/1.1 to them, which a server expecting h2 would refuse.",
                    kw.text
                ),
            ));
        }
        "fcgi" | "spop" | "quic" | "qmux" | "none" => {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("{prefix}'{}' : '{value}' is not supported: Ibex speaks only HTTP/1.1 to servers.", kw.text),
            ));
        }
        other => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("{prefix}'{}' :  unknown MUX protocol '{other}'.", kw.text),
        )),
    }
}

/// `pool-max-conn <max>` (`srv_parse_pool_max_conn`): `atoi`, so text that is not a number
/// reads as 0, and anything below -1 is refused.
fn parse_pool_max_conn(tokens: &[Token], i: usize, who: Option<&str>) -> Result<i32, ConfigError> {
    let arg = server_kw_arg(tokens, i, who, "expects <value> as argument.")?;
    let t = arg.text.trim_start();
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let mut n: i64 = 0;
    for b in digits.bytes().take_while(u8::is_ascii_digit) {
        n = (n * 10 + i64::from(b - b'0')).min(i64::from(i32::MAX) + 1);
    }
    let n = if neg { -n } else { n };
    if n < -1 {
        let prefix = server_keywords::server_prefix(who);
        return Err(ConfigError::new(tokens[i].line, tokens[i].col, format!("{prefix}'pool-max-conn' must be >= -1")));
    }
    Ok(n.min(i64::from(i32::MAX)) as i32)
}

/// `pool-low-conn <max>` (`srv_parse_pool_low_conn`): `atoi` into an unsigned count, so text
/// that is not a number reads as 0 and a negative number wraps.
fn parse_pool_low_conn(tokens: &[Token], i: usize, who: Option<&str>) -> Result<u32, ConfigError> {
    let arg = server_kw_arg(tokens, i, who, "expects <value> as argument.")?;
    let t = arg.text.trim_start();
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let mut n: i64 = 0;
    for b in digits.bytes().take_while(u8::is_ascii_digit) {
        n = (n * 10 + i64::from(b - b'0')).min(i64::from(i32::MAX));
    }
    let n = if neg { -n } else { n };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(n as i32 as u32)
}

/// `pool-purge-delay <delay>` (`srv_parse_pool_purge_delay`): a time in milliseconds by
/// default, with `HAProxy`'s messages.
fn parse_pool_purge_delay(tokens: &[Token], i: usize, who: Option<&str>) -> Result<u32, ConfigError> {
    let arg = server_kw_arg(tokens, i, who, "expects <value> as argument.")?;
    let prefix = server_keywords::server_prefix(who);
    super::rules_http::parse_time_ms(&arg.text).map_err(|e| {
        let msg = if e.starts_with("unexpected character") {
            format!("{prefix}{} in argument to <pool-purge-delay>.", e.trim_end_matches('.'))
        } else {
            format!(
                "{prefix}timer overflow in argument '{}' to 'pool-purge-delay' (maximum value is 2147483647 ms or ~24.8 days)",
                arg.text
            )
        };
        ConfigError::new(tokens[i].line, tokens[i].col, msg)
    })
}

pub(crate) fn parse_default_server(
    def: &mut Option<DefaultServerConfig>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    let mut cfg = def.take().unwrap_or_default();
    let mut i = 1;
    while i < tokens.len() {
        if let Some(last) = parse_server_ssl_keyword(&mut cfg.ssl, tokens, i, None)? {
            i = last + 1;
            continue;
        }
        match tokens[i].text.as_str() {
            "check" => cfg.check = true,
            "no-check" => cfg.check = false,
            "inter" => {
                cfg.inter = Some(parse_server_delay(server_kw_arg(tokens, i, None, "expects a delay as argument.")?, "inter", None)?);
                i += 1;
            }
            "fastinter" => {
                cfg.fastinter = Some(parse_server_delay(server_kw_arg(tokens, i, None, "expects a delay as argument.")?, "fastinter", None)?);
                i += 1;
            }
            "downinter" => {
                cfg.downinter = Some(parse_server_delay(server_kw_arg(tokens, i, None, "expects a delay as argument.")?, "downinter", None)?);
                i += 1;
            }
            "fall" => {
                cfg.fall = Some(parse_u32(server_kw_arg(tokens, i, None, "expects an integer argument.")?, "fall")?);
                i += 1;
            }
            "rise" => {
                cfg.rise = Some(parse_u32(server_kw_arg(tokens, i, None, "expects an integer argument.")?, "rise")?);
                i += 1;
            }
            "send-proxy" => cfg.send_proxy = true,
            "no-send-proxy" => cfg.send_proxy = false,
            "send-proxy-v2" => cfg.send_proxy_v2 = true,
            "no-send-proxy-v2" => cfg.send_proxy_v2 = false,
            "weight" => {
                i += 1;
                if i < tokens.len() {
                    cfg.weight = Some(parse_u32(&tokens[i], "weight")?);
                }
            }
            "maxconn" => {
                i += 1;
                if i < tokens.len() {
                    cfg.maxconn = Some(parse_u32(&tokens[i], "maxconn")?);
                }
            }
            "pool-max-conn" => {
                cfg.pool_max_conn = Some(parse_pool_max_conn(tokens, i, None)?);
                i += 1;
            }
            "pool-low-conn" => {
                cfg.pool_low_conn = Some(parse_pool_low_conn(tokens, i, None)?);
                i += 1;
            }
            "pool-purge-delay" => {
                cfg.pool_purge_delay = Some(parse_pool_purge_delay(tokens, i, None)?);
                i += 1;
            }
            "port" => {
                cfg.check_port = Some(parse_u16(server_kw_arg(tokens, i, None, "expects a port number as argument.")?, "port")?);
                i += 1;
            }
            "check-proto" => {
                cfg.check_proto = Some(parse_server_proto(tokens, i, None)?);
                i += 1;
            }
            "proto" => {
                parse_server_proto(tokens, i, None)?;
                i += 1;
            }
            "cookie" => {
                cfg.cookie = Some(server_kw_arg(tokens, i, None, "expects <value> as argument.")?.text.clone());
                i += 1;
            }
            "proxy-v2-options" => {
                i += 1;
                cfg.proxy_v2_unique_id |= parse_proxy_v2_options(tokens.get(i), kw)?;
            }
            "tfo" => cfg.tfo = true,
            "no-tfo" => cfg.tfo = false,
            "backup" => cfg.backup = true,
            "no-backup" => cfg.backup = false,
            "disabled" => cfg.disabled = true,
            "enabled" => cfg.disabled = false,
            "track" => {
                cfg.track = Some(server_kw_arg(tokens, i, None, "expects [<proxy>/]<server> as argument.")?.text.as_str().into());
                i += 1;
            }
            "stick" | "no-agent-check" | "no-check-send-proxy" | "no-check-reuse-pool"
            | "no-send-proxy-v2-ssl" | "no-send-proxy-v2-ssl-cn" => {}
            _ => i = unimplemented_server_keyword(tokens, i, None)?,
        }
        i += 1;
    }
    *def = Some(cfg);
    Ok(())
}

pub(crate) fn parse_balance(
    balance: &mut BalanceAlgorithm,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<balance> expects an algorithm as argument.",
        ));
    }
    *balance = match tokens[1].text.as_str() {
        "roundrobin" => BalanceAlgorithm::RoundRobin,
        "source" => BalanceAlgorithm::Source,
        "uri" => BalanceAlgorithm::Uri,
        "leastconn" => BalanceAlgorithm::Leastconn,
        "static-rr" => BalanceAlgorithm::StaticRr,
        "first" => BalanceAlgorithm::First,
        "random" => BalanceAlgorithm::Random(2),
        other if other.starts_with("random(") => {
            let Some(inner) = other.strip_prefix("random(").and_then(|s| s.strip_suffix(')')) else {
                return Err(ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    "random : missing closing parenthesis.",
                ));
            };
            let draws: u32 = inner.parse().map_err(|_| {
                ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!("random : unexpected argument '{inner}'."),
                )
            })?;
            if draws < 1 {
                return Err(ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    "random : number of draws must be at least 1.",
                ));
            }
            BalanceAlgorithm::Random(draws)
        }
        other => {
            return Err(ConfigError::new(
                tokens[1].line,
                tokens[1].col,
                format!("unknown balance algorithm <{other}>"),
            ));
        }
    };
    Ok(())
}

pub(crate) fn parse_hash_type(
    hash_type: &mut HashType,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "'hash-type' only supports 'consistent' and 'map-based'.",
        ));
    }
    *hash_type = match tokens[1].text.as_str() {
        "consistent" => HashType::Consistent,
        "map-based" => HashType::MapBased,
        _ => {
            return Err(ConfigError::new(
                tokens[1].line,
                tokens[1].col,
                "'hash-type' only supports 'consistent' and 'map-based'.",
            ));
        }
    };
    if tokens.len() > 2 {
        return Err(ConfigError::new(
            tokens[2].line,
            tokens[2].col,
            "'hash-type': hash function and 'avalanche' modifiers are not implemented.",
        ));
    }
    Ok(())
}

pub(crate) fn parse_hash_preserve_affinity(
    mode: &mut HashPreserveAffinity,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "'hash-preserve-affinity' needs a keyword to specify when to preserve hash affinity.",
        ));
    }
    *mode = match tokens[1].text.as_str() {
        "always" => HashPreserveAffinity::Always,
        "maxconn" => HashPreserveAffinity::MaxConn,
        "maxqueue" => {
            return Err(ConfigError::new(
                tokens[1].line,
                tokens[1].col,
                "'hash-preserve-affinity maxqueue' is not implemented: Ibex has no per-server \
                 request queue, so it cannot hold a request at a saturated server until that \
                 server's queue fills. Use 'always' or 'maxconn'.",
            ));
        }
        other => {
            return Err(ConfigError::new(
                tokens[1].line,
                tokens[1].col,
                format!("'hash-preserve-affinity': unknown keyword '{other}'."),
            ));
        }
    };
    Ok(())
}

pub(crate) fn parse_http_reuse(
    reuse: &mut Option<HttpReuse>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<http-reuse> expects a strategy ('never', 'safe', 'aggressive', 'always') as argument.",
        ));
    }
    *reuse = match tokens[1].text.as_str() {
        "never" => Some(HttpReuse::Never),
        "safe" => Some(HttpReuse::Safe),
        "aggressive" => Some(HttpReuse::Aggressive),
        "always" => Some(HttpReuse::Always),
        other => {
            return Err(ConfigError::new(
                tokens[1].line,
                tokens[1].col,
                format!("unknown http-reuse strategy <{other}>, expected 'never', 'safe', 'aggressive', or 'always'"),
            ));
        }
    };
    Ok(())
}


/// `proxy-v2-options <option>[,<option>]*` (`srv_parse_proxy_v2_options`): whether it asks
/// for `unique-id`. `HAProxy`'s other options (the SSL ones, `authority`, `crc32c`) put TLVs
/// in the header that Ibex does not build, so they are refused rather than left out of it.
fn parse_proxy_v2_options(arg: Option<&Token>, kw: &Token) -> Result<bool, ConfigError> {
    let text = arg.map_or("", |t| t.text.as_str());
    let mut unique_id = false;
    for opt in text.split(',') {
        match opt {
            "unique-id" => unique_id = true,
            "ssl" | "cert-cn" | "cert-key" | "cert-sig" | "ssl-cipher" | "authority" | "crc32c" => {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    format!("'proxy-v2-options' : '{opt}' is not implemented in Ibex"),
                ));
            }
            _ => {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{opt}' : proxy v2 option not implemented")));
            }
        }
    }
    Ok(unique_id)
}
