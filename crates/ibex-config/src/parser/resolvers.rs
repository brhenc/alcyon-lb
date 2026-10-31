// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `resolvers` section (`cfg_parse_resolvers`, `src/resolvers.c`), with `HAProxy`'s
//! messages (measured on 3.5-dev8-885761-29, `docs/design/dns-2026-10-25.md` appendix A).
//!
//! Where it goes: `Config::resolvers`, which `ibex_rt::resolvers::build` reads for the
//! sections a server names (T484). `parse-resolv-conf` (T489) adds the `nameserver` lines of
//! `/etc/resolv.conf` where it stands.

use super::{address, server_keywords, ConfigError, Duration, IpAddr, SocketAddr, Token};
use crate::ast::{Nameserver, NsTransport, ResolversSection};

/// `invalid_char`: a name is letters, digits and `_ - . :`.
fn invalid_char(name: &str) -> Option<char> {
    name.chars().find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':')))
}

fn err(tok: &Token, msg: impl Into<String>) -> ConfigError {
    ConfigError::new(tok.line, tok.col, msg)
}

/// The text of `tokens[i]`, empty when there is none (`*args[i]` in C).
fn arg(tokens: &[Token], i: usize) -> &str {
    tokens.get(i).map_or("", |t| t.text.as_str())
}

pub(crate) fn parse_resolvers_header(tokens: &[Token], kw: &Token, done: &[ResolversSection]) -> Result<ResolversSection, ConfigError> {
    let name = arg(tokens, 1);
    if name.is_empty() {
        return Err(err(kw, "missing name for resolvers section."));
    }
    if let Some(c) = invalid_char(name) {
        return Err(err(kw, format!("character '{c}' is not permitted in 'resolvers' name '{name}'.")));
    }
    if let Some(other) = done.iter().find(|r| r.name == name) {
        return Err(err(kw, format!("resolvers '{name}' has same name as another resolvers (declared at line {}).", other.line)));
    }
    Ok(ResolversSection::new(name.to_string(), kw.line))
}

pub(crate) fn parse_resolvers_directive(r: &mut ResolversSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    match kw.text.as_str() {
        "nameserver" => {
            let ns = parse_nameserver(r, tokens, kw)?;
            r.nameservers.push(ns);
        }
        "parse-resolv-conf" => {
            let warnings = parse_resolv_conf(r, RESOLV_CONF).map_err(|e| {
                ConfigError::alerts(vec![
                    (kw.line, format!("config : parsing {{at}}: {e}")),
                    (kw.line, "config : Error(s) found in configuration file : {file}".to_string()),
                    (kw.line, "config : Fatal errors found in configuration.".to_string()),
                ])
            })?;
            // `indent_msg(&warnmsg, 8)`: one line as it is, several each on its own line.
            let text = match warnings.as_slice() {
                [] => return Ok(()),
                [one] => one.clone(),
                many => many.iter().fold(String::new(), |mut acc, w| {
                    acc.push_str("\n        ");
                    acc.push_str(w);
                    acc
                }),
            };
            super::warn::push(kw.line, crate::ast::global::WarnStyle::Tight, &text);
        }
        "hold" => {
            let (event, time) = (arg(tokens, 1), arg(tokens, 2));
            if time.is_empty() {
                return Err(err(
                    kw,
                    "'hold' expects an <event> and a <time> as arguments.\n<event> can be either 'valid', 'nx', 'refused', 'timeout', or 'other'",
                ));
            }
            let d = parse_resolver_time(kw, time, || format!("<{event}> to <hold>"), "<hold>")?;
            let slot = match event {
                "nx" => &mut r.hold.nx,
                "other" => &mut r.hold.other,
                "refused" => &mut r.hold.refused,
                "timeout" => &mut r.hold.timeout,
                "valid" => &mut r.hold.valid,
                "obsolete" => &mut r.hold.obsolete,
                _ => {
                    return Err(err(
                        kw,
                        format!("'hold' unknown <event>: '{event}', expects either 'nx', 'timeout', 'valid', 'obsolete' or 'other'."),
                    ))
                }
            };
            *slot = d;
            warn_if_small(kw, &format!("hold {event}"), time);
        }
        "accepted_payload_size" => {
            let a = arg(tokens, 1);
            if a.is_empty() {
                return Err(err(kw, "'accepted_payload_size' expects <nb> as argument."));
            }
            // `atoi`, then DNS_HEADER_SIZE..=DNS_MAX_MSG_SIZE.
            let n = server_keywords::atol(a);
            let Some(n) = u16::try_from(n).ok().filter(|n| *n >= 12) else {
                return Err(err(kw, format!("'accepted_payload_size' must be between 12 and 65535 inclusive (was {a}).")));
            };
            r.accepted_payload_size = n;
        }
        "resolution_pool_size" => {
            return Err(err(kw, "'resolution_pool_size' directive is not supported anymore (it never appeared in a stable release)."));
        }
        "resolve_retries" => {
            let a = arg(tokens, 1);
            if a.is_empty() {
                return Err(err(kw, "'resolve_retries' expects <nb> as argument."));
            }
            // `atoi`: what is not a number is 0, as in `HAProxy`.
            #[allow(clippy::cast_possible_truncation)]
            {
                r.resolve_retries = server_keywords::atol(a).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
            }
        }
        "timeout" => {
            let which = arg(tokens, 1);
            if which.is_empty() {
                return Err(err(kw, "'timeout' expects 'retry' or 'resolve' and <time> as arguments."));
            }
            if which != "retry" && which != "resolve" {
                return Err(err(kw, format!("'timeout' expects 'retry' or 'resolve' and <time> as arguments got '{which}'.")));
            }
            let time = arg(tokens, 2);
            if time.is_empty() {
                return Err(err(kw, format!("'timeout {which}' expects <time> as argument.")));
            }
            let d = parse_resolver_time(kw, time, || format!("<{time}> to <timeout {which}>"), &format!("<timeout {which}>"))?;
            if which == "retry" {
                r.timeout_retry = d;
            } else {
                r.timeout_resolve = d;
            }
            warn_if_small(kw, &format!("timeout {which}"), time);
        }
        other => return Err(err(kw, format!("unknown keyword '{other}' in 'resolvers' section"))),
    }
    Ok(())
}

/// `parse_time_err(.., TIME_UNIT_MS)` with the section's messages: `overflow_at` names
/// what overflowed (`<nx> to <hold>`), `kw_at` the keyword (`<hold>`).
fn parse_resolver_time(kw: &Token, time: &str, overflow_at: impl FnOnce() -> String, kw_at: &str) -> Result<Duration, ConfigError> {
    match super::rules_http::parse_time_ms(time) {
        Ok(ms) => Ok(Duration::from_millis(u64::from(ms))),
        Err(e) if e.starts_with("unexpected character") => {
            Err(err(kw, format!("{} in argument to {kw_at}.", e.trim_end_matches('.'))))
        }
        Err(_) => Err(err(
            kw,
            format!("timer overflow in argument {}, maximum value is 2147483647 ms (~24.8 days).", overflow_at()),
        )),
    }
}

/// `warn_if_lower(args[2], 100)`: a number with no unit below 100 is probably not meant in
/// milliseconds. `HAProxy` prints it as an alert that does not stop the load.
fn warn_if_small(kw: &Token, what: &str, time: &str) {
    if let Ok(n) = time.parse::<u32>() {
        if n > 0 && n < 100 {
            super::warn::push_alert(
                kw.line,
                crate::ast::global::WarnStyle::Spaced,
                &format!("'{what} {n}' looks suspiciously small for a value in milliseconds. Please use an explicit unit ('{n}ms') if that was the intent."),
            );
        }
    }
}

/// The transport and family (`4` or `6`) a `nameserver` address prefix names, and the rest.
fn split_prefix(text: &str) -> (Option<NsTransport>, Option<u8>, &str) {
    const PREFIXES: [(&str, NsTransport, Option<u8>); 11] = [
        ("tcp@", NsTransport::Tcp, None),
        ("tcp4@", NsTransport::Tcp, Some(4)),
        ("tcp6@", NsTransport::Tcp, Some(6)),
        ("stream+", NsTransport::Tcp, None),
        ("udp@", NsTransport::Udp, None),
        ("udp4@", NsTransport::Udp, Some(4)),
        ("udp6@", NsTransport::Udp, Some(6)),
        ("dgram+", NsTransport::Udp, None),
        ("ipv4@", NsTransport::Default, Some(4)),
        ("ipv6@", NsTransport::Default, Some(6)),
        ("ip@", NsTransport::Default, None),
    ];
    for (p, t, f) in PREFIXES {
        if let Some(rest) = text.strip_prefix(p) {
            return (Some(t), f, rest);
        }
    }
    (None, None, text)
}

fn parse_nameserver(r: &ResolversSection, tokens: &[Token], kw: &Token) -> Result<Nameserver, ConfigError> {
    let (name, text) = (arg(tokens, 1), arg(tokens, 2));
    if text.is_empty() {
        return Err(err(kw, "'nameserver' expects <name> and <addr>[:<port>] as arguments."));
    }
    if let Some(c) = invalid_char(name) {
        return Err(err(kw, format!("character '{c}' is not permitted in server name '{name}'.")));
    }
    if let Some(other) = r.nameservers.iter().find(|n| n.name == name) {
        return Err(err(kw, format!("nameserver '{name}' has same name as another nameserver (declared at line {}).", other.line)));
    }
    let fail = |msg: String| err(kw, format!("'nameserver {name}' : {msg}"));
    // The prefix (`str2sa_range`): the transport and, for the `4`/`6` forms, the family.
    let (transport, fam, rest) = split_prefix(text);
    if transport.is_none() {
        if let Some(at) = text.find('@') {
            return Err(fail(format!("address prefix '{}' is not implemented", &text[..=at])));
        }
    }
    let transport = transport.unwrap_or_default();
    let text_full = text;
    let text = rest;
    // `str2sa_range(.., PA_O_RESOLVE | PA_O_PORT_MAND)`: the port is after the last colon,
    // or after the brackets of an IPv6 address.
    let bracketed = text.strip_prefix('[').and_then(|rest| rest.split_once(']')).is_some();
    let (host, port) = match text.strip_prefix('[').and_then(|rest| rest.split_once(']')) {
        Some((h, p)) => (h, p.strip_prefix(':')),
        None => match text.rfind(':') {
            Some(i) => (&text[..i], Some(&text[i + 1..])),
            None => (text, None),
        },
    };
    let Some(port) = port.filter(|p| !p.is_empty()) else {
        return Err(fail(format!("missing port specification in '{text_full}'")));
    };
    if port.starts_with('+') || port.starts_with('-') {
        return Err(fail(format!("port offset not permitted here in '{text_full}'")));
    }
    if port.contains('-') {
        return Err(fail(format!("port range not permitted here in '{text_full}'")));
    }
    if let Some(c) = port.chars().find(|c| !c.is_ascii_digit()) {
        return Err(fail(format!("invalid character '{c}' in port number '{port}' in '{text_full}'")));
    }
    let Some(port) = port.parse::<u16>().ok().filter(|p| *p != 0) else {
        return Err(fail(format!("invalid port '{port}'")));
    };
    let shown = if bracketed { format!("[{host}]") } else { host.to_string() };
    let ip = match host.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => address::libc_resolve(host).ok_or_else(|| fail(format!("invalid address: '{shown}' in '{text_full}'")))?,
    };
    if (fam == Some(4) && !ip.is_ipv4()) || (fam == Some(6) && !ip.is_ipv6()) {
        return Err(fail(format!("invalid address: '{shown}' in '{text_full}'")));
    }
    Ok(Nameserver { transport, name: name.to_string(), addr: SocketAddr::new(ip, port), line: kw.line, from_resolv_conf: false })
}

/// The file `parse-resolv-conf` reads: `HAProxy` reads this one only.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";

/// `parse_resolve_conf` (`resolvers.c:3598`): adds to `r`, in order, a nameserver for each
/// `nameserver <addr>` line of `path` (named after the address, port 53, UDP with the TCP
/// fallback), and returns the warnings for the lines it skips, as `HAProxy` words them
/// (`{file}` is the configuration file). `path` is [`RESOLV_CONF`] but for tests.
///
/// # Errors
/// `failed to open /etc/resolv.conf.` when `path` cannot be read (fatal in `HAProxy`).
pub fn parse_resolv_conf(r: &mut ResolversSection, path: &str) -> Result<Vec<String>, String> {
    let bytes = std::fs::read(path).map_err(|_| format!("failed to open {RESOLV_CONF}."))?;
    let mut warnings = Vec::new();
    let ws = |c: char| matches!(c, '\r' | '\n' | '\t' | ' ');
    for (i, line) in String::from_utf8_lossy(&bytes).split_inclusive('\n').enumerate() {
        let n = i + 1;
        let Some(rest) = line.strip_prefix("nameserver") else { continue };
        // `strtok(line + 10, " \t\r\n")`: a token right after the keyword is another
        // keyword (`nameserverX`), no token is a missing address.
        if rest.starts_with(|c: char| !ws(c)) {
            continue;
        }
        let Some(addr) = rest.split(ws).find(|t| !t.is_empty()) else {
            warnings.push(format!("parsing [{RESOLV_CONF}:{n}] : nameserver line is missing address."));
            continue;
        };
        if let Some(other) = r.nameservers.iter().find(|o| o.name == addr) {
            let file = if other.from_resolv_conf { RESOLV_CONF } else { "{file}" };
            warnings.push(format!(
                "Parsing [{RESOLV_CONF}:{n}] : generated name for {RESOLV_CONF} nameserver '{addr}' conflicts with another nameserver (declared at {file}:{}), it appears to be a duplicate and will be excluded.",
                other.line
            ));
            continue;
        }
        // `str2ip2(address, sk, 1)`: an address, or a name libc resolves.
        let Some(ip) = addr.parse::<IpAddr>().ok().or_else(|| address::libc_resolve(addr)) else {
            warnings.push(format!("parsing [{RESOLV_CONF}:{n}] : address '{addr}' could not be recognized, nameserver will be excluded."));
            continue;
        };
        r.nameservers.push(Nameserver { name: addr.to_string(), transport: NsTransport::Default, addr: SocketAddr::new(ip, 53), line: n, from_resolv_conf: true });
    }
    Ok(warnings)
}

/// `cfg_post_check_resolvers`: a section without a nameserver draws a warning.
pub(crate) fn check_resolvers(sections: &[ResolversSection]) {
    for r in sections.iter().filter(|r| r.nameservers.is_empty()) {
        super::warn::push(
            r.line,
            crate::ast::global::WarnStyle::Bare,
            &format!("resolvers '{}' {{at}} has no nameservers configured!", r.name),
        );
    }
}
