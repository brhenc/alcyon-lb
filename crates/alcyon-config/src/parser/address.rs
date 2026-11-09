// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use super::*;

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
            if let Some(val) = crate::env::get(&var_name) {
                out.push_str(&val);
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

pub(crate) fn parse_socket_addr(token: &Token, default_port: Option<u16>) -> Result<(SocketAddr, bool), ConfigError> {
    parse_addr(token, default_port, false).map(|(a, q, _)| (a, q))
}

/// A `server` line's address: as [`parse_socket_addr`], and a host that is not an IP
/// address is a name (`str2sa_range` with `fqdn`), returned third with the unspecified
/// address in its place. It is resolved once the configuration is read
/// (`resolve_server_addrs`, `srv_init_addr` in `HAProxy`).
pub(crate) fn parse_server_addr(token: &Token, default_port: Option<u16>) -> Result<(SocketAddr, bool, Option<String>), ConfigError> {
    parse_addr(token, default_port, true)
}

/// `localhost` is a name like any other on a server line (libc gives `::1` first on most
/// hosts, A.t1f); elsewhere it is still `127.0.0.1`.
fn host_ip(s: &str, allow_name: bool, name: &mut Option<String>, line: usize, col: usize) -> Result<IpAddr, ConfigError> {
    let t = s.trim();
    if allow_name && !t.is_empty() && t != "*" && t != "0" && t.parse::<IpAddr>().is_err() {
        *name = Some(t.to_string());
        return Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
    parse_ip(s, line, col)
}

#[allow(clippy::too_many_lines)]
fn parse_addr(token: &Token, default_port: Option<u16>, allow_name: bool) -> Result<(SocketAddr, bool, Option<String>), ConfigError> {
    let mut name = None;
    let expanded = expand_vars(token.text.as_str());

    // An address that was written as `${VAR}` and expanded to nothing is a deployment that
    // forgot to set the variable, not an address. HAProxy refuses it:
    //
    //     'bind' : '${NO_SUCH}' resolves to an empty address (environment variable missing?)
    //
    // Accepting it hands the operator a listener on an address they did not choose. Note
    // this is deliberately narrow: `${UNDEF}:8080` and `${UNDEF_A}:${UNDEF_B}` are accepted
    // by HAProxy and stay accepted here, because what survives the expansion still parses.
    if expanded.is_empty() && token.text.contains("${") {
        return Err(ConfigError::new(
            token.line,
            token.col,
            format!(
                "'{}' resolves to an empty address (environment variable missing?)",
                token.text
            ),
        ));
    }

    let mut s = expanded.as_str();

    let mut is_quic = false;
    if let Some(stripped) = s.strip_prefix("stream+") {
        s = stripped;
    } else if let Some(stripped) = s.strip_prefix("quic+") {
        s = stripped;
        is_quic = true;
    } else if let Some(stripped) = s.strip_prefix("quic4@") {
        s = stripped;
        is_quic = true;
    } else if let Some(stripped) = s.strip_prefix("quic6@") {
        s = stripped;
        is_quic = true;
    }

    let unsupported_prefixes = [
        "dgram+", "quic4+", "quic6+", "backend@", "ring@",
        "fd@", "unix@", "uxdg@", "uxst@", "abns@", "abnsz@", "ip@", "ipv4@",
        "ipv6@", "tcp4@", "mptcp4@", "udp4@", "tcp6@", "mptcp6@", "udp6@",
        "tcp@", "mptcp@", "udp@", "sockpair@", "rhttp@",
    ];
    for prefix in unsupported_prefixes {
        if s.starts_with(prefix) {
            return Err(ConfigError::new(
                token.line,
                token.col,
                format!("address prefix '{prefix}' is not implemented"),
            ));
        }
    }

    if s.starts_with('/') {
        return Err(ConfigError::new(
            token.line,
            token.col,
            "address prefix 'unix@' is not implemented".to_string(),
        ));
    }

    if s.starts_with('[') {
        if let Some(bracket_end) = s.find(']') {
            let ip_str = &s[1..bracket_end];
            let rest = &s[bracket_end + 1..];
            let port = if let Some(stripped) = rest.strip_prefix(':') {
                if stripped.is_empty() {
                    default_port.unwrap_or(0)
                } else if stripped.starts_with('+') || stripped.starts_with('-') {
                    return Err(ConfigError::new(
                        token.line,
                        token.col + bracket_end + 1,
                        format!("port offsets like '{stripped}' are not implemented"),
                    ));
                } else if stripped.contains('-') {
                    return Err(ConfigError::new(
                        token.line,
                        token.col + bracket_end + 1,
                        format!("port ranges like '{stripped}' are not implemented"),
                    ));
                } else {
                    stripped.parse::<u16>().map_err(|_| {
                        ConfigError::new(
                            token.line,
                            token.col + bracket_end + 1,
                            format!("invalid port '{stripped}' (must be 0..=65535)"),
                        )
                    })?
                }
            } else if let Some(port) = default_port {
                port
            } else {
                return Err(ConfigError::new(
                    token.line,
                    token.col,
                    format!("missing port in address '{s}'"),
                ));
            };
            let ip = parse_ip(ip_str, token.line, token.col)?;
            return Ok((SocketAddr::new(ip, port), is_quic, name));
        }
    }

    if let Some(colon_pos) = s.rfind(':') {
        let (host_part, port_part_with_colon) = s.split_at(colon_pos);
        let port_part = &port_part_with_colon[1..];
        
        let port: u16 = if port_part.is_empty() {
            default_port.unwrap_or(0)
        } else if port_part.starts_with('+') || port_part.starts_with('-') {
            return Err(ConfigError::new(
                token.line,
                token.col + colon_pos + 1,
                format!("port offsets like '{port_part}' are not implemented"),
            ));
        } else if port_part.contains('-') {
            return Err(ConfigError::new(
                token.line,
                token.col + colon_pos + 1,
                format!("port ranges like '{port_part}' are not implemented"),
            ));
        } else {
            port_part.parse().map_err(|_| {
                ConfigError::new(
                    token.line,
                    token.col + colon_pos + 1,
                    format!("invalid port '{port_part}' (must be 0..=65535)"),
                )
            })?
        };
        let ip = host_ip(host_part, allow_name, &mut name, token.line, token.col)?;
        Ok((SocketAddr::new(ip, port), is_quic, name))
    } else if let Some(port) = default_port {
        let ip = host_ip(s, allow_name, &mut name, token.line, token.col)?;
        Ok((SocketAddr::new(ip, port), is_quic, name))
    } else if s.is_empty() {
        let ip = parse_ip(s, token.line, token.col)?;
        Ok((SocketAddr::new(ip, 0), is_quic, name))
    } else {
        Err(ConfigError::new(
            token.line,
            token.col,
            format!("missing port in address '{s}'"),
        ))
    }
}

pub(crate) fn parse_ip(s: &str, line: usize, col: usize) -> Result<IpAddr, ConfigError> {
    let s = s.trim();
    if s.is_empty() || s == "*" || s == "0" {
        return Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
    if s.eq_ignore_ascii_case("localhost") {
        return Ok(IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
    s.parse::<IpAddr>()
        .map_err(|_| ConfigError::new(line, col, format!("invalid IP address '{s}'")))
}


/// `resolv_hostname_validation`: at most 255 characters, labels of at most 63 letters,
/// digits, `-` and `_`.
fn valid_hostname(name: &str) -> bool {
    name.len() <= 255
        && name.split('.').all(|l| l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
}

/// `str2ip2(name, .., 1)`: the first address `getaddrinfo` gives for a valid host name
/// (`srv_set_addr_via_libc`). Called while the configuration loads, never after.
pub(crate) fn libc_resolve(name: &str) -> Option<IpAddr> {
    use std::net::ToSocketAddrs;
    if !valid_hostname(name) {
        return None;
    }
    (name, 0).to_socket_addrs().ok()?.next().map(|a| a.ip())
}

/// `resolv_str_to_dn_label` fails on an empty label (`a..b`, `.a`); a final dot is allowed.
pub(crate) fn dn_label_ok(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty() && name.split('.').all(|l| !l.is_empty())
}
