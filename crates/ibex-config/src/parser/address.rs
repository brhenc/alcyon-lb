use super::*;

pub(crate) fn parse_socket_addr(token: &Token, default_port: Option<u16>) -> Result<(SocketAddr, bool), ConfigError> {
    let mut s = token.text.as_str();

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
        "dgram+", "quic4+", "quic6+",
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
                stripped.parse::<u16>().map_err(|_| {
                    ConfigError::new(
                        token.line,
                        token.col + bracket_end + 1,
                        format!("invalid port '{stripped}' (must be 0..=65535)"),
                    )
                })?
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
            return Ok((SocketAddr::new(ip, port), is_quic));
        }
    }

    if let Some(colon_pos) = s.rfind(':') {
        let (host_part, port_part_with_colon) = s.split_at(colon_pos);
        let port_part = &port_part_with_colon[1..];
        if port_part.is_empty() {
            return Err(ConfigError::new(
                token.line,
                token.col + colon_pos,
                format!("missing port in address '{s}'"),
            ));
        }
        let port: u16 = port_part.parse().map_err(|_| {
            ConfigError::new(
                token.line,
                token.col + colon_pos + 1,
                format!("invalid port '{port_part}' (must be 0..=65535)"),
            )
        })?;
        let ip = parse_ip(host_part, token.line, token.col)?;
        Ok((SocketAddr::new(ip, port), is_quic))
    } else if let Some(port) = default_port {
        let ip = parse_ip(s, token.line, token.col)?;
        Ok((SocketAddr::new(ip, port), is_quic))
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
    s.parse::<IpAddr>()
        .map_err(|_| ConfigError::new(line, col, format!("invalid IP address '{s}'")))
}

