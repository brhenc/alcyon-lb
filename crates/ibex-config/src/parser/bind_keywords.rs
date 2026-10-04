// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `bind` keywords `HAProxy` knows and Ibex does not implement, and what Ibex does
//! with each (T110).
//!
//! `parse_bind` in `proxy.rs` handles the keywords that reach Ibex's data path (`ssl`,
//! `crt`, `alpn`, `proto`, `accept-proxy`, `accept-proxy-v2`). Everything else lands
//! here, and there are only two outcomes, as for server keywords (`server_keywords.rs`):
//!
//! * **refused**, when running without the keyword changes security, who may connect, or
//!   how the connection is served. `bind :443 ssl crt c.pem verify required ca-file ca.pem`
//!   would otherwise load and accept any client;
//! * **ignored with a warning**, when the keyword only tunes the socket or names it.
//!
//! A keyword in neither place is unknown, as `HAProxy` reports it. `args` is the number
//! of arguments the keyword takes, so an ignored keyword's argument is never read as the
//! next keyword.
//!
//! The list is what `haproxy -dKall` prints for `bind <addr>` in 3.5-dev8, plus the QUIC
//! keywords.

use super::{ConfigError, Token};

pub(crate) struct BindKeyword {
    pub name: &'static str,
    pub args: usize,
    /// `None` is refused; `Some(what)` is ignored with a warning naming what it tunes.
    pub ignore: Option<&'static str>,
}

macro_rules! refuse {
    ($name:expr, $args:expr) => {
        BindKeyword { name: $name, args: $args, ignore: None }
    };
}

macro_rules! ignore {
    ($name:expr, $args:expr, $what:expr) => {
        BindKeyword { name: $name, args: $args, ignore: Some($what) }
    };
}

pub(crate) const UNIMPLEMENTED_BIND_KEYWORDS: &[BindKeyword] = &[
    refuse!("accept-netscaler-cip", 1),
    ignore!("backlog", 1, "the listen backlog"),
    ignore!("cc", 1, "the TCP congestion control algorithm"),
    ignore!("defer-accept", 0, "TCP_DEFER_ACCEPT"),
    refuse!("expose-fd", 1),
    refuse!("gid", 1),
    refuse!("group", 1),
    ignore!("guid-prefix", 1, "a global identifier for the CLI and stats"),
    ignore!("idle-ping", 1, "idle connection pings"),
    refuse!("interface", 1),
    ignore!("label", 1, "a name for the stats"),
    refuse!("level", 1),
    refuse!("maxconn", 1),
    refuse!("mode", 1),
    ignore!("mss", 1, "the TCP maximum segment size"),
    refuse!("namespace", 1),
    ignore!("nbconn", 1, "the number of sockets per listener"),
    ignore!("nice", 1, "the scheduling priority of its connections"),
    ignore!("process", 1, "which process accepts"),
    refuse!("severity-output", 1),
    ignore!("shards", 1, "how many threads accept"),
    refuse!("tcp-md5sig", 1),
    ignore!("tcp-ss", 1, "TCP slow start"),
    ignore!("tcp-ut", 1, "the TCP user timeout"),
    ignore!("tfo", 0, "TCP Fast Open"),
    ignore!("thread", 1, "which threads accept"),
    refuse!("transparent", 0),
    refuse!("uid", 1),
    refuse!("user", 1),
    ignore!("v4v6", 0, "IPv6 dual-stack sockets"),
    ignore!("v6only", 0, "IPv6-only sockets"),
    refuse!("allow-0rtt", 0),
    refuse!("ca-file", 1),
    refuse!("ca-ignore-err", 1),
    refuse!("ca-sign-file", 1),
    refuse!("ca-sign-pass", 1),
    refuse!("ca-verify-file", 1),
    refuse!("ciphers", 1),
    refuse!("ciphersuites", 1),
    refuse!("client-sigalgs", 1),
    refuse!("crl-file", 1),
    refuse!("crt-ignore-err", 1),
    refuse!("crt-list", 1),
    refuse!("curves", 1),
    refuse!("default-crt", 1),
    refuse!("ecdhe", 1),
    refuse!("force-sslv3", 0),
    refuse!("force-tlsv10", 0),
    refuse!("force-tlsv11", 0),
    refuse!("force-tlsv12", 0),
    refuse!("force-tlsv13", 0),
    refuse!("generate-certificates", 0),
    refuse!("ktls", 1),
    refuse!("no-alpn", 0),
    refuse!("no-ca-names", 0),
    refuse!("no-sslv3", 0),
    refuse!("no-strict-sni", 0),
    refuse!("no-tls-tickets", 0),
    refuse!("no-tlsv10", 0),
    refuse!("no-tlsv11", 0),
    refuse!("no-tlsv12", 0),
    refuse!("no-tlsv13", 0),
    refuse!("npn", 1),
    refuse!("prefer-client-ciphers", 0),
    refuse!("sigalgs", 1),
    refuse!("ssl-max-ver", 1),
    refuse!("ssl-min-ver", 1),
    refuse!("strict-sni", 0),
    refuse!("tls-ticket-keys", 1),
    refuse!("tls-tickets", 0),
    refuse!("verify", 1),
    refuse!("quic-cc-algo", 1),
    refuse!("quic-force-retry", 0),
    refuse!("quic-socket", 1),
];

/// Handles `tokens[i]`, a bind keyword Ibex does not implement, on the `bind` line of
/// `section` (`listen` or `frontend`). Returns the index of its last argument.
pub(crate) fn unimplemented_bind_keyword(
    tokens: &[Token],
    i: usize,
    section: &str,
) -> Result<usize, ConfigError> {
    let tok = &tokens[i];
    let prefix = format!("'bind {}' in section '{section}'", tokens[1].text);
    let Some(k) = UNIMPLEMENTED_BIND_KEYWORDS.iter().find(|k| k.name == tok.text) else {
        return Err(ConfigError::new(tok.line, tok.col, format!("{prefix}: unknown keyword '{}'.", tok.text)));
    };
    if i + k.args >= tokens.len() {
        return Err(ConfigError::new(tok.line, tok.col, format!("{prefix} : '{}' expects an argument.", k.name)));
    }
    match k.ignore {
        None => Err(ConfigError::new(
            tok.line,
            tok.col,
            format!(
                "{prefix} : '{}' is not supported: Ibex does not implement it, and would serve the bind without it.",
                k.name
            ),
        )),
        Some(what) => {
            eprintln!("[ibex] warning: {prefix} : '{}' is not implemented and is ignored ({what}).", k.name);
            Ok(i + k.args)
        }
    }
}
