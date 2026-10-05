// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `bind` keywords `HAProxy` knows and Ibex does not implement, and what Ibex does
//! with each (T110).
//!
//! `parse_bind` in `proxy.rs` handles the keywords that reach Ibex's data path (`ssl`,
//! `crt`, `alpn`, `proto`, `accept-proxy`, `accept-proxy-v2`, and since T207 `backlog`,
//! `v6only`, `v4v6`, `tcp-ut`, `cc`, `thread all`). Everything else lands here and is
//! **refused**: a keyword the parser accepts and the data path drops is worse than one
//! it never heard of (AGENTS.md section 5). `bind :443 ssl crt c.pem verify required
//! ca-file ca.pem` would otherwise load and accept any client, and `tfo` would leave the
//! operator believing Fast Open was on.
//!
//! A keyword that is not in the list is unknown, as `HAProxy` reports it. `args` is the
//! number of arguments the keyword takes.
//!
//! The list is what `haproxy -dKall` prints for `bind <addr>` in 3.5-dev8, plus the QUIC
//! keywords.

use super::{ConfigError, Token};

pub(crate) struct BindKeyword {
    pub name: &'static str,
    pub args: usize,
}

macro_rules! refuse {
    ($name:expr, $args:expr) => {
        BindKeyword { name: $name, args: $args }
    };
}

pub(crate) const UNIMPLEMENTED_BIND_KEYWORDS: &[BindKeyword] = &[
    refuse!("accept-netscaler-cip", 1),
    refuse!("defer-accept", 0),
    refuse!("expose-fd", 1),
    refuse!("gid", 1),
    refuse!("group", 1),
    refuse!("guid-prefix", 1),
    refuse!("idle-ping", 1),
    refuse!("interface", 1),
    refuse!("label", 1),
    refuse!("level", 1),
    refuse!("maxconn", 1),
    refuse!("mode", 1),
    refuse!("mss", 1),
    refuse!("namespace", 1),
    refuse!("nbconn", 1),
    refuse!("nice", 1),
    refuse!("process", 1),
    refuse!("severity-output", 1),
    refuse!("shards", 1),
    refuse!("tcp-md5sig", 1),
    refuse!("tcp-ss", 1),
    refuse!("tfo", 0),
    refuse!("transparent", 0),
    refuse!("uid", 1),
    refuse!("user", 1),
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
    refuse!("generate-certificates", 0),
    refuse!("ktls", 1),
    refuse!("no-alpn", 0),
    refuse!("no-ca-names", 0),
    refuse!("no-strict-sni", 0),
    refuse!("no-tls-tickets", 0),
    refuse!("npn", 1),
    refuse!("prefer-client-ciphers", 0),
    refuse!("sigalgs", 1),
    refuse!("strict-sni", 0),
    refuse!("tls-ticket-keys", 1),
    refuse!("tls-tickets", 0),
    refuse!("verify", 1),
    refuse!("quic-cc-algo", 1),
    refuse!("quic-force-retry", 0),
    refuse!("quic-socket", 1),
];

/// Handles `tokens[i]`, a bind keyword Ibex does not implement, on the `bind` line of
/// `section` (`listen` or `frontend`). Always an error: see the module comment.
pub(crate) fn unimplemented_bind_keyword(
    tokens: &[Token],
    i: usize,
    section: &str,
) -> ConfigError {
    let tok = &tokens[i];
    let prefix = format!("'bind {}' in section '{section}'", tokens[1].text);
    let Some(k) = UNIMPLEMENTED_BIND_KEYWORDS.iter().find(|k| k.name == tok.text) else {
        return ConfigError::new(tok.line, tok.col, format!("{prefix}: unknown keyword '{}'.", tok.text));
    };
    if i + k.args >= tokens.len() {
        return ConfigError::new(tok.line, tok.col, format!("{prefix} : '{}' expects an argument.", k.name));
    }
    ConfigError::new(
        tok.line,
        tok.col,
        format!(
            "{prefix} : '{}' is not supported: Ibex does not implement it, and would serve the bind without it.",
            k.name
        ),
    )
}
