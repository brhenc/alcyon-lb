// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `server` / `default-server` keywords `HAProxy` knows and Ibex does not implement,
//! and what Ibex does with each.
//!
//! The keyword loops in `server.rs` implement what reaches Ibex's data path. Everything
//! else lands here, and there are only two outcomes:
//!
//! * **refused**, when running without the keyword changes security, encryption,
//!   certificate checking, routing, health, or what is sent to the server. A server line
//!   with `ssl verify required ca-file ...` used to load and connect in plaintext;
//! * **ignored with a warning**, when the keyword only tunes something.
//!
//! A keyword missing from this table and from the loops is unknown, as `HAProxy` reports
//! it. `args` is the number of arguments the keyword takes (`skip` in `HAProxy`'s
//! `srv_kws`), so that an ignored keyword's argument is never read as the next keyword.
//!
//! The list is `srv_kws` in `src/server.c`, `src/check.c`, `src/cfgparse-ssl.c`,
//! `src/cfgparse-tcp.c` and `src/tcpcheck.c` of `HAProxy` 3.5-dev8.

use super::{parse_timeout, ConfigError, Token};

/// What Ibex does with a keyword it does not implement.
#[derive(Clone, Copy)]
pub(crate) enum Unimplemented {
    /// Refused: the reason running without it would be wrong.
    Refuse(&'static str),
    /// Accepted, with a warning: what it would have tuned.
    Ignore(&'static str),
}
use Unimplemented::{Ignore, Refuse};

/// How an ignored keyword's argument is checked before it is skipped.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arg {
    None,
    /// Any word.
    Word,
    /// A delay, which `HAProxy` parses and refuses when malformed (`slowstart backup`).
    Delay,
}

pub(crate) struct ServerKeyword {
    pub name: &'static str,
    pub arg: Arg,
    /// `HAProxy` accepts it on a `default-server` line. When it does not, the keyword
    /// draws an alert and is skipped, and the configuration is still valid.
    pub default_ok: bool,
    pub outcome: Unimplemented,
}

macro_rules! kw {
    ($name:expr, $arg:expr, $outcome:expr $(,)?) => {
        ServerKeyword { name: $name, arg: $arg, default_ok: true, outcome: $outcome }
    };
}

macro_rules! not_for_default {
    ($name:expr, $arg:expr, $outcome:expr $(,)?) => {
        ServerKeyword { name: $name, arg: $arg, default_ok: false, outcome: $outcome }
    };
}

/// The TLS keywords with no rustls equivalent (`server.rs` implements the others, T113).
const TLS: Unimplemented = Refuse(
    "Ibex's TLS engine (rustls) has no equivalent; the connection would be made with other settings than asked",
);
const CHECK: Unimplemented = Refuse(
    "Ibex does not implement it; the health check would silently test something else",
);
const ROUTE: Unimplemented = Refuse("Ibex does not implement it; requests would be routed differently");
const SENT: Unimplemented = Refuse("Ibex does not implement it; the server would receive something else");

/// Keywords `HAProxy` registers that the loops in `server.rs` do not handle.
pub(crate) const UNIMPLEMENTED_SERVER_KEYWORDS: &[ServerKeyword] = &[
    // src/server.c
    kw!("error-limit", Arg::Word, Ignore("the error count for 'observe' and 'on-error', which Ibex refuses")),
    not_for_default!("guid", Arg::Word, Ignore("a global identifier for the CLI and stats")),
    kw!("ws", Arg::Word, Ignore("the protocol for WebSocket; Ibex upgrades over HTTP/1.1")),
    kw!("hash-key", Arg::Word, ROUTE),
    not_for_default!("id", Arg::Word, Refuse(
        "Ibex does not implement it; the server's numeric id places it on the consistent-hash ring, \
         so keys would hash to different servers",
    )),
    kw!("idle-ping", Arg::Delay, Ignore("idle connection pings")),
    kw!("init-addr", Arg::Word, Ignore("how an unresolved address is handled at startup; Ibex refuses one")),
    kw!("init-state", Arg::Word, Refuse("Ibex does not implement it; the server would take traffic in a state it should not")),
    kw!("log-bufsize", Arg::Word, Ignore("log servers only")),
    kw!("log-proto", Arg::Word, Ignore("log servers only")),
    kw!("maxqueue", Arg::Word, Ignore("the server's queue length; Ibex has no server queue")),
    kw!("max-reuse", Arg::Word, Ignore("how many requests a connection carries")),
    kw!("minconn", Arg::Word, Ignore("the dynamic connection limit")),
    kw!("namespace", Arg::Word, ROUTE),
    kw!("no-tfo", Arg::None, Ignore("TCP Fast Open")),
    kw!("non-stick", Arg::None, ROUTE),
    kw!("observe", Arg::Word, CHECK),
    kw!("on-error", Arg::Word, CHECK),
    kw!("on-marked-down", Arg::Word, Refuse("Ibex does not implement it; sessions it should end would continue")),
    kw!("on-marked-up", Arg::Word, Refuse("Ibex does not implement it; sessions it should end would continue")),
    kw!("pool-conn-name", Arg::Word, Refuse(
        "Ibex does not implement it; requests it should keep apart would share server connections",
    )),
    kw!("pool-low-conn", Arg::Word, Ignore("idle connection pool sizing")),
    kw!("pool-max-conn", Arg::Word, Ignore("idle connection pool sizing")),
    kw!("pool-purge-delay", Arg::Delay, Ignore("idle connection pool purging")),
    kw!("redir", Arg::Word, ROUTE),
    kw!("resolve-net", Arg::Word, Ignore("DNS resolution at runtime, which needs 'resolvers'; Ibex refuses it")),
    kw!("resolve-opts", Arg::Word, Ignore("DNS resolution at runtime, which needs 'resolvers'; Ibex refuses it")),
    kw!("resolve-prefer", Arg::Word, Ignore("DNS resolution at runtime, which needs 'resolvers'; Ibex refuses it")),
    kw!("resolvers", Arg::Word, Refuse(
        "Ibex does not implement it; the address resolved at startup would never change",
    )),
    kw!("set-proxy-v2-tlv-fmt", Arg::Word, SENT),
    kw!("shard", Arg::Word, Ignore("peers only")),
    kw!("slowstart", Arg::Delay, Ignore("the warm-up of a server coming back up")),
    kw!("source", Arg::Word, ROUTE),
    kw!("strict-maxconn", Arg::None, Ignore("whether idle connections count against maxconn")),
    kw!("tfo", Arg::None, Ignore("TCP Fast Open")),
    kw!("socks4", Arg::Word, ROUTE),
    kw!("usesrc", Arg::None, ROUTE),
    // src/check.c
    kw!("addr", Arg::Word, CHECK),
    kw!("agent-addr", Arg::Word, Ignore("agent checks, which need 'agent-check'; Ibex refuses it")),
    kw!("agent-check", Arg::None, CHECK),
    kw!("agent-inter", Arg::Delay, Ignore("agent checks, which need 'agent-check'; Ibex refuses it")),
    kw!("agent-port", Arg::Word, Ignore("agent checks, which need 'agent-check'; Ibex refuses it")),
    kw!("agent-send", Arg::Word, Ignore("agent checks, which need 'agent-check'; Ibex refuses it")),
    kw!("check-pool-conn-name", Arg::Word, Ignore("health checks reusing idle connections")),
    kw!("check-reuse-pool", Arg::None, Ignore("health checks reusing idle connections")),
    kw!("check-send-proxy", Arg::None, CHECK),
    kw!("check-via-socks4", Arg::None, CHECK),
    kw!("fastinter", Arg::Delay, Ignore("the check interval while a server changes state")),
    kw!("downinter", Arg::Delay, Ignore("the check interval while a server is down")),
    // src/cfgparse-ssl.c: the rest is implemented in `server.rs` (`parse_server_ssl_keyword`).
    kw!("allow-0rtt", Arg::None, TLS),
    kw!("ciphers", Arg::Word, TLS),
    kw!("ciphersuites", Arg::Word, TLS),
    kw!("client-sigalgs", Arg::Word, TLS),
    kw!("curves", Arg::Word, TLS),
    kw!("ktls", Arg::Word, TLS),
    kw!("no-renegotiate", Arg::None, TLS),
    kw!("no-tls-tickets", Arg::None, TLS),
    kw!("npn", Arg::Word, TLS),
    kw!("renegotiate", Arg::None, TLS),
    kw!("send-proxy-v2-ssl", Arg::None, Refuse(
        "Ibex does not implement it; the PROXY header would carry no TLS information about the client",
    )),
    kw!("send-proxy-v2-ssl-cn", Arg::None, Refuse(
        "Ibex does not implement it; the PROXY header would carry no TLS information about the client",
    )),
    kw!("sigalgs", Arg::Word, TLS),
    kw!("tls-tickets", Arg::None, TLS),
    // src/cfgparse-tcp.c
    kw!("cc", Arg::Word, Ignore("the TCP congestion control algorithm")),
    kw!("tcp-md5sig", Arg::Word, Refuse("Ibex does not implement it; connections would carry no TCP MD5 signature")),
    kw!("tcp-ut", Arg::Delay, Ignore("the TCP user timeout")),
    // src/tcpcheck.c
    kw!("healthcheck", Arg::Word, CHECK),
];

fn find(word: &str) -> Option<&'static ServerKeyword> {
    // `set-proxy-v2-tlv-fmt(<id>)` carries its argument in its name.
    let name = word.split_once('(').map_or(word, |(n, _)| n);
    UNIMPLEMENTED_SERVER_KEYWORDS.iter().find(|k| k.name == name)
}

/// `'server s1' : ` or, on a `default-server` line, nothing, as `HAProxy` prefixes it.
pub(crate) fn server_prefix(server: Option<&str>) -> String {
    server.map_or_else(String::new, |s| format!("'server {s}' : "))
}

/// The argument of `tokens[i]`, or `HAProxy`'s error for a missing one.
pub(crate) fn server_kw_arg<'t>(
    tokens: &'t [Token],
    i: usize,
    server: Option<&str>,
    expects: &str,
) -> Result<&'t Token, ConfigError> {
    let kw = &tokens[i];
    tokens.get(i + 1).filter(|t| !t.text.is_empty()).ok_or_else(|| {
        ConfigError::new(kw.line, kw.col, format!("{}'{}' {expects}", server_prefix(server), kw.text))
    })
}

/// Handles `tokens[i]`, a keyword the loops in `server.rs` do not implement, on the line
/// of `server` (`None` for `default-server`). Returns the index of its last argument.
pub(crate) fn unimplemented_server_keyword(tokens: &[Token], i: usize, server: Option<&str>) -> Result<usize, ConfigError> {
    let tok = &tokens[i];
    let prefix = server_prefix(server);
    let Some(k) = find(&tok.text) else {
        let hint = if server.is_none() { " Hint: no address was expected for this server." } else { "" };
        return Err(ConfigError::new(tok.line, tok.col, format!("{prefix}unknown keyword '{}'.{hint}", tok.text)));
    };
    let last = match k.arg {
        Arg::None => i,
        Arg::Word => server_kw_arg(tokens, i, server, "expects an argument.").map(|_| i + 1)?,
        Arg::Delay => {
            let arg = server_kw_arg(tokens, i, server, "expects a delay as argument.")?;
            parse_timeout(arg, k.name)?;
            i + 1
        }
    };
    if server.is_none() && !k.default_ok {
        eprintln!("[ibex] warning: '{}' option is not accepted in default-server sections; ignored", k.name);
        return Ok(last);
    }
    match k.outcome {
        Refuse(why) => Err(ConfigError::new(tok.line, tok.col, format!("{prefix}'{}' is not supported: {why}.", k.name))),
        Ignore(what) => {
            eprintln!("[ibex] warning: {prefix}'{}' is not implemented and is ignored ({what}).", k.name);
            Ok(last)
        }
    }
}
