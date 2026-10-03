// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Every proxy `option` the reference `HAProxy` knows, in every section, and what Ibex does
//! with it (T94).
//!
//! Until T94 Ibex accepted any `option` it did not implement with a warning, in every
//! section, and any `no ...` line at all. `HAProxy` refuses an option it does not know,
//! and some that Ibex ignored change what reaches the server.
//!
//! The option list is `cfg_opts`, `cfg_opts2` and `cfg_opts3` in `src/proxy.c` and the
//! options parsed by name in `cfg_parse_listen` (`src/cfgparse-listen.c`), `HAProxy`
//! 3.5-dev8-885761-29. The exit status of `haproxy -c` was measured on 2026-10-03 for
//! `option <name>` and for `no option <name>`, one line at a time, in a frontend, a
//! backend, a listen section and a `defaults` section (all `mode http`). The two strings
//! below are those exit statuses, in that order.
//!
//! What the matrix shows:
//! * an unknown option is fatal everywhere ("unknown option 'x'");
//! * an option from the `cfg_opts` tables in a section without the capability it needs is
//!   fatal in this build: `'allbackups' ignored because frontend 'f' has no backend
//!   capability`, then `unknown option 'allbackups'`;
//! * an option parsed by name in a section without the capability is only a warning
//!   (`'httpchk' ignored because frontend 'f' has no backend capability`), exit 0;
//! * `transparent`, `forceclose`, `http-tunnel` and `http_proxy` were removed;
//! * `no option` is refused for every option parsed after `httplog` in
//!   `cfg_parse_listen` ("negation/default is not supported for option 'x'"), and for an
//!   unknown option;
//! * `external-check` is refused here because the `global` section has no
//!   `external-check`.
//!
//! Ibex refuses the same lines, and additionally refuses the options in
//! [`IBEX_REFUSES`] where they would take effect: their absence changes security, routing,
//! or what is sent to the server, and Ibex does not implement them.

use ibex_config::{parse_str, Config, ConfigError};

/// `(option line, HAProxy exit status for "option <line>" in fe/be/listen/defaults,
/// the same for "no option <line>")`.
const MATRIX: &[(&str, &str, &str)] = &[
    ("abortonclose", "0000", "0000"),
    ("allbackups", "1000", "1000"),
    ("checkcache", "1000", "1000"),
    ("clitcpka", "0100", "0100"),
    ("contstats", "0100", "0100"),
    ("dontlognull", "0100", "0100"),
    ("http-buffer-request", "0000", "0000"),
    ("http-drop-request-trailers", "1000", "1000"),
    ("http-drop-response-trailers", "0100", "0100"),
    ("http-ignore-probes", "0100", "0100"),
    ("idle-close-on-response", "0100", "0100"),
    ("prefer-last-server", "1000", "1000"),
    ("logasap", "0100", "0100"),
    ("nolinger", "0000", "0000"),
    ("persist", "1000", "1000"),
    ("srvtcpka", "1000", "1000"),
    ("transparent", "1111", "1111"),
    ("splice-request", "0000", "0000"),
    ("splice-response", "0000", "0000"),
    ("splice-auto", "0000", "0000"),
    ("accept-unsafe-violations-in-http-request", "0100", "0100"),
    ("accept-unsafe-violations-in-http-response", "1000", "1000"),
    ("dontlog-normal", "0100", "0100"),
    ("log-separate-errors", "0100", "0100"),
    ("log-health-checks", "1000", "1000"),
    ("socket-stats", "0100", "0100"),
    ("tcp-smart-accept", "0100", "0100"),
    ("tcp-smart-connect", "1000", "1000"),
    ("independent-streams", "0000", "0000"),
    ("http-use-proxy-header", "0100", "0100"),
    ("http-pretend-keepalive", "1000", "1000"),
    ("http-no-delay", "0000", "0000"),
    ("h1-case-adjust-bogus-client", "0100", "0100"),
    ("h1-case-adjust-bogus-server", "1000", "1000"),
    ("disable-h2-upgrade", "0100", "0100"),
    ("assume-rfc6587-ntf", "0100", "0100"),
    ("dont-parse-log", "0100", "0100"),
    ("forceclose", "1111", "1111"),
    ("httpclose", "0000", "0000"),
    ("http-server-close", "0000", "0000"),
    ("http-keep-alive", "0000", "0000"),
    ("http-tunnel", "1111", "1111"),
    ("forwarded", "0000", "0000"),
    ("redispatch", "0000", "0000"),
    ("http_proxy", "1111", "1111"),
    ("use-small-buffers queue", "0000", "0000"),
    ("httplog", "0000", "1111"),
    ("tcplog", "0000", "1111"),
    ("httpslog", "0000", "1111"),
    ("tcpka", "0000", "1111"),
    ("httpchk", "0000", "1111"),
    ("ssl-hello-chk", "0000", "1111"),
    ("smtpchk", "0000", "1111"),
    ("pgsql-check user postgres", "0000", "1111"),
    ("redis-check", "0000", "1111"),
    ("mysql-check", "0000", "1111"),
    ("ldap-check", "0000", "1111"),
    ("spop-check", "0000", "1111"),
    ("tcp-check", "0000", "1111"),
    ("external-check", "1111", "1111"),
    ("forwardfor", "0000", "1111"),
    ("originalto", "0000", "1111"),
    ("http-restrict-req-hdr-names reject", "0000", "1111"),
    ("accept-invalid-http-request", "0000", "1111"),
    ("accept-invalid-http-response", "0000", "1111"),
    ("bogus-option", "1111", "1111"),
];

/// Options `HAProxy` accepts that Ibex refuses, and the sections where they would take
/// effect (f, b, l, d). Elsewhere `HAProxy` itself ignores them with a warning, or refuses
/// them, and Ibex does the same.
const IBEX_REFUSES: &[(&str, &str)] = &[
    // Checks Ibex cannot run: the server would get a bare TCP connect and be reported UP.
    ("spop-check", "bld"),
    // What reaches the server or the client.
    ("forwarded", "bld"),
    ("http-buffer-request", "fbld"),
    ("http-restrict-req-hdr-names reject", "fbld"),
    ("http-drop-request-trailers", "bld"),
    ("http-drop-response-trailers", "fld"),
    ("checkcache", "bld"),
    ("disable-h2-upgrade", "fld"),
    // The log format: an HTTPS log line Ibex cannot write (T53 refuses it where it would
    // apply; a backend ignores log formats, as HAProxy does).
    ("httpslog", "fld"),
    // Which server is used.
    ("allbackups", "bld"),
    ("persist", "bld"),
];

const SECTIONS: [char; 4] = ['f', 'b', 'l', 'd'];

fn config(section: char, line: &str) -> Result<Config, ConfigError> {
    let (mut d, mut f, mut b, mut l) = (String::new(), String::new(), String::new(), String::new());
    let target = match section {
        'f' => &mut f,
        'b' => &mut b,
        'l' => &mut l,
        _ => &mut d,
    };
    *target = format!("  {line}\n");
    parse_str(&format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n{d}\
         frontend f\n  bind 127.0.0.1:18080\n{f}  default_backend b\n\
         backend b\n{b}  server s1 127.0.0.1:8080\n\
         listen l\n  bind 127.0.0.1:18081\n{l}  server s1 127.0.0.1:8080\n"
    ))
}

fn name(line: &str) -> &str {
    line.split_whitespace().next().unwrap_or(line)
}

#[test]
fn every_haproxy_option_in_every_section() {
    let mut wrong = Vec::new();
    for &(line, hap, _) in MATRIX {
        let refused_here = IBEX_REFUSES.iter().find(|(l, _)| *l == line).map_or("", |(_, s)| *s);
        for (i, sec) in SECTIONS.iter().enumerate() {
            let haproxy_refuses = hap.as_bytes()[i] == b'1';
            let expect_err = haproxy_refuses || refused_here.contains(*sec);
            match config(*sec, &format!("option {line}")) {
                Ok(_) if expect_err => wrong.push(format!(
                    "[{sec}] `option {line}` loaded; {}",
                    if haproxy_refuses { "HAProxy refuses it" } else { "Ibex cannot honour it and must refuse it" }
                )),
                Err(e) if !expect_err => wrong.push(format!("[{sec}] `option {line}` refused, HAProxy loads it: {}", e.message)),
                Err(e) if !e.message.contains(name(line)) => {
                    wrong.push(format!("[{sec}] `option {line}`: the error does not name the option: {}", e.message));
                }
                _ => {}
            }
        }
    }
    assert!(wrong.is_empty(), "{} disagreements:\n{}", wrong.len(), wrong.join("\n"));
}

#[test]
fn every_haproxy_option_negated_in_every_section() {
    let mut wrong = Vec::new();
    for &(line, _, hap) in MATRIX {
        for (i, sec) in SECTIONS.iter().enumerate() {
            let expect_err = hap.as_bytes()[i] == b'1';
            match config(*sec, &format!("no option {line}")) {
                Ok(_) if expect_err => wrong.push(format!("[{sec}] `no option {line}` loaded; HAProxy refuses it")),
                Err(e) if !expect_err => wrong.push(format!("[{sec}] `no option {line}` refused, HAProxy loads it: {}", e.message)),
                _ => {}
            }
        }
    }
    assert!(wrong.is_empty(), "{} disagreements:\n{}", wrong.len(), wrong.join("\n"));
}

/// `option forwardfor` and `option originalto` arguments. `HAProxy` 3.5-dev8 accepts
/// `except <net>`, `header <name>` and (forwardfor only) `if-none`, and refuses anything
/// else: "'option forwardfor' only supports optional values: 'except', 'header' and
/// 'if-none'.", "'option forwardfor except' expects <address>[/mask] as argument.".
/// Ibex sends the client address in `X-Forwarded-For` / `X-Original-To` always, so a
/// different header name (the server would read a header only the client wrote) and
/// `if-none` are refused.
#[test]
fn forwardfor_and_originalto_arguments() {
    for line in ["option forwardfor", "option forwardfor except 10.0.0.0/8", "option originalto except 10.0.0.1"] {
        assert!(config('b', line).is_ok(), "{line}");
    }
    for line in [
        "option forwardfor bogus",
        "option forwardfor except",
        "option originalto bogus",
        "option forwardfor header X-Real-IP",
        "option forwardfor if-none",
        "option originalto header X-Orig",
    ] {
        let err = config('b', line).expect_err(line);
        assert!(err.message.contains("forwardfor") || err.message.contains("originalto"), "{line}: {}", err.message);
    }
}

/// `option http-restrict-req-hdr-names preserve` is the default and is accepted; `reject`
/// and `delete` are refused (Ibex forwards such names). No argument: "missing parameter".
#[test]
fn http_restrict_req_hdr_names_values() {
    assert!(config('b', "option http-restrict-req-hdr-names preserve").is_ok());
    for v in ["reject", "delete", "", "bogus"] {
        assert!(config('b', &format!("option http-restrict-req-hdr-names {v}")).is_err(), "{v:?}");
    }
}

/// Options set in `defaults` reach the proxies that inherit it, and `no option` in a
/// proxy clears what `defaults` set.
#[test]
fn defaults_options_are_inherited_and_negation_clears_them() {
    let cfg = parse_str(
        "defaults\n  mode http\n  option redispatch\n  option forwardfor except 10.0.0.0/8\n  option originalto\n\
         frontend f\n  bind 127.0.0.1:18080\n  default_backend b\n\
         backend b\n  server s1 127.0.0.1:8080\n\
         backend c\n  no option redispatch\n  server s1 127.0.0.1:8080\n",
    )
    .expect("HAProxy loads this");
    assert!(cfg.backends[0].redisp, "option redispatch in defaults");
    assert_eq!(cfg.backends[0].forwardfor.as_deref(), Some("10.0.0.0/8"));
    assert_eq!(cfg.frontends[0].forwardfor.as_deref(), Some("10.0.0.0/8"));
    assert_eq!(cfg.backends[0].originalto.as_deref(), Some(""));
    assert!(!cfg.backends[1].redisp, "no option redispatch");
}

/// `no option` with no name: "'option' expects an option name." (`HAProxy` 3.5-dev8,
/// 2026-10-03). Ibex accepted any `no ...` line. Control: `no log`, which `HAProxy`
/// accepts, is still accepted in every section.
#[test]
fn no_option_without_a_name_is_refused_and_other_no_lines_are_not() {
    for sec in SECTIONS {
        assert!(config(sec, "no option").is_err(), "[{sec}] `no option`");
        assert!(config(sec, "no log").is_ok(), "[{sec}] `no log`");
    }
}

/// `option` with no name. `HAProxy`: "'option' expects an option name."
#[test]
fn an_option_without_a_name_is_refused() {
    assert!(config('b', "option").is_err());
}
