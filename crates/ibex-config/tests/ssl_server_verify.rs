// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Global `ssl-server-verify` (T150): the default of a `server` line's `verify`.
//!
//! It parsed and was dropped, so a config that said `ssl-server-verify none` to reach
//! servers it has no CA for was refused as if it had not. Measured with `HAProxy`
//! 3.5-dev8-885761-29:
//!
//! * `none` or `required`; anything else is "'ssl-server-verify' expects 'none' or
//!   'required' as argument.", no argument "'ssl-server-verify' expects an integer
//!   argument."; the last one wins; `defaults` does not know the keyword;
//! * `none`: a `server ... ssl` (or `check-ssl`) with no `verify` and no `ca-file` loads, and
//!   does not verify; it may come after the sections that use it;
//! * `none` with an explicit `verify required` and no CA: "verify is enabled but no CA file
//!   specified." (no "by default"); `required` is the default and changes nothing.

use ibex_config::{parse_str, SslVerify};

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n";

fn cfg(global: &str, server: &str) -> Result<ibex_config::Config, ibex_config::ConfigError> {
    parse_str(&format!("{global}{DEFAULTS}backend b\n  server s1 127.0.0.1:8080 {server}\n"))
}

fn verify(c: &ibex_config::Config) -> Option<SslVerify> {
    c.backends[0].servers[0].ssl.as_ref().and_then(|s| s.verify)
}

#[test]
fn none_lets_a_tls_server_without_a_ca_load_unverified() {
    for server in ["ssl", "check check-ssl", "ssl ca-file /nonexistent-ca.pem"] {
        let c = cfg("global\n  ssl-server-verify none\n", server);
        let c = c.unwrap_or_else(|e| panic!("`{server}` must load under `none`: {}", e.message));
        assert_eq!(verify(&c), Some(SslVerify::None), "`{server}`");
    }
}

#[test]
fn an_explicit_verify_on_the_server_line_wins_over_the_global() {
    let c = cfg("global\n  ssl-server-verify none\n", "ssl verify required ca-file /nonexistent-ca.pem").unwrap();
    assert_eq!(verify(&c), Some(SslVerify::Required));
    let e = cfg("global\n  ssl-server-verify none\n", "ssl verify required").expect_err("no CA");
    assert!(e.message.contains("verify is enabled but no CA file specified."), "{}", e.message);
    assert!(!e.message.contains("by default"), "{}", e.message);
}

#[test]
fn required_is_the_default() {
    for g in ["", "global\n  ssl-server-verify required\n"] {
        let e = cfg(g, "ssl").expect_err("no CA");
        assert!(e.message.contains("verify is enabled by default but no CA file specified"), "{}", e.message);
    }
}

#[test]
fn the_keyword_may_follow_the_sections_that_use_it_and_the_last_one_wins() {
    let text = format!("{DEFAULTS}backend b\n  server s1 127.0.0.1:8080 ssl\nglobal\n  ssl-server-verify required\n  ssl-server-verify none\n");
    let c = parse_str(&text).expect("loads");
    assert_eq!(verify(&c), Some(SslVerify::None));
}

#[test]
fn bad_arguments_are_refused_with_haproxys_messages() {
    let e = parse_str("global\n  ssl-server-verify bogus\n").expect_err("bogus");
    assert!(e.message.contains("'ssl-server-verify' expects 'none' or 'required' as argument."), "{}", e.message);
    let e = parse_str("global\n  ssl-server-verify\n").expect_err("empty");
    assert!(e.message.contains("'ssl-server-verify' expects an integer argument."), "{}", e.message);
    let e = parse_str("defaults\n  ssl-server-verify none\n").expect_err("defaults");
    assert!(e.message.contains("unknown keyword 'ssl-server-verify'"), "{}", e.message);
}
