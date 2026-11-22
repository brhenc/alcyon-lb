// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T655 T0: the global TLS defaults Alcyon accepted and dropped (AGENTS.md rule 5).
//!
//! `ssl-default-{bind,server}-options` kept only the version words, `ssl-default-{bind,server}-ciphers`
//! were stored and never read, `-ciphersuites` / `-curves` were "unknown keyword". Each is now
//! refused, naming the keyword (tradeoff 6.38). The oracle accepts all of them.

use alcyon_config::parse_str;

const TAIL: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\nlisten x\n  bind 127.0.0.1:1\n";

fn global(line: &str) -> Result<alcyon_config::Config, alcyon_config::ConfigError> {
    parse_str(&format!("global\n  {line}\n{TAIL}"))
}

fn refused(line: &str, needle: &str) {
    let e = global(line).expect_err(line).to_string();
    assert!(e.contains(needle), "{line}: {e}");
}

#[test]
fn bind_options_other_than_versions_are_refused_by_name() {
    refused("ssl-default-bind-options strict-sni", "'strict-sni' is not supported");
    refused("ssl-default-bind-options no-tls-tickets prefer-client-ciphers", "'no-tls-tickets'");
    refused("ssl-default-bind-options ssl-min-ver TLSv1.2 prefer-client-ciphers", "'prefer-client-ciphers'");
    refused("ssl-default-bind-options strict-sni", "'ssl-default-bind-options'");
}

#[test]
fn server_options_other_than_versions_are_refused_by_name() {
    refused("ssl-default-server-options no-tls-tickets", "'no-tls-tickets' is not supported");
    refused("ssl-default-server-options force-tlsv12 verify", "'ssl-default-server-options'");
}

#[test]
fn version_words_still_work() {
    assert!(global("ssl-default-bind-options ssl-min-ver TLSv1.2 no-tlsv13").is_ok());
    assert!(global("ssl-default-server-options force-tlsv12").is_ok());
    assert!(global("ssl-default-bind-options").is_ok());
}

#[test]
fn cipher_curve_globals_are_refused_by_keyword() {
    for kw in [
        "ssl-default-bind-ciphers",
        "ssl-default-server-ciphers",
        "ssl-default-bind-ciphersuites",
        "ssl-default-server-ciphersuites",
        "ssl-default-bind-curves",
        "ssl-default-server-curves",
    ] {
        refused(&format!("{kw} ECDHE-RSA-AES256-GCM-SHA384"), &format!("'{kw}' is not supported"));
    }
}

#[test]
fn per_line_cipher_keywords_are_refused() {
    let bind = |kw: &str| parse_str(&format!("{TAIL}  bind 127.0.0.1:2 ssl crt /tmp/c.pem {kw} NOPE\n"));
    for kw in ["ciphers", "ciphersuites", "curves", "ecdhe"] {
        let e = bind(kw).expect_err(kw).to_string();
        assert!(e.contains(&format!("'{kw}'")), "{kw}: {e}");
    }
    for kw in ["ciphers", "ciphersuites", "curves"] {
        let e = parse_str(&format!("{TAIL}backend b\n  server s 127.0.0.1:3 ssl {kw} NOPE\n")).expect_err(kw).to_string();
        assert!(e.contains(&format!("'{kw}'")), "server {kw}: {e}");
        let e = parse_str(&format!("{TAIL}backend b\n  default-server ssl {kw} NOPE\n  server s 127.0.0.1:3\n")).expect_err(kw).to_string();
        assert!(e.contains(&format!("'{kw}'")), "default-server {kw}: {e}");
    }
}
