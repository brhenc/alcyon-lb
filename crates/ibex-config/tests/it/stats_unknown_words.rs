// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A `stats` word Ibex does not implement is refused at load, never accepted and dropped
//! (AGENTS.md rule 5): `stats auth admin:secret` used to load and serve the stats page to
//! anyone, where HAProxy answers 401. A word HAProxy does not know either is refused with
//! HAProxy's message (3.5-dev8, `-c`).

use ibex_config::parse_str;

fn cfg(line: &str) -> Result<ibex_config::Config, ibex_config::ConfigError> {
    parse_str(&format!("frontend f\n  bind 127.0.0.1:1\n  stats uri /st\n  {line}\n"))
}

#[test]
fn the_stats_words_ibex_does_not_implement_are_refused() {
    for line in [
        "stats scope be",
        "stats show-modules",
    ] {
        let e = cfg(line).expect_err(line);
        assert!(e.to_string().contains("is not implemented"), "{line}: {e}");
    }
}

#[test]
fn a_stats_word_haproxy_does_not_know_is_refused_with_its_message() {
    let e = cfg("stats nosuch").expect_err("nosuch");
    assert!(
        e.to_string().contains(
            "unknown stats parameter 'nosuch', expects 'admin', 'uri', 'realm', 'auth', 'scope', 'enable', \
             'hide-version', 'show-node', 'show-desc' , 'show-legends' or 'show-version'."
        ),
        "{e}"
    );
}

#[test]
fn stats_enable_and_the_implemented_words_still_load() {
    for line in [
        "stats auth admin:secret",
        "stats auth a:b\n  stats auth c:d\n  stats realm Private",
        "stats hide-version",
        "stats show-version",
        "stats http-request deny",
        "stats http-request auth realm x unless { src 1.2.3.4 }",
        "stats http-request allow if TRUE\n  stats http-request deny deny_status 404",
    ] {
        cfg(line).expect(line);
    }
    for line in ["stats enable", "stats refresh 5s", "stats admin if TRUE", "stats show-legends", "stats show-desc d", "stats show-node n"] {
        let c = cfg(line).expect(line);
        assert!(c.frontends[0].stats.enable, "{line}");
    }
}

#[test]
fn stats_auth_and_realm_and_http_request_refusals_are_haproxys() {
    let m = |line: &str| cfg(line).expect_err(line).to_string();
    assert!(m("stats auth").contains("'auth' needs a user:password account."));
    assert!(m("stats realm").contains("'realm' needs an realm name."));
    for line in ["stats auth a:b\n  stats http-request deny", "stats realm R\n  stats http-request deny", "stats http-request allow\n  stats auth a:b"] {
        assert!(
            m(line).contains("proxy 'f': stats 'auth'/'realm' and 'http-request' can't be used at the same time."),
            "{line}"
        );
    }
    // An action the stats page does not run would parse and do nothing.
    assert!(m("stats http-request set-header a b").contains("supports only"));
    assert!(m("stats http-request return status 200").contains("supports only"));
}

#[test]
fn stats_warnings_have_haproxys_text() {
    let texts = |line: &str| -> Vec<String> {
        cfg(line).expect(line).proxy_warnings.iter().map(|w| w.text.clone()).collect()
    };
    assert!(texts("stats auth d:1\n  stats auth d:2").contains(&"uri auth: ignoring duplicated user 'd'.".to_string()));
    assert!(texts("stats http-request allow\n  stats http-request deny")
        .contains(&"previous 'stats' action has no condition attached, further entries are NOOP.".to_string()));
    // `stats realm` alone loads (and protects nothing, as on HAProxy).
    cfg("stats realm R").expect("realm alone");
}

#[test]
fn stats_admin_and_http_request_are_refused_in_defaults() {
    let d = |line: &str| parse_str(&format!("defaults\n  mode http\n  {line}\nfrontend f\n  bind 127.0.0.1:1\n")).expect_err(line).to_string();
    assert!(d("stats admin if TRUE").contains("'stats admin' not allowed in 'defaults' section."));
    assert!(d("stats http-request deny").contains("'stats' not allowed in 'defaults' section."));
}
