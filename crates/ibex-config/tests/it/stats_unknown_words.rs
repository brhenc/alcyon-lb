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
        "stats auth admin:secret",
        "stats realm Private",
        "stats scope be",
        "stats hide-version",
        "stats show-version",
        "stats show-modules",
        "stats http-request deny",
        "stats http-request auth realm x",
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
    for line in ["stats enable", "stats refresh 5s", "stats admin if TRUE", "stats show-legends", "stats show-desc d", "stats show-node n"] {
        let c = cfg(line).expect(line);
        assert!(c.frontends[0].stats.enable, "{line}");
    }
}
