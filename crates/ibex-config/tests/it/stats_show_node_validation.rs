// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `stats show-node` takes a name of digits, letters, '-', '_' and '.', as measured on
//! HAProxy 3.5-dev8; anything else is a fatal error. With no name it is the host name
//! (stored as an empty string, resolved by the stats page).

use ibex_config::parse_str;

fn cfg(line: &str) -> Result<ibex_config::Config, ibex_config::ConfigError> {
    parse_str(&format!("listen l\n  bind 127.0.0.1:1\n  stats enable\n  {line}\n"))
}

#[test]
fn show_node_refuses_characters_haproxy_refuses() {
    for bad in ["a:b", "a<b>", "a&c", "a/b"] {
        let e = cfg(&format!("stats show-node {bad}")).expect_err(bad);
        assert!(e.to_string().contains("invalid node name"), "{bad}: {e}");
    }
}

#[test]
fn show_node_accepts_its_alphabet_and_takes_only_the_first_word() {
    for ok in ["1_-A.b", "lb1"] {
        let c = cfg(&format!("stats show-node {ok}")).expect(ok);
        assert_eq!(c.listens[0].stats.show_node.as_deref(), Some(ok));
    }
    let c = cfg("stats show-node a b").expect("parse");
    assert_eq!(c.listens[0].stats.show_node.as_deref(), Some("a"));
}

#[test]
fn show_node_without_a_name_is_the_host_name() {
    let c = cfg("stats show-node").expect("parse");
    assert_eq!(c.listens[0].stats.show_node.as_deref(), Some(""));
}
