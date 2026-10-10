// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `node` and `description` in `global`, `description` in `listen`/`frontend`/`backend`
//! (T264). Ibex refused `global node` and `global description` as unknown keywords and
//! the proxy ones likewise. The texts are those of `haproxy -c` (3.5-dev8-885761-29), less
//! the `parsing [file:line] :` prefix; what reaches `show info` and the stats page is in
//! `ibex-rt` `tests/node_description.rs`.

use ibex_config::parse_str;

fn refusal(cfg: &str) -> String {
    match parse_str(cfg) {
        Ok(_) => panic!("accepted:\n{cfg}"),
        Err(e) => e.message,
    }
}

const NODE_NAME: &str = "'node' requires valid node name - non-empty string with digits(0-9), letters(A-Z, a-z), dot(.), hyphen(-) or underscode(_).";

#[test]
fn global_node_and_description_are_kept() {
    let c = parse_str("global\n  node a.b-C_1\n  description a   b \"c  d\"\n").expect("accepted");
    let g = c.global.expect("global");
    assert_eq!(g.node.as_deref(), Some("a.b-C_1"));
    // HAProxy joins the words with one space.
    assert_eq!(g.description.as_deref(), Some("a b c  d"));
}

#[test]
fn global_node_refusals() {
    assert_eq!(refusal("global\n  node bad!name\n"), NODE_NAME);
    assert_eq!(refusal("global\n  node\n"), NODE_NAME);
    assert_eq!(refusal("global\n  node a b\n"), "'node' cannot handle unexpected argument 'b'.");
}

#[test]
fn global_description_needs_text() {
    assert_eq!(refusal("global\n  description\n"), "'description' expects a string argument.");
}

#[test]
fn proxy_description_is_kept_in_every_proxy_section() {
    let c = parse_str(
        "frontend f\n  bind 127.0.0.1:1\n  description a  b\n  description c d\n\
         backend b\n  description back\n\
         listen l\n  bind 127.0.0.1:2\n  description lis ten\n",
    )
    .expect("accepted");
    assert_eq!(c.frontends[0].description.as_deref(), Some("c d"), "the last one wins");
    assert_eq!(c.backends[0].description.as_deref(), Some("back"));
    assert_eq!(c.listens[0].description.as_deref(), Some("lis ten"));
}

#[test]
fn proxy_description_refusals() {
    for sec in ["frontend f", "backend b", "listen l"] {
        assert_eq!(refusal(&format!("{sec}\n  description\n")), "'description' expects a string argument.");
    }
    assert_eq!(refusal("defaults\n  description x\n"), "'description' not allowed in 'defaults' section.");
}
