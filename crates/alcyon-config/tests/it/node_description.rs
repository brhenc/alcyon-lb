// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `node` and `description` in `global`, `description` in `listen`/`frontend`/`backend`
//! (T264). Alcyon refused `global node` and `global description` as unknown keywords and
//! the proxy ones likewise. The texts are those of `haproxy -c` (3.5-dev8-885761-29), less
//! the `parsing [file:line] :` prefix; what reaches `show info` and the stats page is in
//! `alcyon-rt` `tests/node_description.rs`.

use alcyon_config::parse_str;

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

// T272 C: `stats show-desc` without text and without `global description` is a warning, and
// sets nothing (src/cfgparse-listen.c; measured on 3.5-dev8-885761-29).

fn show_desc_cfg(global: &str, section: &str) -> String {
    let bind = if section.starts_with("defaults") { "" } else { "  bind 127.0.0.1:18080\n" };
    format!("{global}{section}  mode http\n{bind}  stats enable\n  stats show-desc\n")
}

#[test]
fn show_desc_without_text_or_global_description_warns_and_sets_nothing() {
    for section in ["frontend fe\n", "listen li\n", "defaults\n"] {
        let cfg = parse_str(&show_desc_cfg("", section)).expect("a warning, not a refusal");
        let texts: Vec<&str> = cfg.proxy_warnings.iter().map(|w| w.text.as_str()).collect();
        assert_eq!(texts, ["'show-desc' requires a parameter or 'desc' to be set in the global section."], "{section}");
        assert!(!cfg.proxy_warnings[0].alert);
        assert_eq!(cfg.proxy_warnings[0].line, if section.starts_with("defaults") { 4 } else { 5 }, "{section}");
        let stats = cfg.frontends.first().map(|f| &f.stats).or(cfg.listens.first().map(|l| &l.stats)).or(cfg.defaults.as_ref().map(|d| &d.stats)).expect("a section");
        assert_eq!(stats.show_desc, None, "{section}");
    }
}

#[test]
fn show_desc_is_silent_with_text_or_with_a_global_description_before_it() {
    let cfg = parse_str(&show_desc_cfg("global\n  description hi\n", "frontend fe\n")).expect("parse");
    assert!(cfg.proxy_warnings.is_empty());
    assert_eq!(cfg.frontends[0].stats.show_desc.as_deref(), Some(""));
    let cfg = parse_str("frontend fe\n  mode http\n  bind 127.0.0.1:18080\n  stats enable\n  stats show-desc some text\n").expect("parse");
    assert!(cfg.proxy_warnings.is_empty());
    assert_eq!(cfg.frontends[0].stats.show_desc.as_deref(), Some("some text"));
}

#[test]
fn a_global_description_after_the_proxy_does_not_silence_it() {
    // HAProxy reads the sections in order: `global.desc` is not yet set at the proxy's line.
    let cfg = parse_str("frontend fe\n  mode http\n  bind 127.0.0.1:18080\n  stats enable\n  stats show-desc\nglobal\n  description hi\n").expect("parse");
    assert_eq!(cfg.proxy_warnings.len(), 1);
}
