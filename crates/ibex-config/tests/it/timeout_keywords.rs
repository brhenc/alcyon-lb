// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The word after `timeout` (T240 item 2). `parse_timeout_directive` ended in `_ => {}`, so
//! `timeout bogus 5s` loaded and did nothing, and so did `client-fin`, `server-fin` and
//! `client-hs`, which HAProxy implements and Ibex does not. HAProxy's texts are measured
//! with `haproxy -c` (3.5-dev8), less the `parsing [file:line] :` prefix. Note that
//! HAProxy lists `handshake` as supported and refuses it all the same.

use ibex_config::parse_str;

const SUPPORTS: &str = "'timeout' supports 'client', 'server', 'connect', 'check', 'queue', 'handshake', \
                        'http-keep-alive', 'http-request', 'tunnel', 'tarpit', 'client-fin' and 'server-fin'";

fn refusal(cfg: &str) -> String {
    match parse_str(cfg) {
        Ok(_) => panic!("accepted:\n{cfg}"),
        Err(e) => e.message,
    }
}

#[test]
fn an_unknown_word_is_refused_with_the_list() {
    for (line, got) in [("timeout bogus 5s", "bogus"), ("timeout handshake 5s", "handshake"), ("timeout bogus", "bogus"), ("timeout", "")] {
        assert_eq!(refusal(&format!("defaults\n {line}\n")), format!("{SUPPORTS} (got '{got}')"), "{line}");
    }
}

#[test]
fn the_timeouts_ibex_does_not_implement_are_refused_not_dropped() {
    for kw in ["client-fin", "server-fin", "client-hs"] {
        let m = refusal(&format!("defaults\n timeout {kw} 5s\n"));
        assert_eq!(m, format!("'timeout {kw}' is not implemented in Ibex"), "{kw}");
    }
}

#[test]
fn a_missing_bad_or_extra_value_is_refused_with_haproxys_text() {
    assert_eq!(refusal("defaults\n timeout client\n"), "'timeout client' expects an integer value (in milliseconds)");
    assert_eq!(refusal("defaults\n timeout client 10x\n"), "unexpected character 'x' in 'timeout client'");
    assert_eq!(refusal("defaults\n timeout server -5\n"), "unexpected character '-' in 'timeout server'");
    assert_eq!(
        refusal("defaults\n timeout client 1s 2s\n"),
        "'timeout client' : unexpected extra argument '2s' after value '1s'."
    );
}

#[test]
fn the_implemented_timeouts_still_load() {
    let c = parse_str(
        "defaults\n timeout client 1s\n timeout server 2s\n timeout connect 3s\n timeout check 4s\n timeout queue 5s\n \
         timeout http-keep-alive 6s\n timeout http-request 7s\n timeout tunnel 8s\n timeout tarpit 9s\n timeout client 0\n",
    )
    .expect("loads");
    let t = &c.defaults.expect("defaults").timeouts;
    assert_eq!(t.client, Some(std::time::Duration::ZERO));
    assert_eq!(t.tarpit, Some(std::time::Duration::from_secs(9)));
}

#[test]
fn grace_is_refused_in_every_proxy_section() {
    // Ibex used to store `grace` in a `listen` and never read it; HAProxy refuses it.
    for section in ["defaults", "frontend f", "backend b", "listen l"] {
        assert_eq!(
            refusal(&format!("{section}\n grace 5s\n")),
            "the 'grace' keyword is not supported any more since HAProxy version 2.5.",
            "{section}"
        );
    }
}
