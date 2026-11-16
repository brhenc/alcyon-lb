// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T632 item 1: a `use-server` rule that names no server of its proxy fails the load
//! (`Engine::new`), with HAProxy's wording. Moved here from `request_allocations.rs` (rule 6).

use alcyon_rt::engine::Engine;

/// T632 item 1: an unresolved `use-server` rule is a configuration error at load (`Engine::new`),
/// with HAProxy's wording.
#[test]
fn unresolved_use_server_fails_engine_load_as_haproxy() {
    let mut cfg = alcyon_config::parse_str(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         backend b\n  server s1 127.0.0.1:8080\n",
    )
    .expect("parse");
    let cond = alcyon_config::AclCondition { is_if: true, terms: Vec::new() };
    cfg.backends[0].use_servers.push(alcyon_config::UseServerRule { server: "missing".into(), cond: cond.clone() });
    let err = match Engine::new(&cfg, 64) {
        Ok(_) => panic!("expected Engine::new to fail for unresolved backend use-server"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("backend 'b' : unable to find server 'missing' referenced in a 'use-server' rule."),
        "unexpected error: {err}"
    );

    let mut lcfg = alcyon_config::parse_str(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         listen l\n  bind 127.0.0.1:0\n  server s1 127.0.0.1:8080\n",
    )
    .expect("parse");
    lcfg.listens[0].use_servers.push(alcyon_config::UseServerRule { server: "missing".into(), cond });
    let err = match Engine::new(&lcfg, 64) {
        Ok(_) => panic!("expected Engine::new to fail for unresolved listen use-server"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("proxy 'l' : unable to find server 'missing' referenced in a 'use-server' rule."),
        "unexpected error: {err}"
    );
}
