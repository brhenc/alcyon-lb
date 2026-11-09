// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `id` on a proxy, a server and a bind (T86): what is accepted and what is refused, and
//! the numbers the others get. Every verdict was measured on `HAProxy 3.5-dev8-885761-29`
//! with `-c` on 2026-10-04.

use alcyon_config::ast::{listener_ids, server_puids};
use alcyon_config::parse_str;

fn refused(cfg: &str) -> String {
    parse_str(cfg).expect_err(cfg).to_string()
}

#[test]
fn a_proxy_id_must_be_above_zero() {
    for id in ["0", "-1", "x", "4294967296", "4294967295"] {
        let e = refused(&format!("backend a\n  id {id}\n"));
        assert!(e.contains("custom id has to be > 0"), "id {id}: {e}");
    }
    assert!(refused("backend a\n  id\n").contains("'id' expects an integer argument"));
    let e = refused("frontend a\n  bind :18000 id x\n");
    assert!(e.contains("expects an integer argument, found 'x'"), "{e}");
}

#[test]
fn a_proxy_id_cannot_be_reused() {
    for cfg in ["backend a\n  id 5\nbackend b\n  id 5\n", "frontend a\n  id 2\nbackend b\n  id 2\n", "listen a\n  id 2\nfrontend b\n  id 2\n"] {
        let e = refused(cfg);
        assert!(e.contains("reuses same custom id as"), "{cfg}: {e}");
    }
}

#[test]
fn a_proxy_cannot_take_its_own_id_twice() {
    let e = refused("backend a\n  id 5\n  id 5\n");
    assert!(e.contains("backend a reuses same custom id as backend a"), "{e}");
}

#[test]
fn defaults_have_no_id() {
    assert!(refused("defaults\n  id 5\nbackend a\n").contains("'id' not allowed in 'defaults' section"));
}

#[test]
fn a_server_id_is_between_1_and_u32_max() {
    for id in ["0", "x", "4294967296"] {
        let e = refused(&format!("backend a\n  server s1 127.0.0.1:1 id {id}\n"));
        assert!(e.contains("custom id has to be between 1 and 4294967295"), "id {id}: {e}");
    }
    assert!(parse_str("backend a\n  server s1 127.0.0.1:1 id 4294967295\n").is_ok());
    let e = refused("backend a\n  server s1 127.0.0.1:1 id 3\n  server s2 127.0.0.1:1 id 3\n");
    assert!(e.contains("custom id 3 already used"), "{e}");
}

#[test]
fn a_bind_id_is_above_zero_and_used_once_per_proxy() {
    let e = refused("frontend a\n  bind :18000 id 0\n");
    assert!(e.contains("custom id has to be > 0"), "{e}");
    let e = refused("frontend a\n  bind :18000 id 3\n  bind :18001 id 3\n");
    assert!(e.contains("custom id 3 already used"), "{e}");
    // Another proxy may use it.
    assert!(parse_str("frontend a\n  bind :18000 id 3\nfrontend b\n  bind :18001 id 3\n").is_ok());
}

#[test]
fn proxies_take_the_ids_round_the_explicit_ones() {
    // The order measured on HAProxy: be 2, fe 4 (3 is fe2's), be2 10, fe2 3, li 5, be3 6.
    let cfg = parse_str(
        "backend be\nfrontend fe\n  bind :18000\nbackend be2\n  id 10\nfrontend fe2\n  id 3\n  bind :18001\n\
         listen li\n  bind :18002\nbackend be3\n",
    )
    .expect("parse");
    let ids = cfg.proxy_ids();
    let iid = |v: &[alcyon_config::ast::ProxyId]| v.iter().map(|p| p.iid).collect::<Vec<_>>();
    assert_eq!(iid(&ids.backends), [2, 10, 6]);
    assert_eq!(iid(&ids.frontends), [4, 3]);
    assert_eq!(iid(&ids.listens), [5]);
    assert_eq!(ids.backends.iter().map(|p| p.forced).collect::<Vec<_>>(), [false, true, false]);
    assert_eq!(ids.frontends.iter().map(|p| p.decl).collect::<Vec<_>>(), [1, 3]);
}

#[test]
fn servers_take_the_ids_round_the_explicit_ones() {
    let cfg = parse_str(
        "backend be\n  server s1 127.0.0.1:1\n  server s2 127.0.0.1:1 id 7\n  server s3 127.0.0.1:1\n  server s4 127.0.0.1:1 id 2\n",
    )
    .expect("parse");
    assert_eq!(server_puids(cfg.backends[0].servers.len(), &cfg.backends[0].server_extras.puid), [1, 7, 3, 2]);
}

#[test]
fn listeners_number_from_the_previous_bind() {
    let cfg = parse_str(
        "frontend fe\n  bind :18000 id 5\n  bind :18001\n  bind :18002 id 2\n  bind :18003\n  bind :18004\n",
    )
    .expect("parse");
    assert_eq!(listener_ids(&cfg.frontends[0].binds), [5, 6, 2, 3, 4]);
    // A listener without an id steps over one that has it, wherever that is written.
    let cfg = parse_str("frontend fe\n  bind :18000\n  bind :18001 id 1\n  bind :18002\n  bind :18003 id 4\n  bind :18004\n  bind :18005\n")
        .expect("parse");
    assert_eq!(listener_ids(&cfg.frontends[0].binds), [2, 1, 3, 4, 5, 6]);
}
