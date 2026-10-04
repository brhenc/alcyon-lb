// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Several `global` sections are one (T146 item 2). HAProxy reads every `global` section
//! into the same `global` struct: a keyword in a later one adds to what an earlier one
//! set, a second `stats socket` is a second socket, and a scalar keyword set twice keeps
//! the last value. Ibex used to start a fresh section at each `global` and keep only the
//! last. `ibex-rt` `tests/global_sections.rs` drives both sockets.

use ibex_config::parse_str;

const TWO: &str = "global\n  nbthread 2\n  stats socket /tmp/a.sock mode 600 level admin\n\
                   global\n  maxconn 100\n  stats socket /tmp/b.sock level operator\n";

#[test]
fn the_keywords_of_every_global_section_are_kept() {
    let g = parse_str(TWO).expect("parse").global.expect("global");
    assert_eq!(g.nbthread, Some(2), "set by the first section");
    assert_eq!(g.maxconn, Some(100), "set by the second");
}

#[test]
fn every_stats_socket_is_kept_with_its_own_options() {
    let g = parse_str(TWO).expect("parse").global.expect("global");
    assert_eq!(g.stats_socket.as_deref(), Some("/tmp/a.sock"));
    assert_eq!(g.stats_socket_mode, Some(0o600));
    assert_eq!(g.stats_socket_level.as_deref(), Some("admin"));
    assert_eq!(g.extra_stats_sockets.len(), 1);
    let b = &g.extra_stats_sockets[0];
    assert_eq!((b.path.as_str(), b.mode, b.level.as_deref()), ("/tmp/b.sock", None, Some("operator")));
}

#[test]
fn a_scalar_set_twice_keeps_the_last_value() {
    let g = parse_str("global\n  maxconn 10\nglobal\n  maxconn 20\n").expect("parse").global.expect("global");
    assert_eq!(g.maxconn, Some(20));
}

#[test]
fn two_stats_sockets_in_one_section_are_two_sockets() {
    let g = parse_str("global\n  stats socket /tmp/a.sock\n  stats socket /tmp/b.sock level admin\n")
        .expect("parse")
        .global
        .expect("global");
    assert_eq!(g.stats_socket.as_deref(), Some("/tmp/a.sock"));
    assert_eq!(g.extra_stats_sockets.len(), 1);
    assert_eq!(g.extra_stats_sockets[0].path, "/tmp/b.sock");
    assert_eq!(g.extra_stats_sockets[0].level.as_deref(), Some("admin"));
}
