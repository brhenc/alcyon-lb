// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The per-server and per-proxy structs are paid for 60,000 times over
//! (`request_allocations::sixty_thousand_backends_memory_bounded`). A field that grows one
//! of them must move behind a `Box` unless every server uses it; raise a bound here only
//! after that has been considered.

use std::mem::size_of;

#[test]
fn server_stays_184_bytes() {
    assert!(
        size_of::<ibex_config::Server>() <= 184,
        "ibex_config::Server grew to {} bytes (bound 184): box the new field",
        size_of::<ibex_config::Server>()
    );
}

#[test]
fn proxy_stays_1656_bytes() {
    assert!(
        size_of::<ibex_rt::engine::Proxy>() <= 1656,
        "Proxy grew to {} bytes (bound 1656): box the new field",
        size_of::<ibex_rt::engine::Proxy>()
    );
}

#[test]
fn per_server_check_config_is_boxed() {
    assert!(
        size_of::<Option<Box<ibex_rt::check::ServerCheckConfig>>>() == 8,
        "the per-server check config must stay one pointer"
    );
}

#[test]
fn server_check_state_stays_small() {
    let n = size_of::<ibex_rt::check::ServerCheckState>();
    assert!(n <= 456, "ServerCheckState grew to {n} bytes (bound 456): one is held per checked server, box the new field");
}

/// A session is held for every client connection, idle ones included, in the worker's
/// arena (T183: HAProxy keeps ~1 KB per idle client). Box what only some connections use
/// (`h2_ctx`, `proxy_info` are).
#[test]
fn session_entry_stays_small() {
    let n = size_of::<ibex_rt::engine::SessionEntry>();
    assert!(n <= 1608, "SessionEntry grew to {n} bytes (bound 1608): one is held per client connection, box the new field");
}
