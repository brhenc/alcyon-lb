// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Ibex contributors. See LICENSE.

//! Tests for `TlsArena` and `TlsSlot` pre-allocated zero-allocation layout.

mod common;

use common::{build_root_store, generate_test_cert};
use ibex_tls::{IbexCertResolver, TlsArena, TlsArenaError, TlsConfig};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection};
use std::sync::Arc;

#[test]
fn test_tls_arena_lifecycle() {
    let (cert, cert_der) = generate_test_cert(vec!["example.com".to_string()]);
    let mut resolver = IbexCertResolver::new();
    resolver.set_default_cert(cert);

    let config = TlsConfig::new().with_cert_resolver(Arc::new(resolver));
    let server_config = config.build_server_config().expect("Built server config");

    let root_store = build_root_store(&[cert_der]);
    let client_config = config
        .build_client_config(root_store)
        .expect("Built client config");
    let server_name = ServerName::try_from("example.com").expect("Valid server name");

    let mut arena = TlsArena::new(4, 16_384);
    assert_eq!(arena.capacity(), 4);
    assert_eq!(arena.active_count(), 0);
    assert!(arena.is_empty());

    // Allocate 4 server connections
    let mut ids = Vec::new();
    for _ in 0..4 {
        let conn = ServerConnection::new(server_config.clone()).expect("Created server connection");
        let id = arena.alloc_server(conn).expect("Allocated slot");
        ids.push(id);
    }

    assert_eq!(arena.active_count(), 4);
    assert!(!arena.is_empty());

    // 5th allocation must fail with Exhausted
    let extra_conn =
        ServerConnection::new(server_config.clone()).expect("Created server connection");
    assert_eq!(
        arena.alloc_server(extra_conn).unwrap_err(),
        TlsArenaError::Exhausted(4)
    );

    // Verify slots are readable and mutable
    for &id in &ids {
        let slot = arena.get(id).expect("Slot in use");
        assert_eq!(slot.slot_id, id);
        assert!(slot.in_use);
    }

    // Free slot 1 and slot 2
    arena.free(ids[1]).expect("Freed slot 1");
    arena.free(ids[2]).expect("Freed slot 2");
    assert_eq!(arena.active_count(), 2);

    // Reallocate client connections into the freed slots
    let client_conn_1 = ClientConnection::new(client_config.clone(), server_name.clone())
        .expect("Created client connection");
    let client_conn_2 = ClientConnection::new(client_config.clone(), server_name.clone())
        .expect("Created client connection");

    let new_id_1 = arena
        .alloc_client(client_conn_1)
        .expect("Allocated recycled slot 1");
    let new_id_2 = arena
        .alloc_client(client_conn_2)
        .expect("Allocated recycled slot 2");

    assert_eq!(arena.active_count(), 4);
    assert!(new_id_1 == ids[1] || new_id_1 == ids[2]);
    assert!(new_id_2 == ids[1] || new_id_2 == ids[2]);

    // Free all
    for &id in &ids {
        let _ = arena.free(id);
    }
    assert_eq!(arena.active_count(), 0);
    assert!(arena.is_empty());
}
