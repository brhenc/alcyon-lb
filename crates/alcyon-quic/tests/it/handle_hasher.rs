// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T539: the endpoint's maps keyed by `ConnectionHandle` hash with `HandleHasher` (one
//! multiply) instead of `SipHash`. A handle is quinn-proto's slab index: small, dense,
//! server-assigned. The map must still behave as a map for any set of handles, and the hash
//! must reach hashbrown's control tag (its top seven bits) so dense indices do not all share
//! one tag.

use std::collections::HashSet;
use std::hash::{BuildHasher, BuildHasherDefault, Hasher};

use alcyon_quic::quinn_proto::ConnectionHandle;
use alcyon_quic::table::{HandleHasher, HandleMap};

#[test]
fn a_handle_map_is_a_map() {
    let mut m: HandleMap<usize> = HandleMap::default();
    for i in 0..10_000 {
        assert!(m.insert(ConnectionHandle(i), i * 3).is_none());
    }
    for i in (0..10_000).step_by(2) {
        assert_eq!(m.remove(&ConnectionHandle(i)), Some(i * 3));
    }
    assert_eq!(m.len(), 5_000);
    for i in 0..10_000 {
        assert_eq!(m.get(&ConnectionHandle(i)).copied(), (i % 2 == 1).then_some(i * 3), "handle {i}");
    }
}

#[test]
fn dense_handles_spread_over_the_control_tag() {
    let b = BuildHasherDefault::<HandleHasher>::default();
    let tags: HashSet<u64> = (0..1024).map(|i| b.hash_one(ConnectionHandle(i)) >> 57).collect();
    // 128 possible tags; an identity hash would give one (0) for every small index.
    assert!(tags.len() > 100, "{} distinct tags", tags.len());
    let low: HashSet<u64> = (0..1024).map(|i| b.hash_one(ConnectionHandle(i)) & 1023).collect();
    assert!(low.len() > 512, "{} distinct low-bit buckets", low.len());
}

#[test]
fn bytes_hash_too() {
    // `ConnectionHandle` hashes as one `usize`; the byte path is there for completeness and
    // must still be a function of its input.
    let h = |bytes: &[u8]| {
        let mut s = HandleHasher::default();
        s.write(bytes);
        s.finish()
    };
    assert_eq!(h(b"abc"), h(b"abc"));
    assert_ne!(h(b"abc"), h(b"abd"));
    assert_ne!(h(b""), h(b"\0"));
}
