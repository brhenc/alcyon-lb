// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Connection table keyed by Destination Connection ID (DCID).
//!
//! Under RFC 9000 §5.1, QUIC connections are identified by Connection IDs rather than
//! socket 4-tuples. When a client migrates across IP addresses or ports (NAT rebinding,
//! network change), incoming packets carry the same DCID or a retired/issued DCID belonging
//! to the existing connection.
//!
//! The `ConnectionTable` maintains a fast mapping from every active `ConnectionId` to its
//! corresponding `quinn_proto::ConnectionHandle`, ensuring $O(1)$ lookups regardless of
//! peer address changes.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use quinn_proto::ConnectionHandle;

use crate::connection::ConnectionId;

/// The hasher of a map keyed by [`ConnectionHandle`]: one multiply instead of `SipHash`
/// (T539: the default hasher of the endpoint's five handle maps was ~2 % of an HTTP/3
/// request's instructions). A handle is quinn-proto's own slab index, never a value a peer
/// chooses, so the flooding resistance `SipHash` buys is not needed here; maps keyed by a
/// connection ID (which a client picks) keep the default hasher.
#[derive(Debug, Default, Clone, Copy)]
pub struct HandleHasher(u64);

impl Hasher for HandleHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        // Not reached by `ConnectionHandle` (it hashes as one `usize`); kept total all the same.
        for &b in bytes {
            self.0 = (self.0.rotate_left(8) ^ (u64::from(b) | 0x100)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        }
    }

    fn write_usize(&mut self, n: usize) {
        // The multiply spreads a small index over the high bits too: hashbrown takes its
        // control tag from the top seven.
        self.0 = (self.0 ^ n as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
}

/// A map keyed by [`ConnectionHandle`], hashed by [`HandleHasher`].
pub type HandleMap<V> = HashMap<ConnectionHandle, V, BuildHasherDefault<HandleHasher>>;

/// Connection table mapping Destination Connection IDs to connection handles.
#[derive(Debug, Default, Clone)]
pub struct ConnectionTable {
    /// Mapping from active Connection IDs (DCIDs) to connection handles.
    cid_to_handle: HashMap<ConnectionId, ConnectionHandle>,
    /// Reverse mapping from connection handles to all their registered CIDs.
    handle_to_cids: HandleMap<Vec<ConnectionId>>,
}

impl ConnectionTable {
    /// Creates a new empty `ConnectionTable`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a new connection with its initial Destination Connection ID.
    pub fn insert(&mut self, cid: ConnectionId, handle: ConnectionHandle) {
        self.cid_to_handle.insert(cid, handle);
        self.handle_to_cids.entry(handle).or_default().push(cid);
    }

    /// Registers an additional Connection ID (e.g. issued via `NEW_CONNECTION_ID`) for an existing connection.
    pub fn register_cid(&mut self, cid: ConnectionId, handle: ConnectionHandle) {
        self.cid_to_handle.insert(cid, handle);
        let cids = self.handle_to_cids.entry(handle).or_default();
        if !cids.contains(&cid) {
            cids.push(cid);
        }
    }

    /// Removes a specific Connection ID (e.g. retired by client via `RETIRE_CONNECTION_ID`).
    pub fn remove_cid(&mut self, cid: &ConnectionId) -> Option<ConnectionHandle> {
        let handle = self.cid_to_handle.remove(cid)?;
        if let Some(cids) = self.handle_to_cids.get_mut(&handle) {
            cids.retain(|c| c != cid);
        }
        Some(handle)
    }

    /// Removes a connection and all its associated Connection IDs from the table.
    pub fn remove_connection(&mut self, handle: ConnectionHandle) -> Vec<ConnectionId> {
        if let Some(cids) = self.handle_to_cids.remove(&handle) {
            for cid in &cids {
                self.cid_to_handle.remove(cid);
            }
            cids
        } else {
            Vec::new()
        }
    }

    /// Looks up a connection handle by its Destination Connection ID.
    #[must_use]
    pub fn lookup(&self, cid: &ConnectionId) -> Option<ConnectionHandle> {
        self.cid_to_handle.get(cid).copied()
    }

    /// Returns `true` if the given Connection ID is registered in the table.
    #[must_use]
    pub fn contains_cid(&self, cid: &ConnectionId) -> bool {
        self.cid_to_handle.contains_key(cid)
    }

    /// Returns all registered Connection IDs for a given connection handle.
    #[must_use]
    pub fn cids_for_handle(&self, handle: ConnectionHandle) -> Option<&[ConnectionId]> {
        self.handle_to_cids.get(&handle).map(Vec::as_slice)
    }

    /// Returns the number of distinct active connections in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handle_to_cids.len()
    }

    /// Returns `true` if the connection table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handle_to_cids.is_empty()
    }

    /// Returns the total number of registered Connection IDs across all connections.
    #[must_use]
    pub fn total_cids(&self) -> usize {
        self.cid_to_handle.len()
    }

    /// Clears all entries from the table.
    pub fn clear(&mut self) {
        self.cid_to_handle.clear();
        self.handle_to_cids.clear();
    }
}
