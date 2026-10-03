// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Stick Table storage engine with pre-allocated slots and Elastic Binary Tree index.

use crate::entry::{StickEntryData, StickKey};
use crate::rate::SlidingRate;
use ebtree::EbMbTree;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Errors returned by stick table operations.
#[derive(Debug, thiserror::Error)]
pub enum StickTableError {
    #[error("Stick table lock poisoned: {0}")]
    LockPoisoned(String),
    #[error("Stick table capacity exceeded: max_size={0}")]
    CapacityExceeded(usize),
}

/// Key type specification for stick table configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ip,
    Ipv6,
    Integer,
    String,
    Binary,
}

/// Tracked metrics configuration flags.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrackFlags {
    pub conn_cnt: bool,
    pub conn_cur: bool,
    pub http_req_cnt: bool,
    pub http_err_cnt: bool,
    pub bytes_in_cnt: bool,
    pub bytes_out_cnt: bool,
    pub gpc0: bool,
}

/// Stick Table configuration options
#[derive(Debug, Clone)]
pub struct StickTableConfig {
    pub name: String,
    pub key_type: KeyType,
    pub max_size: usize,
    pub expire: Duration,
    pub flags: TrackFlags,
    pub track_conn_rate_ms: Option<u64>,
    pub track_http_req_rate_ms: Option<u64>,
    pub track_http_err_rate_ms: Option<u64>,
}

impl Default for StickTableConfig {
    fn default() -> Self {
        Self {
            name: "default_table".to_string(),
            key_type: KeyType::Ip,
            max_size: 100_000,
            expire: Duration::from_secs(300),
            flags: TrackFlags {
                conn_cnt: true,
                conn_cur: true,
                http_req_cnt: true,
                http_err_cnt: true,
                bytes_in_cnt: true,
                bytes_out_cnt: true,
                gpc0: true,
            },
            track_conn_rate_ms: Some(10_000),
            track_http_req_rate_ms: Some(10_000),
            track_http_err_rate_ms: Some(10_000),
        }
    }
}

#[derive(Debug, Clone)]
struct StickSlot {
    key: StickKey,
    node_idx: u32,
    data: StickEntryData,
    prev_lru: Option<u32>,
    next_lru: Option<u32>,
}

#[derive(Debug)]
struct StickTableInner {
    slots: Vec<Option<StickSlot>>,
    free_slots: Vec<u32>,
    tree: EbMbTree,
    head_lru: Option<u32>,
    tail_lru: Option<u32>,
    len: usize,
}

impl StickTableInner {
    fn with_capacity(cap: usize) -> Self {
        Self {
            slots: Vec::with_capacity(cap),
            free_slots: Vec::with_capacity(cap),
            tree: EbMbTree::with_capacity(cap),
            head_lru: None,
            tail_lru: None,
            len: 0,
        }
    }

    fn unlink_lru(&mut self, slot_idx: u32) {
        let (prev, next) = if let Some(ref slot) = self.slots[slot_idx as usize] {
            (slot.prev_lru, slot.next_lru)
        } else {
            return;
        };

        if let Some(p) = prev {
            if let Some(ref mut ps) = self.slots[p as usize] {
                ps.next_lru = next;
            }
        } else {
            self.head_lru = next;
        }

        if let Some(n) = next {
            if let Some(ref mut ns) = self.slots[n as usize] {
                ns.prev_lru = prev;
            }
        } else {
            self.tail_lru = prev;
        }

        if let Some(ref mut slot) = self.slots[slot_idx as usize] {
            slot.prev_lru = None;
            slot.next_lru = None;
        }
    }

    fn push_tail_lru(&mut self, slot_idx: u32) {
        if let Some(tail) = self.tail_lru {
            if let Some(ref mut ts) = self.slots[tail as usize] {
                ts.next_lru = Some(slot_idx);
            }
            if let Some(ref mut slot) = self.slots[slot_idx as usize] {
                slot.prev_lru = Some(tail);
                slot.next_lru = None;
            }
            self.tail_lru = Some(slot_idx);
        } else {
            if let Some(ref mut slot) = self.slots[slot_idx as usize] {
                slot.prev_lru = None;
                slot.next_lru = None;
            }
            self.head_lru = Some(slot_idx);
            self.tail_lru = Some(slot_idx);
        }
    }

    fn touch_lru(&mut self, slot_idx: u32) {
        if self.tail_lru == Some(slot_idx) {
            return;
        }
        self.unlink_lru(slot_idx);
        self.push_tail_lru(slot_idx);
    }

    fn evict_slot(&mut self, slot_idx: u32) {
        self.unlink_lru(slot_idx);
        if let Some(slot) = self.slots[slot_idx as usize].take() {
            self.tree.delete(slot.node_idx);
            self.free_slots.push(slot_idx);
            self.len -= 1;
        }
    }
}

/// High-performance Stick Table engine backed by `ebtree` and an intrusive LRU arena.
#[derive(Debug)]
pub struct StickTable {
    config: StickTableConfig,
    inner: RwLock<StickTableInner>,
}

impl StickTable {
    /// Creates a new stick table with configuration.
    #[must_use]
    pub fn new(config: StickTableConfig) -> Self {
        let cap = config.max_size;
        Self {
            config,
            inner: RwLock::new(StickTableInner::with_capacity(cap)),
        }
    }

    /// Accesses or creates an entry for the given key and applies a mutation closure.
    ///
    /// # Errors
    ///
    /// Returns [`StickTableError::LockPoisoned`] if lock acquisition fails, or
    /// [`StickTableError::CapacityExceeded`] if max size is exceeded and no entries can be evicted.
    pub fn update_entry<F>(&self, key: &StickKey, mut f: F) -> Result<(), StickTableError>
    where
        F: FnMut(&mut StickEntryData),
    {
        let mut inner = self
            .inner
            .write()
            .map_err(|e| StickTableError::LockPoisoned(e.to_string()))?;

        let enc_key = key.encode_bytes();

        if let Some(node_idx) = inner.tree.lookup_node(&enc_key) {
            let slot_idx = inner.tree.data_of(node_idx);
            if let Some(ref mut slot) = inner.slots[slot_idx as usize] {
                slot.data.last_updated = Instant::now();
                f(&mut slot.data);
                inner.touch_lru(slot_idx);
                return Ok(());
            }
        }

        // Capacity check and O(1) eviction
        if inner.len >= self.config.max_size {
            let now = Instant::now();
            let expire_dur = self.config.expire;
            if let Some(head) = inner.head_lru {
                let is_expired = inner.slots[head as usize]
                    .as_ref()
                    .is_none_or(|s| now.duration_since(s.data.last_updated) >= expire_dur);
                if is_expired || inner.len >= self.config.max_size {
                    inner.evict_slot(head);
                }
            }
        }

        if inner.len >= self.config.max_size {
            return Err(StickTableError::CapacityExceeded(self.config.max_size));
        }

        let slot_idx = if let Some(idx) = inner.free_slots.pop() {
            idx
        } else {
            let idx = u32::try_from(inner.slots.len())
                .map_err(|_| StickTableError::CapacityExceeded(self.config.max_size))?;
            inner.slots.push(None);
            idx
        };

        let mut data = self.create_default_entry();
        data.last_updated = Instant::now();
        f(&mut data);

        let node_idx = inner.tree.insert(&enc_key, slot_idx);
        inner.slots[slot_idx as usize] = Some(StickSlot {
            key: key.clone(),
            node_idx,
            data,
            prev_lru: None,
            next_lru: None,
        });
        inner.push_tail_lru(slot_idx);
        inner.len += 1;
        Ok(())
    }

    /// Reads an entry for a given key, returning None if not found or expired.
    ///
    /// # Errors
    ///
    /// Returns [`StickTableError::LockPoisoned`] if lock acquisition fails.
    pub fn get_entry(&self, key: &StickKey) -> Result<Option<StickEntryData>, StickTableError> {
        let inner = self
            .inner
            .read()
            .map_err(|e| StickTableError::LockPoisoned(e.to_string()))?;

        let enc_key = key.encode_bytes();
        if let Some(node_idx) = inner.tree.lookup_node(&enc_key) {
            let slot_idx = inner.tree.data_of(node_idx);
            if let Some(ref slot) = inner.slots[slot_idx as usize] {
                if slot.data.last_updated.elapsed() < self.config.expire {
                    return Ok(Some(slot.data.clone()));
                }
            }
        }
        Ok(None)
    }

    /// Purges expired entries from the stick table in $O(E)$ time.
    ///
    /// # Errors
    ///
    /// Returns [`StickTableError::LockPoisoned`] if lock acquisition fails.
    pub fn purge_expired(&self) -> Result<usize, StickTableError> {
        let mut inner = self
            .inner
            .write()
            .map_err(|e| StickTableError::LockPoisoned(e.to_string()))?;

        let now = Instant::now();
        let expire_dur = self.config.expire;
        let mut purged = 0;
        while let Some(head) = inner.head_lru {
            let is_expired = inner.slots[head as usize]
                .as_ref()
                .is_none_or(|s| now.duration_since(s.data.last_updated) >= expire_dur);
            if is_expired {
                inner.evict_slot(head);
                purged += 1;
            } else {
                break;
            }
        }
        Ok(purged)
    }

    /// Clears all entries in the stick table.
    ///
    /// # Errors
    ///
    /// Returns [`StickTableError::LockPoisoned`] if lock acquisition fails.
    pub fn clear(&self) -> Result<(), StickTableError> {
        let mut inner = self
            .inner
            .write()
            .map_err(|e| StickTableError::LockPoisoned(e.to_string()))?;

        while let Some(head) = inner.head_lru {
            inner.evict_slot(head);
        }
        Ok(())
    }

    /// Deletes a specific entry by key from the stick table.
    ///
    /// # Errors
    ///
    /// Returns [`StickTableError::LockPoisoned`] if lock acquisition fails.
    pub fn delete_entry(&self, key: &StickKey) -> Result<bool, StickTableError> {
        let mut inner = self
            .inner
            .write()
            .map_err(|e| StickTableError::LockPoisoned(e.to_string()))?;

        let enc_key = key.encode_bytes();
        if let Some(node_idx) = inner.tree.lookup_node(&enc_key) {
            let slot_idx = inner.tree.data_of(node_idx);
            inner.evict_slot(slot_idx);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Returns the number of entries currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().map_or(0, |inner| inner.len)
    }

    /// Returns true if the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Dumps all active (non-expired) entries in LRU order.
    ///
    /// # Errors
    ///
    /// Returns [`StickTableError::LockPoisoned`] if lock acquisition fails.
    pub fn dump_entries(&self) -> Result<Vec<(StickKey, StickEntryData)>, StickTableError> {
        let inner = self
            .inner
            .read()
            .map_err(|e| StickTableError::LockPoisoned(e.to_string()))?;

        let now = Instant::now();
        let expire_dur = self.config.expire;
        let mut result = Vec::new();
        let mut cur = inner.head_lru;
        while let Some(idx) = cur {
            if let Some(ref slot) = inner.slots[idx as usize] {
                if now.duration_since(slot.data.last_updated) < expire_dur {
                    result.push((slot.key.clone(), slot.data.clone()));
                }
                cur = slot.next_lru;
            } else {
                break;
            }
        }
        Ok(result)
    }

    fn create_default_entry(&self) -> StickEntryData {
        let mut entry = StickEntryData::default();
        if let Some(period) = self.config.track_conn_rate_ms {
            entry.conn_rate = Some(SlidingRate::new(period));
        }
        if let Some(period) = self.config.track_http_req_rate_ms {
            entry.http_req_rate = Some(SlidingRate::new(period));
        }
        if let Some(period) = self.config.track_http_err_rate_ms {
            entry.http_err_rate = Some(SlidingRate::new(period));
        }
        entry
    }

    /// Table configuration.
    #[must_use]
    pub fn config(&self) -> &StickTableConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_stick_table_tracking() {
        let config = StickTableConfig {
            name: "test_ip_table".to_string(),
            key_type: KeyType::Ip,
            ..Default::default()
        };
        let table = StickTable::new(config);
        let key = StickKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));

        table
            .update_entry(&key, |entry| {
                entry.conn_cnt += 1;
                entry.conn_cur += 1;
                if let Some(ref mut rate) = entry.conn_rate {
                    rate.tick(1);
                }
            })
            .expect("update succeeds");

        let entry = table.get_entry(&key).expect("lookup succeeds").unwrap();
        assert_eq!(entry.conn_cnt, 1);
        assert_eq!(entry.conn_cur, 1);
        assert!(entry.conn_rate.unwrap().rate() >= 1);
    }

    #[test]
    fn test_stick_table_expiry() {
        let config = StickTableConfig {
            name: "expiring_table".to_string(),
            key_type: KeyType::String,
            expire: Duration::from_millis(10),
            ..Default::default()
        };
        let table = StickTable::new(config);
        let key = StickKey::String("user-123".to_string());

        table.update_entry(&key, |e| e.conn_cnt = 5).unwrap();
        assert_eq!(table.get_entry(&key).unwrap().unwrap().conn_cnt, 5);

        std::thread::sleep(Duration::from_millis(25));
        assert!(table.get_entry(&key).unwrap().is_none());
        let purged = table.purge_expired().unwrap();
        assert_eq!(purged, 1);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_stick_table_lru_eviction() {
        let config = StickTableConfig {
            name: "bounded_table".to_string(),
            key_type: KeyType::Integer,
            max_size: 2,
            expire: Duration::from_secs(60),
            ..Default::default()
        };
        let table = StickTable::new(config);
        let k1 = StickKey::Integer(1);
        let k2 = StickKey::Integer(2);
        let k3 = StickKey::Integer(3);

        table.update_entry(&k1, |e| e.conn_cnt = 10).unwrap();
        table.update_entry(&k2, |e| e.conn_cnt = 20).unwrap();
        assert_eq!(table.len(), 2);

        // Touch k1 to make k2 the LRU head
        table.update_entry(&k1, |e| e.conn_cnt = 11).unwrap();

        // Insert k3 -> should evict k2
        table.update_entry(&k3, |e| e.conn_cnt = 30).unwrap();
        assert_eq!(table.len(), 2);

        assert!(table.get_entry(&k1).unwrap().is_some());
        assert!(table.get_entry(&k2).unwrap().is_none()); // Evicted
        assert!(table.get_entry(&k3).unwrap().is_some());
    }
}
