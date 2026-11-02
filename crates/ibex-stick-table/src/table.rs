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
    pub sess_cnt: bool,
    pub http_req_cnt: bool,
    pub http_err_cnt: bool,
    pub bytes_in_cnt: bool,
    pub bytes_out_cnt: bool,
    pub gpc0: bool,
    pub gpc1: bool,
    pub gpt0: bool,
    pub http_fail_cnt: bool,
    pub glitch_cnt: bool,
    pub server_id: bool,
}

/// The rate periods and array sizes of the data types the flags do not cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StickExtra {
    pub sess_rate_ms: Option<u64>,
    pub bytes_in_rate_ms: Option<u64>,
    pub bytes_out_rate_ms: Option<u64>,
    pub http_fail_rate_ms: Option<u64>,
    pub glitch_rate_ms: Option<u64>,
    pub gpc0_rate_ms: Option<u64>,
    pub gpc1_rate_ms: Option<u64>,
    /// `gpc(<n>)`: the number of general purpose counters.
    pub gpc_n: usize,
    /// `gpc_rate(<n>,<period>)`: the number of counters with a rate, and its period.
    pub gpc_rate_n: usize,
    pub gpc_rate_ms: u64,
    /// `gpt(<n>)`: the number of general purpose tags.
    pub gpt_n: usize,
}

/// A general purpose counter: the legacy `gpc0` and `gpc1`, or an element of the array of
/// `gpc(<n>)`; and, for the tags, `Zero` is `gpt0` and `Idx` an element of `gpt(<n>)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gpc {
    Zero,
    One,
    Idx(usize),
}

/// What a rule, a fetch or a converter does to a general purpose counter or tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpcOp {
    /// `inc_gpc`: one more, and a tick of its rate; gives the new value.
    Inc,
    /// `sc-add-gpc`: `n` more, and `n` ticks of its rate; gives the new value.
    Add(u64),
    /// `clr_gpc`: back to zero; gives the previous value.
    Clr,
    /// `sc-set-gpt`: the tag set; gives the value.
    SetTag(u32),
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
    pub extra: StickExtra,
}

impl StickTableConfig {
    /// Whether an entry last updated at `last_updated` has expired at `now`. An `expire` of
    /// zero means the entries never expire (`HAProxy` shows `exp=0` and keeps them).
    #[must_use]
    pub fn is_expired(&self, now: Instant, last_updated: Instant) -> bool {
        !self.expire.is_zero() && now.duration_since(last_updated) >= self.expire
    }
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
                sess_cnt: true,
                http_req_cnt: true,
                http_err_cnt: true,
                bytes_in_cnt: true,
                bytes_out_cnt: true,
                gpc0: true,
                gpc1: true,
                gpt0: true,
                http_fail_cnt: true,
                glitch_cnt: true,
                server_id: true,
            },
            track_conn_rate_ms: Some(10_000),
            track_http_req_rate_ms: Some(10_000),
            track_http_err_rate_ms: Some(10_000),
            extra: StickExtra::default(),
        }
    }
}

#[derive(Debug, Clone)]
struct StickSlot {
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
    /// The longest `string` or `binary` key kept (`len`); longer ones are cut to it.
    key_len: usize,
    inner: RwLock<StickTableInner>,
}

impl StickTable {
    /// Whether a panic unwound through a change of the table: its lock is poisoned and its
    /// tree may be half-updated (T447).
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.inner.is_poisoned()
    }

    /// Creates a new stick table with configuration.
    #[must_use]
    pub fn new(config: StickTableConfig) -> Self {
        let cap = config.max_size;
        Self {
            config,
            key_len: usize::MAX,
            inner: RwLock::new(StickTableInner::with_capacity(cap)),
        }
    }

    /// The table keeping `string` and `binary` keys to at most `len` bytes (`stick-table ...
    /// len`; `HAProxy` cuts the key, it does not refuse it).
    #[must_use]
    pub fn with_key_len(mut self, len: usize) -> Self {
        self.key_len = len;
        self
    }

    /// `key` as the table keeps it: a long `string` or `binary` key is cut to `len` bytes
    /// (a string at the last character that fits).
    fn cut<'a>(&self, key: &'a StickKey) -> std::borrow::Cow<'a, StickKey> {
        let n = self.key_len;
        match key {
            StickKey::String(s) if s.len() > n => {
                let mut end = n;
                while !s.is_char_boundary(end) {
                    end -= 1;
                }
                std::borrow::Cow::Owned(StickKey::String(s[..end].to_string()))
            }
            StickKey::Binary(b) if b.len() > n => std::borrow::Cow::Owned(StickKey::Binary(b[..n].to_vec())),
            _ => std::borrow::Cow::Borrowed(key),
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

        let enc_key = self.cut(key).encode_bytes();

        if let Some(node_idx) = inner.tree.lookup_node(&enc_key) {
            let slot_idx = inner.tree.data_of(node_idx);
            if let Some(ref mut slot) = inner.slots[slot_idx as usize] {
                slot.data.last_updated = Instant::now();
                f(&mut slot.data);
                inner.touch_lru(slot_idx);
                return Ok(());
            }
        }

        // Capacity check: the oldest entry no session tracks makes room. An entry a session
        // tracks stays, as in `HAProxy`'s `stktable_trash_oldest` (a tracked entry dropped
        // here loses its `conn_cur` and its rates, which is how a limit is bypassed); when
        // all are tracked the new key gets no entry.
        if inner.len >= self.config.max_size {
            let slots = &inner.slots;
            let next = |&i: &u32| slots[i as usize].as_ref().and_then(|s| s.next_lru);
            let victim = std::iter::successors(inner.head_lru, next)
                .find(|&i| slots[i as usize].as_ref().is_some_and(|s| s.data.trackers == 0));
            if let Some(idx) = victim {
                inner.evict_slot(idx);
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

        let enc_key = self.cut(key).encode_bytes();
        if let Some(node_idx) = inner.tree.lookup_node(&enc_key) {
            let slot_idx = inner.tree.data_of(node_idx);
            if let Some(ref slot) = inner.slots[slot_idx as usize] {
                if !self.config.is_expired(Instant::now(), slot.data.last_updated) {
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
        let mut purged = 0;
        // Bounded by the entries present now: a renewed (tracked) entry moves to the tail and
        // is never expired again within this call, but the walk must end whatever happens.
        let mut budget = inner.len;
        while let Some(head) = inner.head_lru {
            if budget == 0 {
                break;
            }
            budget -= 1;
            // The LRU list links occupied slots only: `evict_slot` unlinks before it frees.
            let Some(slot) = inner.slots[head as usize].as_mut() else { break };
            if !self.config.is_expired(now, slot.data.last_updated) {
                break;
            }
            if slot.data.trackers > 0 {
                // An entry a session still tracks stays, its time renewed (`HAProxy` keeps
                // an entry that has references and arms its expiry again).
                slot.data.last_updated = now;
                inner.touch_lru(head);
            } else {
                inner.evict_slot(head);
                purged += 1;
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

        let enc_key = self.cut(key).encode_bytes();
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
        let mut result = Vec::new();
        let mut cur = inner.head_lru;
        while let Some(idx) = cur {
            if let Some(ref slot) = inner.slots[idx as usize] {
                if !self.config.is_expired(now, slot.data.last_updated) {
                    // The key is kept once, in the tree.
                    if let Some(key) = StickKey::decode_bytes(inner.tree.key_of(slot.node_idx)) {
                        result.push((key, slot.data.clone()));
                    }
                }
                cur = slot.next_lru;
            } else {
                break;
            }
        }
        Ok(result)
    }

    /// Up to `max` live entries of the slots from `from` on, and the slot to continue from
    /// (`None` once the end is reached). The lock is taken for this call only: an entry
    /// created or removed between two calls may be missed, none is given twice.
    pub fn dump_from(&self, from: usize, max: usize) -> (Vec<(StickKey, StickEntryData)>, Option<usize>) {
        let Ok(inner) = self.inner.read() else { return (Vec::new(), None) };
        let now = Instant::now();
        let mut out = Vec::new();
        let mut i = from;
        while i < inner.slots.len() && out.len() < max {
            if let Some(slot) = &inner.slots[i] {
                if !self.config.is_expired(now, slot.data.last_updated) {
                    if let Some(key) = StickKey::decode_bytes(inner.tree.key_of(slot.node_idx)) {
                        out.push((key, slot.data.clone()));
                    }
                }
            }
            i += 1;
        }
        (out, (i < inner.slots.len()).then_some(i))
    }

    /// Applies `op` to the counter or tag `which` of the entry `key`, which is created when
    /// `create` (`stktable_get_entry`; a lookup otherwise). `None` where the table does not
    /// store that counter, `Some(0)` where the entry is not there and is not created.
    pub fn gpc_op(&self, key: &StickKey, create: bool, which: Gpc, op: GpcOp) -> Option<i64> {
        let x = &self.config.extra;
        let f = self.config.flags;
        // `gpc0`, `gpc1` and `gpt0` of a table that stores the array form are its elements 0 and 1.
        let tag = matches!(op, GpcOp::SetTag(_));
        let which = match which {
            Gpc::Zero if !(if tag { f.gpt0 } else { f.gpc0 }) => Gpc::Idx(0),
            Gpc::One if !f.gpc1 => Gpc::Idx(1),
            w => w,
        };
        let stored = match (op, which) {
            (GpcOp::SetTag(_), Gpc::Zero) => f.gpt0,
            (GpcOp::SetTag(_), Gpc::Idx(i)) => i < x.gpt_n,
            (GpcOp::SetTag(_), Gpc::One) => false,
            (_, Gpc::Zero) => f.gpc0,
            (_, Gpc::One) => f.gpc1,
            (_, Gpc::Idx(i)) => i < x.gpc_n,
        };
        if !stored {
            return None;
        }
        if !create && self.get_entry(key).ok().flatten().is_none() {
            return Some(0);
        }
        let mut out = 0u64;
        self.update_entry(key, |e| {
            let (cnt, rate) = match which {
                Gpc::Zero => (&mut e.gpc0, e.gpc0_rate.as_mut()),
                Gpc::One => (&mut e.gpc1, e.gpc1_rate.as_mut()),
                Gpc::Idx(i) => (&mut e.gpc[i], e.gpc_rate.get_mut(i)),
            };
            match op {
                GpcOp::Inc | GpcOp::Add(_) => {
                    let n = if let GpcOp::Add(n) = op { n } else { 1 };
                    *cnt = cnt.saturating_add(n);
                    if let Some(r) = rate {
                        r.tick(n);
                    }
                    out = *cnt;
                }
                GpcOp::Clr => out = std::mem::take(cnt),
                GpcOp::SetTag(v) => {
                    match which {
                        Gpc::Idx(i) => e.gpt[i] = v,
                        // `One` is no tag: refused above, never here.
                        Gpc::Zero | Gpc::One => e.gpt0 = v,
                    }
                    out = u64::from(v);
                }
            }
        })
        .ok()?;
        Some(i64::try_from(out).unwrap_or(i64::MAX))
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
        let x = &self.config.extra;
        let rate = |ms: Option<u64>| ms.map(SlidingRate::new);
        entry.sess_rate = rate(x.sess_rate_ms);
        entry.bytes_in_rate = rate(x.bytes_in_rate_ms);
        entry.bytes_out_rate = rate(x.bytes_out_rate_ms);
        entry.http_fail_rate = rate(x.http_fail_rate_ms);
        entry.glitch_rate = rate(x.glitch_rate_ms);
        entry.gpc0_rate = rate(x.gpc0_rate_ms);
        entry.gpc1_rate = rate(x.gpc1_rate_ms);
        entry.gpc = vec![0; x.gpc_n];
        entry.gpc_rate = (0..x.gpc_rate_n).map(|_| SlidingRate::new(x.gpc_rate_ms)).collect();
        entry.gpt = vec![0; x.gpt_n];
        entry
    }

    /// The data types this table stores, with `d`'s values, in the order `show table`
    /// prints them (`stktable_data_types`): the name, the period of a rate in ms, and the
    /// value. The arrays come after `http_fail_rate`, `glitch_*` last.
    #[must_use]
    pub fn data_fields(&self, d: &StickEntryData) -> Vec<(String, Option<u64>, u64)> {
        let (f, x, c) = (&self.config.flags, &self.config.extra, &self.config);
        let rate = |r: &Option<SlidingRate>| r.as_ref().map_or(0, SlidingRate::rate);
        // Each is a counter (stored when its flag is set) or a rate (when it has a period).
        let scalar = x.gpc_n == 0;
        let types: [(&str, bool, Option<u64>, u64); 22] = [
            // A table a `stick` rule fills keeps the server whether or not `store` says so.
            ("server_id", f.server_id || d.server_id.is_some(), None, u64::from(d.server_id.unwrap_or(0))),
            ("gpt0", f.gpt0 && x.gpt_n == 0, None, u64::from(d.gpt0)),
            ("gpc0", f.gpc0 && scalar, None, d.gpc0),
            ("gpc0_rate", false, x.gpc0_rate_ms, rate(&d.gpc0_rate)),
            ("conn_cnt", f.conn_cnt, None, d.conn_cnt),
            ("conn_rate", false, c.track_conn_rate_ms, rate(&d.conn_rate)),
            ("conn_cur", f.conn_cur, None, u64::from(d.conn_cur)),
            ("sess_cnt", f.sess_cnt, None, d.sess_cnt),
            ("sess_rate", false, x.sess_rate_ms, rate(&d.sess_rate)),
            ("http_req_cnt", f.http_req_cnt, None, d.http_req_cnt),
            ("http_req_rate", false, c.track_http_req_rate_ms, rate(&d.http_req_rate)),
            ("http_err_cnt", f.http_err_cnt, None, d.http_err_cnt),
            ("http_err_rate", false, c.track_http_err_rate_ms, rate(&d.http_err_rate)),
            ("bytes_in_cnt", f.bytes_in_cnt, None, d.bytes_in_cnt),
            ("bytes_in_rate", false, x.bytes_in_rate_ms, rate(&d.bytes_in_rate)),
            ("bytes_out_cnt", f.bytes_out_cnt, None, d.bytes_out_cnt),
            ("bytes_out_rate", false, x.bytes_out_rate_ms, rate(&d.bytes_out_rate)),
            ("gpc1", f.gpc1 && scalar, None, d.gpc1),
            ("gpc1_rate", false, x.gpc1_rate_ms, rate(&d.gpc1_rate)),
            // The value is the server's name, which only the proxy knows: `show table` fills it in.
            ("server_key", d.server_id.is_some(), None, 0),
            ("http_fail_cnt", f.http_fail_cnt, None, d.http_fail_cnt),
            ("http_fail_rate", false, x.http_fail_rate_ms, rate(&d.http_fail_rate)),
        ];
        let mut out: Vec<(String, Option<u64>, u64)> = Vec::new();
        for (name, counter, period, v) in types {
            if counter {
                out.push((name.to_string(), None, v));
            } else if let Some(p) = period {
                out.push((name.to_string(), Some(p), v));
            }
        }
        for i in 0..x.gpt_n {
            out.push((format!("gpt{i}"), None, u64::from(d.gpt.get(i).copied().unwrap_or(0))));
        }
        for i in 0..x.gpc_n {
            out.push((format!("gpc{i}"), None, d.gpc.get(i).copied().unwrap_or(0)));
        }
        for i in 0..x.gpc_rate_n {
            out.push((format!("gpc{i}_rate"), Some(x.gpc_rate_ms), d.gpc_rate.get(i).map_or(0, SlidingRate::rate)));
        }
        if f.glitch_cnt {
            out.push(("glitch_cnt".to_string(), None, d.glitch_cnt));
        }
        if let Some(p) = x.glitch_rate_ms {
            out.push(("glitch_rate".to_string(), Some(p), rate(&d.glitch_rate)));
        }
        out
    }

    /// Table configuration.
    #[must_use]
    pub fn config(&self) -> &StickTableConfig {
        &self.config
    }

    /// `key` converted to this table's key type, as `HAProxy` converts the sample that
    /// tracks or looks up a key (`smp_to_stkey`, through the sample casts): the table
    /// decides the key's type, not the sample. `None` where the cast does not exist or
    /// fails: no key, so nothing is tracked and nothing is found.
    ///
    /// The conversions are the ones measured on `HAProxy` 3.5-dev8-885761-29: an integer
    /// to a string table is its decimal text, to an `ip` table the address with that
    /// 32-bit value, to a `binary` table its eight bytes (never the bytes of its text); a
    /// string to an integer table is its leading number (0 if it has none), to an `ip`
    /// table an IPv4 address and to an `ipv6` table an IPv6 address (`"10.0.0.1"` is not
    /// one); an IPv4 address to an `ipv6` table is its `::ffff:` form, to a string table
    /// its text and to a `binary` table its four bytes. An address to an integer table is
    /// refused when the configuration loads.
    #[must_use]
    pub fn coerce_key(&self, key: StickKey) -> Option<StickKey> {
        coerce_key(self.config.key_type, key)
    }
}

/// [`StickTable::coerce_key`] for a table of key type `ty`.
#[must_use]
// `i as u32` is the cast `HAProxy` makes (`htonl((uint32_t)sint)`): the low 32 bits.
#[allow(clippy::cast_possible_truncation)]
pub fn coerce_key(ty: KeyType, key: StickKey) -> Option<StickKey> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    match (ty, key) {
        (KeyType::Ip, k @ StickKey::Ip(IpAddr::V4(_)))
        | (KeyType::Ipv6, k @ StickKey::Ip(IpAddr::V6(_)))
        | (KeyType::Integer, k @ StickKey::Integer(_))
        | (KeyType::String, k @ StickKey::String(_))
        | (KeyType::Binary, k @ StickKey::Binary(_)) => Some(k),
        (KeyType::Ip, StickKey::Ip(IpAddr::V6(v6))) => v6.to_ipv4_mapped().map(|v4| StickKey::Ip(IpAddr::V4(v4))),
        (KeyType::Ip, StickKey::Integer(i)) => {
            // The low 32 bits, as `htonl((uint32_t)sint)` takes them.
            Some(StickKey::Ip(IpAddr::V4(Ipv4Addr::from(i as u32))))
        }
        (KeyType::Ip, StickKey::String(s)) => s.parse::<Ipv4Addr>().ok().map(|v4| StickKey::Ip(IpAddr::V4(v4))),
        (KeyType::Ip, StickKey::Binary(b)) => <[u8; 4]>::try_from(b.as_slice()).ok().map(|o| StickKey::Ip(IpAddr::V4(Ipv4Addr::from(o)))),
        (KeyType::Ipv6, StickKey::Ip(IpAddr::V4(v4))) => Some(StickKey::Ip(IpAddr::V6(v4.to_ipv6_mapped()))),
        (KeyType::Ipv6, StickKey::Integer(i)) => Some(StickKey::Ip(IpAddr::V6(Ipv4Addr::from(i as u32).to_ipv6_mapped()))),
        (KeyType::Ipv6, StickKey::String(s)) => s.parse::<Ipv6Addr>().ok().map(|v6| StickKey::Ip(IpAddr::V6(v6))),
        (KeyType::Ipv6, StickKey::Binary(b)) => <[u8; 16]>::try_from(b.as_slice()).ok().map(|o| StickKey::Ip(IpAddr::V6(Ipv6Addr::from(o)))),
        (KeyType::Integer, StickKey::String(s)) => Some(StickKey::Integer(leading_number(&s).cast_unsigned())),
        (KeyType::Integer, _) => None,
        (KeyType::String, StickKey::Integer(i)) => Some(StickKey::String(i.cast_signed().to_string())),
        (KeyType::String, StickKey::Ip(ip)) => Some(StickKey::String(ip.to_string())),
        (KeyType::String, StickKey::Binary(b)) => Some(StickKey::String(String::from_utf8_lossy(&b).into_owned())),
        (KeyType::Binary, StickKey::String(s)) => Some(StickKey::Binary(s.into_bytes())),
        (KeyType::Binary, StickKey::Integer(i)) => Some(StickKey::Binary(i.to_ne_bytes().to_vec())),
        (KeyType::Binary, StickKey::Ip(IpAddr::V4(v4))) => Some(StickKey::Binary(v4.octets().to_vec())),
        (KeyType::Binary, StickKey::Ip(IpAddr::V6(v6))) => Some(StickKey::Binary(v6.octets().to_vec())),
    }
}

/// The number a string starts with (`c_str2int`): an optional sign and the digits that
/// follow, 0 if there are none.
fn leading_number(s: &str) -> i64 {
    let t = s.trim_start();
    let (neg, digits) = t.strip_prefix('-').map_or((false, t.strip_prefix('+').unwrap_or(t)), |d| (true, d));
    let n = digits.bytes().take_while(u8::is_ascii_digit).fold(0i64, |n, d| n.wrapping_mul(10).wrapping_add(i64::from(d - b'0')));
    if neg { n.wrapping_neg() } else { n }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// An entry past its expiry is not dumped, though not purged yet; the purge then
    /// takes it.
    #[test]
    fn an_expired_entry_is_not_dumped_and_is_purged() {
        let config = StickTableConfig { key_type: KeyType::Ip, expire: Duration::from_millis(30), ..Default::default() };
        let table = StickTable::new(config);
        let key = StickKey::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        table.update_entry(&key, |e| e.conn_cnt += 1).expect("update");
        assert_eq!(table.dump_from(0, 10).0.len(), 1);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(table.len(), 1, "not purged yet");
        let (dumped, next) = table.dump_from(0, 10);
        assert!(dumped.is_empty() && next.is_none(), "{dumped:?}");
        assert_eq!(table.purge_expired().expect("purge"), 1);
        assert_eq!(table.len(), 0);
    }

    /// A panic inside a change of the table poisons it, and `is_poisoned` says so: a stream
    /// that panicked there must not let the process go on with that table (T447).
    #[test]
    fn a_panic_inside_an_update_leaves_the_table_poisoned() {
        let table = StickTable::new(StickTableConfig { key_type: KeyType::Ip, ..Default::default() });
        let key = StickKey::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!table.is_poisoned());
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = table.update_entry(&key, |_| panic!("half-updated"));
        }));
        assert!(r.is_err());
        assert!(table.is_poisoned());
    }

    /// A deleted entry leaves an empty slot; a dump passes over it and still gives the
    /// entries after it.
    #[test]
    fn a_dump_skips_the_slot_a_deleted_entry_left() {
        let table = StickTable::new(StickTableConfig { key_type: KeyType::Ip, ..Default::default() });
        let first = StickKey::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let second = StickKey::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        table.update_entry(&first, |e| e.conn_cnt += 1).expect("update");
        table.update_entry(&second, |e| e.conn_cnt += 1).expect("update");
        assert!(table.delete_entry(&first).expect("delete"));
        let (dumped, next) = table.dump_from(0, 10);
        assert_eq!(dumped.iter().map(|(k, _)| k).collect::<Vec<_>>(), [&second]);
        assert!(next.is_none());
    }

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
    fn keys_are_cut_to_len_and_dumped_whole() {
        let table = StickTable::new(StickTableConfig { key_type: KeyType::String, ..Default::default() }).with_key_len(4);
        table.update_entry(&StickKey::String("abcdefgh".into()), |e| e.conn_cnt = 1).unwrap();
        // a multi-byte character that straddles the limit is dropped whole
        table.update_entry(&StickKey::String("abc\u{e9}x".into()), |e| e.conn_cnt = 1).unwrap();
        assert_eq!(table.get_entry(&StickKey::String("abcd".into())).unwrap().map(|e| e.conn_cnt), Some(1));
        assert_eq!(table.get_entry(&StickKey::String("abcdzzz".into())).unwrap().map(|e| e.conn_cnt), Some(1));
        assert!(table.delete_entry(&StickKey::String("abcdq".into())).unwrap());
        let bin = StickTable::new(StickTableConfig { key_type: KeyType::Binary, ..Default::default() }).with_key_len(2);
        bin.update_entry(&StickKey::Binary(vec![1, 2, 3]), |e| e.conn_cnt = 1).unwrap();
        bin.update_entry(&StickKey::Binary(vec![1, 2, 9]), |e| e.conn_cnt += 1).unwrap();
        let dump = bin.dump_entries().unwrap();
        assert_eq!(dump.len(), 1);
        assert_eq!(dump[0].0, StickKey::Binary(vec![1, 2]));
        assert_eq!(dump[0].1.conn_cnt, 2);
    }

    /// T342: a renewed (tracked) entry must not make `purge_expired` loop for ever, and
    /// `expire 0` means no expiry (HAProxy shows `exp=0` and keeps the entry).
    #[test]
    fn purge_terminates_with_tracked_entries() {
        for (n, expire) in [(1, Duration::from_millis(1)), (3, Duration::from_millis(1)), (1, Duration::ZERO), (3, Duration::ZERO)] {
            let config = StickTableConfig { key_type: KeyType::Integer, expire, ..Default::default() };
            let table = std::sync::Arc::new(StickTable::new(config));
            for k in 0..n {
                table.update_entry(&StickKey::Integer(k), |e| e.track(false)).unwrap();
            }
            std::thread::sleep(Duration::from_millis(5));
            let t = table.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(t.purge_expired().unwrap());
            });
            let purged = rx.recv_timeout(Duration::from_secs(2)).expect("purge_expired must terminate");
            assert_eq!(purged, 0);
            assert_eq!(table.len(), n as usize);
        }
    }

    #[test]
    fn expire_zero_never_expires() {
        let config = StickTableConfig { key_type: KeyType::Integer, expire: Duration::ZERO, ..Default::default() };
        let table = StickTable::new(config);
        table.update_entry(&StickKey::Integer(1), |e| e.conn_cnt = 1).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(table.get_entry(&StickKey::Integer(1)).unwrap().is_some());
        assert_eq!(table.dump_entries().unwrap().len(), 1);
        assert_eq!(table.purge_expired().unwrap(), 0);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn purge_keeps_an_expired_entry_a_session_tracks() {
        let config = StickTableConfig { key_type: KeyType::Integer, expire: Duration::from_millis(10), ..Default::default() };
        let table = StickTable::new(config);
        table.update_entry(&StickKey::Integer(1), |e| e.track(false)).unwrap();
        table.update_entry(&StickKey::Integer(2), |e| e.conn_cnt = 1).unwrap();
        std::thread::sleep(Duration::from_millis(25));
        assert_eq!(table.purge_expired().unwrap(), 1);
        assert_eq!(table.len(), 1);
        assert!(table.get_entry(&StickKey::Integer(1)).unwrap().is_some());
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

    /// Counters and tags are written where the table stores them: not elsewhere, nothing is
    /// created by a lookup-only write, and the legacy names reach the array's first elements.
    #[test]
    fn gpc_op_writes_what_the_table_stores() {
        let key = StickKey::Integer(1);
        let flags = TrackFlags { gpc0: true, gpt0: true, ..TrackFlags::default() };
        let legacy = StickTable::new(StickTableConfig {
            key_type: KeyType::Integer,
            flags,
            extra: StickExtra { gpc0_rate_ms: Some(1000), ..StickExtra::default() },
            ..Default::default()
        });
        assert_eq!(legacy.gpc_op(&key, false, Gpc::Zero, GpcOp::Inc), Some(0), "not created by a lookup");
        assert!(legacy.is_empty());
        assert_eq!(legacy.gpc_op(&key, true, Gpc::Zero, GpcOp::Add(5)), Some(5));
        assert_eq!(legacy.gpc_op(&key, true, Gpc::Zero, GpcOp::SetTag(9)), Some(9));
        assert_eq!(legacy.get_entry(&key).unwrap().unwrap().gpt0, 9);
        assert_eq!(legacy.gpc_op(&key, true, Gpc::Zero, GpcOp::Clr), Some(5));
        // gpc1, an array element and a tag one of them is not stored.
        assert_eq!(legacy.gpc_op(&key, true, Gpc::One, GpcOp::Inc), None);
        assert_eq!(legacy.gpc_op(&key, true, Gpc::Idx(0), GpcOp::Inc), None);
        assert_eq!(legacy.gpc_op(&key, true, Gpc::Idx(0), GpcOp::SetTag(1)), None);
        assert_eq!(legacy.gpc_op(&key, true, Gpc::One, GpcOp::SetTag(1)), None);
        let with_gpc1 = StickTable::new(StickTableConfig {
            key_type: KeyType::Integer,
            flags: TrackFlags { gpc1: true, ..TrackFlags::default() },
            ..Default::default()
        });
        assert_eq!(with_gpc1.gpc_op(&key, true, Gpc::One, GpcOp::SetTag(1)), None, "gpc1 is no tag");
        let array = StickTable::new(StickTableConfig {
            key_type: KeyType::Integer,
            flags: TrackFlags::default(),
            extra: StickExtra { gpc_n: 2, gpt_n: 2, gpc_rate_n: 2, gpc_rate_ms: 1000, ..StickExtra::default() },
            ..Default::default()
        });
        assert_eq!(array.gpc_op(&key, true, Gpc::Zero, GpcOp::Inc), Some(1), "gpc0 is element 0");
        assert_eq!(array.gpc_op(&key, true, Gpc::One, GpcOp::Add(3)), Some(3), "gpc1 is element 1");
        assert_eq!(array.gpc_op(&key, true, Gpc::Zero, GpcOp::SetTag(4)), Some(4), "gpt0 is element 0");
        let e = array.get_entry(&key).unwrap().unwrap();
        assert_eq!((e.gpc.clone(), e.gpt.clone()), (vec![1, 3], vec![4, 0]));
        assert_eq!(e.gpc_rate[1].rate(), 3);
        assert_eq!(array.gpc_op(&key, true, Gpc::Idx(2), GpcOp::Inc), None, "past the end");
    }

    /// The conversions measured on `HAProxy` 3.5-dev8-885761-29 (see `tests/stick_key_types.rs`
    /// in `ibex-rt` for the traffic they were measured with).
    #[test]
    fn coerce_key_converts_to_the_type_of_the_table() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let v4 = |a: [u8; 4]| StickKey::Ip(IpAddr::V4(Ipv4Addr::from(a)));
        let s = |t: &str| StickKey::String(t.into());
        // Same type: unchanged.
        assert_eq!(coerce_key(KeyType::Integer, StickKey::Integer(7)), Some(StickKey::Integer(7)));
        // To a string table: an integer is its decimal text, an address its text.
        assert_eq!(coerce_key(KeyType::String, StickKey::Integer(1)), Some(s("1")));
        assert_eq!(coerce_key(KeyType::String, v4([127, 0, 0, 1])), Some(s("127.0.0.1")));
        // To an integer table: a string is its leading number (0 without one); an address has no cast.
        assert_eq!(coerce_key(KeyType::Integer, s("2")), Some(StickKey::Integer(2)));
        assert_eq!(coerce_key(KeyType::Integer, s("abc")), Some(StickKey::Integer(0)));
        assert_eq!(coerce_key(KeyType::Integer, s("12ab")), Some(StickKey::Integer(12)));
        assert_eq!(coerce_key(KeyType::Integer, v4([1, 2, 3, 4])), None);
        // To an ip table: the 32 bits of an integer, a dotted string; not a binary of another length.
        assert_eq!(coerce_key(KeyType::Ip, StickKey::Integer(3)), Some(v4([0, 0, 0, 3])));
        assert_eq!(coerce_key(KeyType::Ip, s("10.0.0.9")), Some(v4([10, 0, 0, 9])));
        assert_eq!(coerce_key(KeyType::Ip, s("nope")), None);
        assert_eq!(coerce_key(KeyType::Ip, StickKey::Binary(vec![1, 2, 3])), None);
        // To an ipv6 table: an IPv4 address is mapped; a dotted string is not an IPv6 address.
        let mapped = StickKey::Ip(IpAddr::V6(Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1])));
        assert_eq!(coerce_key(KeyType::Ipv6, v4([127, 0, 0, 1])), Some(mapped));
        assert_eq!(coerce_key(KeyType::Ipv6, s("10.0.0.11")), None);
        assert!(coerce_key(KeyType::Ipv6, s("2001:db8::1")).is_some());
        // An IPv4-mapped IPv6 address is an IPv4 key for an `ip` table; another is not.
        let mapped_v6 = |last: [u8; 4]| {
            StickKey::Ip(IpAddr::V6(Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, last[0], last[1], last[2], last[3]])))
        };
        assert_eq!(coerce_key(KeyType::Ip, mapped_v6([1, 2, 3, 4])), Some(v4([1, 2, 3, 4])));
        assert_eq!(coerce_key(KeyType::Ip, StickKey::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))), None);
        // An integer or 16 raw bytes make an ipv6 key.
        assert_eq!(coerce_key(KeyType::Ipv6, StickKey::Integer(0x0a00_0001)), Some(mapped_v6([10, 0, 0, 1])));
        assert_eq!(
            coerce_key(KeyType::Ipv6, StickKey::Binary(vec![0; 16])),
            Some(StickKey::Ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)))
        );
        assert_eq!(coerce_key(KeyType::Ipv6, StickKey::Binary(vec![0; 4])), None);
        // Binary to a string table is its text.
        assert_eq!(coerce_key(KeyType::String, StickKey::Binary(b"abc".to_vec())), Some(s("abc")));
        assert_eq!(
            coerce_key(KeyType::Binary, StickKey::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))),
            Some(StickKey::Binary(Ipv6Addr::LOCALHOST.octets().to_vec()))
        );
        // To a binary table: text bytes, never the text of an integer; an address's octets.
        assert_eq!(coerce_key(KeyType::Binary, s("4")), Some(StickKey::Binary(vec![b'4'])));
        assert_ne!(coerce_key(KeyType::Binary, StickKey::Integer(7)), Some(StickKey::Binary(vec![b'7'])));
        assert_eq!(coerce_key(KeyType::Binary, v4([1, 2, 3, 4])), Some(StickKey::Binary(vec![1, 2, 3, 4])));
    }
}
