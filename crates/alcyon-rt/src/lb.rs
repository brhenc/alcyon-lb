// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Load balancing algorithms implementation (leastconn, static-rr, URI consistent hashing).

use crate::engine::Proxy;
use crate::check::ServerStatus;
use alcyon_config::{HashPreserveAffinity, HashType, UriHash};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

thread_local! {
    /// The server a redispatch steers this worker's next selection away from (the one a
    /// retry just left), as `(proxy id, server index)`. Per worker and set only around that
    /// selection, so it is not on the `Proxy` the workers share (T160).
    static AVOID: std::cell::Cell<Option<(u32, usize)>> = const { std::cell::Cell::new(None) };
}

#[cfg(debug_assertions)]
thread_local! {
    /// How many times the hash picks (the `balance uri` map and the consistent-hash ring)
    /// took one of their locks on this thread. The request path takes none of them in
    /// steady state (T633); a change of a server's state or weight is what takes them.
    static HASH_PICK_LOCKS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };

    /// How many times the hash picks passed over the proxy's servers comparing each one's
    /// state and weight with what the map or the ring was built from (T633).
    static HASH_PICK_SCANS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(debug_assertions)]
#[must_use]
pub fn hash_pick_locks_on_this_thread() -> u64 {
    HASH_PICK_LOCKS.with(std::cell::Cell::get)
}

#[cfg(debug_assertions)]
#[must_use]
pub fn hash_pick_scans_on_this_thread() -> u64 {
    HASH_PICK_SCANS.with(std::cell::Cell::get)
}

#[cfg(debug_assertions)]
fn count_hash_pick_lock() {
    HASH_PICK_LOCKS.with(|c| c.set(c.get() + 1));
}

#[cfg(not(debug_assertions))]
#[inline]
fn count_hash_pick_lock() {}

#[cfg(debug_assertions)]
fn count_hash_pick_scan() {
    HASH_PICK_SCANS.with(|c| c.set(c.get() + 1));
}

#[cfg(not(debug_assertions))]
#[inline]
fn count_hash_pick_scan() {}

/// Whether the server at `idx` is the one this worker's current selection avoids.
#[inline]
#[must_use]
pub fn avoided(proxy: &Proxy, idx: usize) -> bool {
    AVOID.with(|a| a.get() == Some((proxy.id, idx)))
}

/// Runs `select` while the server `avoid` of `proxy` is not eligible (`None`: every
/// server is).
pub fn with_avoided<T>(proxy: &Proxy, avoid: Option<usize>, select: impl FnOnce() -> T) -> T {
    AVOID.with(|a| a.set(avoid.map(|i| (proxy.id, i))));
    let t = select();
    AVOID.with(|a| a.set(None));
    t
}

/// Forgets the server a selection avoided, after a panic cut [`with_avoided`] short (T447).
pub(crate) fn clear_avoided() {
    AVOID.with(|a| a.set(None));
}

/// Whether a lock of the balancing state of a backend was poisoned: a panic unwound
/// through a change of it (T447).
pub(crate) fn lb_poisoned(fwrr: &Fwrr, chash: &ChashRing) -> bool {
    fwrr.0.is_poisoned() || chash.0.is_poisoned()
}

/// Determines whether a server at `idx` in `proxy` is eligible to receive traffic.
#[inline]
#[must_use]
pub fn is_server_available(proxy: &Proxy, idx: usize) -> bool {
    // The server a retry has just left, while a redispatch looks for another one.
    if idx >= proxy.srv_set().len() || avoided(proxy, idx) {
        return false;
    }
    if let Some(status) = proxy.srv_set().status_cell(idx) {
        if status.load(Ordering::Relaxed) != ServerStatus::Up as u8 {
            return false;
        }
    } else {
        return false;
    }
    if let Some(mc) = proxy.srv_set().maxconn_at(idx) {
        if mc > 0 {
            let act = proxy.srv_set().actconn_at(idx);
            if act >= mc {
                return false;
            }
        }
    }
    true
}

/// [`is_server_available`] and a weight above zero: the balancing algorithms never pick a
/// server whose weight is 0 (`set server ... weight 0`, `weight 0` on the line), as in
/// HAProxy, where it takes only what persistence or `use-server` sends it.
#[inline]
#[must_use]
fn is_selectable(proxy: &Proxy, idx: usize) -> bool {
    is_server_available(proxy, idx) && proxy.srv_set().weight_at(idx).unwrap_or(1) > 0
}

/// Determines whether a server at `idx` is UP, ignoring its connection load. Used to build
/// the hash ring's candidate set: a consistent hash ring includes every UP server regardless
/// of `maxconn`, and only `hash-preserve-affinity` decides whether a saturated server is
/// skipped afterwards.
#[inline]
fn is_server_up(proxy: &Proxy, idx: usize) -> bool {
    proxy.srv_set().status_at(idx) == Some(ServerStatus::Up as u8)
}

/// Whether some server is UP, not avoided and taking balanced traffic, but at its `maxconn`.
#[must_use]
pub fn any_full(proxy: &Proxy) -> bool {
    (0..proxy.srv_set().len()).any(|idx| {
        is_server_up(proxy, idx)
            && !avoided(proxy, idx)
            && proxy.srv_set().weight_at(idx).unwrap_or(1) > 0
            && proxy.srv_set().maxconn_at(idx).is_some_and(|mc| {
                mc > 0 && proxy.srv_set().actconn_at(idx) >= mc
            })
    })
}

/// The backup that takes the traffic when no active server is usable: the first one in
/// declaration order that is UP and under its `maxconn` (`lbprm.fbck`, set by
/// `recount_servers`; Alcyon refuses `option allbackups`, which would use them all).
#[must_use]
pub fn first_backup(proxy: &Proxy) -> Option<usize> {
    (0..proxy.srv_set().len()).find(|&idx| proxy.srv_set().backup_at(idx) && is_selectable(proxy, idx))
}

/// `balance roundrobin`: HAProxy's fast weighted round-robin (`fwrr_get_next_server`,
/// `src/lb_fwrr.c`), for one thread group. Each server owns positions in a window of
/// `sum(weights)` slots (`npos`), the servers wait in the `curr` tree sorted by position,
/// or in the `next`/`init` trees sorted by weight, and a window ends when `curr` is empty.
/// The order is not the nginx smooth round-robin's, so it is a port, not a look-alike.
///
/// The state is shared by the workers, as the thread group's is in `HAProxy`, and is built
/// from the servers' weights on first use. When the weight or state of one server that
/// takes balanced traffic changes (down, up, `set server ... weight`) only that server is
/// moved, as `HAProxy` does (`fwrr_update_server_weight`, `fwrr_set_server_status_up` and
/// `_down`), and the window goes on.
///
/// Per request it costs one uncontended mutex, one compare of a generation (bumped by
/// [`Fwrr::changed`] where a weight or status is written; the trees are synced only then,
/// `O(servers)` once per change) and, in `HAProxy`'s own terms,
/// a handful of `eb32` operations, here pops and inserts on small sorted vectors whose
/// capacity is reserved at the rebuild: no allocation either.
#[derive(Debug, Default)]
pub struct Fwrr(std::sync::Mutex<Option<Box<FwrrState>>>, std::sync::atomic::AtomicU32);

impl Fwrr {
    /// A server's weight or state changed: the next pick moves it in the trees
    /// ([`round_robin`] compares this generation, not every server, per pick).
    pub fn changed(&self) {
        self.1.fetch_add(1, Ordering::Release);
    }
}

/// One server's place in the window (`struct srv_per_tgroup`).
#[derive(Debug, Clone, Copy, Default)]
struct FwrrSlot {
    npos: u32,
    /// The position it was last served at (`lpos`), where a weight change goes on from.
    lpos: u32,
    rweight: u32,
    /// The tree its node is in (`lb_tree`).
    tree: FwrrTree,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum FwrrTree {
    #[default]
    None,
    Init,
    Curr,
    Next,
}

#[derive(Debug, Default)]
struct FwrrState {
    /// Effective weight each server was built with: weight * 16, 0 when it takes no
    /// balanced traffic (backup, not UP, weight 0).
    built_from: Vec<u32>,
    slots: Vec<FwrrSlot>,
    /// The three trees, as `(key, server)` sorted by decreasing key so that the first
    /// node of an `eb32` tree is the last of the vector; a node inserted with an existing
    /// key goes after the ones that have it, as in `eb32_insert`.
    curr: Vec<(u32, usize)>,
    init: Vec<(u32, usize)>,
    next: Vec<(u32, usize)>,
    /// Servers taken out of the trees for being unavailable, put back after the pick.
    full: Vec<usize>,
    curr_pos: u32,
    curr_weight: u32,
    next_weight: u32,
    /// The [`Fwrr::changed`] generation the trees were synced at.
    generation: u32,
}

/// `BE_WEIGHT_SCALE`, and `SRV_EWGHT_MAX` (`SRV_UWGHT_MAX` * `BE_WEIGHT_SCALE`).
const FWRR_EWGHT_MAX: u32 = 256 * BE_WEIGHT_SCALE;

fn tree_insert(tree: &mut Vec<(u32, usize)>, key: u32, idx: usize) {
    let at = tree.partition_point(|n| n.0 > key);
    tree.insert(at, (key, idx));
}

impl FwrrState {
    /// The weight server `idx` counts for in the window.
    fn eweight(proxy: &Proxy, idx: usize) -> u32 {
        let backup = proxy.srv_set().backup_at(idx);
        let up = proxy.srv_set().status_cell(idx).is_some_and(|s| s.load(Ordering::Relaxed) == ServerStatus::Up as u8);
        let w = proxy.srv_set().weight_at(idx).unwrap_or(1).min(256);
        if backup || !up { 0 } else { w * BE_WEIGHT_SCALE }
    }

    /// Rebuild when a server's effective weight is not the one the trees were built with
    /// (`fwrr_init_server_groups`: every usable server in `init`, in declaration order).
    fn sync(&mut self, proxy: &Proxy) {
        alcyon_sample::work::note(alcyon_sample::work::Op::LbSync, 1);
        let n = proxy.srv_set().len();
        if self.built_from.len() != n {
            self.rebuild((0..n).map(|i| Self::eweight(proxy, i)));
            return;
        }
        // A server whose weight or state changed is moved where `HAProxy` moves it, and the
        // window goes on (`fwrr_update_server_weight`, `fwrr_set_server_status_up/down`).
        for i in 0..n {
            let new = Self::eweight(proxy, i);
            let old = self.built_from[i];
            match (old > 0, new > 0) {
                (false, false) => self.built_from[i] = new,
                (false, true) => self.status_up(i, new),
                (true, false) => self.status_down(i),
                (true, true) if old != new => self.weight_change(i, new),
                (true, true) => {}
            }
        }
    }

    /// Takes the server's node out of whichever tree it is in.
    fn dequeue(&mut self, s: usize) {
        for tree in [&mut self.curr, &mut self.init, &mut self.next] {
            tree.retain(|n| n.1 != s);
        }
    }

    /// `fwrr_set_server_status_down`.
    fn status_down(&mut self, s: usize) {
        self.dequeue(s);
        self.slots[s].tree = FwrrTree::None;
        self.next_weight -= self.built_from[s];
        self.built_from[s] = 0;
    }

    /// `fwrr_set_server_status_up`, for a server whose weight is now `ew`.
    fn status_up(&mut self, s: usize, ew: u32) {
        self.next_weight += ew;
        self.built_from[s] = ew;
        self.get_srv(s);
        self.slots[s].npos = self.curr_pos.wrapping_add(self.next_weight.wrapping_add(self.curr_weight).wrapping_sub(self.curr_pos) / ew);
        self.queue(s);
    }

    /// `fwrr_update_server_weight` for a server that stays usable with the weight `ew`.
    ///
    /// `HAProxy` tests `srv->lb_tree`, a field `fwrr` no longer sets (the trees are per thread
    /// group now), so the branch for a server that is in no tree is the one every weight
    /// change takes, whatever tree the server is in: it is taken out, prepared for the tree
    /// it was in (`fwrr_get_srv`), and given a position from the new total
    /// (measured: thirty sequences with weight changes at every point of the window all
    /// follow this and none the branches written for a server in `init`, `curr` or `next`).
    fn weight_change(&mut self, s: usize, ew: u32) {
        let old = self.built_from[s];
        self.next_weight = self.next_weight - old + ew;
        self.built_from[s] = ew;
        self.dequeue(s);
        self.get_srv(s);
        self.slots[s].npos = self.curr_pos.wrapping_add(self.next_weight.wrapping_add(self.curr_weight).wrapping_sub(self.curr_pos) / ew);
        self.queue(s);
    }

    /// `fwrr_queue_by_weight` into `init`.
    fn queue_by_weight_init(&mut self, s: usize) {
        tree_insert(&mut self.init, FWRR_EWGHT_MAX - self.built_from[s], s);
        self.slots[s].tree = FwrrTree::Init;
    }

    /// `fwrr_get_srv`: prepares a server taken out of its tree.
    fn get_srv(&mut self, s: usize) {
        let slot = &mut self.slots[s];
        match slot.tree {
            FwrrTree::Init => {
                slot.npos = 0;
                slot.rweight = 0;
            }
            FwrrTree::Next => slot.npos = slot.npos.wrapping_add(self.curr_weight),
            FwrrTree::None => slot.npos = self.curr_pos,
            FwrrTree::Curr => {}
        }
    }

    /// `fwrr_init_server_groups` for these effective weights.
    fn rebuild(&mut self, eweights: impl Iterator<Item = u32>) {
        self.built_from.clear();
        self.built_from.extend(eweights);
        let n = self.built_from.len();
        self.slots.clear();
        self.slots.resize(n, FwrrSlot::default());
        for tree in [&mut self.curr, &mut self.init, &mut self.next] {
            tree.clear();
            tree.reserve(n);
        }
        self.full.clear();
        self.full.reserve(n);
        self.next_weight = self.built_from.iter().sum();
        self.curr_pos = self.next_weight;
        self.curr_weight = self.next_weight;
        for i in 0..n {
            if self.built_from[i] > 0 {
                self.queue_by_weight_init(i);
            }
        }
    }

    /// `fwrr_get_server_from_group`: the first server of `curr` if its position has come,
    /// else the first of `init`, else (a hole in the window, nothing new) the one of `curr`.
    fn get_from_group(&mut self) -> Option<usize> {
        if let Some(&(_, s1)) = self.curr.last() {
            if self.slots[s1].npos <= self.curr_pos {
                self.curr.pop();
                return Some(s1);
            }
        }
        if let Some((_, s2)) = self.init.pop() {
            self.slots[s2] = FwrrSlot::default();
            return Some(s2);
        }
        self.curr.pop().map(|(_, s1)| s1)
    }

    /// `fwrr_update_position`.
    fn update_position(&mut self, s: usize) {
        let ew = self.built_from[s];
        let slot = &mut self.slots[s];
        if slot.npos == 0 {
            slot.npos = self.curr_pos;
        }
        slot.lpos = slot.npos;
        slot.npos = slot.npos.wrapping_add(self.next_weight / ew);
        slot.rweight += self.next_weight % ew;
        if slot.rweight >= ew {
            slot.rweight -= ew;
            slot.npos = slot.npos.wrapping_add(1);
        }
    }

    /// `fwrr_queue_srv`: back into the window, or into the next one.
    fn queue(&mut self, s: usize) {
        let ew = self.built_from[s];
        let slot = &mut self.slots[s];
        if slot.npos >= self.curr_weight.wrapping_mul(2) || slot.npos >= self.curr_weight.wrapping_add(self.next_weight) {
            slot.npos = slot.npos.wrapping_sub(self.curr_weight);
            slot.tree = FwrrTree::Next;
            tree_insert(&mut self.next, FWRR_EWGHT_MAX - ew, s);
        } else {
            slot.tree = FwrrTree::Curr;
            let key = 256u32
                .wrapping_mul(slot.npos)
                .wrapping_add(FWRR_EWGHT_MAX.wrapping_add(slot.rweight).wrapping_sub(ew) / BE_WEIGHT_SCALE);
            tree_insert(&mut self.curr, key, s);
        }
    }

    /// `fwrr_get_next_server` for the active servers: the next one for which `usable` holds.
    /// The others are taken out, then queued back as if they had been served, so that they
    /// keep their place (or, if the window ended meanwhile, by weight).
    fn pick(&mut self, usable: impl Fn(usize) -> bool) -> Option<usize> {
        let mut switched = false;
        self.full.clear();
        let chosen = loop {
            let s = loop {
                if let Some(s) = self.get_from_group() {
                    break Some(s);
                }
                if switched {
                    break None;
                }
                switched = true;
                std::mem::swap(&mut self.init, &mut self.next);
                for k in 0..self.init.len() {
                    self.slots[self.init[k].1].tree = FwrrTree::Init;
                }
                self.curr_weight = self.next_weight;
                self.curr_pos = self.curr_weight;
            };
            let Some(s) = s else { break None };
            self.update_position(s);
            self.curr_pos = self.curr_pos.wrapping_add(1);
            if usable(s) {
                break Some(s);
            }
            self.full.push(s);
        };
        if let Some(s) = chosen {
            self.queue(s);
        }
        while let Some(f) = self.full.pop() {
            if switched {
                self.queue_by_weight_init(f);
            } else {
                self.queue(f);
            }
        }
        chosen
    }
}

/// The server `balance roundrobin` picks: the next of the active ones in the weighted
/// order, else the first usable backup alone.
#[must_use]
pub fn round_robin(proxy: &Proxy) -> Option<usize> {
    let mut guard = proxy.fwrr.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    // Built on first use: a configuration of tens of thousands of backends pays for the
    // ones that balance only.
    let st = guard.get_or_insert_with(Box::default);
    let generation = proxy.fwrr.1.load(Ordering::Acquire);
    if st.generation != generation || st.built_from.len() != proxy.srv_set().len() {
        st.generation = generation;
        st.sync(proxy);
    }
    st.pick(|i| is_server_available(proxy, i)).or_else(|| first_backup(proxy))
}

/// First Available Server (`balance first`).
/// Picks the first server, in declaration order, that is UP and has a free `maxconn` slot.
/// Falls back to backup servers, in declaration order, if no primary server qualifies.
#[must_use]
pub fn first(proxy: &Proxy) -> Option<usize> {
    for idx in 0..proxy.srv_set().len() {
        let is_backup = proxy.srv_set().backup_at(idx);
        if !is_backup && is_selectable(proxy, idx) {
            return Some(idx);
        }
    }
    first_backup(proxy)
}

/// Fast, non-cryptographic PRNG state for `balance random`. Seeded once from process-local
/// entropy (time + a stack address) and then advanced with xorshift64*; this avoids a syscall
/// on every request the way a `getrandom()` call per draw would, matching HAProxy's own
/// `statistical_prng()`, which is also a reseeded xorshift generator, not a syscall.
static RANDOM_STATE: AtomicU64 = AtomicU64::new(0);

fn initial_seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let addr = std::ptr::addr_of!(RANDOM_STATE) as u64;
    // Odd, so never the zero state xorshift cannot leave.
    (nanos ^ addr.rotate_left(17) ^ 0x9E37_79B9_7F4A_7C15) | 1
}

pub(crate) fn next_random_u64() -> u64 {
    let mut new_state = 0u64;
    // Racing initializers on the very first call converge on some non-zero state either
    // way; correctness of the load balancer does not depend on which writer wins.
    let _ = RANDOM_STATE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| {
        let mut x = if x == 0 { initial_seed() } else { x };
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        new_state = x;
        Some(x)
    });
    new_state
}

/// The usable active servers and their weights (at least 1), in declaration order: what
/// `random` and `static-rr` draw from. Walked in place on each pick, never collected: a
/// pick allocates nothing.
fn usable_primaries(proxy: &Proxy) -> impl Iterator<Item = (usize, u32)> + '_ {
    (0..proxy.srv_set().len())
        .filter(|&idx| !proxy.srv_set().backup_at(idx) && is_selectable(proxy, idx))
        .map(|idx| (idx, proxy.srv_set().weight_at(idx).unwrap_or(1).max(1)))
}

/// The server holding position `pos` when the usable active servers are laid end to end,
/// each as wide as its weight. A server can leave between the pass that summed the weights
/// and this one; the position then falls past the end and the last usable server takes it.
fn primary_at(proxy: &Proxy, pos: u32) -> Option<usize> {
    let mut acc = 0u32;
    let mut at = None;
    for (idx, w) in usable_primaries(proxy) {
        acc = acc.saturating_add(w);
        at = Some(idx);
        if pos < acc {
            break;
        }
    }
    at
}

/// Random draw over the weighted server set (`balance random`, `balance random(N)`).
/// Draws `draws` candidates weighted by server weight and keeps the least loaded one
/// (lowest `actconn / weight`), matching HAProxy's `get_server_rnd`. A server at `maxconn`
/// is not a candidate, so the queue is never picked for a request it cannot serve.
#[must_use]
pub fn random(proxy: &Proxy, draws: u32) -> Option<usize> {
    let total_weight = usable_primaries(proxy).fold(0u32, |t, (_, w)| t.saturating_add(w));
    if total_weight == 0 {
        // No active server: the first usable backup alone (`lbprm.fbck`; Alcyon has no
        // `option allbackups`). `HAProxy` 3.5 sent 30 of 30 requests to it under `random`.
        return first_backup(proxy);
    }
    let draw_one = || primary_at(proxy, (next_random_u64() % u64::from(total_weight)) as u32);

    let mut best = draw_one()?;
    for _ in 1..draws.max(1) {
        let candidate = draw_one().unwrap_or(best);
        if candidate == best {
            continue;
        }
        let best_weight = u64::from(proxy.srv_set().weight_at(best).unwrap_or(1).max(1));
        let cand_weight = u64::from(proxy.srv_set().weight_at(candidate).unwrap_or(1).max(1));
        let best_load = u64::from(proxy.srv_set().actconn_at(best));
        let cand_load = u64::from(proxy.srv_set().actconn_at(candidate));
        // Cross-multiplied comparison of (load / weight): keep whichever is less loaded
        // relative to its own capacity.
        if cand_load.saturating_mul(best_weight) > best_load.saturating_mul(cand_weight) {
            // candidate is more loaded than best -- keep best.
        } else {
            best = candidate;
        }
    }
    Some(best)
}

/// Weighted Least Connections (`balance leastconn`).
/// Selects the server with the lowest connection load relative to its configured weight.
/// Conforms to HAProxy's `fwlc` algorithm (comparing `(actconn + 1) / weight`).
#[must_use]
pub fn leastconn(proxy: &Proxy) -> Option<usize> {
    let mut best_idx = None;
    let mut best_load_metric = (u64::MAX, 1u64); // (load * other_weight, weight)

    // First pass: try primary (non-backup) servers
    for idx in 0..proxy.srv_set().len() {
        let is_backup = proxy.srv_set().backup_at(idx);
        if !is_backup && is_selectable(proxy, idx) {
            let conn = u64::from(proxy.srv_set().actconn_at(idx));
            let weight = u64::from(proxy.srv_set().weight_at(idx).unwrap_or(1).max(1));

            // Load metric comparison: (conn + 1) / weight vs (best_conn + 1) / best_weight
            // Cross-multiplied: (conn + 1) * best_weight vs (best_conn + 1) * weight
            if best_idx.is_none() {
                best_idx = Some(idx);
                best_load_metric = (conn.saturating_add(1), weight);
            } else {
                let (best_conn_plus_1, best_w) = best_load_metric;
                let lhs = conn.saturating_add(1).saturating_mul(best_w);
                let rhs = best_conn_plus_1.saturating_mul(weight);

                if lhs < rhs || (lhs == rhs && weight > best_w) {
                    best_idx = Some(idx);
                    best_load_metric = (conn.saturating_add(1), weight);
                }
            }
        }
    }

    if best_idx.is_some() {
        return best_idx;
    }

    // No active server: the first usable backup alone.
    first_backup(proxy)
}

/// Weighted Round Robin with static weights (`balance static-rr`).
/// Produces an interleaved distribution matching HAProxy map-based round-robin.
#[must_use]
pub fn static_rr(proxy: &Proxy) -> Option<usize> {
    let total_weight = usable_primaries(proxy).fold(0u32, |t, (_, w)| t.saturating_add(w));
    if total_weight == 0 {
        // Backup failover: the first usable backup alone.
        return first_backup(proxy);
    }
    let counter = proxy.next_server_idx.fetch_add(1, Ordering::Relaxed);
    primary_at(proxy, (counter % (total_weight as usize)) as u32)
}

/// Deterministic URI Hash (`balance uri`), `map-based` as HAProxy defaults it.
///
/// HAProxy's `get_server_uh` (`src/backend.c`) hashes the URI with `sdbm` -- the default
/// hash function, and no avalanche unless `hash-type` asks for one -- over the slice
/// its options select, by default the part before the `?` ([`uri_hash_parts`]), and `map_get_server_hash` takes that modulo the
/// backend's `tot_weight` into the interleaved weighted map ([`WeightMap`]). Both the hash
/// and the map matter: hashing the query string, or laying the weights out in contiguous
/// blocks, sends the same URI to another server than HAProxy does.
///
/// For HTTP/2 and HTTP/3 requests whose `:authority` was present, `req_uri` keeps `:path`
/// while `H2Child::req_abs` holds `scheme://authority`; [`balance_uri_with_abs`] hashes the
/// two parts sequentially without joining unless `path-only` is set (`OPTIONS *` with
/// `req_abs` hashes `req_abs` alone without `*`).
#[must_use]
pub fn balance_uri(proxy: &Proxy, uri: &str, cache: &mut LbSnapCache) -> Option<usize> {
    balance_uri_with_abs(proxy, uri, None, cache)
}

/// [`balance_uri`] with an optional `scheme://authority` prefix (`H2Child::req_abs`).
#[must_use]
pub fn balance_uri_with_abs(proxy: &Proxy, uri: &str, abs: Option<&str>, cache: &mut LbSnapCache) -> Option<usize> {
    // `hash-preserve-affinity` only has an effect
    // on a consistent-hash ring (HAProxy gates
    // it the same way: the option is read only from `chash_get_server_hash`).
    if proxy.hash_type == HashType::Consistent {
        return balance_uri_consistent(proxy, uri, abs, cache);
    }
    let hash = hash_uri(uri, abs, proxy.chash.2);
    if let Some(idx) = proxy.chash.map_pick(proxy, hash, cache) {
        return Some(idx);
    }

    // Backup failover: the first usable backup alone.
    first_backup(proxy)
}

fn hash_uri(uri: &str, abs: Option<&str>, opts: UriHash) -> u32 {
    let (head, tail) = uri_hash_parts(uri, abs, opts);
    hash_sdbm_step(hash_sdbm_step(0, head), tail)
}

/// The slices of `uri` (and `abs`, when `Some`) that `balance uri` hashes, as `get_server_uh`
/// (`src/backend.c`) and its caller cut them: with `path-only` the scheme and authority are
/// dropped first; `len` keeps the first bytes across the remaining parts; then the walk
/// stops before the `?` unless `whole` is set, and before the slash that ends `depth`
/// directories (that slash is the `depth + 1`-th, which is what `depth_end` holds). `OPTIONS *`
/// with `abs` has an empty path (`""`, not `*`).
fn uri_hash_parts<'a>(uri: &'a str, abs: Option<&'a str>, opts: UriHash) -> (&'a [u8], &'a [u8]) {
    let (mut head, mut tail) = match abs.filter(|a| !a.is_empty()) {
        Some(_) if opts.path_only => (uri_path(uri.as_bytes()), &[][..]),
        Some(abs) => (abs.as_bytes(), if uri == "*" { &[][..] } else { uri.as_bytes() }),
        None => (if opts.path_only { uri_path(uri.as_bytes()) } else { uri.as_bytes() }, &[][..]),
    };
    if opts.len > 0 {
        let cap = opts.len as usize;
        head = &head[..head.len().min(cap)];
        tail = &tail[..tail.len().min(cap - head.len())];
    }
    let mut slashes = 0i32;
    let mut cut = |bytes: &'a [u8]| -> Option<usize> {
        bytes.iter().position(|&c| {
            if c == b'/' {
                slashes += 1;
                slashes == opts.depth_end
            } else {
                c == b'?' && !opts.whole
            }
        })
    };
    if let Some(end) = cut(head) {
        return (&head[..end], &[]);
    }
    match cut(tail) {
        Some(end) => (head, &tail[..end]),
        None => (head, tail),
    }
}

/// `http_parse_path` (`src/http.c`) for `path-only`: an absolute path as it is, what
/// follows the authority of an absolute URI, and nothing for `*` or an authority alone.
fn uri_path(uri: &[u8]) -> &[u8] {
    if uri.first() == Some(&b'/') {
        return uri;
    }
    let Some(scheme_end) = uri.windows(3).position(|w| w == b"://") else {
        return &[];
    };
    let rest = &uri[scheme_end + 3..];
    rest.iter().position(|&c| c == b'/').map_or(&[], |at| &rest[at..])
}

/// HAProxy's weighted server map (`recalc_server_map` with `init_server_map`,
/// `src/lb_map.c`) over the usable primary servers: `tot_weight` slots, the sum of the
/// usable servers' reduced weights, and a hash picks slot `hash % tot_weight`.
///
/// Each server holds `next_eweight` slots -- its user weight divided by the greatest
/// common divisor of every configured weight, rounded up -- handed out one at a time to
/// whoever leads on the weighted counter `wscore`. That is what spreads a heavy server
/// over the whole range instead of in one block, and it keeps the declaration order on
/// ties, so the first declared server holds slot 0. A server a health check takes out
/// holds no slot at all: the map is rebuilt over the rest and every hash re-lands
/// somewhere else, which is what HAProxy does too.
///
/// It is built when the usable servers or their weights change, not per request
/// ([`ChashRing::map_pick`]), and rebuilt into the buffers of the previous build, so a
/// rebuild allocates only when the map grows.
#[derive(Debug, Default)]
struct WeightMap {
    /// Per server, the user weight it was built with, 0 when it held no slot (a backup,
    /// unusable, or weight 0). A request compares the servers against this, and nothing else.
    built_from: Vec<u32>,
    /// `tot_weight` slots, each a server index.
    slots: Vec<u32>,
    /// `wscore` per server, kept only to reuse its buffer.
    score: Vec<i64>,
}

impl WeightMap {
    fn rebuild(&mut self, proxy: &Proxy, in_map: impl Fn(usize) -> u32) {
        let n = proxy.srv_set().len();
        self.built_from.clear();
        self.built_from.extend((0..n).map(&in_map));
        let gcd = weight_gcd(proxy);
        // HAProxy's `(uweight * wdiv + wmult - 1) / wmult`, `wdiv` being 1 for the map.
        let eweight = |w: u32| -> u32 { if w == 0 { 0 } else { w.saturating_add(gcd - 1) / gcd } };
        let tot_weight: u32 = self.built_from.iter().map(|&w| eweight(w)).fold(0, u32::saturating_add);
        self.slots.clear();
        self.score.clear();
        self.score.resize(n, 0);
        let tot = i64::from(tot_weight);
        for _ in 0..tot_weight {
            let mut best = 0usize;
            let mut max = i64::MIN;
            for (idx, &w) in self.built_from.iter().enumerate() {
                let w = eweight(w);
                if w == 0 {
                    continue;
                }
                self.score[idx] += i64::from(w);
                // `(wscore + tot) / tot`, the integer lead HAProxy compares.
                let v = (self.score[idx] + tot) / tot;
                if v > max {
                    max = v;
                    best = idx;
                }
            }
            self.score[best] -= tot;
            self.slots.push(u32::try_from(best).unwrap_or(u32::MAX));
        }
    }

    fn pick(&self, hash: u32) -> Option<usize> {
        let len = u32::try_from(self.slots.len()).ok().filter(|&l| l > 0)?;
        self.slots.get((hash % len) as usize).map(|&i| i as usize)
    }
}

/// The greatest common divisor of every configured server weight -- `init_server_map`'s
/// `wmult`, taken over all servers including backups and checked-down ones because it is
/// computed from the user weights once at config time. Zero-weight servers are skipped,
/// as HAProxy skips them looking for the first non-zero one.
fn weight_gcd(proxy: &Proxy) -> u32 {
    let mut g = 0u32;
    for idx in 0..proxy.srv_set().len() {
        let w = proxy.srv_set().weight_at(idx).unwrap_or(0);
        if w == 0 {
            continue;
        }
        g = if g == 0 { w } else { gcd2(g, w) };
    }
    g.max(1)
}

/// Euclid's algorithm, as `init_server_map` runs it in place.
fn gcd2(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

/// `balance uri` with `hash-type consistent` (`get_server_uh` + `chash_get_server_hash`,
/// `src/backend.c` and `src/lb_chash.c`).
///
/// The key is `sdbm` of the same slice of the URI ([`uri_hash_key`]), avalanched by `full_hash` -- `hash-type
/// consistent` alone means `sdbm avalanche` (`cfgparse-listen.c`) -- and the server is the one owning the
/// ring point nearest to it. A server at `maxconn` is passed over for the next point
/// round the ring: that is `hash-preserve-affinity maxconn`. `HAProxy`'s default, `always`,
/// would instead queue the request on the full server; Alcyon has no server queue and never
/// sends a server more than its `maxconn`, so `always` walks the same way once the server
/// is full. `None` when no server is up, or every candidate is full.
fn balance_uri_consistent(proxy: &Proxy, uri: &str, abs: Option<&str>, cache: &mut LbSnapCache) -> Option<usize> {
    consistent_pick(proxy, |_| full_hash(hash_uri(uri, abs, proxy.chash.2)), cache)
}

/// Source IP hash (`balance source`), `map-based` as `HAProxy` defaults it (`get_server_sh`
/// and `map_get_server_hash`, `src/backend.c` and `src/lb_map.c`), or `hash-type consistent`
/// ([`balance_source_consistent`]).
///
/// The key is the XOR of the address' 32-bit big-endian words (`ntohl`, no avalanche in
/// `map-based` mode), and `map_get_server_hash` indexes the interleaved [`WeightMap`]
/// modulo `tot_weight`.
#[must_use]
pub fn balance_source(proxy: &Proxy, ip: std::net::IpAddr, cache: &mut LbSnapCache) -> Option<usize> {
    if proxy.hash_type == HashType::Consistent {
        return balance_source_consistent(proxy, ip, cache);
    }
    let hash = source_hash_key(ip);
    if let Some(idx) = proxy.chash.map_pick(proxy, hash, cache) {
        return Some(idx);
    }

    // Backup failover: the first usable backup alone.
    first_backup(proxy)
}

fn source_hash_key(ip: std::net::IpAddr) -> u32 {
    match ip {
        std::net::IpAddr::V4(a) => u32::from(a),
        std::net::IpAddr::V6(a) => {
            a.octets().as_chunks::<4>().0.iter().fold(0, |h, &c| h ^ u32::from_be_bytes(c))
        }
    }
}

/// `balance source` with `hash-type consistent` (`get_server_sh`, `src/backend.c`): the
/// key is the XOR of the address' 32-bit words (host order), avalanched by `full_hash`,
/// and 0 when only one server is left to choose from, then the ring as for `balance uri`.
#[must_use]
pub fn balance_source_consistent(proxy: &Proxy, ip: std::net::IpAddr, cache: &mut LbSnapCache) -> Option<usize> {
    let key = source_hash_key(ip);
    consistent_pick(proxy, |servers_in_ring| if servers_in_ring <= 1 { 0 } else { full_hash(key) }, cache)
}

/// The server owning the ring point nearest to the key `hash(n)`, `n` being how many
/// servers the ring holds (`tot_used`), through the worker's snapshot ([`LbSnapCache`]).
fn consistent_pick(proxy: &Proxy, hash: impl FnOnce(usize) -> u32, cache: &mut LbSnapCache) -> Option<usize> {
    let ring = &proxy.chash.sync(proxy, cache).ring;
    let points = match &ring.members {
        RingMembers::Active => &ring.points,
        RingMembers::FirstBackup(idx) => {
            return is_server_available(proxy, *idx).then_some(*idx);
        }
        RingMembers::None => return None,
    };

    // The point at or after the key, or the first one past the end of the ring; then
    // whichever of it and the point before is closer, the earlier one on a tie.
    let hash = hash(ring.servers);
    let next = points.partition_point(|&(k, _)| k < hash) % points.len();
    let prev = (next + points.len() - 1) % points.len();
    let dp = hash.wrapping_sub(points[prev].0);
    let dn = points[next].0.wrapping_sub(hash);
    let start = if dp <= dn { prev } else { next };

    match proxy.hash_preserve_affinity {
        HashPreserveAffinity::MaxConn | HashPreserveAffinity::Always => (0..points.len())
            .map(|step| points[(start + step) % points.len()].1 as usize)
            .find(|&idx| is_server_available(proxy, idx)),
    }
}

/// `hash_sdbm` (`src/hash.c`), `HAProxy`'s default hash function for `balance uri`.
/// `hash_sdbm` (`src/hash.c`), `HAProxy`'s default hash function for `balance uri`, folded
/// from `init` so two slices hash identically to their concatenation.
fn hash_sdbm_step(init: u32, bytes: &[u8]) -> u32 {
    bytes.iter().fold(init, |h, &c| {
        u32::from(c).wrapping_add(h << 6).wrapping_add(h << 16).wrapping_sub(h)
    })
}

/// `full_hash` (`include/haproxy/intops.h`): Bob Jenkins' integer avalanche, spread by a
/// large prime. It places the ring's points.
fn full_hash(mut a: u32) -> u32 {
    a = a.wrapping_add(0x7ed5_5d16).wrapping_add(a << 12);
    a = (a ^ 0xc761_c23c) ^ (a >> 19);
    a = a.wrapping_add(0x1656_67b1).wrapping_add(a << 5);
    a = a.wrapping_add(0xd3a2_646c) ^ (a << 9);
    a = a.wrapping_add(0xfd70_46c5).wrapping_add(a << 3);
    a = (a ^ 0xb55a_4f09) ^ (a >> 16);
    a.wrapping_mul(3_221_225_473)
}

/// Points per unit of weight (`BE_WEIGHT_SCALE`), and the spacing of each server's point
/// keys (`SRV_EWGHT_RANGE` = 256 * 16).
const BE_WEIGHT_SCALE: u32 = 16;
const SRV_EWGHT_RANGE: u32 = 256 * BE_WEIGHT_SCALE;

/// Who the ring serves, as `chash_get_server_hash` decides it.
#[derive(Debug, Default)]
enum RingMembers {
    /// The active servers that are up, placed on the ring.
    Active,
    /// None is up: the first backup that is (`lbprm.fbck`; Alcyon has no `option
    /// allbackups`, which would put every backup on a ring of their own).
    FirstBackup(usize),
    #[default]
    None,
}

#[derive(Debug, Default)]
struct Ring {
    /// Which servers this ring was built from, by index; rebuilt when that changes.
    built_from: Vec<bool>,
    members: RingMembers,
    /// `(key, server index)`, sorted by key.
    points: Vec<(u32, u32)>,
    /// How many servers hold points (`tot_used`), counted when the ring is built so that
    /// a request does not count them.
    servers: usize,
}

impl Ring {
    /// (Re)builds, in place, from the servers' states: the up primaries with a weight, each
    /// with `weight * 16` points keyed by its `puid` (T633: called only when a server's
    /// state or weight moves the generation, under the builder's lock). A server's points
    /// depend only on its id and weight, so the rebuilt ring is the one `HAProxy` holds,
    /// and keys move only to and from the server that changed.
    fn rebuild(&mut self, proxy: &Proxy) {
        let in_ring = |idx: usize| {
            !proxy.srv_set().backup_at(idx)
                && is_server_up(proxy, idx)
                && proxy.srv_set().weight_at(idx).unwrap_or(1) > 0
        };
        self.built_from.clear();
        self.built_from.extend((0..proxy.srv_set().len()).map(in_ring));
        self.points.clear();
        self.servers = 0;
        for idx in (0..proxy.srv_set().len()).filter(|&i| self.built_from[i]) {
            // `puid`: the server's id, from 1 in declaration order around the ones
            // with an `id`; `hash-key id` is the default.
            let puid = proxy.server_puid(idx);
            let base = puid.wrapping_mul(SRV_EWGHT_RANGE);
            let nodes = proxy.srv_set().weight_at(idx).unwrap_or(1) * BE_WEIGHT_SCALE;
            let server = u32::try_from(idx).unwrap_or(u32::MAX);
            self.points.extend((0..nodes).map(|j| (full_hash(base.wrapping_add(j)), server)));
            self.servers += usize::from(nodes > 0);
        }
        // Stable, so equal keys keep HAProxy's insertion order.
        self.points.sort_by_key(|&(k, _)| k);
        self.members = if !self.points.is_empty() {
            RingMembers::Active
        } else if let Some(b) = (0..proxy.srv_set().len()).find(|&i| {
            proxy.srv_set().backup_at(i) && is_server_up(proxy, i)
        }) {
            RingMembers::FirstBackup(b)
        } else {
            RingMembers::None
        };
    }
}

/// The immutable snapshot of a proxy's hash-pick state (T633): the weighted map and the
/// consistent-hash ring, both built from one generation of the servers' states and weights.
/// Built once per generation change, read by every worker afterwards, never written.
#[derive(Debug, Default)]
pub struct ChashSnap {
    /// The map of the usable primary servers: the `balance uri`/`balance source` picks.
    pub map: WeightMap,
    /// The ring of the up primary servers: the `hash-type consistent` picks.
    pub ring: Ring,
}

/// What the builder holds while the workers hold the published [`ChashSnap`]s (T633): the
/// snapshot the last build published and the generation it was built from.
#[derive(Debug, Default)]
struct SnapPub {
    snap: Option<Arc<ChashSnap>>,
    generation: u32,
}

/// One worker's view of the snapshots its hash picks are reading (T633): per hash-balanced
/// backend the worker has picked on, the generation it last saw and the `Arc` of the
/// snapshot built from it. The worker writes only its own slots; a pick takes no lock and
/// scans no server while the generation it holds is the current one. One `Arena` slot per
/// backend per worker (`show pools`, pool `lbsnap`).
#[derive(Debug, Default)]
pub struct LbSnapCache {
    slots: Vec<LbSnapSlot>,
    published: alcyon_alloc::arena::Published,
}

/// One [`LbSnapCache`] slot: the proxy's id, the generation the worker's snapshot was built
/// from, and the snapshot.
#[derive(Debug)]
pub struct LbSnapSlot {
    key: u32,
    generation: u32,
    snap: Arc<ChashSnap>,
}

/// Slots of every worker's [`LbSnapCache`], for `show pools` (pool `lbsnap`).
pub static LB_SNAP_POOL: alcyon_alloc::ArenaStats = alcyon_alloc::ArenaStats::new(
    "lbsnap",
    std::mem::size_of::<LbSnapSlot>(),
    std::mem::align_of::<LbSnapSlot>(),
    file!(),
    line!(),
);

/// `show pools` provider for the `lbsnap` pool: the slots ever created, those in use.
#[allow(clippy::unnecessary_wraps)]
pub fn lbsnap_pool_stats() -> Option<alcyon_alloc::PoolHead> {
    Some(LB_SNAP_POOL.head())
}

impl LbSnapCache {
    /// The worker's empty cache: the first pick on a hash-balanced backend makes its slot
    /// (the tests use it; the engine's cache is pre-sized, [`Self::with_hash_proxies`]).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The worker's cache for an engine holding `hash_proxies` hash-balanced proxies: the
    /// slots are reserved at creation, so a pick never grows them.
    #[must_use]
    pub fn with_hash_proxies(hash_proxies: usize) -> Self {
        let mut slots = Vec::new();
        slots.reserve(hash_proxies);
        Self { slots, ..Default::default() }
    }

    /// Publishes the slot counts to `show pools` (once per loop pass, only when moved).
    pub fn publish(&mut self) {
        let mut last = self.published;
        LB_SNAP_POOL.publish_arena::<LbSnapSlot>(&mut last, self);
        self.published = last;
    }
}

impl alcyon_alloc::Arena<LbSnapSlot> for LbSnapCache {
    fn slots(&self) -> usize {
        self.slots.len()
    }

    /// Every slot is in use for the worker's lifetime: nothing to give back.
    fn live(&self) -> usize {
        self.slots.len()
    }

    fn compact(&mut self) -> usize {
        0
    }
}

impl Drop for LbSnapCache {
    fn drop(&mut self) {
        LB_SNAP_POOL.retire(&mut self.published);
    }
}

/// The hash-pick state of one proxy, shared by its workers (the `Proxy` clones).
///
/// `HAProxy` updates its map or tree only where a server changes state (`lb_map.c`,
/// `lb_chash.c`): here the map and the ring are immutable once built ([`ChashSnap`]), the
/// one current snapshot sits behind one mutex taken only when the generation has moved,
/// and each worker keeps its own `Arc` of it in its [`LbSnapCache`] (design 2026-11-16,
/// section 3.5). A pick reads the generation -- one `Acquire` load, no lock, no pass over
/// the servers -- and follows the snapshot it already holds.
///
/// The third field is the proxy's `balance uri` options, set when the proxy is built and
/// never written again: they sit here, with the rest of what a hash pick reads, because
/// `Proxy` is paid for by every proxy and must not grow (`struct_sizes`).
#[derive(Debug, Default)]
pub struct ChashRing(Mutex<SnapPub>, AtomicU32, UriHash);

impl ChashRing {
    /// The balancing state of a proxy whose `balance uri` line had the options `uri`.
    #[must_use]
    pub fn new(uri: UriHash) -> Self {
        ChashRing(Mutex::default(), AtomicU32::new(0), uri)
    }

    /// A server's state or weight was written, or the set of servers moved: the next pick
    /// from a worker holding the older snapshot takes the lock and rebuilds (like
    /// [`Fwrr::changed`]).
    pub fn changed(&self) {
        self.1.fetch_add(1, Ordering::Release);
    }

    /// The generation the current snapshot was built from.
    #[must_use]
    pub fn generation(&self) -> u32 {
        self.1.load(Ordering::Acquire)
    }

    /// The snapshot of `proxy`'s hash state at the current generation, through the worker's
    /// cache: the worker's own if its slot's generation is the current one, else the one
    /// just built (or built by another worker since the load), into the slot. Per pick in
    /// steady state: one `Acquire` load and one read through the worker's own slot -- no
    /// lock, no scan.
    fn sync<'c>(&self, proxy: &Proxy, cache: &'c mut LbSnapCache) -> &'c ChashSnap {
        let gen = self.1.load(Ordering::Acquire);
        let key = proxy.id;
        if let Some(i) = cache.slots.iter().position(|s| s.key == key) {
            let slot = &mut cache.slots[i];
            if slot.generation != gen {
                slot.snap = self.build_if_changed(proxy, gen);
                slot.generation = gen;
            }
            return &slot.snap;
        }
        // The worker's first pick on this backend: make the slot. In the engine's
        // pre-sized cache the push grows nothing.
        let snap = self.build_if_changed(proxy, gen);
        cache.slots.push(LbSnapSlot { key, generation: gen, snap });
        cache.slots.last().map(|s| s.snap.as_ref()).expect("the slot above is pushed")
    }

    /// The snapshot at generation `gen`, under the builder's lock: rebuilt only when no
    /// worker has yet built for it (a worker that lost the race reads the other's build).
    /// One pass over the servers, on the way.
    fn build_if_changed(&self, proxy: &Proxy, gen: u32) -> Arc<ChashSnap> {
        count_hash_pick_lock();
        let mut pub_ = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if pub_.snap.is_none() || pub_.generation != gen {
            count_hash_pick_scan();
            let in_map = |idx: usize| -> u32 {
                if proxy.srv_set().backup_at(idx) || !is_selectable(proxy, idx) {
                    0
                } else {
                    proxy.srv_set().weight_at(idx).unwrap_or(1)
                }
            };
            let mut snap = ChashSnap::default();
            snap.map.rebuild(proxy, in_map);
            snap.ring.rebuild(proxy);
            pub_.snap = Some(Arc::new(snap));
            pub_.generation = gen;
        }
        pub_.snap.clone().expect("the build above published a snapshot")
    }

    /// The server `balance uri` or `balance source` (map-based) picks for `hash`, from the
    /// [`WeightMap`] of the usable primary servers; `None` when none is usable. Per request,
    /// in steady state: one `Acquire` load of the generation and one read through the
    /// worker's own snapshot -- no lock, no scan. The map is rebuilt, under the lock, only
    /// when a server's state or weight moves the generation.
    fn map_pick(&self, proxy: &Proxy, hash: u32, cache: &mut LbSnapCache) -> Option<usize> {
        let map = &self.sync(proxy, cache).map;
        // The snapshot cannot shed a slot whose server stopped being selectable since the
        // build: a `maxconn` saturation (and this worker's redispatch-avoided server)
        // moves no generation. The walk passes the slot over, the way the ring's
        // `hash-preserve-affinity` walks, so a full server is not sent one connection
        // more; the steady state (every slot's server selectable) reads one slot.
        let len = u32::try_from(map.slots.len()).ok()?;
        (0..len).find_map(|off| {
            let idx = map.slots[(hash.wrapping_add(off) % len) as usize] as usize;
            is_selectable(proxy, idx).then_some(idx)
        })
    }
}

/// Whether a failed connect is retried on a newly balanced server instead of the one that
/// failed: `stream_choose_redispatch` (`include/haproxy/stream.h`), given that
/// `option redispatch` is set and the stream is not `force-persist`.
///
/// * `after` is `redispatch_after`: `> 0` redispatches every `after`-th retry, `< 0` counts
///   back from the last one (`-1`: on it).
/// * `retries_done` is `s->conn_retries` after the failure being retried, `max_retries`
///   the stream's budget.
/// * `srv_running`: the failed server is still `SRV_ST_RUNNING`; one that is not goes at once.
/// * `direct`: the server was chosen by persistence (`SF_DIRECT`).
/// * `active_servers`: usable active servers (`srv_act`); `hash_kind`: a hash algorithm,
///   which would choose the same server again.
#[must_use]
pub fn redispatch_due(
    after: i32,
    max_retries: u16,
    retries_done: u16,
    srv_running: bool,
    direct: bool,
    active_servers: usize,
    hash_kind: bool,
) -> bool {
    if !srv_running {
        return true;
    }
    let done = i32::from(retries_done);
    if after > 0 && done % after == 0 {
        return true;
    }
    // C's `%` with a zero divisor would fault; `checked_rem` makes that "no".
    if after < 0 && done.checked_rem(i32::from(max_retries) + 1 + after) == Some(0) {
        return true;
    }
    !direct && active_servers > 1 && !hash_kind
}

#[cfg(test)]
mod fwrr_tests {
    use super::FwrrState;

    fn state(weights: &[u32]) -> FwrrState {
        let mut st = FwrrState::default();
        st.rebuild(weights.iter().map(|w| w * 16));
        st
    }

    #[test]
    fn an_unavailable_server_is_skipped_and_keeps_its_share_when_it_comes_back() {
        let mut st = state(&[1, 1, 1]);
        // s1 is full for six picks, over two windows: the others alternate...
        let skipped: Vec<usize> = (0..6).filter_map(|_| st.pick(|i| i != 1)).collect();
        assert_eq!(skipped, [0, 2, 0, 2, 0, 2]);
        // ...and it is served again as soon as it can be, without a burst.
        let after: Vec<usize> = (0..6).filter_map(|_| st.pick(|_| true)).collect();
        assert_eq!(after.iter().filter(|&&i| i == 1).count(), 2, "{after:?}");
    }

    /// A weight change before the first pick (the server is in `init`) and one that takes a
    /// server out of the trees and back (`status_down`, `status_up`).
    #[test]
    fn weight_changes_before_any_pick_and_a_server_going_away_and_back() {
        let mut st = state(&[1, 1]);
        st.weight_change(1, 3 * 16);
        let got: Vec<usize> = (0..8).filter_map(|_| st.pick(|_| true)).collect();
        assert_eq!(got.iter().filter(|&&i| i == 1).count(), 6, "{got:?}");
        st.status_down(1);
        let alone: Vec<usize> = (0..3).filter_map(|_| st.pick(|_| true)).collect();
        assert_eq!(alone, [0, 0, 0]);
        st.status_up(1, 16);
        let back: Vec<usize> = (0..6).filter_map(|_| st.pick(|_| true)).collect();
        assert_eq!(back.iter().filter(|&&i| i == 1).count(), 3, "{back:?}");
    }

    /// A weight change for a server that was queued for the next window (`Next`).
    #[test]
    fn a_weight_change_for_a_server_in_the_next_window() {
        let mut st = state(&[3, 1]);
        let mut picks = 0;
        while st.next.is_empty() {
            st.pick(|_| true).expect("a server");
            picks += 1;
            assert!(picks < 64, "no server ever queued for the next window");
        }
        let next: Vec<usize> = st.next.iter().map(|n| n.1).collect();
        for s in next {
            st.weight_change(s, 2 * 16);
        }
        let got: Vec<usize> = (0..12).filter_map(|_| st.pick(|_| true)).collect();
        assert_eq!(got.len(), 12);
    }

    #[test]
    fn nothing_usable_gives_none_and_loses_no_server() {
        let mut st = state(&[2, 1]);
        assert_eq!(st.pick(|_| false), None);
        let got: Vec<usize> = (0..6).filter_map(|_| st.pick(|_| true)).collect();
        assert_eq!(got.iter().filter(|&&i| i == 0).count(), 4, "{got:?}");
    }
}

#[cfg(test)]
mod uri_tests {
    use super::hash_uri;
    use alcyon_config::UriHash;

    #[test]
    fn split_abs_and_path_hashes_match_joined_uri() {
        let cases = [
            ("http://h", "/"),
            ("http://h", "/a/b/c?x=1"),
            ("https://example.test:8443", "//a//b?q=1&r=2"),
            ("http://h", "*"),
        ];
        for (abs, path) in cases {
            let joined = if path == "*" { abs.to_string() } else { format!("{abs}{path}") };
            for whole in [false, true] {
                for path_only in [false, true] {
                    for len in [0, 1, 4, 8, 10, 15, 64] {
                        for depth_end in [0, 2, 3, 4, 5, i32::MAX] {
                            let opts = UriHash { len, depth_end, whole, path_only };
                            assert_eq!(
                                hash_uri(path, Some(abs), opts),
                                hash_uri(&joined, None, opts),
                                "abs={abs:?} path={path:?} opts={opts:?}",
                            );
                        }
                    }
                }
            }
        }
    }
}
