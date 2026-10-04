// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Load balancing algorithms implementation (leastconn, static-rr, URI consistent hashing).

use crate::engine::Proxy;
use crate::check::ServerStatus;
use ibex_config::{HashPreserveAffinity, HashType};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{RwLock, RwLockReadGuard};

/// Determines whether a server at `idx` in `proxy` is eligible to receive traffic.
#[inline]
#[must_use]
pub fn is_server_available(proxy: &Proxy, idx: usize) -> bool {
    // The server a retry has just left, while a redispatch looks for another one.
    if idx >= proxy.servers.len() || proxy.avoid_idx == Some(idx) {
        return false;
    }
    if let Some(status) = proxy.server_statuses.get(idx) {
        if status.load(Ordering::Relaxed) != ServerStatus::Up as u8 {
            return false;
        }
    } else {
        return false;
    }
    if let Some(Some(mc)) = proxy.server_maxconn.get(idx) {
        if *mc > 0 {
            let act = proxy.server_actconn.get(idx).map_or(0, |a| a.load(Ordering::Relaxed));
            if act >= *mc {
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
    is_server_available(proxy, idx) && proxy.server_weights.get(idx).copied().unwrap_or(1) > 0
}

/// Determines whether a server at `idx` is UP, ignoring its connection load. Used to build
/// the hash ring's candidate set: a consistent hash ring includes every UP server regardless
/// of `maxconn`, and only `hash-preserve-affinity` decides whether a saturated server is
/// skipped afterwards.
#[inline]
fn is_server_up(proxy: &Proxy, idx: usize) -> bool {
    proxy
        .server_statuses
        .get(idx)
        .is_some_and(|status| status.load(Ordering::Relaxed) == ServerStatus::Up as u8)
}

/// The backup that takes the traffic when no active server is usable: the first one in
/// declaration order that is UP and under its `maxconn` (`lbprm.fbck`, set by
/// `recount_servers`; Ibex refuses `option allbackups`, which would use them all).
#[must_use]
pub fn first_backup(proxy: &Proxy) -> Option<usize> {
    (0..proxy.servers.len()).find(|&idx| proxy.server_backups.get(idx).copied().unwrap_or(false) && is_selectable(proxy, idx))
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
/// Per request it costs one uncontended mutex, one compare of the weights with the ones
/// the state was built from (`O(servers)`, no allocation) and, in `HAProxy`'s own terms,
/// a handful of `eb32` operations, here pops and inserts on small sorted vectors whose
/// capacity is reserved at the rebuild: no allocation either.
#[derive(Debug, Default)]
pub struct Fwrr(std::sync::Mutex<Option<Box<FwrrState>>>);

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
        let backup = proxy.server_backups.get(idx).copied().unwrap_or(false);
        let up = proxy.server_statuses.get(idx).is_some_and(|s| s.load(Ordering::Relaxed) == ServerStatus::Up as u8);
        let w = proxy.server_weights.get(idx).copied().unwrap_or(1).min(256);
        if backup || !up { 0 } else { w * BE_WEIGHT_SCALE }
    }

    /// Rebuild when a server's effective weight is not the one the trees were built with
    /// (`fwrr_init_server_groups`: every usable server in `init`, in declaration order).
    fn sync(&mut self, proxy: &Proxy) {
        let n = proxy.servers.len();
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
    st.sync(proxy);
    st.pick(|i| is_server_available(proxy, i)).or_else(|| first_backup(proxy))
}

/// First Available Server (`balance first`).
/// Picks the first server, in declaration order, that is UP and has a free `maxconn` slot.
/// Falls back to backup servers, in declaration order, if no primary server qualifies.
#[must_use]
pub fn first(proxy: &Proxy) -> Option<usize> {
    for idx in 0..proxy.servers.len() {
        let is_backup = proxy.server_backups.get(idx).copied().unwrap_or(false);
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

fn next_random_u64() -> u64 {
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

/// Builds the weighted candidate set for a random draw: primary (non-backup) servers
/// under their `maxconn` if any are eligible, otherwise the first eligible backup alone.
/// Returns `(candidates, total_weight)` where `candidates` is `(server_idx, weight)`.
fn weighted_eligible(proxy: &Proxy) -> (Vec<(usize, u32)>, u32) {
    let mut total_weight = 0u32;
    let mut eligible_primaries = Vec::new();
    for idx in 0..proxy.servers.len() {
        let is_backup = proxy.server_backups.get(idx).copied().unwrap_or(false);
        if !is_backup && is_selectable(proxy, idx) {
            let w = proxy.server_weights.get(idx).copied().unwrap_or(1).max(1);
            total_weight = total_weight.saturating_add(w);
            eligible_primaries.push((idx, w));
        }
    }
    if !eligible_primaries.is_empty() {
        return (eligible_primaries, total_weight);
    }

    // No active server: the first usable backup alone (`lbprm.fbck`; Ibex has no
    // `option allbackups`). `HAProxy` 3.5 sent 30 of 30 requests to it under `random`.
    match first_backup(proxy) {
        Some(idx) => (vec![(idx, 1)], 1),
        None => (Vec::new(), 0),
    }
}

/// Random draw over the weighted server set (`balance random`, `balance random(N)`).
/// Draws `draws` candidates weighted by server weight and keeps the least loaded one
/// (lowest `actconn / weight`), matching HAProxy's `get_server_rnd`. A server at `maxconn`
/// is not a candidate, so the queue is never picked for a request it cannot serve.
#[must_use]
pub fn random(proxy: &Proxy, draws: u32) -> Option<usize> {
    let (candidates, total_weight) = weighted_eligible(proxy);
    if candidates.is_empty() || total_weight == 0 {
        return None;
    }

    let draw_one = |candidates: &[(usize, u32)], total_weight: u32| -> usize {
        let pos = (next_random_u64() % u64::from(total_weight)) as u32;
        let mut acc = 0u32;
        let mut picked = candidates[0].0;
        for &(idx, w) in candidates {
            acc = acc.saturating_add(w);
            if pos < acc {
                picked = idx;
                break;
            }
        }
        picked
    };

    let mut best = draw_one(&candidates, total_weight);
    for _ in 1..draws.max(1) {
        let candidate = draw_one(&candidates, total_weight);
        if candidate == best {
            continue;
        }
        let best_weight = u64::from(proxy.server_weights.get(best).copied().unwrap_or(1).max(1));
        let cand_weight = u64::from(proxy.server_weights.get(candidate).copied().unwrap_or(1).max(1));
        let best_load = u64::from(proxy.server_actconn.get(best).map_or(0, |a| a.load(Ordering::Relaxed)));
        let cand_load = u64::from(proxy.server_actconn.get(candidate).map_or(0, |a| a.load(Ordering::Relaxed)));
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
    for idx in 0..proxy.servers.len() {
        let is_backup = proxy.server_backups.get(idx).copied().unwrap_or(false);
        if !is_backup && is_selectable(proxy, idx) {
            let conn = u64::from(proxy.server_actconn.get(idx).map_or(0, |a| a.load(Ordering::Relaxed)));
            let weight = u64::from(proxy.server_weights.get(idx).copied().unwrap_or(1).max(1));

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
    let mut total_weight = 0u32;
    let mut eligible_primaries = Vec::new();

    for idx in 0..proxy.servers.len() {
        let is_backup = proxy.server_backups.get(idx).copied().unwrap_or(false);
        if !is_backup && is_selectable(proxy, idx) {
            let w = proxy.server_weights.get(idx).copied().unwrap_or(1).max(1);
            total_weight = total_weight.saturating_add(w);
            eligible_primaries.push((idx, w));
        }
    }

    if !eligible_primaries.is_empty() {
        let counter = proxy.next_server_idx.fetch_add(1, Ordering::Relaxed);
        let pos = (counter % (total_weight as usize)) as u32;

        let mut acc = 0u32;
        for (idx, w) in eligible_primaries {
            acc = acc.saturating_add(w);
            if pos < acc {
                return Some(idx);
            }
        }
        return None;
    }

    // Backup failover: the first usable backup alone.
    first_backup(proxy)
}

/// 64-bit FNV-1a deterministic hash function for URI path/query mapping.
#[inline]
fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3_u64);
    }
    hash
}

/// Deterministic Consistent URI Hash (`balance uri`).
/// Hashes the request URI and consistently selects the backend server.
#[must_use]
pub fn balance_uri(proxy: &Proxy, uri: &str) -> Option<usize> {
    // `hash-preserve-affinity` only has an effect on a consistent-hash ring (HAProxy gates
    // it the same way: the option is read only from `chash_get_server_hash`). Map-based
    // hashing (the default) keeps the pre-existing weighted-modulo-over-eligible-servers
    // behaviour below untouched.
    if proxy.hash_type == HashType::Consistent {
        return balance_uri_consistent(proxy, uri);
    }
    let hash = fnv1a_64(uri.as_bytes()) as usize;

    let mut total_weight = 0u32;
    let mut eligible_primaries = Vec::new();

    for idx in 0..proxy.servers.len() {
        let is_backup = proxy.server_backups.get(idx).copied().unwrap_or(false);
        if !is_backup && is_selectable(proxy, idx) {
            let w = proxy.server_weights.get(idx).copied().unwrap_or(1).max(1);
            total_weight = total_weight.saturating_add(w);
            eligible_primaries.push((idx, w));
        }
    }

    if !eligible_primaries.is_empty() {
        let pos = (hash % (total_weight as usize)) as u32;
        let mut acc = 0u32;
        for (idx, w) in eligible_primaries {
            acc = acc.saturating_add(w);
            if pos < acc {
                return Some(idx);
            }
        }
        return None;
    }

    // Backup failover: the first usable backup alone.
    first_backup(proxy)
}

/// `balance uri` with `hash-type consistent` (`get_server_uh` + `chash_get_server_hash`,
/// `src/backend.c` and `src/lb_chash.c`).
///
/// The key is `sdbm` of the URI up to its `?`, avalanched by `full_hash` -- `hash-type
/// consistent` alone means `sdbm avalanche` (`cfgparse-listen.c`) -- and the server is the one owning the
/// ring point nearest to it. A server at `maxconn` is passed over for the next point
/// round the ring: that is `hash-preserve-affinity maxconn`. `HAProxy`'s default, `always`,
/// would instead queue the request on the full server; Ibex has no server queue and never
/// sends a server more than its `maxconn`, so `always` walks the same way once the server
/// is full. `None` when no server is up, or every candidate is full.
fn balance_uri_consistent(proxy: &Proxy, uri: &str) -> Option<usize> {
    let key = uri.split('?').next().unwrap_or("");
    chash_lookup(proxy, |_| full_hash(hash_sdbm(key.as_bytes())))
}

/// `balance source` with `hash-type consistent` (`get_server_sh`, `src/backend.c`): the
/// key is the XOR of the address' 32-bit words (host order), avalanched by `full_hash`,
/// and 0 when only one server is left to choose from, then the ring as for `balance uri`.
#[must_use]
pub fn balance_source_consistent(proxy: &Proxy, ip: std::net::IpAddr) -> Option<usize> {
    let words = match ip {
        std::net::IpAddr::V4(a) => vec![u32::from(a)],
        std::net::IpAddr::V6(a) => a.octets().chunks(4).map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]])).collect(),
    };
    chash_lookup(proxy, |servers_in_ring| {
        if servers_in_ring <= 1 { 0 } else { full_hash(words.iter().fold(0, |h, w| h ^ w)) }
    })
}

/// The server owning the ring point nearest to the key `hash(n)`, `n` being how many
/// servers the ring holds (`tot_used`).
fn chash_lookup(proxy: &Proxy, hash: impl FnOnce(usize) -> u32) -> Option<usize> {
    let ring = proxy.chash.ring(proxy);
    let points = match &ring.members {
        RingMembers::Active => &ring.points,
        RingMembers::FirstBackup(idx) => {
            return is_server_available(proxy, *idx).then_some(*idx);
        }
        RingMembers::None => return None,
    };

    // The point at or after the key, or the first one past the end of the ring; then
    // whichever of it and the point before is closer, the earlier one on a tie.
    let mut in_ring: Vec<u32> = points.iter().map(|p| p.1).collect();
    in_ring.sort_unstable();
    in_ring.dedup();
    let hash = hash(in_ring.len());
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
fn hash_sdbm(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0u32, |h, &c| {
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
    /// None is up: the first backup that is (`lbprm.fbck`; Ibex has no `option
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
}

/// The consistent-hash ring of one proxy, shared by its workers (the `Proxy` clones).
///
/// `HAProxy` moves a server's points in and out as its state changes; here the ring is
/// rebuilt from scratch whenever the set of up servers differs from the one it was built
/// from. A server's points depend only on its id and weight, so the rebuilt ring is the
/// one `HAProxy` holds, and keys move only to and from the server that changed.
#[derive(Debug, Default)]
pub struct ChashRing(RwLock<Ring>);

impl ChashRing {
    fn ring<'a>(&'a self, proxy: &Proxy) -> RwLockReadGuard<'a, Ring> {
        let in_ring = |idx: usize| {
            !proxy.server_backups.get(idx).copied().unwrap_or(false)
                && is_server_up(proxy, idx)
                && proxy.server_weights.get(idx).copied().unwrap_or(1) > 0
        };
        {
            let ring = self.0.read().unwrap_or_else(std::sync::PoisonError::into_inner);
            if ring.built_from.len() == proxy.servers.len()
                && ring.built_from.iter().enumerate().all(|(i, &b)| b == in_ring(i))
            {
                return ring;
            }
        }
        {
            let mut ring = self.0.write().unwrap_or_else(std::sync::PoisonError::into_inner);
            let built_from: Vec<bool> = (0..proxy.servers.len()).map(in_ring).collect();
            ring.points.clear();
            for idx in (0..proxy.servers.len()).filter(|&i| built_from[i]) {
                // `puid`: the server's id, from 1 in declaration order around the ones
                // with an `id`; `hash-key id` is the default.
                let puid = proxy.server_puid(idx);
                let base = puid.wrapping_mul(SRV_EWGHT_RANGE);
                let nodes = proxy.server_weights.get(idx).copied().unwrap_or(1) * BE_WEIGHT_SCALE;
                let server = u32::try_from(idx).unwrap_or(u32::MAX);
                ring.points.extend((0..nodes).map(|j| (full_hash(base.wrapping_add(j)), server)));
            }
            // Stable, so equal keys keep HAProxy's insertion order.
            ring.points.sort_by_key(|&(k, _)| k);
            ring.built_from = built_from;
            ring.members = if !ring.points.is_empty() {
                RingMembers::Active
            } else if let Some(b) = (0..proxy.servers.len()).find(|&i| {
                proxy.server_backups.get(i).copied().unwrap_or(false) && is_server_up(proxy, i)
            }) {
                RingMembers::FirstBackup(b)
            } else {
                RingMembers::None
            };
        }
        // Read again rather than downgrade (std has no downgrade); another writer in
        // between would have built the same ring from the same states.
        self.0.read().unwrap_or_else(std::sync::PoisonError::into_inner)
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

    #[test]
    fn nothing_usable_gives_none_and_loses_no_server() {
        let mut st = state(&[2, 1]);
        assert_eq!(st.pick(|_| false), None);
        let got: Vec<usize> = (0..6).filter_map(|_| st.pick(|_| true)).collect();
        assert_eq!(got.iter().filter(|&&i| i == 0).count(), 4, "{got:?}");
    }
}
