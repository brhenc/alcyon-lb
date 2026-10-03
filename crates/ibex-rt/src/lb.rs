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
    if idx >= proxy.servers.len() {
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

/// First Available Server (`balance first`).
/// Picks the first server, in declaration order, that is UP and has a free `maxconn` slot.
/// Falls back to backup servers, in declaration order, if no primary server qualifies.
#[must_use]
pub fn first(proxy: &Proxy) -> Option<usize> {
    for idx in 0..proxy.servers.len() {
        let is_backup = proxy.server_backups.get(idx).copied().unwrap_or(false);
        if !is_backup && is_server_available(proxy, idx) {
            return Some(idx);
        }
    }
    for idx in 0..proxy.servers.len() {
        let is_backup = proxy.server_backups.get(idx).copied().unwrap_or(false);
        if is_backup && is_server_available(proxy, idx) {
            return Some(idx);
        }
    }
    None
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
        if !is_backup && is_server_available(proxy, idx) {
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
    match (0..proxy.servers.len()).find(|&idx| {
        proxy.server_backups.get(idx).copied().unwrap_or(false) && is_server_available(proxy, idx)
    }) {
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
        if !is_backup && is_server_available(proxy, idx) {
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

    // Second pass: backup servers fallback
    for idx in 0..proxy.servers.len() {
        let is_backup = proxy.server_backups.get(idx).copied().unwrap_or(false);
        if is_backup && is_server_available(proxy, idx) {
            let conn = u64::from(proxy.server_actconn.get(idx).map_or(0, |a| a.load(Ordering::Relaxed)));
            let weight = u64::from(proxy.server_weights.get(idx).copied().unwrap_or(1).max(1));

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

    best_idx
}

/// Weighted Round Robin with static weights (`balance static-rr`).
/// Produces an interleaved distribution matching HAProxy map-based round-robin.
#[must_use]
pub fn static_rr(proxy: &Proxy) -> Option<usize> {
    let mut total_weight = 0u32;
    let mut eligible_primaries = Vec::new();

    for idx in 0..proxy.servers.len() {
        let is_backup = proxy.server_backups.get(idx).copied().unwrap_or(false);
        if !is_backup && is_server_available(proxy, idx) {
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

    // Backup failover
    let mut total_backup_weight = 0u32;
    let mut eligible_backups = Vec::new();

    for idx in 0..proxy.servers.len() {
        let is_backup = proxy.server_backups.get(idx).copied().unwrap_or(false);
        if is_backup && is_server_available(proxy, idx) {
            let w = proxy.server_weights.get(idx).copied().unwrap_or(1).max(1);
            total_backup_weight = total_backup_weight.saturating_add(w);
            eligible_backups.push((idx, w));
        }
    }

    if !eligible_backups.is_empty() {
        let counter = proxy.next_server_idx.fetch_add(1, Ordering::Relaxed);
        let pos = (counter % (total_backup_weight as usize)) as u32;

        let mut acc = 0u32;
        for (idx, w) in eligible_backups {
            acc = acc.saturating_add(w);
            if pos < acc {
                return Some(idx);
            }
        }
    }

    None
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
        if !is_backup && is_server_available(proxy, idx) {
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

    // Backup failover
    let mut total_backup_weight = 0u32;
    let mut eligible_backups = Vec::new();

    for idx in 0..proxy.servers.len() {
        let is_backup = proxy.server_backups.get(idx).copied().unwrap_or(false);
        if is_backup && is_server_available(proxy, idx) {
            let w = proxy.server_weights.get(idx).copied().unwrap_or(1).max(1);
            total_backup_weight = total_backup_weight.saturating_add(w);
            eligible_backups.push((idx, w));
        }
    }

    if !eligible_backups.is_empty() {
        let pos = (hash % (total_backup_weight as usize)) as u32;
        let mut acc = 0u32;
        for (idx, w) in eligible_backups {
            acc = acc.saturating_add(w);
            if pos < acc {
                return Some(idx);
            }
        }
    }

    None
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
    let hash = full_hash(hash_sdbm(key.as_bytes()));

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
                // `puid`: servers are numbered from 1 in declaration order (Ibex has no
                // `id` keyword on servers), and `hash-key id` is the default.
                let puid = u32::try_from(idx + 1).unwrap_or(u32::MAX);
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
