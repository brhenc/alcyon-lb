// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Ibex contributors. See LICENSE.

//! Load balancing algorithms implementation (leastconn, static-rr, URI consistent hashing).

use crate::engine::Proxy;
use crate::check::ServerStatus;
use std::sync::atomic::Ordering;

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
