// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

pub mod engine {
    pub use alcyon_rt::engine::*;
}
pub mod check {
    pub use alcyon_rt::check::*;
}

use alcyon_rt::lb;

use alcyon_config::parse_str;
use std::sync::atomic::Ordering;

fn get_proxy(config_str: &str) -> engine::Engine {
    let config = parse_str(config_str).unwrap();
    engine::Engine::new(&config, 1024).unwrap()
}

#[test]
fn test_leastconn() {
    let cfg = "
backend test_be
    mode http
    server s1 127.0.0.1:8001 weight 1 maxconn 100
    server s2 127.0.0.1:8002 weight 2 maxconn 100
    server s3 127.0.0.1:8003 weight 1 maxconn 100
";
    let eng = get_proxy(cfg);
    let proxy = &eng.proxies[0];
    
    for s in proxy.server_statuses.iter() {
        s.store(check::ServerStatus::Up as u8, Ordering::Relaxed);
    }
    
    proxy.server_actconn[0].store(5, Ordering::Relaxed);
    proxy.server_actconn[1].store(10, Ordering::Relaxed);
    proxy.server_actconn[2].store(5, Ordering::Relaxed);
    
    assert_eq!(lb::leastconn(proxy), Some(1));
    
    proxy.set_weight(2, 2);
    assert_eq!(lb::leastconn(proxy), Some(2));
    
    proxy.server_actconn[1].store(2, Ordering::Relaxed);
    assert_eq!(lb::leastconn(proxy), Some(1));
}

#[test]
fn test_static_rr() {
    let cfg = "
backend test_be
    mode http
    server s1 127.0.0.1:8001 weight 2
    server s2 127.0.0.1:8002 weight 1
";
    let eng = get_proxy(cfg);
    let proxy = &eng.proxies[0];
    
    for s in proxy.server_statuses.iter() {
        s.store(check::ServerStatus::Up as u8, Ordering::Relaxed);
    }
    
    let mut counts = vec![0; 2];
    for _ in 0..600 {
        if let Some(idx) = lb::static_rr(proxy) {
            counts[idx] += 1;
        }
    }
    
    assert_eq!(counts[0], 400); 
    assert_eq!(counts[1], 200); 
}

#[test]
fn test_balance_uri() {
    let cfg = "
backend test_be
    mode http
    server s1 127.0.0.1:8001 weight 1
    server s2 127.0.0.1:8002 weight 1
    server s3 127.0.0.1:8003 weight 1
";
    let eng = get_proxy(cfg);
    let proxy = &eng.proxies[0];
    
    for s in proxy.server_statuses.iter() {
        s.store(check::ServerStatus::Up as u8, Ordering::Relaxed);
    }
    
    let uri1 = "/api/v1/users";
    let server_for_uri1 = lb::balance_uri(proxy, uri1).unwrap();
    
    for _ in 0..100 {
        assert_eq!(lb::balance_uri(proxy, uri1).unwrap(), server_for_uri1);
    }
    
    let mut counts = vec![0; 3];
    for i in 0..100 {
        let uri = format!("/api/v1/resource/{}", i);
        let idx = lb::balance_uri(proxy, &uri).unwrap();
        counts[idx] += 1;
    }
    
    assert!(counts[0] > 10);
    assert!(counts[1] > 10);
    assert!(counts[2] > 10);
}

#[test]
fn balance_uri_reaches_the_data_path() {
    let cfg = "
backend test_be
    balance uri
    mode http
    server s1 127.0.0.1:8001 weight 1
    server s2 127.0.0.1:8002 weight 1
    server s3 127.0.0.1:8003 weight 1
";
    let eng = get_proxy(cfg);
    let proxy = &eng.proxies[0];
    
    for s in proxy.server_statuses.iter() {
        s.store(check::ServerStatus::Up as u8, Ordering::Relaxed);
    }
    
    let mut counts = vec![0; 3];
    for i in 0..100 {
        let uri = format!("/api/v1/resource/{}", i);
        // Drive the engine's real selection path -- not lb::balance_uri
        let target = proxy.select_server_with_key(None, Some(&uri)).unwrap();
        let idx = proxy.servers.position(target).unwrap();
        counts[idx] += 1;
    }
    
    let active_servers = counts.iter().filter(|&&c| c > 0).count();
    assert!(active_servers > 1, "balance uri sent all requests to a single server!");
}

/// Verified against the reference binary (`/home/bhenc/reference/haproxy/haproxy` 3.5-dev7):
/// three real HTTP servers behind `balance first`, 20 requests through the real engine,
/// landed on the first server 20/20 times ({'18091': 20}). `first` is not a random or
/// rotating choice -- it always prefers the earliest server in declaration order that has
/// a free slot.
#[test]
fn test_balance_first() {
    let cfg = "
backend test_be
    mode http
    balance first
    server s1 127.0.0.1:8001
    server s2 127.0.0.1:8002
    server s3 127.0.0.1:8003
";
    let eng = get_proxy(cfg);
    let proxy = &eng.proxies[0];

    for s in proxy.server_statuses.iter() {
        s.store(check::ServerStatus::Up as u8, Ordering::Relaxed);
    }

    for _ in 0..20 {
        let target = proxy.select_server_with_key(None, None).unwrap();
        assert_eq!(target, proxy.servers.at(0), "balance first must always pick the earliest server with a free slot");
    }
}

/// `balance first` moves on to the next server, in declaration order, once the earlier one
/// is at `maxconn` -- HAProxy's `lb_fas.c` keeps servers in a tree ordered by declaration
/// and always serves from its head until that server is full.
#[test]
fn test_balance_first_skips_saturated_earlier_server() {
    let cfg = "
backend test_be
    mode http
    balance first
    server s1 127.0.0.1:8001 maxconn 1
    server s2 127.0.0.1:8002 maxconn 1
";
    let eng = get_proxy(cfg);
    let proxy = &eng.proxies[0];

    for s in proxy.server_statuses.iter() {
        s.store(check::ServerStatus::Up as u8, Ordering::Relaxed);
    }
    proxy.server_actconn[0].store(1, Ordering::Relaxed); // s1 (index 0) is full

    let target = proxy.select_server_with_key(None, None).unwrap();
    assert_eq!(target, proxy.servers.at(1), "a full earlier server must be skipped in favour of the next one");
}

/// Verified against the reference binary: three real HTTP servers behind `balance random`,
/// 60 requests through the real engine, landed on all three ({'18091': 20, '18092': 17,
/// '18093': 23}). `random` must not collapse to a single server the way a naive hash of a
/// fixed key would.
#[test]
fn test_balance_random() {
    let cfg = "
backend test_be
    mode http
    balance random
    server s1 127.0.0.1:8001
    server s2 127.0.0.1:8002
    server s3 127.0.0.1:8003
";
    let eng = get_proxy(cfg);
    let proxy = &eng.proxies[0];

    for s in proxy.server_statuses.iter() {
        s.store(check::ServerStatus::Up as u8, Ordering::Relaxed);
    }

    let mut counts = vec![0; 3];
    for _ in 0..300 {
        let target = proxy.select_server_with_key(None, None).unwrap();
        let idx = proxy.servers.position(target).unwrap();
        counts[idx] += 1;
    }

    let active_servers = counts.iter().filter(|&&c| c > 0).count();
    assert!(active_servers > 1, "balance random sent every request to a single server: {counts:?}");
}

/// A server at `maxconn` is not a candidate for `balance random`: HAProxy's `get_server_rnd`
/// pretends a full server does not exist ("if the selected server is full, pretend we have
/// none") so the request reaches the backend's queue/failover instead of a server that
/// cannot serve it.
#[test]
fn test_balance_random_never_picks_a_saturated_server() {
    let cfg = "
backend test_be
    mode http
    balance random
    server s1 127.0.0.1:8001 maxconn 1
    server s2 127.0.0.1:8002 maxconn 5
";
    let eng = get_proxy(cfg);
    let proxy = &eng.proxies[0];

    for s in proxy.server_statuses.iter() {
        s.store(check::ServerStatus::Up as u8, Ordering::Relaxed);
    }
    proxy.server_actconn[0].store(1, Ordering::Relaxed); // s1 is full

    for _ in 0..50 {
        let target = proxy.select_server_with_key(None, None).unwrap();
        assert_eq!(target, proxy.servers.at(1), "a saturated server must never be drawn");
    }
}

/// `hash-preserve-affinity maxconn` (with `hash-type consistent`) walks the ring forward to
/// the next UP server once the hashed one is at `maxconn`, matching
/// `chash_get_server_hash`'s `PR_O3_HASHAFNTY_MAXCONN` branch -- this is the mechanism
/// behind reg-test balance/balance-hash-maxconn.vtc, which passes against the real engine.
#[test]
fn test_hash_preserve_affinity_maxconn_skips_saturated_natural_target() {
    let cfg = "
backend test_be
    mode http
    balance uri
    hash-type consistent
    hash-preserve-affinity maxconn
    server s1 127.0.0.1:8001 maxconn 1
    server s2 127.0.0.1:8002 maxconn 1
";
    let eng = get_proxy(cfg);
    let proxy = &eng.proxies[0];
    for s in proxy.server_statuses.iter() {
        s.store(check::ServerStatus::Up as u8, Ordering::Relaxed);
    }

    let uri = "/test-url";
    let natural = proxy.select_server_with_key(None, Some(uri)).unwrap();
    let natural_idx = proxy.servers.position(natural).unwrap();

    // Saturate the natural target and confirm the ring moves to the other server.
    proxy.server_actconn[natural_idx].store(1, Ordering::Relaxed);
    let other_idx = 1 - natural_idx;
    let target = proxy.select_server_with_key(None, Some(uri)).unwrap();
    assert_eq!(target, proxy.servers.at(other_idx), "hash-preserve-affinity maxconn must skip a full natural target");
}

fn all_up(proxy: &engine::Proxy) {
    for s in proxy.server_statuses.iter() {
        s.store(check::ServerStatus::Up as u8, Ordering::Relaxed);
    }
}

/// With every active server down, `HAProxy` 3.5 sent 30 of 30 requests to the first backup
/// under both `balance random` and `balance first` (`lbprm.fbck`: without `option
/// allbackups` only the first usable backup serves). Measured 2026-10-02.
#[test]
fn random_and_first_fall_back_to_the_first_backup_only() {
    for algo in ["random", "first"] {
        let eng = get_proxy(&format!(
            "backend b\n    balance {algo}\n    server a 127.0.0.1:8001\n    server b1 127.0.0.1:8002 backup\n    server b2 127.0.0.1:8003 backup\n"
        ));
        let proxy = &eng.proxies[0];
        all_up(proxy);
        proxy.server_statuses[0].store(check::ServerStatus::Down as u8, Ordering::Relaxed);
        for _ in 0..50 {
            assert_eq!(proxy.select_server_with_key(None, None), Some(proxy.servers.at(1)), "balance {algo}");
        }
        // And nothing at all once the backups are down too.
        proxy.server_statuses[1].store(check::ServerStatus::Down as u8, Ordering::Relaxed);
        proxy.server_statuses[2].store(check::ServerStatus::Down as u8, Ordering::Relaxed);
        assert_eq!(proxy.select_server_with_key(None, None), None, "balance {algo}");
    }
}

/// `random(N)` keeps the least loaded of its draws (`get_server_rnd`): with ten draws a
/// busy server wins only when every draw lands on it.
#[test]
fn random_draws_prefer_the_less_loaded_server() {
    let eng = get_proxy("backend b\n    balance random(10)\n    server s1 127.0.0.1:8001\n    server s2 127.0.0.1:8002\n");
    let proxy = &eng.proxies[0];
    all_up(proxy);
    proxy.server_actconn[0].store(50, Ordering::Relaxed);
    let to_s2 = (0..1000).filter(|_| proxy.select_server_with_key(None, None) == Some(proxy.servers.at(1))).count();
    assert!(to_s2 > 950, "{to_s2}/1000 to the idle server");
}

/// The shared runtime values (T177): a `maxconn` set at run time keeps a full server out of
/// `balance source` without a source address (and of `select_server`, its fallback), and a
/// weight set to 0 takes the server out, on the very `Proxy` every worker reads.
#[test]
fn runtime_maxconn_and_weight_reach_the_fallback_selections() {
    for algo in ["source", "uri"] {
        let eng = get_proxy(&format!(
            "backend b\n    balance {algo}\n    server s1 127.0.0.1:8001\n    server s2 127.0.0.1:8002\n"
        ));
        let proxy = &eng.proxies[0];
        all_up(proxy);
        assert!(proxy.server_maxconn.set(0, Some(1)));
        proxy.server_actconn[0].store(1, Ordering::Relaxed);
        for _ in 0..10 {
            assert_eq!(proxy.select_server_with_key(None, None), Some(proxy.servers.at(1)), "balance {algo}");
            assert_eq!(proxy.select_server(), Some(proxy.servers.at(1)), "balance {algo}");
        }
        proxy.server_actconn[0].store(0, Ordering::Relaxed);
        proxy.set_weight(1, 0);
        assert_eq!(proxy.initial_weight(1), 1);
        for _ in 0..10 {
            assert_eq!(proxy.select_server_with_key(None, None), Some(proxy.servers.at(0)), "balance {algo}");
        }
    }
}
