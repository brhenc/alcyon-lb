// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `balance uri` with `hash-type consistent`: the server each key lands on, as the
//! reference `HAProxy` (3.5-dev7-e6f616-55) chose it, measured 2026-10-02 with four
//! servers behind it (`http-request return` listeners naming themselves) and curl.
//!
//! The ring is `src/lb_chash.c`: every server gets `weight * 16` points keyed
//! `full_hash(puid * 4096 + i)`, a request's key is `sdbm` of the URI up to `?`
//! (`get_server_uh`), and it goes to the nearest point, the one before it on a tie.

use std::sync::atomic::Ordering;

use alcyon_rt::check::ServerStatus;
use alcyon_rt::Engine;

const SERVERS: &str = "
    server s1 127.0.0.1:27101
    server s2 127.0.0.1:27102 weight 3
    server s3 127.0.0.1:27103
    server s4 127.0.0.1:27104 weight 2
";

/// With every server up.
const ALL_UP: [(&str, &str); 20] = [
    ("/test-url", "s3"), ("/", "s2"), ("/a", "s4"), ("/b", "s2"), ("/c", "s1"),
    ("/img/1.png", "s2"), ("/img/2.png", "s4"), ("/q?x=1", "s3"), ("/q?x=2", "s3"),
    ("/api/users", "s1"), ("/api/orders", "s3"), ("/x/y/z", "s4"), ("/index.html", "s4"),
    ("/favicon.ico", "s1"), ("/static/app.js", "s2"), ("/k1", "s3"), ("/k2", "s2"),
    ("/k3", "s3"), ("/k4", "s3"), ("/k5", "s2"),
];

/// With s3 out (`disabled`): its keys move, no other key does.
const S3_DOWN: [(&str, &str); 20] = [
    ("/test-url", "s2"), ("/", "s2"), ("/a", "s4"), ("/b", "s2"), ("/c", "s1"),
    ("/img/1.png", "s2"), ("/img/2.png", "s4"), ("/q?x=1", "s1"), ("/q?x=2", "s1"),
    ("/api/users", "s1"), ("/api/orders", "s2"), ("/x/y/z", "s4"), ("/index.html", "s4"),
    ("/favicon.ico", "s1"), ("/static/app.js", "s2"), ("/k1", "s2"), ("/k2", "s2"),
    ("/k3", "s2"), ("/k4", "s1"), ("/k5", "s2"),
];

/// `hash-preserve-affinity maxconn`, every server `maxconn 1`, s3 busy with one request:
/// the keys whose point is s3's walk forward round the ring.
const S3_FULL: [(&str, &str); 6] = [
    ("/test-url", "s1"), ("/q?x=1", "s2"), ("/api/orders", "s4"), ("/k1", "s4"),
    ("/k3", "s1"), ("/k4", "s2"),
];

fn engine(extra: &str, servers: &str) -> Engine {
    let cfg = format!("backend be\n    mode http\n    balance uri\n    hash-type consistent\n{extra}{servers}");
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("engine");
    for s in engine.proxies[0].server_statuses.iter() {
        s.store(ServerStatus::Up as u8, Ordering::Relaxed);
    }
    engine
}

fn pick(engine: &mut Engine, uri: &str) -> Option<String> {
    let proxy = &engine.proxies[0];
    let addr = proxy.select_server_with_key(None, Some(uri))?;
    let idx = proxy.servers.position(addr).expect("a configured server");
    Some(proxy.server_ids[idx].clone())
}

fn assert_choices(engine: &mut Engine, expected: &[(&str, &str)]) {
    let got: Vec<(&str, String)> =
        expected.iter().map(|&(u, _)| (u, pick(engine, u).unwrap_or_default())).collect();
    let want: Vec<(&str, String)> = expected.iter().map(|&(u, s)| (u, s.to_string())).collect();
    assert_eq!(got, want);
}

#[test]
fn every_key_lands_where_haproxy_puts_it() {
    assert_choices(&mut engine("", SERVERS), &ALL_UP);
}

#[test]
fn a_server_going_down_moves_only_its_own_keys() {
    let mut e = engine("", SERVERS);
    e.proxies[0].server_statuses[2].store(ServerStatus::Down as u8, Ordering::Relaxed);
    assert_choices(&mut e, &S3_DOWN);
    // And back: the ring is rebuilt from who is up, not patched.
    e.proxies[0].server_statuses[2].store(ServerStatus::Up as u8, Ordering::Relaxed);
    assert_choices(&mut e, &ALL_UP);
}

#[test]
fn a_full_server_s_keys_walk_round_the_ring_under_maxconn_affinity() {
    let servers = SERVERS.replace("27101", "27101 maxconn 1").replace("27102 weight 3", "27102 weight 3 maxconn 1")
        .replace("27103", "27103 maxconn 1").replace("27104 weight 2", "27104 weight 2 maxconn 1");
    let mut e = engine("    hash-preserve-affinity maxconn\n", &servers);
    e.proxies[0].server_actconn[2].store(1, Ordering::Relaxed);
    assert_choices(&mut e, &S3_FULL);
}

/// HAProxy's default, `always`, would queue the request on the full server. Alcyon has no
/// server queue, and every algorithm here treats a server at `maxconn` as unavailable
/// rather than send it one connection more, so `always` walks the ring like `maxconn`
/// once the server is full -- and only then.
#[test]
fn without_a_server_queue_always_walks_off_a_full_server_rather_than_exceed_maxconn() {
    let servers = SERVERS.replace("27103", "27103 maxconn 1");
    let mut e = engine("", &servers);
    assert_eq!(pick(&mut e, "/test-url").as_deref(), Some("s3"));
    e.proxies[0].server_actconn[2].store(1, Ordering::Relaxed);
    assert_eq!(pick(&mut e, "/test-url").as_deref(), Some("s1"));
}

#[test]
fn with_no_active_server_up_the_first_backup_takes_every_key() {
    // lbprm.fbck: without `option allbackups`, only the first usable backup serves.
    let mut e = engine(
        "",
        "    server a 127.0.0.1:27101\n    server b1 127.0.0.1:27102 backup\n    server b2 127.0.0.1:27103 backup\n",
    );
    e.proxies[0].server_statuses[0].store(ServerStatus::Down as u8, Ordering::Relaxed);
    for (u, _) in ALL_UP {
        assert_eq!(pick(&mut e, u).as_deref(), Some("b1"), "{u}");
    }
}

#[test]
fn with_no_server_up_there_is_no_server() {
    let mut e = engine("", SERVERS);
    for s in e.proxies[0].server_statuses.iter() {
        s.store(ServerStatus::Down as u8, Ordering::Relaxed);
    }
    assert_eq!(pick(&mut e, "/a"), None);
}
