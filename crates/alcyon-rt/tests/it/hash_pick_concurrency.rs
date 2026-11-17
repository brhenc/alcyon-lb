// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Hash picks from several worker threads while another thread flips a server's state and
//! weight (T633): no panic, no out-of-range index, and a pick never names a server that
//! was not eligible in the generation the pick read.
//!
//! A pick reads the proxy's generation, and the snapshot it follows is built from exactly
//! that generation -- a worker's cache slot is used only while the slot's generation equals
//! the current one, else the pick rebuilds (or takes the build another worker just made).
//! So the generation a pick read brackets the generation of the state it picked from, both
//! sides: a pick that reads a generation inside the window in which `s2` was disabled
//! cannot name `s2`, which that generation keeps out of the map and of the ring.
//!
//! The windows span several generations: the flipper is the only thing that bumps a proxy's
//! generation, and it makes extra weight bumps between the disabling and the re-enabling,
//! so the window has interior generations during which the disabled state is settled. Each
//! window is recorded in one packed store -- `[from, to)` with `to` known in advance, since
//! the number of bumps between them is the flipper's own -- right after the disabling
//! bump, so a pick inside the window already sees the whole window. A pick whose read
//! generations are both strictly inside a window names a snapshot built strictly inside it;
//! a pick that straddles the window may legally follow the generation it read, and is not
//! judged.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use alcyon_rt::check::ServerStatus;
use alcyon_rt::engine::Proxies;
use alcyon_rt::srvlog::{Cause, Kind};
use alcyon_rt::track;
use alcyon_rt::Engine;

/// The 20 keys the workers hash, as in `lb_chash`.
const URIS: [&str; 20] = [
    "/test-url", "/", "/a", "/b", "/c", "/img/1.png", "/img/2.png", "/q?x=1", "/q?x=2",
    "/api/users", "/api/orders", "/x/y/z", "/index.html", "/favicon.ico", "/static/app.js",
    "/k1", "/k2", "/k3", "/k4", "/k5",
];

/// Two backends over four servers each, weights 1 3 1 2: `be1` map-based (`balance uri`),
/// `be2` the same with `hash-type consistent`, so both snapshots are exercised.
fn engine() -> Engine {
    let servers = |base: u16| {
        format!(
            "    server s1 127.0.0.1:{base}\n    server s2 127.0.0.1:{} weight 3\n\
             server s3 127.0.0.1:{}\n    server s4 127.0.0.1:{} weight 2\n",
            base + 1,
            base + 2,
            base + 3
        )
    };
    let cfg = format!(
        "backend be1\n    mode http\n    balance uri\n{be1}\
         backend be2\n    mode http\n    balance uri\n    hash-type consistent\n{be2}",
        be1 = servers(27151),
        be2 = servers(27161)
    );
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("engine");
    for p in 0..2 {
        for i in 0..4 {
            engine.proxies[p].srv_set().status_cell(i).expect("status").store(ServerStatus::Up as u8, Ordering::Relaxed);
        }
    }
    engine
}

#[test]
fn picks_while_servers_flip_state_and_weight_never_name_an_ineligible_server() {
    let engine = engine();
    // The workers and the flipper share the proxies the way the engine's workers do:
    // a `Proxies` is the `Arc` over the one `Proxy` list, not a copy.
    let proxies = Arc::new(engine.proxies.clone());
    let running = Arc::new(AtomicBool::new(true));
    // One packed `[from, to)` window per backend per server: `s2`'s down window and
    // `s3`'s zero-weight window. 0 means the window is not recorded yet.
    let s2_win = [Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0))];
    let s3_win = [Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0))];
    let mut workers = Vec::new();
    for _ in 0..4 {
        let proxies = Arc::clone(&proxies);
        let running = Arc::clone(&running);
        let s2_win = [Arc::clone(&s2_win[0]), Arc::clone(&s2_win[1])];
        let s3_win = [Arc::clone(&s3_win[0]), Arc::clone(&s3_win[1])];
        workers.push(thread::spawn(move || {
            let mut cache = alcyon_rt::lb::LbSnapCache::new();
            let mut n = 0u64;
            while running.load(Ordering::Relaxed) || n < 100 {
                for p in 0..2 {
                    let px = &proxies[p];
                    let uri = URIS[(n + p as u64) as usize % URIS.len()];
                    let g0 = px.chash.generation();
                    // `None` (every server ineligible at that generation) is fine: the
                    // question is what a pick that names a server names.
                    let idx = px
                        .select_server_with_key(None, Some(uri), &mut cache)
                        .map(|a| px.srv_set().slot_of_addr(a).expect("a configured server, not an out-of-range index"));
                    let g1 = px.chash.generation();
                    if let Some(i) = idx {
                        let in_window = |pack: u64, lo: u32| {
                            let (from, to) = ((pack >> 32) as u32, pack as u32);
                            from != 0 && lo > from && g1 < to
                        };
                        let s2 = s2_win[p].load(Ordering::Acquire);
                        if i == 1 && in_window(s2, g0) {
                            panic!("a pick reading gen {g0}..{g1} inside the s2 down window named s2");
                        }
                        let s3 = s3_win[p].load(Ordering::Acquire);
                        if i == 2 && in_window(s3, g0) {
                            panic!("a pick reading gen {g0}..{g1} inside the s3 zero-weight window named s3");
                        }
                    }
                }
                n += 1;
            }
            n
        }));
    }
    let flipper = {
        let proxies = Arc::clone(&proxies);
        let running = Arc::clone(&running);
        let s2_win = [Arc::clone(&s2_win[0]), Arc::clone(&s2_win[1])];
        let s3_win = [Arc::clone(&s3_win[0]), Arc::clone(&s3_win[1])];
        thread::spawn(move || {
            for p in 0..2 {
                let px = &proxies[p];
                // s2 down: the bump moves the generation to `from`; three more bumps
                // follow before `s2` is back, so the window is `[from, from + 3)` and is
                // recorded at once, before the workers can pick inside it.
                track::set_status(&proxies, p, 1, ServerStatus::Maint, Kind::Admin, Cause::Cli);
                let from = px.chash.generation();
                s2_win[p].store(((from as u64) << 32) | (from + 3) as u64, Ordering::Release);
                px.set_weight(3, 5);
                thread::sleep(Duration::from_millis(3));
                px.set_weight(3, 2);
                track::set_status(&proxies, p, 1, ServerStatus::Up, Kind::Admin, Cause::Cli);
                // s3 at weight 0: the same, three bumps to its restore.
                px.set_weight(2, 0);
                let from = px.chash.generation();
                s3_win[p].store(((from as u64) << 32) | (from + 3) as u64, Ordering::Release);
                px.set_weight(3, 5);
                thread::sleep(Duration::from_millis(3));
                px.set_weight(3, 2);
                px.set_weight(2, 3);
            }
            running.store(false, Ordering::Release);
        })
    };
    flipper.join().expect("the flipper");
    let total: u64 = workers.into_iter().map(|h| h.join().expect("a worker")).sum();
    assert!(total >= 400, "the workers stopped before picking {total}");
    for p in 0..2 {
        assert_ne!(s2_win[p].load(Ordering::Acquire), 0, "the s2 window of backend {p} was never opened");
        assert_ne!(s3_win[p].load(Ordering::Acquire), 0, "the s3 window of backend {p} was never opened");
    }
}
