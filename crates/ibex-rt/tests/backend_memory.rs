// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! What a backend costs in memory at startup (T175).
//!
//! Milestone M1: "RSS at startup, 10 / 1k / 10k backends <= 1.5x `HAProxy`". `HAProxy`
//! 3.5-dev8 (`nbthread 1`, `global maxconn 1000`, N backends of one server each,
//! `tools/measure/startup_rss.py`): 21.6 MB at 10 backends, 106.5 MB at 10,000, so about
//! 8.7 KB per backend; 1.5x that is 13 KB. Ibex took 257.6 MB at 10,000, about 25 KB per
//! backend, of which the heap held 24 KB.

use std::fmt::Write as _;

use ibex_alloc::CountingAllocator;
use ibex_rt::engine::Engine;

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator::new();

const BACKENDS: usize = 10_000;

fn config_text(backends: usize) -> String {
    let mut cfg = String::from(
        "global\n    maxconn 1000\ndefaults\n    mode http\n    timeout connect 5s\n    timeout client 5s\n    timeout server 5s\n\
         frontend fe\n    bind 127.0.0.1:0\n    default_backend b0\n",
    );
    for i in 0..backends {
        let _ = write!(cfg, "backend b{i}\n    server s{i} 127.0.0.1:{}\n", 20_000 + i % 1_000);
    }
    cfg
}

fn live() -> usize {
    ibex_alloc::alloc_counters().bytes_live()
}

/// The heap a backend holds once the configuration is parsed and one worker's engine is
/// built, everything a running process keeps. 1.5x `HAProxy`'s 8.7 KB per backend of RSS
/// leaves 13 KB; the heap gets 10 KB of it, the rest is for allocator overhead and
/// fragmentation. Measured: 25,607 bytes before T175 (21,699 of them the proxies, the
/// predefined ACLs compiled into each), 6,446 after (config 3,891, proxies 2,539).
#[test]
fn a_backend_holds_at_most_10_kb_at_startup() {
    let text = config_text(BACKENDS);
    let base = live();
    let config = ibex_config::parse_str(&text).expect("parse");
    let parsed = live();
    let shared = Engine::build_shared_state(&config).expect("build_shared_state");
    let built = live();
    let engine = Engine::new_worker(&config, 64, 0, shared).expect("worker");
    let worker = live();
    let per = |a: usize, b: usize| b.saturating_sub(a) / BACKENDS;
    println!(
        "[MEASUREMENT] {BACKENDS} backends, bytes per backend: config {}, proxies {}, worker {}, total {}",
        per(base, parsed),
        per(parsed, built),
        per(built, worker),
        per(base, worker)
    );
    let total = per(base, worker);
    assert!(
        total <= 10 * 1024,
        "a backend holds {total} bytes of heap at startup (bound 10 KB, from 1.5x HAProxy's 8.7 KB of RSS)"
    );
    drop(engine);
    drop(config);
}
