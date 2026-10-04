// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! What a worker costs in memory (T160).
//!
//! `HAProxy`'s threads share one copy of every proxy and server: 10,000 backends take
//! 110 MB with `nbthread 1` and 131 MB with `nbthread 16`. Ibex gave each worker a clone of
//! every `Proxy`, about 14 KB per backend per worker: 450 MB and 2.5 GB. The workers now
//! share the proxies, so an extra worker costs what its own engine holds and nothing per
//! backend.

mod common;

use ibex_alloc::CountingAllocator;
use ibex_rt::engine::Engine;

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator::new();

const BACKENDS: usize = 2_000;
const WORKERS: usize = 8;

fn config_text(backends: usize, global: &str, bind: &str) -> String {
    let mut cfg = format!(
        "{global}defaults\n    mode http\n    timeout connect 5s\n    timeout client 5s\n    timeout server 5s\n\
         frontend fe\n    bind {bind}\n    default_backend b0\n",
    );
    for i in 0..backends {
        cfg.push_str(&format!("backend b{i}\n    server s{i} 127.0.0.1:{}\n", 20_000 + i % 1_000));
    }
    cfg
}

fn config(backends: usize) -> ibex_config::Config {
    ibex_config::parse_str(&config_text(backends, "", "127.0.0.1:0")).expect("parse")
}

/// `VmRSS` of the `ibex` binary started on `backends` backends with `nbthread`, in kB,
/// once it listens.
fn startup_rss_kb(backends: usize, nbthread: usize) -> u64 {
    let addr = common::reserve_addr();
    let path = std::env::temp_dir().join(format!("ibex-t160-{}-{nbthread}.cfg", std::process::id()));
    let global = format!("global\n    nbthread {nbthread}\n    maxconn 1000\n");
    std::fs::write(&path, config_text(backends, &global, &addr.to_string())).expect("write config");
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn ibex");
    // Ten thousand backends take a debug build a while to load.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while std::net::TcpStream::connect(addr).is_err() {
        assert!(std::time::Instant::now() < deadline, "ibex did not listen on {addr}");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // Every worker has built its engine by now; let the last ones settle.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let status = std::fs::read_to_string(format!("/proc/{}/status", child.id())).expect("status");
    common::stop(&mut child);
    let _ = std::fs::remove_file(&path);
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .expect("VmRSS")
}

/// The milestone's bound (`docs/milestones.md`, T160): 16 threads cost at most 20 MB more
/// than one, at the largest of its sizes. `HAProxy` 3.5-dev8, 10,000 backends: 110 MB and
/// 131 MB.
#[test]
fn sixteen_threads_cost_at_most_20_mb_more_than_one() {
    let one = startup_rss_kb(10_000, 1);
    let sixteen = startup_rss_kb(10_000, 16);
    println!("[MEASUREMENT] 10000 backends: VmRSS {one} kB at nbthread 1, {sixteen} kB at nbthread 16");
    assert!(
        sixteen <= one + 20 * 1024,
        "nbthread 16 takes {sixteen} kB, nbthread 1 {one} kB: more than 20 MB apart"
    );
}

#[test]
fn an_extra_worker_costs_nothing_per_backend() {
    let config = config(BACKENDS);
    let shared = Engine::build_shared_state(&config).expect("build_shared_state");
    let mut engines = Vec::with_capacity(WORKERS);
    engines.push(Engine::new_worker(&config, 64, 0, shared.clone()).expect("worker 0"));
    let one = ibex_alloc::alloc_counters().bytes_live();
    for w in 1..WORKERS {
        engines.push(Engine::new_worker(&config, 64, w, shared.clone()).expect("worker"));
    }
    let all = ibex_alloc::alloc_counters().bytes_live();
    let per_worker = all.saturating_sub(one) / (WORKERS - 1);
    println!("[MEASUREMENT] {BACKENDS} backends: {per_worker} bytes per extra worker");
    // Measured: 153,424 bytes, the same at 200 backends (the engine's own tables). Before
    // T160, 30,068,057: 15 KB per backend.
    assert!(
        per_worker <= 256 * 1024,
        "an extra worker holds {per_worker} bytes for {BACKENDS} backends (bound 256 KB): \
         something per backend is copied into every worker"
    );
    drop(engines);
}
