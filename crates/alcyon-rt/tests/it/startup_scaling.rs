// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T188: building the shared state must scale linearly with the number of backends.

use alcyon_rt::Engine;
use std::time::Instant;

fn build_time(n: usize) -> f64 {
    let mut cfg = String::from("global\n    nbthread 1\ndefaults\n    mode http\n    timeout connect 5s\n    timeout client 5s\n    timeout server 5s\nfrontend fe\n    bind 127.0.0.1:0\n    default_backend b0\n");
    for i in 0..n {
        cfg.push_str(&format!("backend b{i}\n    server s{i} 127.0.0.1:{}\n", 20000 + i % 1000));
    }
    let config = alcyon_config::parse_str(&cfg).expect("config");
    let t = Instant::now();
    let shared = Engine::build_shared_state(&config).expect("build_shared_state");
    let d = t.elapsed().as_secs_f64();
    drop(shared);
    d
}

#[test]
fn build_shared_state_scales_linearly() {
    let small = (0..3).map(|_| build_time(10_000)).fold(f64::MAX, f64::min);
    let large = (0..3).map(|_| build_time(30_000)).fold(f64::MAX, f64::min);
    eprintln!("10k: {small:.3}s  30k: {large:.3}s  ratio {:.2}", large / small);
    assert!(large < small * 4.5, "30k backends took {:.2}x the time of 10k", large / small);
}
