// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T260): measures the CPU use of the test process, which every other test in a shared binary adds to

use ibex_rt::cpu::CpuMonitor;
use std::time::Duration;
use ibex_rt::stats::format_show_info;

#[test]
fn test_cpu_monitor_idle_and_load() {
    let mut monitor = CpuMonitor::new(Duration::from_millis(100));
    
    // Test idle
    std::thread::sleep(Duration::from_millis(200));
    let idle = monitor.idle_pct();
    assert!(idle > 80, "Expected high idle pct, got {}", idle);
    println!("Measured idle pct: {}", idle);
    
    // Test load
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_millis(200) {
        let _ = (0..1000).fold(0, |a, b| a ^ b);
    }
    let usage = monitor.usage_pct();
    assert!(usage > 0, "Expected >0 usage pct under load, got {}", usage);
    println!("Measured usage pct under load: {}", usage);
}

#[test]
fn test_show_info_idle_pct() {
    let out = format_show_info(std::time::Instant::now(), 1234, 10, 2, 5, 1000);
    assert!(out.contains("Idle_pct:"), "Expected Idle_pct in output");
}
