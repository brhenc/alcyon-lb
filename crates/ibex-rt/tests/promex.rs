// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

pub use ibex_rt::engine;
pub use ibex_rt::check;

#[path = "../src/promex.rs"]
pub mod promex;

use ibex_config::ast::{BackendSection, Config, FrontendSection, Mode, Server};
use ibex_rt::engine::Engine;
use std::collections::HashMap;
use std::time::Duration;

fn parse_prom_metrics(output: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in output.lines() {
        if line.starts_with("# TYPE ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 4 {
                map.insert(parts[2].to_string(), parts[3].to_string());
            }
        }
    }
    map
}

#[test]
fn differential_test() {
    let fe = FrontendSection {
        name: "fe_http".into(),
        bind: Some("127.0.0.1:0".parse().unwrap()),
        mode: Mode::Http,
        default_backend: Some("be_http".into()),
        clitimeout: Some(Duration::from_secs(5)),
        ..Default::default()
    };
    
    let config = Config {
        frontends: vec![fe],
        backends: vec![BackendSection {
            name: "be_http".into(),
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(5)),
            srvtimeout: Some(Duration::from_secs(5)),
            servers: vec![Server::new("s1", "127.0.0.1:8080".parse().unwrap())],
            ..Default::default()
        }],
        ..Default::default()
    };

    let engine = Engine::new(&config, 64).expect("Engine::new");
    let stats = promex::StatsSnapshot {
        proxies: &engine.proxies,
        checks: &engine.checks,
        start_time: engine.start_time,
        pid: 1,
        total_tasks: 10,
        run_queue_len: 2,
        active_conns: 15,
        max_conns: 1000,
    };
    
    let mut ibex_out = String::new();
    promex::render(&stats, &mut ibex_out);
    
    let ibex_metrics = parse_prom_metrics(&ibex_out);

    // A server without `check` has no check counters: HAProxy leaves the field empty
    // (stats-proxy.c, ST_I_PX_CHKFAIL/CHKDOWN), prints NaN, and the family takes its type
    // from that empty value, gauge. Measured with HAProxy 3.5-dev7 (see the oracle file).
    for family in ["haproxy_server_check_failures_total", "haproxy_server_check_up_down_total"] {
        let line = format!("{family}{{proxy=\"be_http\",server=\"s1\"}} NaN");
        assert!(ibex_out.contains(&line), "expected `{line}` in:\n{ibex_out}");
    }
    
    // The oracle, captured from HAProxy and kept with the tests (how: see the file's header).
    // It was read from /tmp/oracle_metrics.txt, which nothing in the repository wrote, so the
    // test failed on every machine but the one it was written on.
    let oracle_str = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/promex_oracle_types.txt"))
        .expect("read the promex oracle");
    let oracle_metrics = parse_prom_metrics(&oracle_str);
    
    let mut missing_in_ibex = Vec::new();
    for name in oracle_metrics.keys() {
        if !ibex_metrics.contains_key(name) {
            missing_in_ibex.push(name.clone());
        }
    }
    
    for (name, typ) in &ibex_metrics {
        assert!(oracle_metrics.contains_key(name), "Ibex invented metric {name} which HAProxy does not have");
        assert_eq!(oracle_metrics.get(name).unwrap(), typ, "Type mismatch for {name}");
    }
    
    missing_in_ibex.sort();
    println!("--- Metrics HAProxy emits that Ibex cannot yet: ---");
    for m in &missing_in_ibex {
        println!("{m}");
    }
    println!("---------------------------------------------------");
    println!("Ibex emits {} metrics.", ibex_metrics.len());
    println!("HAProxy emits {} metrics.", oracle_metrics.len());
}

/// With `check` on the server the counters exist: a number, and the family is a counter
/// (`ST_I_PX_CHKFAIL`/`CHKDOWN` are `FN_COUNTER` in stats-proxy.c).
#[test]
fn check_counters_of_a_checked_server_are_counters() {
    let mut srv = Server::new("s1", "127.0.0.1:8080".parse().unwrap());
    srv.check = true;
    let config = Config {
        backends: vec![BackendSection {
            name: "be_http".into(),
            mode: Mode::Http,
            servers: vec![srv],
            ..Default::default()
        }],
        ..Default::default()
    };
    let engine = Engine::new(&config, 64).expect("Engine::new");
    let stats = promex::StatsSnapshot {
        proxies: &engine.proxies,
        checks: &engine.checks,
        start_time: engine.start_time,
        pid: 1,
        total_tasks: 0,
        run_queue_len: 0,
        active_conns: 0,
        max_conns: 0,
    };
    let mut out = String::new();
    promex::render(&stats, &mut out);
    for family in ["haproxy_server_check_failures_total", "haproxy_server_check_up_down_total"] {
        assert!(out.contains(&format!("# TYPE {family} counter\n")), "{family} type in:\n{out}");
        let line = format!("{family}{{proxy=\"be_http\",server=\"s1\"}} 0\n");
        assert!(out.contains(&line), "expected `{line}` in:\n{out}");
    }
}

#[global_allocator]
static ALLOC: ibex_alloc::CountingAllocator = ibex_alloc::CountingAllocator::new();

#[test]
fn test_allocations() {
    let mut frontends = Vec::new();
    let mut backends = Vec::new();
    for i in 0..100 {
        frontends.push(FrontendSection {
            name: format!("fe_{i}"),
            bind: Some("127.0.0.1:0".parse().unwrap()),
            mode: Mode::Http,
            ..Default::default()
        });
        
        let mut servers = Vec::new();
        for j in 0..600 {
            servers.push(Server::new(format!("s_{j}"), "127.0.0.1:80".parse().unwrap()));
        }
        
        backends.push(BackendSection {
            name: format!("be_{i}"),
            mode: Mode::Http,
            servers,
            ..Default::default()
        });
    }
    
    let config = Config {
        frontends,
        backends,
        ..Default::default()
    };
    
    let engine = Engine::new(&config, 64).expect("Engine::new");
    let stats = promex::StatsSnapshot {
        proxies: &engine.proxies,
        checks: &engine.checks,
        start_time: engine.start_time,
        pid: 1,
        total_tasks: 10,
        run_queue_len: 2,
        active_conns: 15,
        max_conns: 1000,
    };
    
    let mut out = String::with_capacity(10 * 1024 * 1024);
    
    // warmup
    promex::render(&stats, &mut out);
    out.clear();
    
    let before = ibex_alloc::alloc_counters();
    promex::render(&stats, &mut out);
    let after = ibex_alloc::alloc_counters();
    
    let diff = before.diff(&after);
    println!("Allocations: {} allocs, {} bytes", diff.alloc_count, diff.bytes_allocated);
    assert_eq!(diff.alloc_count, 0, "rendering must not allocate");
}
