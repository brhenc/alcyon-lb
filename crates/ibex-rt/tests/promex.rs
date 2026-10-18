// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T260): installs its own #[global_allocator] to count what a scrape allocates.
// The families, types and label keys against HAProxy are in tests/it/prometheus_exporter.rs.

use ibex_config::ast::{BackendSection, Config, FrontendSection, Mode, Server};
use ibex_rt::engine::Engine;
use ibex_rt::promex::{self, Query};
use std::time::Duration;

fn render(engine: &Engine) -> String {
    let mut out = String::new();
    promex::render(&engine.proxies, &engine.checks, 1, &Query::default(), &mut out);
    out
}

fn one_server_engine(check: bool) -> Engine {
    let fe = FrontendSection {
        name: "fe_http".into(),
        bind: Some("127.0.0.1:0".parse().unwrap()),
        mode: Mode::Http,
        default_backend: Some("be_http".into()),
        clitimeout: Some(Duration::from_secs(5)),
        ..Default::default()
    };
    let mut srv = Server::new("s1", "127.0.0.1:8080".parse().unwrap());
    srv.check = check;
    let config = Config {
        frontends: vec![fe],
        backends: vec![BackendSection {
            name: "be_http".into(),
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(5)),
            srvtimeout: Some(Duration::from_secs(5)),
            servers: vec![srv],
            ..Default::default()
        }],
        ..Default::default()
    };
    Engine::new(&config, 64).expect("Engine::new")
}

/// A server without `check` has no check counters: HAProxy leaves the field empty
/// (stats-proxy.c, ST_I_PX_CHKFAIL/CHKDOWN), prints NaN, and the family takes its type from
/// that empty value, gauge. Measured with HAProxy 3.5-dev8 built with PROMEX. With `check` the
/// counters exist: a number, and the family is a counter (`FN_COUNTER`).
#[test]
fn check_counters_are_nan_gauges_without_a_check_and_counters_with_one() {
    let out = render(&one_server_engine(false));
    for family in ["haproxy_server_check_failures_total", "haproxy_server_check_up_down_total"] {
        assert!(out.contains(&format!("# TYPE {family} gauge\n")), "{family} in:\n{out}");
        let line = format!("{family}{{proxy=\"be_http\",server=\"s1\"}} NaN\n");
        assert!(out.contains(&line), "expected `{line}` in:\n{out}");
    }
    let out = render(&one_server_engine(true));
    for family in ["haproxy_server_check_failures_total", "haproxy_server_check_up_down_total"] {
        assert!(out.contains(&format!("# TYPE {family} counter\n")), "{family} type in:\n{out}");
        let line = format!("{family}{{proxy=\"be_http\",server=\"s1\"}} 0\n");
        assert!(out.contains(&line), "expected `{line}` in:\n{out}");
    }
}

#[global_allocator]
static ALLOC: ibex_alloc::CountingAllocator = ibex_alloc::CountingAllocator::new();

/// What a scrape allocates. It was 0 for the hand-written renderer, which printed made-up
/// values for the proxies (T368 replaced it by the `show stat` rows and the `show info`
/// pairs, so that a number here is the number there). Now it is the cost of those: a number of
/// allocations per row and per `show info` field that does not depend on traffic, and none in
/// the rendering itself once `out` has room. The bound below is generous per row; the count
/// printed is the measurement.
#[test]
fn scrape_allocations_are_per_row_and_bounded() {
    let mut frontends = Vec::new();
    let mut backends = Vec::new();
    let (n_px, n_srv) = (10usize, 20usize);
    for i in 0..n_px {
        frontends.push(FrontendSection { name: format!("fe_{i}"), bind: Some("127.0.0.1:0".parse().unwrap()), mode: Mode::Http, ..Default::default() });
        let servers = (0..n_srv).map(|j| Server::new(format!("s_{j}"), "127.0.0.1:80".parse().unwrap())).collect();
        backends.push(BackendSection { name: format!("be_{i}"), mode: Mode::Http, servers, ..Default::default() });
    }
    let engine = Engine::new(&Config { frontends, backends, ..Default::default() }, 64).expect("Engine::new");
    let mut out = String::with_capacity(8 * 1024 * 1024);
    promex::render(&engine.proxies, &engine.checks, 1, &Query::default(), &mut out); // warm up
    out.clear();
    let before = ibex_alloc::alloc_counters();
    promex::render(&engine.proxies, &engine.checks, 1, &Query::default(), &mut out);
    let diff = before.diff(&ibex_alloc::alloc_counters());
    let rows = n_px * (n_srv + 2);
    println!("Allocations: {} allocs, {} bytes, for {rows} rows ({} per row)", diff.alloc_count, diff.bytes_allocated, diff.alloc_count / rows);
    assert!(diff.alloc_count < rows * 600 + 2000, "a scrape allocates per row, not more: {} allocs", diff.alloc_count);
    // Only the process section, which a memory-only scrape asks for, is cheap and constant.
    let q = promex::parse_query("/metrics?scope=global").expect("query");
    out.clear();
    let before = ibex_alloc::alloc_counters();
    promex::render(&engine.proxies, &engine.checks, 1, &q, &mut out);
    let diff = before.diff(&ibex_alloc::alloc_counters());
    println!("scope=global: {} allocs, {} bytes", diff.alloc_count, diff.bytes_allocated);
    assert!(diff.alloc_count < 200, "scope=global: {} allocs", diff.alloc_count);
}

fn failing_pool() -> Option<ibex_alloc::PoolHead> {
    Some(ibex_alloc::PoolHead {
        name: "memmax_test",
        size: 64,
        align: 8,
        allocated: 4,
        alloc_bytes: 256,
        used: 2,
        cached: 0,
        needed_avg: 2,
        failures: 7,
        users: 1,
        reg: None,
    })
}

/// `PoolFailed` and the four `haproxy_process_*` memory metrics read the counters through
/// the pool registry (the sum of every provider's `failures`) and the `-m` budget. Nothing in
/// the data path increments a pool's `failures` yet (the fallible buffer take is a later
/// slice), so this test registers a provider that reports 7 failures rather than provoking
/// one. Names, HELP texts and types are from HAProxy's source, not measured: the reference
/// binary is built without PROMEX (src/stats.c:106-112 `.alt_name`/`.desc`; promex gives a
/// `FN_COUNTER` field the counter type, `FN_LIMIT` and the rest gauge).
#[test]
fn memory_metrics_and_pool_failed() {
    ibex_alloc::global_pool_registry().register_provider("memmax_test", failing_pool);
    ibex_rt::globalconn::set_memmax_mb(64);

    let info = ibex_rt::stats::format_show_info(std::time::Instant::now(), 1, 0, 0, 0, 0);
    assert!(info.lines().any(|l| l == "PoolFailed: 7"), "{info}");
    assert!(info.lines().any(|l| l == "Memmax_MB: 64"), "{info}");
    assert!(info.lines().any(|l| l == "Memmax_bytes: 67108864"), "{info}");

    let out = render(&Engine::new(&Config::default(), 64).expect("Engine::new"));
    for (name, ty, help, value) in [
        ("haproxy_process_max_memory_bytes", "gauge", "Worker process's hard limit on memory usage in bytes (-m on command line)", "67108864"),
        ("haproxy_process_pool_allocated_bytes", "gauge", "Amount of memory allocated in pools (in bytes)", ""),
        ("haproxy_process_pool_used_bytes", "gauge", "Amount of pool memory currently used (in bytes)", ""),
        ("haproxy_process_pool_failures_total", "counter", "Number of failed pool allocations since this worker was started", "7"),
    ] {
        assert!(out.contains(&format!("# HELP {name} {help}\n# TYPE {name} {ty}\n{name} {value}")), "{name} in:\n{out}");
    }
}
