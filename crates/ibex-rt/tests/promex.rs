// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T260): installs its own #[global_allocator] to count what a scrape allocates.
// The families, types and label keys against HAProxy are in tests/it/prometheus_exporter.rs.

use ibex_config::ast::{BackendSection, Config, FrontendSection, Mode, Server};
use ibex_rt::engine::Engine;
use ibex_rt::promex::{self, Cursor};
use std::time::Duration;

/// One whole scrape through `scrape_chunk` into 16 KiB buffers, the chunks decoded.
fn scrape(engine: &Engine, uri: &str) -> String {
    let mut body = String::new();
    let mut cur = Cursor::start();
    let mut dst = vec![0u8; 16384];
    while !cur.finished {
        let n = promex::scrape_chunk(&mut cur, &engine.proxies, &engine.checks, 1, uri, &mut dst);
        let mut rest = std::str::from_utf8(&dst[..n]).expect("utf8");
        while let Some((len, after)) = rest.split_once("\r\n") {
            let len = usize::from_str_radix(len, 16).expect("hex");
            if len == 0 {
                break;
            }
            body.push_str(&after[..len]);
            rest = &after[len + 2..];
        }
    }
    body
}

fn render(engine: &Engine) -> String {
    scrape(engine, "/metrics")
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

/// Two servers without a check, set to the admin states `show stat` prints as MAINT and DRAIN,
/// and a tcp-mode proxy beside an http one.
fn states_engine() -> Engine {
    let mut servers: Vec<Server> = ["up", "maint", "drain"].iter().map(|n| Server::new(*n, "127.0.0.1:8080".parse().unwrap())).collect();
    for s in &mut servers {
        s.check = false;
    }
    let config = Config {
        frontends: vec![
            FrontendSection { name: "fe_http".into(), bind: Some("127.0.0.1:0".parse().unwrap()), mode: Mode::Http, default_backend: Some("be".into()), ..Default::default() },
            FrontendSection { name: "fe_tcp".into(), bind: Some("127.0.0.1:0".parse().unwrap()), mode: Mode::Tcp, default_backend: Some("be_tcp".into()), ..Default::default() },
        ],
        backends: vec![
            BackendSection { name: "be".into(), mode: Mode::Http, servers, ..Default::default() },
            BackendSection { name: "be_tcp".into(), mode: Mode::Tcp, servers: vec![Server::new("t1", "127.0.0.1:8081".parse().unwrap())], ..Default::default() },
        ],
        ..Default::default()
    };
    let engine = Engine::new(&config, 64).expect("Engine::new");
    let be = engine.proxies.iter().find(|p| p.name == "be").expect("be");
    be.server_statuses[0].store(ibex_rt::check::ServerStatus::Up as u8, std::sync::atomic::Ordering::Relaxed);
    be.server_statuses[1].store(ibex_rt::check::ServerStatus::Maint as u8, std::sync::atomic::Ordering::Relaxed);
    be.server_statuses[2].store(ibex_rt::check::ServerStatus::Drain as u8, std::sync::atomic::Ordering::Relaxed);
    engine
}

/// The `state` label of the one sample set to 1 for `server` in `haproxy_server_status`.
fn state_of(out: &str, server: &str) -> String {
    let prefix = format!("haproxy_server_status{{proxy=\"be\",server=\"{server}\",state=\"");
    let l = out.lines().find(|l| l.starts_with(&prefix) && l.ends_with(" 1")).unwrap_or_else(|| panic!("{server} in:\n{out}"));
    l[prefix.len()..].split('"').next().unwrap().to_string()
}

/// A server in maintenance or draining is the sample of its own state (the label set is
/// `DOWN UP MAINT DRAIN NOLB`, as HAProxy's), `no-maint` leaves the one in maintenance out,
/// and the metrics that only an HTTP proxy has are not printed for a tcp one.
#[test]
fn server_states_no_maint_and_tcp_proxies() {
    let engine = states_engine();
    let out = scrape(&engine, "/metrics?scope=server");
    assert_eq!(state_of(&out, "maint"), "MAINT");
    assert_eq!(state_of(&out, "drain"), "DRAIN");
    assert!(out.contains("haproxy_server_status{proxy=\"be\",server=\"maint\",state=\"NOLB\"} 0\n"), "{out}");
    let out = scrape(&engine, "/metrics?scope=server&no-maint");
    assert!(!out.contains("server=\"maint\""), "{out}");
    assert!(out.contains("server=\"drain\""), "{out}");
    // `hrsp_1xx` (http_responses_total) is an HTTP column: the tcp frontend has none.
    let out = scrape(&engine, "/metrics?scope=frontend&metrics=haproxy_frontend_http_responses_total");
    assert!(out.contains("proxy=\"fe_http\"") && !out.contains("proxy=\"fe_tcp\""), "{out}");
}

/// The query string is URL-decoded: `%XX` and `+`. A bad escape and a ninth `metrics=` are
/// refused (the scrape ends at once: `finished`, no byte written).
#[test]
fn the_query_string_is_url_decoded_and_a_bad_one_ends_the_scrape() {
    let engine = one_server_engine(false);
    // (`uptime` moves between two scrapes and the description is another test's: compare names.)
    let names = |b: &str| -> Vec<String> { b.lines().filter_map(|l| l.strip_prefix("# TYPE ")).map(|l| l.split(' ').next().unwrap().to_string()).filter(|n| n != "haproxy_process_description").collect() };
    let escaped = scrape(&engine, "/metrics?scope=%67lobal&x+y=1&no%2Dmaint");
    let plain = scrape(&engine, "/metrics?scope=global");
    assert!(!names(&plain).is_empty() && names(&escaped) == names(&plain), "{escaped}");
    assert!(promex::query_ok("/metrics?x+y=1"));
    for bad in ["/metrics?scope=%zz", "/metrics?scope=%6", "/metrics?scope=global+", "/metrics?metrics=a&metrics=b&metrics=c&metrics=d&metrics=e&metrics=f&metrics=g&metrics=h&metrics=i"] {
        assert!(!promex::query_ok(bad), "{bad}");
        let mut cur = Cursor::start();
        let mut dst = vec![0u8; 4096];
        let n = promex::scrape_chunk(&mut cur, &engine.proxies, &engine.checks, 1, bad, &mut dst);
        assert!(n == 0 && cur.finished, "{bad}: {n} bytes, finished {}", cur.finished);
    }
    assert!(promex::query_ok("/metrics?metrics=a&metrics=b&metrics=c&metrics=d&metrics=e&metrics=f&metrics=g&metrics=h"));
}

/// A buffer with less than `MIN_ROOM` free gets nothing and the cursor does not move; a unit
/// larger than a whole buffer ends the scrape rather than loop (a 10000-byte `description`
/// with `desc-labels` makes the `status` unit that big).
#[test]
fn a_small_buffer_gets_nothing_and_a_unit_too_big_ends_the_scrape() {
    let engine = one_server_engine(false);
    let mut cur = Cursor::start();
    let mut small = vec![0u8; promex::MIN_ROOM - 1];
    assert_eq!(promex::scrape_chunk(&mut cur, &engine.proxies, &engine.checks, 1, "/metrics", &mut small), 0);
    assert!(!cur.finished);

    let big = "d".repeat(10000);
    let fe = FrontendSection { name: "fe_big".into(), bind: Some("127.0.0.1:0".parse().unwrap()), mode: Mode::Http, description: Some(big.clone()), ..Default::default() };
    let engine = Engine::new(&Config { frontends: vec![fe], ..Default::default() }, 64).expect("Engine::new");
    let out = scrape(&engine, "/metrics?scope=frontend&desc-labels");
    // The units before the first oversized one are there; the scrape ended without the rest.
    let plain = scrape(&engine, "/metrics?scope=frontend");
    assert!(plain.contains("haproxy_frontend_status{proxy=\"fe_big\",state=\"UP\"} 1"), "{plain}");
    let samples = |b: &str| b.lines().filter(|l| l.starts_with("haproxy_frontend_")).count();
    assert!(samples(&out) > 0 && samples(&out) < samples(&plain), "{} of {} samples", samples(&out), samples(&plain));
}

/// `global description` is a family of its own and a `desc` label with `desc-labels`; a
/// proxy's `description` is the `desc` label of its samples. The one test of this binary
/// that sets the process-wide identity.
#[test]
fn descriptions_are_a_family_and_the_desc_label() {
    // A `node` that is empty has no sample, the other labelled families do.
    ibex_rt::stats::set_identity(Some(""), None);
    let out = scrape(&Engine::new(&Config::default(), 64).expect("Engine::new"), "/metrics?scope=global");
    assert!(!out.contains("haproxy_process_node"), "{out}");
    ibex_rt::stats::set_identity(Some("n1"), Some("blog edge"));
    let fe = FrontendSection { name: "fe_d".into(), bind: Some("127.0.0.1:0".parse().unwrap()), mode: Mode::Http, description: Some("front door".into()), ..Default::default() };
    let engine = Engine::new(&Config { frontends: vec![fe], ..Default::default() }, 64).expect("Engine::new");
    let out = scrape(&engine, "/metrics?scope=global");
    assert!(out.contains("# TYPE haproxy_process_description gauge\nhaproxy_process_description{desc=\"blog edge\"} 1\n"), "{out}");
    assert!(out.contains("haproxy_process_node{node=\"n1\"} 1\n"), "{out}");
    let out = scrape(&engine, "/metrics?scope=global&desc-labels");
    assert!(out.contains("haproxy_process_node{node=\"n1\",desc=\"blog edge\"} 1\n"), "{out}");
    assert!(out.contains("haproxy_process_uptime_seconds{desc=\"blog edge\"} "), "{out}");
    let out = scrape(&engine, "/metrics?scope=frontend&desc-labels&metrics=haproxy_frontend_current_sessions");
    assert!(out.contains("haproxy_frontend_current_sessions{proxy=\"fe_d\",desc=\"front door\"} 0\n"), "{out}");
    ibex_rt::stats::set_identity(None, None);
}

#[global_allocator]
static ALLOC: ibex_alloc::CountingAllocator = ibex_alloc::CountingAllocator::new();

/// A scrape allocates nothing, the first one included (T369): the scratch is made when the
/// engine starts, the output goes into the caller's buffer a chunk at a time, and what does
/// not fit waits for the next call. 5 frontends and 5 backends of 100 servers make about 10
/// buffers of output, so the resume path runs; the count over the whole scrape must be 0.
#[test]
fn a_scrape_allocates_nothing_the_first_one_included() {
    let mut frontends = Vec::new();
    let mut backends = Vec::new();
    for i in 0..5 {
        frontends.push(FrontendSection { name: format!("fe_{i}"), bind: Some("127.0.0.1:0".parse().unwrap()), mode: Mode::Http, ..Default::default() });
        let servers = (0..100).map(|j| Server::new(format!("s_{j}"), "127.0.0.1:80".parse().unwrap())).collect();
        backends.push(BackendSection { name: format!("be_{i}"), mode: Mode::Http, servers, ..Default::default() });
    }
    let engine = Engine::new(&Config { frontends, backends, ..Default::default() }, 64).expect("Engine::new");
    // `Engine::new` does this when a `use-service prometheus-exporter` rule is configured;
    // this config has none. It renders nothing: the first scrape below is a real first one.
    promex::prewarm();
    let mut dst = vec![0u8; 16384];
    for (label, uri) in [("first", "/metrics"), ("second", "/metrics"), ("scope=global", "/metrics?scope=global"), ("no-maint", "/metrics?scope=server&no-maint&desc-labels&metrics=-haproxy_server_weight")] {
        let mut cur = Cursor::start();
        let (mut chunks, mut bytes) = (0, 0);
        let before = ibex_alloc::thread_alloc_counters();
        while !cur.finished {
            let n = promex::scrape_chunk(&mut cur, &engine.proxies, &engine.checks, 1, uri, &mut dst);
            chunks += usize::from(n > 0);
            bytes += n;
        }
        let diff = before.diff(&ibex_alloc::thread_alloc_counters());
        println!("{label}: {} allocs, {} bytes allocated, {chunks} chunks, {bytes} bytes out", diff.alloc_count, diff.bytes_allocated);
        assert_eq!(diff.alloc_count, 0, "{label}: a scrape must not allocate");
        if uri == "/metrics" {
            assert!(chunks >= 8, "{label}: {chunks} chunks; the resume path is not exercised");
        }
    }
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
