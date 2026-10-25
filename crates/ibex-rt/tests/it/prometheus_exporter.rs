// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `http-request use-service prometheus-exporter` (T368), against a scrape of HAProxy
//! 3.5-dev8-885761-29 built with USE_PROMEX=1 (the shipped binary is built without PROMEX).
//! Measured there: 200, `cache-control: no-cache`, `content-type: text/plain; version=0.0.4`,
//! `transfer-encoding: chunked`; `HEAD` the head only; `scope=` an empty body; `scope=bogus`
//! the 400 page; `use-service` ends the rules. Families, types and label keys are compared
//! with `tests/data/promex_oracle_families.txt`, values are compared by presence.

use crate::common;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::Engine;

const CFG: &str = "defaults
  mode http
  timeout connect 1s
  timeout client 5s
  timeout server 5s
frontend fe
  bind @FE@
  http-request use-service prometheus-exporter if { path /metrics }
  http-request deny
  default_backend be
backend be
  server s1 127.0.0.1:@S1@ check
  server s2 127.0.0.1:@S2@ check
";

/// What HAProxy prints for this config and Ibex does not, with why. The test fails when this
/// list and the scrape disagree, so docs/differences.md cannot drift from the code.
const OMITTED: &[&str] = &[
    // counted by nothing in Ibex: connection pool gauges, last session age, bytes by direction,
    // the interception counter, the cache hint counter
    "haproxy_backend_http_cache_hint_hits_total",
    "haproxy_backend_last_session_seconds",
    "haproxy_backend_req_bytes_in_total",
    "haproxy_backend_req_bytes_out_total",
    "haproxy_backend_res_bytes_in_total",
    "haproxy_backend_res_bytes_out_total",
    "haproxy_frontend_http_cache_hint_hits_total",
    "haproxy_frontend_intercepted_requests_total",
    "haproxy_frontend_req_bytes_in_total",
    "haproxy_frontend_req_bytes_out_total",
    "haproxy_frontend_res_bytes_in_total",
    "haproxy_frontend_res_bytes_out_total",
    "haproxy_server_idle_connections_current",
    "haproxy_server_last_session_seconds",
    "haproxy_server_need_connections_current",
    "haproxy_server_private_idle_connections_current",
    "haproxy_server_req_bytes_in_total",
    "haproxy_server_req_bytes_out_total",
    "haproxy_server_res_bytes_in_total",
    "haproxy_server_res_bytes_out_total",
    "haproxy_server_safe_idle_connections_current",
    "haproxy_server_unsafe_idle_connections_current",
    "haproxy_server_used_connections_current",
    // the aggregate check states, the per-state check status, agent checks
    "haproxy_backend_agg_check_status",
    "haproxy_backend_agg_server_check_status",
    "haproxy_backend_agg_server_status",
    "haproxy_server_check_status",
    // Ibex has no resolvers
    "haproxy_resolver_any_err",
    "haproxy_resolver_cname",
    "haproxy_resolver_cname_error",
    "haproxy_resolver_invalid",
    "haproxy_resolver_nx",
    "haproxy_resolver_other",
    "haproxy_resolver_outdated",
    "haproxy_resolver_refused",
    "haproxy_resolver_send_error",
    "haproxy_resolver_sent",
    "haproxy_resolver_tcp_fallback",
    "haproxy_resolver_timeout",
    "haproxy_resolver_too_big",
    "haproxy_resolver_truncated",
    "haproxy_resolver_update",
    "haproxy_resolver_valid",
];

struct Run {
    fe: SocketAddr,
    engine: Engine,
}

fn start() -> Run {
    let fe = common::reserve_addr();
    let cfg = CFG.replace("@FE@", &fe.to_string()).replace("@S1@", &common::reserve_port().to_string()).replace("@S2@", &common::reserve_port().to_string());
    let config = ibex_config::parse_str(&cfg).expect("parse");
    let mut run = Run { fe, engine: Engine::new(&config, 64).expect("Engine::new") };
    // The checks connect to nothing and fail: servers down, check codes and durations known.
    run.settle(Duration::from_millis(1500));
    run
}

impl Run {
    fn settle(&mut self, d: Duration) {
        let deadline = Instant::now() + d;
        while Instant::now() < deadline {
            let _ = self.engine.run_once();
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// Sends `req` and returns the whole answer (the client closes after it).
    fn ask(&mut self, req: &str) -> String {
        let fe = self.fe;
        let req = req.to_string();
        let client = thread::spawn(move || {
            let mut s = TcpStream::connect(fe).expect("connect");
            s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
            s.write_all(req.as_bytes()).expect("send");
            let mut out = Vec::new();
            let _ = s.read_to_end(&mut out);
            String::from_utf8_lossy(&out).into_owned()
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        while !client.is_finished() && Instant::now() < deadline {
            let _ = self.engine.run_once();
            thread::sleep(Duration::from_millis(1));
        }
        client.join().expect("client")
    }

    fn get(&mut self, target: &str) -> String {
        self.ask(&format!("GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
    }
}

/// The body of a chunked answer.
fn body_of(answer: &str) -> String {
    let (_, mut rest) = answer.split_once("\r\n\r\n").expect("head");
    let mut body = String::new();
    loop {
        let (len, after) = rest.split_once("\r\n").expect("chunk size");
        let n = usize::from_str_radix(len, 16).expect("hex");
        if n == 0 {
            return body;
        }
        body.push_str(&after[..n]);
        rest = &after[n + 2..];
    }
}

/// family -> (type, label keys), and family -> label sets of its samples.
fn families(body: &str) -> BTreeMap<String, (String, String)> {
    let mut f = BTreeMap::new();
    let mut types = BTreeMap::new();
    for l in body.lines() {
        if let Some(t) = l.strip_prefix("# TYPE ") {
            let (n, ty) = t.split_once(' ').expect("type line");
            types.insert(n.to_string(), ty.to_string());
        } else if !l.starts_with('#') {
            let head = l.rsplit_once(' ').expect("sample").0;
            let (name, keys) = match head.split_once('{') {
                None => (head, "-".to_string()),
                Some((n, lab)) => {
                    let lab = lab.trim_end_matches('}');
                    let keys: Vec<&str> = lab.split(',').map(|kv| kv.split('=').next().unwrap_or("")).collect();
                    (n, keys.join(","))
                }
            };
            let ty = types.get(name).unwrap_or_else(|| panic!("sample before its TYPE: {l}")).clone();
            let e = f.entry(name.to_string()).or_insert((ty, keys.clone()));
            assert_eq!(e.1, keys, "label keys of {name} differ between samples");
        }
    }
    f
}

#[test]
fn a_scrape_has_the_oracles_head_and_families() {
    let mut run = start();
    let answer = run.get("/metrics");
    let head = answer.split("\r\n\r\n").next().expect("head");
    let lines: Vec<&str> = head.lines().collect();
    assert_eq!(
        lines,
        ["HTTP/1.1 200 OK", "cache-control: no-cache", "content-type: text/plain; version=0.0.4", "transfer-encoding: chunked", "connection: close"],
        "{head}"
    );
    let ours = families(&body_of(&answer));

    let oracle = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/promex_oracle_families.txt")).expect("oracle");
    let mut theirs = BTreeMap::new();
    for l in oracle.lines().filter(|l| !l.starts_with('#')) {
        let mut w = l.split(' ');
        theirs.insert(w.next().expect("name").to_string(), (w.next().expect("type").to_string(), w.next().expect("keys").to_string()));
    }
    for (name, v) in &ours {
        assert_eq!(theirs.get(name), Some(v), "{name} differs from HAProxy's (type, label keys)");
    }
    let missing: BTreeSet<&str> = theirs.keys().filter(|n| !ours.contains_key(*n)).map(String::as_str).collect();
    let documented: BTreeSet<&str> = OMITTED.iter().copied().collect();
    assert_eq!(missing, documented, "families HAProxy has and Ibex leaves out, against the documented list");
    assert!(ours.len() > 150, "{} families", ours.len());
}

#[test]
fn the_samples_are_the_proxies_and_servers_of_the_config() {
    let mut run = start();
    let body = body_of(&run.get("/metrics"));
    let mut seen: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for l in body.lines().filter(|l| !l.starts_with('#')) {
        let kind = if l.starts_with("haproxy_frontend_") {
            "frontend"
        } else if l.starts_with("haproxy_backend_") {
            "backend"
        } else if l.starts_with("haproxy_server_") {
            "server"
        } else {
            continue;
        };
        let lab = l.split_once('{').expect("labels").1.split_once('}').expect("close").0;
        let id: Vec<&str> = lab.split(',').filter(|kv| kv.starts_with("proxy=") || kv.starts_with("server=")).collect();
        seen.entry(kind).or_default().insert(id.join(","));
    }
    assert_eq!(seen["frontend"], BTreeSet::from(["proxy=\"fe\"".to_string()]));
    assert_eq!(seen["backend"], BTreeSet::from(["proxy=\"be\"".to_string()]));
    assert_eq!(seen["server"], BTreeSet::from(["proxy=\"be\",server=\"s1\"".to_string(), "proxy=\"be\",server=\"s2\"".to_string()]));
    // The servers are checked and down: the state words say so, in HAProxy's order.
    for s in ["s1", "s2"] {
        let want = format!("haproxy_server_status{{proxy=\"be\",server=\"{s}\",state=\"DOWN\"}} 1\n");
        assert!(body.contains(&want), "{want} in:\n{body}");
    }
    assert!(body.contains("haproxy_frontend_status{proxy=\"fe\",state=\"UP\"} 1\n"), "{body}");
}

#[test]
fn use_service_ends_the_rules_and_other_paths_are_not_served() {
    let mut run = start();
    // `http-request deny` follows the rule: a scrape is still answered.
    let a = run.get("/metrics");
    assert!(a.starts_with("HTTP/1.1 200 OK\r\n"), "{a}");
    // The condition is a path: elsewhere the next rule (deny) answers.
    let b = run.get("/other");
    assert!(b.starts_with("HTTP/1.1 403"), "{b}");
}

#[test]
fn the_query_string_picks_the_scope_and_a_bad_one_is_a_400() {
    let mut run = start();
    let only = |run: &mut Run, q: &str| -> BTreeSet<String> {
        let b = body_of(&run.get(&format!("/metrics?{q}")));
        b.lines().filter(|l| !l.starts_with('#')).filter_map(|l| l.strip_prefix("haproxy_")).map(|l| l.split('_').next().unwrap_or("").to_string()).collect()
    };
    assert_eq!(only(&mut run, "scope=global"), BTreeSet::from(["process".to_string()]));
    assert_eq!(only(&mut run, "scope=server"), BTreeSet::from(["server".to_string()]));
    assert_eq!(only(&mut run, "scope=frontend&scope=backend"), BTreeSet::from(["frontend".to_string(), "backend".to_string()]));
    let all = only(&mut run, "no-maint&extra-counters");
    assert_eq!(all, BTreeSet::from(["process", "frontend", "backend", "server"].map(String::from)));
    // `scope=` is a valid, empty scrape.
    let empty = run.get("/metrics?scope=");
    assert!(empty.starts_with("HTTP/1.1 200 OK\r\n") && body_of(&empty).is_empty(), "{empty}");
    for bad in ["scope=bogus", "scope", "scope=a=b", "x=%zz"] {
        let r = run.get(&format!("/metrics?{bad}"));
        assert!(r.starts_with("HTTP/1.1 400 Bad request\r\n") && r.contains("Your browser sent an invalid request."), "{bad}: {r}");
    }
    // `metrics=` keeps the families asked for, `-name` drops one.
    let b = body_of(&run.get("/metrics?metrics=haproxy_process_uptime_seconds,haproxy_frontend_status"));
    let names: Vec<&str> = b.lines().filter_map(|l| l.strip_prefix("# TYPE ")).map(|l| l.split(' ').next().unwrap_or("")).collect();
    assert_eq!(names, ["haproxy_process_uptime_seconds", "haproxy_frontend_status"]);
    let b = body_of(&run.get("/metrics?scope=global&metrics=-haproxy_process_uptime_seconds"));
    assert!(!b.contains("haproxy_process_uptime_seconds") && b.contains("haproxy_process_nbthread"), "{b}");
}

#[test]
fn head_gets_the_head_only_and_the_method_does_not_matter_otherwise() {
    let mut run = start();
    let h = run.ask("HEAD /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(h.starts_with("HTTP/1.1 200 OK\r\n") && h.ends_with("\r\n\r\n") && !h.contains("# TYPE"), "{h:?}");
    let p = run.ask("POST /metrics HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    assert!(p.starts_with("HTTP/1.1 200 OK\r\n") && p.contains("# TYPE haproxy_process_uptime_seconds gauge"), "{p}");
}

/// The memory numbers are `show info`'s: the same names in both, and the process memory
/// families are served. A burst of held connections raises the pool and connection numbers,
/// and they come back.
#[test]
fn memory_and_connection_metrics_move_with_a_burst() {
    let mut run = start();
    let read = |body: &str, name: &str| -> f64 {
        body.lines().find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix(' '))).unwrap_or_else(|| panic!("{name} in {body}")).parse().expect("number")
    };
    for fam in ["haproxy_process_max_memory_bytes", "haproxy_process_pool_allocated_bytes", "haproxy_process_pool_used_bytes", "haproxy_process_pool_failures_total", "haproxy_process_current_connections"] {
        assert!(body_of(&run.get("/metrics")).contains(&format!("# TYPE {fam} ")), "{fam}");
    }
    let before = body_of(&run.get("/metrics"));
    // 30 clients connect and send half a request: the sessions and their buffers are held.
    let fe = run.fe;
    let held: Vec<TcpStream> = (0..30)
        .map(|_| {
            let mut s = TcpStream::connect(fe).expect("connect");
            s.write_all(b"GET /other HTTP/1.1\r\nHost: x\r\n").expect("send");
            s
        })
        .collect();
    // The engine takes the 30 connections as its thread gets to them: scrape until they show
    // (up to 20 s), not after a fixed second.
    let deadline = Instant::now() + Duration::from_secs(20);
    let during = loop {
        run.settle(Duration::from_millis(250));
        let b = body_of(&run.get("/metrics"));
        if read(&b, "haproxy_process_current_connections") >= read(&before, "haproxy_process_current_connections") + 30.0 || Instant::now() > deadline {
            break b;
        }
    };
    assert!(read(&during, "haproxy_process_current_connections") >= read(&before, "haproxy_process_current_connections") + 30.0, "connections: {} then {}", read(&before, "haproxy_process_current_connections"), read(&during, "haproxy_process_current_connections"));
    assert!(read(&during, "haproxy_process_pool_used_bytes") > read(&before, "haproxy_process_pool_used_bytes"), "pool use rises with the held sessions");
    drop(held);
    let deadline = Instant::now() + Duration::from_secs(20);
    let after = loop {
        run.settle(Duration::from_millis(250));
        let b = body_of(&run.get("/metrics"));
        if read(&b, "haproxy_process_current_connections") <= read(&before, "haproxy_process_current_connections") + 1.0 || Instant::now() > deadline {
            break b;
        }
    };
    assert!(read(&after, "haproxy_process_current_connections") <= read(&before, "haproxy_process_current_connections") + 1.0, "connections come back");
    // Q2 (S4): the burst's slots are kept, as `HAProxy` keeps its pools, and only `pool_gc` gives
    // them back; the use must not grow past the peak (a scrape or two may take a slot more).
    assert!(read(&after, "haproxy_process_pool_used_bytes") <= read(&during, "haproxy_process_pool_used_bytes") + 16384.0, "pool use grows after the burst: {} then {} then {}", read(&before, "haproxy_process_pool_used_bytes"), read(&during, "haproxy_process_pool_used_bytes"), read(&after, "haproxy_process_pool_used_bytes"));
    // `show info` reads the same sources.
    let mut pairs = ibex_rt::stats::InfoPairs::default();
    ibex_rt::stats::process_info_pairs(&mut pairs, &run.engine.proxies);
    let info = pairs.pairs();
    for (k, fam) in [("PoolAlloc_bytes", "haproxy_process_pool_allocated_bytes"), ("Memmax_bytes", "haproxy_process_max_memory_bytes"), ("PoolFailed", "haproxy_process_pool_failures_total")] {
        let v = info.iter().find(|(n, _)| *n == k).expect(k).1.parse::<f64>().expect("number");
        assert!((read(&after, fam) - v).abs() <= v.max(1.0) * 0.5 + 65536.0, "{fam} and {k} disagree: {} vs {v}", read(&after, fam));
    }
}

/// A scrape bigger than the response buffer, read slowly by the client: the producer fills the
/// buffer, waits for the client to take some, compacts and goes on (`pump`), and the client
/// gets the whole body, well formed, ending with the closing chunk.
#[test]
fn a_slow_reader_gets_the_whole_scrape_through_a_full_buffer() {
    let fe = common::reserve_addr();
    let mut cfg = format!("defaults\n  mode http\n  timeout connect 1s\n  timeout client 10s\n  timeout server 5s\nfrontend fe\n  bind {fe}\n  http-request use-service prometheus-exporter\nbackend be\n");
    for i in 0..400 {
        cfg.push_str(&format!("  server s{i} 127.0.0.1:{}\n", 20000 + i));
    }
    let config = ibex_config::parse_str(&cfg).expect("parse");
    let mut engine = Engine::new(&config, 64).expect("Engine::new");
    let client = thread::spawn(move || {
        let mut s = TcpStream::connect(fe).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
        s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
        let mut out = Vec::new();
        let mut buf = [0u8; 2048];
        loop {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
            thread::sleep(Duration::from_millis(2));
        }
        String::from_utf8_lossy(&out).into_owned()
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let answer = client.join().expect("client");
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n") && answer.ends_with("0\r\n\r\n"), "{}", &answer[..answer.len().min(200)]);
    let body = body_of(&answer);
    assert!(body.len() > 300_000, "{} bytes", body.len());
    assert_eq!(body.lines().filter(|l| l.starts_with("haproxy_server_status{") && l.contains("server=\"s399\"")).count(), 5);
}
