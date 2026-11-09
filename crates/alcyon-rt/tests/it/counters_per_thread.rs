// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.alcyon.counters per-thread` (T582, `docs/design/per-thread-counters-2026-11-02.md`):
//! each thread writes its own counter rows and the readers sum them, so `show stat`, `show
//! info` and the Prometheus scrape read the same with the setting on and off, over the same
//! configuration and traffic (§4: the totals exactly; the rates, the averages of the timings
//! and the ages are left out, being functions of when they are read). `clear counters all`
//! zeroes the rows of every thread (the owner clears its own, a reader counts a stale one as
//! zero), and counting starts again from zero.
//!
//! The rows are an `alcyon_alloc` arena (AGENTS.md §8): `show pools` lists them as pool
//! `counters`, and the start prints their size.

use crate::common;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

/// An HTTP/1.1 server that answers every request `200` with `ok`, keeping the connection
/// unless the request said `Connection: close`.
fn backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for c in listener.incoming().flatten() {
            thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(10))).ok();
                let mut w = c.try_clone().expect("clone");
                let mut r = BufReader::new(c);
                loop {
                    let (mut len, mut close, mut any) = (0usize, false, false);
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        if line == "\r\n" && any {
                            break;
                        }
                        any = true;
                        let l = line.to_ascii_lowercase();
                        if let Some(v) = l.strip_prefix("content-length:") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                        close |= l.starts_with("connection:") && l.contains("close");
                    }
                    let mut body = vec![0u8; len];
                    if r.read_exact(&mut body).is_err() {
                        return;
                    }
                    let head = if close { "Connection: close\r\n" } else { "" };
                    if w.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n{head}\r\nok").as_bytes()).is_err() || close {
                        return;
                    }
                }
            });
        }
    });
    port
}

/// Reads one response off `r`: its status and body (by `Content-Length`).
fn response(r: &mut BufReader<TcpStream>) -> (String, Vec<u8>) {
    let mut status = String::new();
    r.read_line(&mut status).expect("status line");
    let mut len = 0usize;
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).expect("header") == 0 || line == "\r\n" {
            break;
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).expect("body");
    (status.split(' ').nth(1).unwrap_or("").to_string(), body)
}

/// A CLI command to `d`, counted: each CLI connection is a stream (`CumStreams`), and
/// [`compare`] evens the counts of the two daemons out before it reads them.
fn cli(d: &Daemon, cmd: &str) -> String {
    d.cli_calls.set(d.cli_calls.get() + 1);
    let mut c = UnixStream::connect(&d.sock).expect("connect cli");
    c.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = String::new();
    c.read_to_string(&mut out).expect("read");
    out
}

struct Daemon {
    alcyon: common::Alcyon,
    sock: PathBuf,
    cfg: PathBuf,
    http: u16,
    tcp: u16,
    prom: u16,
    cli_calls: std::cell::Cell<u64>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.alcyon);
        let _ = std::fs::remove_file(&self.sock);
        let _ = std::fs::remove_file(&self.cfg);
    }
}

fn start(tag: &str, nbthread: usize, mode: Option<&str>, live: u16, dead: u16, stderr: Stdio) -> Daemon {
    let (http, tcp, prom) = (common::reserve_port(), common::reserve_port(), common::reserve_port());
    let dir = std::env::temp_dir();
    let id = format!("alcyon_t582_{tag}_{nbthread}_{}", std::process::id());
    let sock = dir.join(format!("{id}.sock"));
    let cfg = dir.join(format!("{id}.cfg"));
    let setting = mode.map_or(String::new(), |m| format!("  tune.alcyon.counters {m}\n"));
    std::fs::write(
        &cfg,
        format!(
            "global\n  nbthread {nbthread}\n  stats socket {} level admin\n{setting}\
             defaults\n  mode http\n  timeout connect 1s\n  timeout client 10s\n  timeout server 10s\n\
             frontend f\n  bind 127.0.0.1:{http}\n  http-request deny if {{ path /deny }}\n\
               http-request return status 404 if {{ path /return }}\n\
               use_backend bd if {{ path /dead }}\n  use_backend br if {{ path /retry }}\n  default_backend b\n\
             backend b\n  balance roundrobin\n  server s1 127.0.0.1:{live}\n  server s2 127.0.0.1:{live}\n\
             backend bd\n  retries 0\n  server d 127.0.0.1:{dead}\n\
             backend br\n  balance roundrobin\n  retries 1\n  option redispatch\n  server x 127.0.0.1:{dead}\n  server y 127.0.0.1:{live}\n\
             listen t\n  mode tcp\n  bind 127.0.0.1:{tcp}\n  server s 127.0.0.1:{live}\n\
             frontend p\n  bind 127.0.0.1:{prom}\n  http-request use-service prometheus-exporter\n",
            sock.display()
        ),
    )
    .expect("write config");
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .expect("spawn alcyon");
    let d = Daemon { alcyon: common::Alcyon(child), sock, cfg, http, tcp, prom, cli_calls: std::cell::Cell::new(0) };
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", d.http)).is_err()
        || TcpStream::connect(("127.0.0.1", d.tcp)).is_err()
        || TcpStream::connect(("127.0.0.1", d.prom)).is_err()
        || !d.sock.exists()
    {
        assert!(Instant::now() < deadline, "alcyon ({tag}) never listened");
        thread::sleep(Duration::from_millis(20));
    }
    d
}

/// The fixed traffic: kept-alive requests over several client connections (so they land on
/// several threads), bodies, a deny, a `return`, a dead server, a request the frontend
/// cannot parse, TCP sessions.
fn traffic(d: &Daemon) {
    for conn in 0..6 {
        let c = TcpStream::connect(("127.0.0.1", d.http)).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let mut w = c.try_clone().expect("clone");
        let mut r = BufReader::new(c);
        for i in 0..8 {
            if i % 3 == 0 {
                let body = "x".repeat(10 + conn * 7 + i);
                write!(w, "POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}", body.len()).expect("write");
            } else {
                write!(w, "GET /g{i} HTTP/1.1\r\nHost: x\r\n\r\n").expect("write");
            }
            let (status, body) = response(&mut r);
            assert_eq!((status.as_str(), body.as_slice()), ("200", &b"ok"[..]));
        }
        write!(w, "GET /return HTTP/1.1\r\nHost: x\r\n\r\n").expect("write");
        assert_eq!(response(&mut r).0, "404");
        drop((w, r));
        // One connection at a time, so `smax` does not depend on when the last one closed.
        idle(d);
    }
    // `/retry`: the balancer's picks alternate between a dead server, which fails and
    // redispatches to the live one (a failed attempt, a second `lbtot`), and the live one.
    for path in ["/deny", "/deny", "/dead", "/dead", "/dead", "/retry", "/retry", "/retry", "/retry"] {
        let mut c = TcpStream::connect(("127.0.0.1", d.http)).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(10))).ok();
        write!(c, "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
        let status = String::from_utf8_lossy(&out).split(' ').nth(1).unwrap_or("").to_string();
        let want = match path {
            "/deny" => "403",
            "/retry" => "200",
            _ => "503",
        };
        assert_eq!(status, want, "{path}");
        drop(c);
        idle(d);
    }
    let mut c = TcpStream::connect(("127.0.0.1", d.http)).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(10))).ok();
    c.write_all(b"NOT A REQUEST\r\n\r\n").expect("write");
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    assert!(out.starts_with(b"HTTP/1.1 400"), "{:?}", String::from_utf8_lossy(&out));
    drop(c);
    idle(d);
    for _ in 0..4 {
        let mut c = TcpStream::connect(("127.0.0.1", d.tcp)).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(10))).ok();
        c.write_all(b"GET /t HTTP/1.1\r\nHost: x\r\n\r\n").expect("write");
        // The client closes first, once it has the answer.
        let mut out = Vec::new();
        let mut b = [0u8; 256];
        while !out.ends_with(b"ok") {
            match c.read(&mut b) {
                Ok(n) if n > 0 => out.extend_from_slice(&b[..n]),
                _ => break,
            }
        }
        assert!(out.ends_with(b"ok"), "{:?}", String::from_utf8_lossy(&out));
        drop(c);
        idle(d);
    }
}

/// `show stat` as `(proxy, server, column) -> value`, without the columns that depend on
/// when they are read: rates, ages, the timing averages and maxima.
fn stat(d: &Daemon) -> BTreeMap<(String, String, String), String> {
    const VOLATILE: &[&str] = &[
        "rate", "rate_max", "req_rate", "req_rate_max", "conn_rate", "conn_rate_max", "lastsess", "lastchg", "qtime",
        "ctime", "rtime", "ttime", "qtime_max", "ctime_max", "rtime_max", "ttime_max", "downtime", "check_duration",
    ];
    let out = cli(d, "show stat");
    let mut lines = out.lines();
    let header: Vec<String> = lines.next().expect("header").trim_start_matches("# ").split(',').map(str::to_string).collect();
    let mut m = BTreeMap::new();
    for l in lines.filter(|l| !l.is_empty()) {
        let f: Vec<&str> = l.split(',').collect();
        for (i, h) in header.iter().enumerate() {
            if !h.is_empty() && !VOLATILE.contains(&h.as_str()) {
                m.insert((f[0].to_string(), f[1].to_string(), h.clone()), f.get(i).copied().unwrap_or("").to_string());
            }
        }
    }
    m
}

/// `show info`'s totals: no time, rate, memory or process identity. `TotalBytesOut` counts
/// the CLI's own answers, whose left-out columns differ in length.
fn info(d: &Daemon) -> BTreeMap<String, String> {
    const VOLATILE: &[&str] = &[
        "Pid", "Uptime", "Start_time", "Pool", "Memmax", "Rate", "Tasks", "Run_queue", "Idle_pct", "node", "Ulimit", "Hard_max", "Maxsock",
        "Worker_id", "BytesOut",
    ];
    cli(d, "show info")
        .lines()
        .filter_map(|l| l.split_once(": "))
        .filter(|(k, _)| !VOLATILE.iter().any(|v| k.contains(v)))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// The Prometheus scrape as `metric{labels} -> value`, the same families left out.
fn metrics(d: &Daemon) -> BTreeMap<String, String> {
    const VOLATILE: &[&str] = &["rate", "time", "uptime", "last_", "pool", "memory", "idle", "tasks", "run_queue", "pid", "limit", "max_", "worker_id", "process_bytes_out"];
    let mut c = TcpStream::connect(("127.0.0.1", d.prom)).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(10))).ok();
    c.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out).into_owned();
    text.lines()
        .filter(|l| l.starts_with("haproxy_"))
        .filter_map(|l| l.rsplit_once(' '))
        .filter(|(k, _)| !VOLATILE.iter().any(|v| k.split('{').next().unwrap_or("").contains(v)))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Waits until no stream of `d` is current, so its last streams have been counted.
fn idle(d: &Daemon) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let out = cli(d, "show stat");
        let busy: Vec<&str> = out
            .lines()
            .skip(1)
            .filter(|l| l.split(',').nth(4).is_some_and(|scur| scur != "0" && !scur.is_empty()))
            .collect();
        if busy.is_empty() {
            return;
        }
        assert!(Instant::now() < deadline, "alcyon never went idle: {busy:?}");
        thread::sleep(Duration::from_millis(20));
    }
}

fn diff<K: Ord + std::fmt::Debug>(what: &str, a: &BTreeMap<K, String>, b: &BTreeMap<K, String>) {
    let keys: std::collections::BTreeSet<&K> = a.keys().chain(b.keys()).collect();
    let bad: Vec<String> = keys.into_iter().filter(|k| a.get(k) != b.get(k)).map(|k| format!("{k:?}: shared {:?}, per-thread {:?}", a.get(k), b.get(k))).collect();
    assert!(bad.is_empty(), "{what} differs with tune.alcyon.counters per-thread:\n{}", bad.join("\n"));
}

fn compare(shared: &Daemon, per: &Daemon, when: &str) {
    for d in [shared, per] {
        idle(d);
    }
    while shared.cli_calls.get() != per.cli_calls.get() {
        let d = if shared.cli_calls.get() < per.cli_calls.get() { shared } else { per };
        let _ = cli(d, "show info");
    }
    diff(&format!("show stat ({when})"), &stat(shared), &stat(per));
    diff(&format!("show info ({when})"), &info(shared), &info(per));
    diff(&format!("Prometheus ({when})"), &metrics(shared), &metrics(per));
}

#[test]
fn show_stat_show_info_and_prometheus_read_the_same_with_per_thread_rows() {
    let (live, dead) = (backend(), common::reserve_port());
    for nbthread in [1, 4] {
        let shared = start("shared", nbthread, None, live, dead, Stdio::null());
        let per = start("per", nbthread, Some("per-thread"), live, dead, Stdio::null());
        for d in [&shared, &per] {
            traffic(d);
        }
        compare(&shared, &per, &format!("nbthread {nbthread}"));
        let req_tot = |d: &Daemon| stat(d).get(&("f".into(), "FRONTEND".into(), "req_tot".into())).cloned();
        let counted = req_tot(&shared);
        assert!(counted.as_deref().is_some_and(|n| n.parse::<u64>().is_ok_and(|n| n >= 60)), "the frontend counted the traffic: {counted:?}");
        assert_eq!(req_tot(&per), counted);
        // The retries reached the paths they are there for: a redispatch, an attempt that failed.
        let st = stat(&per);
        let at = |px: &str, sv: &str, c: &str| st.get(&(px.into(), sv.into(), c.into())).cloned().unwrap_or_default();
        assert_ne!(at("br", "BACKEND", "wredis"), "0", "a redispatch");
        assert_ne!(at("br", "x", "stot"), "0", "a failed attempt counted on the dead server");

        for d in [&shared, &per] {
            assert_eq!(cli(d, "clear counters all"), "\n");
        }
        for (k, v) in stat(&per) {
            if ["stot", "req_tot", "bin", "bout", "hrsp_2xx", "lbtot", "connect", "reuse", "ereq"].contains(&k.2.as_str()) && k.0 != "p" {
                assert!(v == "0" || v.is_empty(), "{k:?} is {v:?} after clear counters all, per-thread rows");
            }
        }
        compare(&shared, &per, &format!("nbthread {nbthread}, after clear counters all"));
        for d in [&shared, &per] {
            traffic(d);
        }
        compare(&shared, &per, &format!("nbthread {nbthread}, traffic after the clear"));
    }
}

#[test]
fn per_thread_rows_are_a_pool_and_the_start_says_their_size() {
    let (live, dead) = (backend(), common::reserve_port());
    let mut per = start("pools", 2, Some("per-thread"), live, dead, Stdio::piped());
    let line = |out: &str| out.lines().find(|l| l.trim_start().starts_with("- Pool counters (")).map(str::to_string);
    let pools = cli(&per, "show pools");
    let pool = line(&pools).unwrap_or_else(|| panic!("no counters pool in {pools}"));
    // 6 proxies (f, b, bd, br, t, p) x 2 rows, and 6 servers: 18 rows a thread, and a guard
    // row at each end of the thread's slab so that no other object shares its first and last
    // cache lines: 20 rows a thread, 2 threads.
    let size: usize = pool.split(" (").nth(1).and_then(|s| s.split(' ').next()).and_then(|s| s.parse().ok()).expect("size");
    let allocated: usize = pool.split(" : ").nth(1).and_then(|r| r.split_whitespace().next()).and_then(|n| n.parse().ok()).expect("allocated");
    assert_eq!(allocated, 40, "{pool}");
    assert!(size >= 200, "{pool}");

    let shared = start("pools_shared", 2, Some("shared"), live, dead, Stdio::null());
    let pools = cli(&shared, "show pools");
    assert_eq!(line(&pools), None, "no counter rows with tune.alcyon.counters shared: {pools}");
    drop(shared);

    common::stop(&mut per.alcyon);
    let mut err = String::new();
    per.alcyon.stderr.take().expect("stderr").read_to_string(&mut err).expect("stderr");
    let notice = err.lines().find(|l| l.contains("tune.alcyon.counters per-thread")).unwrap_or_else(|| panic!("no notice in {err:?}"));
    assert!(notice.starts_with("[NOTICE]"), "{notice}");
    assert!(notice.contains(&format!("{} bytes", 40 * size)), "{notice}");
}

/// `clear counters` (the maxima only) under `per-thread`: every thread's `rate_max` reads 0 at
/// once (no thread writes another's row: a reader counts a row of an older clear as no
/// maximum), the totals stay, and a thread that counts again starts its peak from 0.
#[test]
fn clear_counters_zeroes_the_per_thread_rate_maxima_and_keeps_the_totals() {
    let (live, dead) = (backend(), common::reserve_port());
    let per = start("maxima", 2, Some("per-thread"), live, dead, Stdio::null());
    traffic(&per);
    idle(&per);
    let col = |d: &Daemon, px: &str, sv: &str, name: &str| -> String {
        let out = cli(d, "show stat");
        let mut lines = out.lines();
        let header: Vec<&str> = lines.next().expect("header").trim_start_matches("# ").split(',').collect();
        let i = header.iter().position(|h| *h == name).expect("column");
        lines.map(|l| l.split(',').collect::<Vec<_>>()).find(|f| f[0] == px && f[1] == sv).map(|f| f[i].to_string()).expect("row")
    };
    assert_ne!(col(&per, "b", "BACKEND", "rate_max"), "0", "the traffic made a peak");
    let stot = col(&per, "b", "BACKEND", "stot");
    assert_eq!(cli(&per, "clear counters"), "\n");
    for sv in ["BACKEND", "s1", "s2"] {
        assert_eq!(col(&per, "b", sv, "rate_max"), "0", "b/{sv} rate_max after clear counters");
    }
    assert_eq!(col(&per, "b", "BACKEND", "stot"), stot, "clear counters keeps the totals");
    traffic(&per);
    idle(&per);
    assert_ne!(col(&per, "b", "BACKEND", "rate_max"), "0", "a peak after the clear");
}

/// One proxy's counters cleared and not another's (the stats page's `clear_counters` of a
/// backend, `Engine::clear_counters(Some(..))`) under `per-thread`: the cleared backend's rows
/// read 0, and when the thread counts again it zeroes only those; the other backend keeps its
/// totals and its peak.
#[test]
fn clearing_one_backend_leaves_the_other_backends_per_thread_rows() {
    use alcyon_rt::statcnt::{snapshot, BE};
    let live = backend();
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n  tune.alcyon.counters per-thread\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  use_backend ba if {{ path /a }}\n  default_backend bb\n\
         backend ba\n  server s 127.0.0.1:{live}\n\
         backend bb\n  server s 127.0.0.1:{live}\n"
    );
    let mut engine = alcyon_rt::engine::Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_nonblocking(true).expect("nonblocking");
    let mut get = |engine: &mut alcyon_rt::engine::Engine, path: &str| {
        write!(c, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").expect("write");
        let mut got = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !got.ends_with(b"ok") && Instant::now() < deadline {
            let _ = engine.run_once();
            let mut b = [0u8; 512];
            if let Ok(n) = c.read(&mut b) {
                got.extend_from_slice(&b[..n]);
            }
        }
        assert!(got.ends_with(b"ok"), "{:?}", String::from_utf8_lossy(&got));
        // The stream's accounting may run a pass later.
        for _ in 0..3 {
            let _ = engine.run_once();
        }
    };
    for path in ["/a", "/b", "/a", "/b", "/b"] {
        get(&mut engine, path);
    }
    let idx = |engine: &alcyon_rt::engine::Engine, name: &str| engine.proxies.iter().position(|p| p.name == name).expect("proxy");
    let (ba, bb) = (idx(&engine, "ba"), idx(&engine, "bb"));
    let stot = |engine: &alcyon_rt::engine::Engine, i: usize| snapshot(&engine.proxies[i], BE).stot;
    let peak = |engine: &alcyon_rt::engine::Engine, i: usize| snapshot(&engine.proxies[i], BE).rate_max;
    assert_eq!((stot(&engine, ba), stot(&engine, bb)), (2, 3));
    let bb_peak = peak(&engine, bb);
    assert!(bb_peak > 0, "bb made a peak");

    assert!(engine.clear_counters(Some("ba")));
    assert_eq!((stot(&engine, ba), peak(&engine, ba)), (0, 0), "ba reads cleared at once");
    assert_eq!(stot(&engine, bb), 3, "bb keeps its totals");

    // The thread counts again, once the session rate has fallen (two seconds: its window and
    // the one before), so a peak zeroed by mistake would show: it zeroes its rows of `ba` and
    // leaves those of `bb`, peak included.
    thread::sleep(Duration::from_millis(2100));
    get(&mut engine, "/b");
    assert_eq!(stot(&engine, ba), 0);
    assert_eq!(stot(&engine, bb), 4, "bb counted on");
    assert_eq!(peak(&engine, bb), bb_peak, "bb keeps its peak");
    get(&mut engine, "/a");
    assert_eq!(stot(&engine, ba), 1, "ba counts from 0");
}
