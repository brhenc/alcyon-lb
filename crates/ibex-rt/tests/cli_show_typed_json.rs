// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `show stat typed|json`, `show info typed|json` and the `show info` line set (T245).
//!
//! The expected files in `tests/data/*_oracle.txt` are what `HAProxy 3.5-dev8-885761-29`
//! prints for one frontend, one backend and two servers (no checks), with every value
//! replaced by `V` (typed: removed): the structure, the order, the tags and the types
//! are the contract; the values depend on the run.

mod common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::Duration;

fn answers(cmds: &[&str]) -> Vec<String> {
    answers_with("backend be\n  server s1 127.0.0.1:18091\n  server s2 127.0.0.1:18092\n", cmds)
}

/// The CLI answers to `cmds` of an Ibex with a frontend `fe` (default backend `be`) and `proxies`.
fn answers_with(proxies: &str, cmds: &[&str]) -> Vec<String> {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let id = format!("{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    let sock = format!("/tmp/ibex-typed-{id}.sock");
    let cfg = std::env::temp_dir().join(format!("ibex-typed-{id}.cfg"));
    let fe = common::reserve_addr();
    std::fs::write(
        &cfg,
        format!(
            "global\n  stats socket {sock} level admin\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind {fe}\n  default_backend be\n{proxies}"
        ),
    )
    .expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    assert!(common::wait_listening(fe), "ibex never listened");
    let mut res = Vec::new();
    for cmd in cmds {
        let mut c = UnixStream::connect(&sock).expect("connect cli");
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(format!("{cmd}\n").as_bytes()).unwrap();
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
        res.push(String::from_utf8_lossy(&out).into_owned());
    }
    common::stop(&mut child);
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&cfg);
    res
}

/// `a.b.c:TAGS:type:value` -> `a.b.c:TAGS:type`.
fn strip_typed(s: &str) -> String {
    s.split_inclusive('\n')
        .map(|l| {
            let t = l.trim_end_matches('\n');
            let mut it = t.splitn(4, ':');
            match (it.next(), it.next(), it.next()) {
                (Some(a), Some(b), Some(c)) => format!("{a}:{b}:{c}\n"),
                _ => l.to_string(),
            }
        })
        .collect()
}

/// Every scalar `"value":<x>` (not the `"value":{"type"...` object) becomes `"value":V`.
fn strip_json(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("\"value\":") {
        let (head, tail) = rest.split_at(i + 8);
        out.push_str(head);
        if tail.starts_with('{') {
            rest = tail;
            continue;
        }
        let end = if tail.starts_with('"') {
            tail[1..].find('"').map_or(tail.len(), |j| j + 2)
        } else {
            tail.find('}').unwrap_or(tail.len())
        };
        out.push('V');
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

fn oracle(name: &str) -> String {
    std::fs::read_to_string(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).expect("oracle file")
}

fn assert_same_text(got: &str, want: &str) {
    if let Some(i) = got.bytes().zip(want.bytes()).position(|(a, b)| a != b).or((got.len() != want.len()).then_some(got.len().min(want.len()))) {
        let from = i.saturating_sub(120);
        panic!("differ at byte {i}:\n got: {:?}\nwant: {:?}", &got[from..(i + 120).min(got.len())], &want[from..(i + 120).min(want.len())]);
    }
}

fn assert_same_lines(got: &str, want: &str) {
    let g: Vec<&str> = got.lines().collect();
    let w: Vec<&str> = want.lines().collect();
    let gs: std::collections::BTreeSet<_> = g.iter().collect();
    let ws: std::collections::BTreeSet<_> = w.iter().collect();
    let missing: Vec<_> = ws.difference(&gs).collect();
    let extra: Vec<_> = gs.difference(&ws).collect();
    assert!(
        g == w,
        "{} lines vs {} expected\nmissing: {missing:?}\nextra: {extra:?}",
        g.len(),
        w.len()
    );
}

#[test]
fn show_stat_typed_has_the_haproxy_lines() {
    let a = answers(&["show stat typed"]);
    assert!(a[0].ends_with("\n\n"), "no end-of-answer empty line: {:?}", &a[0][a[0].len().saturating_sub(40)..]);
    assert_same_lines(&strip_typed(a[0].trim_end_matches('\n')), oracle("show_stat_typed_oracle.txt").trim_end_matches('\n'));
}

#[test]
fn show_stat_json_has_the_haproxy_structure() {
    let a = answers(&["show stat json"]);
    assert!(a[0].ends_with("]]\n\n"), "{:?}", &a[0][a[0].len().saturating_sub(40)..]);
    let v: serde_json::Value = serde_json::from_str(a[0].trim()).expect("valid json");
    assert_eq!(v.as_array().map(Vec::len), Some(4), "one array per object");
    assert_same_text(&strip_json(&a[0]), &oracle("show_stat_json_oracle.txt"));
}

#[test]
fn show_info_typed_and_json_have_the_haproxy_fields() {
    let a = answers(&["show info typed", "show info json"]);
    assert!(a[0].ends_with("\n\n"));
    assert_same_lines(&strip_typed(a[0].trim_end_matches('\n')), oracle("show_info_typed_oracle.txt").trim_end_matches('\n'));
    assert!(a[1].ends_with("]\n\n"), "{:?}", &a[1][a[1].len().saturating_sub(40)..]);
    serde_json::from_str::<serde_json::Value>(a[1].trim()).expect("valid json");
    assert_same_text(&strip_json(&a[1]), &oracle("show_info_json_oracle.txt"));
}

#[test]
fn show_info_has_the_haproxy_line_set_and_ends_with_an_empty_line() {
    let a = answers(&["show info"]);
    assert!(a[0].ends_with("\n\n"), "{:?}", &a[0][a[0].len().saturating_sub(40)..]);
    let keys: String = a[0]
        .trim_end_matches('\n')
        .lines()
        .map(|l| format!("{}\n", l.split(':').next().unwrap_or("")))
        .collect();
    assert_same_lines(keys.trim_end_matches('\n'), oracle("show_info_keys_oracle.txt").trim_end_matches('\n'));
}

#[test]
fn show_stat_typed_takes_the_filters_and_refuses_desc() {
    let a = answers(&["show stat fe -1 -1 typed", "show stat typed be 4 -1", "show stat desc typed", "show info desc"]);
    assert!(a[0].lines().filter(|l| !l.is_empty()).all(|l| l.starts_with("F.")), "{:.300}", a[0]);
    assert!(a[0].contains("F.2.0.0.pxname.1:KNSV:str:fe\n"), "{:.300}", a[0]);
    assert!(a[1].lines().filter(|l| !l.is_empty()).all(|l| l.starts_with("S.")), "{:.300}", a[1]);
    assert!(a[1].contains("S.3.1.1.svname.1:KNSV:str:s1\n") && a[1].contains("S.3.2.1.svname.1:KNSV:str:s2\n"), "{:.300}", a[1]);
    assert!(a[2].contains("not supported"), "{:.300}", a[2]);
    assert!(a[3].contains("not supported"), "{:.300}", a[3]);
}

#[test]
fn show_stat_type_filter_uses_haproxy_bits() {
    // 1 frontend, 2 backend, 4 server (measured: HAProxy `show stat -1 <bits> -1`).
    let a = answers(&["show stat -1 1 -1 typed", "show stat -1 2 -1 typed", "show stat -1 4 -1 typed", "show stat -1 5 -1 typed"]);
    let kinds = |s: &str| -> String {
        let mut k: Vec<char> = s.lines().filter_map(|l| l.chars().next()).collect();
        k.sort_unstable();
        k.dedup();
        k.into_iter().collect()
    };
    assert_eq!(kinds(&a[0]), "F");
    assert_eq!(kinds(&a[1]), "B");
    assert_eq!(kinds(&a[2]), "S");
    assert_eq!(kinds(&a[3]), "FS");
}

/// The `algo` column names the backend's balance algorithm as HAProxy does; `random`
/// prints `unknown` (measured on HAProxy 3.5-dev8 with one backend per algorithm). A
/// backend with no `balance` line is left out: HAProxy prints `unknown` (its default is
/// `random`), Ibex `roundrobin`.
#[test]
fn show_stat_algo_names_each_balance_algorithm_as_haproxy() {
    let algos = ["roundrobin", "source", "uri", "leastconn", "static-rr", "first", "random"];
    let mut proxies = String::from("backend be\n  server s1 127.0.0.1:18091\n");
    for a in algos {
        proxies.push_str(&format!("backend b_{a}\n  balance {a}\n  server s1 127.0.0.1:18091\n"));
    }
    let a = answers_with(&proxies, &["show stat"]);
    let mut lines = a[0].lines();
    let head: Vec<&str> = lines.next().unwrap_or_default().trim_start_matches("# ").split(',').collect();
    let col = head.iter().position(|h| *h == "algo").expect("algo column");
    let got: Vec<(String, String)> = lines
        .map(|l| l.split(',').collect::<Vec<_>>())
        .filter(|r| r.len() > col && r[1] == "BACKEND" && r[0].starts_with("b_"))
        .map(|r| (r[0].to_string(), r[col].to_string()))
        .collect();
    let want: Vec<(String, String)> =
        algos.iter().map(|a| (format!("b_{a}"), if *a == "random" { "unknown" } else { *a }.to_string())).collect();
    assert_eq!(got, want, "{:.400}", a[0]);
}
