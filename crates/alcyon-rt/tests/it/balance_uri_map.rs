// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `balance uri` with the default `hash-type` (map-based), BALURI. Measured on the reference
//! `HAProxy` 3.5-dev8 (`/var/tmp/qwen-next-eval/oracle/haproxy`, 2026-11-15): for each server
//! layout, the answering server's number for the URIs `/p0` .. `/p31`, then `/q?a=1`, `/q?a=2`
//! and `/q` (the query string is not hashed, so the last three land together).
//!
//! `get_server_uh` (`src/backend.c`) hashes the path with `sdbm`, and `map_get_server_hash`
//! (`src/lb_map.c`) takes it modulo `tot_weight` into the interleaved weighted map. Reaches
//! the data path in `lb::balance_uri`, called from `Proxy` server selection (`engine.rs`).

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn backend(id: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            c.set_read_timeout(Some(Duration::from_millis(500))).ok();
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf);
            let _ = write!(c, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n{id}");
        }
    });
    port
}

fn get(port: u16, uri: &str) -> char {
    // An absolute URI names its own authority; HAProxy refuses one the `Host` contradicts.
    // `"OPTIONS *"`: a method before the target; GET without one.
    let (method, uri) = uri.split_once(' ').unwrap_or(("GET", uri));
    let host = uri.strip_prefix("http://").and_then(|r| r.split('/').next()).unwrap_or("x");
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    write!(s, "{method} {uri} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    if out.starts_with("HTTP/1.1 200") { out.chars().last().unwrap_or('x') } else { 'x' }
}

/// The answering server's number for each URI, behind `balance uri` and servers with
/// `weights`; with `s2_down` the second server is `disabled`.
fn answers(weights: &[u32], s2_down: bool) -> String {
    let uris: Vec<String> = (0..32).map(|i| format!("/p{i}")).chain(["/q?a=1", "/q?a=2", "/q"].map(String::from)).collect();
    answers_of("balance uri", weights, s2_down, &uris.iter().map(String::as_str).collect::<Vec<_>>())
}

/// The answering server's number for each of `uris`, behind the backend lines `balance`
/// (the `balance` line, and a `hash-type` one if any) and servers with `weights`.
fn answers_of(balance: &str, weights: &[u32], s2_down: bool, uris: &[&str]) -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static RUN: AtomicUsize = AtomicUsize::new(0);
    let mut servers = String::new();
    for (i, w) in weights.iter().enumerate() {
        let down = if s2_down && i == 1 { " disabled" } else { "" };
        servers.push_str(&format!("  server s{} 127.0.0.1:{} weight {w}{down}\n", i + 1, backend(i + 1)));
    }
    let port = common::reserve_port();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind 127.0.0.1:{port}\n  default_backend be\n\
         backend be\n  {balance}\n{servers}"
    );
    let path = std::env::temp_dir().join(format!("alcyon_baluri_{}_{}", std::process::id(), RUN.fetch_add(1, Ordering::Relaxed)));
    std::fs::write(&path, cfg).expect("write config");
    let _child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Alcyon)
        .expect("spawn alcyon");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the daemon never listened on {port}: {balance}");
        thread::sleep(Duration::from_millis(25));
    }
    let got = uris.iter().map(|u| get(port, u)).collect();
    let _ = std::fs::remove_file(&path);
    got
}

#[test]
fn equal_weights_follow_haproxys_map() {
    assert_eq!(answers(&[1, 1, 1, 1], false), "41234123411234123412412341234134333", "four servers");
    assert_eq!(answers(&[1, 1, 1], false), "23123123123123123123123123123123222", "three servers");
    assert_eq!(answers(&[1, 1, 1, 1, 1], false), "23451234515123451234451234512334222", "five servers");
}

#[test]
fn unequal_weights_interleave_like_haproxys_map() {
    assert_eq!(answers(&[1, 2, 3], false), "32323132322323132323323132323123222", "weights 1 2 3");
    assert_eq!(answers(&[10, 20, 5], false), "31221223122122312212223122122331222", "weights 10 20 5");
}

#[test]
fn a_server_down_is_left_out_of_the_map() {
    assert_eq!(answers(&[1, 1, 1, 1], true), "34134134134134134134134134134134333");
}

/// The URIs of the option rows: twelve plain ones, then paths that share a directory, a
/// prefix or a query string, absolute URIs (what `path-only` strips), and the edges.
const OPTION_URIS: [&str; 34] = [
    "/p0", "/p1", "/p2", "/p3", "/p4", "/p5", "/p6", "/p7", "/p8", "/p9", "/p10", "/p11", "/a/b/c/d1", "/a/b/c/d2", "/a/b/x", "/a/y", "/a/b?x=1", "/a/b?x=2", "/a/b", "/abcdefgh1", "/abcdefgh2", "/abcd", "/abc?d=1", "/abc?e=1", "http://h/a/b/c/d1", "http://h/a/b?x=1", "http://h/a/b?x=2", "http://h/a/b", "http://g/a/b", "/", "/?q=1", "//a//b", "/a/b/", "/a/b/c/"
];

/// `balance uri <options>` on four equal servers, measured on the reference `HAProxy`
/// 3.5-dev8 (2026-11-15) for [`OPTION_URIS`]. `whole` hashes past the `?`; `len` cuts the
/// URI to its first bytes; `depth` stops before the slash that ends that many directories;
/// `path-only` drops the scheme and authority of an absolute URI first; a repeated option
/// keeps its last value. Reaches the data path in `lb::uri_hash_key`.
const OPTIONS_4EQ_MAP: [(&str, &str); 21] = [
    ("whole", "4123412341124131342342122124342233"),
    ("len 4", "4123412341122221222444441111144322"),
    ("len 3", "4123412341112222222111111111144222"),
    ("len 1", "4444444444444444444444441111144444"),
    ("depth 1", "4123412341123333333342442222244433"),
    ("depth 2", "4123412341122221222342443333244222"),
    ("depth 3", "4123412341122231222342441111444332"),
    ("path-only", "4123412341124131222342444222244233"),
    ("whole path-only", "4123412341124131342342124342242233"),
    ("len 6 depth 2", "4123412341122221222112442222244222"),
    ("whole len 8", "4123412341123331342222123333242233"),
    ("whole depth 2", "4123412341122221342342123333242222"),
    ("path-only depth 1", "4123412341123333333342443333344433"),
    ("path-only len 4", "4123412341122221222444442222244322"),
    ("depth 2 len 100000", "4123412341122221222342443333244222"),
    ("len 4 len 6", "4123412341122231222112442222244232"),
    ("depth 1 depth 3", "4123412341122231222342441111444332"),
    ("path-only whole len 9 depth 2", "4123412341122221342442122342242222"),
    // `atoi`: digits up to the first other byte, and an int that wraps (2^32 + 1 is 1); a
    // depth of `INT_MAX` is a slash count never reached.
    ("len 3x", "4123412341112222222111111111144222"),
    ("len 4294967297", "4444444444444444444444441111144444"),
    ("depth 2147483647", "4123412341124131222342442444344233"),
];

/// The same with `hash-type consistent` (`lb::balance_uri_consistent`, same key).
const OPTIONS_4EQ_CONSISTENT: [(&str, &str); 18] = [
    ("whole", "1441123143441332422212122331124313"),
    ("len 4", "1441123143442222222444442222222422"),
    ("len 3", "1441123143443333333444441111122133"),
    ("len 1", "2222222222222222222222221111122222"),
    ("depth 1", "1441123143444444444212444444422244"),
    ("depth 2", "1441123143442222222212441111122122"),
    ("depth 3", "1441123143441132222212442222322411"),
    ("path-only", "1441123143441332222212441222222313"),
    ("whole path-only", "1441123143441332422212121422224313"),
    ("len 6 depth 2", "1441123143442222222222444444422122"),
    ("whole len 8", "1441123143444432422332121111124313"),
    ("whole depth 2", "1441123143442222422212121111124122"),
    ("path-only depth 1", "1441123143444444444212444444422244"),
    ("path-only len 4", "1441123143442222222444442222222422"),
    ("depth 2 len 100000", "1441123143442222222212441111122122"),
    ("len 4 len 6", "1441123143441132222222444444422311"),
    ("depth 1 depth 3", "1441123143441132222212442222322411"),
    ("path-only whole len 9 depth 2", "1441123143442222422222122422224122"),
];

/// Weights 1, 2 and 3, map-based then consistent: no option, and one row per option.
const OPTIONS_W123_MAP: [(&str, &str); 6] = [
    ("", "3232313232233122333133333333133322"),
    ("whole", "3232313232233122233133133233133322"),
    ("len 4", "3232313232233332333333332222233233"),
    ("depth 2", "3232313232233332333133332222333333"),
    ("path-only", "3232313232233122333133333333333322"),
    ("path-only whole len 9 depth 2", "3232313232233332233333133233333333"),
];
const OPTIONS_W123_CONSISTENT: [(&str, &str); 6] = [
    ("", "1221123133331222222212333222322213"),
    ("whole", "1221123133331222332212123332322213"),
    ("len 4", "1221123133332222222333332222222322"),
    ("depth 2", "1221123133332222222212332222122122"),
    ("path-only", "1221123133331222222212331222222213"),
    ("path-only whole len 9 depth 2", "1221123133332222332222122332222122"),
];

fn check_rows(rows: &[(&str, &str)], hash_type: &str, weights: &[u32]) {
    let mut wrong = Vec::new();
    for (opt, want) in rows {
        let balance = format!("balance uri {opt}{hash_type}");
        let got = answers_of(&balance, weights, false, &OPTION_URIS);
        if got != *want {
            wrong.push(format!("{balance:?} {weights:?}\n   got {got}\n  want {want}"));
        }
    }
    assert!(wrong.is_empty(), "{} of {} rows differ from HAProxy:\n{}", wrong.len(), rows.len(), wrong.join("\n"));
}

#[test]
fn uri_options_pick_haproxys_server_map_based() {
    check_rows(&OPTIONS_4EQ_MAP, "", &[1, 1, 1, 1]);
    check_rows(&OPTIONS_W123_MAP, "", &[1, 2, 3]);
}

#[test]
fn uri_options_pick_haproxys_server_consistent() {
    check_rows(&OPTIONS_4EQ_CONSISTENT, "\n  hash-type consistent", &[1, 1, 1, 1]);
    check_rows(&OPTIONS_W123_CONSISTENT, "\n  hash-type consistent", &[1, 2, 3]);
}

/// `OPTIONS *` has no path: with `path-only` the key is empty (hash 0, the map's first slot),
/// without it the `*` is hashed. Measured on the reference `HAProxy` 3.5-dev8 (2026-11-15),
/// four equal servers. Not seen red: Alcyon agreed when the row was measured; it is here
/// for the target without a path (`lb::uri_path`).
#[test]
fn a_target_without_a_path_hashes_as_haproxys() {
    for (balance, want) in [
        ("balance uri", "3"),
        ("balance uri path-only", "1"),
        ("balance uri path-only len 4", "1"),
        ("balance uri\n  hash-type consistent", "3"),
        ("balance uri path-only\n  hash-type consistent", "3"),
    ] {
        assert_eq!(answers_of(balance, &[1, 1, 1, 1], false, &["OPTIONS *"]), want, "{balance}");
    }
}
