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
//!
//! `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`: it passes all.

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
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

fn with_alcyon(bind_opts: &str, balance: &str, weights: &[u32], s2_down: bool, run: impl FnOnce(u16) -> String) -> String {
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
         frontend f\n  bind 127.0.0.1:{port}{bind_opts}\n  default_backend be\n\
         backend be\n  {balance}\n{servers}"
    );
    let path = std::env::temp_dir().join(format!("alcyon_baluri_{}_{}", std::process::id(), RUN.fetch_add(1, Ordering::Relaxed)));
    std::fs::write(&path, cfg).expect("write config");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let _child = Command::new(&bin)
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
    let got = run(port);
    let _ = std::fs::remove_file(&path);
    got
}

/// The answering server's number for each of `uris`, behind the backend lines `balance`
/// (the `balance` line, and a `hash-type` one if any) and servers with `weights`.
fn answers_of(balance: &str, weights: &[u32], s2_down: bool, uris: &[&str]) -> String {
    with_alcyon("", balance, weights, s2_down, |port| uris.iter().map(|u| get(port, u)).collect())
}

/// `with_alcyon`, with a `stats socket {sock} mode 600 level admin` in the `global` section
/// (bound after the frontends listen), so `run` can drive the proxy over its admin socket.
fn with_admin(balance: &str, weights: &[u32], run: impl FnOnce(u16, &Path) -> String) -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static RUN: AtomicUsize = AtomicUsize::new(0);
    let mut servers = String::new();
    for (i, w) in weights.iter().enumerate() {
        servers.push_str(&format!("  server s{} 127.0.0.1:{} weight {w}\n", i + 1, backend(i + 1)));
    }
    let port = common::reserve_port();
    let run_id = RUN.fetch_add(1, Ordering::Relaxed);
    let sock = std::env::temp_dir().join(format!("alcyon_baluri_adm_{}_{}.sock", std::process::id(), run_id));
    let _ = std::fs::remove_file(&sock);
    let cfg = format!(
        "global\n  stats socket {} mode 600 level admin\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind 127.0.0.1:{port}\n  default_backend be\n\
         backend be\n  {balance}\n{servers}",
        sock.display()
    );
    let path = std::env::temp_dir().join(format!("alcyon_baluri_adm_{}_{}.cfg", std::process::id(), run_id));
    std::fs::write(&path, &cfg).expect("write config");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let _child = Command::new(&bin)
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Alcyon)
        .expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the daemon never listened on {port}: {balance}");
        thread::sleep(Duration::from_millis(25));
    }
    while !sock.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(sock.exists(), "the stats socket never appeared: {balance}");
    let got = run(port, &sock);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&sock);
    got
}

/// Sends `cmd` on the stats socket and reads the reply (the connection is closed after it).
fn cli(sock: &Path, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// The 35 URIs of `answers()`: `/p0` .. `/p31`, then `/q?a=1`, `/q?a=2` and `/q`.
fn runtime_uris() -> Vec<String> {
    (0..32).map(|i| format!("/p{i}")).chain(["/q?a=1", "/q?a=2", "/q"].map(String::from)).collect()
}

fn h2_frame(ftype: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(9 + len);
    let len_bytes = u32::try_from(len).expect("frame fits u24").to_be_bytes();
    out.extend_from_slice(&[len_bytes[1], len_bytes[2], len_bytes[3], ftype, flags]);
    out.extend_from_slice(&(sid & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn h2_read_frame(s: &mut TcpStream) -> Option<(u8, u8, u32, Vec<u8>)> {
    let mut hdr = [0u8; 9];
    s.read_exact(&mut hdr).ok()?;
    let len = (usize::from(hdr[0]) << 16) | (usize::from(hdr[1]) << 8) | usize::from(hdr[2]);
    let sid = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
    let mut pay = vec![0u8; len];
    s.read_exact(&mut pay).ok()?;
    Some((hdr[3], hdr[4], sid, pay))
}

fn h2_get_all(port: u16, reqs: &[Vec<(&'static str, &'static str)>]) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut init = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    init.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    s.write_all(&init).expect("preface");

    let mut out = String::with_capacity(reqs.len());
    for (idx, hdrs) in reqs.iter().enumerate() {
        let sid = u32::try_from(idx).expect("idx") * 2 + 1;
        let mut blk = Vec::new();
        for (k, v) in hdrs {
            blk.push(0x00);
            blk.push(u8::try_from(k.len()).expect("header name < 127"));
            blk.extend_from_slice(k.as_bytes());
            blk.push(u8::try_from(v.len()).expect("header value < 127"));
            blk.extend_from_slice(v.as_bytes());
        }
        s.write_all(&h2_frame(1, 0x05, sid, &blk)).expect("headers");
        let mut body = Vec::new();
        while let Some((ft, fl, rsid, pay)) = h2_read_frame(&mut s) {
            if ft == 4 && (fl & 1) == 0 {
                let _ = s.write_all(&h2_frame(4, 1, 0, &[]));
            } else if ft == 6 && (fl & 1) == 0 && pay.len() == 8 {
                let _ = s.write_all(&h2_frame(6, 1, 0, &pay));
            } else if ft == 0 && rsid == sid {
                body.extend_from_slice(&pay);
                if (fl & 1) != 0 {
                    break;
                }
            } else if ft == 1 && rsid == sid && (fl & 1) != 0 {
                break;
            } else if ft == 3 && rsid == sid || ft == 7 {
                body.clear();
                break;
            }
        }
        let ans = match body.as_slice() {
            [b] if b.is_ascii_digit() => char::from(*b),
            _ => 'x',
        };
        out.push(ans);
    }
    out
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

/// A server `disabled` at run time (admin socket) leaves the map until it is `enable`d
/// again, and nothing else moves: measured on the reference `HAProxy` (3.5-dev11,
/// 2026-11-16) for `/p0` .. `/p31`, `/q?a=1`, `/q?a=2`, `/q`, four equal servers, `balance uri`.
#[test]
fn a_server_disabled_at_run_time_is_left_out_of_the_map_until_reenabled() {
    with_admin("balance uri", &[1, 1, 1, 1], |port, sock| {
        let uris = runtime_uris();
        let init: String = uris.iter().map(|u| get(port, u)).collect();
        assert_eq!(init, "41234123411234123412412341234134333", "before the change");
        cli(sock, "disable server be/s2");
        let down: String = uris.iter().map(|u| get(port, u)).collect();
        assert_eq!(down, "34134134134134134134134134134134333", "while s2 is disabled");
        cli(sock, "enable server be/s2");
        let up: String = uris.iter().map(|u| get(port, u)).collect();
        assert_eq!(up, init, "after s2 is re-enabled");
        up
    });
}

/// `set server be/s2 weight 0%` / `100%` at run time re-weighs the map and restores it.
/// `balance uri` is a static LB algorithm: an absolute runtime weight is refused by `HAProxy`
/// (only `0%` and `100%` are accepted), so those are the commands measured here (reference
/// `HAProxy`, 3.5-dev11, 2026-11-16): weights 1 3 1 2, s2 to 0, then back.
#[test]
fn a_runtime_weight_change_reweighs_the_map() {
    with_admin("balance uri", &[1, 3, 1, 2], |port, sock| {
        let uris = runtime_uris();
        let init: String = uris.iter().map(|u| get(port, u)).collect();
        assert_eq!(init, "41224234122423412242234122423441222", "before the change");
        cli(sock, "set server be/s2 weight 0%");
        let w0: String = uris.iter().map(|u| get(port, u)).collect();
        assert_eq!(w0, "41434143411434143414414341434134333", "s2 at weight 0");
        cli(sock, "set server be/s2 weight 100%");
        let back: String = uris.iter().map(|u| get(port, u)).collect();
        assert_eq!(back, init, "s2 back at its configured weight");
        back
    });
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

fn check_rows_with(rows: &[(&str, &str)], hash_type: &str, weights: &[u32], runner: impl Fn(&str, &[u32]) -> String) {
    let mut wrong = Vec::new();
    for (opt, want) in rows {
        let balance = format!("balance uri {opt}{hash_type}");
        let got = runner(&balance, weights);
        if got != *want {
            wrong.push(format!("{balance:?} {weights:?}\n   got {got}\n  want {want}"));
        }
    }
    assert!(wrong.is_empty(), "{} of {} rows differ from HAProxy:\n{}", wrong.len(), rows.len(), wrong.join("\n"));
}

fn check_rows(rows: &[(&str, &str)], hash_type: &str, weights: &[u32]) {
    check_rows_with(rows, hash_type, weights, |b, w| answers_of(b, w, false, &OPTION_URIS));
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

/// HTTP/2 `balance uri` requests: `HAProxy` hashes `scheme://authority/path` when `:scheme`
/// and `:authority` are both present (default ports `:80`/`:443` stripped; `OPTIONS *` hashes
/// `scheme://authority` without `*`, non-`OPTIONS *` hashes `scheme://authority/`) unless
/// `path-only` is set; requests without `:authority` hash only `:path`.
///
/// Measured on `HAProxy` 3.5-dev8 (`/home/bhenc/ibex-worktrees/agy-eval/oracle/haproxy`,
/// `bind ... proto h2`). Reaches `lb::balance_uri_with_abs` via `H2Child::req_abs`.
fn h2_requests() -> Vec<Vec<(&'static str, &'static str)>> {
    let mut out: Vec<Vec<(&'static str, &'static str)>> = OPTION_URIS[..24]
        .iter()
        .map(|&p| vec![(":method", "GET"), (":scheme", "http"), (":authority", "h"), (":path", p)])
        .collect();
    for p in ["/a/b/c/d1", "/a/b?x=1", "/a/b?x=2", "/a/b"] {
        out.push(vec![(":method", "GET"), (":scheme", "http"), (":authority", "h"), (":path", p)]);
    }
    out.push(vec![(":method", "GET"), (":scheme", "http"), (":authority", "g"), (":path", "/a/b")]);
    out.push(vec![(":method", "GET"), (":scheme", "https"), (":authority", "h"), (":path", "/a/b")]);
    for &p in &OPTION_URIS[29..34] {
        out.push(vec![(":method", "GET"), (":scheme", "http"), (":authority", "h"), (":path", p)]);
    }
    out.extend([
        vec![(":method", "GET"), (":scheme", "http"), (":path", "/a/b")],
        vec![(":method", "GET"), (":scheme", "http"), (":path", "/a/b"), ("host", "h")],
        vec![(":method", "OPTIONS"), (":scheme", "http"), (":authority", "h"), (":path", "*")],
        vec![(":method", "OPTIONS"), (":scheme", "http"), (":path", "*")],
        vec![(":method", "GET"), (":scheme", "http"), (":authority", "h"), (":path", "*")],
        vec![(":method", "GET"), (":scheme", "http"), (":authority", "h:80"), (":path", "/a/b")],
        vec![(":method", "GET"), (":scheme", "http"), (":authority", "h:81"), (":path", "/a/b")],
        vec![(":method", "GET"), (":scheme", "https"), (":authority", "h:443"), (":path", "/a/b")],
        vec![(":method", "GET"), (":scheme", "https"), (":authority", "h:80"), (":path", "/a/b")],
    ]);
    out
}

const H2_4EQ_MAP: [(&str, &str); 17] = [
    ("", "23412341233423134441242224443322411223324333"),
    ("whole", "23412341233423131241243421243324411223324333"),
    ("len 4", "11111111111111111111111111111111111221311111"),
    ("len 10", "44444444444411111111111111114322311223321132"),
    ("len 12", "23412341233444434442222244443122144223324312"),
    ("depth 1", "22222222222222222222222222222122222332322211"),
    ("depth 2", "33333333333333333333333333332233333223333222"),
    ("depth 3", "23412341233411111111242211114422211223321444"),
    ("depth 4", "23412341233444434441242244443322444223324333"),
    ("path-only", "41234123411241312223424442222244233221142222"),
    ("whole path-only", "41234123411241313423421243422242233221142222"),
    ("path-only depth 1", "41234123411233333333424433333344433331143333"),
    ("path-only len 4", "41234123411222212224444422222244322221142222"),
    ("len 12 depth 3", "23412341233411111112222211114422211223321342"),
    ("whole len 15", "23412341233411132241144312243324411223324331"),
    ("whole depth 3", "23412341233411111111243411114424211223321444"),
    ("path-only whole len 9 depth 2", "41234123411222213424421223422242222221142222"),
];

const H2_4EQ_CONSISTENT: [(&str, &str); 6] = [
    ("", "13422144434224131114314421111122122221321111"),
    ("whole", "13422144434224133314314123311122122221321111"),
    ("len 10", "33333333333322222222222222223122422221322113"),
    ("depth 3", "13422144434222222224314422223322222221322134"),
    ("path-only", "14411231434413322222124412222222313223322222"),
    ("path-only whole len 9 depth 2", "14411231434422224222221224222224122223322222"),
];

const H2_W123_MAP: [(&str, &str); 6] = [
    ("", "32323132322332223332333333331233321332133221"),
    ("whole", "32323132322332222332332332331233321332133221"),
    ("len 10", "33333333333322222222222222223133222332132213"),
    ("depth 3", "32323132322322222222333322223333322332132333"),
    ("path-only", "32323132322331223331333333333333322331133333"),
    ("path-only whole len 9 depth 2", "32323132322333322333331332333333333331133333"),
];

const H2_W123_CONSISTENT: [(&str, &str); 6] = [
    ("", "33323123332233132223311132223122123222322111"),
    ("whole", "33323123332233133323312133323122123222322111"),
    ("len 10", "33333333333322222222222222223122222222322113"),
    ("depth 3", "33323123332222222223311122223322222222322333"),
    ("path-only", "12211231333312222222123312222222213223322222"),
    ("path-only whole len 9 depth 2", "12211231333322223322221223322222122223322222"),
];

fn answers_of_h2(balance: &str, weights: &[u32], reqs: &[Vec<(&'static str, &'static str)>]) -> String {
    with_alcyon(" proto h2", balance, weights, false, |port| h2_get_all(port, reqs))
}

#[test]
fn h2_uri_options_pick_haproxys_server_map_based() {
    let reqs = h2_requests();
    check_rows_with(&H2_4EQ_MAP, "", &[1, 1, 1, 1], |b, w| answers_of_h2(b, w, &reqs));
    check_rows_with(&H2_W123_MAP, "", &[1, 2, 3], |b, w| answers_of_h2(b, w, &reqs));
}

#[test]
fn h2_uri_options_pick_haproxys_server_consistent() {
    let reqs = h2_requests();
    check_rows_with(&H2_4EQ_CONSISTENT, "\n  hash-type consistent", &[1, 1, 1, 1], |b, w| answers_of_h2(b, w, &reqs));
    check_rows_with(&H2_W123_CONSISTENT, "\n  hash-type consistent", &[1, 2, 3], |b, w| answers_of_h2(b, w, &reqs));
}
