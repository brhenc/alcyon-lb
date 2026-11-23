// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `hash-type <method> <function> [avalanche]`: the hash function and the `avalanche`
//! modifier of the hash-based `balance`s. Every row of the task table, measured on the
//! reference `HAProxy` 3.5-dev11 (`/var/tmp/qwen-next-eval/oracle/haproxy`, 2026-11-23):
//! each row is a `mode http` backend with four servers `s1`..`s4` (no weights) and 16
//! requests; the answer is the number of the answering server per request.
//!
//! `gen_hash` (`src/backend.c`) applies the configured hash function to the key and the
//! `avalanche` modifier to its result; `get_server_uh` feeds it the URI and `get_server_sh`
//! (`balance source`) does not use it for the function at all, only for the modifier.
//! Reaches the data path in `lb::hash_uri` (reads `proxy.hash_type`) and
//! `lb::balance_source`, called from `Proxy::select_server_with_key_abs_idx` (`engine.rs`).
//!
//! `hash-type consistent` alone means `sdbm avalanche`; naming a function turns the
//! default avalanche off (`consistent sdbm` hashes `sdbm`, no avalanche).
//!
//! The two `url_param n` rows are refused by `Alcyon` at load, because `balance url_param`
//! itself is unimplemented: the assertion there is that the `hash-type` line parses and the
//! refusal names the balance, not the hash.
//!
//! `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`: it passes all.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static RUN: AtomicUsize = AtomicUsize::new(0);

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
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    write!(s, "GET {uri} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    if out.starts_with("HTTP/1.1 200") { out.chars().last().unwrap_or('x') } else { 'x' }
}

/// One request from a client bound to `src` (its address is the `balance source` key).
fn from(src: &str, port: u16) -> char {
    let fd = rustix::net::socket_with(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("socket");
    rustix::net::bind(&fd, &format!("{src}:0").parse::<SocketAddr>().expect("addr")).expect("bind source");
    rustix::net::connect(&fd, &format!("127.0.0.1:{port}").parse::<SocketAddr>().expect("addr")).expect("connect");
    let mut s = TcpStream::from(fd);
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    write!(s, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    if out.starts_with("HTTP/1.1 200") { out.chars().last().unwrap_or('x') } else { 'x' }
}

/// The answering server's number for the 16 requests of the row: `GET /p0` .. `/p15`
/// (`Host: x`) for `uri`, `GET /q?n=0` .. `/q?n=15` for `url_param`, and `GET /` from the
/// client addresses `127.0.0.1` .. `127.0.0.16` for `source`. `Err`: the binary refused
/// to load the configuration (captured stderr).
fn measure(balance: &str, htype: Option<&str>) -> Result<String, String> {
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut servers = String::new();
    for i in 1..=4 {
        servers.push_str(&format!("  server s{i} 127.0.0.1:{}\n", backend(i)));
    }
    let ht = htype.map_or(String::new(), |h| format!("  hash-type {h}\n"));
    let port = common::reserve_port();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind 127.0.0.1:{port}\n  default_backend be\n\
         backend be\n  balance {balance}\n{ht}{servers}"
    );
    let path = std::env::temp_dir().join(format!(
        "alcyon_htfn_{}_{}",
        std::process::id(),
        RUN.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, &cfg).expect("write config");
    let mut child = Command::new(&bin)
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Alcyon)
        .expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        if let Some(status) = child.0.try_wait().expect("poll the child") {
            return Err(format!("the daemon refused the configuration, exit {status}"));
        }
        assert!(
            Instant::now() < deadline,
            "the daemon never listened: {balance} {htype:?}"
        );
        thread::sleep(Duration::from_millis(25));
    }
    let got: String = if balance.starts_with("url_param") {
        (0..16).map(|i| get(port, &format!("/q?n={i}"))).collect()
    } else if balance == "source" {
        (1..=16).map(|i| from(&format!("127.0.0.{i}"), port)).collect()
    } else {
        (0..16).map(|i| get(port, &format!("/p{i}"))).collect()
    };
    common::stop(&mut child.0);
    let _ = std::fs::remove_file(&path);
    Ok(got)
}

/// `<bin> -c -f <cfg>`: the configuration check; `Err(stderr)` when the config is refused.
fn check_config(bin: &str, balance: &str, htype: &str) -> Result<(), String> {
    let port = common::reserve_port();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n\
         frontend f\n  bind 127.0.0.1:{port}\n  default_backend be\n\
         backend be\n  balance {balance}\n  hash-type {htype}\n  server s1 127.0.0.1:9\n"
    );
    let path = std::env::temp_dir().join(format!(
        "alcyon_htfn_c_{}_{}",
        std::process::id(),
        RUN.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, &cfg).expect("write config");
    let out = Command::new(bin).arg("-c").arg("-f").arg(&path).output().expect("run -c");
    let _ = std::fs::remove_file(&path);
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

/// One row of the task's answer table, both binaries: the answering server per request.
const ROWS: &[(&str, Option<&str>, &str)] = &[
    ("uri", None, "4123412341123412"),
    ("uri", Some("map-based sdbm"), "4123412341123412"),
    ("uri", Some("map-based sdbm avalanche"), "1332144111234343"),
    ("uri", Some("map-based djb2"), "1234123412234123"),
    ("uri", Some("map-based wt6"), "2424242424111144"),
    ("uri", Some("map-based crc32"), "2424131342313142"),
    ("uri", Some("map-based djb2 avalanche"), "4213334143343421"),
    ("uri", Some("consistent"), "1441123143441344"),
    ("uri", Some("consistent sdbm"), "4444444444333333"),
    ("uri", Some("consistent djb2"), "4444444444222222"),
    ("uri", Some("consistent crc32 avalanche"), "4322444134211123"),
    // The `none` function reads the key as a decimal integer (`read_int64`); a URI path
    // has no leading digit, so the hash is 0: every request takes slot 0, the first
    // server, and on the ring the point nearest 0.
    ("uri", Some("map-based none"), "1111111111111111"),
    ("uri", Some("consistent none"), "4444444444444444"),
    // `balance url_param`: unimplemented in `Alcyon`, which refuses the load; the row is
    // measured on `HAProxy` alone.
    ("url_param n", Some("map-based none"), "1234123412341234"),
    ("url_param n", Some("consistent none"), "4444444444444444"),
    ("source", Some("map-based djb2"), "2341234123412341"),
    ("source", Some("map-based sdbm avalanche"), "4434434342434111"),
    ("source", Some("consistent sdbm"), "2222222222222222"),
];

#[test]
fn hash_type_function_matches_haproxy() {
    let oracle = std::env::var("T281_ORACLE").ok();
    for (balance, htype, expected) in ROWS {
        match measure(balance, *htype) {
            Ok(got) => {
                assert_eq!(
                    &got, *expected,
                    "{balance} {htype:?}: the answering servers (oracle: {expected:?})"
                );
            }
            Err(why) => {
                // `Alcyon` alone refuses what it cannot implement; the oracle answers.
                let url_param_unimplemented = balance.starts_with("url_param") && oracle.is_none();
                assert!(
                    url_param_unimplemented,
                    "{balance} {htype:?}: {why}"
                );
            }
        }
    }
}

#[test]
fn url_param_row_refuses_on_the_balance_not_the_hash() {
    // The `hash-type` line of the two `url_param` rows is valid `HAProxy` syntax; `Alcyon`'s
    // refusal of the row must name the unimplemented balance, not the hash.
    let oracle = std::env::var("T281_ORACLE").is_ok();
    for htype in ["map-based none", "consistent none"] {
        match check_config(&std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string()), "url_param n", htype) {
            Ok(()) => assert!(oracle, "{htype}: the oracle answers the row, Alcyon refuses it"),
            Err(stderr) => {
                assert!(
                    !oracle,
                    "the oracle refused a valid configuration: {stderr}"
                );
                assert!(
                    stderr.contains("unknown balance algorithm"),
                    "{htype}: the refusal must name the balance, not the hash-type: {stderr}"
                );
            }
        }
    }
}

/// The task's load-time refusals, word for word: `<bin> -c` exits non-zero and its stderr
/// carries `haproxy`'s exact message after `parsing [file:line] : `.
#[test]
fn hash_type_refusals_match_haproxy() {
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    for (htype, message) in [
        ("map-based md5", "'hash-type' only supports 'sdbm', 'djb2', 'crc32', or 'wt6' hash functions."),
        // The names are case-sensitive.
        ("consistent SDBM", "'hash-type' only supports 'sdbm', 'djb2', 'crc32', or 'wt6' hash functions."),
        ("consistent sdbm foo", "'hash-type' only supports 'avalanche' as a modifier for hash functions."),
        ("avalanche", "experimental feature 'hash-type avalanche' is not supported anymore, please use 'hash-type map-based sdbm avalanche' instead."),
        ("bogus", "'hash-type' only supports 'consistent' and 'map-based'."),
    ] {
        let err = match check_config(&bin, "uri", htype) {
            Ok(()) => panic!("{htype:?}: refused a configuration haproxy accepts"),
            Err(err) => err,
        };
        assert!(
            err.contains(message),
            "{htype:?}: expected haproxy's words {message:?}, got:\n{err}"
        );
    }
    // `none` is a hash function, with or without the modifier: both load.
    assert!(check_config(&bin, "uri", "map-based none").is_ok(), "map-based none must load");
    assert!(
        check_config(&bin, "uri", "map-based none avalanche").is_ok(),
        "map-based none avalanche must load"
    );
}
