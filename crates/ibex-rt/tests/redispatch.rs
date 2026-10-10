// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `option redispatch [<interval>]` and what a connect retry does without it (T112).
//!
//! Measured on the reference `HAProxy` 3.5-dev8-885761-29 on 2026-10-03, `nbthread 1`, one
//! dead server and one live one, six sequential requests:
//!
//! * Without `option redispatch` a retry goes back to the server that failed
//!   (`stream_choose_redispatch`, `include/haproxy/stream.h`), whatever `retries` is: under
//!   `balance roundrobin` the requests alternate 503, 200, 503, 200, ... The task that
//!   started this (T94 said "200 in 4 of 4 runs") had `option redispatch` in `defaults`.
//! * With it, every retry re-balances away from the failed server for every algorithm
//!   that is not a hash (`roundrobin`, `first`, `leastconn`, `static-rr`, `random`): six 200.
//!   The interval (`1`, `2`, `-1`, `5`) changes nothing here, because the last term of
//!   the condition (more than one active server, not a hash) redispatches at once.
//! * `option redispatch 0` (and a non-numeric argument, `atol`) switches it off again;
//!   `no option redispatch` cancels an earlier one.
//!
//! The interval itself, where it can be observed only on one active server or a hash, is
//! checked as a decision table against `include/haproxy/stream.h` in
//! `the_interval_follows_stream_choose_redispatch`.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::lb::redispatch_due;

struct Daemon(Child, std::path::PathBuf);

impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_file(&self.1);
    }
}

fn live_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            c.set_read_timeout(Some(Duration::from_millis(500))).ok();
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    port
}

/// The response head to `GET <path>` with the extra header lines `hdr` (each ending CRLF).
fn get_head(port: u16, path: &str, hdr: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\n{hdr}Connection: close\r\n\r\n").expect("write");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).split("\r\n\r\n").next().unwrap_or("").to_string()
}

fn status_of(head: &str) -> String {
    head.split(' ').nth(1).unwrap_or("").to_string()
}

/// Six sequential requests through a backend made of `lines` (a dead server named `dead`
/// and a live one named `a`, in that order, are appended).
fn statuses(tag: &str, lines: &str) -> Vec<String> {
    statuses_with(tag, lines, "")
}

/// [`statuses`] with `a_opts` appended to the live server's line.
fn statuses_with(tag: &str, lines: &str, a_opts: &str) -> Vec<String> {
    heads(tag, lines, ("", a_opts), "", 6).iter().map(|h| status_of(h)).collect()
}

/// `n` sequential response heads, each request carrying the header lines `hdr`;
/// `(dead_opts, a_opts)` are appended to the two server lines.
fn heads(tag: &str, lines: &str, (dead_opts, a_opts): (&str, &str), hdr: &str, n: usize) -> Vec<String> {
    let live = live_backend();
    let dead = common::reserve_port();
    let port = common::reserve_port();
    // `timeout connect` under 1 s is also the turnaround before a retry of the same server,
    // on HAProxy as on Ibex (measured: six requests, `retries 3`, 12.1 s at `1s`, 2.5 s at
    // `200ms`); the dead server refuses at once, so nothing else here depends on it (T259).
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 200ms\n  timeout client 3s\n  timeout server 3s\n\
         frontend f\n  bind 127.0.0.1:{port}\n  default_backend be\n\
         backend be\n{lines}  server dead 127.0.0.1:{dead}{dead_opts}\n  server a 127.0.0.1:{live}{a_opts}\n"
    );
    let path = std::env::temp_dir().join(format!("ibex_t112_{}_{tag}", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let _d = Daemon(child, path);
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the daemon never listened on {port}");
        thread::sleep(Duration::from_millis(25));
    }
    (0..n).map(|i| get_head(port, &format!("/{i}"), hdr)).collect()
}

const ALTERNATING: [&str; 6] = ["503", "200", "503", "200", "503", "200"];

/// Control: without the option a retry returns to the dead server, so half the requests
/// fail whatever `retries` says. This passed before the change and must keep passing.
#[test]
fn without_redispatch_a_retry_goes_back_to_the_same_server() {
    for retries in [0, 1, 3] {
        let s = statuses(&format!("none{retries}"), &format!("  balance roundrobin\n  retries {retries}\n"));
        assert_eq!(s, ALTERNATING, "retries {retries}");
    }
}

/// `option redispatch` moves the retry off the failed server for every algorithm that is
/// not a hash, with any interval. `first` and `leastconn` chose the dead server again
/// (nothing told them to avoid it) and `random` drew it again one time in two.
#[test]
fn redispatch_reaches_the_live_server_for_every_non_hash_algorithm() {
    for balance in ["roundrobin", "first", "leastconn", "static-rr", "random"] {
        for opt in ["", " 1", " 2", " -1", " 5"] {
            let s = statuses(
                &format!("{balance}{}", opt.replace([' ', '-'], "")),
                &format!("  balance {balance}\n  retries 1\n  option redispatch{opt}\n"),
            );
            assert!(s.iter().all(|c| c == "200"), "balance {balance}, `option redispatch{opt}`: {s:?}");
        }
    }
}

/// `option redispatch 0` is off, as is a non-numeric interval (`atol` gives 0).
#[test]
fn redispatch_with_a_zero_interval_is_off() {
    for arg in ["0", "abc"] {
        let s = statuses(&format!("zero{arg}"), &format!("  balance roundrobin\n  retries 1\n  option redispatch {arg}\n"));
        assert_eq!(s, ALTERNATING, "`option redispatch {arg}`");
    }
}

/// The last `option redispatch` or `no option redispatch` in a section wins.
#[test]
fn the_last_redispatch_line_wins() {
    let s = statuses("neg", "  balance first\n  retries 1\n  option redispatch\n  no option redispatch\n");
    assert!(s.iter().all(|c| c == "503"), "`no option redispatch` after `option redispatch`: {s:?}");
    let s = statuses("again", "  balance first\n  retries 1\n  option redispatch 0\n  option redispatch\n");
    assert!(s.iter().all(|c| c == "200"), "`option redispatch` after `option redispatch 0`: {s:?}");
}

/// A client whose cookie names the dead server (`cookie SRV insert indirect`, the dead
/// server `cookie d`). `HAProxy`: without the option 503 twice; with it the retry leaves
/// the persistence (`SF_DIRECT` cleared, `TX_CK_DOWN`), reaches the live server, and the
/// response sets the cookie for it, `SRV=a`. Ibex answered 503 then 200 and the one 200
/// came from the round-robin turn, not from the retry.
#[test]
fn a_redispatch_leaves_the_persistence_cookie_s_dead_server() {
    let lines = "  balance roundrobin\n  retries 1\n  cookie SRV insert indirect\n";
    let servers = (" cookie d", " cookie a");
    let h = heads("ckplain", lines, servers, "Cookie: SRV=d\r\n", 2);
    let st: Vec<_> = h.iter().map(|x| status_of(x)).collect();
    assert_eq!(st, ["503", "503"], "without the option the retry stays on the cookie's server: {h:?}");

    let h = heads("ckredis", &format!("{lines}  option redispatch\n"), servers, "Cookie: SRV=d\r\n", 2);
    let st: Vec<_> = h.iter().map(|x| status_of(x)).collect();
    assert_eq!(st, ["200", "200"], "{h:?}");
    assert!(
        h.iter().all(|x| x.to_ascii_lowercase().contains("set-cookie: srv=a; path=/")),
        "the response must set the live server's cookie: {h:?}"
    );
}

/// One active server and a backup: the redispatch asks the balancer to avoid the failed
/// server, but a backup is not another active server, so `HAProxy` asks the same one again
/// (six 503, with and without the option). An implementation that simply excludes the
/// failed server reaches the backup and answers 200.
#[test]
fn a_backup_is_not_a_way_out_of_the_only_active_server() {
    for opt in ["", "  option redispatch\n"] {
        let s = statuses_with("backup", &format!("  balance roundrobin\n  retries 1\n{opt}"), " backup");
        assert!(s.iter().all(|c| c == "503"), "`{opt}`: {s:?}");
    }
}

/// `include/haproxy/stream.h` `stream_choose_redispatch`, term by term. `retries_done` is
/// `s->conn_retries` after the failure that is being retried. With one active server and
/// not a hash, only the first two terms can say yes.
#[test]
fn the_interval_follows_stream_choose_redispatch() {
    // (after, max_retries, retries_done, expected)
    let table: &[(i32, u16, u16, bool)] = &[
        // the default, -1: on the last retry
        (-1, 3, 1, false),
        (-1, 3, 2, false),
        (-1, 3, 3, true),
        (-1, 1, 1, true),
        // -2: one retry before the last; 1 + 3 - 2 == 2
        (-2, 3, 1, false),
        (-2, 3, 2, true),
        (-2, 3, 3, false),
        // 1: every retry; 2: every second; 5 with retries 3: never
        (1, 3, 1, true),
        (1, 3, 3, true),
        (2, 5, 1, false),
        (2, 5, 2, true),
        (2, 5, 3, false),
        (2, 5, 4, true),
        (5, 3, 3, false),
        // 0 is off (the option is cleared at parse time); a zero modulus is not a division
        (0, 3, 3, false),
        (-4, 3, 3, false),
    ];
    for &(after, max, done, want) in table {
        assert_eq!(
            redispatch_due(after, max, done, true, false, 1, false),
            want,
            "after {after}, retries {max}, {done} done"
        );
    }
    // a server that is not running redispatches at once, any interval
    assert!(redispatch_due(5, 3, 1, false, false, 1, false));
    // more than one active server and not a hash: at once, unless the stream is persistent
    assert!(redispatch_due(5, 3, 1, true, false, 2, false));
    assert!(!redispatch_due(5, 3, 1, true, true, 2, false), "SF_DIRECT keeps the retry on its server");
    assert!(!redispatch_due(5, 3, 1, true, false, 2, true), "a hash would choose the same server");
    assert!(!redispatch_due(5, 3, 1, true, false, 1, false), "one active server");
}

/// A retry on the same server waits `MIN(1s, timeout connect)` after a refused connect
/// (`SC_ST_TAR`, `src/backend.c`). Measured on the reference with one closed port,
/// `timeout connect 300ms`: `retries 2` answers 503 after 0.60 s, `retries 3` after 0.90 s,
/// one turnaround per retry (the attempts themselves are refused at once).
#[test]
fn a_retry_on_the_same_server_waits_a_turnaround() {
    let dead = common::reserve_port();
    let port = common::reserve_port();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 300ms\n  timeout client 3s\n  timeout server 3s\n  retries 2\n\
         frontend f\n  bind 127.0.0.1:{port}\n  default_backend be\n\
         backend be\n  server dead 127.0.0.1:{dead}\n"
    );
    let path = std::env::temp_dir().join(format!("ibex_t131_tar_{}", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let _d = Daemon(child, path);
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the daemon never listened on {port}");
        thread::sleep(Duration::from_millis(25));
    }
    let t = Instant::now();
    let head = get_head(port, "/", "");
    let took = t.elapsed();
    assert_eq!(status_of(&head), "503");
    assert!(took >= Duration::from_millis(550), "two retries took {took:?}, the reference waits 0.60 s");
    assert!(took < Duration::from_millis(1500), "two retries took {took:?}");
}
