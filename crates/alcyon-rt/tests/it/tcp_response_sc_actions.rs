// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The stick-counter actions of `tcp-response content`: `sc-inc-gpc0`, `sc-inc-gpc1`,
//! `sc-inc-gpc`, `sc-add-gpc`, `sc-set-gpt0` and `sc-set-gpt`, the way the request side
//! already takes and runs them. The response side once refused every one of them
//! (`'tcp-response content sc-inc-gpc0' is not implemented`); the actions are shared with
//! the request side in `HAProxy` (`src/stick_table.c`), only the sample direction changes,
//! so an expression in a `tcp-response` rule reads the response, as `res.len` does.
//!
//! Measured on `HAProxy` 3.5-dev11, 2026-11-23, with the configuration of the task: the
//! frontend tracks `src` in `st` (`gpc0,gpc1,gpt0`) and `st2` (`gpc(3),gpt(3)`); the server
//! reads one line, answers `hello\n` and closes; each row opens three connections in turn,
//! each sending `x\n` and reading until close. After the three, the test reads `show
//! table st` and `show table st2` on the stats socket and checks the entry for
//! `key=127.0.0.1` (every counter not listed is 0). The test waits for the stats socket,
//! not the frontend: a probe connection to the frontend is tracked too.
//!
//! `HAProxy` evaluates the response rules once before any response byte has arrived, so an
//! unconditional rule there sees `res.len` 0; Alcyon first evaluates them when data
//! arrives. No row of the table below depends on the difference (every row whose value is
//! a `res.len` fetch carries a condition that waits for the data), so both binaries give
//! the same entry.
//!
//! The same six actions also run on an HTTP stream, through the response path that runs
//! `be`'s `tcp-response` rules where the other response actions run. The rows there send a
//! real `GET` and the server answers a valid `200` (a request that is not HTTP is 400'd by
//! `HAProxy` before the tracking rules run, and an invalid response never reaches the
//! response rules on Alcyon); the values are the same as in TCP mode.
//!
//! Set `T281_ORACLE=/path/to/haproxy` to run against `HAProxy`: every row passes there.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// `(st's gpt0, gpc0, gpc1)`, `(st2's gpt0, gpt1, gpt2, gpc0, gpc1, gpc2)` after the three
/// connections of the row.
const ROWS: &[(&str, (u64, u64, u64), (u64, u64, u64, u64, u64, u64))] = &[
    ("tcp-response content sc-inc-gpc0(0)", (0, 3, 0), (0, 0, 0, 0, 0, 0)),
    ("tcp-response content sc-inc-gpc1(0)", (0, 0, 3), (0, 0, 0, 0, 0, 0)),
    // No id is `sc0`.
    ("tcp-response content sc-inc-gpc0", (0, 3, 0), (0, 0, 0, 0, 0, 0)),
    ("tcp-response content sc-inc-gpc0(1)", (0, 0, 0), (0, 0, 0, 3, 0, 0)),
    ("tcp-response content sc-set-gpt0(0) 7", (7, 0, 0), (0, 0, 0, 0, 0, 0)),
    ("tcp-response content sc-inc-gpc(2,1)", (0, 0, 0), (0, 0, 0, 0, 0, 3)),
    ("tcp-response content sc-add-gpc(1,1) 5", (0, 0, 0), (0, 0, 0, 0, 15, 0)),
    ("tcp-response content sc-set-gpt(2,1) 9", (0, 0, 0), (0, 0, 9, 0, 0, 0)),
    // The condition never holds: the response is six bytes.
    ("tcp-response content sc-inc-gpc0(0) if { res.len gt 100 }", (0, 0, 0), (0, 0, 0, 0, 0, 0)),
    // `accept` ends the list: the last rule never runs.
    (
        "tcp-response content sc-inc-gpc1(0)\ntcp-response content accept\ntcp-response content sc-inc-gpc0(0)",
        (0, 0, 3),
        (0, 0, 0, 0, 0, 0),
    ),
    // The condition waits for the data; the response is six bytes.
    ("tcp-response inspect-delay 1s\ntcp-response content sc-inc-gpc0(0) if { res.len gt 3 }", (0, 3, 0), (0, 0, 0, 0, 0, 0)),
    ("tcp-response inspect-delay 1s\ntcp-response content sc-set-gpt0(0) res.len if { res.len gt 0 }", (6, 0, 0), (0, 0, 0, 0, 0, 0)),
    ("tcp-response inspect-delay 1s\ntcp-response content sc-add-gpc(1,1) res.len if { res.len gt 0 }", (0, 0, 0), (0, 0, 0, 0, 18, 0)),
];

const CFG: &str = r####"global
  stats socket {sock} level admin
defaults
  mode {mode}
  timeout connect 1s
  timeout client 5s
  timeout server 5s
frontend f
  bind {fport}
  tcp-request content track-sc0 src table st
  tcp-request content track-sc1 src table st2
  default_backend be
backend st
  stick-table type ip size 1k store gpc0,gpc1,gpt0
backend st2
  stick-table type ip size 1k store gpc(3),gpt(3)
backend be
{rules}
  server s1 {srv}
"####;

/// The server of the rows: reads one line, answers `resp`, closes.
fn server(addr: SocketAddr, resp: &'static [u8]) {
    let Ok(l) = TcpListener::bind(addr) else {
        panic!("bind {addr}");
    };
    thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(mut c) = conn else { continue };
            let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
            let mut got_nl = false;
            let mut b = [0u8; 8];
            while !got_nl {
                match c.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got_nl = b[..n].contains(&b'\n'),
                }
            }
            let _ = c.write_all(resp);
        }
    });
}

/// One connection of a row: sends `req`, reads until close, checks the answer when
/// `want` is set (the HTTP rows forward the server's 200; its text is not asserted).
fn hit(addr: SocketAddr, req: &[u8], want: Option<&[u8]>) {
    let mut c = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(req).expect("send");
    let mut got = Vec::new();
    c.read_to_end(&mut got).expect("read to close");
    if let Some(want) = want {
        assert_eq!(got, want);
    }
}

/// The counters of the `key=127.0.0.1` entry of `table`, in the order `show table` prints
/// them: every `gpc*`/`gpt*` field of the stored set.
fn counters(sock: &Path, table: &str) -> Vec<(String, u64)> {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("show table {table}\n").as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).expect("cli answer");
    out.lines()
        .find(|l| l.contains("key=127.0.0.1"))
        .expect("the client entry is in the table")
        .split_whitespace()
        .filter_map(|w| w.split_once('='))
        .filter(|(k, _)| k.starts_with("gpc") || k.starts_with("gpt"))
        .map(|(k, v)| (k.to_string(), v.parse().expect("counter")))
        .collect()
}

fn one_row(
    bin: &str,
    i: usize,
    mode: &str,
    rules: &str,
    srv_resp: &'static [u8],
    req: &[u8],
    want: Option<&[u8]>,
    want_st: (u64, u64, u64),
    want_st2: (u64, u64, u64, u64, u64, u64),
) {
    let dir = TempDir::new().expect("tmpdir");
    let sock = dir.path().join("s");
    let (fport, srv) = (common::reserve_addr(), common::reserve_addr());
    server(srv, srv_resp);
    let rules = rules.lines().map(|l| format!("  {l}")).collect::<Vec<_>>().join("\n");
    let cfg_text = CFG.replace("{mode}", mode)
        .replace("{sock}", &sock.display().to_string())
        .replace("{fport}", &fport.to_string())
        .replace("{srv}", &srv.to_string())
        .replace("{rules}", &rules);
    let cfg = dir.path().join("cfg");
    std::fs::write(&cfg, cfg_text).expect("cfg");
    let mut child = Command::new(bin)
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("row {i}: spawn {bin}: {e}"));
    // The stats socket, not the frontend: a probe connection to the frontend is tracked too.
    let mut stderr = child.stderr.take();
    let drained = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    {
        let d = drained.clone();
        thread::spawn(move || {
            if let Some(stderr) = stderr.as_mut() {
                let mut out = String::new();
                let _ = std::io::Read::read_to_string(stderr, &mut out);
                let mut d = d.lock().expect("stderr lock");
                d.push_str(&out);
            }
        });
    }
    let t0 = Instant::now();
    loop {
        if UnixStream::connect(&sock).is_ok() {
            break;
        }
        if let Some(status) = child.try_wait().expect("wait") {
            let out = drained.lock().expect("stderr lock").clone();
            panic!("row {i}: {bin} exited early: {status}; stderr:\n{out}");
        }
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "row {i}: the stats socket never opened; stderr:\n{}",
            drained.lock().expect("stderr lock")
        );
        thread::sleep(Duration::from_millis(20));
    }
    for _ in 0..3 {
        hit(fport, req, want);
    }
    let st = counters(&sock, "st");
    let st2 = counters(&sock, "st2");
    let mut wrong = Vec::new();
    let want_st: Vec<(String, u64)> =
        [("gpt0", want_st.0), ("gpc0", want_st.1), ("gpc1", want_st.2)]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
    let want_st2: Vec<(String, u64)> = [
        ("gpt0", want_st2.0),
        ("gpt1", want_st2.1),
        ("gpt2", want_st2.2),
        ("gpc0", want_st2.3),
        ("gpc1", want_st2.4),
        ("gpc2", want_st2.5),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    for (k, v) in &want_st {
        let got = st.iter().find(|(n, _)| n == k).map_or(0, |(_, n)| *n);
        if got != *v {
            wrong.push(format!("row {i} ({rules:?}): st {k} is {got}, wanted {v}"));
        }
    }
    for (k, v) in &want_st2 {
        let got = st2.iter().find(|(n, _)| n == k).map_or(0, |(_, n)| *n);
        if got != *v {
            wrong.push(format!("row {i} ({rules:?}): st2 {k} is {got}, wanted {v}"));
        }
    }
    common::stop(&mut child);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn response_sc_actions_run_on_the_response_side() {
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    for (i, (rules, st, st2)) in ROWS.iter().enumerate() {
        one_row(&bin, i, "tcp", rules, b"hello\n", b"x\n", Some(b"hello\n"), *st, *st2);
    }
}

/// The same six actions on an HTTP stream: the `tcp-response content` rules of a backend
/// run there too, where the other response actions run (`apply_http_response_rules`), and
/// the entries the `tcp-request content track-sc*` rules bound to the request are the ones
/// they update. Measured on `HAProxy` 3.5-dev11 with the same tables, `defaults mode http`,
/// the client sending a `GET` and the server answering a valid `200` whose body is
/// `hello\n` (a request `HAProxy` 400's never reaches the tracking rules).
const HTTP_ROWS: &[(&str, (u64, u64, u64), (u64, u64, u64, u64, u64, u64))] = &[
    ("tcp-response content sc-inc-gpc0(0)", (0, 3, 0), (0, 0, 0, 0, 0, 0)),
    ("tcp-response content sc-inc-gpc1(0)", (0, 0, 3), (0, 0, 0, 0, 0, 0)),
    ("tcp-response content sc-set-gpt0(0) 7", (7, 0, 0), (0, 0, 0, 0, 0, 0)),
    ("tcp-response content sc-inc-gpc(2,1)", (0, 0, 0), (0, 0, 0, 0, 0, 3)),
    ("tcp-response content sc-add-gpc(1,1) 5", (0, 0, 0), (0, 0, 0, 0, 15, 0)),
    ("tcp-response content sc-set-gpt(2,1) 9", (0, 0, 0), (0, 0, 9, 0, 0, 0)),
];

const HTTP_REQ: &[u8] = b"GET / HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n";
const HTTP_RES: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\nconnection: close\r\n\r\nhello\n";

#[test]
fn the_actions_run_in_http_mode_streams_too() {
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    for (i, (rules, st, st2)) in HTTP_ROWS.iter().enumerate() {
        one_row(&bin, i, "http", rules, HTTP_RES, HTTP_REQ, None, *st, *st2);
    }
}

/// At load time, the response side refuses exactly what the request side refuses, with the
/// same words. The two rows were measured on `HAProxy` 3.5-dev11 `-c`, in a `backend b`.
const REFUSALS: &[(&str, &str)] = &[
    (
        "tcp-response content sc-inc-gpc(1)",
        "Missing gpc ID 'sc-inc-gpc(1)'. Expects sc-inc-gpc(<GPC ID>,<Track ID>)",
    ),
    (
        "tcp-response content sc-set-gpt(0,0) 1 foo",
        "'tcp-response content sc-set-gpt(0,0)' only accepts 'if' or 'unless', in backend 'b' (got 'foo')",
    ),
];

const REFUSAL_CFG: &str = r####"global
defaults
  mode tcp
  timeout connect 1s
  timeout client 5s
  timeout server 5s
frontend f
  bind {fport}
  default_backend b
backend b
{rule}
  server s1 {srv}
"####;

#[test]
fn the_response_side_refuses_like_the_request_side() {
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut wrong = Vec::new();
    for (i, (rule, want)) in REFUSALS.iter().enumerate() {
        let dir = TempDir::new().expect("tmpdir");
        let (fport, srv) = (common::reserve_addr(), common::reserve_addr());
        let cfg_text = REFUSAL_CFG.replace("{fport}", &fport.to_string())
            .replace("{srv}", &srv.to_string())
            .replace("{rule}", &format!("  {rule}"));
        let cfg = dir.path().join("cfg");
        std::fs::write(&cfg, cfg_text).expect("cfg");
        let out = Command::new(&bin).arg("-c").arg("-f").arg(&cfg).output().expect("-c");
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        if out.status.success() || !text.lines().any(|l| l.contains(want)) {
            wrong.push(format!("row {i} ({rule}): wanted {want:?} in the -c output, got {text:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
