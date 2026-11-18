// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `clear counters server <be>/<sv> [force]` (spec: the reg-test
//! `stats/clear_counters_server.vtc`): the named server's cumulative counters reset to 0,
//! the sibling server's stay.
//!
//! Every expected value was measured on the 3.5-dev11 oracle
//! (`/var/tmp/qwen-next-eval/oracle/haproxy`): after the clear, `stot`, `lbtot`, `req_tot`,
//! the `hrsp_*` classes, `bin`, `bout`, `connect`, `reuse`, `econ`, `eresp`, `wretr`,
//! `wredis` and `cli_abrt`/`srv_abrt` of the named server read 0, the other server is
//! untouched, and counting starts again from 0. Set `T281_ORACLE=/path/to/haproxy` to run
//! these tests against `HAProxy`: they pass. The per-thread test is Alcyon-only
//! (`tune.alcyon.counters` is not a `HAProxy` keyword).

use crate::common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// The binary under test: alcyon, or the oracle when `T281_ORACLE` is set.
fn bin() -> String {
    std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

fn is_oracle() -> bool {
    std::env::var("T281_ORACLE").is_ok()
}

/// A backend answering every request `200` with `ok`.
fn backend(addr: SocketAddr) {
    let listener = TcpListener::bind(addr).expect("bind backend");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(10))).ok();
                let mut r = BufReader::new(&mut c);
                let mut line = String::new();
                loop {
                    line.clear();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            });
        }
    });
}

struct Proxy {
    child: std::process::Child,
    sock: PathBuf,
    cfg: PathBuf,
    fe: u16,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
        let _ = std::fs::remove_file(&self.cfg);
    }
}

/// The vtc's configuration: one frontend, one backend, `s1` and the backup `s2`.
/// `counters` is a `tune.alcyon.counters` line (Alcyon only), `nbthread` the worker count.
fn start(counters: Option<&str>, nbthread: usize) -> Proxy {
    let (fe, p1, p2) = (common::reserve_port(), common::reserve_port(), common::reserve_port());
    backend(SocketAddr::from(([127, 0, 0, 1], p1)));
    backend(SocketAddr::from(([127, 0, 0, 1], p2)));
    let dir = std::env::temp_dir();
    let id = format!("alcyon_clear_counters_server_{}_{}_{}", nbthread, std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
    let sock = dir.join(format!("{id}.sock"));
    let cfg = dir.join(format!("{id}.cfg"));
    let tune = counters.map_or(String::new(), |m| format!("  tune.alcyon.counters {m}\n"));
    std::fs::write(
        &cfg,
        format!(
            "global\n  nbthread {nbthread}\n{tune}  stats socket {} level admin\n\
             defaults\n  mode http\n  timeout connect 5s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind 127.0.0.1:{fe}\n  default_backend be\n\
             backend be\n  server s1 127.0.0.1:{p1}\n  server s2 127.0.0.1:{p2} backup\n",
            sock.display()
        ),
    )
    .expect("write config");
    let child = Command::new(bin())
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn proxy");
    let p = Proxy { child, sock, cfg, fe };
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", p.fe)).is_err() || !p.sock.exists() {
        assert!(Instant::now() < deadline, "the proxy never listened");
        thread::sleep(Duration::from_millis(20));
    }
    p
}

fn request(p: &Proxy) {
    let mut s = TcpStream::connect(("127.0.0.1", p.fe)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = Vec::new();
    s.read_to_end(&mut out).expect("read");
    assert!(out.starts_with(b"HTTP/1.1 200"), "the answer: {out:?}");
}

/// One CLI command, its own connection (closed by the proxy afterwards).
fn cli(p: &Proxy, cmd: &str) -> String {
    let mut c = UnixStream::connect(&p.sock).expect("connect cli");
    c.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = String::new();
    c.read_to_string(&mut out).expect("read");
    out
}

/// The `be` server rows of `show stat`, `svname` to its fields.
fn rows(p: &Proxy) -> std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>> {
    let out = cli(p, "show stat be 4 -1");
    let mut lines = out.lines();
    let header: Vec<&str> = lines.next().expect("header").trim_start_matches("# ").split(',').collect();
    let mut res = std::collections::BTreeMap::new();
    for l in lines {
        if l.is_empty() {
            continue;
        }
        let f: Vec<&str> = l.split(',').collect();
        if f[0] == "be" {
            res.insert(f[1].to_string(), header.iter().zip(f.iter()).map(|(h, v)| (h.to_string(), v.to_string())).collect());
        }
    }
    res
}

fn col(p: &Proxy, sv: &str, name: &str) -> String {
    let r = rows(p);
    r.get(sv).unwrap_or_else(|| panic!("no row for {sv} in show stat")).get(name).unwrap_or_else(|| panic!("no {name} column")).clone()
}

/// The vtc's scenario: two requests (both to `s1`), the clear of `s1`, and the checks of
/// what reset and what stayed.
fn scenario(counters: Option<&str>) {
    let p = start(counters, 2);

    // Two requests, both to s1 (s2 is backup); s1 accumulates, s2 stays at zero.
    request(&p);
    request(&p);
    assert_eq!(col(&p, "s1", "stot"), "2", "pre: s1 served both");
    assert_eq!(col(&p, "s1", "lbtot"), "2", "pre: s1 chosen twice");
    assert_eq!(col(&p, "s1", "req_tot"), "2", "pre: s1 parsed two requests");
    assert_eq!(col(&p, "s1", "hrsp_2xx"), "2", "pre: s1 sent two 200");
    assert_eq!(col(&p, "s1", "connect"), "2", "pre: s1 took two connections");
    assert_ne!(col(&p, "s1", "bin"), "0", "pre: s1 counted request bytes");
    assert_ne!(col(&p, "s1", "bout"), "0", "pre: s1 counted response bytes");
    assert_eq!(col(&p, "s2", "stot"), "0", "pre: the backup served nothing");

    // The misses, as the oracle answers them.
    assert!(cli(&p, "clear counters server nosuch/s1").contains("No such backend"), "miss the backend");
    assert!(cli(&p, "clear counters server be/nosuch").contains("No such server"), "miss the server");

    // The clear of s1 and only s1.
    assert!(cli(&p, "clear counters server be/s1").contains("Server counters cleared"), "the clear");
    for name in ["stot", "lbtot", "req_tot", "hrsp_2xx", "bin", "bout", "connect", "reuse", "econ", "eresp", "wretr", "wredis", "cli_abrt", "srv_abrt"] {
        assert_eq!(col(&p, "s1", name), "0", "s1 {name} after the clear");
    }
    assert_eq!(col(&p, "s2", "stot"), "0", "s2 untouched");

    // Counting starts again from zero.
    request(&p);
    request(&p);
    assert_eq!(col(&p, "s1", "stot"), "2", "s1 recounts from zero");

    // 'force' is accepted and is a no-op for process-local counters.
    assert!(cli(&p, "clear counters server be/s2 force").contains("Server counters cleared"), "the forced clear");

    // The command (with its 'force' option) is discoverable via help.
    let help = cli(&p, "help");
    assert!(
        help.lines().any(|l| l.contains("clear counters") && l.contains("server") && l.contains("force")),
        "help: no 'clear counters ... server ... force' line in:\n{help}"
    );
}

#[test]
fn server_counters_reset_and_no_other() {
    scenario(None);
}

/// Under `tune.alcyon.counters per-thread` the same clear must zero the rows of every
/// worker's slab that counted on the server (T582: a reader counts a stale row as zero, and
/// the owner zeroes its own before it next writes). Alcyon-only.
#[test]
fn server_counters_reset_under_per_thread() {
    if is_oracle() {
        return;
    }
    scenario(Some("per-thread"));
}
