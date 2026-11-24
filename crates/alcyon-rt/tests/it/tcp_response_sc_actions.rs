// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The stick-counter actions of `tcp-response content`: `sc-inc-gpc0`, `sc-inc-gpc1`,
//! `sc-inc-gpc`, `sc-add-gpc`, `sc-set-gpt0` and `sc-set-gpt`, run on the entry the
//! connection tracks, as `HAProxy` does (`action_inc_gpc` and its siblings in
//! `src/stick_table.c`, shared with every rule set; only the sample direction differs).
//!
//! Measured on 11-23 on `HAProxy` 3.5-dev11. `T281_ORACLE=<haproxy>` runs this file
//! against it: every row of the task's tables is a row here, and a row the oracle does
//! not pass is a wrong row, not a pass.
//!
//! In `tcp` mode the server reads one line and answers `hello\n`; in `http` mode it reads
//! the head and answers an `HTTP/1.1 200` with body `hello`, and the client sends a full
//! HTTP request. Every row opens three connections in turn, one after the other; after
//! all three, `show table st` and `show table st2` are read on the stats socket. The test
//! waits for the stats socket, not the frontend port: a probe connection to the frontend
//! is tracked too (`tcp-request content track-sc0` runs with the first payload the client
//! sends, whatever it is).
//!
//! `st` is `store gpc0,gpc1,gpt0`; `st2` is `store gpc(3),gpt(3)`, printed as
//! `gpt0 gpt1 gpt2 gpc0 gpc1 gpc2`. Every field not shown in a row is 0.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Proxy {
    child: Child,
    dir: PathBuf,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const TEMPLATE: &str = "global
  stats socket {sock} level admin
defaults
  mode {mode}
  timeout connect 1s
  timeout client 5s
  timeout server 5s
frontend f
  bind {fe}
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
";

/// The backend of the task's configuration: reads one line, answers `hello\n`, closes. In
/// `http` mode it reads the head and answers a full `HTTP/1.1 200` whose body is `hello`.
fn backend(http: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 64];
                if http {
                    let mut head = Vec::new();
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match c.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                            Err(_) => break,
                        }
                    }
                    let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
                } else {
                    let _ = c.read(&mut buf);
                    let _ = c.write_all(b"hello\n");
                }
            });
        }
    });
    addr
}

/// One of the three connections of a row: sends `x\n` (or a full HTTP request in `http`
/// mode), reads until close, and gives the reply. The connect is retried while it is
/// refused: a refused connect never reaches the proxy, so it tracks nothing (a connect
/// that reaches it would be tracked, and the test must open exactly three).
fn one_connection(http: bool, fe: SocketAddr) -> String {
    let t0 = Instant::now();
    let mut c = loop {
        match TcpStream::connect_timeout(&fe, Duration::from_secs(2)) {
            Ok(c) => break c,
            Err(_) => {
                assert!(t0.elapsed() < Duration::from_secs(10), "the frontend never accepted a connection");
                thread::sleep(Duration::from_millis(50));
            }
        }
    };
    c.set_read_timeout(Some(Duration::from_secs(10))).expect("read timeout");
    c.write_all(if http { b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n" } else { b"x\n" }).expect("send");
    let mut got = Vec::new();
    c.read_to_end(&mut got).expect("read the reply");
    String::from_utf8_lossy(&got).into_owned()
}

/// The `field=value` words of the entry whose key is in the `show table` dump.
fn fields(dump: &str) -> Vec<(String, u64)> {
    let line = dump
        .lines()
        .find(|l| l.contains("key="))
        .unwrap_or_else(|| panic!("no entry in the table dump:\n{dump}"));
    line.split_whitespace()
        .filter_map(|w| {
            let (k, v) = w.split_once('=')?;
            Some((k.to_string(), v.parse::<u64>().unwrap_or(u64::MAX)))
        })
        .collect()
}

/// `show table <t>` on the stats socket, with `table` being the line that names it.
fn show_table(sock: &PathBuf, table: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(10))).expect("cli read timeout");
    s.write_all(format!("show table {table}\n").as_bytes()).expect("send show table");
    let mut out = String::new();
    s.read_to_string(&mut out).expect("read the dump");
    out
}

/// The dump of one table, checked field by field against `want`.
fn check_table(table: &str, dump: &str, want: &[(u64, &str)], row: &str, bad: &mut Vec<String>) {
    let got = fields(dump);
    for &(want_v, name) in want {
        let have = got.iter().find(|(k, _)| k == name).map(|(_, v)| v);
        if have != Some(&want_v) {
            bad.push(format!("{row}: {table} {name}: want {want_v}, got {have:?} (dump: {dump:?})"));
        }
    }
}

/// Starts the proxy of `rules` in `mode`, waits for the stats socket (not the frontend
/// port), runs the three connections and reads the two tables.
fn run_row(mode: &str, rules: &str) -> (String, String) {
    let http = mode == "http";
    let dir = std::env::temp_dir().join(format!("tressc-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::create_dir_all(&dir).expect("tmp dir");
    let sock = dir.join("s");
    let fe = common::reserve_addr();
    let srv = backend(http);
    let cfg = TEMPLATE
        .replace("{mode}", mode)
        .replace("{sock}", &sock.display().to_string())
        .replace("{fe}", &fe.to_string())
        .replace("{srv}", &srv.to_string())
        .replace("{rules}", &rules.replace('\n', "\n  "));
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(&bin)
        .arg("-f")
        .arg(dir.join("cfg"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the proxy");
    let mut p = Proxy { child, dir: dir.clone() };
    std::fs::write(dir.join("cfg"), cfg).expect("write the config");
    let t0 = Instant::now();
    while UnixStream::connect(&sock).is_err() {
        assert!(t0.elapsed() < Duration::from_secs(10), "the stats socket never opened");
        thread::sleep(Duration::from_millis(20));
    }
    for _ in 0..3 {
        let reply = one_connection(http, fe);
        if http {
            assert!(reply.contains("200 OK") && reply.ends_with("hello"), "the reply of the three connections: {reply:?}");
        } else {
            assert_eq!(reply, "hello\n", "the reply of the three connections");
        }
    }
    let st = show_table(&sock, "st");
    let st2 = show_table(&sock, "st2");
    drop(p);
    (st, st2)
}

/// One row of the task's table.
struct Row {
    name: &'static str,
    /// `tcp` (the task's rows) or `http`: the same actions, exercised through the
    /// `http-response` path's `tcp-response content` pass.
    mode: &'static str,
    rules: &'static str,
    /// The wanted fields of `st` (`value, name`); a field not listed must be 0.
    st: &'static [(u64, &'static str)],
    /// The wanted fields of `st2` (`value, name`); a field not listed must be 0.
    st2: &'static [(u64, &'static str)],
}

fn rows() -> Vec<Row> {
    let zero: &[(u64, &str)] = &[(0, "gpc0"), (0, "gpc1"), (0, "gpt0")];
    let zero2: &[(u64, &str)] = &[(0, "gpc0"), (0, "gpc1"), (0, "gpc2"), (0, "gpt0"), (0, "gpt1"), (0, "gpt2")];
    let mut rows = vec![
        Row { name: "sc-inc-gpc0(0)", mode: "tcp", rules: "  tcp-response content sc-inc-gpc0(0)", st: &[(3, "gpc0")], st2: zero2 },
        Row { name: "sc-inc-gpc1(0)", mode: "tcp", rules: "  tcp-response content sc-inc-gpc1(0)", st: &[(3, "gpc1")], st2: zero2 },
        Row { name: "sc-inc-gpc0 (no id: sc0)", mode: "tcp", rules: "  tcp-response content sc-inc-gpc0", st: &[(3, "gpc0")], st2: zero2 },
        Row { name: "sc-inc-gpc0(1)", mode: "tcp", rules: "  tcp-response content sc-inc-gpc0(1)", st: zero, st2: &[(3, "gpc0")] },
        Row { name: "sc-set-gpt0(0) 7", mode: "tcp", rules: "  tcp-response content sc-set-gpt0(0) 7", st: &[(7, "gpt0")], st2: zero2 },
        Row { name: "sc-inc-gpc(2,1)", mode: "tcp", rules: "  tcp-response content sc-inc-gpc(2,1)", st: zero, st2: &[(3, "gpc2")] },
        Row { name: "sc-add-gpc(1,1) 5", mode: "tcp", rules: "  tcp-response content sc-add-gpc(1,1) 5", st: zero, st2: &[(15, "gpc1")] },
        Row { name: "sc-set-gpt(2,1) 9", mode: "tcp", rules: "  tcp-response content sc-set-gpt(2,1) 9", st: zero, st2: &[(9, "gpt2")] },
        Row { name: "if res.len gt 100 (false)", mode: "tcp", rules: "  tcp-response content sc-inc-gpc0(0) if { res.len gt 100 }", st: zero, st2: zero2 },
        Row {
            name: "three rules, accept stops them",
            mode: "tcp",
            rules: "  tcp-response content sc-inc-gpc1(0)\n  tcp-response content accept\n  tcp-response content sc-inc-gpc0(0)",
            st: &[(3, "gpc1")],
            st2: zero2,
        },
        Row {
            name: "inspect-delay, if res.len gt 3",
            mode: "tcp",
            rules: "  tcp-response inspect-delay 1s\n  tcp-response content sc-inc-gpc0(0) if { res.len gt 3 }",
            st: &[(3, "gpc0")],
            st2: zero2,
        },
        Row {
            name: "inspect-delay, sc-set-gpt0(0) res.len",
            mode: "tcp",
            rules: "  tcp-response inspect-delay 1s\n  tcp-response content sc-set-gpt0(0) res.len if { res.len gt 0 }",
            st: &[(6, "gpt0")],
            st2: zero2,
        },
        Row {
            name: "inspect-delay, sc-add-gpc(1,1) res.len",
            mode: "tcp",
            rules: "  tcp-response inspect-delay 1s\n  tcp-response content sc-add-gpc(1,1) res.len if { res.len gt 0 }",
            st: zero,
            st2: &[(18, "gpc1")],
        },
    ];
    // The same six actions in `mode http`: measured on the oracle, the counters land the
    // same way (the response is read before the response is analysed as HTTP).
    rows.extend([
        Row { name: "http sc-inc-gpc0(0)", mode: "http", rules: "  tcp-response content sc-inc-gpc0(0)", st: &[(3, "gpc0")], st2: zero2 },
        Row { name: "http sc-inc-gpc1(0)", mode: "http", rules: "  tcp-response content sc-inc-gpc1(0)", st: &[(3, "gpc1")], st2: zero2 },
        Row { name: "http sc-set-gpt0(0) 7", mode: "http", rules: "  tcp-response content sc-set-gpt0(0) 7", st: &[(7, "gpt0")], st2: zero2 },
        Row { name: "http sc-inc-gpc(2,1)", mode: "http", rules: "  tcp-response content sc-inc-gpc(2,1)", st: zero, st2: &[(3, "gpc2")] },
        Row { name: "http sc-add-gpc(1,1) 5", mode: "http", rules: "  tcp-response content sc-add-gpc(1,1) 5", st: zero, st2: &[(15, "gpc1")] },
        Row { name: "http sc-set-gpt(2,1) 9", mode: "http", rules: "  tcp-response content sc-set-gpt(2,1) 9", st: zero, st2: &[(9, "gpt2")] },
    ]);
    rows
}

#[test]
fn the_response_rules_run_the_stick_counters() {
    let mut bad = Vec::new();
    for row in rows() {
        let (st, st2) = run_row(row.mode, row.rules);
        check_table("st", &st, row.st, row.name, &mut bad);
        check_table("st2", &st2, row.st2, row.name, &mut bad);
    }
    assert!(bad.is_empty(), "{}:\n{}", bad.len(), bad.join("\n"));
}

/// A row the configuration must refuse at load, with a word the message contains: the
/// exit is non-zero and the word is on `stderr`.
fn refuse_row(name: &'static str, rules: &str, word: &str) -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!("tressc-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::create_dir_all(&dir).expect("tmp dir");
    let sock = dir.join("s");
    let fe = common::reserve_addr();
    let srv = backend(false);
    let cfg = TEMPLATE
        .replace("{mode}", "tcp")
        .replace("{sock}", &sock.display().to_string())
        .replace("{fe}", &fe.to_string())
        .replace("{srv}", &srv.to_string())
        .replace("{rules}", &rules.replace('\n', "\n  "));
    std::fs::write(dir.join("cfg"), cfg).expect("write the config");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut child = Command::new(&bin)
        .arg("-f")
        .arg(dir.join("cfg"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{name}: spawn: {e}"))?;
    let t0 = Instant::now();
    let status = loop {
        match child.try_wait().map_err(|e| format!("{name}: wait: {e}"))? {
            Some(s) => break s,
            None => {
                assert!(t0.elapsed() < Duration::from_secs(10), "{name}: the proxy never exited");
                thread::sleep(Duration::from_millis(20));
            }
        }
    };
    let mut err = String::new();
    use std::io::Read as _;
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    let _ = std::fs::remove_dir_all(&dir);
    if status.success() {
        return Err(format!("{name}: the configuration was accepted, it must be refused:\n{err}"));
    }
    if err.contains(word) {
        Ok(())
    } else {
        Err(format!("{name}: refused with a different message, want a message containing {word:?}:\n{err}"))
    }
}

#[test]
fn the_response_side_refuses_what_the_request_side_refuses() {
    // The two rows of the task's second table, as `HAProxy` 3.5-dev11 `-c` words them.
    let r1 = refuse_row("sc-inc-gpc(1)", "  tcp-response content sc-inc-gpc(1)", "Missing gpc ID");
    assert!(r1.is_ok(), "{r1:?}");
    let r2 = refuse_row("sc-set-gpt(0,0) 1 foo", "  tcp-response content sc-set-gpt(0,0) 1 foo", "only accepts 'if' or 'unless'");
    assert!(r2.is_ok(), "{r2:?}");
    // A name neither proxy knows in `tcp-response content` stays refused (a name both
    // accept, such as `close`, cannot be a row: the test runs on the oracle too).
    let r = refuse_row("unknown action", "  tcp-response content frobnicate", "frobnicate");
    assert!(r.is_ok(), "{r:?}");
    // A request-side action the response side does not take: refused by both, and the
    // refusal names what the response side does take.
    let r = refuse_row("set-src", "  tcp-response content set-src src", "set-src");
    assert!(r.is_ok(), "{r:?}");
}
