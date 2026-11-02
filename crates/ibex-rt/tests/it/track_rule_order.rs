// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! RV-C: `http-request track-sc*` and `tcp-request connection track-sc*` run in rule order, as
//! any other rule: an earlier terminal action (`allow`, `deny`, `accept`) stops them, and an
//! earlier `set-header`/`set-var` is seen by their key and condition.
//!
//! Measured on `HAProxy` 3.5-dev8 (`RVC_ORACLE=<haproxy>` runs this file against it), one
//! request with `x-k: orig` to each frontend of [`CFG`]; the table of each afterwards:
//! `hset` foo, `allow` none, `deny` none, `caccept` none, `hlate` orig, `hvar` v1,
//! `ginc` (sc-inc-gpc0 before the track) `http_req_cnt=1 gpc0=0`; a second track of a slot
//! (`cdup`, `htwice`) leaves it on the first entry, counted once; a missing key (`cnokey`,
//! `hnokey`) tracks nothing; a slot the connection rules tracked whose `http-request track-sc`
//! does not run (`hdefer`) still counts the request.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Proc(Child, std::path::PathBuf);

impl Drop for Proc {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

const CFG: &str = r####"global
  stats socket {sock} mode 600 level admin
defaults
  mode http
  timeout client 5s
  timeout server 5s
  timeout connect 5s
backend ts_hset
  stick-table type string len 16 size 10 expire 1m store http_req_cnt
backend ts_hlate
  stick-table type string len 16 size 10 expire 1m store http_req_cnt
backend ts_hvar
  stick-table type string len 16 size 10 expire 1m store http_req_cnt
backend ts_allow
  stick-table type ip size 10 expire 1m store http_req_cnt
backend ts_deny
  stick-table type ip size 10 expire 1m store http_req_cnt
backend ts_caccept
  stick-table type ip size 10 expire 1m store conn_cnt
backend ts_ginc
  stick-table type ip size 10 expire 1m store http_req_cnt,gpc0
backend ts_cdup
  stick-table type ip size 10 expire 1m store http_req_cnt
backend ts_cdup2
  stick-table type ip size 10 expire 1m store http_req_cnt
backend ts_cnokey
  stick-table type string len 16 size 10 expire 1m store conn_cnt
backend ts_htwice
  stick-table type ip size 10 expire 1m store http_req_cnt
backend ts_hnokey
  stick-table type string len 16 size 10 expire 1m store http_req_cnt
backend ts_hdefer
  stick-table type ip size 10 expire 1m store http_req_cnt
frontend hset
  bind {hset}
  http-request set-header x-k foo
  http-request track-sc0 req.hdr(x-k) table ts_hset
  http-request return status 200
frontend hlate
  bind {hlate}
  http-request track-sc0 req.hdr(x-k) table ts_hlate
  http-request set-header x-k late
  http-request return status 200
frontend hvar
  bind {hvar}
  http-request set-var(txn.k) str(v1)
  http-request track-sc0 var(txn.k) table ts_hvar if { var(txn.k) -m found }
  http-request return status 200
frontend allow
  bind {allow}
  http-request allow if { src 127.0.0.1 }
  http-request track-sc0 src table ts_allow
  http-request return status 200
frontend deny
  bind {deny}
  http-request deny if { src 127.0.0.1 }
  http-request track-sc0 src table ts_deny
frontend caccept
  bind {caccept}
  tcp-request connection accept if { src 127.0.0.1 }
  tcp-request connection track-sc0 src table ts_caccept
  http-request return status 200
frontend ginc
  bind {ginc}
  http-request sc-inc-gpc0(0)
  http-request track-sc0 src table ts_ginc
  http-request return status 200
frontend cdup
  bind {cdup}
  tcp-request connection track-sc0 src table ts_cdup
  tcp-request connection track-sc0 src table ts_cdup2
  http-request return status 200
frontend cnokey
  bind {cnokey}
  tcp-request connection track-sc1 var(sess.none) table ts_cnokey
  http-request return status 200
frontend htwice
  bind {htwice}
  http-request track-sc0 src table ts_htwice
  http-request track-sc0 src table ts_htwice
  http-request return status 200
frontend hnokey
  bind {hnokey}
  http-request track-sc1 req.hdr(x-none) table ts_hnokey
  http-request return status 200
frontend hdefer
  bind {hdefer}
  tcp-request connection track-sc0 src table ts_hdefer
  http-request track-sc0 src table ts_hdefer if FALSE
  http-request return status 200
"####;

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn get(addr: SocketAddr) {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nx-k: orig\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
}

/// The entries of `table` as `key=.. http_req_cnt=.. gpc0=..` lines (ids and timers dropped).
fn entries(sock: &str, table: &str) -> Vec<String> {
    let mut v: Vec<String> = cli(sock, &format!("show table {table}"))
        .lines()
        .filter(|l| l.contains("key="))
        .map(|l| l.split_whitespace().filter(|w| !w.starts_with("0x") && !w.starts_with("exp=") && !w.starts_with("use=") && !w.starts_with("shard=")).collect::<std::collections::BTreeSet<_>>().into_iter().collect::<Vec<_>>().join(" "))
        .collect();
    v.sort();
    v
}

#[test]
fn track_rules_run_in_rule_order() {
    let names = ["hset", "hlate", "hvar", "allow", "deny", "caccept", "ginc", "cdup", "cnokey", "htwice", "hnokey", "hdefer"];
    let addrs: Vec<SocketAddr> = names.iter().map(|_| common::reserve_addr()).collect();
    let dir = std::env::temp_dir().join(format!("rvc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let mut cfg = CFG.replace("{sock}", &sock);
    for (n, a) in names.iter().zip(&addrs) {
        cfg = cfg.replace(&format!("{{{n}}}"), &a.to_string());
    }
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let bin = std::env::var("RVC_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _p = Proc(child, dir);
    for a in &addrs {
        assert!(common::wait_listening(*a), "no listener on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    // `wait_listening` itself connects: start from empty tables. (Ibex has no `clear table`
    // yet, T625: the tables count requests, which the probe connection does not make.)
    for n in names.iter().chain(&["cdup2"]) {
        cli(&sock, &format!("clear table ts_{n}"));
    }
    for a in &addrs {
        get(*a);
    }
    let mut bad = Vec::new();
    for (n, want) in [
        ("hset", vec!["http_req_cnt=1 key=foo"]),
        ("hlate", vec!["http_req_cnt=1 key=orig"]),
        ("hvar", vec!["http_req_cnt=1 key=v1"]),
        ("allow", vec![]),
        ("deny", vec![]),
        ("caccept", vec![]),
        ("ginc", vec!["gpc0=0 http_req_cnt=1 key=127.0.0.1"]),
        ("cdup", vec!["http_req_cnt=1 key=127.0.0.1"]),
        ("cdup2", vec![]),
        ("cnokey", vec![]),
        ("htwice", vec!["http_req_cnt=1 key=127.0.0.1"]),
        ("hnokey", vec![]),
        ("hdefer", vec!["http_req_cnt=1 key=127.0.0.1"]),
    ] {
        let got = entries(&sock, &format!("ts_{n}"));
        if got != want {
            bad.push(format!("{n}: want {want:?}, got {got:?}"));
        }
    }
    assert!(bad.is_empty(), "tables differ:\n{}", bad.join("\n"));
}
