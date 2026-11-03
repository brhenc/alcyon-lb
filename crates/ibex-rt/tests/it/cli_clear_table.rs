// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T625: `clear table <table> [key <k> | data.<type> <op> <v> ...]` on the stats socket.
//!
//! Measured on `HAProxy` 3.5-dev8 (`CCT_ORACLE=<haproxy>` runs this file against it). A whole
//! table or a filter removes the matching entries and answers nothing; an entry a session
//! tracks (`use=1`) is kept, silently by those and with "Entry currently in use, cannot
//! remove" by `key`; `key` of an absent key answers nothing; the filters of one command are
//! ANDed; each malformed word has its own message.

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
  timeout client 10s
  timeout server 5s
  timeout connect 5s
backend t1
  stick-table type string len 16 size 10 expire 1m store http_req_cnt
backend t2
  stick-table type ip size 10 expire 1m store conn_cnt
frontend f
  bind {f}
  http-request track-sc0 req.hdr(x-k) table t1
  http-request return status 200
frontend g
  bind {g}
  tcp-request connection track-sc0 src table t2
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

fn get(addr: SocketAddr, k: &str) {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("GET / HTTP/1.1\r\nHost: x\r\nx-k: {k}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
}

/// `key=count` of each entry of `table`, sorted.
fn keys(sock: &str, table: &str) -> String {
    let mut v: Vec<String> = cli(sock, &format!("show table {table}"))
        .lines()
        .filter(|l| l.contains("key="))
        .map(|l| l.split_whitespace().filter(|w| w.starts_with("key=") || w.starts_with("http_req_cnt=")).collect::<Vec<_>>().join(":"))
        .collect();
    v.sort();
    v.join(",")
}

#[test]
fn clear_table() {
    let f = common::reserve_addr();
    let g = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("cct-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let cfg = CFG.replace("{sock}", &sock).replace("{f}", &f.to_string()).replace("{g}", &g.to_string());
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let bin = std::env::var("CCT_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _p = Proc(child, dir);
    assert!(common::wait_listening(f), "no listener");
    assert!(common::wait_listening(g), "no listener");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    let fill = || {
        for (k, n) in [("a", 1), ("b", 2), ("c", 3)] {
            for _ in 0..n {
                get(f, k);
            }
        }
    };
    let mut bad = Vec::new();
    let mut check = |what: &str, got: String, want: &str| {
        if got != want {
            bad.push(format!("{what}: want {want:?}, got {got:?}"));
        }
    };
    let all = "key=a:http_req_cnt=1,key=b:http_req_cnt=2,key=c:http_req_cnt=3";
    fill();
    check("filled", keys(&sock, "t1"), all);
    check("key b", cli(&sock, "clear table t1 key b"), "\n");
    check("after key b", keys(&sock, "t1"), "key=a:http_req_cnt=1,key=c:http_req_cnt=3");
    check("absent key", cli(&sock, "clear table t1 key zz"), "\n");
    check("gt 2", cli(&sock, "clear table t1 data.http_req_cnt gt 2"), "\n");
    check("after gt", keys(&sock, "t1"), "key=a:http_req_cnt=1");
    check("whole", cli(&sock, "clear table t1"), "\n");
    check("after whole", keys(&sock, "t1"), "");
    fill();
    check("anded", cli(&sock, "clear table t1 data.http_req_cnt ne 1 data.http_req_cnt le 2"), "\n");
    check("after anded", keys(&sock, "t1"), "key=a:http_req_cnt=1,key=c:http_req_cnt=3");
    check("ge", cli(&sock, "clear table t1 data.http_req_cnt ge 1"), "\n");
    check("after ge", keys(&sock, "t1"), "");
    fill();
    check("eq", cli(&sock, "clear table t1 data.http_req_cnt eq 3"), "\n");
    check("lt", cli(&sock, "clear table t1 data.http_req_cnt lt 2"), "\n");
    check("after eq lt", keys(&sock, "t1"), "key=b:http_req_cnt=2");
    check("not stored", cli(&sock, "clear table t1 data.conn_cnt eq 0"), "Filter entry #1: Data type not stored in this table\n\n");

    // Errors, as HAProxy words them.
    let req = "Required arguments: <table> \"data.<store_data_type>\" <operator> <value> or <table> key <key> or <table> ptr <ptr>\n\n";
    check("no table", cli(&sock, "clear table nope"), "No such table\n\n");
    check("bare", cli(&sock, "clear table"), req);
    check("bogus", cli(&sock, "clear table t1 bogus"), req);
    check("op", cli(&sock, "clear table t1 data.http_req_cnt xx 8"), "Filter entry #1: Require and operator among \"eq\", \"ne\", \"le\", \"ge\", \"lt\", \"gt\"\n\n");
    check("no value", cli(&sock, "clear table t1 data.http_req_cnt eq"), "Filter entry #1: Require a valid integer value to compare against\n\n");
    check("bad value", cli(&sock, "clear table t1 data.http_req_cnt eq zz"), "Filter entry #1: Require a valid integer value to compare against\n\n");
    check("unknown type", cli(&sock, "clear table t1 data.foo eq 1"), "Filter entry #1: Unknown data type\n\n");
    check("second filter", cli(&sock, "clear table t1 data.http_req_cnt eq 2 data.foo eq 1"), "Filter entry #2: Unknown data type\n\n");
    check("no key", cli(&sock, "clear table t1 key"), "Key value expected\n\n");
    check("bad ip key", cli(&sock, "clear table t2 key notip"), "Invalid key\n\n");
    check("errors keep b", keys(&sock, "t1"), "key=b:http_req_cnt=2");

    // An entry a connection tracks is kept.
    let mut held = TcpStream::connect(g).unwrap();
    held.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut buf = [0u8; 256];
    let _ = held.read(&mut buf);
    let t2 = |sock: &str| keys(sock, "t2");
    let before = t2(&sock);
    check("t2 has entry", before.is_empty().to_string(), "false");
    check("in use whole", cli(&sock, "clear table t2"), "\n");
    check("in use filter", cli(&sock, "clear table t2 data.conn_cnt ge 0"), "\n");
    check("in use kept", t2(&sock), &before);
    check("in use key", cli(&sock, "clear table t2 key 127.0.0.1"), "Entry currently in use, cannot remove\n\n");
    check("in use kept 2", t2(&sock), &before);
    drop(held);
    std::thread::sleep(Duration::from_millis(500));
    check("released whole", cli(&sock, "clear table t2"), "\n");
    check("released gone", t2(&sock), "");
    assert!(bad.is_empty(), "differences:\n{}", bad.join("\n"));
}
