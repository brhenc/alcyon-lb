// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T364 S4: what the variable outputs print for each stored type. Every expected string was measured on
//! `HAProxy` 3.5-dev8 (`$ALCYON_REFERENCE/haproxy/haproxy`):
//! - CLI `get var proc.v` prints `proc.v: type=<bool|sint|str|bin|ipv4|ipv6|meth> value=<...>`, the value cast to
//!   a string (`bin` stops at its first NUL byte), every byte that is not printable ASCII shown as `.`.
//! - `dump_all_vars(<scope>)` prints a string quoted and escaped, a `bin` as upper-case hex, an integer bare,
//!   a bool as `true`/`false`, an address as text, a method quoted.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::Duration;

fn ask(sock: &std::path::Path, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect cli");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn get(addr: std::net::SocketAddr, method: &str) -> String {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{method} / HTTP/1.1\r\nHost: a\r\nx-q: a\"b\\c\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    let mut answer = String::new();
    let _ = s.read_to_string(&mut answer);
    answer.split_once("\r\n\r\n").map_or(String::new(), |(_, b)| b.to_string())
}

#[test]
fn get_var_and_dump_all_vars_print_by_type() {
    let dir = tempfile::tempdir().expect("tmp dir");
    let sock = dir.path().join("cli.sock");
    let fe = common::reserve_addr();
    let cfg = dir.path().join("alcyon.cfg");
    std::fs::write(
        &cfg,
        format!(
            "global\n  stats socket {} level admin\n\
             defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 1s\n\
             frontend f\n  bind {fe}\n\
             \x20 http-request set-var(txn.bo) bool(1)\n\
             \x20 http-request set-var(txn.bf) bool(0)\n\
             \x20 http-request set-var(txn.si) int(-5)\n\
             \x20 http-request set-var(txn.st) req.hdr(x-q)\n\
             \x20 http-request set-var(txn.bn) bin(41004243)\n\
             \x20 http-request set-var(txn.bh) bin(80ff0a09)\n\
             \x20 http-request set-var(txn.v4) str(10.1.2.3),ipmask(32)\n\
             \x20 http-request set-var(txn.v6) str(2001:db8::1),ipmask(32,128)\n\
             \x20 http-request set-var(txn.me) method\n\
             \x20 http-request set-var(sess.s) int(1)\n\
             \x20 http-request set-var(req.r) str(x)\n\
             \x20 http-response set-var(res.q) bool(0)\n\
             \x20 http-request set-var(proc.pp) int(7)\n\
             \x20 http-request return status 200 content-type text/plain lf-string \"%[dump_all_vars(txn)]\\n%[dump_all_vars(sess)]\\n%[dump_all_vars(req)]\\n%[dump_all_vars(proc)]\\n\"\n",
            sock.display()
        ),
    )
    .expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Alcyon)
        .expect("spawn alcyon");
    assert!(common::wait_listening(fe), "alcyon never listened on {fe}");

    // get var, one type each.
    let mut got = Vec::new();
    for e in [
        "bool(1)", "bool(0)", "int(-5)", "str(ab)", "bin(41004243)", "bin(0001)", "bin(80ff0a09)", "str(10.1.2.3),ipmask(32)",
        "str(2001:db8::1),ipmask(32,128)",
    ] {
        ask(&sock, &format!("experimental-mode on;set var proc.v expr {e}"));
        got.push(ask(&sock, "get var proc.v"));
    }
    let want = [
        "proc.v: type=bool value=<1>\n\n",
        "proc.v: type=bool value=<0>\n\n",
        "proc.v: type=sint value=<-5>\n\n",
        "proc.v: type=str value=<ab>\n\n",
        "proc.v: type=bin value=<A>\n\n",
        "proc.v: type=bin value=<>\n\n",
        "proc.v: type=bin value=<....>\n\n",
        "proc.v: type=ipv4 value=<10.1.2.3>\n\n",
        "proc.v: type=ipv6 value=<2001:db8::1>\n\n",
    ];
    for (g, w) in got.iter().zip(want) {
        assert_eq!(g, w);
    }

    let b = get(fe, "GET");
    let o = get(fe, "FOOBAR");
    common::stop(&mut child);
    let txn = |m: &str| {
        format!(
            "txn.bf=false, txn.bh=80FF0A09, txn.bn=41004243, txn.bo=true, txn.me=\"{m}\", txn.si=-5, txn.st=\"a\\\"b\\\\c\", txn.v4=10.1.2.3, txn.v6=2001:db8::1"
        )
    };
    assert_eq!(b, format!("{}\nsess.s=1\nreq.r=\"x\"\nproc.pp=7, proc.v=2001:db8::1\n", txn("GET")));
    assert_eq!(o, format!("{}\nsess.s=1\nreq.r=\"x\"\nproc.pp=7, proc.v=2001:db8::1\n", txn("FOOBAR")));
}
