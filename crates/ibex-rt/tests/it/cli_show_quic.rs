// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `show quic` on the CLI (T524, M2 slice 8).
//!
//! Recorded on HAProxy 3.5-dev7 with QUIC (`~/reference/haproxy-quic/haproxy`, `nbthread 2`,
//! one `quic4@` frontend `fe`, three aioquic connections from `tests/data/h3_hold.py`):
//!
//! ```text
//! # conn/frontend                     state   in_flight infl_p lost_p         Local Address           Foreign Address      local & remote CIDs
//! 0x7efd78054bb0[00]/fe               ESTAB           0      0      0         127.0.0.1:18443         127.0.0.1:56248 26445cd1cd48080e e904fc611f1c8aea
//! 0x35d584b0[01]/fe                   ESTAB           0      0      0         127.0.0.1:18443         127.0.0.1:52561 6536120194cbfe85 e00df3fc1e8afb30
//! ```
//!
//! then an empty line. With no connection only the header is there. `all` adds the closing
//! and backend connections, `clo` lists the closing ones, `be` the backend ones (the header
//! alone here), `oneline` is the default. `help`, `foo` (`Invalid argument, use 'help' for more
//! options.`), `tp,xx` (`Invalid field, ...`) and `0xzz` (`Invalid quic_conn pointer.`) answer
//! the texts asserted below. `show info` has the same fields with and without a QUIC bind.
//!
//! Ibex fills the connection, state, `lost_p` and address columns. quinn-proto exposes neither
//! the bytes (packets) in flight nor the connection IDs, so those columns print `-`
//! (docs/differences.md); the pointer is the first eight bytes of the first Initial's
//! destination CID.

use crate::common;

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const HEADER: &str = "# conn/frontend                     state   in_flight infl_p lost_p         Local Address           Foreign Address      local & remote CIDs";

struct Rig {
    _ibex: common::Ibex,
    dir: std::path::PathBuf,
    sock: String,
    quic: u16,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start(tag: &str) -> Rig {
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let quic = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("shq-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let sock = dir.join("cli.sock").display().to_string();
    let cfg = format!(
        "global\n  stats socket {sock} level admin\n  nbthread 2\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n\
         frontend fe\n  bind quic4@{quic} ssl crt {crt} alpn h3\n\
         \x20 http-request return status 200 content-type text/plain string \"ok\"\n"
    );
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).expect("cfg");
    let child = common::ibex_command(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let ibex = common::Ibex(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(500));
    Rig { _ibex: ibex, dir, sock, quic: quic.port() }
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// `conns` HTTP/3 connections, one request each, held open `hold` seconds. Returns once
/// every one has been served.
fn hold(port: u16, conns: u32, hold: u32) -> Child {
    let script = format!("{}/tests/data/h3_hold.py", env!("CARGO_MANIFEST_DIR"));
    let mut c = Command::new("python3")
        .args([&script, &port.to_string(), &conns.to_string(), "1", &hold.to_string(), "5"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("python3 with aioquic");
    let mut out = BufReader::new(c.stdout.take().expect("stdout"));
    loop {
        let mut l = String::new();
        assert!(out.read_line(&mut l).expect("probe") > 0, "probe ended");
        if l.starts_with("ready") {
            assert!(l.contains(&format!("ok={conns}")), "{l}");
            break;
        }
    }
    // The probe's stdout is not read again; it exits when its hold is over.
    std::mem::forget(out);
    c
}

/// One row, checked field by field against the format of `dump_quic_oneline`.
fn check_row(row: &str, quic: u16) {
    let (ptr, rest) = row.split_once('[').expect("pointer");
    assert!(ptr.starts_with("0x") && ptr[2..].chars().all(|c| c.is_ascii_hexdigit()), "{row}");
    let (thr, rest) = rest.split_once("]/").expect("thread");
    assert!(thr == "00" || thr == "01", "{row}");
    assert!(rest.starts_with("fe "), "{row}");
    // `%p[%02u]/%-.12s ` padded to 36 columns, then `ESTAB   `.
    assert!(row.len() > 44, "{row}");
    assert_eq!(row[..36].trim_end(), format!("{ptr}[{thr}]/fe"), "{row}");
    assert_eq!(&row[36..44], "ESTAB   ", "{row}");
    // `%9llu %6llu %6llu   `: the two Ibex cannot fill are `-`, lost packets are counted.
    let counters = &row[44..44 + 9 + 1 + 6 + 1 + 6 + 3];
    assert_eq!(counters, format!("{:>9} {:>6} {:>6}   ", "-", "-", "0"), "{row}");
    // `%15s:%-5s   ` local, `%15s:%-5s ` foreign, then the two CIDs.
    let tail = &row[44 + 9 + 1 + 6 + 1 + 6 + 3..];
    assert_eq!(&tail[..15 + 1 + 5 + 3], format!("{:>15}:{:<5}   ", "127.0.0.1", quic), "{row}");
    let tail = &tail[15 + 1 + 5 + 3..];
    let (peer, cids) = tail.split_at(15 + 1 + 5 + 1);
    assert!(peer.starts_with("      127.0.0.1:"), "{row}");
    assert!(peer[16..21].trim_end().parse::<u16>().is_ok(), "{row}");
    assert_eq!(cids, "- -", "{row}");
}

fn rows(out: &str) -> Vec<&str> {
    let mut l: Vec<&str> = out.split('\n').collect();
    assert_eq!(l.pop(), Some(""), "ends with a newline");
    assert_eq!(l.pop(), Some(""), "and an empty line");
    assert_eq!(l.first().copied(), Some(HEADER), "header: {out}");
    l.remove(0);
    l
}

#[test]
fn empty_and_connections() {
    let r = start("rows");
    for arg in ["", " oneline", " all", " be", " clo"] {
        assert_eq!(cli(&r.sock, &format!("show quic{arg}")), format!("{HEADER}\n\n"), "show quic{arg} with none");
    }
    let mut probe = hold(r.quic, 3, 4);
    let out = cli(&r.sock, "show quic");
    let l = rows(&out);
    assert_eq!(l.len(), 3, "{out}");
    for row in &l {
        check_row(row, r.quic);
    }
    let ptrs: std::collections::HashSet<&str> = l.iter().map(|x| x.split('[').next().unwrap()).collect();
    assert_eq!(ptrs.len(), 3, "three different connections: {out}");
    for arg in [" oneline", " all"] {
        let again = cli(&r.sock, &format!("show quic{arg}"));
        assert_eq!(rows(&again).len(), 3, "show quic{arg}: {again}");
    }
    // Backend connections: none. Closing ones: none yet.
    for arg in [" be", " clo"] {
        assert_eq!(cli(&r.sock, &format!("show quic{arg}")), format!("{HEADER}\n\n"));
    }
    // `show info` has no QUIC field, as on HAProxy.
    assert!(!cli(&r.sock, "show info").to_lowercase().contains("quic"));
    let _ = probe.wait();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let out = cli(&r.sock, "show quic");
        if rows(&out).is_empty() {
            break;
        }
        assert!(Instant::now() < deadline, "closed connections still listed: {out}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn help_errors_and_refusals() {
    let r = start("msgs");
    let help = cli(&r.sock, "show quic help");
    assert!(help.starts_with("Usage: show quic [help|<format>] [<filter>]\nDumps information about QUIC connections. Available output formats:\n  oneline    dump a single, netstat-like line per connection (default)\n"), "{help}");
    assert!(help.ends_with("Without any argument, active frontend connections are dumped using the oneline format.\n\n"), "{help}");
    assert_eq!(cli(&r.sock, "show quic foo"), "Invalid argument, use 'help' for more options.\n\n");
    assert_eq!(cli(&r.sock, "show quic tp,xx"), "Invalid field, use 'help' for more options.\n\n");
    assert_eq!(cli(&r.sock, "show quic 0xzz"), "Invalid quic_conn pointer.\n\n");
    for (cmd, named) in [
        ("show quic full", "full"),
        ("show quic stream", "stream"),
        ("show quic tp", "tp"),
        ("show quic cc,mux", "cc,mux"),
        ("show quic 0x1234", "0x1234"),
    ] {
        let out = cli(&r.sock, cmd);
        assert!(out.starts_with(&format!("'show quic {named}' is not supported by Ibex")), "{cmd}: {out}");
        assert!(!out.contains(HEADER), "{cmd}: {out}");
    }
}
