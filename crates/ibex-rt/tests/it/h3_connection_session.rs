// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T504: a QUIC connection is a session of its frontend (HTTP/3 into the engine, slice H1).
//!
//! The numbers are HAProxy 3.5-dev7 with QUIC's (`~/reference/haproxy-quic/haproxy`, same
//! configuration, same client `tests/data/h3_hold.py`, deltas over its own stats-socket
//! connections): a request stream counts in `req_tot` only; the connection counts in `stot`,
//! `conn_tot`, `scur`, `CumConns`, `CurrConns`; `CurrSslConns`/`CumSslConns` count every
//! handshake, also of a connection `maxconn` holds; `maxconn` holds the connections that
//! come after it (`scur` stays at the limit, the others wait).

use crate::common;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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

/// A frontend that answers every request itself, with `fe_extra` among its keywords.
fn start(tag: &str, global_extra: &str, fe_extra: &str) -> Rig {
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let quic = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("h3cs-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let sock = dir.join("cli.sock").display().to_string();
    let cfg = format!(
        "global\n  stats socket {sock} level admin\n{global_extra}\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n\
         frontend fe\n{fe_extra}  bind quic4@{quic} ssl crt {crt} alpn h3\n\
         \x20 http-request return status 200 content-type text/plain string \"ok\"\n"
    );
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
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

/// The frontend's `show stat` row, by column name.
fn stat(sock: &str) -> HashMap<String, u64> {
    let out = cli(sock, "show stat");
    let mut lines = out.lines();
    let head: Vec<&str> = lines.next().expect("header").trim_start_matches("# ").split(',').collect();
    let row = lines.find(|l| l.starts_with("fe,FRONTEND,")).expect("frontend row");
    head.iter().zip(row.split(',')).map(|(k, v)| ((*k).to_string(), v.parse().unwrap_or(0))).collect()
}

fn info(sock: &str) -> HashMap<String, u64> {
    cli(sock, "show info").lines().filter_map(|l| l.split_once(": ")).filter_map(|(k, v)| Some((k.to_string(), v.trim().parse().ok()?))).collect()
}

/// The HTTP/3 client: `conns` connections at once, `reqs` requests on each, held `hold` s.
struct Probe(Child, BufReader<std::process::ChildStdout>);

impl Probe {
    fn run(port: u16, conns: u32, reqs: u32, hold: u32, wait: u32) -> Self {
        let script = format!("{}/tests/data/h3_hold.py", env!("CARGO_MANIFEST_DIR"));
        let mut c = Command::new("python3")
            .args([&script, &port.to_string(), &conns.to_string(), &reqs.to_string(), &hold.to_string(), &wait.to_string()])
            .stdout(Stdio::piped())
            .spawn()
            .expect("python3 with aioquic");
        let out = BufReader::new(c.stdout.take().expect("stdout"));
        Self(c, out)
    }

    /// Reads the `served` lines of `n` connections, then returns the `ready` line.
    /// The flow-control limits the server announced, from the `params` line.
    fn params(&mut self) -> (u64, u64) {
        let l = self.raw_line();
        let v: Vec<u64> = l.strip_prefix("params ").unwrap_or_else(|| panic!("no params line: {l}")).split(' ').filter_map(|kv| kv.split_once('=')?.1.parse().ok()).collect();
        (v[0], v[1])
    }

    fn served(&mut self, n: usize) -> String {
        for _ in 0..n {
            assert_eq!(self.line(), "served");
        }
        self.line()
    }

    fn raw_line(&mut self) -> String {
        let mut l = String::new();
        self.1.read_line(&mut l).expect("probe output");
        l.trim().to_string()
    }

    /// The next line, but for the `params` one.
    fn line(&mut self) -> String {
        loop {
            let l = self.raw_line();
            if !l.starts_with("params ") {
                return l;
            }
        }
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn frontend_maxconn_holds_the_quic_connections_that_come_after_it() {
    let rig = start("maxconn", "", "  maxconn 2\n");
    let mut p = Probe::run(rig.quic, 6, 1, 3, 4);
    assert_eq!((p.line(), p.line()), ("served".to_string(), "served".to_string()), "two connections are served");
    // The other four have completed their handshake and wait (they give up after four seconds).
    std::thread::sleep(Duration::from_secs(1));
    let s = stat(&rig.sock);
    let i = info(&rig.sock);
    assert_eq!((s["scur"], s["slim"], s["stot"], s["conn_tot"], s["req_tot"]), (2, 2, 2, 2, 2), "{s:?}");
    assert_eq!((i["CurrConns"], i["CumConns"], i["CumReq"]), (6, 2, 2), "the four waiting connections are in CurrConns only");
    assert_eq!((i["CurrSslConns"], i["CumSslConns"]), (6, 6), "every handshake counts");
    assert_eq!(p.line(), "ready ok=2 fail=4", "the other four never get served");
    assert_eq!(p.line(), "closed");
    std::thread::sleep(Duration::from_millis(500));
    let s = stat(&rig.sock);
    let i = info(&rig.sock);
    assert_eq!((s["scur"], s["stot"], i["CurrConns"], i["CurrSslConns"]), (0, 2, 0, 0), "a closed connection is given back: {s:?}");
}

#[test]
fn a_request_stream_counts_in_req_tot_and_the_connection_in_the_rest() {
    let rig = start("pattern", "", "");
    let mut p = Probe::run(rig.quic, 3, 2, 3, 3);
    assert_eq!(p.served(3), "ready ok=3 fail=0");
    let s = stat(&rig.sock);
    let i = info(&rig.sock);
    assert_eq!((s["scur"], s["smax"], s["stot"], s["conn_tot"], s["req_tot"]), (3, 3, 3, 3, 6), "{s:?}");
    // HAProxy: 6 x 63 (the HTX size of the request). Ibex counts the HTTP/1 bytes of the relay.
    assert!(s["bin"] > 0, "{s:?}");
    assert_eq!((i["CurrConns"], i["CumConns"], i["CumReq"], i["CurrSslConns"], i["CumSslConns"]), (3, 3, 6, 3, 3));
    assert_eq!(p.line(), "closed");
    std::thread::sleep(Duration::from_millis(500));
    let s = stat(&rig.sock);
    let i = info(&rig.sock);
    assert_eq!((s["scur"], s["stot"], s["req_tot"], i["CurrConns"], i["CurrSslConns"], i["CumSslConns"]), (0, 3, 6, 0, 0, 3), "{s:?}");
}

#[test]
fn two_hundred_idle_connections_are_two_hundred_sessions() {
    let rig = start("idle200", "", "");
    let mut p = Probe::run(rig.quic, 200, 1, 3, 15);
    let ready = p.served(200);
    assert!(ready.starts_with("ready ok=200 fail=0"), "{ready}");
    let i = info(&rig.sock);
    assert_eq!((i["CurrConns"], i["CurrSslConns"]), (200, 200));
    assert_eq!(stat(&rig.sock)["scur"], 200);
    assert_eq!(p.line(), "closed");
}

/// The windows are HAProxy's (`quic_transport_params_init`): 100 streams of `bufsize - 4` for the
/// connection, 90 % of that for a request stream (`tune.quic.fe.stream-data-ratio`). Measured on
/// 3.5-dev7 with the default bufsize (16384) and `tune.bufsize 8192`.
#[test]
fn the_transport_windows_follow_bufsize_and_the_stream_data_ratio() {
    for (global, expected) in [("", (1_638_000, 1_474_200)), ("  tune.bufsize 8192\n", (818_800, 736_920))] {
        let rig = start("windows", global, "");
        let mut p = Probe::run(rig.quic, 1, 1, 0, 5);
        assert_eq!(p.params(), expected, "global: {global:?}");
    }
}

/// `global maxconn` reached: HAProxy's listener does not accept the connection at all, so it is
/// neither waiting nor in any counter (3.5-dev7, `global maxconn 3`, 6 connections: `CurrConns 3`,
/// `CumSslConns 3`, `scur 3`, three clients served and three failed).
#[test]
fn global_maxconn_refuses_the_connections_beyond_it() {
    let rig = start("globalmax", "  maxconn 3\n", "");
    let mut p = Probe::run(rig.quic, 6, 1, 3, 4);
    assert_eq!(p.served(3), "ready ok=3 fail=3");
    let s = stat(&rig.sock);
    let i = info(&rig.sock);
    assert_eq!((s["scur"], s["stot"], s["req_tot"]), (3, 3, 3), "{s:?}");
    assert_eq!((i["CurrConns"], i["CurrSslConns"], i["CumSslConns"]), (3, 3, 3));
    assert_eq!(p.line(), "closed");
}
