// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T624: `tcp-request connection track-sc0` and `http-request track-sc1` on a QUIC frontend.
//! One HTTP/3 connection, three requests (`tests/data/h3_hold.py`), the tables read while the
//! connection is open and again after it closed. `H3TRACK_ORACLE=<haproxy>` runs this file
//! against HAProxy (`~/reference/haproxy-quic/haproxy`, 3.5-dev10); the numbers in the
//! assertions are the ones it printed.

use crate::common;

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// The counters of the one entry of `table`, as `conn_cnt=1 conn_cur=0 http_req_cnt=3`.
fn entry(sock: &str, table: &str) -> String {
    let out = cli(sock, &format!("show table {table}"));
    let row = out.lines().find(|l| l.contains("key=")).unwrap_or("none");
    let keep = |w: &&str| w.starts_with("conn_cnt=") || w.starts_with("conn_cur=") || w.starts_with("http_req_cnt=");
    let v: Vec<&str> = row.split_whitespace().filter(keep).collect();
    if v.is_empty() { row.trim().to_string() } else { v.join(" ") }
}

type Seen = ((String, String), (String, String));

/// The two tables while the connection is open and after it closed.
fn run() -> Seen {
    run_with("")
}

/// [`run`] with `extra` (config lines) after the `tcp-request connection track-sc0` rule.
fn run_with(extra: &str) -> Seen {
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let quic = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("h3track-{}-{}", std::process::id(), quic.port()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let sock = dir.join("cli.sock").display().to_string();
    let cfg = format!(
        "global\n  stats socket {sock} level admin\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n\
         backend t\n  stick-table type ip size 10 expire 1m store conn_cnt,conn_cur,http_req_cnt\n\
         backend t2\n  stick-table type ip size 10 expire 1m store conn_cnt,conn_cur,http_req_cnt\n\
         frontend fe\n  bind quic4@{quic} ssl crt {crt} alpn h3\n\
         \x20 tcp-request connection track-sc0 src table t\n{extra}\
         \x20 http-request track-sc1 src table t2\n\
         \x20 http-request return status 200 content-type text/plain string \"ok\"\n"
    );
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).expect("cfg");
    let bin = std::env::var("H3TRACK_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut child = Command::new(bin).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(500));
    let script = format!("{}/tests/data/h3_hold.py", env!("CARGO_MANIFEST_DIR"));
    let mut p = Command::new("python3")
        .args([&script, &quic.port().to_string(), "1", "3", "3", "3"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("python3 with aioquic");
    let mut out = BufReader::new(p.stdout.take().expect("stdout"));
    let mut line = String::new();
    while !line.starts_with("ready") {
        line.clear();
        assert!(out.read_line(&mut line).expect("probe") > 0, "probe ended");
    }
    let open = (entry(&sock, "t"), entry(&sock, "t2"));
    line.clear();
    while !line.starts_with("closed") {
        line.clear();
        assert!(out.read_line(&mut line).expect("probe") > 0, "probe ended");
    }
    std::thread::sleep(Duration::from_millis(500));
    let closed = (entry(&sock, "t"), entry(&sock, "t2"));
    let _ = p.wait();
    common::stop(&mut child);
    let _ = std::fs::remove_dir_all(&dir);
    (open, closed)
}

#[test]
fn the_connection_rule_tracks_a_quic_connection_and_gives_it_back_at_close() {
    let (open, closed) = run();
    // HAProxy 3.5-dev10: the connection's slot sees the connection and its three requests.
    assert_eq!(open.0, "conn_cnt=1 conn_cur=1 http_req_cnt=3");
    assert_eq!(closed.0, "conn_cnt=1 conn_cur=0 http_req_cnt=3", "conn_cur is given back at close");
}

/// Step 2b of T624, not done: a request stream's own `http-request track-sc1` slot. HAProxy
/// counts a connection per stream (each stream is a session of the QUIC mux) and releases it at
/// the stream's end: `conn_cnt=3 conn_cur=0 http_req_cnt=3`. Alcyon's stream shares the
/// connection's slot (`h2_child_done` hands it to the owner): `conn_cnt=1`, `conn_cur=1` until
/// the connection closes.
#[test]
fn the_request_rule_tracks_each_stream_and_gives_it_back_at_its_end() {
    let (open, closed) = run();
    assert_eq!(open.1, "conn_cnt=3 conn_cur=0 http_req_cnt=3");
    assert_eq!(closed.1, "conn_cnt=3 conn_cur=0 http_req_cnt=3");
}

/// A connection a `tcp-request connection reject` ends after `track-sc0` has counted it gives
/// its slot back at once (the `untrack_slots` path of `adopt_quic_owners`): the client gets no
/// answer (`ok=0`), the entry exists with its one connection and none open. No request ran.
#[test]
fn a_rejected_quic_connection_gives_its_tracked_slot_back() {
    let (open, closed) = run_with("  tcp-request connection reject if { src 127.0.0.1 }\n");
    assert_eq!(open.0, "conn_cnt=1 conn_cur=0 http_req_cnt=0", "while the probe waits");
    assert_eq!(closed.0, "conn_cnt=1 conn_cur=0 http_req_cnt=0", "after it closed");
    assert_eq!(closed.1, "none", "no stream ran");
}
