// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T627: `tcp-request connection track-sc0` and `http-request track-sc1` on an h2c frontend.
//! Each h2 stream is a session for `http-request track-sc`: it counts a connection and gives
//! the slot back at its end; the connection's own slot stays shared. `H2TRACK_ORACLE=<haproxy>`
//! runs this file against HAProxy (`~/reference/haproxy/haproxy`, 3.5-dev8); the numbers in
//! the assertions are the ones it printed.

use crate::common;

use std::io::{Read, Write};
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

/// The counters of the one entry of `table`, as `conn_cnt=1 conn_cur=0 http_req_cnt=3`, and its `use`.
fn entry(sock: &str, table: &str) -> String {
    let out = cli(sock, &format!("show table {table}"));
    let row = out.lines().find(|l| l.contains("key=")).unwrap_or("none");
    let keep = |w: &&str| w.starts_with("conn_cnt=") || w.starts_with("conn_cur=") || w.starts_with("http_req_cnt=") || w.starts_with("use=");
    let v: Vec<&str> = row.split_whitespace().filter(keep).collect();
    if v.is_empty() { row.trim().to_string() } else { v.join(" ") }
}

/// Runs `client` (argv, `{port}` replaced) against one h2c connection; returns both tables once it closed.
fn run(client: &[&str]) -> (String, String) {
    let port = common::reserve_addr().port();
    let dir = std::env::temp_dir().join(format!("h2track-{}-{port}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let sock = dir.join("cli.sock").display().to_string();
    let cfg = format!(
        "global\n  stats socket {sock} level admin\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n\
         backend t\n  stick-table type ip size 10 expire 1m store conn_cnt,conn_cur,http_req_cnt\n\
         backend t2\n  stick-table type ip size 10 expire 1m store conn_cnt,conn_cur,http_req_cnt\n\
         frontend fe\n  bind 127.0.0.1:{port} proto h2\n\
         \x20 tcp-request connection track-sc0 src table t\n\
         \x20 http-request track-sc1 src table t2\n\
         \x20 http-request return status 200 content-type text/plain string \"ok\"\n"
    );
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).expect("cfg");
    let bin = std::env::var("H2TRACK_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let mut child = Command::new(bin).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(300));
    let args: Vec<String> = client.iter().map(|a| a.replace("{port}", &port.to_string())).collect();
    let st = Command::new(&args[0]).args(&args[1..]).stdout(Stdio::null()).stderr(Stdio::null()).status().expect("client");
    assert!(st.success(), "client failed");
    std::thread::sleep(Duration::from_millis(500));
    let closed = (entry(&sock, "t"), entry(&sock, "t2"));
    common::stop(&mut child);
    let _ = std::fs::remove_dir_all(&dir);
    closed
}

/// Three streams of one connection (`nghttp -n`): HAProxy 3.5-dev8 counts a connection per
/// stream on `t2`, one on `t`, and nothing stays in use.
#[test]
fn concurrent_streams_each_track_and_give_back_their_slot() {
    let c = run(&["nghttp", "-n", "http://127.0.0.1:{port}/a", "http://127.0.0.1:{port}/b", "http://127.0.0.1:{port}/c"]);
    assert_eq!(c.0, "use=0 conn_cnt=1 conn_cur=0 http_req_cnt=3");
    assert_eq!(c.1, "use=0 conn_cnt=3 conn_cur=0 http_req_cnt=3");
}

/// Four requests one after the other on one connection (curl reuses it): `t2` counts four.
#[test]
fn sequential_streams_each_count_a_connection() {
    let u = "http://127.0.0.1:{port}/";
    let c = run(&["curl", "-s", "--http2-prior-knowledge", "-o", "/dev/null", u, u, u, u]);
    assert_eq!(c.0, "use=0 conn_cnt=1 conn_cur=0 http_req_cnt=4");
    assert_eq!(c.1, "use=0 conn_cnt=4 conn_cur=0 http_req_cnt=4");
}
