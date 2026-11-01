// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T561: a QUIC connection the proxy closes itself gives its counters back.
//!
//! quinn raises no `ConnectionLost` for a connection closed on this side (the close timer
//! drains it silently), so the endpoint has to report that end itself. Without it
//! `act_conn`/`maxconn` of the frontend (and `CurrConns`) never come down and the frontend
//! ends refusing every new h3 connection. `maxconn 10`, 5 rounds of 10 connections the proxy
//! closes (`http-request reject`), then `CurrConns`/`scur` are 0 and one
//! more connection is served.

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

/// `conns` connections, `reqs` requests each, held `hold` s. Returns the probe once every
/// connection has been answered or given up, with its "ready" line; the clients stay open.
fn probe(port: u16, conns: u32, reqs: u32, hold: u32, wait: u32) -> (std::process::Child, String) {
    let script = format!("{}/tests/data/h3_hold.py", env!("CARGO_MANIFEST_DIR"));
    let mut c = Command::new("python3")
        .args([&script, &port.to_string(), &conns.to_string(), &reqs.to_string(), &hold.to_string(), &wait.to_string()])
        .stdout(Stdio::piped())
        .spawn()
        .expect("python3 with aioquic");
    let mut out = BufReader::new(c.stdout.take().expect("stdout"));
    loop {
        let mut l = String::new();
        assert!(out.read_line(&mut l).expect("probe") > 0, "probe ended");
        if l.starts_with("ready") {
            std::mem::forget(out);
            return (c, l);
        }
    }
}

fn field(info: &str, name: &str) -> u64 {
    info.lines().find_map(|l| l.strip_prefix(&format!("{name}: "))).and_then(|v| v.trim().parse().ok()).unwrap_or_else(|| panic!("{name} in {info}"))
}

fn scur(stat: &str) -> u64 {
    stat.lines().find(|l| l.starts_with("fe,FRONTEND,")).and_then(|l| l.split(',').nth(4)).and_then(|v| v.parse().ok()).unwrap_or_else(|| panic!("fe scur in {stat}"))
}

fn run(tag: &str, rule: &str, reqs: u32, hold: u32) {
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let quic = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("t561-{tag}-{}-{}", common::h3_path_name(), std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let sock = dir.join("cli.sock").display().to_string();
    let cfg = format!(
        "global\n  stats socket {sock} level admin\n  nbthread 2\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 200ms\n  timeout server 30s\n\
         frontend fe\n  maxconn 10\n  bind quic4@{quic} ssl crt {crt} alpn h3\n  {rule}\n"
    );
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).expect("cfg");
    let child = common::ibex_command(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let _ibex = common::Ibex(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(500));
    let port = quic.port();
    // The clients stay silent and open for `hold` s: only the proxy can end the connection.
    for _ in 0..5 {
        let (mut p, _) = probe(port, 10, reqs, hold, 2);
        let deadline = Instant::now() + Duration::from_secs(u64::from(hold) - 1);
        loop {
            let info = cli(&sock, "show info");
            let stat = cli(&sock, "show stat");
            let (c, s) = (field(&info, "CurrConns"), scur(&stat));
            if c == 0 && s == 0 {
                break;
            }
            assert!(Instant::now() < deadline, "the proxy closed 10 connections, the clients are still open: CurrConns={c} scur={s}\n{stat}");
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = p.wait();
    }
    let q = cli(&sock, "show quic");
    assert_eq!(q.lines().filter(|l| l.starts_with("0x")).count(), 0, "connections left: {q}");
    // A 51st is still served (the reject rule answers nothing, so only count it admitted).
    let (mut p, last) = probe(port, 1, reqs, 0, 2);
    let _ = p.wait();
    if reqs > 0 {
        assert!(last.contains("ok=1"), "51st connection not served: {last:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

crate::h3_both_paths! {
fn reject_releases_the_slot() {
    run("rj", "http-request reject", 0, 3);
}
}
