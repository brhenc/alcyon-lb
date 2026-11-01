// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T562: `timeout client` closes an idle h3 connection, with or without client PINGs
//! (HAProxy 3.5-dev10, measured: `qcc_refresh_timeout` falls back to `timeout client` when
//! neither `http-request` nor `http-keep-alive` is set; the timer runs from `idle_start` and a
//! PING does not move it). The mux path only: the relay is retired by H5 and keeps its old timers.

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

fn counts(sock: &str) -> (u64, u64) {
    let info = cli(sock, "show info");
    let c = info.lines().find_map(|l| l.strip_prefix("CurrConns: ")).and_then(|v| v.trim().parse().ok()).unwrap_or(99);
    let stat = cli(sock, "show stat");
    let s = stat.lines().find(|l| l.starts_with("fe,FRONTEND,")).and_then(|l| l.split(',').nth(4)).and_then(|v| v.parse().ok()).unwrap_or(99);
    (c, s)
}

fn run(tag: &str, req: u32, ping: &str) {
    run_max(tag, req, ping, 100);
}

/// `maxconn` of the frontend: two idle closes, then a third client is still served.
fn run_max(tag: &str, req: u32, ping: &str, maxconn: u32) {
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let quic = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("t562-{tag}-{}-{}", common::h3_path_name(), std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let sock = dir.join("cli.sock").display().to_string();
    let cfg = format!(
        "global\n  stats socket {sock} level admin\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 500ms\n  timeout server 30s\n\
         frontend fe\n  maxconn {maxconn}\n  bind quic4@{quic} ssl crt {crt} alpn h3\n  http-request return status 200 content-type text/plain string ok\n"
    );
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).expect("cfg");
    let child = common::ibex_command(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let _ibex = common::Ibex(child);
    std::thread::sleep(Duration::from_millis(700));
    let script = format!("{}/tests/data/h3_idle.py", env!("CARGO_MANIFEST_DIR"));
    let port = quic.port().to_string();
    let client = || {
        let t = Instant::now();
        let out = Command::new("python3").args([&script, &port, &req.to_string(), ping, "6", "30"]).output().expect("python3 with aioquic");
        let out = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.contains("CLOSED"), "the proxy kept an idle connection past `timeout client 500ms` ({tag}): {out}");
        assert!(t.elapsed() < Duration::from_secs(4), "closed too late: {:?} {out}", t.elapsed());
        // Its slot comes back with the close (T561's release reaches this path too).
        let end = Instant::now() + Duration::from_secs(1);
        loop {
            let (c, s) = counts(&sock);
            if c == 0 && s == 0 {
                break;
            }
            assert!(Instant::now() < end, "closed by `timeout client`, but CurrConns={c} scur={s} ({tag})");
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    let rounds = if maxconn < 100 { maxconn + 1 } else { 1 };
    for _ in 0..rounds {
        client();
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn silent_client() {
    common::on_h3_path("mux", || run("silent", 0, "0"));
}

#[test]
fn silent_after_request() {
    common::on_h3_path("mux", || run("afterreq", 1, "0"));
}

#[test]
fn pinging_client() {
    common::on_h3_path("mux", || run("ping", 1, "0.2"));
}

#[test]
fn maxconn_slots_come_back() {
    common::on_h3_path("mux", || run_max("max", 1, "0", 2));
}
