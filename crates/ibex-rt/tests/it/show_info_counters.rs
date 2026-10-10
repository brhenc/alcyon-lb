// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `show info` fields a monitoring tool reads, after three requests (T165). The
//! reference `HAProxy` (3.5-dev8-885761-29) printed `Uptime: 0d 0h00m01s` (the hours are
//! not padded), `Uptime_sec: 1`, `CurrConns: 0`, `CumConns: 4` and `CumReq: 4` (its own
//! `show info` connection counts, Ibex's does not), `Maxsock` and `Ulimit-n` the file
//! descriptor limit (1048576), `Maxconn` 524174, `Process_num: 1`, `Idle_pct: 99`.
//! Ibex printed `Ulimit-n: 0`, `Maxsock: 0`, `CumConns: 0`, `CumReq: 0` and `00h` hours.
//!
//! Reaches the data path in `stats.rs` (`format_show_info`), which `applet.rs` calls with
//! the proxies' counters.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn show_info_counts_connections_requests_and_descriptors() {
    let port = common::reserve_port();
    let sock = std::env::temp_dir().join(format!("ibex_t165_info_{}.sock", std::process::id()));
    let cfg = format!(
        "global\n  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout client 5s\n\
         frontend fe\n  bind 127.0.0.1:{port}\n  http-request return status 200\n",
        sock.display()
    );
    let path = std::env::temp_dir().join(format!("ibex_t165_info_{}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Ibex).expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sock.exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        thread::sleep(Duration::from_millis(25));
    }
    thread::sleep(Duration::from_millis(300));
    for _ in 0..3 {
        let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.write_all(b"GET /a HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n").expect("write");
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
    }
    thread::sleep(Duration::from_millis(300));
    let mut c = UnixStream::connect(&sock).expect("cli");
    c.write_all(b"show info\n").expect("write");
    let mut info = String::new();
    c.read_to_string(&mut info).expect("read");
    common::stop(&mut child);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&sock);

    let field = |k: &str| info.lines().find_map(|l| l.strip_prefix(&format!("{k}: "))).unwrap_or_else(|| panic!("no {k} in {info}")).to_string();
    let num = |k: &str| field(k).parse::<u64>().unwrap_or_else(|_| panic!("{k}: {}", field(k)));
    assert_eq!(num("CumConns"), 3);
    assert_eq!(num("CumReq"), 3);
    assert_eq!(num("CurrConns"), 0);
    assert!(num("Maxsock") >= 1024 && num("Ulimit-n") == num("Maxsock"), "{info}");
    assert!(num("Maxconn") > 0 && num("Uptime_sec") < 60 && num("Process_num") == 1 && num("Nbthread") >= 1 && num("Idle_pct") <= 100);
    // `0d 0h00m01s`: days and hours are not padded, minutes and seconds are.
    let up = field("Uptime");
    let ok = up.split_once("d ").is_some_and(|(d, r)| {
        d.parse::<u32>().is_ok() && r.split_once('h').is_some_and(|(h, r)| h.parse::<u32>().is_ok() && !h.starts_with('0') | (h == "0") && r.len() == 6 && r.ends_with('s'))
    });
    assert!(ok, "Uptime {up:?}");
}

/// The engine's own `show info` text (`Engine::format_stats_info`) carries the same fields,
/// with nothing counted yet.
#[test]
fn the_engine_formats_its_info_with_the_counters() {
    let port = common::reserve_port();
    let cfg = format!("defaults\n  mode http\n  timeout client 5s\nfrontend fe\n  bind 127.0.0.1:{port}\n  http-request return status 200\n");
    let engine = ibex_rt::Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let info = engine.format_stats_info();
    for want in ["CumConns: 0\n", "CumReq: 0\n", "Process_num: 1\n"] {
        assert!(info.contains(want), "{want:?} in {info}");
    }
    assert!(!info.contains("Maxsock: 0\n"), "{info}");
}
