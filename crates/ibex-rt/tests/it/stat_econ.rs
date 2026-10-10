// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `econ` column of `show stat` (T146 item 19), measured on the reference `HAProxy`
//! 3.5-dev8-885761-29 with `timeout connect 1s` and a closed port:
//!
//! * `econ` counts the requests whose connection attempts all failed, once per request and
//!   not per attempt: `retries 0` or `retries 2`, two requests, 503 each, the server's and
//!   the backend's `econ` are both 2 (and `wretr` 0 or 4);
//! * it is the server of the last attempt that is charged: with `option redispatch` and two
//!   closed servers, the two requests leave `econ` 1 on each and 2 on the backend;
//! * a request that finds no server (`503`, every server in maintenance) is charged to the
//!   backend only: backend 2, server 0;
//! * the frontend row has it empty, and a plain `clear counters` does not reset it.
//!
//! Reaches the data path where a request's connection attempts end in a 503 (`engine.rs`,
//! `count_connect_failure`); `stats.rs` prints it.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Daemon(Child, std::path::PathBuf);

impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_file(&self.1);
    }
}

fn get_status(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).split(' ').nth(1).unwrap_or("").to_string()
}

fn cli(sock: &std::path::Path, cmd: &str) -> String {
    let mut c = UnixStream::connect(sock).expect("connect cli");
    c.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = String::new();
    c.read_to_string(&mut out).expect("read");
    out
}

/// `(proxy, server) -> econ` from `show stat`.
fn econ(sock: &std::path::Path) -> Vec<(String, String, String)> {
    let out = cli(sock, "show stat");
    let mut lines = out.lines();
    let header: Vec<&str> = lines.next().expect("header").trim_start_matches("# ").split(',').collect();
    let col = header.iter().position(|h| *h == "econ").expect("an econ column");
    lines
        .filter(|l| !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split(',').collect();
            (f[0].to_string(), f[1].to_string(), f[col].to_string())
        })
        .collect()
}

#[test]
fn econ_is_counted_per_failed_request_on_the_last_server_and_the_backend() {
    let dead = common::reserve_port();
    let port = common::reserve_port();
    let dir = std::env::temp_dir();
    let sock = dir.join(format!("ibex_t146_econ_{}.sock", std::process::id()));
    let cfg = format!(
        "global\n  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 10s\n  timeout server 10s\n\
         frontend f\n  bind 127.0.0.1:{port}\n  use_backend b0 if {{ path /b0 }}\n  use_backend b2 if {{ path /b2 }}\n  \
         use_backend redisp if {{ path /redisp }}\n  default_backend nosrv\n\
         backend b0\n  retries 0\n  server d 127.0.0.1:{dead}\n\
         backend b2\n  retries 2\n  server d 127.0.0.1:{dead}\n\
         backend nosrv\n  server d 127.0.0.1:{dead} disabled\n\
         backend redisp\n  retries 2\n  option redispatch 1\n  balance roundrobin\n  server d 127.0.0.1:{dead}\n  server e 127.0.0.1:{dead}\n",
        sock.display()
    );
    let path = dir.join(format!("ibex_t146_econ_{}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let _d = Daemon(child, path);
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() || !sock.exists() {
        assert!(Instant::now() < deadline, "the daemon never listened");
        thread::sleep(Duration::from_millis(25));
    }

    for p in ["/b0", "/b0", "/b2", "/b2", "/nosrv", "/nosrv", "/redisp", "/redisp"] {
        assert_eq!(get_status(port, p), "503", "{p}");
    }
    let rows = econ(&sock);
    let row = |px: &str, sv: &str| {
        rows.iter().find(|r| r.0 == px && r.1 == sv).unwrap_or_else(|| panic!("no row {px}/{sv}")).2.clone()
    };
    assert_eq!(row("f", "FRONTEND"), "");
    assert_eq!((row("b0", "d").as_str(), row("b0", "BACKEND").as_str()), ("2", "2"));
    assert_eq!((row("b2", "d").as_str(), row("b2", "BACKEND").as_str()), ("2", "2"));
    assert_eq!((row("nosrv", "d").as_str(), row("nosrv", "BACKEND").as_str()), ("0", "2"));
    assert_eq!(row("redisp", "BACKEND"), "2");
    let (d, e) = (row("redisp", "d").parse::<u32>().expect("a number"), row("redisp", "e").parse::<u32>().expect("a number"));
    assert_eq!(d + e, 2, "each failed request is charged to one server: d={d} e={e}");

    // A plain `clear counters` leaves it, `clear counters all` zeroes it.
    cli(&sock, "clear counters");
    assert_eq!(econ(&sock).iter().find(|r| r.0 == "b0" && r.1 == "BACKEND").map(|r| r.2.clone()), Some("2".to_string()));
    cli(&sock, "clear counters all");
    assert_eq!(econ(&sock).iter().find(|r| r.0 == "b0" && r.1 == "BACKEND").map(|r| r.2.clone()), Some("0".to_string()));
}
