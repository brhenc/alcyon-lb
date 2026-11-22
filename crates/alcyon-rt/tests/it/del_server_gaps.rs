// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T652: what a deleted server leaves behind. After `del server`, its health check logs
//! nothing (HAProxy stops the check task), and the Prometheus exporter has no series for it.
//! Both run against the reference binary with `DELGAPS_ORACLE=/path/to/haproxy`; the promex
//! one needs a build with PROMEX (`~/reference/haproxy-3.5-latest/haproxy`, the default one has none).

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn wait_cli(sock: &str) -> bool {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(5) {
        if UnixStream::connect(sock).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

fn binary() -> String {
    std::env::var("DELGAPS_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

fn spawn(dir: &std::path::Path, cfg: &str) -> common::Alcyon {
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let child = Command::new(binary())
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    common::Alcyon(child)
}

/// A port that accepts for `on` then refuses for `off`, forever: the check of a server on it
/// flips between passing and failing, so its health counter moves and `option
/// log-health-checks` writes a line for most checks.
fn flapping_port() -> u16 {
    let port = common::reserve_port();
    std::thread::spawn(move || loop {
        if let Ok(l) = TcpListener::bind(("127.0.0.1", port)) {
            l.set_nonblocking(true).unwrap();
            let t = Instant::now();
            while t.elapsed() < Duration::from_millis(130) {
                let _ = l.accept();
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        std::thread::sleep(Duration::from_millis(130));
    });
    port
}

fn drain(sink: &UdpSocket, until: Duration) -> Vec<String> {
    let mut lines = Vec::new();
    let t = Instant::now();
    let mut buf = [0u8; 4096];
    while t.elapsed() < until {
        if let Ok(n) = sink.recv(&mut buf) {
            lines.push(String::from_utf8_lossy(&buf[..n]).into_owned());
        }
    }
    lines
}

#[test]
fn a_deleted_servers_check_logs_nothing() {
    let (p1, p2) = (flapping_port(), flapping_port());
    let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
    sink.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let dir = std::env::temp_dir().join(format!("delgaps-chk-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").to_string_lossy().into_owned();
    let cfg = format!(
        "global\n  stats socket {sock} mode 600 level admin\n  log 127.0.0.1:{} local0\n\
         defaults\n  mode http\n  log global\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         backend be\n  option log-health-checks\n  server s1 127.0.0.1:{p1} check inter 30ms fall 100 rise 100\n  \
         server s2 127.0.0.1:{p2} check inter 30ms fall 100 rise 100\n",
        sink.local_addr().unwrap().port()
    );
    let _proc = spawn(&dir, &cfg);
    assert!(wait_cli(&sock), "no CLI socket");

    let before = drain(&sink, Duration::from_millis(700));
    assert!(before.iter().any(|l| l.contains("check for server be/s2")), "the sink sees s2's checks: {before:?}");

    cli(&sock, "disable server be/s2");
    assert_eq!(cli(&sock, "del server be/s2"), "Server deleted.\n\n");
    let _ = drain(&sink, Duration::from_millis(100)); // lines already in flight

    let after = drain(&sink, Duration::from_millis(800));
    assert!(after.iter().any(|l| l.contains("check for server be/s1")), "the sink still sees s1: {after:?}");
    let stale: Vec<_> = after.iter().filter(|l| l.contains("be/s2") || l.contains("be/ ") || l.contains("be/,")).collect();
    assert!(stale.is_empty(), "a deleted server's check logged: {stale:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn scrape(addr: &str) -> String {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn promex_lists_no_deleted_server() {
    let fe = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("delgaps-prx-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").to_string_lossy().into_owned();
    let cfg = format!(
        "global\n  stats socket {sock} mode 600 level admin\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend px\n  bind {fe}\n  http-request use-service prometheus-exporter if {{ path /metrics }}\n\
         backend be\n  server s1 127.0.0.1:1\n  server s2 127.0.0.1:2\n  server s3 127.0.0.1:3\n"
    );
    let _proc = spawn(&dir, &cfg);
    assert!(wait_cli(&sock), "no CLI socket");
    assert!(common::wait_listening(fe));

    let fe = fe.to_string();
    let first = scrape(&fe);
    assert!(first.contains("server=\"s2\""), "s2 is listed before the delete: {first}");

    cli(&sock, "disable server be/s2");
    assert_eq!(cli(&sock, "del server be/s2"), "Server deleted.\n\n");

    let body = scrape(&fe);
    assert!(body.contains("proxy=\"be\",server=\"s1\""), "s1 stays: {body}");
    assert!(body.contains("proxy=\"be\",server=\"s3\""), "s3 stays: {body}");
    assert!(!body.contains("server=\"s2\""), "the deleted server has series");
    assert!(!body.contains("server=\"\""), "a series has an empty server name");
    let _ = std::fs::remove_dir_all(&dir);
}

fn tasks(sock: &str) -> i64 {
    let out = cli(sock, "show info");
    let line = out.lines().find(|l| l.starts_with("Tasks:")).unwrap_or_else(|| panic!("no Tasks line in {out:?}"));
    line["Tasks:".len()..].trim().parse().unwrap()
}

/// T658: `del server` frees the server's check task and its agent-check task, as HAProxy's
/// `srv_drop` does; `show info`'s `Tasks` is the count. Before the fix the tasks stayed and
/// woke every `inter` for the life of the process.
#[test]
fn a_deleted_servers_check_tasks_are_freed() {
    let dir = std::env::temp_dir().join(format!("delgaps-tsk-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").to_string_lossy().into_owned();
    // Accepts and never answers: a check and an agent check on it are in flight (waiting for
    // the reply) when the server goes, so their sockets must be closed with the task.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let sp = silent.local_addr().unwrap().port();
    let mut cfg = format!(
        "global\n  stats socket {sock} mode 600 level admin\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n  timeout check 1s\n\
         backend be\n  option httpchk\n"
    );
    for i in 1..=6 {
        // A check and an agent-check each: two tasks per server.
        let (port, aport) = if i == 1 { (sp, sp) } else { (9 + i, 20 + i) };
        cfg.push_str(&format!("  server s{i} 127.0.0.1:{port} check inter 200ms agent-check agent-port {aport} agent-inter 200ms\n"));
    }
    // This one is never deleted: its tasks must stay.
    cfg.push_str("  server keep 127.0.0.1:40 check inter 200ms\n");
    let _proc = spawn(&dir, &cfg);
    assert!(wait_cli(&sock), "no CLI socket");

    // Startup tasks (one-shot) end within the first moments.
    std::thread::sleep(Duration::from_millis(500));
    let before = tasks(&sock);
    silent.set_nonblocking(true).unwrap();
    let mut held = Vec::new();
    let t = Instant::now();
    while held.len() < 2 && t.elapsed() < Duration::from_secs(3) {
        match silent.accept() {
            Ok((c, _)) => held.push(c),
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    assert_eq!(held.len(), 2, "the check and the agent check of s1 are connected");
    for i in 1..=6 {
        cli(&sock, &format!("disable server be/s{i}"));
        assert_eq!(cli(&sock, &format!("del server be/s{i}")), "Server deleted.\n\n");
    }
    // HAProxy frees them at once; Alcyon's tasks free themselves on their next wake (one
    // `inter` at most), which ends them: wait for it.
    let t = Instant::now();
    let mut after = tasks(&sock);
    while before - after < 12 && t.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(50));
        after = tasks(&sock);
    }
    assert!(before - after >= 12, "12 tasks (6 checks, 6 agent-checks) go with the servers: Tasks {before} -> {after}");
    let _ = std::fs::remove_dir_all(&dir);
}
