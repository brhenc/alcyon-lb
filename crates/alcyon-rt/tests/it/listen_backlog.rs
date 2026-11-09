// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T360: the `listen()` backlog of a bind is `HAProxy`'s `listener_backlog()`: the bind's
//! `backlog`, else the proxy's `backlog`, else the proxy's `maxconn` (which is the global
//! `maxconn` when the proxy sets none), capped by `net.core.somaxconn`; a socket handed
//! over by `-x` keeps the backlog it had.
//!
//! Expected values measured on /home/bhenc/reference/haproxy/haproxy (3.5-dev8-885761-29):
//! the Send-Q of the LISTEN sockets in `ss -ltn`, which this test reads. Task file: tasks/T360-listen-backlog-default.md.

use crate::common;

use std::io::Write;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;

/// The backlogs of the LISTEN sockets on `addr`, one per socket (a worker thread each): the
/// Send-Q column of `ss -ltn`. (/proc/net/tcp does not show it on this kernel.)
fn backlogs(addr: SocketAddr) -> Vec<u64> {
    let out = Command::new("ss")
        .args(["-ltn", &format!("sport = :{}", addr.port())])
        .output()
        .expect("this test needs `ss` (iproute2)");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().nth(2)?.parse().ok())
        .collect()
}

fn somaxconn() -> u64 {
    std::fs::read_to_string("/proc/sys/net/core/somaxconn").expect("somaxconn").trim().parse().expect("number")
}

fn start(cfg: &str, extra: &[String]) -> (NamedTempFile, common::Alcyon) {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Alcyon)
        .expect("spawn");
    (f, child)
}

fn config(global: &str, defaults: &str, fe: &str, bind: &str, addr: SocketAddr) -> String {
    format!(
        "global\n{global}\ndefaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n{defaults}\n\
         frontend fe\n{fe}\n  bind {addr} {bind}\n  default_backend be\nbackend be\n  server s 127.0.0.1:1\n"
    )
}

/// (name, global, defaults, frontend, bind, expected backlog), before the somaxconn cap.
const SHAPES: &[(&str, &str, &str, &str, &str, u64)] = &[
    ("global maxconn 50", "  maxconn 50", "", "", "", 50),
    ("global maxconn 2000", "  maxconn 2000", "", "", "", 2000),
    ("frontend maxconn 300", "", "", "  maxconn 300", "", 300),
    ("frontend maxconn 300, global 5000", "  maxconn 5000", "", "  maxconn 300", "", 300),
    ("global 2000, frontend 300", "  maxconn 2000", "", "  maxconn 300", "", 300),
    ("frontend backlog 50", "", "", "  backlog 50", "", 50),
    ("bind backlog 40", "", "", "", "backlog 40", 40),
    ("bind backlog 40 over frontend backlog 50", "", "", "  backlog 50", "backlog 40", 40),
    ("frontend backlog 50 over frontend maxconn 300", "", "", "  backlog 50\n  maxconn 300", "", 50),
    ("defaults maxconn 400", "", "  maxconn 400", "", "", 400),
    ("defaults maxconn 400, global 5000", "  maxconn 5000", "  maxconn 400", "", "", 400),
    ("defaults maxconn 400, frontend 300", "", "  maxconn 400", "  maxconn 300", "", 300),
    ("defaults backlog 60", "", "  backlog 60", "", "", 60),
    ("defaults backlog 60, frontend backlog 50", "", "  backlog 60", "  backlog 50", "", 50),
    ("defaults backlog 60 over defaults maxconn 400", "", "  backlog 60\n  maxconn 400", "", "", 60),
    ("frontend backlog 0 is unset", "  maxconn 70", "", "  backlog 0", "", 70),
];

#[test]
fn the_listen_backlog_follows_listener_backlog() {
    let mut bad = Vec::new();
    for &(name, global, defaults, fe, bind, expected) in SHAPES {
        let addr = common::reserve_addr();
        let (_f, mut child) = start(&config(global, defaults, fe, bind, addr), &[]);
        let up = common::wait_listening(addr);
        let got = backlogs(addr);
        common::stop(&mut child);
        let want = expected.min(somaxconn());
        if !up || got.is_empty() || got.iter().any(|&b| b != want) {
            bad.push(format!("{name}: expected {want}, listening sockets have {got:?} (up: {up})"));
        }
    }
    assert!(bad.is_empty(), "listen() backlogs differ from HAProxy's:\n{}", bad.join("\n"));
}

#[test]
fn without_any_setting_the_backlog_is_the_global_maxconn_capped_by_somaxconn() {
    // Measured: 4096 with somaxconn 4096 and the ideal maxconn of a 1M-descriptor limit.
    let hard = rustix::process::getrlimit(rustix::process::Resource::Nofile).maximum.unwrap_or(u64::MAX);
    if hard < 2 * somaxconn() + 100 {
        eprintln!("skipped: the descriptor limit {hard} makes the ideal maxconn lower than somaxconn");
        return;
    }
    let addr = common::reserve_addr();
    let (_f, mut child) = start(&config("", "", "", "", addr), &[]);
    assert!(common::wait_listening(addr));
    let got = backlogs(addr);
    common::stop(&mut child);
    assert!(!got.is_empty() && got.iter().all(|&b| b == somaxconn()), "{got:?} vs somaxconn {}", somaxconn());
}

/// Measured with `haproxy -W` and SIGUSR2: the new worker takes the listening sockets over and
/// they keep the backlog of the process that bound them, whatever the new configuration says.
#[test]
fn a_socket_taken_over_keeps_its_backlog() {
    let addr = common::reserve_addr();
    let sock = std::path::PathBuf::from(format!("/tmp/alcyon-bl-{}.sock", std::process::id()));
    let with_sock = |c: String| c.replacen("global\n", &format!("global\n  stats socket {} mode 600 level admin expose-fd listeners\n", sock.display()), 1);
    let (_f1, mut old) = start(&with_sock(config("", "", "  backlog 50", "", addr)), &[]);
    assert!(common::wait_listening(addr));
    assert!(backlogs(addr).iter().all(|&b| b == 50), "old: {:?}", backlogs(addr));
    let (_f2, mut new) = start(
        &with_sock(config("", "", "  backlog 70", "", addr)),
        &["-x".into(), sock.display().to_string(), "-sf".into(), old.0.id().to_string()],
    );
    let _ = old.0.wait();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let got = backlogs(addr);
    common::stop(&mut new);
    let _ = std::fs::remove_file(&sock);
    assert!(!got.is_empty() && got.iter().all(|&b| b == 50), "after the reload: {got:?}");
}

#[test]
fn a_backlog_without_a_number_is_refused_as_haproxy_does() {
    // `haproxy -c` on 3.5-dev8: "'backlog' expects an integer argument.", exit 1.
    let cfg = "defaults\n  mode http\n  timeout client 1s\n  timeout server 1s\n  timeout connect 1s\nfrontend f\n  bind 127.0.0.1:1\n  backlog\n";
    let f = NamedTempFile::new().expect("tmp");
    std::fs::write(f.path(), cfg).expect("write cfg");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(f.path()).output().expect("alcyon -c");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("'backlog' expects an integer argument."), "{}", String::from_utf8_lossy(&out.stderr));
}
