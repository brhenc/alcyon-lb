// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `silent-drop rst-ttl <n>` sets the socket's `IP_TTL` to `n` before the reset (tasks/T302
//! item 7). Measured with `strace -f -e trace=setsockopt` on `HAProxy` 3.5-dev8: a plain
//! `silent-drop` calls `setsockopt(SOL_IP, IP_TTL, [1])` then `SO_LINGER {1, 0}` on the
//! client socket, `rst-ttl 5` calls `IP_TTL [5]` instead. The RST still reaches a client on
//! loopback. The test traces the proxy and reads the calls back; set `T306C_ORACLE` to run
//! it against `HAProxy`. It needs `strace` and fails, rather than skipping, without it.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;

/// Runs `rule` in a frontend under strace, makes one HTTP request, and returns the
/// `IP_TTL` values set on any socket (HAProxy and Alcyon both set it twice), plus whether the client saw a reset.
fn ttls(rule: &str) -> (Vec<String>, bool) {
    ttls_on(rule, false)
}

/// [`ttls`] on a `[::1]` listener when `v6`, where the hop limit is `IPV6_UNICAST_HOPS`.
fn ttls_on(rule: &str, v6: bool) -> (Vec<String>, bool) {
    let mut fe = common::reserve_addr();
    if v6 {
        fe.set_ip(std::net::Ipv6Addr::LOCALHOST.into());
    }
    let mut cfg = NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "defaults\n  mode http\n  timeout client 3s\n  timeout server 3s\n  timeout connect 1s\n\
         frontend f\n  bind {fe}\n  {rule}\n  default_backend b\nbackend b\n  server s 127.0.0.1:1\n"
    )
    .expect("write cfg");
    let trace = NamedTempFile::new().expect("trace");
    let bin = std::env::var("T306C_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut child = common::Alcyon(Command::new("strace")
        .args(["-f", "-o"])
        .arg(trace.path())
        .args(["-e", "trace=setsockopt", &bin, "-f"])
        .arg(cfg.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("strace must be installed"));
    assert!(common::wait_listening(fe), "never listened:\n{rule}");
    let mut c = TcpStream::connect(fe).expect("connect");
    let _ = c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    let mut out = Vec::new();
    let reset = c.read_to_end(&mut out).is_err();
    // SIGUSR1 to the traced proxy (strace's child; not the first pid in the trace, which on
    // `HAProxy` is a short-lived fork), not to strace: the proxy exits normally, which writes
    // the coverage profile, and strace ends with it.
    let traced = std::fs::read_to_string(format!("/proc/{0}/task/{0}/children", child.id()))
        .unwrap_or_default()
        .split_whitespace()
        .next()
        .and_then(|p| p.parse::<i32>().ok())
        .and_then(rustix::process::Pid::from_raw);
    if let Some(pid) = traced {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::Usr1);
        // strace ends once the proxy has exited; stopping it sooner would detach the proxy
        // while it writes its coverage profile.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline && matches!(child.try_wait(), Ok(None)) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    common::stop(&mut child);
    // strace detaches from a proxy still running when it is stopped, which would leave the
    // proxy orphaned.
    if let Some(pid) = traced {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::Kill);
    }
    let log = std::fs::read_to_string(trace.path()).expect("trace");
    let ttls = log
        .lines()
        .filter(|l| !l.contains("= -1"))
        .filter_map(|l| l.split(if v6 { "IPV6_UNICAST_HOPS, [" } else { "IP_TTL, [" }).nth(1).and_then(|r| r.split(']').next()).map(str::to_string))
        .collect();
    (ttls, reset)
}

#[test]
fn rst_ttl_is_set_on_the_socket_before_the_reset() {
    for (rule, want) in [
        ("tcp-request connection silent-drop", "1"),
        ("tcp-request connection silent-drop rst-ttl 5", "5"),
        ("tcp-request session silent-drop rst-ttl 6", "6"),
        ("tcp-request content silent-drop rst-ttl 7", "7"),
        ("http-request silent-drop rst-ttl 8", "8"),
        ("http-request silent-drop rst-ttl 255 if { path / }", "255"),
        ("http-request silent-drop", "1"),
    ] {
        let (ttls, reset) = ttls(rule);
        assert_eq!(ttls.last().map(String::as_str), Some(want), "{rule}: {ttls:?}");
        assert!(reset, "{rule}: the client should see the connection reset");
    }
}

#[test]
fn rst_ttl_on_an_ipv6_listener_sets_the_hop_limit() {
    let (hops, reset) = ttls_on("http-request silent-drop rst-ttl 9", true);
    assert_eq!(hops.last().map(String::as_str), Some("9"), "{hops:?}");
    assert!(reset, "the client should see the connection reset");
}
