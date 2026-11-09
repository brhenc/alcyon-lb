// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T386: `cpu_calls`, `cpu_ns_tot`, `cpu_ns_avg`, `lat_ns_tot`, `lat_ns_avg` and
//! `cpu_usage_{proc,thr,grp}`. Measured on `HAProxy` 3.5-dev8 with `profiling.tasks` off (the
//! default): the nanosecond counters are 0, `cpu_calls` is 1 in a rule of the first request,
//! the usage values are percentages.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

fn body(addr: SocketAddr) -> String {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn cpu_and_latency_fetches_have_values() {
    let a = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("cpu-lat-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(
        &path,
        format!(
            "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind {a}\n  http-request return status 200 hdr x-cpu \"%[cpu_calls] %[cpu_ns_tot] %[cpu_ns_avg] %[lat_ns_tot] %[lat_ns_avg]\" hdr x-dateus \"%[date_us]\" hdr x-usage \"%[cpu_usage_proc] %[cpu_usage_thr] %[cpu_usage_grp]\"\n\
             \x20 http-after-response set-header x-c2 \"%[cpu_calls] %[cpu_ns_tot] %[lat_ns_tot]\"\n"
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let ok = common::wait_listening(a);
    let resp = if ok { body(a) } else { String::new() };
    common::stop(&mut child);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(ok, "alcyon did not listen");
    let hdr = |n: &str| {
        resp.lines()
            .find_map(|l| l.to_ascii_lowercase().strip_prefix(&format!("{n}: ")).map(str::to_string))
            .unwrap_or_else(|| panic!("no {n} in {resp:?}"))
    };
    assert_eq!(hdr("x-cpu"), "1 0 0 0 0");
    // `date_us` is the microsecond part of the date (`date.tv_usec`), not the whole date.
    assert!(hdr("x-dateus").parse::<u32>().unwrap() < 1_000_000);
    assert_eq!(hdr("x-c2"), "1 0 0");
    let usage: Vec<u32> = hdr("x-usage").split(' ').map(|v| v.parse().unwrap()).collect();
    assert_eq!(usage.len(), 3);
    assert!(usage.iter().all(|&u| u <= 100));
}

/// `HAProxy` exports `HAPROXY_LOCALPEER` (the host name, measured: "amanet" on a plain
/// config) before the configuration is read, overriding whatever the environment had; it
/// is visible to `env()`.
#[test]
fn haproxy_localpeer_is_exported() {
    let a = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("localpeer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(
        &path,
        format!(
            "defaults\n  mode http\n  timeout client 5s\nfrontend fe\n  bind {a}\n  \
             http-request return status 200 hdr x-env \"%[env(HAPROXY_LOCALPEER)]\"\n"
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(&path)
        .env("HAPROXY_LOCALPEER", "stale")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let ok = common::wait_listening(a);
    let resp = if ok { body(a) } else { String::new() };
    common::stop(&mut child);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(ok, "alcyon did not listen");
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
    let host = host.trim();
    assert!(resp.contains(&format!("x-env: {host}\r\n")), "{resp:?}");
}
