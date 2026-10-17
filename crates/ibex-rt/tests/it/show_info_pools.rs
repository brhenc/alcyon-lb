// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T320: show info pool totals

use crate::common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Ibex(Child, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Starts ibex on `cfg` (`{sock}` is replaced by the stats socket path), waits for `addrs` and the
/// socket, then lets the readiness probes slide out of the one-second windows and clears the maxima.
fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> (Ibex, String) {
    let dir = std::env::temp_dir().join(format!("qh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg.replace("{sock}", &sock).replace("{dir}", &dir.display().to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let ibex = Ibex(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "ibex did not listen on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(2200));
    cli(&sock, "clear counters");
    (ibex, sock)
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn info(sock: &str) -> HashMap<String, String> {
    cli(sock, "show info").lines().filter_map(|l| l.split_once(": ")).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn num(i: &HashMap<String, String>, k: &str) -> u64 {
    i.get(k).unwrap_or_else(|| panic!("show info has no {k}")).parse().unwrap_or_else(|_| panic!("{k} is not a number: {:?}", i[k]))
}

/// One request on a new connection; the whole raw answer.
fn get(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";

fn http_cfg(global: &str, body: &str) -> String {
    format!(
        "global\n  stats socket {{sock}} level admin\n{global}\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n{body}"
    )
}

#[test]
fn show_info_pools() {
    let a = common::reserve_addr();
    let (ibex, sock) = start("show_info_pools", &http_cfg("", &format!("frontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain string 0123456789\n")), &[a]);

    for _ in 0..5 {
        get(a, GET);
    }

    std::thread::sleep(Duration::from_millis(200));

    let info = info(&sock);
    let pools_out = cli(&sock, "show pools");

    // Parse the Total line from show pools
    let total_line = pools_out.lines().find(|l| l.starts_with("Total:"))
        .expect("show pools has no Total: line");

    // Format: "Total: N pools, A bytes allocated, U used (~C by thread caches)."
    let alloc_bytes = total_line
        .split(',')
        .nth(1)
        .and_then(|s| s.split("bytes allocated").next())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .expect("could not parse allocated bytes from Total line");

    let used_bytes = total_line
        .split(',')
        .nth(2)
        .and_then(|s| s.split(" used").next())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .expect("could not parse used bytes from Total line");

    assert!(alloc_bytes > 0, "PoolAlloc_bytes should be > 0 after requests");

    let info_alloc_mb = num(&info, "PoolAlloc_MB");
    let info_used_mb = num(&info, "PoolUsed_MB");
    let info_alloc_bytes = num(&info, "PoolAlloc_bytes");
    let info_used_bytes = num(&info, "PoolUsed_bytes");

    assert_eq!(info_alloc_bytes, alloc_bytes, "PoolAlloc_bytes mismatch");
    assert_eq!(info_used_bytes, used_bytes, "PoolUsed_bytes mismatch");
    assert_eq!(info_alloc_mb, alloc_bytes / 1_048_576, "PoolAlloc_MB mismatch");
    assert_eq!(info_used_mb, used_bytes / 1_048_576, "PoolUsed_MB mismatch");

    drop(ibex);
}
