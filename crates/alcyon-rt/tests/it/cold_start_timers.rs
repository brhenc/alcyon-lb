// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T375: the log timers are stamped from the loop's per-iteration clock (`now_ns`), so the
//! first request of a freshly started Alcyon, parsed and connected in one pass, logs `Tq`
//! and `Tw` 0 whatever the machine is doing, as HAProxy does (tradeoff.md 6.16).

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// CPU burners, killed and reaped when dropped.
struct Burners(Vec<Child>);

impl Burners {
    fn start() -> Burners {
        let n = std::thread::available_parallelism().map_or(4, |n| n.get()) * 2;
        Burners(
            (0..n)
                .filter_map(|_| Command::new("sh").args(["-c", "while :; do :; done"]).stdin(Stdio::null()).spawn().ok())
                .collect(),
        )
    }
}

impl Drop for Burners {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// The timers `Tq/Tw/Tc/Tr/Ta` of the one request a fresh Alcyon serves.
fn timers_of_first_request() -> String {
    let be = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let be_addr = be.local_addr().expect("addr");
    std::thread::spawn(move || {
        while let Ok((mut s, _)) = be.accept() {
            let mut b = [0u8; 1024];
            let _ = s.read(&mut b);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    let log = UdpSocket::bind("127.0.0.1:0").expect("bind log");
    log.set_read_timeout(Some(Duration::from_millis(200))).expect("timeout");
    let log_addr = log.local_addr().expect("addr");
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n  nbthread 1\ndefaults\n  mode http\n  timeout client 5s\n  timeout connect 1s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  log {log_addr} format raw local0\n  option httplog\n  default_backend b\n\
         backend b\n  server s {be_addr}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Alcyon).expect("spawn alcyon");
    assert!(common::wait_listening(fe), "alcyon never listened");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    c.write_all(b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    let _ = c.read(&mut [0u8; 200]);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut buf = [0u8; 4096];
    let mut got = None;
    while got.is_none() && Instant::now() < deadline {
        if let Ok(n) = log.recv(&mut buf) {
            let l = String::from_utf8_lossy(&buf[..n]).into_owned();
            if let Some(i) = l.find("] ").filter(|_| l.contains("GET /x")) {
                got = Some(l[i + 2..].trim().to_string());
            }
        }
    }
    common::stop(&mut child);
    got.expect("no log line for the request")
}

#[test]
fn first_request_of_a_cold_start_waits_zero_under_cpu_load() {
    let _burn = Burners::start();
    for run in 0..10 {
        let line = timers_of_first_request();
        // `f b/s Tq/Tw/Tc/Tr/Ta ...`
        let t = line.split(' ').nth(2).expect("timers");
        let v: Vec<&str> = t.split('/').collect();
        assert_eq!(v[0], "0", "run {run} Tq: {line}");
        assert_eq!(v[1], "0", "run {run} Tw: {line}");
    }
}
