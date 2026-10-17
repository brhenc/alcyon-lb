// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T320: show info CumStreams

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
fn test_cum_streams() {
    let a = common::reserve_addr();
    let (ibex, sock) = start(
        "show_info_cum_streams",
        &http_cfg("  nbthread 4\n", &format!("frontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain string 0123456789\n")),
        &[a],
    );

    let a_info = info(&sock);
    let a_cum = num(&a_info, "CumStreams");

    // 10 requests on 10 separate connections
    for _ in 0..10 {
        get(a, GET);
    }

    // 5 requests on one keep-alive connection
    let mut ka = TcpStream::connect_timeout(&a, Duration::from_secs(2)).expect("ka connect");
    ka.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    for _ in 0..5 {
        ka.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        let mut buf = Vec::new();
        loop {
            let mut tmp = [0u8; 4096];
            match ka.read(&mut tmp) {
                Ok(0) => break, // connection closed
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(_) => break,
            }
            if buf.len() >= 10 {
                break;
            }
        }
    }
    drop(ka);

    // The expected CumStreams after A: 15 (10 single + 5 keep-alive) + number of show info reads since A
    // (each show info connection itself counts as a stream). Poll up to 2s for the streams to be counted.
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut last_info = a_info.clone();
    let mut last_cum = a_cum;
    let mut extra_reads = 0u64;
    loop {
        extra_reads += 1;
        last_info = info(&sock);
        last_cum = num(&last_info, "CumStreams");
        let expected = a_cum + 15 + extra_reads;
        if last_cum >= expected {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let expected = a_cum + 15 + extra_reads;
    assert_eq!(last_cum, expected, "CumStreams was {last_cum}, expected {expected} (a_cum={a_cum}, extra_reads={extra_reads})");
    drop(ibex);
}
