// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `bind ... tcp-ss <mode>` and `%[fc_saved_syn]` (spec: `doc/configuration.txt`,
//! "tcp-ss <mode>" and "fc_saved_syn"; `src/cfgparse-tcp.c` `bind_parse_tcp_ss`,
//! `src/tcp_sample.c` `smp_fetch_fc_saved_syn`): the bind asks the kernel to keep the
//! first SYN packet of every connection it accepts (mode 1: IP and TCP headers, mode 2:
//! also the Ethernet one), and the fetch returns the saved packet as a binary sample.
//!
//! Every expected value was measured on the 3.5-dev11 oracle
//! (`/var/tmp/qwen-next-eval/oracle/haproxy`), over IPv4 loopback:
//! - `tcp-ss 1`: 120 hex characters (60 bytes: 20 IP + 40 TCP, the kernel's SYN options),
//!   first byte `0x45` (IPv4, IHL 5), IP protocol byte 9 = `0x06` (TCP);
//! - `tcp-ss 2`: 148 hex characters (74 bytes: 14 ETH + the 60 of mode 1), EtherType bytes
//!   12-13 = `0x0800`, then the same `0x45` / `0x06` at 14 / 23;
//! - a bind without `tcp-ss`: the sample has no value, and `http-request return hdr`
//!   with an empty value sends no header at all (the oracle sends no `x-syn` header).
//!
//! The SYN carries the client's TCP options, so the absolute length is a property of the
//! kernel; within one run mode 2 is exactly the 14-byte Ethernet header more than mode 1
//! (both measured: 120 and 148).
//!
//! The variable parts (ports, sequence, TCP options) differ between connections, so the
//! fixed parts only are compared. Set `T281_ORACLE=/path/to/haproxy` to run this test
//! against `HAProxy`: it passes.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

/// The binary under test: alcyon, or the oracle when `T281_ORACLE` is set.
fn bin() -> String {
    std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

/// `127.0.0.1:port`, the address the frontend binds and the test connects to.
fn addr(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, port))
}

/// The `X-Syn` header value of the answer, case-insensitive on the name; `None` when the
/// answer carries no such header.
fn syn_header(s: &str) -> Option<String> {
    s.split("\r\n")
        .filter_map(|h| h.strip_prefix("X-Syn:").or_else(|| h.strip_prefix("x-syn:")))
        .next()
        .map(|v| v.trim().to_string())
}

/// One request to `fe`; the frontend's `http-request return` answers it.
fn request(fe: u16) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", fe)).expect("connect the frontend");
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = Vec::new();
    s.read_to_end(&mut out).expect("read");
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_byte(h: &str, n: usize) -> u8 {
    u8::from_str_radix(&h[2 * n..2 * n + 2], 16).unwrap_or_else(|e| panic!("bad hex in {h:?} at byte {n}: {e}"))
}

#[test]
fn saved_syn_per_mode() {
    let fe1 = common::reserve_port();
    let fe2 = common::reserve_port();
    let fe3 = common::reserve_port();
    let dir = std::env::temp_dir();
    let id = format!("alcyon_saved_syn_{}_{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
    let cfg = dir.join(format!("{id}.cfg"));
    std::fs::write(
        &cfg,
        format!(
            "global\n  maxconn 100\n\
             defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
             frontend f1\n  bind 127.0.0.1:{fe1} tcp-ss 1\n  http-request return status 200 hdr X-Syn \"%[fc_saved_syn,hex]\"\n\
             frontend f2\n  bind 127.0.0.1:{fe2} tcp-ss 2\n  http-request return status 200 hdr X-Syn \"%[fc_saved_syn,hex]\"\n\
             frontend f3\n  bind 127.0.0.1:{fe3}\n  tcp-request content reject if {{ fc_saved_syn,hex str(zqx) }}\n  http-request return status 200 hdr X-Syn \"%[fc_saved_syn,hex]\"\n",
        ),
    )
    .expect("write config");
    let mut child = Command::new(bin())
        .args(["-d", "-db", "-f"])
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proxy");
    let mut stderr = child.stderr.take();
    // One wait, on the first frontend: the three binds happen at startup, so a process
    // accepting on fe1 has bound them all. Waiting on three addresses serially would
    // triple the chance of a slow start on a loaded host reading as a config failure.
    assert!(common::wait_listening(addr(fe1)), "the proxy never listened on fe1");
    let alive = child.try_wait().expect("wait");
    // Only drain the pipe once the process is gone: alive, it would block on the open end.
    let stderr = alive.is_some()
        .then(|| {
            let mut b = String::new();
            if let Some(mut s) = stderr.take() {
                let _ = s.read_to_string(&mut b);
            }
            b
        })
        .unwrap_or_default();
    assert!(alive.is_none(), "the proxy died on the config (tcp-ss must parse):\n{stderr}");
    // tcp-ss 1: 60 bytes (20 IP + 40 TCP: the kernel's SYN options), IPv4, protocol TCP.
    let ans = request(fe1);
    let syn1 = syn_header(&ans).unwrap_or_else(|| panic!("tcp-ss 1: no X-Syn header in:\n{ans}"));
    assert_eq!(syn1.len(), 120, "tcp-ss 1: 60 bytes expected, got {} bytes of hex: {syn1:?}", syn1.len() / 2);
    assert_eq!(hex_byte(&syn1, 0), 0x45, "tcp-ss 1: the IP version/IHL byte (45 = IPv4, 20-byte header)");
    assert_eq!(hex_byte(&syn1, 9), 0x06, "tcp-ss 1: the IP protocol byte (6 = TCP)");

    // tcp-ss 2: mode 1 plus the 14-byte Ethernet header, EtherType IPv4, then the same.
    let ans = request(fe2);
    let syn2 = syn_header(&ans).unwrap_or_else(|| panic!("tcp-ss 2: no X-Syn header in:\n{ans}"));
    assert_eq!(
        syn2.len(),
        syn1.len() + 28,
        "tcp-ss 2: the 14-byte Ethernet header more than tcp-ss 1, got {} vs {} hex",
        syn2.len() / 2,
        syn1.len() / 2
    );
    assert_eq!(hex_byte(&syn2, 12), 0x08, "tcp-ss 2: the EtherType high byte (0x0800 = IPv4)");
    assert_eq!(hex_byte(&syn2, 13), 0x00, "tcp-ss 2: the EtherType low byte (0x0800 = IPv4)");
    assert_eq!(hex_byte(&syn2, 14), 0x45, "tcp-ss 2: the IP version/IHL byte (45 = IPv4, 20-byte header)");
    assert_eq!(hex_byte(&syn2, 23), 0x06, "tcp-ss 2: the IP protocol byte (6 = TCP)");

    // Without tcp-ss the kernel saves nothing: no sample, and `return hdr` with an empty
    // value sends no header at all (measured on the oracle).
    let ans = request(fe3);
    assert!(syn_header(&ans).is_none(), "no tcp-ss: the X-Syn header must be absent:\n{ans}");

    common::stop(&mut child);
    let _ = std::fs::remove_file(&cfg);
}
