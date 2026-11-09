// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T330: ip.src/dst/hdr/data

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Alcyon(Child, std::path::PathBuf);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Starts alcyon on `cfg` (`{sock}` is replaced by the stats socket path), waits for `addrs` and the
/// socket, then lets the readiness probes slide out of the one-second windows and clears the maxima.
fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> (Alcyon, String) {
    let dir = std::env::temp_dir().join(format!("qh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg.replace("{sock}", &sock).replace("{dir}", &dir.display().to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let alcyon = Alcyon(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "alcyon did not listen on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(2200));
    cli(&sock, "clear counters");
    (alcyon, sock)
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
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

/// The body of the answer to `req` (what follows the first empty line).
fn body(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    s.split_once("\r\n\r\n").map_or_else(|| panic!("no answer: {s:?}"), |(_, b)| b.to_string())
}

const CFG: &str = r#"
frontend fe
  bind {A}
  http-request return status 200 content-type text/plain lf-string "%[bin(4510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.src]|%[bin(4510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.dst]|%[bin(4510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.hdr,hex]|%[bin(4510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.data,hex]|%[bin(600000000028064020010db800000000000000000000000120010db80000000000000000000000029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.src]|%[bin(600000000028064020010db800000000000000000000000120010db80000000000000000000000029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.dst]|%[bin(600000000028064020010db800000000000000000000000120010db80000000000000000000000029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.hdr,hex]|%[bin(600000000028064020010db800000000000000000000000120010db80000000000000000000000029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.data,hex]"
"#;

#[test]
fn ip_converters_extract_ipv4_and_ipv6_fields() {
    let addr = common::reserve_addr();
    let cfg = http_cfg("", &CFG.replace("{A}", &addr.to_string()));
    let (_alcyon, _sock) = start("ip-converters", &cfg, &[addr]);

    // Expected output for IPv4 packet:
    // ip.src: 192.0.2.1
    // ip.dst: 198.51.100.2
    // ip.hdr (hex): 4510003C1C46400040060000C0000201C6336402
    // ip.data (hex): 9C4001BB0102030400000000A002FAF000000000020405B40402080A112233440000000001030307
    // Expected output for IPv6 packet:
    // ip.src: 2001:db8::1
    // ip.dst: 2001:db8::2
    // ip.hdr (hex): 600000000028064020010DB800000000000000000000000120010DB8000000000000000000000002
    // ip.data (hex): 9C4001BB0102030400000000A002FAF000000000020405B40402080A112233440000000001030307

    let expected = "192.0.2.1|198.51.100.2|4510003C1C46400040060000C0000201C6336402|9C4001BB0102030400000000A002FAF000000000020405B40402080A112233440000000001030307|2001:db8::1|2001:db8::2|600000000028064020010DB800000000000000000000000120010DB8000000000000000000000002|9C4001BB0102030400000000A002FAF000000000020405B40402080A112233440000000001030307";
    assert_eq!(body(addr, GET), expected);
}

/// T330 review B1-B3: a bare 20-byte v4 or 40-byte v6 header is enough for `ip.dst` (also on the
/// output of `ip.hdr`) and gives an empty `ip.data`; an IHL below 5 still splits the packet, and an
/// IHL of 0 gives no sample. Expected values from `HAProxy` 3.5-dev8.
#[test]
fn ip_converters_bare_headers_and_short_ihl() {
    const V4: &str = "4510003c1c46400040060000c0000201c6336402";
    const V6: &str = "600000000014064020010db800000000000000000000000120010db8000000000000000000000002";
    let line = |k: &str, h: &str| {
        format!("{k}=[%[bin({h}),ip.src]|%[bin({h}),ip.dst]|%[bin({h}),ip.hdr,ip.dst]|%[bin({h}),ip.data,length]]")
    };
    let lf = format!(
        "{}\\n{}\\nI1=[%[bin(41000000aabb),ip.hdr,hex]|%[bin(41000000aabb),ip.data,hex]]\\nI0=[%[bin(40000000aabb),ip.hdr,hex]|%[bin(40000000aabb),ip.data,hex]]",
        line("V4", V4),
        line("V6", V6)
    );
    let addr = common::reserve_addr();
    let fe = format!("frontend fe\n  bind {addr}\n  http-request return status 200 content-type text/plain lf-string \"{lf}\"\n");
    let (_alcyon, _sock) = start("ip-bare", &http_cfg("", &fe), &[addr]);
    assert_eq!(
        body(addr, GET),
        "V4=[192.0.2.1|198.51.100.2|198.51.100.2|0]\n\
         V6=[2001:db8::1|2001:db8::2|2001:db8::2|0]\n\
         I1=[41000000|AABB]\n\
         I0=[|]"
    );
}
