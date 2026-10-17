// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T330: eth.* converters

use crate::common;

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
  http-request return status 200 content-type text/plain lf-string "%[bin(02000000000102000000000208004510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),eth.data,hex]|%[bin(02000000000102000000000208004510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),eth.dst,hex]|%[bin(02000000000102000000000208004510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),eth.hdr,hex]|%[bin(02000000000102000000000208004510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),eth.proto]|%[bin(02000000000102000000000208004510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),eth.src,hex]|%[bin(02000000000102000000000208004510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),eth.vlan]|%[bin(0200000000010200000000028100002a08004510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),eth.data,hex]|%[bin(0200000000010200000000028100002a08004510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),eth.dst,hex]|%[bin(0200000000010200000000028100002a08004510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),eth.hdr,hex]|%[bin(0200000000010200000000028100002a08004510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),eth.proto]|%[bin(0200000000010200000000028100002a08004510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),eth.src,hex]|%[bin(0200000000010200000000028100002a08004510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),eth.vlan]"
"#;

#[test]
fn eth_converters_table() {
    // Frame without VLAN: 02:00:00:00:00:01 (dst) 02:00:00:00:00:02 (src) 0x0800 (EtherType)
    // Frame with VLAN:    02:00:00:00:00:01 (dst) 02:00:00:00:00:02 (src) 0x8100 (VLAN) 0x002A (TCI, VLAN ID=42) 0x0800 (EtherType)
    let a = common::reserve_addr();
    let cfg = http_cfg("", &CFG.replace("{A}", &a.to_string()));
    let (_ibex, _sock) = start("eth", &cfg, &[a]);
    // First 6 values: without VLAN
    // eth.data: IP header after eth header (12 bytes = 6 dst + 6 src)
    assert_eq!(
        body(a, GET),
        "4510003C1C46400040060000C0000201C63364029C4001BB0102030400000000A002FAF000000000020405B40402080A112233440000000001030307\
         |020000000001\
         |0200000000010200000000020800\
         |2048\
         |020000000002\
         |\
         |4510003C1C46400040060000C0000201C63364029C4001BB0102030400000000A002FAF000000000020405B40402080A112233440000000001030307\
         |020000000001\
         |0200000000010200000000028100002A0800\
         |2048\
         |020000000002\
         |42"
    );
}

/// One line per frame, `K=[data|hdr|proto|vlan|src|dst]`, each converter applied to `bin(<frame>)`.
fn eth_lf(frames: &[(&str, &str)]) -> String {
    frames
        .iter()
        .map(|(k, f)| {
            format!(
                "{k}=[%[bin({f}),eth.data,hex]|%[bin({f}),eth.hdr,hex]|%[bin({f}),eth.proto]|%[bin({f}),eth.vlan]|%[bin({f}),eth.src,hex]|%[bin({f}),eth.dst,hex]]"
            )
        })
        .collect::<Vec<_>>()
        .join("\\n")
}

fn eth_body(tag: &str, frames: &[(&str, &str)]) -> String {
    let a = common::reserve_addr();
    let fe = format!(
        "frontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"{}\"\n",
        eth_lf(frames)
    );
    let (_ibex, _sock) = start(tag, &http_cfg("", &fe), &[a]);
    body(a, GET)
}

/// T330 review A1/A3: frames too short for an `EtherType` give no sample (and must not panic);
/// the 12- and 13-byte frames used to abort the process. Expected values from `HAProxy` 3.5-dev8.
#[test]
fn eth_converters_short_frames() {
    let got = eth_body(
        "eth-short",
        &[
            ("F5", "0200000000"),
            ("F11", "0200000000010200000000"),
            ("F12", "020000000001020000000002"),
            ("F13", "02000000000102000000000208"),
            ("F14", "0200000000010200000000020800"),
            ("F16", "0200000000010200000000028100002a"),
            ("F18", "0200000000010200000000028100002a0800"),
        ],
    );
    assert_eq!(
        got,
        "F5=[|||||]\n\
         F11=[|||||020000000001]\n\
         F12=[||||020000000002|020000000001]\n\
         F13=[||||020000000002|020000000001]\n\
         F14=[||||020000000002|020000000001]\n\
         F16=[||||020000000002|020000000001]\n\
         F18=[||||020000000002|020000000001]"
    );
}

/// T330 review A2/A3: every 802.1Q tag is skipped (`QinQ`), `eth.vlan` is the last id and id 0 is no
/// VLAN, and one byte past the `EtherType` is enough. Expected values from `HAProxy` 3.5-dev8.
#[test]
fn eth_converters_vlan_walk() {
    let got = eth_body(
        "eth-vlan",
        &[
            ("F15", "020000000001020000000002080045"),
            ("FQ", "0200000000010200000000028100000a8100002b08004500"),
            ("F0", "0200000000010200000000028100000008004500"),
        ],
    );
    assert_eq!(
        got,
        "F15=[45|0200000000010200000000020800|2048||020000000002|020000000001]\n\
         FQ=[4500|0200000000010200000000028100000A8100002B0800|2048|43|020000000002|020000000001]\n\
         F0=[4500|020000000001020000000002810000000800|2048||020000000002|020000000001]"
    );
}
