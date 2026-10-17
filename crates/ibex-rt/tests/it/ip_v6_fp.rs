// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T330: the `ip.fp` converter on IPv4 and IPv6 input. Every expected row was measured on the
//! reference (3.5-dev8) with the same lf-string.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Ibex(Child, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

#[test]
fn ip_fp_converter() {
    // (input hex, ip.fp arguments, expected `ip.fp...,hex`)
    let rows: [(&str, &str, &str); 29] = [
        // IPv4 SYN with MSS, SACK-permitted, timestamps, NOP, wscale 7; every mode bit
        ("4510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307", "", "1050A8FAF005B447"),
        ("4510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307", "(1)", "1050A8FAF005B44740"),
        ("4510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307", "(2)", "1050A8FAF005B4470204080103"),
        ("4510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307", "(4)", "1050A8FAF005B447C0000201"),
        ("4510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307", "(7)", "1050A8FAF005B447400204080103C0000201"),
        // the same SYN over IPv6
        ("600000000028064020010db800000000000000000000000120010db80000000000000000000000029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307", "", "00D0A8FAF005B447"),
        ("600000000028064020010db800000000000000000000000120010db80000000000000000000000029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307", "(1)", "00D0A8FAF005B44740"),
        ("600000000028064020010db800000000000000000000000120010db80000000000000000000000029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307", "(2)", "00D0A8FAF005B4470204080103"),
        ("600000000028064020010db800000000000000000000000120010db80000000000000000000000029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307", "(4)", "00D0A8FAF005B44720010DB8000000000000000000000001"),
        ("600000000028064020010db800000000000000000000000120010db80000000000000000000000029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307", "(7)", "00D0A8FAF005B44740020408010320010DB8000000000000000000000001"),
        // 20 bytes of 0x45 (as from a request header), a bare IPv4 header, a bare IPv6 header: no sample, no panic
        ("4545454545454545454545454545454545454545", "", ""),
        ("4500002c00004000400600000a0000010a000002", "", ""),
        ("600000000014064020010db800000000000000000000000120010db8000000000000000000000002", "", ""),
        // wscale 0, 15, 255 and 14: the nibble is wscale+1, capped at 15
        ("4510002c1c46400040060000c0000201c63364029c4001bb01020304000000006002faf00000000003030001", "(2)", "105061FAF00000020301"),
        ("4510002c1c46400040060000c0000201c63364029c4001bb01020304000000006002faf00000000003030f01", "(2)", "10506FFAF00000020301"),
        ("4510002c1c46400040060000c0000201c63364029c4001bb01020304000000006002faf0000000000303ff01", "(2)", "10506FFAF00000020301"),
        ("4510002c1c46400040060000c0000201c63364029c4001bb01020304000000006002faf00000000003030e01", "(2)", "10506FFAF00000020301"),
        // IPv4 total length (32) shorter than its headers: no sample
        ("451000201c46400040060000c0000201c63364029c4001bb01020304000000006002faf00000000003030701", "(2)", ""),
        // IPv6 next header UDP (17) is fingerprinted; a hop-by-hop extension header is walked and sets IP.ext
        ("600000000018114020010db800000000000000000000000120010db80000000000000000000000029c4001bb01020304000000006002faf00000000003030701", "(2)", "00D068FAF00000020301"),
        ("600000000020004020010db800000000000000000000000120010db800000000000000000000000206000000000000009c4001bb01020304000000006002faf00000000003030701", "(2)", "00D868FAF00000020301"),
        // IPv4 with 4 bytes of data after the TCP header: the data-present bit
        ("451000301c46400040060000c0000201c63364029c4001bb01020304000000006002faf00000000003030701aabbccdd", "(2)", "105468FAF00000020301"),
        // IPv6 extension header cut short: no sample
        ("600000000008004020010db800000000000000000000000120010db800000000000000000000000206", "", ""),
        // mode -1 sets every bit
        ("4510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307", "(-1)", "1050A8FAF005B447400204080103C0000201"),
        // IPv4 header with options (ihl 6): IP.ext
        ("461000301c46400040060000c0000201c6336402010101019c4001bb01020304000000006002faf00000000003030701", "(2)", "105868FAF00000020301"),
        // TCP header shorter than its data offset; MSS of length 4; MSS of length 3 read anyway
        ("4510002c1c46400040060000c0000201c63364029c4001bb01020304000000006002faf0000000000204", "(2)", ""),
        ("4510002c1c46400040060000c0000201c63364029c4001bb01020304000000006002faf00000000002040102", "(2)", "105060FAF001020102"),
        ("4510002c1c46400040060000c0000201c63364029c4001bb01020304000000006002faf00000000002030102", "(2)", "105060FAF001020102"),
        // IPv4 ihl 1 and IP version 7: no sample
        ("4110002c1c46400040060000c0000201c63364029c4001bb01020304000000006002faf00000000003030701", "", ""),
        ("70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "", ""),
    ];
    let lf = rows.iter().map(|(hex, m, _)| format!("%[bin({hex}),ip.fp{m},hex]")).collect::<Vec<_>>().join(";");

    let a = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("ibex-ip-fp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    let cfg = format!(
        "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"{lf}\"\n"
    );
    std::fs::write(&path, cfg).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _ibex = Ibex(child, dir);
    assert!(common::wait_listening(a), "ibex did not listen on {a}");

    let mut s = TcpStream::connect_timeout(&a, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let out = String::from_utf8_lossy(&out).into_owned();
    let body = out.split_once("\r\n\r\n").map_or_else(|| panic!("no answer (ibex crashed?): {out:?}"), |(_, b)| b.to_string());

    let got: Vec<&str> = body.split(';').collect();
    assert_eq!(got.len(), rows.len(), "body: {body:?}");
    let bad: Vec<String> = rows
        .iter()
        .zip(got)
        .filter(|((_, _, want), got)| got != want)
        .map(|((hex, m, want), got)| format!("{hex} ip.fp{m}: got {got:?}, want {want:?}"))
        .collect();
    assert!(bad.is_empty(), "rows differing from the reference:\n{}", bad.join("\n"));
}
