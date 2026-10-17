// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T330: the `tcp.options.*` and `tcp.options_list` converters. Every expected row was measured on
//! the reference (3.5-dev8) with the same lf-string.

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

/// A TCP header prefix (ports, seq, ack); each row appends data offset, flags, window,
/// checksum, urgent pointer and options.
const H: &str = "9c4001bb0102030400000000";

const CONVS: [&str; 7] = [
    "tcp.options.mss",
    "tcp.options.sack",
    "tcp.options.tsopt",
    "tcp.options.tsval",
    "tcp.options.wscale",
    "tcp.options.wsopt",
    "tcp.options_list,hex",
];

#[test]
fn tcp_options_converters() {
    // input hex -> mss|sack|tsopt|tsval|wscale|wsopt|options_list,hex
    let rows: [(String, &str); 12] = [
        // a full SYN: MSS, SACK-permitted, timestamps, NOP, wscale
        (format!("{H}a002faf000000000020405b40402080a112233440000000001030307"), "1460|1|1|287454020|7|1|0204080103"),
        // no options
        (format!("{H}5002faf000000000"), "0|0|0|0|0|0|"),
        // incomplete header: no sample at all
        ("0102".to_string(), "||||||"),
        // data offset 24 past the 20 bytes given: no sample
        (format!("{H}6002faf000000000"), "||||||"),
        // wscale with no length byte: its kind is still listed
        (format!("{H}6002faf00000000001010103"), "0|0|0|0|0|0|01010103"),
        // MSS whose length (8) runs past the header
        (format!("{H}6002faf0000000000208a5b4"), "0|0|0|0|0|0|02"),
        // MSS with length 1
        (format!("{H}6002faf0000000000201ffff"), "0|0|0|0|0|0|02"),
        // MSS overrunning the header by one byte
        (format!("{H}6002faf00000000001010204"), "0|0|0|0|0|0|010102"),
        // MSS with length 2: the value is read from the two bytes after it anyway
        (format!("{H}6002faf00000000002020101"), "257|0|0|0|0|0|020101"),
        // TS with length 4: TSval is read from the four bytes after kind and length
        (format!("{H}6002faf0000000000804aabbccdd"), "0|0|1|2864434397|0|0|08"),
        // NOP, then an option whose length (255) runs past the header
        (format!("{H}6002faf0000000000102ff00"), "0|0|0|0|0|0|0102"),
        // wscale 0 is present, and its shift count is 0
        (format!("{H}6002faf00000000001030300"), "0|0|0|0|0|1|0103"),
    ];
    let lf = rows
        .iter()
        .map(|(hex, _)| CONVS.iter().map(|c| format!("%[bin({hex}),{c}]")).collect::<Vec<_>>().join("|"))
        .collect::<Vec<_>>()
        .join(";");

    let a = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("ibex-tcp-options-{}", std::process::id()));
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
    let body = out.split_once("\r\n\r\n").map_or_else(|| panic!("no answer: {out:?}"), |(_, b)| b.to_string());

    let got: Vec<&str> = body.split(';').collect();
    assert_eq!(got.len(), rows.len(), "body: {body:?}");
    let bad: Vec<String> =
        rows.iter().zip(got).filter(|((_, want), got)| got != want).map(|((hex, want), got)| format!("{hex}: got {got:?}, want {want:?}")).collect();
    assert!(bad.is_empty(), "rows differing from HAProxy:\n{}", bad.join("\n"));
}
