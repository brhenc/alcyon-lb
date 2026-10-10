// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Every `strftime` specifier of the `utime` converter, against HAProxy (T149b).
//!
//! `HAProxy` formats with the C library's `strftime`. Measured on 3.5-dev8-885761-29 with
//! `http-request return ... lf-string "%[int(<epoch>),utime(%<spec>)]"` for three instants
//! (UTC): 1700000000 (Tue 2023-11-14 22:13:20), 1709999999 (Sat 2024-03-09 15:59:59, a
//! single-digit day and month) and 1735689600 (Wed 2025-01-01 00:00:00, midnight, ISO week 1).
//! `%e %j %p %I` and the rest printed literally in Ibex before.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

const EPOCHS: [i64; 3] = [1_700_000_000, 1_709_999_999, 1_735_689_600];

/// `(specifier, [output at EPOCHS[0], EPOCHS[1], EPOCHS[2]])`, as HAProxy printed them.
const EXPECTED: &[(char, [&str; 3])] = &[
    ('a', ["Tue", "Sat", "Wed"]),
    ('A', ["Tuesday", "Saturday", "Wednesday"]),
    ('b', ["Nov", "Mar", "Jan"]),
    ('B', ["November", "March", "January"]),
    ('c', ["Tue Nov 14 22:13:20 2023", "Sat Mar  9 15:59:59 2024", "Wed Jan  1 00:00:00 2025"]),
    ('C', ["20", "20", "20"]),
    ('d', ["14", "09", "01"]),
    ('D', ["11/14/23", "03/09/24", "01/01/25"]),
    ('e', ["14", " 9", " 1"]),
    ('F', ["2023-11-14", "2024-03-09", "2025-01-01"]),
    ('g', ["23", "24", "25"]),
    ('G', ["2023", "2024", "2025"]),
    ('h', ["Nov", "Mar", "Jan"]),
    ('H', ["22", "15", "00"]),
    ('I', ["10", "03", "12"]),
    ('j', ["318", "069", "001"]),
    ('k', ["22", "15", " 0"]),
    ('l', ["10", " 3", "12"]),
    ('m', ["11", "03", "01"]),
    ('M', ["13", "59", "00"]),
    ('n', ["\n", "\n", "\n"]),
    ('p', ["PM", "PM", "AM"]),
    ('P', ["pm", "pm", "am"]),
    ('r', ["10:13:20 PM", "03:59:59 PM", "12:00:00 AM"]),
    ('R', ["22:13", "15:59", "00:00"]),
    ('s', ["1700000000", "1709999999", "1735689600"]),
    ('S', ["20", "59", "00"]),
    ('t', ["\t", "\t", "\t"]),
    ('T', ["22:13:20", "15:59:59", "00:00:00"]),
    ('u', ["2", "6", "3"]),
    ('U', ["46", "09", "00"]),
    ('V', ["46", "10", "01"]),
    ('w', ["2", "6", "3"]),
    ('W', ["46", "10", "00"]),
    ('x', ["11/14/23", "03/09/24", "01/01/25"]),
    ('X', ["22:13:20", "15:59:59", "00:00:00"]),
    ('y', ["23", "24", "25"]),
    ('Y', ["2023", "2024", "2025"]),
    ('z', ["+0000", "+0000", "+0000"]),
    ('Z', ["GMT", "GMT", "GMT"]),
];

#[test]
fn every_specifier_prints_what_haproxy_prints() {
    let fe = common::reserve_addr();
    let mut cfg = format!("global\n  nbthread 1\ndefaults\n  mode http\n  timeout client 5s\n  timeout connect 1s\n  timeout server 5s\nfrontend f\n  bind {fe}\n");
    for (spec, _) in EXPECTED {
        for (i, epoch) in EPOCHS.iter().enumerate() {
            cfg.push_str(&format!(
                "  http-request return status 200 content-type text/plain lf-string \"%[int({epoch}),utime(%{spec})]\" if {{ path /{i}{spec} }}\n"
            ));
        }
    }
    cfg.push_str("  http-request return status 404\n");
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Ibex).expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened");
    let mut wrong = Vec::new();
    for (spec, want) in EXPECTED {
        for (i, w) in want.iter().enumerate() {
            let mut c = TcpStream::connect(fe).expect("connect");
            c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
            c.write_all(format!("GET /{i}{spec} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes()).expect("send");
            let mut got = Vec::new();
            let _ = c.read_to_end(&mut got);
            let text = String::from_utf8_lossy(&got).into_owned();
            let body = text.split_once("\r\n\r\n").map_or("", |(_, b)| b);
            if body != *w {
                wrong.push(format!("%{spec} at {}: want {w:?}, got {body:?}", EPOCHS[i]));
            }
        }
    }
    common::stop(&mut child);
    assert!(wrong.is_empty(), "{} differences:\n{}", wrong.len(), wrong.join("\n"));
}
