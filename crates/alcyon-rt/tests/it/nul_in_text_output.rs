// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A NUL inside what a log-format writes as text (T146 item 11).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-04 (UDP log socket, raw client):
//! a binary sample written as text is cast with `c_bin2str`, which stops at the first NUL,
//! in a log line (`bin(610062)` is `a`) as in a `return` body; what is left empty after the
//! cut is `-` in a log line and nothing in a body. `hex` and `base64` take the bytes as
//! they are. `url_dec` refuses `%00` ("cannot be represented in a string"): the fetch fails,
//! `-` in a log line, nothing in a body. Not done here: a variable holds the type it was
//! given in HAProxy (`var(txn.v),length` is 1 for `bin(610062)`), Alcyon's hold text.

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

#[test]
fn a_binary_written_as_text_stops_at_the_first_nul() {
    let fe = common::reserve_addr();
    let logs = UdpSocket::bind("127.0.0.1:0").expect("log socket");
    logs.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let cfg = format!(
        "global\n  log {} local0\ndefaults\n  mode http\n  log global\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  \
         log-format \"A[%[bin(610062)]] B[%[bin(610062),hex]] G[x%[bin(00)]y] H[%[bin(610062),base64]] U[%[str(a%00b),url_dec]] V[%[str(a%41),url_dec]]\"\n  \
         http-request return status 200 content-type text/plain lf-string \"R[%[bin(610062)]] S[%[str(YQBi),b64dec]] E[%[bin(00)]] U[%[str(a%00b),url_dec]] V[%[str(a%41),url_dec]]\\n\"\n",
        logs.local_addr().expect("addr")
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Alcyon)
        .expect("spawn alcyon");
    assert!(common::wait_listening(fe), "alcyon never listened");
    // The probe connection of `wait_listening` leaves a log line: drop what is there.
    logs.set_nonblocking(true).ok();
    let mut buf = [0u8; 2048];
    while logs.recv(&mut buf).is_ok() {}
    logs.set_nonblocking(false).ok();

    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).ok();
    c.write_all(b"GET /x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n").expect("send");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    let body = got.windows(4).position(|w| w == b"\r\n\r\n").map_or(&got[..0], |p| &got[p + 4..]);
    assert_eq!(body, b"R[a] S[a] E[] U[] V[aA]\n", "body: {:?}", String::from_utf8_lossy(&got));

    let n = logs.recv(&mut buf).expect("a log line");
    let line = &buf[..n];
    let at = line.windows(2).position(|w| w == b"A[").expect("the format's start");
    // (HAProxy ends the datagram with a newline, Alcyon does not: not this item's business.)
    assert_eq!(line[at..].trim_ascii_end(), &b"A[a] B[610062] G[x-y] H[YQBi] U[-] V[aA]"[..], "log: {:?}", String::from_utf8_lossy(line));
    common::stop(&mut child);
}
