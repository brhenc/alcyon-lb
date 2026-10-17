// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T363a: a binary sample stored in a variable keeps its bytes, so `secure_memcmp` against it
//! matches as `HAProxy`'s reg-test `converter/secure_memcmp.vtc` (frontend `fe2`) expects.
//!
//! `set-var` stored a `bin` sample with `String::from_utf8_lossy`, so every byte from 0x80 up
//! became U+FFFD, and `secure_memcmp` compared the UTF-8 of the stored text: a `b64dec` hash never
//! matched its `sha1`. The pairs below are the reg-test's (`sha1` of `Raw`, base64 in `Hash`).

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

fn ask(addr: std::net::SocketAddr, raw: &str, hash: &str) -> String {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    s.write_all(format!("GET / HTTP/1.1\r\nHost: a\r\nRaw: {raw}\r\nHash: {hash}\r\nConnection: close\r\n\r\n").as_bytes()).expect("send");
    let mut d = Vec::new();
    let _ = s.read_to_end(&mut d);
    let d = String::from_utf8_lossy(&d).into_owned();
    d.split_once("\r\n\r\n").map_or(d.clone(), |(_, b)| b.to_string())
}

#[test]
fn secure_memcmp_matches_a_binary_variable_byte_for_byte() {
    let addr = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 2s\n  timeout server 2s\n  timeout connect 2s\n\
         frontend fe2\n  bind {addr}\n\
         \x20 http-request set-var(txn.hash) req.hdr(hash),b64dec\n\
         \x20 http-request set-var(txn.raw) req.hdr(raw)\n\
         \x20 acl is_match var(txn.raw),sha1,secure_memcmp(txn.hash)\n\
         \x20 http-request return status 200 content-type text/plain string true if is_match\n\
         \x20 http-request return status 200 content-type text/plain string false\n"
    );
    let path = std::env::temp_dir().join(format!("ibex-t363a-{}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write cfg");
    let mut ibex = common::Ibex(
        Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-db").arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex"),
    );
    assert!(common::wait_listening(addr), "ibex did not listen");
    // (Raw, Hash, HAProxy's answer), from reg-tests/converter/secure_memcmp.vtc client c2.
    let rows = [
        ("1", "NWoZK3kTsExUV00Ywo1G5jlUKKs=", "true"),
        ("2", "2kuSN7rMzfGcB2DKt67EqDWQELA=", "true"),
        ("2", "2kuSN7rMzfGcB2DKt67EqDWQELX=", "false"),
        ("3", "2kuSN7rMzfGcB2DKt67EqDWQELA=", "false"),
        ("6132845", "AAAAVaeL9nNcSok1j6sd40EEw8s=", "true"),
    ];
    let got: Vec<String> = rows.iter().map(|(r, h, _)| ask(addr, r, h)).collect();
    common::stop(&mut ibex);
    let _ = std::fs::remove_file(&path);
    let want: Vec<&str> = rows.iter().map(|r| r.2).collect();
    assert_eq!(got, want);
}

#[test]
fn a_binary_variable_goes_out_in_a_header_as_its_bytes() {
    // HAProxy 3.5-dev8 sends `x-v: A\x80\xffB` for this config (measured, od -c).
    let addr = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 2s\n  timeout server 2s\n  timeout connect 2s\n\
         frontend f\n  bind {addr}\n\
         \x20 http-request set-var(txn.b2) str(QYD/Qg==),b64dec\n\
         \x20 http-request return status 200 content-type text/plain hdr x-v \"%[var(txn.b2)]\"\n"
    );
    let path = std::env::temp_dir().join(format!("ibex-t363a-hdr-{}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write cfg");
    let mut ibex = common::Ibex(
        Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-db").arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex"),
    );
    assert!(common::wait_listening(addr), "ibex did not listen");
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").expect("send");
    let mut d = Vec::new();
    let _ = s.read_to_end(&mut d);
    common::stop(&mut ibex);
    let _ = std::fs::remove_file(&path);
    assert!(d.windows(9).any(|w| w == b"x-v: A\x80\xffB"), "{:?}", String::from_utf8_lossy(&d));
}
