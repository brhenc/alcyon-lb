// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Several `cookie` fields of an HTTP/2 request reach an HTTP/1 server as one `cookie: a; b`
//! line placed after the other fields, and rules see one header (RFC 9113 section 8.2.3;
//! T506; measured on `HAProxy` 3.5-dev8).

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("short");
    let mut v = Vec::new();
    v.extend_from_slice(&len.to_be_bytes()[1..]);
    v.push(ftype);
    v.push(flags);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn lit(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00, u8::try_from(name.len()).unwrap()];
    v.extend_from_slice(name);
    v.push(u8::try_from(value.len()).unwrap());
    v.extend_from_slice(value);
    v
}

fn request(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut v = vec![0x82, 0x86, 0x04, 0x02];
    v.extend_from_slice(b"/p");
    v.extend_from_slice(&[0x01, 9]);
    v.extend_from_slice(b"localhost");
    for (n, val) in fields {
        v.extend_from_slice(&lit(n, val));
    }
    v
}

fn exchange(rules: &str, f: &[(&[u8], &[u8])]) -> String {
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let be = l.local_addr().unwrap();
    let sink = Arc::clone(&seen);
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let sink = Arc::clone(&sink);
            thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
                let mut got = Vec::new();
                let mut b = [0u8; 4096];
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b) {
                        Ok(n) if n > 0 => got.extend_from_slice(&b[..n]),
                        _ => return,
                    }
                }
                sink.lock().unwrap().push(got);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            });
        }
    });
    let port = common::reserve_port();
    let cfg = std::env::temp_dir().join(format!("alcyon_h2ck_{}_{port}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 20s\n\ttimeout server 20s\n\
             frontend fe\n\tbind 127.0.0.1:{port} proto h2\n\
             {rules}\tdefault_backend be\n\
             backend be\n\tserver s1 {be}\n"
        ),
    )
    .expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    assert!(common::wait_listening(([127, 0, 0, 1], port).into()), "never listened");
    let mut c = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    c.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
    c.write_all(&frame(0x04, 0, 0, &[])).unwrap();
    c.write_all(&frame(0x01, 0x05, 1, &request(f))).unwrap();
    thread::sleep(Duration::from_millis(1500));
    drop(c);
    common::stop(&mut child);
    let _ = std::fs::remove_file(&cfg);
    let seen = seen.lock().unwrap();
    String::from_utf8_lossy(seen.first().expect("no request reached the server")).into_owned()
}

#[test]
fn h2_cookie_fields_are_merged_into_one_line() {
    let rules = "\thttp-request set-header x-hdr %[req.hdr(cookie)]\n\thttp-request set-header x-cnt %[req.hdr_cnt(cookie)]\n\thttp-request set-header x-b %[req.cook(b)]\n";
    let got = exchange(rules, &[(b"cookie", b"a=1"), (b"x-y", b"z"), (b"cookie", b" b=2")]);
    // The oracle: the cookie line follows the other fields, the values joined by "; " with
    // the leading blank of the second kept; the rules see one header.
    let want = "GET /p HTTP/1.1\r\nhost: localhost\r\nx-y: z\r\ncookie: a=1;  b=2\r\nx-hdr: a=1;  b=2\r\nx-cnt: 1\r\nx-b: 2\r\n\r\n";
    assert_eq!(got, want);
}

/// `http_cookie_merge` trims nothing: the leading blank of the first crumb and the trailing
/// blank of the last reach the server, also when a rule rewrote the head (T514; measured on
/// `HAProxy` 3.5-dev8, `cookie:  a=1 ; b=2 `). The rules' `req.hdr` trims, as `HAProxy`'s.
#[test]
fn h2_cookie_merge_keeps_outer_blanks_after_a_rewrite() {
    let rules = "\thttp-request set-header x-hdr [%[req.hdr(cookie)]]\n\thttp-request set-header x-b %[req.cook(b)]\n";
    let got = exchange(rules, &[(b"cookie", b" a=1 "), (b"x-y", b"z"), (b"cookie", b"b=2 ")]);
    let want = "GET /p HTTP/1.1\r\nhost: localhost\r\nx-y: z\r\ncookie:  a=1 ; b=2 \r\nx-hdr: [a=1 ; b=2]\r\nx-b: 2\r\n\r\n";
    assert_eq!(got, want);
}
