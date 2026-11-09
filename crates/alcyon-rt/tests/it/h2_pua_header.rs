// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A header value an HTTP/2 client sends that is valid UTF-8 spelling a private-use
//! character (U+F780 is EF 9E 80) reaches an HTTP/1 server as those bytes, and is not the
//! byte 0x80 to a rule (T286): the mapping of stray bytes to text (`alcyon_regex::bytetext`)
//! must not be confused by what a client sends.

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

/// `GET /<path>` with the header `<name>: <value>`, no Huffman.
fn request(path: &str, name: &str, value: &[u8]) -> Vec<u8> {
    let mut v = vec![0x82, 0x86, 0x04, u8::try_from(path.len()).expect("short path")];
    v.extend_from_slice(path.as_bytes());
    v.extend_from_slice(&[0x01, 9]);
    v.extend_from_slice(b"localhost");
    v.extend_from_slice(&[0x00, u8::try_from(name.len()).expect("short name")]);
    v.extend_from_slice(name.as_bytes());
    v.push(u8::try_from(value.len()).expect("short value"));
    v.extend_from_slice(value);
    v
}

#[test]
fn an_h2_value_in_the_private_use_range_is_not_a_stray_byte() {
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
    let cfg = std::env::temp_dir().join(format!("alcyon_h2pua_{}_{port}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 20s\n\ttimeout server 20s\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\
             \thttp-request deny deny_status 403 if {{ req.hdr(x-k) -m str \"\\xef\\x9e\\x80\" }}\n\
             \thttp-request deny deny_status 403 if {{ req.hdr(x-j) -m str \"\\x80\" }}\n\
             \tdefault_backend be\n\
             backend be\n\tserver s1 {be}\n"
        ),
    )
    .expect("write config");
    let mut child = common::Alcyon(Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn"));
    assert!(common::wait_listening(([127, 0, 0, 1], port).into()), "never listened");
    let mut c = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    c.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
    c.write_all(&frame(0x04, 0, 0, &[])).unwrap();
    // EF 9E 80 is valid UTF-8, U+F780. The rule that spells those bytes denies it (/a); the
    // rule on the stray byte 0x80 does not (/b), and the server gets the bytes as sent.
    c.write_all(&frame(0x01, 0x05, 1, &request("/a", "x-k", b"\xef\x9e\x80"))).unwrap();
    c.write_all(&frame(0x01, 0x05, 3, &request("/b", "x-j", b"\xef\x9e\x80"))).unwrap();
    thread::sleep(Duration::from_millis(1500));
    drop(c);
    common::stop(&mut child);
    let _ = std::fs::remove_file(&cfg);
    let seen = seen.lock().unwrap();
    let want: &[u8] = b"x-j: \xef\x9e\x80\r\n";
    let shown = || seen.iter().map(|h| h.escape_ascii().to_string()).collect::<Vec<_>>();
    assert!(seen.iter().any(|h| h.windows(want.len()).any(|w| w == want)), "/b not forwarded as sent: {:?}", shown());
    assert!(!seen.iter().any(|h| h.starts_with(b"GET /a ")), "/a was not denied: {:?}", shown());
}
