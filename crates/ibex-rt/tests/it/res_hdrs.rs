// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T329: `res.hdrs`, the response's header block as `HAProxy`'s H1 parser leaves it (names
//! lowercased, `close`/`keep-alive` out of `Connection`, `h2c` out of `Upgrade`), each
//! `name: value\r\n`, then `\r\n`. The sample itself is raw: the `%0D%0A` in an
//! `http-response set-header` comes from the header's log-format encoding
//! (`http_encode_map`), so `res.hdrs,length` and `res.hdrs,hex` see the CR LFs. Every
//! expectation is what 3.5-dev8-885761-29 answered on 2026-10-17.

use crate::common;

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

/// A server that reads each request head, answers `resp` and closes the connection.
fn backend(resp: &'static [u8]) -> SocketAddr {
    let addr = common::reserve_addr();
    let listener = TcpListener::bind(addr).unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let _ = conn.set_read_timeout(Some(Duration::from_secs(2)));
            let (mut head, mut buf) = (Vec::new(), [0u8; 4096]);
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match conn.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(got) => head.extend_from_slice(&buf[..got]),
                }
            }
            let _ = conn.write_all(resp);
        }
    });
    addr
}

/// The value of header `name` in the answer to `GET path`, if any.
fn header(addr: SocketAddr, path: &str, name: &str) -> Option<Vec<u8>> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let end = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(out.len());
    let prefix = format!("{name}: ");
    out[..end].split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l)).find_map(|l| l.strip_prefix(prefix.as_bytes())).map(<[u8]>::to_vec)
}

const RESPS: [&[u8]; 5] = [
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-B: 1\r\nX-B: 2, 3\r\nSet-Cookie: s=abc\r\n\r\nok",
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok",
    b"HTTP/1.1 200 OK\r\nConnection: keep-alive, foo\r\nContent-Length: 2\r\n\r\nok",
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-U: caf\xc3\xa9\r\nX-T: a\tb\r\nUpgrade: h2c, x\r\n\r\nok",
];

/// `x-out` for each of [`RESPS`]: the block as set-header writes it, its length, its hex.
const WANT: [&[u8]; 5] = [
    b"[content-length: 2%0D%0Ax-b: 1%0D%0Ax-b: 2, 3%0D%0Aset-cookie: s=abc%0D%0A%0D%0A]|59|636F6E74656E742D6C656E6774683A20320D0A782D623A20310D0A782D623A20322C20330D0A7365742D636F6F6B69653A20733D6162630D0A0D0A",
    b"[content-length: 2%0D%0A%0D%0A]|21|636F6E74656E742D6C656E6774683A20320D0A0D0A",
    b"[content-length: 2%0D%0A%0D%0A]|21|636F6E74656E742D6C656E6774683A20320D0A0D0A",
    b"[connection: foo%0D%0Acontent-length: 2%0D%0A%0D%0A]|38|636F6E6E656374696F6E3A20666F6F0D0A636F6E74656E742D6C656E6774683A20320D0A0D0A",
    b"[content-length: 2%0D%0Ax-u: caf\xc3\xa9%0D%0Ax-t: a\tb%0D%0Aupgrade: x%0D%0A%0D%0A]|55|636F6E74656E742D6C656E6774683A20320D0A782D753A20636166C3A90D0A782D743A206109620D0A757067726164653A20780D0A0D0A",
];

#[test]
fn test_res_hdrs() {
    let a = common::reserve_addr();
    let mut cfg = format!("defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nfrontend fe\n  bind {a}\n");
    for i in 0..RESPS.len() {
        let _ = writeln!(cfg, "  use_backend b{i} if {{ path /{i} }}");
    }
    for (i, resp) in RESPS.iter().enumerate() {
        let be = backend(resp);
        let _ = write!(
            cfg,
            "backend b{i}\n  http-response set-header x-out \"[%[res.hdrs]]|%[res.hdrs,length]|%[res.hdrs,hex]\"\n\
             \x20 http-response set-header x-m yes if {{ res.hdrs,hex -m sub 0D0A0D0A }}\n  server s {be}\n"
        );
    }
    let dir = std::env::temp_dir().join(format!("res-hdrs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _ibex = common::Ibex(child);
    assert!(common::wait_listening(a), "ibex did not listen on {a}");

    let mut wrong = Vec::new();
    for (i, want) in WANT.iter().enumerate() {
        let got = header(a, &format!("/{i}"), "x-out").unwrap_or_default();
        if got != *want {
            wrong.push(format!("/{i}: got {:?}, want {:?}", String::from_utf8_lossy(&got), String::from_utf8_lossy(want)));
        }
        // The raw block ends with an empty line, so the documented truncated-block check works.
        if header(a, &format!("/{i}"), "x-m").as_deref() != Some(b"yes") {
            wrong.push(format!("/{i}: res.hdrs,hex -m sub 0D0A0D0A did not match"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    let _ = std::fs::remove_dir_all(&dir);
}
