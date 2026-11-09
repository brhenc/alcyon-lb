// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T302: `req.hdrs`, the request's header block as `HAProxy`'s H1 parser leaves it: names
//! lowercased, values trimmed, `close`/`keep-alive` taken out of `Connection`, an `Upgrade`
//! without a `Connection: upgrade` dropped (and the reverse), then the empty line, which is
//! there even when no header is. Every expectation is what 3.5-dev8-885761-29 answered on
//! 2026-10-17 for the same request.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

const H: &str = "GET / HTTP/1.1\r\nHost: a\r\n";

/// One request on a new connection; the body of the answer.
fn body(addr: SocketAddr, req: &[u8]) -> String {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    // Read up to the end of the body (by its content-length): the connection stays open.
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let text = String::from_utf8_lossy(&out).into_owned();
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let len = head.lines().find_map(|l| l.strip_prefix("content-length: ")).and_then(|v| v.parse::<usize>().ok());
            if len.is_some_and(|n| body.len() >= n) {
                return body.to_string();
            }
        }
        match s.read(&mut buf) {
            Ok(0) | Err(_) => return text,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
}

#[test]
fn test_req_hdrs() {
    let a = common::reserve_addr();
    let b = common::reserve_addr();
    let c = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("req-hdrs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(
        &path,
        format!(
            "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"[%[req.hdrs]]\"\n\
             frontend fl\n  bind {b}\n  http-request return status 200 content-type text/plain lf-string \"[%[req.hdrs,length]]\"\n\
             frontend fs\n  bind {c}\n  http-request set-header x-in \"%[req.hdrs]\"\n  http-request return status 200 content-type text/plain lf-string \"[%[req.fhdr(x-in)]]\"\n"
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _alcyon = common::Alcyon(child);
    assert!(common::wait_listening(a) && common::wait_listening(b) && common::wait_listening(c), "alcyon did not listen");

    let cases: &[(String, &str)] = &[
        (format!("{H}X-Foo: Bar\r\nConnection: close\r\n\r\n"), "[host: a\r\nx-foo: Bar\r\n\r\n]"),
        (format!("{H}X-A: 1\r\nx-a: 2\r\nUser-Agent: T/1\r\nConnection: keep-alive, close\r\n\r\n"), "[host: a\r\nx-a: 1\r\nx-a: 2\r\nuser-agent: T/1\r\n\r\n]"),
        ("GET / HTTP/1.1\r\nX-Empty:\r\nX-Sp:   padded  \r\n\r\n".into(), "[x-empty: \r\nx-sp: padded\r\n\r\n]"),
        // No header at all, or only a Connection that the parser empties: still the empty line.
        ("GET / HTTP/1.0\r\n\r\n".into(), "[\r\n]"),
        ("GET / HTTP/1.0\r\nConnection: close\r\n\r\n".into(), "[\r\n]"),
        (format!("{H}Connection: close\r\n\r\n"), "[host: a\r\n\r\n]"),
        // Only the close/keep-alive tokens go; the rest stays, joined with a bare comma
        // once something was taken out, verbatim when nothing was.
        (format!("{H}Connection: close, X-Hop\r\nX-Hop: 1\r\n\r\n"), "[host: a\r\nconnection: X-Hop\r\nx-hop: 1\r\n\r\n]"),
        (format!("{H}Connection: X-Hop, close\r\n\r\n"), "[host: a\r\nconnection: X-Hop\r\n\r\n]"),
        (format!("{H}Connection: A,  B\r\n\r\n"), "[host: a\r\nconnection: A,  B\r\n\r\n]"),
        (format!("{H}Connection: keep-alive, A,  B\r\n\r\n"), "[host: a\r\nconnection: A,B\r\n\r\n]"),
        (format!("{H}Connection: close\r\nConnection: X-A\r\n\r\n"), "[host: a\r\nconnection: X-A\r\n\r\n]"),
        // `upgrade` in Connection with no Upgrade header goes, and so does an Upgrade header
        // with no `upgrade` in Connection; `h2c` and `h2` are taken out of Upgrade.
        (format!("{H}Connection: Upgrade\r\n\r\n"), "[host: a\r\n\r\n]"),
        (format!("{H}Connection: keep-alive, Upgrade\r\n\r\n"), "[host: a\r\n\r\n]"),
        (format!("{H}Connection: foo, Upgrade, bar\r\n\r\n"), "[host: a\r\nconnection: foo,bar\r\n\r\n]"),
        (format!("{H}Upgrade: websocket\r\n\r\n"), "[host: a\r\n\r\n]"),
        (format!("{H}Connection: Upgrade, foo\r\nUpgrade: h2c\r\n\r\n"), "[host: a\r\nconnection: foo\r\n\r\n]"),
        (format!("{H}Upgrade: a ,  b\r\nConnection: upgrade\r\n\r\n"), "[host: a\r\nupgrade: a ,  b\r\nconnection: upgrade\r\n\r\n]"),
    ];
    let mut wrong = Vec::new();
    for (req, want) in cases {
        let got = body(a, req.as_bytes());
        if got != *want {
            wrong.push(format!("{req:?}: got {got:?}, want {want:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert_eq!(body(b, b"GET / HTTP/1.0\r\n\r\n"), "[2]");
    assert_eq!(body(b, b"GET / HTTP/1.1\r\nHost: a\r\nX-Foo: Bar\r\nConnection: close\r\n\r\n"), "[23]");
    // Written into a header, the CR LFs are %XX (http_encode_map), not a header injection.
    assert_eq!(body(c, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"), "[host: a%0D%0A%0D%0A]");
    let _ = std::fs::remove_dir_all(&dir);
}
