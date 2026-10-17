// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A sample value written into an HTTP message by a log-format rule (set-header and the
//! other formats `HAProxy` parses with `LOG_OPT_HTTP`) has the bytes of `http_encode_map`
//! (0x00-0x08, 0x0a-0x1f, 0x7f) written `%XX`, so that a CR LF in a sample cannot end the
//! header or the request line (`lf_encode_chunk`, `src/log.c`). TAB and bytes from 0x80
//! pass, `%` itself too, and a `return` body stays raw. Every expectation below is what
//! 3.5-dev8-885761-29 sent on 2026-10-17 for the same configuration.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

/// A backend that answers each request with its head as the body.
fn echo_backend() -> SocketAddr {
    let addr = common::reserve_addr();
    let listener = TcpListener::bind(addr).unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            let _ = conn.set_read_timeout(Some(Duration::from_secs(1)));
            let mut head = Vec::new();
            let mut buf = [0u8; 4096];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match conn.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(got) => head.extend_from_slice(&buf[..got]),
                }
            }
            let mut out = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", head.len()).into_bytes();
            out.extend_from_slice(&head);
            let _ = conn.write_all(&out);
        }
    });
    addr
}

fn get(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn http_formats_encode_control_bytes() {
    let be = echo_backend();
    let a = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("http-encode-map-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(
        &path,
        format!(
            "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind {a}\n  option http-buffer-request\n\
             \x20 unique-id-format \"u%[str(a%0Ab),url_dec]\"\n  unique-id-header x-uid\n\
             \x20 http-request redirect location \"/r%[str(%0D%0Ab),url_dec]\" if {{ path /redir }}\n\
             \x20 http-request return status 200 content-type text/plain hdr x-r \"%[str(a%0D%0Ab),url_dec]\" lf-string \"B%[str(c%0D%0Ad),url_dec]\" if {{ path /ret }}\n\
             \x20 http-request set-header x-a \"%[str(a%0D%0Ax-evil: 1),url_dec]\"\n\
             \x20 http-request set-header x-b \"%[str(t%09ab%7F%C3%A9z),url_dec]\"\n\
             \x20 http-request set-header x-c \"l%%%[str(x%25y),url_dec]\"\n\
             \x20 http-request set-header x-d \"%[req.body]\"\n\
             \x20 http-request set-path \"/p%[str(%0Aq),url_dec]\" if {{ path /sp }}\n\
             \x20 http-response set-header x-ra \"%[str(a%0D%0Ax-evil: 1),url_dec]\"\n\
             \x20 http-response add-header x-rb \"%[str(%01%1F),url_dec]\"\n\
             \x20 default_backend b\nbackend b\n  server s {be}\n"
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _ibex = common::Ibex(child);
    assert!(common::wait_listening(a), "ibex did not listen on {a}");

    let r = get(a, b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\nConnection: close\r\n\r\na\r\nX-Inj:1");
    let shown = String::from_utf8_lossy(&r).into_owned();
    // The response rules, on what goes to the client.
    assert!(has(&r, b"\r\nx-ra: a%0D%0Ax-evil: 1\r\n"), "{shown}");
    assert!(has(&r, b"\r\nx-rb: %01%1F\r\n"), "{shown}");
    // The request rules, on what the server received (the body echoed).
    assert!(has(&r, b"\r\nx-a: a%0D%0Ax-evil: 1\r\n"), "{shown}");
    assert!(has(&r, b"\r\nx-b: t\tab%7F\xc3\xa9z\r\n"), "{shown}");
    assert!(has(&r, b"\r\nx-c: l%x%y\r\n"), "{shown}");
    assert!(has(&r, b"\r\nx-d: a%0D%0AX-Inj:1\r\n"), "{shown}");
    assert!(has(&r, b"\r\nx-uid: ua%0Ab\r\n"), "{shown}");
    assert!(!has(&r, b"\r\nx-evil:") && !has(&r, b"\r\nx-inj:"), "a sample injected a header: {shown}");

    // `return`: a header value is encoded, the lf-string body is not.
    let r = get(a, b"GET /ret HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    let shown = String::from_utf8_lossy(&r).into_owned();
    assert!(has(&r, b"\r\nx-r: a%0D%0Ab\r\n"), "{shown}");
    assert!(r.ends_with(b"\r\n\r\nBc\r\nd"), "{shown}");

    let r = get(a, b"GET /redir HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    assert!(has(&r, b"\r\nlocation: /r%0D%0Ab\r\n"), "{}", String::from_utf8_lossy(&r));

    let r = get(a, b"GET /sp HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    assert!(has(&r, b"\r\n\r\nGET /p%0Aq HTTP/1.1\r\n"), "{}", String::from_utf8_lossy(&r));
    let _ = std::fs::remove_dir_all(&dir);
}
