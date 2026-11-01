// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `measure-bench backend` answers each request once, a body that arrives in a read of its own
//! included (T555: Ibex sends an h3 POST's head and body in two writes; the backend answered
//! the body as a second request, and the proxy's server connection broke on the extra reply).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

#[test]
fn a_body_in_its_own_read_is_not_a_second_request() {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_measure-bench")).args(["backend", &port.to_string()]).stdout(Stdio::piped()).spawn().expect("spawn backend");
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut ready).unwrap();
    assert_eq!(ready.trim(), "READY");
    let mut c = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    c.write_all(b"POST / HTTP/1.1\r\nhost: x\r\ncontent-length: 4\r\n\r\n").unwrap();
    sleep(Duration::from_millis(50));
    c.write_all(b"abcd").unwrap();
    sleep(Duration::from_millis(50));
    c.write_all(b"GET / HTTP/1.1\r\nhost: x\r\n\r\n").unwrap();
    sleep(Duration::from_millis(100));
    c.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = c.read(&mut buf) {
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    let _ = child.kill();
    let _ = child.wait();
    let replies = got.windows(15).filter(|w| *w == b"HTTP/1.1 200 OK").count();
    assert_eq!(replies, 2, "two requests, {replies} replies: {:?}", String::from_utf8_lossy(&got));
}
