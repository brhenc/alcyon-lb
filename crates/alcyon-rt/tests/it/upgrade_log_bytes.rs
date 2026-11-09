// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `%B` and `%U` of an HTTP/1.1 WebSocket upgrade: the `101` head counted with its
//! `Connection: Upgrade` (which `HAProxy`'s H1 parser keeps in the HTX, unlike `close` and
//! `keep-alive`), and the tunnel's bytes both ways (T514; measured on `HAProxy` 3.5-dev8 on
//! this exchange: `ST=101 B=1132 U=437`).

use crate::common;

use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const RESP: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
const REQ: &[u8] = b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

#[test]
fn the_log_counts_the_upgrade_heads_and_the_tunnel_bytes() {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let be = l.local_addr().unwrap();
    let (got_tx, got_rx) = mpsc::channel();
    thread::spawn(move || {
        let Ok((mut s, _)) = l.accept() else { return };
        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
        let mut got = Vec::new();
        let mut b = [0u8; 4096];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            match s.read(&mut b) {
                Ok(n) if n > 0 => got.extend_from_slice(&b[..n]),
                _ => return,
            }
        }
        let _ = s.write_all(RESP);
        thread::sleep(Duration::from_millis(200));
        let _ = s.write_all(&[b'S'; 1000]);
        let mut n = got.len() - got.windows(4).position(|w| w == b"\r\n\r\n").unwrap() - 4;
        while n < 300 {
            match s.read(&mut b) {
                Ok(k) if k > 0 => n += k,
                _ => break,
            }
        }
        let _ = got_tx.send(n);
    });
    let port = common::reserve_port();
    let dir = tempfile::tempdir().expect("dir");
    let cfg = dir.path().join("alcyon.cfg");
    std::fs::write(
        &cfg,
        format!(
            "global\n\tlog stdout format raw local0\n\
             defaults\n\tmode http\n\tlog global\n\toption httplog\n\ttimeout connect 3s\n\ttimeout client 20s\n\ttimeout server 20s\n\ttimeout tunnel 20s\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tlog-format \"ST=%ST B=%B U=%U\"\n\tdefault_backend be\n\
             backend be\n\tserver s1 {be}\n"
        ),
    )
    .expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&cfg).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn");
    let out = child.stdout.take().expect("stdout");
    let (tx, logs) = mpsc::channel();
    thread::spawn(move || {
        for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    assert!(common::wait_listening(([127, 0, 0, 1], port).into()), "never listened");
    let mut c = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    c.write_all(REQ).unwrap();
    thread::sleep(Duration::from_millis(300));
    c.write_all(&[b'C'; 300]).unwrap();
    assert_eq!(got_rx.recv_timeout(Duration::from_secs(5)).ok(), Some(300), "the server got the tunnel's bytes");
    let _ = c.set_read_timeout(Some(Duration::from_secs(3)));
    let mut seen = 0;
    let mut b = [0u8; 4096];
    while seen < RESP.len() - 4 + 1000 {
        match c.read(&mut b) {
            Ok(n) if n > 0 => seen += n,
            _ => break,
        }
    }
    drop(c);
    // The probe of `wait_listening` read no request: `U=0`.
    let line = std::iter::from_fn(|| logs.recv_timeout(Duration::from_secs(3)).ok()).find(|l| !l.ends_with(" U=0")).expect("the stream is logged");
    common::stop(&mut child);
    assert_eq!(line, "ST=101 B=1132 U=437");
}
