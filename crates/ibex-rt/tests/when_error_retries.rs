// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `when(error)` / `when(normal)` count a connection retry as an error, not only a 5xx status
//! (`sample_conv_when`: `SF_REDISP`, or no error flag and `conn_retries != 0`; T147 item 4).
//!
//! Measured against `HAProxy` 3.5-dev8-885761-29, 2026-10-04: `balance first`,
//! `option redispatch`, `retries 2`, a dead first server and a live second one, with
//! `http-response set-header x-e "%[str(y),when(error)]"` (and `x-n` for `normal`): all three
//! requests answer 200, `x-e: y`, `x-n:` empty. With only the live server: `x-e` empty,
//! `x-n: y`.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn live_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    port
}

fn head(port: u16) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    write!(s, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).split("\r\n\r\n").next().unwrap_or("").to_string()
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

/// The heads of three requests through a backend with `servers` after the rules.
fn heads(tag: &str, dead_first: bool) -> Vec<String> {
    let live = live_backend();
    let dead = common::reserve_port();
    let port = common::reserve_port();
    let servers = if dead_first {
        format!("  server dead 127.0.0.1:{dead}\n  server a 127.0.0.1:{live}\n")
    } else {
        format!("  server a 127.0.0.1:{live}\n")
    };
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 3s\n  timeout server 3s\n  retries 2\n  option redispatch\n\
         frontend f\n  bind 127.0.0.1:{port}\n  default_backend be\n\
         backend be\n  balance first\n  http-response set-header x-e \"%[str(y),when(error)]\"\n  \
         http-response set-header x-n \"%[str(y),when(normal)]\"\n{servers}"
    );
    let path = std::env::temp_dir().join(format!("ibex_whenerr_{}_{tag}", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Ibex)
        .expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the daemon never listened on {port}");
        thread::sleep(Duration::from_millis(25));
    }
    let out = (0..3).map(|_| head(port)).collect();
    common::stop(&mut child);
    let _ = std::fs::remove_file(&path);
    out
}

#[test]
fn a_retry_is_an_error_for_when() {
    for h in heads("retry", true) {
        assert!(h.starts_with("HTTP/1.1 200"), "{h}");
        assert_eq!(header(&h, "x-e").as_deref(), Some("y"), "{h}");
        assert_eq!(header(&h, "x-n").as_deref(), Some(""), "{h}");
    }
}

#[test]
fn a_clean_request_is_normal_for_when() {
    for h in heads("clean", false) {
        assert!(h.starts_with("HTTP/1.1 200"), "{h}");
        assert_eq!(header(&h, "x-e").as_deref(), Some(""), "{h}");
        assert_eq!(header(&h, "x-n").as_deref(), Some("y"), "{h}");
    }
}
