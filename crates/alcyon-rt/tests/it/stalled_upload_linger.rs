// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A stalled upload answered 400 `cH--` keeps its connection for one more `timeout client`
//! (T501, VV-9). Measured on `HAProxy 3.5-dev8-885761-29` (`tools/battery/repro/vv-t305/stall.py`,
//! `timeout client 2s`, `timeout server 4s`): the 400 at 2.0 s, the close at 4.0 s; more bytes
//! from the client restart the wait (data at 2.5 s: close at 4.5 s); a client FIN closes at once.

use crate::common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum After {
    Nothing,
    MoreAt(u64),
    FinAt(u64),
}

/// Seconds at which the 400 arrived and at which the connection closed, and the log line.
fn run(after: After) -> (String, f64, f64) {
    let port = common::reserve_port();
    let be = TcpListener::bind("127.0.0.1:0").expect("backend");
    let bport = be.local_addr().unwrap().port();
    thread::spawn(move || {
        for c in be.incoming().flatten() {
            thread::spawn(move || {
                let mut c = c;
                let mut b = [0u8; 4096];
                while c.read(&mut b).map(|n| n > 0).unwrap_or(false) {}
            });
        }
    });
    let dir = std::env::temp_dir().join(format!("alcyon_t501_{}_{port}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let (cfgf, logf) = (dir.join("c.cfg"), dir.join("out.log"));
    let cfg = format!(
        "global\n  log stdout format raw local0\ndefaults\n  mode http\n  log global\n  option httplog\n  \
         timeout connect 1s\n  timeout client 1s\n  timeout server 5s\n\
         listen l\n  bind 127.0.0.1:{port}\n  server s1 127.0.0.1:{bport}\n"
    );
    std::fs::write(&cfgf, cfg).expect("write config");
    let out = std::fs::File::create(&logf).expect("log");
    let mut child = Command::new(std::env::var("ALCYON_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string()))
        .arg("-f")
        .arg(&cfgf)
        .stdout(out)
        .stderr(Stdio::null())
        .spawn()
        .map(common::Alcyon)
        .expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "never listened");
        thread::sleep(Duration::from_millis(25));
    }
    let t = Instant::now();
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(50))).ok();
    s.write_all(b"POST /stall HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n0123456789").expect("write");
    let (mut first, mut closed, mut got, mut acted) = (None, None, Vec::new(), false);
    let mut buf = [0u8; 4096];
    while t.elapsed() < Duration::from_secs(6) && closed.is_none() {
        match s.read(&mut buf) {
            Ok(0) => closed = Some(t.elapsed().as_secs_f64()),
            Ok(n) => {
                got.extend_from_slice(&buf[..n]);
                first.get_or_insert(t.elapsed().as_secs_f64());
            }
            Err(_) => {}
        }
        let el = t.elapsed().as_millis() as u64;
        match after {
            After::MoreAt(ms) if !acted && el >= ms => {
                acted = true;
                let _ = s.write_all(b"xxxxx");
            }
            After::FinAt(ms) if !acted && el >= ms => {
                acted = true;
                let _ = s.shutdown(Shutdown::Write);
            }
            _ => {}
        }
    }
    thread::sleep(Duration::from_millis(200));
    common::stop(&mut child);
    let log = std::fs::read_to_string(&logf).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    let status = String::from_utf8_lossy(&got).lines().next().unwrap_or("").to_string();
    assert_eq!(status, "HTTP/1.1 400 Bad request", "{log}");
    assert!(log.contains(" 400 "), "{log}");
    assert!(log.contains("cH--"), "{log}");
    (log, first.unwrap_or(-1.0), closed.unwrap_or(-1.0))
}

#[test]
fn connection_held_one_more_timeout() {
    let (_, first, closed) = run(After::Nothing);
    assert!((0.9..1.4).contains(&first), "400 at {first}");
    assert!((1.9..2.5).contains(&closed), "closed at {closed}");
}

#[test]
fn bytes_after_the_page_restart_the_wait() {
    let (_, first, closed) = run(After::MoreAt(1500));
    assert!((0.9..1.4).contains(&first), "400 at {first}");
    assert!((2.4..3.1).contains(&closed), "closed at {closed}");
}

#[test]
fn client_fin_after_the_page_closes_at_once() {
    let (_, _, closed) = run(After::FinAt(1200));
    assert!((1.0..1.6).contains(&closed), "closed at {closed}");
}
