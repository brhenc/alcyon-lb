// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `hard-stop-after` ends a WebSocket (an upgraded tunnel) with a FIN, never a RST.
//!
//! Measured on the reference `HAProxy` (3.5-dev8-885761-29), `-W`, `hard-stop-after 1s`,
//! a client that keeps sending through a WebSocket, `SIGUSR2`: the client read EOF in 6 of 6
//! trials. Ibex gave a reset in 3 of 8, because the process left its loop with bytes of the
//! client still unread in the socket, and closing a socket in that state makes Linux send RST.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::NamedTempFile;

fn echo_backend() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 65536];
                let mut head = Vec::new();
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut buf) {
                        Ok(n) if n > 0 => head.extend_from_slice(&buf[..n]),
                        _ => return,
                    }
                }
                let _ = c.write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                      Sec-WebSocket-Accept: x\r\n\r\n",
                );
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 || c.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn pid_of(pidfile: &Path) -> rustix::process::Pid {
    let text = std::fs::read_to_string(pidfile).expect("pidfile");
    let pid: i32 = text.split_whitespace().next().and_then(|p| p.parse().ok()).expect("pid");
    rustix::process::Pid::from_raw(pid).expect("pid")
}

/// One trial: a WebSocket written to without pause, a reload, and how the client saw it end.
fn trial(pidfile: &Path, fe: SocketAddr) -> &'static str {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.write_all(
        b"GET /ws HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .expect("upgrade");
    let mut head = Vec::new();
    let mut b = [0u8; 4096];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut b).expect("101");
        assert!(n > 0, "no 101");
        head.extend_from_slice(&b[..n]);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let mut w = s.try_clone().expect("clone");
    let stop_w = stop.clone();
    let writer = thread::spawn(move || {
        let chunk = [b'x'; 200];
        while !stop_w.load(Ordering::Relaxed) {
            if w.write_all(&chunk).is_err() {
                break;
            }
            thread::sleep(Duration::from_micros(50));
        }
    });
    thread::sleep(Duration::from_millis(200));
    rustix::process::kill_process(pid_of(pidfile), rustix::process::Signal::Usr2).expect("SIGUSR2");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let t0 = Instant::now();
    let how = loop {
        match s.read(&mut b) {
            Ok(0) => break "FIN",
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break "RST",
            Err(_) => break "other",
        }
        if t0.elapsed() > Duration::from_secs(5) {
            break "still open";
        }
    };
    stop.store(true, Ordering::Relaxed);
    let _ = writer.join();
    thread::sleep(Duration::from_millis(300));
    how
}

#[test]
fn hard_stop_after_closes_an_upgraded_connection_with_a_fin() {
    let srv = echo_backend();
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n  hard-stop-after 300ms\n\
         defaults\n  mode http\n  timeout client 30s\n  timeout server 30s\n  timeout connect 3s\n  timeout tunnel 60s\n\
         frontend f\n  bind {fe}\n  default_backend b\nbackend b\n  server s {srv}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write");
    let pidfile = NamedTempFile::new().expect("pidfile");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .args(["-W", "-p"])
        .arg(pidfile.path())
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Ibex)
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened");
    thread::sleep(Duration::from_millis(500));
    let hows: Vec<&str> = (0..12).map(|_| trial(pidfile.path(), fe)).collect();
    let _ = rustix::process::kill_process(pid_of(pidfile.path()), rustix::process::Signal::Usr1);
    let _ = child.wait();
    assert!(hows.iter().all(|h| *h == "FIN"), "how each of 12 WebSockets ended: {hows:?}");
}
