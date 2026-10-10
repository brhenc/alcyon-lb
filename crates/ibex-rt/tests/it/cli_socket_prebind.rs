// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Stats sockets are bound on the main thread before any worker serves (T220).
//!
//! HAProxy binds every listener, `stats socket` included, in `protocol_bind_all` before it
//! creates its threads: when the frontend port accepts, the socket file exists, and an
//! unbindable `stats socket` path stops the start before any port listens. Measured on
//! 3.5-dev8-885761-29:
//!
//! ```text
//! [ALERT] (pid) : Binding [bad.cfg:2] for frontend GLOBAL: protocol unix_stream: cannot bind UNIX socket (No such file or directory) [/nonexistent-dir/x.sock].
//! [ALERT] (pid) : [haproxy.main()] Some protocols failed to start their listeners! Exiting.
//! ```
//! exit status 1, and the frontend port never accepted.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::{NamedTempFile, TempDir};

fn config(sock_lines: &str, addr: SocketAddr) -> NamedTempFile {
    let cfg = format!(
        "global\n  nbthread 64\n{sock_lines}\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend fe\n  bind {addr}\n  http-request return status 200\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    f
}

#[test]
fn stats_sockets_exist_when_the_frontend_port_first_accepts() {
    let dir = TempDir::new().expect("dir");
    for attempt in 0..15 {
        let addr = common::reserve_addr();
        let s1 = dir.path().join(format!("a{attempt}.sock"));
        let s2 = dir.path().join(format!("b{attempt}.sock"));
        let f = config(
            &format!("  stats socket {} level admin\n  stats socket {} level user\n", s1.display(), s2.display()),
            addr,
        );
        let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
            .arg("-f")
            .arg(f.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn().map(common::Ibex)
            .expect("spawn ibex");
        // No sleep: the point is the first instant the port answers.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut accepted = false;
        while Instant::now() < deadline {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                accepted = true;
                break;
            }
        }
        let (e1, e2) = (s1.exists(), s2.exists());
        common::stop(&mut child);
        assert!(accepted, "ibex never listened on {addr}");
        assert!(e1 && e2, "attempt {attempt}: the port accepted but the stats sockets did not exist (first {e1}, second {e2})");
    }
}

#[test]
fn an_unbindable_stats_socket_stops_the_start_before_any_port_listens() {
    let addr = common::reserve_addr();
    let f = config("  stats socket /nonexistent-dir/x.sock\n", addr);
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn().map(common::Ibex)
        .expect("spawn ibex");
    let mut stderr = child.stderr.take().expect("stderr");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut accepted = false;
    let status = loop {
        if let Some(st) = child.try_wait().expect("wait") {
            break st;
        }
        if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            accepted = true;
        }
        if Instant::now() > deadline {
            common::stop(&mut child);
            panic!("ibex neither exited nor failed");
        }
    };
    let mut err = String::new();
    let _ = stderr.read_to_string(&mut err);
    assert!(!accepted, "the frontend port accepted before ibex gave up:\n{err}");
    assert_eq!(status.code(), Some(1), "exit status; stderr:\n{err}");
    assert!(
        err.contains("Binding for frontend GLOBAL: protocol unix_stream: cannot bind UNIX socket (No such file or directory) [/nonexistent-dir/x.sock]."),
        "alert text; stderr:\n{err}"
    );
    assert!(err.contains("[ALERT] [haproxy.main()] Some protocols failed to start their listeners! Exiting."), "stderr:\n{err}");
}
