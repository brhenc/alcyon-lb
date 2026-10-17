// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T342: a runtime message printed to a full stderr must not abort the process.
//!
//! `log stderr` makes fd 2 O_NONBLOCK (T236). Rust's `eprintln!` panics on EAGAIN and the
//! crash hook turns the panic into an abort: with stderr a pipe nobody reads, filled by
//! request logs, a SIGUSR2 (plain mode: "SIGUSR2 ignored" notice) killed ibex with SIGABRT.
//! HAProxy stays alive and keeps serving (measured on 3.5-dev8-885761-29).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

fn get(addr: SocketAddr) -> Result<(), String> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).map_err(|e| format!("connect: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"GET /a-path-long-enough-to-make-the-log-line-big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .map_err(|e| format!("write: {e}"))?;
    let mut out = String::new();
    s.read_to_string(&mut out).map_err(|e| format!("read: {e}"))?;
    if out.starts_with("HTTP/1.1 200") { Ok(()) } else { Err(format!("bad answer {out:?}")) }
}

#[test]
fn full_stderr_pipe_then_sigusr2_keeps_serving() {
    let dir = std::path::PathBuf::from(format!("/tmp/t342b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let addr = common::reserve_addr();
    let cfg = dir.join("c.cfg");
    std::fs::write(
        &cfg,
        format!(
            "global\n  nbthread 1\n  log stderr format raw local0\n\
             defaults\n  mode http\n  log global\n  option httplog\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind {addr}\n  http-request return status 200 content-type text/plain string ok\n"
        ),
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ibex"));
    cmd.arg("-f").arg(&cfg).stderr(Stdio::piped()).stdout(Stdio::null());
    let mut ibex = common::Ibex(cmd.spawn().expect("spawn"));
    assert!(common::wait_listening(addr), "ibex did not start");
    // 1500 lines of ~100 bytes overflow the 64 KiB pipe: stderr is full from here on.
    for i in 0..1500 {
        get(addr).unwrap_or_else(|e| panic!("request {i}: {e}"));
    }
    let pid = rustix::process::Pid::from_raw(i32::try_from(ibex.id()).unwrap()).unwrap();
    for _ in 0..3 {
        rustix::process::kill_process(pid, rustix::process::Signal::Usr2).unwrap();
        std::thread::sleep(Duration::from_millis(700));
    }
    if let Ok(Some(st)) = ibex.try_wait() {
        panic!("ibex died after SIGUSR2 with a full stderr: {st}");
    }
    get(addr).expect("still serves after SIGUSR2");
}
