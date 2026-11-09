// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;
use std::io::Write;

fn run_alcyon_with_notify(sock_addr: &SocketAddr, env_val: &str) -> String {
    let mut config_file = NamedTempFile::new().unwrap();
    write!(config_file, "listen test\n  bind 127.0.0.1:0\n").unwrap();

    let sock = match sock_addr.as_pathname() {
        Some(p) => {
            let _ = std::fs::remove_file(p);
            UnixDatagram::bind(p).unwrap()
        }
        None => {
            UnixDatagram::bind_addr(sock_addr).unwrap()
        }
    };
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-Ws")
        .arg("-f")
        .arg(config_file.path())
        .env("NOTIFY_SOCKET", env_val)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let mut buf = [0u8; 1024];
    let res = sock.recv(&mut buf);
    // Soft stop, not SIGKILL: a killed process never writes its coverage profile, and the
    // abstract-socket path this file exists to test would count as untested.
    if let Some(pid) = rustix::process::Pid::from_raw(i32::try_from(cmd.id()).unwrap_or(0)) {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::Usr1);
    }
    for _ in 0..250 {
        if cmd.try_wait().ok().flatten().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = cmd.kill();
    let _ = cmd.wait();

    match res {
        Ok(n) => String::from_utf8_lossy(&buf[..n]).to_string(),
        Err(_) => String::new(),
    }
}

#[test]
fn test_systemd_notify_path() {
    // Per process: a fixed name is shared by every concurrent run of this test.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notify.sock");
    let addr = SocketAddr::from_pathname(&path).unwrap();
    let out = run_alcyon_with_notify(&addr, path.to_str().unwrap());
    assert!(out.contains("READY=1\n"));
}

#[test]
fn test_systemd_notify_abstract() {
    let name = format!("alcyon_test_notify_abstract_{}", std::process::id());
    let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let out = run_alcyon_with_notify(&addr, &format!("@{name}"));
    assert!(out.contains("READY=1\n"));
}
