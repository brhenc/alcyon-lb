// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The `global maxconn` a configuration without one gets (T149b).
//!
//! Measured on HAProxy 3.5-dev8-885761-29 (`nbthread 1`, one frontend with one `bind`, no
//! `maxconn`) under `ulimit -n N`: it raises the soft limit to the hard one, and sets
//! `global.maxconn` ("Automatically setting global.maxconn to ...") to
//! `(N - 1 - overhead) / 2`, the overhead being 12, plus one per listener, plus 10 for a
//! `stats socket`. Measured: N = 1048576 and 4096 with a `stats socket` (24 in all, with its
//! listener and the frontend's) gave 524275 and 2035; N = 4096 with two binds and no
//! `stats socket` gave 2040 (14). `show info` reports it as `Maxconn` and `Hard_maxconn`;
//! `set maxconn global` above it is `Value out of range.`, 0 goes back to it.

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

struct Ibex {
    child: Child,
    sock: PathBuf,
    dir: PathBuf,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn backend() -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut b = [0u8; 4096];
                while let Ok(n) = c.read(&mut b) {
                    if n == 0 || c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn start() -> Ibex {
    let fe = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("ibex_t149b_mc_{}_{}", std::process::id(), fe.port()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sock = dir.join("s.sock");
    let cfg = format!(
        "global\n  nbthread 1\n  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout client 5s\n  timeout connect 1s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  default_backend be\nbackend be\n  server s {}\n",
        sock.display(),
        backend()
    );
    std::fs::write(dir.join("cfg"), cfg).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(dir.join("cfg")).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let ibex = Ibex { child, sock, dir };
    assert!(common::wait_listening(fe));
    let end = std::time::Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(&ibex.sock).is_err() {
        assert!(std::time::Instant::now() < end, "the stats socket never came up");
        thread::sleep(Duration::from_millis(25));
    }
    ibex
}

fn cli(sock: &Path, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn info(sock: &Path, key: &str) -> String {
    cli(sock, "show info").lines().find_map(|l| l.strip_prefix(&format!("{key}: ")).map(str::to_string)).unwrap_or_default()
}

/// The hard limit on open files of this process, which Ibex inherits.
fn hard_nofile() -> Option<u64> {
    let limits = std::fs::read_to_string("/proc/self/limits").ok()?;
    let line = limits.lines().find(|l| l.starts_with("Max open files"))?;
    line.split_whitespace().nth(4)?.parse().ok()
}

#[test]
fn a_configuration_without_maxconn_gets_one_from_the_fd_limit() {
    let Some(hard) = hard_nofile() else {
        eprintln!("no numeric hard limit on open files here: skipped");
        return;
    };
    let ibex = start();
    let want = ((hard - 1 - 24) / 2).to_string();
    assert_eq!((info(&ibex.sock, "Maxconn"), info(&ibex.sock, "Hard_maxconn")), (want.clone(), want.clone()));
    assert_eq!(cli(&ibex.sock, "set maxconn global 99999999999"), "Value out of range.\n\n");
    assert_eq!(cli(&ibex.sock, &format!("set maxconn global {}", hard * 2)), "Value out of range.\n\n");
    assert_eq!(cli(&ibex.sock, "set maxconn global 1"), "\n");
    assert_eq!((info(&ibex.sock, "Maxconn"), info(&ibex.sock, "Hard_maxconn")), ("1".to_string(), want.clone()));
    assert_eq!(cli(&ibex.sock, "set maxconn global 0"), "\n");
    assert_eq!(info(&ibex.sock, "Maxconn"), want);
}
