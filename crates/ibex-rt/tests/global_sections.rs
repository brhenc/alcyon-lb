// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Several `global` sections, several `stats socket`s (T146 item 2). `HAProxy` binds every
//! `stats socket` of every `global` section, each with its own `level`; Ibex bound one and
//! dropped the rest. The parser half is `ibex-config` `tests/global_sections.rs`.

mod common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn cli(sock: &Path, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn wait_for_socket(p: &Path) {
    let end = Instant::now() + Duration::from_secs(10);
    while Instant::now() < end {
        if UnixStream::connect(p).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("{} never accepted a connection", p.display());
}

#[test]
fn every_stats_socket_of_every_global_section_answers_at_its_own_level() {
    let dir = std::env::temp_dir().join(format!("ibex_t146_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let (a, b, c): (PathBuf, PathBuf, PathBuf) = (dir.join("a.sock"), dir.join("b.sock"), dir.join("c.sock"));
    let cfg = format!(
        "global\n  stats socket {} level admin\nglobal\n  stats socket {} level operator\n  stats socket {} level user\n\
         defaults\n  mode http\n  timeout client 1s\n  timeout connect 1s\n  timeout server 1s\n\
         frontend f\n  bind {}\n  default_backend be\nbackend be\n  server s 127.0.0.1:1\n",
        a.display(),
        b.display(),
        c.display(),
        common::reserve_addr()
    );
    let cfg_path = dir.join("cfg");
    std::fs::write(&cfg_path, cfg).expect("write cfg");
    let mut child =
        Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg_path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    for s in [&a, &b, &c] {
        wait_for_socket(s);
    }
    // Measured on HAProxy 3.5-dev8-885761-29, the same configuration: `show info` answers
    // at every level, `clear counters` needs operator, `disable server` needs admin.
    let denied = |s: &Path, cmd: &str| cli(s, cmd).contains("Permission denied");
    for s in [&a, &b, &c] {
        assert!(cli(s, "show info").contains("Name: "), "show info on {}", s.display());
    }
    assert!(!denied(&a, "clear counters") && !denied(&a, "disable server be/s"), "admin was refused");
    assert!(!denied(&b, "clear counters"), "operator was refused `clear counters`");
    assert!(denied(&b, "disable server be/s"), "operator was allowed `disable server`");
    assert!(denied(&c, "clear counters"), "user was allowed `clear counters`");
    common::stop(&mut child);
    let _ = std::fs::remove_dir_all(&dir);
}
