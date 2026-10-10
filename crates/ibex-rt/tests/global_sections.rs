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

/// Ends the child on every path out of a test, a failed assertion included: a `-W` master
/// left running keeps its worker, and both load the machine for every later gate.
struct Ibex(std::process::Child);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

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
    let (a, b, c, d): (PathBuf, PathBuf, PathBuf, PathBuf) =
        (dir.join("a.sock"), dir.join("b.sock"), dir.join("c.sock"), dir.join("d.sock"));
    let cfg = format!(
        "global\n  stats socket {} level admin\nglobal\n  stats socket {} level operator\n  stats socket {} level user\n  stats socket {}\n\
         defaults\n  mode http\n  timeout client 1s\n  timeout connect 1s\n  timeout server 1s\n\
         frontend f\n  bind {}\n  default_backend be\nbackend be\n  server s 127.0.0.1:1\n",
        a.display(),
        b.display(),
        c.display(),
        d.display(),
        common::reserve_addr()
    );
    let cfg_path = dir.join("cfg");
    std::fs::write(&cfg_path, cfg).expect("write cfg");
    let _child = Ibex(
        Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg_path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn"),
    );
    for s in [&a, &b, &c, &d] {
        wait_for_socket(s);
    }
    // Measured on HAProxy 3.5-dev8-885761-29, the same configuration: `show info` answers
    // at every level, `clear counters` needs operator, `disable server` needs admin.
    let denied = |s: &Path, cmd: &str| cli(s, cmd).contains("Permission denied");
    for s in [&a, &b, &c, &d] {
        assert!(cli(s, "show info").contains("Name: "), "show info on {}", s.display());
    }
    assert!(!denied(&a, "clear counters") && !denied(&a, "disable server be/s"), "admin was refused");
    assert!(!denied(&b, "clear counters"), "operator was refused `clear counters`");
    assert!(denied(&b, "disable server be/s"), "operator was allowed `disable server`");
    assert!(denied(&c, "clear counters"), "user was allowed `clear counters`");
    // No `level`: HAProxy's default is operator (`bind_conf->level |= ACCESS_LVL_OPER`,
    // src/cli.c), not user, and not admin, which Ibex used to give.
    assert!(!denied(&d, "clear counters"), "a socket without `level` was refused `clear counters`");
    assert!(denied(&d, "disable server be/s"), "a socket without `level` was allowed `disable server`");
    let _ = std::fs::remove_dir_all(&dir);
}

fn config(dir: &Path, stats: &str) -> PathBuf {
    let cfg = format!(
        "global\n{stats}defaults\n  mode http\n  timeout client 1s\n  timeout connect 1s\n  timeout server 1s\n\
         frontend f\n  bind {}\n  default_backend be\nbackend be\n  server s 127.0.0.1:1\n",
        common::reserve_addr()
    );
    std::fs::create_dir_all(dir).expect("mkdir");
    let p = dir.join("cfg");
    std::fs::write(&p, cfg).expect("write cfg");
    p
}

#[test]
fn the_master_socket_is_admin_whatever_the_configuration_says() {
    // `-S` (the master CLI, which needs `-W` as in HAProxy) is admin, and so is the worker
    // CLI it forwards `@1` to; the configuration's own socket, with no `level`, is operator.
    let dir = std::env::temp_dir().join(format!("ibex_t146m_{}", std::process::id()));
    let (conf_sock, master) = (dir.join("c.sock"), dir.join("m.sock"));
    let cfg = config(&dir, &format!("  stats socket {}\n", conf_sock.display()));
    let _child = Ibex(
        Command::new(env!("CARGO_BIN_EXE_ibex"))
            .arg("-W")
            .arg("-f")
            .arg(&cfg)
            .arg("-S")
            .arg(&master)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn"),
    );
    wait_for_socket(&master);
    wait_for_socket(&conf_sock);
    assert_eq!(cli(&master, "show cli level"), "admin\n\n");
    // The master learns of its worker a moment after the worker's own socket is up.
    let end = Instant::now() + Duration::from_secs(10);
    while cli(&master, "@1 show cli level") != "admin\n\n" {
        assert!(Instant::now() < end, "the master never forwarded `@1` to the worker");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!cli(&master, "@1 disable server be/s").contains("Permission denied"));
    assert_eq!(cli(&conf_sock, "show cli level"), "operator\n\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_further_stats_socket_gets_its_mode_and_a_bad_path_stops_the_start() {
    let dir = std::env::temp_dir().join(format!("ibex_t146x_{}", std::process::id()));
    let (a, b) = (dir.join("a.sock"), dir.join("b.sock"));
    let cfg = config(&dir, &format!("  stats socket {}\n  stats socket {} mode 640\n", a.display(), b.display()));
    let mut child = Ibex(Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn"));
    wait_for_socket(&b);
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&b).expect("stat").permissions().mode() & 0o777, 0o640);
    }
    common::stop(&mut child.0);

    let bad = config(&dir, &format!("  stats socket {}\n  stats socket /nonexistent-dir-t146/x.sock\n", a.display()));
    let status = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&bad).stdout(Stdio::null()).stderr(Stdio::null()).status().expect("run");
    assert!(!status.success(), "an unbindable stats socket must stop the start, as for the first one");
    let _ = std::fs::remove_dir_all(&dir);
}
