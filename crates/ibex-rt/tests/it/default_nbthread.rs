// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Default `nbthread` (T208). Measured on HAProxy 3.5-dev8-885761-29: with no `nbthread`
//! line, `show info` Nbthread is the number of CPUs in the affinity mask (64 plain,
//! 4 under `taskset -c 0-3`, 1 under `taskset -c 0`); an explicit `nbthread 2` wins (2);
//! the default is capped at MAX_THREADS_DEFAULT (64), an explicit value is not.

use crate::common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Ibex {
    child: Child,
    sock: std::path::PathBuf,
    dir: std::path::PathBuf,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start(cpus: &str, nbthread: Option<u32>) -> Ibex {
    let addr = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("ibex_t208_{}_{}", std::process::id(), addr.port()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sock = dir.join("s.sock");
    let nb = nbthread.map(|n| format!("  nbthread {n}\n")).unwrap_or_default();
    let cfg = format!(
        "global\n{nb}  stats socket {} level admin\ndefaults\n  mode http\n  timeout client 5s\n  timeout connect 1s\n  timeout server 5s\nfrontend f\n  bind {addr}\n",
        sock.display()
    );
    std::fs::write(dir.join("cfg"), cfg).expect("cfg");
    // taskset execs, so the child's pid is the ibex process.
    let child = Command::new("taskset")
        .args(["-c", cpus, env!("CARGO_BIN_EXE_ibex"), "-f"])
        .arg(dir.join("cfg"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let ibex = Ibex { child, sock, dir };
    assert!(common::wait_listening(addr));
    let end = Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(&ibex.sock).is_err() {
        assert!(Instant::now() < end, "the stats socket never came up");
        std::thread::sleep(Duration::from_millis(25));
    }
    ibex
}

fn nbthread(i: &Ibex) -> String {
    let mut s = UnixStream::connect(&i.sock).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(b"show info\n").expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out.lines().find_map(|l| l.strip_prefix("Nbthread: ").map(str::to_string)).unwrap_or_default()
}

/// Number of threads in /proc/<pid>/task.
fn tasks(i: &Ibex) -> usize {
    std::fs::read_dir(format!("/proc/{}/task", i.child.id())).expect("task dir").count()
}

#[test]
fn default_follows_affinity_mask() {
    let i = start("0-3", None);
    assert_eq!(nbthread(&i), "4");
    // Worker threads plus however many helper threads ibex runs; printed so the report can say.
    let t = tasks(&i);
    eprintln!("threads in /proc/<pid>/task: {t}");
    assert!(t >= 4, "at least one thread per Nbthread, got {t}");
}

#[test]
fn default_single_cpu_is_one() {
    let i = start("0", None);
    assert_eq!(nbthread(&i), "1");
}

#[test]
fn explicit_nbthread_overrides_the_mask() {
    let i = start("0-3", Some(2));
    assert_eq!(nbthread(&i), "2");
}
