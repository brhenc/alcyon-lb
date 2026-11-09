// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T260): sets RLIMIT_CORE 0 for the test process and re-executes itself by test name

//! A panic takes the whole process down (T238), as a `BUG_ON()` does in `HAProxy`.
//!
//! Before T238 a panicking worker unwound alone: the process served on without it, or, with
//! one worker, exited 0 so that `Restart=on-failure` did not restart it. The reproducer was
//! an `option ldap-check` backend answering `30` and closing, which indexed past the end of
//! the reply: with the hook, alcyon died of SIGABRT within one check interval. That panic is
//! fixed (tests/check_malformed_replies.rs), so the hook is tested on its own below.
//!
//! (Plain `-W` is one process here, reloading in place: the hook aborts it, and the service
//! manager sees SIGABRT.) Measured on `HAProxy` 3.5-dev8-885761-29 (2026-10-10), `-W -db`,
//! `kill -ABRT <worker>`:
//!
//! ```text
//! [ALERT]    (M) : Current worker (W) exited with code 134 (Aborted)
//! [ALERT]    (M) : exit-on-failure: killing every processes with SIGTERM
//! [WARNING]  (M) : All workers exited. Exiting... (134)
//! ```
//! and the master's exit status is 134 (139 for SIGSEGV, 137 with `Killed` for SIGKILL).
//!
//! No test here makes a process die of SIGABRT: every such death is a crash report on the
//! developer's desktop (systemd-coredump journals it even with `RLIMIT_CORE` 0). The master
//! test kills its worker with SIGKILL, which dumps nothing and goes through the same path;
//! the hook test runs its child with `LLVM_PROFILE_FILE` set, under which the hook exits
//! 134 instead of aborting (see `crash::die`). The abort itself was checked by hand.

mod common;

use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const CHILD: &str = "ALCYON_T238_PANIC_CHILD";

struct Alcyon(Child);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}


/// No core files: an aborting debug build would spend seconds writing one (and fill
/// `coredumpctl`). Inherited by the processes this test starts.
fn no_core_dumps() {
    let _ = rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit { current: Some(0), maximum: Some(0) },
    );
}

fn wait_exit(child: &mut Child, within: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Ok(Some(st)) = child.try_wait() {
            return Some(st);
        }
        thread::sleep(Duration::from_millis(20));
    }
    None
}

/// The hook itself: a panic on a thread other than main aborts the process while main
/// still runs (as `supervise` does, waiting on its workers).
#[test]
fn a_panic_on_any_thread_aborts_the_process() {
    if std::env::var_os(CHILD).is_some() {
        alcyon_rt::crash::abort_on_panic();
        let _ = thread::spawn(|| panic!("t238 deliberate panic")).join();
        // Reached only if the panic did not take the process down.
        thread::sleep(Duration::from_secs(2));
        std::process::exit(0);
    }
    no_core_dumps();
    // An instrumented run keeps its own profile path; otherwise any path will do, nothing
    // is written to it.
    let profile = std::env::var_os("LLVM_PROFILE_FILE").unwrap_or_else(|| "/tmp/alcyon-t238-%p.profraw".into());
    let out = Command::new(std::env::current_exe().expect("exe"))
        .args(["--exact", "a_panic_on_any_thread_aborts_the_process", "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .env("LLVM_PROFILE_FILE", profile)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("re-run this test");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(134), "the process did not go down: {:?}\n{err}", out.status);
    assert_eq!(out.status.signal(), None);
    assert!(err.contains("t238 deliberate panic"), "the standard panic message is kept:\n{err}");
    assert!(err.contains("[ALERT] alcyon: a thread panicked"), "{err}");
}

/// The process alcyon -W started as its worker.
fn worker_of(master: u32) -> Option<u32> {
    for e in std::fs::read_dir("/proc").ok()?.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
        // pid (comm) state ppid ...: comm may hold spaces, so split after the last ')'.
        let ppid = stat.rsplit_once(')').and_then(|(_, rest)| rest.split_whitespace().nth(1)?.parse::<u32>().ok());
        if ppid == Some(master) {
            return Some(pid);
        }
    }
    None
}

/// Under -W with a master CLI (-S) alcyon runs a master process and a worker process, as
/// `HAProxy` does; the master treats a worker killed by a signal as `HAProxy`'s does: it
/// stops everything and exits 128 + the signal.
#[test]
fn master_exits_when_its_worker_dies_of_a_signal() {
    let dir = tempfile::TempDir::new().expect("tmp");
    let front = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode tcp\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
         frontend f\n  bind {front}\n  default_backend b\nbackend b\n  server s 127.0.0.1:9\n"
    );
    let path = dir.path().join("alcyon.cfg");
    std::fs::write(&path, cfg).expect("write cfg");
    no_core_dumps();
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .args(["-W", "-db", "-S"])
        .arg(dir.path().join("master.sock"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn alcyon -W");
    let mut alcyon = Alcyon(child);
    // Everything the master writes, line by line; the worker is killed once the master has
    // counted it loaded (killed before that, it is a failed load, not a dead worker).
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let stderr = alcyon.0.stderr.take().expect("stderr");
    thread::spawn(move || {
        for line in std::io::BufRead::lines(std::io::BufReader::new(stderr)).map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let mut err = String::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !err.contains("Loading success.") && Instant::now() < deadline {
        if let Ok(l) = rx.recv_timeout(Duration::from_millis(100)) {
            err.push_str(&l);
            err.push('\n');
        }
    }
    assert!(err.contains("Loading success."), "the worker never loaded:\n{err}");
    let worker = worker_of(alcyon.0.id()).expect("the master has a worker");
    let pid = rustix::process::Pid::from_raw(i32::try_from(worker).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::Kill).expect("kill -KILL");
    let st = wait_exit(&mut alcyon.0, Duration::from_secs(5)).expect("the master exits");
    while let Ok(l) = rx.recv_timeout(Duration::from_millis(500)) {
        err.push_str(&l);
        err.push('\n');
    }
    assert_eq!(st.code(), Some(137), "{err}");
    assert!(err.contains(&format!("Current worker ({worker}) exited with code 137 (Killed)")), "{err}");
    assert!(err.contains("exit-on-failure: killing every processes with SIGTERM"), "{err}");
    assert!(err.contains("All workers exited. Exiting... (137)"), "{err}");
}
