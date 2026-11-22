// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T659: an idle process does not wake. With no traffic `HAProxy` 3.5-dev11 makes no context
//! switch at all (`voluntary_ctxt_switches` of every thread stays put for 10 s, measured with
//! nbthread 1, 4 and 16, with a stats socket, and with a `check inter 2s` server); Alcyon
//! used to make ~23 a second per thread (a poll timeout of 100 ms, a watchdog tick of 100 ms,
//! the supervising thread's 20 ms nap).
//!
//! The test starts the process, lets it settle, sums the voluntary and involuntary context
//! switches of every thread (`/proc/<pid>/task/*/status`) over 5 s and asserts a ceiling per
//! thread per second. `IDLE_ORACLE=<haproxy>` runs it on `HAProxy`; the failure message prints
//! both rates. It reads the child's counters only, so no process-wide state of the test
//! process is involved and it does not need a binary of its own.

use crate::common;

use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Wakeups per thread per second an idle process may make. `HAProxy` makes none; the
/// remainder is the check timer (2 s) and the settle noise.
const CEILING_PER_THREAD_PER_S: f64 = 2.0;

struct Proc(Child, std::path::PathBuf);

impl Drop for Proc {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn oracle() -> Option<String> {
    std::env::var("IDLE_ORACLE").ok()
}

fn start(tag: &str, nbthread: usize, server: &str) -> Proc {
    let fe = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("alcyon_t659_{tag}_{}_{}", std::process::id(), fe.port()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let cfg = format!(
        "global\n  nbthread {nbthread}\n  stats socket {}/s.sock level admin\n\
         defaults\n  mode http\n  timeout connect 5s\n  timeout client 30s\n  timeout server 30s\n\
         frontend f\n  bind {fe}\n  default_backend b\nbackend b\n  {server}\n",
        dir.display()
    );
    std::fs::write(dir.join("cfg"), cfg).expect("cfg");
    let profile = std::env::var_os("LLVM_PROFILE_FILE").unwrap_or_else(|| "/tmp/alcyon-t659-%p.profraw".into());
    let bin = oracle().unwrap_or_else(|| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(bin)
        .arg("-f")
        .arg(dir.join("cfg"))
        .arg("-db")
        .env("LLVM_PROFILE_FILE", profile)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let sock = dir.join("s.sock");
    let end = std::time::Instant::now() + Duration::from_secs(10);
    while std::os::unix::net::UnixStream::connect(&sock).is_err() {
        assert!(std::time::Instant::now() < end, "the stats socket never came up");
        std::thread::sleep(Duration::from_millis(50));
    }
    Proc(child, dir)
}

/// Voluntary plus involuntary context switches summed over every thread, and the threads.
fn switches(pid: u32) -> (u64, usize) {
    let mut sum = 0;
    let mut threads = 0;
    for t in std::fs::read_dir(format!("/proc/{pid}/task")).expect("task dir").flatten() {
        let Ok(status) = std::fs::read_to_string(t.path().join("status")) else { continue };
        threads += 1;
        sum += status
            .lines()
            .filter(|l| l.starts_with("voluntary_ctxt_switches:") || l.starts_with("nonvoluntary_ctxt_switches:"))
            .filter_map(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
            .sum::<u64>();
    }
    (sum, threads)
}

fn idle_rate(p: &Proc) -> (f64, usize) {
    std::thread::sleep(Duration::from_secs(2));
    let (a, threads) = switches(p.0.id());
    std::thread::sleep(Duration::from_secs(5));
    let (b, _) = switches(p.0.id());
    ((b - a) as f64 / 5.0 / threads as f64, threads)
}

fn check(tag: &str, nbthread: usize, server: &str) {
    let p = start(tag, nbthread, server);
    let (rate, threads) = idle_rate(&p);
    eprintln!("{tag}: {threads} threads, {rate:.2} context switches per thread per second");
    assert!(
        rate <= CEILING_PER_THREAD_PER_S,
        "{tag}: an idle process made {rate:.2} context switches per thread per second over {threads} threads \
         (ceiling {CEILING_PER_THREAD_PER_S}; HAProxy makes none): something wakes it without a deadline"
    );
}

#[test]
fn an_idle_process_with_no_checks_does_not_wake() {
    check("a", 1, "server s1 127.0.0.1:9");
}

#[test]
fn an_idle_process_on_four_threads_does_not_wake() {
    check("d4", 4, "server s1 127.0.0.1:9");
}

#[test]
fn an_idle_process_with_a_two_second_check_wakes_only_for_the_check() {
    check("c", 1, "server s1 127.0.0.1:9 check inter 2s");
}

/// T659: `Engine::run_once` and `Engine::step` are single-step entry points used by callers
/// that interleave their own work on the same thread; unlike `Engine::run_loop`, an idle
/// step with no timers or events must return within the poll bound (100 ms) rather than
/// blocking forever in `epoll_wait(-1)`.
#[test]
fn run_once_and_step_return_within_poll_bound_when_idle() {
    use alcyon_rt::Engine;
    use alcyon_sched::Tick;
    let cfg = alcyon_config::parse_str("global\n").expect("parse");
    let (tx, rx) = std::sync::mpsc::channel();
    let h = std::thread::spawn(move || {
        let mut engine = Engine::new(&cfg, 64).expect("Engine::new");
        let _ = engine.run_once();
        let _ = engine.step(Tick(100));
        let _ = tx.send(());
    });
    assert!(
        rx.recv_timeout(Duration::from_secs(2)).is_ok(),
        "Engine::run_once / Engine::step blocked past the 100 ms poll bound when idle"
    );
    h.join().expect("join");
}
