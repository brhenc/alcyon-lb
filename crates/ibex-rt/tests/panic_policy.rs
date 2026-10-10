// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A panic takes the whole process down (T238), as a `BUG_ON()` does in `HAProxy`.
//!
//! Before T238 a panicking worker unwound alone: the process served on without it, or, with
//! one worker, exited 0 so that `Restart=on-failure` did not restart it. The reproducer was
//! an `option ldap-check` backend answering `30` and closing, which indexed past the end of
//! the reply (fixed since; the hook is tested on its own below).
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
//! and the master's exit status is 134 (139 for SIGSEGV).

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const CHILD: &str = "IBEX_T238_PANIC_CHILD";

struct Ibex(Child);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// Aborted, or, in a coverage-instrumented run (which must write its profile), exit 134.
fn aborted(st: ExitStatus) -> bool {
    st.signal() == Some(6) || st.code() == Some(134)
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
        ibex_rt::crash::abort_on_panic();
        let _ = thread::spawn(|| panic!("t238 deliberate panic")).join();
        // Reached only if the panic did not take the process down.
        thread::sleep(Duration::from_secs(2));
        std::process::exit(0);
    }
    no_core_dumps();
    let out = Command::new(std::env::current_exe().expect("exe"))
        .args(["--exact", "a_panic_on_any_thread_aborts_the_process", "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("re-run this test");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(aborted(out.status), "not aborted: {:?}\n{err}", out.status);
    assert!(err.contains("t238 deliberate panic"), "the standard panic message is kept:\n{err}");
    assert!(err.contains("[ALERT] ibex: a thread panicked"), "{err}");
}

/// The process ibex -W started as its worker.
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

/// Under -W with a master CLI (-S) ibex runs a master process and a worker process, as
/// `HAProxy` does; the master treats a worker that died of SIGABRT as `HAProxy`'s does: it stops
/// everything and exits 134.
#[test]
fn master_exits_134_when_its_worker_aborts() {
    let dir = tempfile::TempDir::new().expect("tmp");
    let front = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode tcp\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
         frontend f\n  bind {front}\n  default_backend b\nbackend b\n  server s 127.0.0.1:9\n"
    );
    let path = dir.path().join("ibex.cfg");
    std::fs::write(&path, cfg).expect("write cfg");
    no_core_dumps();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .args(["-W", "-db", "-S"])
        .arg(dir.path().join("master.sock"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ibex -W");
    let mut ibex = Ibex(child);
    // Everything the master writes, line by line; the worker is killed once the master has
    // counted it loaded (killed before that, it is a failed load, not a dead worker).
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let stderr = ibex.0.stderr.take().expect("stderr");
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
    let worker = worker_of(ibex.0.id()).expect("the master has a worker");
    let pid = rustix::process::Pid::from_raw(i32::try_from(worker).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::Abort).expect("kill -ABRT");
    let st = wait_exit(&mut ibex.0, Duration::from_secs(5)).expect("the master exits");
    while let Ok(l) = rx.recv_timeout(Duration::from_millis(500)) {
        err.push_str(&l);
        err.push('\n');
    }
    assert_eq!(st.code(), Some(134), "{err}");
    assert!(err.contains(&format!("Current worker ({worker}) exited with code 134 (Aborted)")), "{err}");
    assert!(err.contains("All workers exited. Exiting... (134)"), "{err}");
}

/// The T238 reproducer, end to end: an LDAP server that answers `30` and closes.
fn ldap_answers_30(mut s: TcpStream) {
    s.set_read_timeout(Some(Duration::from_secs(1))).ok();
    let mut b = [0u8; 256];
    let _ = s.read(&mut b);
    let _ = s.write_all(&[0x30]);
}

#[test]
fn a_worker_panic_aborts_ibex() {
    let backend = TcpListener::bind("127.0.0.1:0").expect("bind");
    let baddr = backend.local_addr().unwrap();
    thread::spawn(move || {
        for s in backend.incoming().flatten() {
            thread::spawn(move || ldap_answers_30(s));
        }
    });
    let dir = tempfile::TempDir::new().expect("tmp");
    let front = common::reserve_addr();
    let cfg = format!(
        "global\n  nbthread 2\ndefaults\n  mode tcp\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n  \
         timeout check 1s\nfrontend f\n  bind {front}\n  default_backend b\nbackend b\n  option ldap-check\n  \
         server s {baddr} check inter 200ms\n"
    );
    let path = dir.path().join("ibex.cfg");
    std::fs::write(&path, cfg).expect("write cfg");
    no_core_dumps();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ibex");
    let mut ibex = Ibex(child);
    let st = wait_exit(&mut ibex.0, Duration::from_secs(5));
    let mut err = String::new();
    if st.is_some() {
        let _ = ibex.0.stderr.take().map(|mut e| e.read_to_string(&mut err));
    }
    let st = st.expect("ibex still running 5s after a worker panicked");
    assert!(aborted(st), "not aborted: {st:?}\n{err}");
}
