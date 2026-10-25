// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T361: the thread watchdog (`HAProxy`'s src/wdt.c).
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29, nbthread 2, admin stats socket (tasks/T361):
//!
//! * `debug dev loop <ms>` needs `expert-mode on` ("This command is restricted to expert
//!   mode only."), which needs admin ("Permission denied" at operator);
//! * `expert-mode on; debug dev loop 3000`: `WARNING! thread 1 has stopped processing
//!   traffic for 201 milliseconds` and one more every 100 ms, then `PANIC! Thread 1 is
//!   about to kill the process (pid N).` about 1.2 s into the loop; exit status 134;
//! * 30 connections each running `debug dev loop 80` (2.5 s of work in short slices): no
//!   warning, the process lives;
//! * `debug dev loop 3000 warn` (the loop says it is under control): warnings, no panic.
//!
//! The dying process exits 134 through `crash::die`'s `LLVM_PROFILE_FILE` path rather
//! than SIGABRT, so the suite leaves no crash report (see `tests/panic_policy.rs`); the
//! abort itself is the same call the panic hook makes.

use crate::common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Ibex {
    child: Child,
    sock: PathBuf,
    dir: PathBuf,
    stderr: Arc<Mutex<String>>,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Ibex {
    fn stderr(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    /// Runs one command line on a new connection and returns the answer (until EOF).
    fn cli(&self, line: &str) -> String {
        let mut s = UnixStream::connect(&self.sock).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
        s.write_all(format!("{line}\n").as_bytes()).expect("write");
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    /// Sends one command line and does not wait for the answer.
    fn cli_send(&self, line: &str) -> UnixStream {
        let mut s = UnixStream::connect(&self.sock).expect("connect");
        s.write_all(format!("{line}\n").as_bytes()).expect("write");
        s
    }

    fn wait_exit(&mut self, within: Duration) -> Option<std::process::ExitStatus> {
        let end = Instant::now() + within;
        while Instant::now() < end {
            if let Ok(Some(st)) = self.child.try_wait() {
                return Some(st);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        None
    }
}

fn start(tag: &str) -> Ibex {
    start_with(tag, "")
}

fn start_with(tag: &str, global: &str) -> Ibex {
    let fe = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("ibex_t361_{tag}_{}_{}", std::process::id(), fe.port()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sock = dir.join("s.sock");
    let cfg = format!(
        "global\n  nbthread 2\n  stats socket {} level admin\n{global}defaults\n  mode http\n  timeout client 5s\n  timeout connect 1s\n  timeout server 5s\n\
         frontend f\n  bind {}\n  http-request return status 200\n",
        sock.display(),
        fe
    );
    std::fs::write(dir.join("cfg"), cfg).expect("cfg");
    // An instrumented run keeps its own profile path; otherwise any path will do.
    let profile = std::env::var_os("LLVM_PROFILE_FILE").unwrap_or_else(|| "/tmp/ibex-t361-%p.profraw".into());
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(dir.join("cfg"))
        .env("LLVM_PROFILE_FILE", profile)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let stderr = Arc::new(Mutex::new(String::new()));
    let mut pipe = child.stderr.take().expect("stderr");
    let sink = Arc::clone(&stderr);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = pipe.read(&mut buf) {
            if n == 0 {
                break;
            }
            sink.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });
    let end = Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(&sock).is_err() {
        assert!(Instant::now() < end, "the stats socket never came up");
        std::thread::sleep(Duration::from_millis(50));
    }
    Ibex { child, sock, dir, stderr }
}

fn blocked_warnings(ibex: &Ibex) -> u64 {
    let info = ibex.cli("show info");
    let line = info.lines().find(|l| l.starts_with("BlockedTrafficWarnings:")).unwrap_or_else(|| panic!("no BlockedTrafficWarnings in {info}"));
    line["BlockedTrafficWarnings:".len()..].trim().parse().expect("number")
}

#[test]
fn debug_dev_loop_needs_expert_mode_and_admin() {
    let ibex = start("levels");
    let cases: &[(&str, &str)] = &[
        ("debug dev loop 10", "This command is restricted to expert mode only.\n\n"),
        ("operator; expert-mode on; debug dev loop 10", "\nPermission denied\n\nThis command is restricted to expert mode only.\n\n"),
        // Going down a level leaves expert mode.
        ("expert-mode on; operator; debug dev loop 10", "\n\nThis command is restricted to expert mode only.\n\n"),
        ("expert-mode on; expert-mode off; debug dev loop 10", "\n\nThis command is restricted to expert mode only.\n\n"),
        ("expert-mode on", "\n"),
        ("expert-mode", "expert-mode is OFF\n\n"),
        ("expert-mode on; expert-mode", "\nexpert-mode is ON\n\n"),
        ("expert-mode on; debug dev loop", "\n\n"),
        ("expert-mode on; debug dev loop 20; show cli level", "\n\nadmin\n\n"),
    ];
    for (line, want) in cases {
        assert_eq!(ibex.cli(line), *want, "{line}");
    }
}

/// One worker spins: the process prints the warnings, then the panic, and exits 134, about
/// 1.2 s (of the thread's CPU time) into the stall. The loop would last 20 s.
#[test]
fn a_spinning_thread_aborts_the_process() {
    let mut ibex = start("spin");
    let pid = ibex.child.id();
    let t0 = Instant::now();
    let _conn = ibex.cli_send("expert-mode on; debug dev loop 20000");
    let status = ibex.wait_exit(Duration::from_secs(10));
    let took = t0.elapsed();
    let err = ibex.stderr();
    let status = status.unwrap_or_else(|| panic!("ibex still running 10 s into a 20 s spin; stderr: {err}"));
    assert!(status.code() == Some(134) || status.signal() == Some(6), "{status:?}; stderr: {err}");
    assert!(took < Duration::from_secs(6), "took {took:?}");
    assert!(err.contains("WARNING! thread 1 has stopped processing traffic for "), "{err}");
    assert!(err.contains("streams currently blocked, prevented from making any progress."), "{err}");
    assert!(err.contains(&format!("PANIC! Thread 1 is about to kill the process (pid {pid}).")), "{err}");
    let warn = err.find("WARNING! thread 1").unwrap();
    assert!(warn < err.find("PANIC!").unwrap(), "{err}");
}

/// 2.4 s of work on one worker, in 80 ms slices with the event loop running between them:
/// never reported, and the process lives.
#[test]
fn a_busy_thread_that_makes_progress_is_left_alone() {
    let mut ibex = start("busy");
    for _ in 0..30 {
        assert_eq!(ibex.cli("expert-mode on; debug dev loop 80"), "\n\n");
    }
    assert!(ibex.wait_exit(Duration::from_millis(300)).is_none(), "ibex exited: {}", ibex.stderr());
    assert_eq!(blocked_warnings(&ibex), 0);
    common::stop(&mut ibex.child);
    let err = ibex.stderr();
    assert!(!err.contains("WARNING! thread"), "{err}");
    assert!(!err.contains("PANIC!"), "{err}");
}

/// `debug dev loop <ms> warn` clears the stuck mark as it loops, as code that knows it is
/// long but under control does: every warning is printed, the process is not killed.
#[test]
fn a_loop_under_control_warns_and_lives() {
    let mut ibex = start("warn");
    assert_eq!(ibex.cli("expert-mode on; debug dev loop 1600 warn"), "\n\n");
    assert!(ibex.wait_exit(Duration::from_millis(200)).is_none(), "ibex exited: {}", ibex.stderr());
    let n = blocked_warnings(&ibex);
    assert!(n >= 5, "{n} warnings");
    let err = ibex.stderr();
    assert!(err.contains("WARNING! thread 1 has stopped processing traffic for "), "{err}");
    assert!(!err.contains("PANIC!"), "{err}");
}

/// `warn-blocked-traffic-after` (src/wdt.c:209): 1 to 1000 ms, `HAProxy`'s four texts
/// (measured with `haproxy -c`); words after the time are ignored, as `HAProxy` does.
#[test]
fn warn_blocked_traffic_after_is_checked() {
    let dir = std::env::temp_dir().join(format!("ibex_t361_kw_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let kw = "warn-blocked-traffic-after";
    let range = |a: &str| format!("timer out of range in argument '{a}' to '{kw}' (value must be between 1 and 1000 ms)");
    let cases: Vec<(&str, Option<String>)> = vec![
        ("", Some(format!("'{kw}' expects <time> as argument between 1 and 1000 ms."))),
        ("0", Some(range("0"))),
        ("1001", Some(range("1001"))),
        ("5s", Some(range("5s"))),
        ("0us", Some(range("0us"))),
        ("1m", Some(range("1m"))),
        ("1h", Some(range("1h"))),
        ("1d", Some(range("1d"))),
        ("abc", Some(format!("unexpected character 'a' in argument to <{kw}>."))),
        ("10x", Some(format!("unexpected character 'x' in argument to <{kw}>."))),
        ("0.5", Some(format!("unexpected character '.' in argument to <{kw}>."))),
        ("99999999999", Some(format!("timer overflow in argument '99999999999' to '{kw}' (maximum value is 1000 ms)"))),
        ("1", None),
        ("1000", None),
        ("1s", None),
        ("1000us", None),
        ("1001us", None),
        ("50ms", None),
        ("100 extra", None),
    ];
    for (arg, want) in cases {
        let cfg = dir.join("c.cfg");
        std::fs::write(
            &cfg,
            format!("global\n  {kw} {arg}\ndefaults\n  mode http\n  timeout client 1s\n  timeout server 1s\n  timeout connect 1s\nfrontend f\n  bind 127.0.0.1:0\n  http-request return status 200\n"),
        )
        .expect("cfg");
        let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&cfg).stdin(Stdio::null()).output().expect("run");
        let err = String::from_utf8_lossy(&out.stderr);
        match want {
            Some(msg) => {
                assert_eq!(out.status.code(), Some(1), "'{arg}': {err}");
                assert!(err.contains(&format!("parsing [{}:2] : {msg}", cfg.display())), "'{arg}': wanted {msg:?} in {err}");
            }
            None => assert_eq!(out.status.code(), Some(0), "'{arg}': {err}"),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The keyword reaches the monitor: at 20 ms an 80 ms loop is reported, at the default
/// 100 ms it is not (`a_busy_thread_that_makes_progress_is_left_alone`).
#[test]
fn warn_blocked_traffic_after_moves_the_warning() {
    let mut ibex = start_with("kw20", "  warn-blocked-traffic-after 20\n");
    // A report needs two looks of the monitor (every 20 ms) inside the stall, with 10 ms of the
    // worker's CPU time between them (the watchdog counts CPU time, not wall time). On a loaded
    // host the monitor can sleep through an 80 ms loop, or the worker get too little CPU in it,
    // so that loop goes unreported. The keyword is what makes a report possible at all (the
    // sibling test shows that 80 ms is never reported at the default, on an idle host): try the
    // 80 ms loop first, then longer ones (still under the 1 s of CPU that aborts the process),
    // and fail if none of them is reported.
    let mut n = 0;
    for ms in [80, 80, 160, 160, 320, 320, 640, 640] {
        assert_eq!(ibex.cli(&format!("expert-mode on; debug dev loop {ms}")), "\n\n");
        n = blocked_warnings(&ibex);
        if n >= 1 {
            break;
        }
    }
    assert!(n >= 1, "{}", ibex.stderr());
    common::stop(&mut ibex.child);
    assert!(ibex.stderr().contains("WARNING! thread 1 has stopped processing traffic for "));
}

/// `experimental-mode on|off` at the prompt answers with the prompt again, as `HAProxy`
/// does (measured: `\n> ` for `prompt` and for each of the two commands).
#[test]
fn experimental_mode_at_the_prompt_returns_the_prompt() {
    let mut ibex = start("expprompt");
    let mut s = UnixStream::connect(&ibex.sock).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    s.write_all(b"prompt\nexperimental-mode on\nexperimental-mode off\nquit\n").expect("write");
    let mut got = Vec::new();
    let _ = s.read_to_end(&mut got);
    assert_eq!(String::from_utf8_lossy(&got), "\n> \n> \n> ");
    common::stop(&mut ibex.child);
}

/// `ibex.watchdog-warn-only` (Ibex only; `HAProxy` 3.5-dev8-885761-29 refuses it as an unknown
/// keyword, measured with `haproxy -c`): the same spin that kills the process in
/// `a_spinning_thread_aborts_the_process` is warned about every tick, 1.2 s and beyond, and
/// the process stays alive and serves its CLI afterwards.
#[test]
fn watchdog_warn_only_warns_and_never_aborts() {
    let mut ibex = start_with("warnonly", "  ibex.watchdog-warn-only\n");
    let _conn = ibex.cli_send("expert-mode on; debug dev loop 3000");
    assert!(ibex.wait_exit(Duration::from_millis(3500)).is_none(), "ibex exited: {}", ibex.stderr());
    let n = blocked_warnings(&ibex);
    assert!(n >= 12, "{n} warnings");
    common::stop(&mut ibex.child);
    let err = ibex.stderr();
    assert!(err.contains("WARNING! thread 1 has stopped processing traffic for "), "{err}");
    assert!(!err.contains("PANIC!"), "{err}");
}

/// The keyword takes no argument.
#[test]
fn watchdog_warn_only_takes_no_argument() {
    let dir = std::env::temp_dir().join(format!("ibex_t361_wo_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("c.cfg");
    for (arg, ok) in [("", true), (" on", false)] {
        std::fs::write(&cfg, format!("global\n  ibex.watchdog-warn-only{arg}\nfrontend f\n  bind 127.0.0.1:0\n  mode http\n  http-request return status 200\n")).expect("cfg");
        let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&cfg).stdin(Stdio::null()).output().expect("run");
        let err = String::from_utf8_lossy(&out.stderr);
        if ok {
            assert_eq!(out.status.code(), Some(0), "{err}");
        } else {
            assert_eq!(out.status.code(), Some(1), "{err}");
            assert!(err.contains("parsing [") && err.contains(":2] : 'ibex.watchdog-warn-only' cannot handle unexpected argument 'on'."), "{err}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `debug dev loop <ms> isolated` stops every other thread in `HAProxy` (src/debug.c:1281);
/// Ibex has no thread isolation, so it refuses the form instead of running it unisolated.
#[test]
fn debug_dev_loop_isolated_is_refused() {
    let ibex = start("isolated");
    assert_eq!(
        ibex.cli("expert-mode on; debug dev loop 20 isolated"),
        "\n'debug dev loop ... isolated' is not supported: Ibex has no thread isolation.\n\n"
    );
}
