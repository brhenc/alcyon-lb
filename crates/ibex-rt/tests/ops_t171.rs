// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Operations gaps found by T168 (T171): `-c` errors, the SIGTERM exit status and `-h | head`.
//!
//! Measured on `HAProxy 3.5-dev8-885761-29`, 2026-10-05:
//!
//! * `haproxy -c -f bad.cfg` prints `[ALERT]    (<pid>) : config : parsing [<file>:<line>] :
//!   <message>` per error, then `config : Error(s) found in configuration file : <file>`,
//!   and exits 1; `-f` naming a missing file is `config : Cannot open configuration
//!   file/directory <path> : No such file or directory`, also 1. With several files the line
//!   is the line in the file it is in, not in the merged text;
//! * `SIGTERM` to `haproxy -W` makes it exit 0 (its worker dies of it, the master reports it
//!   and exits 0); without `-W` the process dies of the signal (status 143); `SIGINT` dies of
//!   the signal either way.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

fn ibex() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ibex"))
}

fn check(files: &[(&str, &str)]) -> (i32, String) {
    let dir = tempfile::tempdir().expect("tmp dir");
    let mut cmd = ibex();
    cmd.arg("-c");
    for (name, text) in files {
        let path = dir.path().join(name);
        std::fs::write(&path, text).expect("write cfg");
        cmd.arg("-f").arg(&path);
    }
    let out = cmd.output().expect("run ibex -c");
    let text = String::from_utf8_lossy(&out.stderr).replace(&dir.path().display().to_string(), "<dir>");
    (out.status.code().expect("exit code"), text)
}

#[test]
fn check_names_file_and_line() {
    let cfg = "global\n  nbthread 1\ndefaults\n  mode http\nfrontend f\n  bind 127.0.0.1:0\n  bogus-keyword 1\n";
    let (rc, err) = check(&[("bad.cfg", cfg)]);
    assert_eq!(rc, 1, "{err}");
    let alerts: Vec<&str> = err.lines().collect();
    let first = alerts.first().copied().unwrap_or("");
    assert!(
        first.starts_with("[ALERT]    (") && first.contains(") : config : parsing [<dir>/bad.cfg:7] : unknown keyword 'bogus-keyword' in 'frontend' section"),
        "first line: {err}"
    );
    assert!(err.contains(" : config : Error(s) found in configuration file : <dir>/bad.cfg\n"), "{err}");
}

#[test]
fn check_line_is_relative_to_its_file() {
    let (rc, err) = check(&[("a.cfg", "defaults\n  mode http\n"), ("b.cfg", "frontend f\n  bind 127.0.0.1:0\n  oops\n")]);
    assert_eq!(rc, 1, "{err}");
    assert!(err.contains("parsing [<dir>/b.cfg:3] : unknown keyword 'oops'"), "{err}");
}

#[test]
fn check_missing_file() {
    let out = ibex().args(["-c", "-f", "/nonexistent/t171.cfg"]).output().expect("run");
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains(" : config : Cannot open configuration file/directory /nonexistent/t171.cfg : No such file or directory"), "{err}");
}

#[test]
fn check_unreadable_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tmp dir");
    let path = dir.path().join("secret.cfg");
    std::fs::write(&path, "global\n").expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0)).expect("chmod");
    if std::fs::read(&path).is_ok() {
        return; // running as root: nothing is unreadable
    }
    let out = ibex().arg("-c").arg("-f").arg(&path).output().expect("run");
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains(" : config : Cannot open configuration file/directory ") && err.contains("secret.cfg"), "{err}");
}

#[test]
fn check_valid_is_still_zero() {
    let (rc, err) = check(&[("ok.cfg", "global\n  nbthread 1\n")]);
    assert_eq!((rc, err.as_str()), (0, ""));
}

/// Starts `ibex <flags> -f <cfg>` on a minimal configuration and sends it SIGTERM once it
/// listens; returns how it ended: `(exit code, signal)`.
fn term(flags: &[&str], sig: rustix::process::Signal) -> (Option<i32>, Option<i32>) {
    use std::os::unix::process::ExitStatusExt;
    let fe = common::reserve_addr();
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    write!(f, "defaults\n  mode http\n  timeout client 2s\nfrontend f\n  bind {fe}\n  http-request return status 200\n").expect("cfg");
    let mut child = ibex().args(flags).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Ibex).expect("spawn");
    assert!(common::wait_listening(fe), "ibex never listened");
    std::thread::sleep(Duration::from_millis(300));
    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).expect("pid")).expect("pid");
    rustix::process::kill_process(pid, sig).expect("kill");
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(st) = child.try_wait().expect("wait") {
            return (st.code(), st.signal());
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return (None, None);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn sigterm_under_w_exits_zero() {
    assert_eq!(term(&["-W"], rustix::process::Signal::Term), (Some(0), None));
}

#[test]
fn sigterm_standalone_dies_of_the_signal() {
    assert_eq!(term(&[], rustix::process::Signal::Term), (None, Some(15)));
}

#[test]
fn help_to_a_closed_pipe_does_not_panic() {
    let mut child = ibex().arg("-h").stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn");
    drop(child.stdout.take());
    let out = child.wait_with_output().expect("wait");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("panicked"), "{err}");
    assert_eq!(out.status.code(), Some(0), "{err}");
}
