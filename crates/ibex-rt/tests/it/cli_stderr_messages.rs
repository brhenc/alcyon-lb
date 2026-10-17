// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T342: the command-line and startup diagnostics ibex prints on stderr.
//!
//! They are written through `stderr_line!` (a full non-blocking stderr drops a message
//! instead of aborting the process), so each one is pinned here: the text and the exit
//! status. The texts are Ibex's own: `HAProxy` (3.5-dev8-885761-29) words most of these
//! differently (`-f` with no argument is "failed to copy argv.", an unknown option prints
//! the usage on stdout, `-n abc` is accepted), but it too exits 1 for a missing argument,
//! an unknown option and an unreachable `-C` directory.

use crate::common;

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

const CFG: &str = "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n\
                   frontend fe\n  bind 127.0.0.1:0\n  http-request return status 200\n";

fn run(args: &[&str]) -> (Option<i32>, String) {
    let dir = std::path::PathBuf::from(format!("/tmp/t342b-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("c.cfg");
    std::fs::write(&cfg, CFG).unwrap();
    let args: Vec<String> = args.iter().map(|a| a.replace("CFG", &cfg.display().to_string())).collect();
    let out = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .expect("run ibex");
    (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn bad_command_lines_say_why_and_exit_1() {
    let cases: &[(&[&str], &str)] = &[
        (&["-f"], "Option -f expects a configuration file/directory path argument."),
        (&["-cc"], "Option -cc expects a condition expression."),
        (&["-C"], "Option -C expects a directory path argument."),
        (&["-p"], "Option -p expects a pidfile path argument."),
        (&["-x"], "Option -x requires a unix socket path"),
        (&["-S"], "Option -S expects a socket path argument."),
        (&["-n"], "Option -n expects an integer argument (maxconn)."),
        (&["-N"], "Option -N expects an integer argument (maxpconn)."),
        (&["-m"], "Option -m expects an integer argument (megabytes)."),
        (&["-n", "abc", "-f", "CFG", "-c"], "Option -n: invalid integer argument 'abc'"),
        (&["-m", "abc", "-f", "CFG", "-c"], "Option -m: invalid integer argument 'abc'"),
        (&["-Z"], "Unknown option: -Z"),
        (&["-c"], "Error: No configuration file specified. Use -f <path>."),
        (&["-C", "/nonexistent", "-f", "CFG", "-c"], "Cannot change directory to '/nonexistent'"),
        (&["-p", "/nonexistent/d/pid", "-f", "CFG"], "Cannot create pidfile '/nonexistent/d/pid'"),
        (&["-f", "CFG", "-x", "/nonexistent/sock"], "Failed to get the sockets from the old process!"),
    ];
    for (args, want) in cases {
        let (code, err) = run(args);
        assert!(err.contains(want), "{args:?}: wanted {want:?} in {err:?}");
        assert_eq!(code, Some(1), "{args:?}: {err:?}");
    }
}

#[test]
fn debug_flags_announce_themselves() {
    let (code, err) = run(&["-dr", "-de", "-dp", "-f", "CFG", "-c"]);
    assert_eq!(code, Some(0), "{err}");
    for want in [
        "[DIAG] Flag -dr: ignoring server address resolution failures.",
        "[DIAG] Flag -de: disabling epoll poller (falling back to standard poll).",
        "[DIAG] Flag -dp: disabling poll poller.",
    ] {
        assert!(err.contains(want), "{want:?} missing from {err:?}");
    }
}

/// `-sf` naming a process ibex may not signal (pid 1) and `-m` above the hard address-space
/// limit: both are warnings, the proxy starts anyway.
#[test]
fn signal_and_memory_limit_failures_warn_and_start() {
    let dir = std::path::PathBuf::from(format!("/tmp/t342b-cli2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("c.cfg");
    let addr = common::reserve_addr();
    std::fs::write(&cfg, CFG.replace("127.0.0.1:0", &addr.to_string())).unwrap();
    let script = format!(
        "ulimit -S -H -v 3000000; exec {} -m 4096 -sf 1 -f {}",
        env!("CARGO_BIN_EXE_ibex"),
        cfg.display()
    );
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(script).stderr(Stdio::piped()).stdout(Stdio::null());
    let mut ibex = common::Ibex(cmd.spawn().expect("spawn"));
    assert!(common::wait_listening(addr), "ibex did not start");
    let mut err = ibex.stderr.take().unwrap();
    common::stop(&mut ibex);
    let mut text = String::new();
    err.read_to_string(&mut text).unwrap();
    assert!(text.contains("[WARNING] Unable to enforce memory limit (-m 4096 MB):"), "{text:?}");
    assert!(text.contains("[WARNING] Failed to send signal Usr1 to PID 1:"), "{text:?}");
}

fn write_cfg(tag: &str, addr: std::net::SocketAddr) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(format!("/tmp/t342b-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("c.cfg");
    std::fs::write(&cfg, CFG.replace("127.0.0.1:0", &addr.to_string())).unwrap();
    cfg
}

/// `-D` whose pidfile cannot be written, and a `-D` that cannot start the daemon.
#[test]
fn daemon_mode_failures_are_reported() {
    let (code, err) = run(&["-D", "-p", "/nonexistent/d/pid", "-f", "CFG"]);
    assert!(err.contains("Cannot create pidfile '/nonexistent/d/pid'"), "{err:?}");
    assert_eq!(code, Some(1));
    // A process limit of 1 (the user already runs more) makes the daemon's fork fail.
    let cfg = write_cfg("daemon", common::reserve_addr());
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("ulimit -S -u 1; exec {} -D -f {}", env!("CARGO_BIN_EXE_ibex"), cfg.display()))
        .stdin(Stdio::null())
        .output()
        .expect("sh");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Failed to daemonize:"), "{err:?}");
    assert_eq!(out.status.code(), Some(1));
}

/// `no <keyword>` that is neither `no log` nor `no option`: ibex warns and ignores it.
/// `HAProxy` (3.5-dev8-885761-29) refuses an unknown one ("unknown keyword") -- a known
/// gap, pinned here so that the warning, now written through `stderr_line!`, is executed.
#[test]
fn an_ignored_no_directive_is_announced() {
    let dir = std::path::PathBuf::from(format!("/tmp/t342b-no-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("c.cfg");
    std::fs::write(&cfg, CFG.replace("http-request", "no foo\n  http-request")).unwrap();
    let (code, err) = run(&["-c", "-f", &cfg.display().to_string()]);
    assert!(err.contains("[ibex] warning: ignored 'no foo'"), "{err:?}");
    assert_eq!(code, Some(0));
}

fn start_w(args: &[&str], envs: &[(&str, &str)], exe: &std::path::Path, addr: std::net::SocketAddr) -> (common::Ibex, std::process::ChildStderr) {
    let mut cmd = Command::new(exe);
    cmd.args(args).stderr(Stdio::piped()).stdout(Stdio::null());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut ibex = common::Ibex(cmd.spawn().expect("spawn"));
    assert!(common::wait_listening(addr), "ibex did not start");
    let err = ibex.stderr.take().unwrap();
    (ibex, err)
}

#[test]
fn a_systemd_notify_failure_warns_and_serves() {
    let addr = common::reserve_addr();
    let cfg = write_cfg("notify", addr);
    let exe = std::path::Path::new(env!("CARGO_BIN_EXE_ibex"));
    let (mut ibex, mut err) =
        start_w(&["-Ws", "-f", &cfg.display().to_string()], &[("NOTIFY_SOCKET", "/nonexistent/notify")], exe, addr);
    common::stop(&mut ibex);
    let mut text = String::new();
    err.read_to_string(&mut text).unwrap();
    assert!(text.contains("[WARNING] systemd notify failed:"), "{text:?}");
}

/// A reload that cannot start its new process (the binary is gone) says so and the old
/// process keeps serving.
#[test]
fn a_reload_that_cannot_start_a_process_is_reported() {
    let addr = common::reserve_addr();
    let cfg = write_cfg("rlfail", addr);
    let exe = std::path::PathBuf::from(format!("{}-t342b-{}", env!("CARGO_BIN_EXE_ibex"), std::process::id()));
    std::fs::hard_link(env!("CARGO_BIN_EXE_ibex"), &exe).expect("hard link the binary");
    let (mut ibex, mut err) = start_w(&["-W", "-f", &cfg.display().to_string()], &[], &exe, addr);
    std::fs::remove_file(&exe).unwrap();
    let pid = rustix::process::Pid::from_raw(i32::try_from(ibex.id()).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::Usr2).unwrap();
    std::thread::sleep(Duration::from_millis(800));
    assert!(ibex.try_wait().unwrap().is_none(), "the old process must keep running");
    assert!(common::wait_listening(addr));
    common::stop(&mut ibex);
    let mut text = String::new();
    err.read_to_string(&mut text).unwrap();
    assert!(text.contains("[ALERT] reload failed to start a new process:"), "{text:?}");
}

/// A client of the reload's private socket that asks for the sockets and leaves: the old
/// process reports that it could not hand them over, and keeps serving.
#[test]
fn a_failed_socket_handover_is_reported() {
    use std::io::Write;
    let addr = common::reserve_addr();
    let cfg = write_cfg("handover", addr);
    let exe = std::path::Path::new(env!("CARGO_BIN_EXE_ibex"));
    let (mut ibex, mut err) = start_w(&["-W", "-f", &cfg.display().to_string()], &[], exe, addr);
    let sock = std::env::temp_dir().join(format!("ibex-reload-{}-0", ibex.id())).join("s");
    let pid = rustix::process::Pid::from_raw(i32::try_from(ibex.id()).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::Usr2).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(mut s) = std::os::unix::net::UnixStream::connect(&sock) {
            s.write_all(b"_getsocks\n").unwrap();
            break;
        }
        assert!(std::time::Instant::now() < deadline, "the reload socket never appeared");
        std::thread::sleep(Duration::from_millis(1));
    }
    std::thread::sleep(Duration::from_secs(2));
    common::stop(&mut ibex);
    let mut text = String::new();
    err.read_to_string(&mut text).unwrap();
    assert!(text.contains("[ALERT] could not hand the listening sockets over:"), "{text:?}");
}

/// T351: `-dM` (HAProxy: poison pool memory) has no Ibex equivalent, so every form is refused
/// with a message naming the option instead of printing a banner and doing nothing.
#[test]
fn dm_is_refused_in_every_form() {
    for flag in ["-dM", "-dMhelp", "-dM0x55", "-dMfail", "-dMno-cache"] {
        let (code, err) = run(&[flag, "-f", "CFG", "-c"]);
        assert_eq!(code, Some(1), "{flag}: {err:?}");
        assert!(err.contains("-dM") && err.contains("not supported"), "{flag}: {err:?}");
    }
}
