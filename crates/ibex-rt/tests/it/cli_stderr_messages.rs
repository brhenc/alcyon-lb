// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T342: the command-line and startup diagnostics ibex prints on stderr.
//!
//! They are written through `stderr_line!` (a full non-blocking stderr drops a message
//! instead of aborting the process), so each one is pinned here: the text and the exit
//! status. The texts are Ibex's own: HAProxy (3.5-dev8-885761-29) words most of these
//! differently (`-f` with no argument is "failed to copy argv.", an unknown option prints
//! the usage on stdout, `-n abc` is accepted), but it too exits 1 for a missing argument,
//! an unknown option and an unreachable `-C` directory.

use crate::common;

use std::io::Read;
use std::process::{Command, Stdio};

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
    let (code, err) = run(&["-dr", "-de", "-dp", "-dM", "-f", "CFG", "-c"]);
    assert_eq!(code, Some(0), "{err}");
    for want in [
        "[DIAG] Flag -dr: ignoring server address resolution failures.",
        "[DIAG] Flag -de: disabling epoll poller (falling back to standard poll).",
        "[DIAG] Flag -dp: disabling poll poller.",
        "[DIAG] Flag -dM: memory pool debugging active.",
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
