// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `-m <megs>` as `HAProxy` means it: a budget that sizes `maxconn`, shown as `Memmax_MB` and
//! `Memmax_bytes`, and `RLIMIT_DATA` soft and hard (T465b; never `RLIMIT_AS`). Every expected value was measured on `haproxy` 3.5-dev8-885761-29
//! (2026-10-17, `nbthread 1`, `tune.bufsize` 16384):
//!
//! | config                         | `-m` | Maxconn | Memmax_bytes | other                           |
//! |--------------------------------|------|---------|--------------|---------------------------------|
//! | cleartext bind                 | 64   | 1800    | 67108864     | Hard_maxconn 1800               |
//! | cleartext bind                 | 8    | 220     | 8388608      |                                 |
//! | `bind ... ssl crt`             | 64   | 470     |              | `[NOTICE] Automatically setting global.maxconn to 470 and global.maxsslconn to 470.` |
//! | `bind ... ssl crt`             | 8    | 32      |              |                                 |
//! | cleartext, `maxconn 100000`    | 64   | 100000  |              | loads                           |
//! | `bind ... ssl crt`, `maxconn 100000` | 64 | exit 1 | | `[ALERT] Cannot compute the automatic maxsslconn because global.maxconn is already too high for the global.memmax value (64 MB). The absolute maximum possible value without SSL is 1713, but 100000 was found and SSL is in use.` |

use crate::common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};

const DIR: &str = "/tmp/mem-show-info";

struct Run {
    child: Child,
    sock: String,
}

impl Drop for Run {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
    }
}

fn pem() -> String {
    std::fs::create_dir_all(DIR).unwrap();
    let path = format!("{DIR}/memmax-{}.pem", std::process::id());
    let key = rcgen::KeyPair::generate().unwrap();
    let c = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap().self_signed(&key).unwrap();
    std::fs::write(&path, format!("{}{}", c.pem(), key.serialize_pem())).unwrap();
    path
}

fn config(name: &str, port: u16, tls: bool, global_extra: &str) -> (String, String) {
    std::fs::create_dir_all(DIR).unwrap();
    let sock = format!("{DIR}/{name}-{}.sock", std::process::id());
    let ssl = if tls { format!(" ssl crt {}", pem()) } else { String::new() };
    let cfg = format!("{DIR}/{name}-{}.cfg", std::process::id());
    std::fs::write(
        &cfg,
        format!(
            "global\n  nbthread 1\n  stats socket {sock} level admin\n{global_extra}\
             defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n\
             frontend f\n  bind 127.0.0.1:{port}{ssl}\n  http-request return status 200 content-type text/plain string ok\n"
        ),
    )
    .unwrap();
    (cfg, sock)
}

fn spawn(megs: &str, cfg: &str, sock: String, port: u16) -> Run {
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .args(["-m", megs, "-f", cfg])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn ibex");
    let run = Run { child, sock };
    assert!(common::wait_listening(format!("127.0.0.1:{port}").parse().unwrap()), "ibex never listened");
    run
}

fn show_info(sock: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("stats socket");
    s.write_all(b"show info\n").unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

fn field(info: &str, name: &str) -> String {
    info.lines().find_map(|l| l.strip_prefix(&format!("{name}: "))).unwrap_or_else(|| panic!("no {name} in {info}")).to_string()
}

fn check(name: &str, port: u16, tls: bool, megs: &str, maxconn: &str, bytes: &str) {
    let (cfg, sock) = config(name, port, tls, "");
    let run = spawn(megs, &cfg, sock, port);
    let info = show_info(&run.sock);
    assert_eq!(field(&info, "Memmax_MB"), megs, "{info}");
    assert_eq!(field(&info, "Memmax_bytes"), bytes, "{info}");
    assert_eq!(field(&info, "Maxconn"), maxconn, "{info}");
    assert_eq!(field(&info, "Hard_maxconn"), maxconn, "{info}");
}

#[test]
fn m64_cleartext() {
    check("m64", common::reserve_port(), false, "64", "1800", "67108864");
}

#[test]
fn m8_cleartext() {
    check("m8", common::reserve_port(), false, "8", "220", "8388608");
}

#[test]
fn m64_tls() {
    check("m64tls", common::reserve_port(), true, "64", "470", "67108864");
}

#[test]
fn m8_tls() {
    check("m8tls", common::reserve_port(), true, "8", "32", "8388608");
}

#[test]
fn explicit_maxconn_cleartext_is_kept() {
    let port = common::reserve_port();
    let (cfg, sock) = config("m64mc", port, false, "  maxconn 100000\n");
    let run = spawn("64", &cfg, sock, port);
    let info = show_info(&run.sock);
    assert_eq!(field(&info, "Maxconn"), "100000", "{info}");
    assert_eq!(field(&info, "Memmax_MB"), "64", "{info}");
}

/// A configured `maxconn` that leaves room for the TLS connections is kept (the oracle,
/// `-m 64`, `maxconn 100`, one `bind ... ssl`: `Maxconn: 100`, `Hard_maxconn: 100`).
#[test]
fn explicit_maxconn_with_room_for_tls_is_kept() {
    let port = common::reserve_port();
    let (cfg, sock) = config("m64mctls", port, true, "  maxconn 100\n");
    let run = spawn("64", &cfg, sock, port);
    let info = show_info(&run.sock);
    assert_eq!(field(&info, "Maxconn"), "100", "{info}");
    assert_eq!(field(&info, "Hard_maxconn"), "100", "{info}");
    assert_eq!(field(&info, "Memmax_MB"), "64", "{info}");
}

/// A budget that cannot hold one connection of the configured buffer size is refused with
/// the oracle's alert (`-m 1`, `tune.bufsize 2000000`, cleartext: exit 1, "The absolute
/// maximum possible value is 10, but 0 was found.").
#[test]
fn budget_too_small_for_one_connection_is_refused() {
    let port = common::reserve_port();
    let (cfg, _sock) = config("m1big", port, false, "  tune.bufsize 2000000\n");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).args(["-m", "1", "-f", &cfg]).output().expect("run ibex");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {err}");
    assert!(
        err.contains("Cannot compute the automatic maxconn because global.maxsslconn is already too high for the global.memmax value (1 MB). The absolute maximum possible value is 10, but 0 was found."),
        "stderr: {err}"
    );
}

#[test]
fn explicit_maxconn_too_high_for_tls_is_refused() {
    let (cfg, _sock) = config("m64refuse", common::reserve_port(), true, "  maxconn 100000\n");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).args(["-m", "64", "-f", &cfg]).output().expect("run ibex");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {err}");
    assert!(
        err.contains(
            "Cannot compute the automatic maxsslconn because global.maxconn is already too high for the global.memmax value (64 MB). The absolute maximum possible value without SSL is 1713, but 100000 was found and SSL is in use."
        ),
        "stderr: {err}"
    );
}

/// `-m 8` used to be `setrlimit(RLIMIT_AS, 8 MB)`: the worker died of `memory allocation of
/// N bytes failed` (exit 134) under 200 connections. `HAProxy` sets `RLIMIT_DATA` to 8 MiB (its
/// `VmData` is already 43 MB then); its `maxconn` is 220 and it serves all 200 (measured 2026-10-25).
/// Ibex does the same, under the same limit.
#[test]
fn m8_with_200_keepalive_connections_does_not_abort() {
    let port = common::reserve_port();
    let (cfg, sock) = config("m8abort", port, false, "");
    let mut run = spawn("8", &cfg, sock, port);
    let mut conns = Vec::new();
    for i in 0..200 {
        let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        c.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut buf = [0u8; 512];
        let n = c.read(&mut buf).unwrap_or(0);
        assert!(buf[..n].starts_with(b"HTTP/1.1 200"), "connection {i}: {:?}", String::from_utf8_lossy(&buf[..n]));
        conns.push(c);
    }
    assert!(run.child.try_wait().unwrap().is_none(), "ibex exited: {:?}", run.child.try_wait());
    let info = show_info(&run.sock);
    assert_eq!(field(&info, "Maxconn"), "220", "{info}");
    // The clients hang up first, so the TIME_WAIT entries are theirs and the port stays
    // bindable for the next run.
    drop(conns);
    std::thread::sleep(std::time::Duration::from_millis(300));
}

/// `-m N` sets `RLIMIT_DATA`, soft and hard, to N MiB, as `HAProxy` 3.5-dev8 does (measured:
/// `Max data size 67108864 67108864 bytes` for `-m 64`, 8388608 for `-m 8`; T465).
#[test]
fn m_sets_rlimit_data_soft_and_hard() {
    for (megs, bytes) in [("64", "67108864"), ("8", "8388608")] {
        let port = common::reserve_port();
        let (cfg, sock) = config(&format!("mlimit{megs}"), port, false, "");
        let run = spawn(megs, &cfg, sock, port);
        let limits = std::fs::read_to_string(format!("/proc/{}/limits", run.child.id())).expect("limits");
        let line = limits.lines().find(|l| l.starts_with("Max data size")).expect("Max data size");
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields[3..5], [bytes, bytes], "-m {megs}: {line}");
    }
}

/// A hard `RLIMIT_DATA` below the `-m` budget cannot be raised unprivileged: `HAProxy` 3.5-dev8
/// exits 1 with `[ALERT] ... : [haproxy.main()] Cannot fix MEM limit to 300 megs.` (measured
/// under `prlimit --data=200000000`; T465).
#[test]
fn m_above_the_hard_data_limit_is_refused() {
    let port = common::reserve_port();
    let (cfg, _sock) = config("mhard", port, false, "");
    let out = Command::new("prlimit")
        .args(["--data=200000000", env!("CARGO_BIN_EXE_ibex"), "-m", "300", "-f", &cfg])
        .output()
        .expect("prlimit");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {err}");
    assert!(err.contains("[haproxy.main()] Cannot fix MEM limit to 300 megs."), "stderr: {err}");
}

/// T508: under a very small `-m` the start either serves, with its watchdog, or is refused
/// with an `[ALERT]` and exit 1: never a panic or abort (exit 134, "failed to spawn thread"),
/// never a warning that lockup detection is off. HAProxy 3.5-dev8 serves at every `-m` from 1
/// to 8 (measured 2026-10-25, 503 from a dead server); its watchdog is a timer, Ibex's a thread.
#[test]
fn a_tiny_m_serves_or_refuses_cleanly() {
    for megs in 1..=8 {
        let port = common::reserve_port();
        let (cfg, sock) = config(&format!("tiny{megs}"), port, false, "");
        let errfile = format!("{DIR}/tiny{megs}-{}.err", std::process::id());
        let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
            .args(["-m", &megs.to_string(), "-f", &cfg])
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&errfile).unwrap())
            .spawn()
            .expect("spawn ibex");
        let mut run = Run { child, sock };
        let addr = format!("127.0.0.1:{port}").parse().unwrap();
        let start = std::time::Instant::now();
        let exited = loop {
            if let Some(st) = run.child.try_wait().unwrap() {
                break Some(st);
            }
            if std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(100)).is_ok() || start.elapsed().as_secs() > 10 {
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        let err = std::fs::read_to_string(&errfile).unwrap();
        let _ = std::fs::remove_file(&errfile);
        assert!(!err.contains("panicked") && !err.contains("disabling lockup"), "-m {megs}: stderr: {err}");
        if let Some(st) = exited {
            assert_eq!(st.code(), Some(1), "-m {megs}: {st:?} stderr: {err}");
            assert!(err.contains("[ALERT]") && err.contains("thread"), "-m {megs}: stderr: {err}");
        }
    }
}

/// A worker thread that cannot be created (`RLIMIT_NPROC` 1: the user already runs more than
/// one task, so every `clone` fails with EAGAIN, whatever the host's memory) fails the start
/// with the alert and exit 1, never a panic (T508; the path `-m` only reaches by chance).
#[test]
fn a_thread_that_cannot_be_created_fails_the_start_cleanly() {
    let port = common::reserve_port();
    let (cfg, _sock) = config("nproc", port, false, "");
    let out = Command::new("sh")
        .args(["-c", "ulimit -u 1 && exec \"$0\" -f \"$1\"", env!("CARGO_BIN_EXE_ibex"), &cfg])
        .stdout(Stdio::null())
        .output()
        .expect("run ibex");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {err}");
    assert!(err.contains("[ALERT]") && err.contains("Failed to create thread 0"), "stderr: {err}");
    assert!(!err.contains("panicked"), "stderr: {err}");
}
