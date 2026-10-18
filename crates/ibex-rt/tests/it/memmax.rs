// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `-m <megs>` as `HAProxy` means it: a budget that sizes `maxconn`, shown as `Memmax_MB` and
//! `Memmax_bytes`, never an rlimit (past an `RLIMIT_AS` Rust aborts the process on the first
//! failed allocation). Every expected value was measured on `haproxy` 3.5-dev8-885761-29
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
/// N bytes failed` (exit 134) under 200 connections. `HAProxy` sets no rlimit; with `-m 8` its
/// `maxconn` is 220 and it serves all of them.
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
