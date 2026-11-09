// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T342 (T243-D #1): `option smtpchk` against a server that closes before a full greeting.
//!
//! The greeting parser needs four bytes; with fewer, the check used to wait for more even
//! after the close. The closed socket is always readable and the poller is level-triggered,
//! so the worker re-ran the check on every poll pass (99% of a core) until `timeout check`,
//! and the status came out `L7TOUT`. Measured on the reference binary (3.5-dev8-885761-29),
//! same three servers, `show stat`: closes at once -> `L7RSP` "Layer7 invalid response";
//! sends `22` then closes -> `L7RSP`; sends `220 ok` and answers HELO/QUIT -> `L7OK` 221.
//! HAProxy used 0 CPU ticks over 3 s in each case.

use crate::common;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum Mode {
    Close,
    Short,
    Healthy,
}

fn spawn_server(mode: Mode) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            match mode {
                Mode::Close => {}
                Mode::Short => {
                    let _ = s.write_all(b"22");
                }
                Mode::Healthy => {
                    let mut b = [0u8; 64];
                    let _ = s.write_all(b"220 ok\r\n");
                    let _ = s.read(&mut b);
                    let _ = s.write_all(b"250 hi\r\n");
                    let _ = s.read(&mut b);
                    let _ = s.write_all(b"221 bye\r\n");
                }
            }
        }
    });
    addr
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = std::os::unix::net::UnixStream::connect(sock).expect("connect cli");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// (server, status, check_status, check_code) rows of `show stat`.
fn rows(sock: &str) -> Vec<(String, String, String, String)> {
    let out = cli(sock, "show stat");
    let mut lines = out.lines();
    let head: Vec<&str> = lines.next().unwrap_or("").trim_start_matches("# ").split(',').collect();
    let col = |n: &str| head.iter().position(|h| *h == n).expect(n);
    let (sv, st, cs, cc) = (col("svname"), col("status"), col("check_status"), col("check_code"));
    lines
        .filter(|l| !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split(',').collect();
            (f[sv].into(), f[st].into(), f[cs].into(), f[cc].into())
        })
        .collect()
}

fn cpu_ticks(pid: u32) -> u64 {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("stat");
    let rest = &s[s.rfind(')').expect(")") + 2..];
    let f: Vec<&str> = rest.split(' ').collect();
    f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()
}

#[test]
fn smtpchk_short_greeting_at_close_is_judged_and_does_not_spin() {
    let (c, sh, ok) = (spawn_server(Mode::Close), spawn_server(Mode::Short), spawn_server(Mode::Healthy));
    let dir = std::env::temp_dir().join(format!("smtpeof-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let front = common::reserve_addr();
    let cfg = format!(
        "global\n    nbthread 1\n    stats socket {sock} level admin\n\
         defaults\n    mode tcp\n    timeout connect 500ms\n    timeout client 5s\n    timeout server 5s\n    timeout check 10s\n\
         listen smtp\n    bind {front}\n    option smtpchk\n\
         \x20   server close {c} check inter 1s fall 1 rise 1\n    server short {sh} check inter 1s fall 1 rise 1\n    server ok {ok} check inter 1s fall 1 rise 1\n"
    );
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    assert!(common::wait_listening(front), "alcyon did not listen");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    // The first round of checks, then two seconds of idle time to measure.
    std::thread::sleep(Duration::from_millis(1500));
    let (t0, w0) = (cpu_ticks(child.id()), Instant::now());
    std::thread::sleep(Duration::from_secs(2));
    let (t1, wall) = (cpu_ticks(child.id()), w0.elapsed());
    let got: Vec<_> = rows(&sock).into_iter().filter(|r| ["close", "short", "ok"].contains(&r.0.as_str())).collect();
    common::stop(&mut child);
    let _ = std::fs::remove_dir_all(&dir);
    // 100 ticks per second; a spinning worker used ~1 tick per 10 ms.
    let used = t1 - t0;
    assert!(used <= 10, "{used} CPU ticks in {wall:?} against servers that close (HAProxy: 0)");
    let sv = |n: &str| got.iter().find(|r| r.0 == n).cloned().unwrap_or_default();
    assert_eq!(
        (sv("close").1, sv("close").2),
        ("DOWN".into(), "L7RSP".into()),
        "oracle: a server that closes at once is L7RSP"
    );
    assert_eq!((sv("short").1, sv("short").2), ("DOWN".into(), "L7RSP".into()), "oracle: `22` then close is L7RSP");
    let ok = sv("ok");
    assert_eq!((ok.1, ok.2, ok.3), ("UP".into(), "L7OK".into(), "221".into()));
}
