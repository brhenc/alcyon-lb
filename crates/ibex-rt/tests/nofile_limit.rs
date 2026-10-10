// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Running out of file descriptors (T237).
//!
//! Measured on HAProxy 3.5-dev8-885761-29, `nbthread 1`, `maxconn 1000`, under
//! `prlimit --nofile=128:128`: with 300 clients connected (200 here: the backlog is 128) and the process out of fds, it
//! used no CPU over 2 s (0 clock ticks), a further client waits in the backlog, and once the
//! clients close a request is answered at once. `accept` failing with `EMFILE` is
//! `CO_AC_PAUSE` (src/sock.c): the listener goes to the global listener queue
//! (`limit_listener`) and is resumed when a connection is released or after 100 ms.
//!
//! Ibex mapped `EMFILE` to "the queue is drained" and left the listener armed on a
//! level-triggered epoll: 100% of a CPU (199 ticks in 2 s) in `accept4` while saturated.
//!
//! The soft limit: `HAProxy` raises it to `maxsock` at startup (`apply_nofile_limit`,
//! src/limits.c), never lowers it, and with the default `strict-limits` refuses to start
//! when it cannot. Measured with `nbthread 1`, one `bind` and a `stats socket`:
//! - no `maxconn`, `prlimit --nofile=64:4096`: soft limit 4095, `show info` `Maxconn: 2035`,
//!   `Maxsock: 4095`, `Ulimit-n: 4095`;
//! - `maxconn 100`, 64:4096: soft limit 225, `Maxsock`/`Ulimit-n` 225; under 1024:4096 the
//!   soft limit stays 1024 and `Ulimit-n` is still 225;
//! - `maxconn 2000`, 1024:1024: exit 1, "Cannot raise FD limit to 4025, current limit is
//!   1024 and hard limit is 1024.";
//! - `maxconn 1000` and `no strict-limits`, 128:128: starts with the soft limit at the hard
//!   one, `Ulimit-n: 128`, `Maxsock: 2025`.
//!
//! Ibex never raised the soft limit (`maxconn` from the hard limit, 262131 under systemd's
//! 1024:524288, and `EMFILE` past ~500 sessions).

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Ibex {
    child: Child,
    dir: PathBuf,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Ibex {
    fn pid(&self) -> u32 {
        self.child.id()
    }
}

fn have_prlimit() -> bool {
    Command::new("prlimit").arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
}

/// `ibex -f <cfg>` under `prlimit --nofile=<nofile>`; `prlimit` execs, so the child is ibex.
fn spawn(tag: &str, nofile: &str, global: &str, fe: SocketAddr) -> Ibex {
    spawn_with(tag, nofile, global, fe, Stdio::null())
}

fn spawn_with(tag: &str, nofile: &str, global: &str, fe: SocketAddr, stderr: Stdio) -> Ibex {
    let dir = std::env::temp_dir().join(format!("ibex_t237_{tag}_{}_{}", std::process::id(), fe.port()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let cfg = format!(
        "global\n{global}\
         defaults\n  mode http\n  timeout client 30s\n  timeout connect 1s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  http-request return status 200 content-type text/plain string ok\n"
    );
    std::fs::write(dir.join("cfg"), cfg).expect("cfg");
    let child = Command::new("prlimit")
        .arg(format!("--nofile={nofile}"))
        .arg(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(dir.join("cfg"))
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .expect("spawn");
    Ibex { child, dir }
}

/// utime + stime of `pid`, in clock ticks.
fn cpu_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("stat");
    let rest = stat.rsplit_once(')').expect("comm").1;
    let f: Vec<&str> = rest.split_whitespace().collect();
    f[11].parse::<u64>().expect("utime") + f[12].parse::<u64>().expect("stime")
}

/// The soft limit on open files of `pid`.
fn soft_nofile(pid: u32) -> u64 {
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).expect("limits");
    let line = limits.lines().find(|l| l.starts_with("Max open files")).expect("nofile line");
    line.split_whitespace().nth(3).expect("soft").parse().expect("number")
}

/// One request on a fresh connection; the status line, or what went wrong.
fn get(addr: SocketAddr, wait: Duration) -> String {
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(1)) else {
        return "connect failed".into();
    };
    s.set_read_timeout(Some(wait)).expect("timeout");
    if s.write_all(b"GET / HTTP/1.0\r\n\r\n").is_err() {
        return "write failed".into();
    }
    let mut buf = Vec::new();
    match s.read_to_end(&mut buf) {
        Ok(_) | Err(_) if !buf.is_empty() => String::from_utf8_lossy(&buf).lines().next().unwrap_or("").to_string(),
        Ok(_) => "closed".into(),
        Err(e) => e.to_string(),
    }
}

#[test]
fn out_of_fds_on_accept_the_listener_pauses_and_resumes() {
    if !have_prlimit() {
        eprintln!("prlimit is not installed: skipped");
        return;
    }
    let fe = common::reserve_addr();
    let ibex = spawn("emfile", "128:128", "  nbthread 1\n  maxconn 1000\n  no strict-limits\n", fe);
    assert!(common::wait_listening(fe), "ibex never listened");
    assert_eq!(get(fe, Duration::from_secs(3)), "HTTP/1.1 200 OK");

    // More clients than the process has descriptors: it runs out on accept.
    let clients: Vec<TcpStream> = (0..200).map(|_| TcpStream::connect(fe).expect("connect")).collect();
    thread::sleep(Duration::from_millis(500));
    let before = cpu_ticks(ibex.pid());
    thread::sleep(Duration::from_secs(2));
    let used = cpu_ticks(ibex.pid()) - before;
    // HAProxy: 0. Spinning on accept is ~200 (a whole CPU at 100 ticks a second).
    assert!(used < 40, "ibex used {used} clock ticks in 2 s while out of fds: it is spinning on accept");

    drop(clients);
    let t = Instant::now();
    assert_eq!(get(fe, Duration::from_secs(3)), "HTTP/1.1 200 OK", "not served once the clients closed");
    assert!(t.elapsed() < Duration::from_secs(1), "served {:?} after the clients closed", t.elapsed());
}

/// `show info` on the stats socket `sock`, the value of `key`.
fn info(sock: &std::path::Path, key: &str) -> String {
    let end = Instant::now() + Duration::from_secs(10);
    let mut s = loop {
        match std::os::unix::net::UnixStream::connect(sock) {
            Ok(s) => break s,
            Err(_) if Instant::now() < end => thread::sleep(Duration::from_millis(25)),
            Err(e) => panic!("the stats socket never came up: {e}"),
        }
    };
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(b"show info\n").expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out.lines().find_map(|l| l.strip_prefix(&format!("{key}: ")).map(str::to_string)).unwrap_or_default()
}

fn stats_global(tag: &str, fe: SocketAddr, extra: &str) -> (String, PathBuf) {
    let sock = std::env::temp_dir().join(format!("ibex_t237_{tag}_{}_{}.sock", std::process::id(), fe.port()));
    (format!("  nbthread 1\n  stats socket {} level admin\n{extra}", sock.display()), sock)
}

#[test]
fn without_maxconn_the_soft_limit_is_raised_to_maxsock() {
    if !have_prlimit() {
        eprintln!("prlimit is not installed: skipped");
        return;
    }
    let fe = common::reserve_addr();
    let (global, sock) = stats_global("auto", fe, "");
    let ibex = spawn("auto", "64:4096", &global, fe);
    assert!(common::wait_listening(fe), "ibex never listened");
    let got = (info(&sock, "Maxconn"), info(&sock, "Maxsock"), info(&sock, "Ulimit-n"), soft_nofile(ibex.pid()));
    assert_eq!(got, ("2035".to_string(), "4095".to_string(), "4095".to_string(), 4095));

    // Two hundred sessions at once, under what was a soft limit of 64.
    let clients: Vec<TcpStream> = (0..200).map(|_| TcpStream::connect(fe).expect("connect")).collect();
    thread::sleep(Duration::from_millis(300));
    assert_eq!(get(fe, Duration::from_secs(2)), "HTTP/1.1 200 OK");
    drop(clients);
    drop(ibex);
    let _ = std::fs::remove_file(&sock);

    // Threads take descriptors too: `nbthread 4` gets 2031 (measured), and `maxsock` still
    // fits the hard limit, which a configuration without `maxconn` must never be refused for.
    let fe = common::reserve_addr();
    let (global, sock) = stats_global("auto4", fe, "");
    let global = global.replace("nbthread 1", "nbthread 4");
    let ibex = spawn("auto4", "64:4096", &global, fe);
    assert!(common::wait_listening(fe), "ibex never listened");
    let maxsock: u64 = info(&sock, "Maxsock").parse().expect("Maxsock");
    assert_eq!(info(&sock, "Maxconn"), "2031");
    assert!(maxsock <= 4096 && soft_nofile(ibex.pid()) == maxsock, "Maxsock {maxsock}");
    drop(ibex);
    let _ = std::fs::remove_file(&sock);
}

#[test]
fn a_configured_maxconn_raises_the_soft_limit_and_never_lowers_it() {
    if !have_prlimit() {
        eprintln!("prlimit is not installed: skipped");
        return;
    }
    for (nofile, soft) in [("64:4096", 225), ("1024:4096", 1024)] {
        let fe = common::reserve_addr();
        let (global, sock) = stats_global("mc100", fe, "  maxconn 100\n");
        let ibex = spawn("mc100", nofile, &global, fe);
        assert!(common::wait_listening(fe), "ibex never listened");
        let got = (info(&sock, "Maxconn"), info(&sock, "Maxsock"), info(&sock, "Ulimit-n"), soft_nofile(ibex.pid()));
        assert_eq!(got, ("100".to_string(), "225".to_string(), "225".to_string(), soft), "under {nofile}");
        drop(ibex);
        let _ = std::fs::remove_file(&sock);
    }
}

#[test]
fn a_maxconn_the_hard_limit_cannot_hold_is_refused_unless_no_strict_limits() {
    if !have_prlimit() {
        eprintln!("prlimit is not installed: skipped");
        return;
    }
    let fe = common::reserve_addr();
    let (global, sock) = stats_global("strict", fe, "  maxconn 2000\n  strict-limits\n");
    let mut ibex = spawn_with("strict", "1024:1024", &global, fe, Stdio::piped());
    let end = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(st) = ibex.child.try_wait().expect("wait") {
            break st;
        }
        assert!(Instant::now() < end, "ibex started with maxconn 2000 under a hard limit of 1024");
        thread::sleep(Duration::from_millis(20));
    };
    let mut err = String::new();
    let _ = ibex.child.stderr.take().expect("stderr").read_to_string(&mut err);
    assert_eq!(status.code(), Some(1), "{err}");
    assert!(err.contains("Cannot raise FD limit to 4025, current limit is 1024 and hard limit is 1024."), "{err}");
    drop(ibex);

    let fe = common::reserve_addr();
    let (global, sock2) = stats_global("nostrict", fe, "  maxconn 1000\n  no strict-limits\n");
    let ibex = spawn("nostrict", "128:128", &global, fe);
    assert!(common::wait_listening(fe), "ibex never listened");
    let got = (info(&sock2, "Maxsock"), info(&sock2, "Ulimit-n"), soft_nofile(ibex.pid()));
    assert_eq!(got, ("2025".to_string(), "128".to_string(), 128));
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&sock2);
}
