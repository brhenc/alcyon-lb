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
        .stderr(Stdio::null())
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
    let ibex = spawn("emfile", "128:128", "  nbthread 1\n  maxconn 1000\n", fe);
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
