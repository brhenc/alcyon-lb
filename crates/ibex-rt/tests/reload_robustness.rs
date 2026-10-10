// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T252: reloads that HAProxy 3.5-dev8-885761-29 survives and Ibex did not.
//!
//! * A `log-forward` section with a `bind` or `dgram-bind` made every reload fail with
//!   "Address already in use". HAProxy hands those sockets to the new worker like any
//!   other listener (the same socket inodes before and after `reload`, measured with
//!   `ss -ulnpe` / `ss -tlnpe`).
//! * A soft-stopping process closed a connection it had accepted but not yet read a request
//!   from. HAProxy serves that first request, with `connection: close`; only a connection
//!   that is between two requests is closed (`H1C_F_WAIT_NEXT_REQ`, `src/mux_h1.c`).
//! * A `reload` on the master CLI after the master got `SIGUSR1` hung until the master
//!   exited. HAProxy starts a new worker and answers `Success=1`; the master then keeps
//!   running with it.
//! * A new worker that never became ready blocked every later reload. HAProxy has the same
//!   hang (measured: the first `reload` never answers, later ones say "Another reload is
//!   still in progress."); Ibex bounds it, see `master.rs`.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A spawned `ibex` (master or single process) and everything it started. Dropping it
/// stops the process with `SIGUSR1` (`common::stop`) and then kills any worker that
/// outlived it, so no `ibex -W` is left behind on any path.
struct Ibex {
    child: Child,
    dir: PathBuf,
    seen: Vec<u32>,
}

impl Ibex {
    fn spawn(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ibex"));
        cmd.args(args).stdout(Stdio::null()).stderr(Stdio::null());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let child = cmd.spawn().expect("spawn ibex");
        Self { child, dir: dir.to_path_buf(), seen: Vec::new() }
    }

    /// Remembers the master's current children, so `drop` can reap them.
    fn note_children(&mut self) {
        for pid in children(self.child.id()) {
            if !self.seen.contains(&pid) {
                self.seen.push(pid);
            }
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Ibex {
    fn drop(&mut self) {
        self.note_children();
        common::stop(&mut self.child);
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.seen.iter().any(|p| alive(*p)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        for p in &self.seen {
            if alive(*p) {
                sig(*p, rustix::process::Signal::Kill);
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn children(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    if let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) {
        for t in tasks.flatten() {
            let text = std::fs::read_to_string(t.path().join("children")).unwrap_or_default();
            out.extend(text.split_whitespace().filter_map(|s| s.parse::<u32>().ok()));
        }
    }
    out
}

fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
        && !std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default().contains(") Z ")
}

fn sig(pid: u32, s: rustix::process::Signal) {
    if let Some(p) = i32::try_from(pid).ok().and_then(rustix::process::Pid::from_raw) {
        let _ = rustix::process::kill_process(p, s);
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    let dir = PathBuf::from(format!("/tmp/t252-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One master CLI command; the answer, or what came before `within` ran out.
fn master(sock: &Path, cmd: &str, within: Duration) -> String {
    let mut s = UnixStream::connect(sock).expect("connect master socket");
    s.set_read_timeout(Some(within)).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn wait_for_socket(p: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(p).is_err() {
        assert!(Instant::now() < deadline, "{} never accepted", p.display());
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn get(port: u16) -> Result<String, String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").map_err(|e| e.to_string())?;
    let mut out = String::new();
    s.read_to_string(&mut out).map_err(|e| e.to_string())?;
    if !out.starts_with("HTTP/1.1 200") {
        return Err(out);
    }
    Ok(out.rsplit("\r\n\r\n").next().unwrap_or("").to_string())
}

fn served_eventually(port: u16, want: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let got = get(port).unwrap_or_default();
        if got == want || Instant::now() > deadline {
            return got;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn http(port: u16, body: &str, extra: &str) -> String {
    format!(
        "global\n  nbthread 2\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 10s\n  timeout server 5s\n\
         frontend fe\n  bind 127.0.0.1:{port}\n  http-request return status 200 content-type text/plain string {body}\n{extra}"
    )
}

/// A connection the old worker is in the middle of reading a request from: it keeps that
/// worker alive (soft-stopping) until the connection goes.
fn hold_old_worker(port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: t\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(200));
    s
}

/// The datagrams that reached `rx` within `within`, as text.
fn drain(rx: &UdpSocket, within: Duration) -> String {
    rx.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let mut out = String::new();
    let deadline = Instant::now() + within;
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        if let Ok(n) = rx.recv(&mut buf) {
            out.push_str(&String::from_utf8_lossy(&buf[..n]));
            out.push('\n');
        }
    }
    out
}

/// `log-forward` with a `dgram-bind` and a `bind`: a reload succeeds, the new worker has
/// the sockets, and once the old worker is stopping it no longer takes messages from them,
/// even while it stays alive to finish a connection.
#[test]
fn a_log_forward_section_does_not_stop_a_reload() {
    let dir = tmpdir("lf");
    let sock = dir.join("m.sock");
    let cfg = dir.join("c.cfg");
    let port = common::reserve_port();
    let udp = common::reserve_port();
    let tcp = common::reserve_port();
    let rx1 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let rx2 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let lf = |rx: &UdpSocket| {
        format!(
            "log-forward lf\n  dgram-bind 127.0.0.1:{udp}\n  bind 127.0.0.1:{tcp}\n  log {} format raw local0\n",
            rx.local_addr().unwrap()
        )
    };
    std::fs::write(&cfg, http(port, "v1", &lf(&rx1))).unwrap();
    let mut ibex = Ibex::spawn(&dir, &["-W", "-S", sock.to_str().unwrap(), "-f", cfg.to_str().unwrap()], &[]);
    wait_for_socket(&sock);
    assert!(common::wait_listening(SocketAddr::from(([127, 0, 0, 1], port))));
    ibex.note_children();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    tx.send_to(b"<134>Oct 10 12:00:00 h app: before-reload", ("127.0.0.1", udp)).unwrap();
    assert!(drain(&rx1, Duration::from_millis(500)).contains("before-reload"), "v1 forwards");

    let _held = hold_old_worker(port);
    std::fs::write(&cfg, http(port, "v2", &lf(&rx2))).unwrap();
    let out = master(&sock, "reload", Duration::from_secs(15));
    ibex.note_children();
    assert!(out.starts_with("Success=1\n"), "reload with a log-forward section: {out:?}");
    assert_eq!(served_eventually(port, "v2"), "v2");

    // The old worker is still there (it holds `_held`) but stopping: every message goes to
    // the new worker's target.
    for i in 0..20 {
        tx.send_to(format!("<134>Oct 10 12:00:00 h app: udp-{i}").as_bytes(), ("127.0.0.1", udp)).unwrap();
    }
    let mut t = TcpStream::connect(("127.0.0.1", tcp)).expect("log-forward tcp bind after reload");
    t.write_all(b"<134>Oct 10 12:00:00 h app: over-tcp\n").unwrap();
    let got2 = drain(&rx2, Duration::from_secs(1));
    let got1 = drain(&rx1, Duration::from_millis(200));
    for i in 0..20 {
        assert!(got2.contains(&format!("udp-{i}\n")), "udp-{i} reached the new target: {got2:?}");
    }
    assert!(got2.contains("over-tcp"), "the tcp bind is the new worker's: {got2:?}");
    assert_eq!(got1, "", "the stopping worker forwarded with its old configuration");
}

/// A connection accepted before the stop whose first request comes after it is served,
/// with `connection: close`; a keep-alive connection waiting between requests is closed.
#[test]
fn a_stopping_process_serves_the_first_request_of_an_accepted_connection() {
    let dir = tmpdir("fresh");
    let cfg = dir.join("c.cfg");
    let port = common::reserve_port();
    std::fs::write(&cfg, http(port, "ok", "")).unwrap();
    let ibex = Ibex::spawn(&dir, &["-f", cfg.to_str().unwrap()], &[]);
    assert!(common::wait_listening(SocketAddr::from(([127, 0, 0, 1], port))));
    let mut fresh = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut ka = TcpStream::connect(("127.0.0.1", port)).unwrap();
    ka.write_all(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    ka.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 4096];
    assert!(ka.read(&mut buf).unwrap() > 0);
    std::thread::sleep(Duration::from_millis(300));
    sig(ibex.pid(), rustix::process::Signal::Usr1);
    std::thread::sleep(Duration::from_millis(1500));

    fresh.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let _ = fresh.write_all(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n");
    let mut out = String::new();
    let _ = fresh.read_to_string(&mut out);
    let lower = out.to_ascii_lowercase();
    assert!(lower.starts_with("http/1.1 200") && lower.contains("\r\nconnection: close\r\n"), "{out:?}");
    let _ = ka.write_all(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n");
    let mut out = Vec::new();
    let _ = ka.read_to_end(&mut out);
    assert!(out.is_empty(), "the idle keep-alive connection is closed: {:?}", String::from_utf8_lossy(&out));
}

/// `reload` after the master got `SIGUSR1`: answered, and a new worker takes over.
#[test]
fn a_reload_while_the_master_is_stopping_is_answered() {
    let dir = tmpdir("stopping");
    let sock = dir.join("m.sock");
    let cfg = dir.join("c.cfg");
    let port = common::reserve_port();
    std::fs::write(&cfg, http(port, "v1", "")).unwrap();
    let mut ibex = Ibex::spawn(&dir, &["-W", "-S", sock.to_str().unwrap(), "-f", cfg.to_str().unwrap()], &[]);
    wait_for_socket(&sock);
    assert!(common::wait_listening(SocketAddr::from(([127, 0, 0, 1], port))));
    ibex.note_children();
    let held = hold_old_worker(port);
    sig(ibex.pid(), rustix::process::Signal::Usr1);
    std::thread::sleep(Duration::from_millis(300));
    std::fs::write(&cfg, http(port, "v2", "")).unwrap();
    let t0 = Instant::now();
    let out = master(&sock, "reload", Duration::from_secs(10));
    ibex.note_children();
    assert!(out.starts_with("Success=1\n"), "reload while stopping, after {:?}: {out:?}", t0.elapsed());
    drop(held);
    assert_eq!(served_eventually(port, "v2"), "v2");
    std::thread::sleep(Duration::from_millis(500));
    assert!(alive(ibex.pid()), "the master runs on with the new worker, as HAProxy's does");
}

/// A new worker that never becomes ready (its `errorfile` is a FIFO nobody writes) is
/// given up on: the `reload` answers `Success=0`, the old worker goes on serving, and the
/// next reload works.
#[test]
fn a_worker_that_never_becomes_ready_does_not_block_reloads() {
    let dir = tmpdir("stuck");
    let sock = dir.join("m.sock");
    let cfg = dir.join("c.cfg");
    let fifo = dir.join("fifo");
    assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let port = common::reserve_port();
    std::fs::write(&cfg, http(port, "v1", "")).unwrap();
    let mut ibex = Ibex::spawn(
        &dir,
        &["-W", "-S", sock.to_str().unwrap(), "-f", cfg.to_str().unwrap()],
        &[("IBEX_WORKER_LOAD_TIMEOUT_MS", "1500")],
    );
    wait_for_socket(&sock);
    assert!(common::wait_listening(SocketAddr::from(([127, 0, 0, 1], port))));
    std::fs::write(&cfg, http(port, "v2", &format!("  errorfile 503 {}\n", fifo.display()))).unwrap();
    let s2 = sock.clone();
    let first = std::thread::spawn(move || master(&s2, "reload", Duration::from_secs(10)));
    std::thread::sleep(Duration::from_millis(300));
    ibex.note_children();
    assert_eq!(
        master(&sock, "reload", Duration::from_secs(5)),
        "Success=0\n--\nAnother reload is still in progress.\n",
        "while the worker loads"
    );
    let t0 = Instant::now();
    let out = first.join().unwrap();
    assert!(out.starts_with("Success=0\n"), "the stuck load is given up on, after {:?}: {out:?}", t0.elapsed());
    assert_eq!(get(port).as_deref(), Ok("v1"), "the old worker still serves");

    std::fs::write(&cfg, http(port, "v3", "")).unwrap();
    let out = master(&sock, "reload", Duration::from_secs(10));
    ibex.note_children();
    assert!(out.starts_with("Success=1\n"), "the next reload: {out:?}");
    assert_eq!(served_eventually(port, "v3"), "v3");
}
