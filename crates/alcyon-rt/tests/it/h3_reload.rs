// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTTP/3 across reloads (T558, VV-30): `-W`, `SIGUSR2` every 400 ms, curl `--http3-only`
//! loops opening one QUIC connection per request, and one slow request at a time that keeps
//! each old process draining for a second while the new one serves.
//!
//! V&V (100 reloads 1.5 s apart, main 4808be65): Alcyon lost 36 of 1962 short requests, all
//! closed by the old process with `H3_NO_ERROR` and no GOAWAY; `HAProxy` 3.5-dev10 lost
//! about one per 33 reloads (a connection accepted by the old worker as it stopped, then
//! never answered). The target is none lost.
//!
//! Two ways a request was lost here before T558: a connection whose handshake ended in the
//! old process during its stop was closed before its request was read (`h3_mux_drain.rs`
//! has the deterministic cases), and while an old process drained, the kernel still hashed
//! about half the new connections' Initials to its listening socket, which refused them
//! (`CONNECTION_REFUSED`; curl does not retry). The new process now takes the old one's QUIC
//! sockets over (`-x`, as dev10 does for every listener) and the old one stops reading
//! them at its stop, so a new connection only ever reaches the new process.

use crate::common;

use rustix::process::{kill_process, Pid, Signal};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// An HTTP/1 backend: `/slow` answers after a second, anything else at once.
fn backend() -> SocketAddr {
    let ls = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = ls.local_addr().expect("addr");
    thread::spawn(move || {
        for s in ls.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    let mut got = Vec::new();
                    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => got.extend_from_slice(&buf[..n]),
                        }
                    }
                    if got.starts_with(b"GET /slow") {
                        thread::sleep(Duration::from_secs(1));
                    }
                    if s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| s.rsplit_once(')').map(|(_, r)| !r.trim_start().starts_with('Z')))
        .unwrap_or(false)
}

fn read_pid(p: &Path) -> Option<u32> {
    std::fs::read_to_string(p).ok()?.trim().parse().ok()
}

fn signal(pid: u32, sig: Signal) {
    if let Some(p) = Pid::from_raw(i32::try_from(pid).unwrap_or(0)) {
        let _ = kill_process(p, sig);
    }
}

/// Every process of the test's reload chain: the replaced ones and the one serving. A
/// reloaded `-W` process is not a child of the test (it is reparented to init), so stopping
/// the first leaves the last running; each gets `SIGUSR1` (a soft stop, coverage written)
/// when the test ends, even by a panic, then `SIGKILL` if it is still there 7 s later.
struct Chain(Vec<u32>);

impl Drop for Chain {
    fn drop(&mut self) {
        for &p in &self.0 {
            signal(p, Signal::Usr1);
        }
        let t = Instant::now();
        while self.0.iter().any(|&p| alive(p)) && t.elapsed() < Duration::from_secs(7) {
            thread::sleep(Duration::from_millis(20));
        }
        for &p in self.0.iter().filter(|&&p| alive(p)) {
            signal(p, Signal::Kill);
        }
    }
}

/// What a failed run leaves behind: the chain's stderr (every process of a reload chain
/// inherits it) and `ps` of the processes still there, printed when the test panics, and
/// always when `ALCYON_TEST_DIAG` is set. The log stays in the test's temporary directory
/// otherwise, which goes with it.
struct Diag {
    errlog: std::path::PathBuf,
    pidfile: std::path::PathBuf,
    dumped: std::cell::Cell<bool>,
}

impl Drop for Diag {
    fn drop(&mut self) {
        if (thread::panicking() || std::env::var_os("ALCYON_TEST_DIAG").is_some()) && !self.dumped.get() {
            self.dump();
        }
    }
}

impl Diag {
    /// Printed before the "took over" assertion, while the chain is still there.
    fn dump(&self) {
        self.dumped.set(true);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64());
        eprintln!("--- T565 diag at {now:.3}: pidfile {:?}", std::fs::read_to_string(&self.pidfile).map(|s| s.trim().to_string()));
        let ps = Command::new("ps").args(["-eo", "pid,ppid,stat,etimes,wchan:20,args"]).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
        for l in ps.lines().filter(|l| l.contains("/alcyon -W") || l.contains("/alcyon -f") || l.contains("-sf ")) {
            eprintln!("ps: {l}");
        }
        eprintln!("--- {} (every process of the chain):", self.errlog.display());
        eprint!("{}", std::fs::read_to_string(&self.errlog).unwrap_or_default());
        eprintln!("--- end of diag");
    }
}

/// One request on a new QUIC connection: curl's status line, or what went wrong.
fn curl(quic: SocketAddr, path: &str) -> Result<(), String> {
    let ip = if quic.ip().is_unspecified() { "127.0.0.2".to_string() } else { quic.ip().to_string() };
    let out = Command::new("curl")
        .args(["-sS", "--http3-only", "-k", "--max-time", "10", "--resolve"])
        .arg(format!("localhost:{}:{ip}", quic.port()))
        .arg(format!("https://localhost:{}{path}", quic.port()))
        .args(["-o", "/dev/null", "-w", "%{http_code}"])
        .output()
        .map_err(|e| e.to_string())?;
    let code = String::from_utf8_lossy(&out.stdout).into_owned();
    if code == "200" {
        Ok(())
    } else {
        Err(format!("{path}: {code} {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

/// The inode of the UDP socket bound to `port` that has no peer, per process (`ss`).
fn unconnected_udp(port: u16) -> Vec<String> {
    let out = Command::new("ss").args(["-uanpe"]).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    let mut v: Vec<String> = out
        .lines()
        .filter(|l| l.contains(&format!(":{port} ")) && l.contains("UNCONN"))
        .filter_map(|l| l.split_whitespace().find_map(|w| w.strip_prefix("ino:")).map(str::to_string))
        .collect();
    v.sort();
    v
}

#[test]
fn h3_requests_across_reloads_are_all_served() {
    across_reloads(false);
}

/// The same on a wildcard bind, the client reaching 127.0.0.2 (T552/VV-27 note): the old
/// process's pinned socket for a connection must be bound to the address the client reached,
/// or the kernel gives it the route's source (127.0.0.1), the client's datagrams do not
/// match it, and they go to the listening socket, which the old process no longer reads.
#[test]
fn h3_requests_across_reloads_on_a_wildcard_bind_are_all_served() {
    across_reloads(true);
}

#[allow(clippy::too_many_lines)]
fn across_reloads(wildcard: bool) {
    const RELOADS: u32 = 15;
    let ok = Command::new("curl").arg("--version").output().is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("HTTP3"));
    assert!(ok, "this test needs a curl with HTTP/3; it fails rather than skips");
    let be = backend();
    let tcp = common::reserve_addr();
    let quic = common::reserve_addr();
    let quic = if wildcard { SocketAddr::from(([0, 0, 0, 0], quic.port())) } else { quic };
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let dir = tempfile::tempdir().expect("tmpdir");
    let cfg = dir.path().join("c.cfg");
    let pidfile = dir.path().join("p.pid");
    // Every process of the chain inherits this stderr (T565): on a failure the master log
    // and the chain's `ps` are printed, so a reload that stalls says where it stalled.
    let errlog = dir.path().join("alcyon.err");
    let stderr = std::fs::File::create(&errlog).expect("stderr log");
    let diag = Diag { errlog: errlog.clone(), pidfile: pidfile.clone(), dumped: std::cell::Cell::new(false) };
    std::fs::write(
        &cfg,
        format!(
            "global\n  nbthread 2\n  hard-stop-after 5s\n\
             defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
             frontend fe\n  bind {tcp}\n  bind quic4@{quic} ssl crt {crt} alpn h3\n  default_backend be\n\
             backend be\n  server s1 {be}\n"
        ),
    )
    .expect("cfg");
    let mut first = common::Alcyon(
        common::alcyon_command(env!("CARGO_BIN_EXE_alcyon"))
            .arg("-W")
            .arg("-f")
            .arg(&cfg)
            .arg("-p")
            .arg(&pidfile)
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()
            .expect("spawn alcyon"),
    );
    assert!(common::wait_listening(tcp), "alcyon did not start");
    let sockets_before = unconnected_udp(quic.port());

    let stop = Arc::new(AtomicBool::new(false));
    let served = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(Mutex::new(Vec::new()));
    let mut load = Vec::new();
    for i in 0..4 {
        let (stop, served, errors) = (Arc::clone(&stop), Arc::clone(&served), Arc::clone(&errors));
        // Three loops of short requests, one of slow ones: an old process always has a
        // request to drain.
        let path = if i == 3 { "/slow" } else { "/" };
        load.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match curl(quic, path) {
                    Ok(()) => served.fetch_add(1, Ordering::Relaxed),
                    Err(e) => {
                        errors.lock().expect("lock").push(e);
                        0
                    }
                };
            }
        }));
    }
    thread::sleep(Duration::from_millis(500));

    let mut serving = first.id();
    let mut chain = Chain(vec![serving]);
    for i in 1..=RELOADS {
        let t0 = Instant::now();
        let old = serving;
        signal(serving, Signal::Usr2);
        while Instant::now() < t0 + Duration::from_millis(400) || (serving == old && t0.elapsed() < Duration::from_secs(20)) {
            if let Some(p) = read_pid(&pidfile).filter(|&p| p != old && alive(p)) {
                serving = p;
            }
            thread::sleep(Duration::from_millis(10));
        }
        if !chain.0.contains(&serving) {
            chain.0.push(serving);
        }
        if serving == old {
            diag.dump();
        }
        assert_ne!(serving, old, "reload {i}: no new process took over within 20 s");
    }
    thread::sleep(Duration::from_millis(1500));
    let sockets_after = unconnected_udp(quic.port());
    stop.store(true, Ordering::Relaxed);
    for t in load {
        t.join().expect("load thread");
    }
    drop(chain);
    common::stop(&mut first.0);
    drop(diag);

    let errors = errors.lock().expect("lock").clone();
    let n = served.load(Ordering::Relaxed);
    let report = format!("served {n}, lost {}: {errors:?}", errors.len());
    eprintln!("{report}");
    assert!(n > u64::from(RELOADS) * 10, "too little load to mean anything: {report}");
    assert!(errors.is_empty(), "requests lost across reloads: {report}");
    // dev10 keeps one socket per listener across reloads; Alcyon one per thread, the same ones.
    assert_eq!(sockets_after, sockets_before, "the QUIC sockets must be handed over, not bound anew");
}
