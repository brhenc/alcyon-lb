// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Reload under load (T166, the M1 operations parameter "Reload").
//!
//! `-W`, constant keep-alive HTTP/1.1 load, a long download and a WebSocket, `SIGUSR2`
//! every second. What the operator must not see: a failed request, a reset connection, a
//! download cut short, an old process that outlives `hard-stop-after`, RSS or fds growing.
//!
//! A request sent on a reused keep-alive connection that the proxy closes before one byte
//! of response is the race every HTTP client retries (RFC 9112 9.3.1). It cannot be
//! avoided -- the request may be on the wire when the close is -- so it is retried here and
//! counted, and the count is held to one per reload. `tools/measure/reload_under_load.py`
//! (100 reloads, 8 clients, nbthread 1, release build): `HAProxy` 3.5-dev8 23, Ibex 311
//! before this test, 0 after. `HAProxy` closes idle connections only when its thread has
//! nothing to run, so under load every client gets `Connection: close` instead; Ibex
//! closed them on every turn of its loop. The clients pause 200 us between requests, as a
//! real client does; with no pause a connection is hardly ever idle and nothing is tested.
//!
//! The 100-reload run is `#[ignore]`d (about two minutes); the gate runs ten.

use crate::common;

use rustix::process::{kill_process, Pid, Signal};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const BIG: usize = 4 * 1024 * 1024;
const HARD_STOP_AFTER: Duration = Duration::from_secs(3);
/// What a client spends between two requests on one connection.
const THINK: Duration = Duration::from_micros(200);

fn backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(s) = stream else { continue };
            thread::spawn(move || serve(s));
        }
    });
    addr
}

fn serve(mut s: TcpStream) {
    let mut r = BufReader::new(s.try_clone().expect("clone"));
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let mut upgrade = false;
        loop {
            let mut h = String::new();
            if r.read_line(&mut h).unwrap_or(0) == 0 {
                return;
            }
            if h == "\r\n" {
                break;
            }
            upgrade |= h.to_ascii_lowercase().starts_with("upgrade: websocket");
        }
        if upgrade {
            // The proxy does not check the accept key; it tunnels after a 101.
            let _ = s.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                  Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            );
            let mut buf = [0u8; 256];
            while let Ok(n) = r.read(&mut buf) {
                if n == 0 || s.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
            return;
        }
        if line.starts_with("GET /big ") {
            // About 1.5 s: long enough to span a reload, short of hard-stop-after.
            if s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {BIG}\r\n\r\n").as_bytes()).is_err() {
                return;
            }
            let chunk = vec![b'x'; 64 * 1024];
            for _ in 0..BIG / chunk.len() {
                if s.write_all(&chunk).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(23));
            }
        } else if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
            return;
        }
    }
}

#[derive(Default)]
struct Counts {
    ok: AtomicU64,
    failed: AtomicU64,
    resets: AtomicU64,
    stale: AtomicU64,
    dl_ok: AtomicU64,
    dl_failed: AtomicU64,
    errors: Mutex<Vec<String>>,
}

impl Counts {
    fn note(&self, what: String) {
        let mut e = self.errors.lock().expect("lock");
        if e.len() < 10 {
            e.push(what);
        }
    }
}

/// Reads one response; `Ok((status, close))`, or `Err(bytes_seen)`.
fn response(r: &mut BufReader<TcpStream>) -> Result<(u16, bool), (usize, std::io::Error)> {
    let eof = || std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
    let mut line = String::new();
    match r.read_line(&mut line) {
        Ok(0) => return Err((0, eof())),
        Ok(_) => {}
        Err(e) => return Err((0, e)),
    }
    let status = line.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let (mut len, mut close) = (0usize, false);
    loop {
        let mut h = String::new();
        match r.read_line(&mut h) {
            Ok(0) => return Err((1, eof())),
            Ok(_) => {}
            Err(e) => return Err((1, e)),
        }
        if h == "\r\n" {
            break;
        }
        let l = h.to_ascii_lowercase();
        if let Some(v) = l.strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        } else if l.starts_with("connection:") && l.contains("close") {
            close = true;
        }
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).map_err(|e| (1, e))?;
    Ok((status, close))
}

fn keepalive_client(fe: SocketAddr, c: &Counts, stop: &AtomicBool) {
    let mut conn: Option<(TcpStream, BufReader<TcpStream>, bool)> = None;
    while !stop.load(Ordering::Relaxed) {
        for attempt in 0..2 {
            if conn.is_none() {
                match TcpStream::connect(fe) {
                    Ok(s) => {
                        s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
                        let r = BufReader::new(s.try_clone().expect("clone"));
                        conn = Some((s, r, false));
                    }
                    Err(e) => {
                        c.failed.fetch_add(1, Ordering::Relaxed);
                        c.note(format!("connect: {e}"));
                        break;
                    }
                }
            }
            let (s, r, reused) = conn.as_mut().expect("conn");
            let reused = *reused;
            let res = s
                .write_all(b"GET /s HTTP/1.1\r\nHost: t\r\n\r\n")
                .map_err(|e| (0, e))
                .and_then(|()| response(r));
            match res {
                Ok((200, close)) => {
                    c.ok.fetch_add(1, Ordering::Relaxed);
                    thread::sleep(THINK);
                    if close {
                        conn = None;
                    } else if let Some(x) = conn.as_mut() {
                        x.2 = true;
                    }
                    break;
                }
                Ok((st, _)) => {
                    c.failed.fetch_add(1, Ordering::Relaxed);
                    c.note(format!("status {st}"));
                    conn = None;
                    break;
                }
                Err((seen, e)) => {
                    conn = None;
                    if e.kind() == std::io::ErrorKind::ConnectionReset {
                        c.resets.fetch_add(1, Ordering::Relaxed);
                    }
                    if reused && seen == 0 && attempt == 0 {
                        c.stale.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    c.failed.fetch_add(1, Ordering::Relaxed);
                    c.note(format!("request (reused={reused}, seen={seen}): {e}"));
                    break;
                }
            }
        }
    }
}

fn download(fe: SocketAddr, c: &Counts) {
    let res = TcpStream::connect(fe).and_then(|mut s| {
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        s.write_all(b"GET /big HTTP/1.1\r\nHost: t\r\n\r\n")?;
        let mut r = BufReader::new(s);
        response(&mut r).map_err(|(_, e)| e)
    });
    match res {
        Ok((200, _)) => c.dl_ok.fetch_add(1, Ordering::Relaxed),
        other => {
            c.note(format!("download: {other:?}"));
            c.dl_failed.fetch_add(1, Ordering::Relaxed)
        }
    };
}

/// Opens a WebSocket and pings it until it is closed; returns when, and how.
fn websocket(fe: SocketAddr, stop: &AtomicBool) -> (Instant, String) {
    let mut s = TcpStream::connect(fe).expect("ws connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(
        b"GET /ws HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .expect("ws handshake");
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(s.read(&mut b).expect("ws head"), 1, "ws handshake cut: {head:?}");
        head.push(b[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 101"), "{}", String::from_utf8_lossy(&head));
    let mut got = [0u8; 4];
    while !stop.load(Ordering::Relaxed) {
        if let Err(e) = s.write_all(b"ping").and_then(|()| s.read_exact(&mut got)) {
            return (Instant::now(), format!("{:?}", e.kind()));
        }
        thread::sleep(Duration::from_millis(50));
    }
    (Instant::now(), "still open".into())
}

fn status_kb(pid: u32, key: &str) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix(key).map(|v| v.trim().trim_end_matches(" kB").parse().unwrap_or(0)))
        .unwrap_or(0)
}

/// The process's fds net of TCP connections open, opening or half-closed (established,
/// SYN sent/received, close-wait). The load keeps a varying number
/// of client and server connections open, so the raw count moves with the load; what is
/// left is what a leak across reloads would grow.
fn fds(pid: u32) -> usize {
    let mut established = std::collections::HashSet::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        for line in std::fs::read_to_string(table).unwrap_or_default().lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() > 9 && matches!(f[3], "01" | "02" | "03" | "08") {
                established.insert(format!("socket:[{}]", f[9]));
            }
        }
    }
    std::fs::read_dir(format!("/proc/{pid}/fd")).map_or(0, |d| {
        d.filter_map(Result::ok)
            .filter(|e| {
                std::fs::read_link(e.path())
                    .is_ok_and(|t| !established.contains(t.to_string_lossy().as_ref()))
            })
            .count()
    })
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

#[allow(clippy::too_many_lines)]
fn reload_under_load(reloads: u32) {
    let be = backend();
    let fe = common::reserve_addr();
    let dir = tempfile::tempdir().expect("tmpdir");
    let cfg = dir.path().join("c.cfg");
    let pidfile = dir.path().join("p.pid");
    std::fs::write(
        &cfg,
        format!(
            "global\n  hard-stop-after {}ms\n\
             defaults\n  mode http\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n  timeout tunnel 60s\n\
             frontend fe\n  bind {fe}\n  default_backend be\n\
             backend be\n  server s1 {be}\n",
            HARD_STOP_AFTER.as_millis()
        ),
    )
    .expect("cfg");
    let mut first = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-W")
        .arg("-f")
        .arg(&cfg)
        .arg("-p")
        .arg(&pidfile)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Ibex)
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex did not start");

    let c = Arc::new(Counts::default());
    let stop = Arc::new(AtomicBool::new(false));
    let mut load = Vec::new();
    for _ in 0..8 {
        let (c, stop) = (Arc::clone(&c), Arc::clone(&stop));
        load.push(thread::spawn(move || keepalive_client(fe, &c, &stop)));
    }
    {
        let (c, stop) = (Arc::clone(&c), Arc::clone(&stop));
        load.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                download(fe, &c);
            }
        }));
    }
    // The WebSocket lives on the first process; the first reload retires that process.
    let ws = {
        let stop = Arc::clone(&stop);
        thread::spawn(move || websocket(fe, &stop))
    };
    thread::sleep(Duration::from_millis(500));

    let mut retired: Vec<(u32, Instant)> = Vec::new();
    let mut gone: Vec<(u32, Duration)> = Vec::new();
    let mut first_retire = None;
    let mut at10 = None;
    let mut serving = first.id();
    for i in 1..=reloads {
        let t0 = Instant::now();
        signal(serving, Signal::Usr2);
        retired.push((serving, t0));
        first_retire.get_or_insert(t0);
        let old = serving;
        // One second between reloads; longer while no new process has taken over yet (a
        // loaded host starts one late).
        while Instant::now() < t0 + Duration::from_secs(1) || (serving == old && Instant::now() < t0 + Duration::from_secs(20)) {
            if let Some(p) = read_pid(&pidfile).filter(|&p| p != old && alive(p)) {
                serving = p;
            }
            retired.retain(|&(p, at)| {
                if alive(p) {
                    return true;
                }
                gone.push((p, at.elapsed()));
                false
            });
            thread::sleep(Duration::from_millis(10));
        }
        assert_ne!(serving, old, "reload {i}: no new process took over within 20 s");
        if i == 10 {
            at10 = Some((status_kb(serving, "VmRSS:"), (0..3).map(|_| fds(serving)).min().unwrap_or(0)));
        }
    }
    let last = (status_kb(serving, "VmRSS:"), (0..3).map(|_| fds(serving)).min().unwrap_or(0));

    // Keep the load on while the last old processes drain.
    let deadline = Instant::now() + HARD_STOP_AFTER + Duration::from_secs(2);
    while !retired.is_empty() && Instant::now() < deadline {
        retired.retain(|&(p, at)| {
            if alive(p) {
                return true;
            }
            gone.push((p, at.elapsed()));
            false
        });
        thread::sleep(Duration::from_millis(10));
    }
    stop.store(true, Ordering::Relaxed);
    for t in load {
        t.join().expect("load thread");
    }
    let (ws_end, ws_how) = ws.join().expect("ws thread");
    let ws_after = ws_end.saturating_duration_since(first_retire.expect("reloaded"));

    // SIGUSR1 with a download in flight: the download completes, the process exits 0.
    let inflight = {
        let c = Arc::clone(&c);
        thread::spawn(move || download(fe, &c))
    };
    thread::sleep(Duration::from_millis(300));
    let dl_before = c.dl_ok.load(Ordering::Relaxed);
    signal(serving, Signal::Usr1);
    inflight.join().expect("download thread");
    let usr1_dl = c.dl_ok.load(Ordering::Relaxed) - dl_before;
    let t = Instant::now();
    while alive(serving) && t.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(10));
    }
    let serving_left = !alive(serving);
    common::stop(&mut first);

    let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
    let errors = c.errors.lock().expect("lock").clone();
    let report = format!(
        "ok={} failed={} resets={} stale(retried)={} downloads ok={} failed={} ws closed after {ws_after:?} \
         ({ws_how}) undrained={:?} drain max={:?} rss/fds at 10={at10:?} at {reloads}={last:?} errors={errors:?}",
        n(&c.ok),
        n(&c.failed),
        n(&c.resets),
        n(&c.stale),
        n(&c.dl_ok),
        n(&c.dl_failed),
        retired,
        gone.iter().map(|g| g.1).max(),
    );
    eprintln!("{report}");
    assert!(n(&c.ok) > u64::from(reloads) * 100, "too little load to mean anything: {report}");
    assert_eq!(n(&c.failed), 0, "failed requests: {report}");
    assert_eq!(n(&c.resets), 0, "reset connections: {report}");
    assert!(
        n(&c.stale) <= u64::from(reloads),
        "keep-alive requests lost to the old process closing connections: {report}"
    );
    assert_eq!(n(&c.dl_failed), 0, "downloads cut short: {report}");
    assert!(n(&c.dl_ok) >= 2, "{report}");
    assert!(retired.is_empty(), "old processes outlived hard-stop-after: {report}");
    assert!(
        ws_after >= HARD_STOP_AFTER - Duration::from_millis(300)
            && ws_after <= HARD_STOP_AFTER + Duration::from_secs(1),
        "the old process's WebSocket must last until hard-stop-after: {report}"
    );
    assert_eq!(usr1_dl, 1, "SIGUSR1 must let the in-flight download finish: {report}");
    assert!(serving_left, "SIGUSR1: the process did not exit: {report}");
    if let Some((rss10, fds10)) = at10.filter(|_| reloads > 10) {
        assert!(last.0 * 100 <= rss10 * 105, "RSS grew from reload 10 to {reloads}: {report}");
        assert!(last.1 * 100 <= fds10 * 105, "fds grew from reload 10 to {reloads}: {report}");
    }
}

#[test]
fn ten_reloads_under_load_lose_nothing() {
    reload_under_load(10);
}

#[test]
#[ignore = "about two minutes: cargo test --test reload_under_load -- --ignored"]
fn a_hundred_reloads_under_load_lose_nothing() {
    reload_under_load(100);
}
