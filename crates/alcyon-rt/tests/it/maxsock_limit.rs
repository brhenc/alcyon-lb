// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! No socket past `maxsock` (MY-7, T312 item 2).
//!
//! `HAProxy` closes any socket whose descriptor is `>= global.maxsock`, whatever the soft
//! limit on open files allows: a server socket fails the connect as a configuration limit
//! (`sock_create_server_socket`, src/sock.c: "socket(): not enough free sockets", no retry,
//! `CO_ER_CONF_FDLIM`) and an accepted one is closed and the listener paused (`sock_accept_conn`,
//! "reached the configured maximum connection limit"). `maxconn` alone does not bound the
//! descriptors, because one HTTP/2 connection carries up to 100 streams, each with a server
//! connection of its own.
//!
//! Measured 2026-10-11 on HAProxy 3.5-dev8-885761-29 and Alcyon 26881cde, this file's config
//! (`nbthread 1`, `maxconn 10`, an h2 bind, an h1 bind, a `stats socket`: `Maxsock` 46 on
//! both), soft limit 1048576, one h2c connection with 100 POSTs whose bodies never come:
//!
//! ```text
//!   haproxy: 46 fds, 36 server connections; the other 64 streams answered 503 at once
//!            (HEADERS, DATA "503 Service Unavailable", RST_STREAM NO_ERROR); a new h1
//!            client is reset while saturated and served once the h2 connection closes
//!   alcyon:    109 fds, 100 server connections; the new h1 client is served
//! ```
//!
//! A proxy with no ceiling but the kernel's reaches resource exhaustion in places nobody has
//! tested (the red team saw 20 232 fds at `maxconn 2000`, HAProxy 4 036).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// `Maxsock` for the config below, as both `HAProxy` and Alcyon report it.
const MAXSOCK: usize = 46;
const STREAMS: u32 = 100;

struct Alcyon {
    child: Child,
    dir: PathBuf,
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A server that accepts and holds every connection; the count of those accepted.
fn holding_backend() -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let n = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&n);
    thread::spawn(move || {
        let mut held = Vec::new();
        for c in l.incoming().flatten() {
            seen.fetch_add(1, Ordering::SeqCst);
            held.push(c);
        }
    });
    (addr, n)
}

fn spawn(h2: SocketAddr, h1: SocketAddr, be: SocketAddr) -> Alcyon {
    spawn_with(env!("CARGO_BIN_EXE_alcyon"), false, h2, h1, be)
}

/// The descriptor a launcher leaves open, without CLOEXEC, in the tests that inherit one.
const INHERITED_FD: usize = 2000;

/// `bin` with `-f` on this file's config; `inherit` starts it from `bash` with `INHERITED_FD`
/// open on /dev/null (what `dup2` in a pre_exec does; the crate forbids `unsafe`).
fn spawn_with(bin: &str, inherit: bool, h2: SocketAddr, h1: SocketAddr, be: SocketAddr) -> Alcyon {
    let dir = std::env::temp_dir().join(format!("alcyon_maxsock_{}_{}", std::process::id(), h2.port()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sock = dir.join("sock");
    let cfg = format!(
        "global\n  nbthread 1\n  maxconn 10\n  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout client 30s\n  timeout connect 2s\n  timeout server 30s\n\
         frontend f\n  bind {h2} proto h2\n  default_backend b\n\
         frontend f2\n  bind {h1}\n  http-request return status 200 content-type text/plain string ok\n\
         backend b\n  server s1 {be}\n",
        sock.display()
    );
    std::fs::write(dir.join("cfg"), cfg).expect("cfg");
    let mut cmd = if inherit {
        let mut c = Command::new("bash");
        c.arg("-c").arg(format!("exec {INHERITED_FD}</dev/null; exec \"$0\" \"$@\"")).arg(bin);
        c
    } else {
        Command::new(bin)
    };
    let child = cmd
        .arg("-f")
        .arg(dir.join("cfg"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    Alcyon { child, dir }
}

fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("len").to_be_bytes();
    let mut f = vec![len[1], len[2], len[3], ftype, flags];
    f.extend_from_slice(&stream_id.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// HPACK literal fields without indexing, no Huffman.
fn request(method: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    for (n, v) in [(&b":method"[..], method), (b":scheme", b"http"), (b":path", b"/x"), (b":authority", b"a")] {
        b.push(0);
        b.push(u8::try_from(n.len()).expect("name"));
        b.extend_from_slice(n);
        b.push(u8::try_from(v.len()).expect("value"));
        b.extend_from_slice(v);
    }
    b
}

/// An h2c connection holding `STREAMS` POSTs whose bodies never come.
fn hold_streams(h2: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(h2).expect("connect h2");
    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    out.extend(frame(4, 0, 0, b""));
    for i in 0..STREAMS {
        out.extend(frame(1, 4, 1 + 2 * i, &request(b"POST")));
    }
    s.write_all(&out).expect("write");
    s
}

/// (HEADERS frames, whether a DATA frame carried "503") in `got`.
fn count_frames(got: &[u8]) -> (usize, bool) {
    let (mut headers, mut saw_503, mut i) = (0, false, 0);
    while i + 9 <= got.len() {
        let len = usize::from(got[i]) << 16 | usize::from(got[i + 1]) << 8 | usize::from(got[i + 2]);
        let end = (i + 9 + len).min(got.len());
        match got[i + 3] {
            1 => headers += 1,
            0 => saw_503 |= got[i + 9..end].windows(3).any(|w| w == b"503"),
            _ => {}
        }
        i += 9 + len;
    }
    (headers, saw_503)
}

/// (HEADERS frames, whether a DATA frame carried "503") read from `s` within `wait`.
fn answers(s: &mut TcpStream, wait: Duration) -> (usize, bool) {
    answers_until(s, wait, usize::MAX)
}

/// Like `answers`, but returns as soon as `enough` HEADERS frames and a "503" have arrived: a
/// loaded host takes longer than any fixed time to get the proxy to its descriptor limit, so
/// callers give a long `wait` and are not slowed by it when the host is quiet.
fn answers_until(s: &mut TcpStream, wait: Duration, enough: usize) -> (usize, bool) {
    s.set_read_timeout(Some(Duration::from_millis(100))).expect("timeout");
    let mut got = Vec::new();
    let deadline = Instant::now() + wait;
    let mut buf = [0u8; 65536];
    // Once `enough` has arrived, keep reading for another second: what follows is still
    // part of the answer (and the callers measure the proxy after it).
    let mut enough_at: Option<Instant> = None;
    while Instant::now() < deadline && enough_at.is_none_or(|t| t.elapsed() < Duration::from_secs(1)) {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(_) => {}
        }
        let (headers, saw_503) = count_frames(&got);
        if headers >= enough && saw_503 {
            enough_at.get_or_insert_with(Instant::now);
        }
    }
    count_frames(&got)
}

fn open_fds(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd")).expect("fd dir").count()
}

/// Waits until `pid` holds as many descriptors as 50 ms before (at most 2 s).
fn settle_fds(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut last = open_fds(pid);
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
        let now = open_fds(pid);
        if now == last {
            return;
        }
        last = now;
    }
}

/// The status line of a GET on a fresh h1 connection, or what went wrong.
fn h1_get(addr: SocketAddr) -> String {
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(1)) else {
        return "connect failed".into();
    };
    s.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
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
fn held_h2_streams_stop_at_maxsock_and_the_rest_get_a_503() {
    let (h2, h1) = (common::reserve_addr(), common::reserve_addr());
    let (be, accepted) = holding_backend();
    let alcyon = spawn(h2, h1, be);
    assert!(common::wait_listening(h2) && common::wait_listening(h1), "alcyon never listened");

    let mut s = hold_streams(h2);
    let (headers, saw_503) = answers_until(&mut s, Duration::from_secs(30), 50);
    let fds = open_fds(alcyon.child.id());
    let servers = accepted.load(Ordering::SeqCst);
    // HAProxy: 46 fds, 36 server connections, 64 streams answered 503.
    assert!(fds <= MAXSOCK, "{fds} descriptors open with maxsock {MAXSOCK} ({servers} server connections)");
    assert!(servers < MAXSOCK, "{servers} server connections with maxsock {MAXSOCK}");
    assert!(headers >= 50 && saw_503, "{headers} streams answered (503 seen: {saw_503}); HAProxy answers the 64 it cannot connect with a 503");
}

#[test]
fn a_client_past_maxsock_is_closed_and_served_once_descriptors_free_up() {
    let (h2, h1) = (common::reserve_addr(), common::reserve_addr());
    let (be, _) = holding_backend();
    let alcyon = spawn(h2, h1, be);
    assert!(common::wait_listening(h2) && common::wait_listening(h1), "alcyon never listened");
    // The probes' connections are closed by the client: the proxy holds their descriptors
    // until it reads the close. Taken by the burst below, one of them was a server
    // connection fewer, and the descriptor it freed later served the client asserted
    // refused (35 server connections and 45 descriptors, not 36 and 46, once the streams
    // ran in the pass their owner woke them in, L2).
    settle_fds(alcyon.child.id());

    let mut s = hold_streams(h2);
    let _ = answers_until(&mut s, Duration::from_secs(30), 50);
    let saturated = h1_get(h1);
    assert_ne!(saturated, "HTTP/1.1 200 OK", "a client was served on a descriptor past maxsock");

    drop(s);
    let t = Instant::now();
    let mut after = h1_get(h1);
    while after != "HTTP/1.1 200 OK" && t.elapsed() < Duration::from_secs(20) {
        thread::sleep(Duration::from_millis(50));
        after = h1_get(h1);
    }
    assert_eq!(after, "HTTP/1.1 200 OK", "not served within 20 s of the descriptors being released");
}

/// (`Maxsock`, `Ulimit-n`) from `show info` on the stats socket in `dir`.
fn info_limits(dir: &std::path::Path) -> (String, String) {
    use std::os::unix::net::UnixStream;
    let mut s = UnixStream::connect(dir.join("sock")).expect("stats socket");
    s.write_all(b"show info\n").expect("write");
    let mut out = String::new();
    s.read_to_string(&mut out).expect("read");
    let field = |k: &str| out.lines().find_map(|l| l.strip_prefix(k)).unwrap_or("").trim().to_string();
    (field("Maxsock:"), field("Ulimit-n:"))
}

/// What `bin` does with `INHERITED_FD` open at start: `(Maxsock, Ulimit-n, descriptors other than
/// the inherited one, server connections, 503 seen)` with 100 held h2 streams.
fn inherited_run(bin: &str) -> ((String, String), usize, usize, bool) {
    let (h2, h1) = (common::reserve_addr(), common::reserve_addr());
    let (be, accepted) = holding_backend();
    let alcyon = spawn_with(bin, true, h2, h1, be);
    assert!(common::wait_listening(h2) && common::wait_listening(h1), "{bin} never listened");
    let limits = info_limits(&alcyon.dir);
    let mut s = hold_streams(h2);
    let (_, saw_503) = answers_until(&mut s, Duration::from_secs(30), 50);
    let pid = alcyon.child.id();
    let open = std::fs::read_dir(format!("/proc/{pid}/fd")).expect("fd dir").flatten().filter(|e| e.file_name().to_str() != Some("2000")).count();
    (limits, open, accepted.load(Ordering::SeqCst), saw_503)
}

/// `HAProxy`'s `maxsock` is what the configuration sizes, not what it found open: with a
/// descriptor at 2000 inherited, `Maxsock` is still 46, the sockets stay under it and the
/// streams that cannot connect get a 503 (measured on 3.5-dev8-885761-29, T438).
#[test]
fn an_inherited_high_descriptor_does_not_raise_the_ceiling() {
    let ((maxsock, ulimit), open, servers, saw_503) = inherited_run(env!("CARGO_BIN_EXE_alcyon"));
    assert_eq!((maxsock.as_str(), ulimit.as_str()), ("46", "46"), "Maxsock / Ulimit-n");
    assert!(open <= MAXSOCK, "{open} descriptors open besides the inherited one, maxsock {MAXSOCK}");
    assert!(servers < MAXSOCK && saw_503, "{servers} server connections (503 seen: {saw_503})");
}

/// The oracle, started the same way: what the test above asserts of Alcyon.
#[test]
fn oracle_with_an_inherited_high_descriptor_keeps_its_ceiling() {
    let haproxy = "/home/bhenc/reference/haproxy/haproxy";
    if !std::path::Path::new(haproxy).exists() {
        return;
    }
    let ((maxsock, ulimit), open, servers, saw_503) = inherited_run(haproxy);
    assert_eq!((maxsock.as_str(), ulimit.as_str()), ("46", "46"), "Maxsock / Ulimit-n");
    assert!(open <= MAXSOCK, "{open} descriptors open besides the inherited one");
    assert!(servers < MAXSOCK && saw_503, "{servers} server connections (503 seen: {saw_503})");
}
