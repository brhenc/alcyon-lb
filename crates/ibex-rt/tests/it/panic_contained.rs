// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A panic in one stream's run closes that stream, not the process (T447).
//!
//! `ibex.debug.panic <request|response> <path-prefix>` (debug builds only) makes the run of
//! the stream whose request path starts with the prefix panic once its request head is
//! parsed, or once its response head is in. Before T447 the panic hook aborted the process
//! (T238) and every other connection went with it.
//!
//! What the stream's end looks like follows `HAProxy`'s internal errors, measured on 3.5-dev8
//! with `-dMfail` and `tune.fail-alloc 10` (`tasks/T447-progress.md`): termination state `I`
//! and the phase, counted in `eint`; the connection is closed without a response, as on a
//! failed `stream_new`.

use crate::common;

use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// A keep-alive HTTP/1.1 server answering `ok` to every request, counting the connections
/// it saw closed by the proxy.
fn backend() -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = l.local_addr().expect("addr");
    let closed = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&closed);
    thread::spawn(move || {
        for s in l.incoming().map_while(Result::ok) {
            let seen = Arc::clone(&seen);
            thread::spawn(move || serve(s, &seen));
        }
    });
    (addr, closed)
}

fn serve(mut s: TcpStream, closed: &AtomicUsize) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            buf.drain(..end + 4);
            if s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").is_err() {
                break;
            }
        }
    }
    closed.fetch_add(1, Ordering::SeqCst);
}

struct Ibex {
    child: Child,
    sock: PathBuf,
    stderr: PathBuf,
    _dir: tempfile::TempDir,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn start(fault: &str, server: SocketAddr) -> (Ibex, SocketAddr) {
    let dir = tempfile::TempDir::new().expect("tmp");
    let front = common::reserve_addr();
    let sock = dir.path().join("cli.sock");
    let cfg = format!(
        "global\n  stats socket {} level admin\n  ibex.debug.panic {fault}\n\
         defaults\n  mode http\n  log stderr format raw local0\n  option httplog\n\
           timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {front}\n  default_backend b\n\
         backend b\n  server s {server}\n",
        sock.display()
    );
    let path = dir.path().join("ibex.cfg");
    std::fs::write(&path, cfg).expect("write cfg");
    let stderr = dir.path().join("stderr");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .args(["-db", "-f"])
        .arg(&path)
        // A panic that is not contained exits 134 at once under `LLVM_PROFILE_FILE` instead
        // of aborting (`crash::die`): no core dump to wait for, no crash report. An
        // instrumented run keeps its own path.
        .env("LLVM_PROFILE_FILE", std::env::var_os("LLVM_PROFILE_FILE").unwrap_or_else(|| "/tmp/ibex-t447-%p.profraw".into()))
        .stdout(Stdio::null())
        .stderr(File::create(&stderr).expect("stderr file"))
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, sock, stderr, _dir: dir };
    assert!(common::wait_listening(front), "ibex never listened");
    (ibex, front)
}

fn cli(sock: &Path, cmd: &str) -> String {
    let mut c = UnixStream::connect(sock).expect("connect cli");
    c.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    out
}

/// `col` of the `show stat` line `px,sv`.
fn stat(sock: &Path, px: &str, sv: &str, col: &str) -> String {
    let out = cli(sock, "show stat");
    let mut lines = out.lines();
    let head: Vec<&str> = lines.next().unwrap_or("").trim_start_matches("# ").split(',').collect();
    let i = head.iter().position(|h| *h == col).unwrap_or_else(|| panic!("no column {col}"));
    lines
        .map(|l| l.split(',').collect::<Vec<_>>())
        .find(|v| v.len() > i && v[0] == px && v[1] == sv)
        .map_or_else(|| panic!("no line {px},{sv}:\n{out}"), |v| v[i].to_string())
}

/// Everything the proxy sends before it closes, or `None` if it does not close in 5 s.
fn read_to_close(c: &mut TcpStream) -> Option<Vec<u8>> {
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut got = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match c.read(&mut chunk) {
            Ok(0) => return Some(got),
            Ok(n) => got.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::ConnectionReset => return Some(got),
            Err(_) => return None,
        }
    }
}

/// One complete response on `c`, `content-length: 2`.
fn read_response(c: &mut TcpStream) -> String {
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut got = Vec::new();
    let mut chunk = [0u8; 4096];
    while got.windows(4).position(|w| w == b"\r\n\r\n").is_none_or(|e| got.len() < e + 6) {
        match c.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8_lossy(&got).into_owned()
}

fn get(front: SocketAddr, path: &str) -> String {
    let mut c = TcpStream::connect(front).expect("connect");
    c.write_all(format!("GET {path} HTTP/1.1\r\nhost: x\r\n\r\n").as_bytes()).expect("send");
    read_response(&mut c)
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if f() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("never: {what}");
}

/// The panicking stream, with another connection in the middle of its request: the panicking
/// one is closed unanswered, the other is answered, the process serves on.
fn panic_in(fault: &str) -> (Ibex, Arc<AtomicUsize>) {
    let (server, closed) = backend();
    let (mut ibex, front) = start(fault, server);
    // A connection served before, kept alive, and in the middle of its next request.
    let mut other = TcpStream::connect(front).expect("connect");
    other.write_all(b"GET /first HTTP/1.1\r\nhost: x\r\n\r\n").expect("send");
    assert!(read_response(&mut other).starts_with("HTTP/1.1 200"), "the first request is served");
    other.write_all(b"GET /second HTTP/1.1\r\nhost: x\r\n").expect("send");

    let mut boom = TcpStream::connect(front).expect("connect");
    boom.write_all(b"GET /boom HTTP/1.1\r\nhost: x\r\n\r\n").expect("send");
    let got = read_to_close(&mut boom).expect("the panicking stream is closed");
    thread::sleep(Duration::from_millis(100));
    let err = std::fs::read_to_string(&ibex.stderr).unwrap_or_default();
    assert!(ibex.child.try_wait().expect("try_wait").is_none(), "the process died:\n{err}");
    if fault.starts_with("request") {
        assert!(got.is_empty(), "no response to the panicking stream: {}", String::from_utf8_lossy(&got));
    }

    other.write_all(b"\r\n").expect("finish the request");
    let r = read_response(&mut other);
    assert!(r.starts_with("HTTP/1.1 200") && r.ends_with("ok"), "the other connection is served: {r:?}");
    let r = get(front, "/after");
    assert!(r.starts_with("HTTP/1.1 200"), "a new connection is served: {r:?}");
    drop(other);

    assert_eq!(stat(&ibex.sock, "f", "FRONTEND", "eint"), "1", "an internal error on the frontend");
    wait_for("every stream ended", || stat(&ibex.sock, "f", "FRONTEND", "scur") == "0" && stat(&ibex.sock, "b", "s", "scur") == "0");
    let err = std::fs::read_to_string(&ibex.stderr).unwrap_or_default();
    assert!(err.contains("deliberate panic in the stream of /boom"), "the panic is reported:\n{err}");
    assert!(err.contains("[ALERT]") && err.contains("closed"), "an alert says the stream was closed:\n{err}");
    let line = err.lines().find(|l| l.contains("GET /boom")).unwrap_or_else(|| panic!("no log line for /boom:\n{err}"));
    assert!(line.contains(" I"), "termination state I: {line}");
    (ibex, closed)
}

#[test]
fn a_panic_with_the_request_head_closes_that_stream_only() {
    let (ibex, _) = panic_in("request /boom");
    let err = std::fs::read_to_string(&ibex.stderr).unwrap_or_default();
    let line = err.lines().find(|l| l.contains("GET /boom")).unwrap_or_default();
    // `HAProxy`'s internal error in the request phase is `IR--` (it answers 500 there).
    assert!(line.contains(" -1 0 - - IR-- "), "no status was sent, the stream failed in its request: {line}");
    assert_eq!(stat(&ibex.sock, "b", "BACKEND", "eint"), "0", "no backend had it yet");
}

#[test]
fn a_panic_with_the_response_head_releases_the_server_connection() {
    let (ibex, closed) = panic_in("response /boom");
    // The panicking stream's server connection is closed, not left to its server.
    wait_for("the server connection of /boom closed", || closed.load(Ordering::SeqCst) >= 1);
    let err = std::fs::read_to_string(&ibex.stderr).unwrap_or_default();
    let line = err.lines().find(|l| l.contains("GET /boom")).unwrap_or_default();
    assert!(line.contains(" f b/s ") && line.contains(" IH-- "), "the stream failed with its response head: {line}");
    assert_eq!(stat(&ibex.sock, "b", "BACKEND", "eint"), "1", "and on its backend");
    assert_eq!(stat(&ibex.sock, "b", "s", "eint"), "1", "and on its server");
}

/// A panic under a shared lock may have left what it guards half-changed: that one is not
/// contained, the process goes down as before T447 (exit 134 here, SIGABRT deployed).
#[test]
fn a_panic_under_a_shared_lock_still_takes_the_process_down() {
    let (server, _) = backend();
    let (mut ibex, front) = start("request-locked /boom", server);
    let mut boom = TcpStream::connect(front).expect("connect");
    boom.write_all(b"GET /boom HTTP/1.1\r\nhost: x\r\n\r\n").expect("send");
    let _ = read_to_close(&mut boom);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut st = None;
    while st.is_none() && Instant::now() < deadline {
        st = ibex.child.try_wait().expect("try_wait");
        thread::sleep(Duration::from_millis(20));
    }
    let err = std::fs::read_to_string(&ibex.stderr).unwrap_or_default();
    assert_eq!(st.and_then(|s| s.code()), Some(134), "the process exits as on SIGABRT:\n{err}");
    assert!(err.contains("[ALERT] ibex: a stream panicked and left the ibex.debug.panic lock half-changed"), "{err}");
}
