// SPDX-License-Identifier: GPL-2.0-or-later
//! `errorfile` against the real binary, with what `HAProxy` 3.5 sends for the same
//! configuration.
//!
//! The reg-tests in `reg-tests/http-errorfiles` reach error pages through `http-request
//! deny`/`return`. The page an operator most often customises is the 503 the proxy sends
//! itself when no server can take the request; `HAProxy` looks for it in the backend's
//! pages, then the frontend's (`http_error_message`, `src/http_ana.c`).

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

struct Ibex {
    child: Child,
    _cfgs: Vec<NamedTempFile>,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        stop(&mut self.child);
    }
}

/// Stops the binary the way it exits cleanly -- `SIGUSR1`, the soft stop -- so an
/// instrumented build writes its coverage profile; `SIGKILL` discards it, which left every
/// line these tests run invisible to `harness/covercheck.py`. Killed if it lingers.
fn stop(child: &mut Child) {
    let _ = Command::new("kill").arg("-USR1").arg(child.id().to_string()).status();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn page(raw: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(raw.as_bytes()).expect("write page");
    f
}

/// Starts ibex on `cfg`, where `{fe}` is the listening address and `{0}`, `{1}`, ... are the
/// paths of `pages`.
fn start(cfg: &str, pages: Vec<NamedTempFile>) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let mut text = cfg.replace("{fe}", &fe.to_string());
    for (i, p) in pages.iter().enumerate() {
        text = text.replace(&format!("{{{i}}}"), &p.path().display().to_string());
    }
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let mut files = pages;
    files.push(f);
    let ibex = Ibex { child, _cfgs: files };
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
        thread::sleep(Duration::from_millis(20));
    }
    (ibex, fe)
}

/// Sends `GET path` on `c` and reads until `quiet` passes with nothing arriving, the peer
/// closes, or two seconds pass. The bool is whether the peer closed.
fn get(c: &mut TcpStream, path: &str, quiet: Duration) -> (String, bool) {
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).unwrap();
    c.set_read_timeout(Some(quiet)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    let mut closed = false;
    while Instant::now() < deadline {
        match c.read(&mut buf) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(n) => resp.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    (String::from_utf8_lossy(&resp).into_owned(), closed)
}

const DEFAULTS: &str =
    "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n";

/// `HAProxy`: `x-page: custom503` for `/own`, `x-page: fe` for `/bare`.
#[test]
fn the_proxys_own_503_uses_the_backends_errorfile_then_the_frontends() {
    let (_ibex, fe) = start(
        &format!(
            "{DEFAULTS}frontend fe\n  bind {{fe}}\n  errorfile 503 {{0}}\n\
             \x20 use_backend own if {{ path /own }}\n  default_backend bare\n\
             backend own\n  errorfile 503 {{1}}\nbackend bare\n"
        ),
        vec![
            page("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 3\r\nX-Page: fe\r\n\r\nfe\n"),
            page("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 6\r\nX-Page: custom503\r\n\r\nsorry\n"),
        ],
    );
    for (path, want) in [("/own", "X-Page: custom503"), ("/bare", "X-Page: fe")] {
        let mut c = TcpStream::connect(fe).expect("connect");
        let (resp, _) = get(&mut c, path, Duration::from_millis(300));
        assert!(resp.starts_with("HTTP/1.1 503"), "{path}: {resp:?}");
        assert!(resp.contains(want), "{path}: wanted {want}: {resp:?}");
    }
}

/// `http-request return ... errorfile` answers and keeps the connection, like `return` with
/// an inline body: `HAProxy` answered three requests in a row on one connection.
#[test]
fn return_with_an_errorfile_keeps_the_connection() {
    let (_ibex, fe) = start(
        &format!(
            "{DEFAULTS}frontend fe\n  bind {{fe}}\n  http-request return status 200 errorfile {{0}}\n\
             \x20 default_backend be\nbackend be\n"
        ),
        vec![page("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX-Page: ret200\r\n\r\nhi\n")],
    );
    let mut c = TcpStream::connect(fe).expect("connect");
    for i in 0..3 {
        let (resp, closed) = get(&mut c, &format!("/{i}"), Duration::from_millis(300));
        assert_eq!(resp.matches("X-Page: ret200").count(), 1, "request {i}: {resp:?}");
        assert!(!closed, "request {i} closed the connection: {resp:?}");
    }
}
