// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `option persist` (T149b).
//!
//! Measured on HAProxy 3.5-dev8-885761-29: two servers, a stick table on a request header
//! (`stick on req.hdr(x-k)`) or a `cookie SRV insert` with `cookie c1`/`c2` on the servers.
//! Keys `a` and `b` first go to s1 and s2. After `set server b/s1 state maint`:
//!   - without `option persist`: `a` is load balanced (s2); with the cookie, the response
//!     carries `Set-Cookie: SRV=c2; path=/`;
//!   - with `option persist`: `a` still goes to s1, and no `Set-Cookie` is sent.
//! A draining server (`state drain`) keeps its clients either way.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
    sock: PathBuf,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
    }
}

fn server(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        buf.drain(..end + 4);
                        let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Server: {name}\r\n\r\nok");
                        if c.write_all(resp.as_bytes()).is_err() {
                            return;
                        }
                    }
                    match c.read(&mut chunk) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
            });
        }
    });
    addr
}

fn start(backend_lines: &str) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let sock = std::env::temp_dir().join(format!("ibex_t149b_{}_{n}.sock", std::process::id()));
    let (s1, s2) = (server("s1"), server("s2"));
    let text = format!(
        "global\n  nbthread 1\n  stats socket {sock} mode 600 level admin\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  default_backend b\nbackend b\n{backend_lines}  server s1 {s1} cookie c1\n  server s2 {s2} cookie c2\n",
        sock = sock.display()
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, _cfg: f, sock };
    assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !ibex.sock.exists() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    (ibex, fe)
}

fn cli(ibex: &Ibex, cmd: &str) -> String {
    let mut s = UnixStream::connect(&ibex.sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// The `X-Server` and `Set-Cookie` lines of the answer to `GET /` with `header`.
fn get(fe: SocketAddr, header: &str) -> (String, Option<String>) {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(format!("GET / HTTP/1.1\r\nHost: x\r\n{header}\r\nConnection: close\r\n\r\n").as_bytes()).expect("send");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    let text = String::from_utf8_lossy(&got).into_owned();
    // Header names are case-insensitive; HAProxy emits them lowercase.
    let line = |name: &str| {
        text.split("\r\n").find_map(|l| l.split_once(": ").filter(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.to_string()))
    };
    (line("X-Server").unwrap_or_else(|| text.lines().next().unwrap_or("<nothing>").to_string()), line("Set-Cookie"))
}

const STICK: &str = "  stick-table type string len 20 size 100\n  stick on req.hdr(x-k)\n";

fn stick_after(extra: &str, state: &str) -> Vec<String> {
    let (ibex, fe) = start(&format!("{STICK}{extra}"));
    let first = [get(fe, "X-K: a\r\n").0, get(fe, "X-K: b\r\n").0];
    assert_eq!(first, ["s1", "s2"], "the keys were not spread over the two servers first");
    assert_eq!(cli(&ibex, &format!("set server b/s1 state {state}")).trim(), "");
    vec![get(fe, "X-K: a\r\n").0, get(fe, "X-K: b\r\n").0]
}

#[test]
fn stick_match_without_persist_leaves_a_server_in_maint() {
    assert_eq!(stick_after("", "maint"), ["s2", "s2"]);
}

#[test]
fn stick_match_with_persist_keeps_the_server_in_maint() {
    assert_eq!(stick_after("  option persist\n", "maint"), ["s1", "s2"]);
}

#[test]
fn a_draining_server_keeps_its_clients_either_way() {
    assert_eq!(stick_after("", "drain"), ["s1", "s2"]);
}

#[test]
fn no_option_persist_turns_it_off() {
    assert_eq!(stick_after("  option persist\n  no option persist\n", "maint"), ["s2", "s2"]);
}

#[test]
fn cookie_without_persist_is_redistributed_and_reissued() {
    let (ibex, fe) = start("  cookie SRV insert\n");
    cli(&ibex, "set server b/s1 state maint");
    assert_eq!(get(fe, "Cookie: SRV=c1\r\n"), ("s2".to_string(), Some("SRV=c2; path=/".to_string())));
}

#[test]
fn cookie_with_persist_goes_to_the_server_in_maint_and_issues_nothing() {
    let (ibex, fe) = start("  cookie SRV insert\n  option persist\n");
    cli(&ibex, "set server b/s1 state maint");
    assert_eq!(get(fe, "Cookie: SRV=c1\r\n"), ("s1".to_string(), None));
}

/// Measured: a table a `stick` rule fills shows the server it stored, whether or not `store`
/// names `server_id`: `... shard=0 server_id=1 server_key=s1`, the ids numbering the servers
/// from 1.
#[test]
fn a_stick_table_shows_the_server_it_stored() {
    let (ibex, fe) = start(STICK);
    assert_eq!(get(fe, "X-K: a\r\n").0, "s1");
    assert_eq!(get(fe, "X-K: b\r\n").0, "s2");
    let out = cli(&ibex, "show table b");
    assert!(out.contains("key=a ") && out.contains(" shard=0 server_id=1 server_key=s1"), "{out}");
    assert!(out.contains("key=b ") && out.contains(" shard=0 server_id=2 server_key=s2"), "{out}");
}
