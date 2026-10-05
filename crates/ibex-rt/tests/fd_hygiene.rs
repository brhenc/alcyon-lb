// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! No socket is kept open after its peer is gone (T217).
//!
//! Measured on HAProxy 3.5-dev8-885761-29 (`nbthread 1`, 10 keep-alive clients one request
//! each, a backend that closes its connection 200 ms after answering, by FIN or by RST): 1.5 s
//! later the process holds the listener and the 10 client sockets and no server socket
//! (`/proc/<pid>/fd`); it subscribes its idle server connections for reads and closes one that
//! reads EOF, an error or data (`conn_idle_*`, `srv_cleanup_*`). Ibex kept the dead ones in the
//! pool until a request took them (283 left open in T187's soak run).

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// A backend that answers one request per connection and closes the connection 200 ms later:
/// with a FIN, or with an RST (`SO_LINGER` 0).
fn closing_backend(rst: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                if s.read(&mut buf).unwrap_or(0) == 0 {
                    return;
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                thread::sleep(Duration::from_millis(200));
                if rst {
                    let _ = rustix::net::sockopt::set_socket_linger(&s, Some(Duration::ZERO));
                }
            });
        }
    });
    addr
}

struct Ibex(Child, #[allow(dead_code)] NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(cfg: &str, fe: SocketAddr) -> Ibex {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never started listening on {fe}");
    Ibex(child, f)
}

/// Sockets `pid` holds, from `/proc/<pid>/fd`.
fn sockets(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .expect("fd dir")
        .filter_map(Result::ok)
        .filter(|e| std::fs::read_link(e.path()).is_ok_and(|l| l.to_string_lossy().starts_with("socket:")))
        .count()
}

fn ask(c: &mut TcpStream) -> String {
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    while !resp.ends_with(b"ok") {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&resp).lines().next().unwrap_or("").to_string()
}

/// `n` keep-alive clients each send a request, the server closes every server connection;
/// returns the sockets the proxy holds beyond its listener and the clients one second
/// later, and the answers to a second request on each client.
fn closed_by_server(rst: bool, n: usize) -> (usize, Vec<String>) {
    let be = closing_backend(rst);
    let fe = common::reserve_addr();
    let ibex = start(
        &format!(
            "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n\
             listen l\n  bind {fe}\n  server s {be}\n"
        ),
        fe,
    );
    let pid = ibex.0.id();
    let mut clients = Vec::new();
    for _ in 0..n {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        assert!(ask(&mut c).starts_with("HTTP/1.1 200"));
        clients.push(c);
        thread::sleep(Duration::from_millis(10));
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    // the listener and the clients are the sockets that belong there
    let want = n + 1;
    thread::sleep(Duration::from_millis(500));
    while Instant::now() < deadline && sockets(pid) > want {
        thread::sleep(Duration::from_millis(50));
    }
    let extra = sockets(pid).saturating_sub(want);
    let answers = clients.iter_mut().map(ask).collect();
    (extra, answers)
}

/// An idle pooled server connection whose server closed it is closed within a poll: by FIN
/// and by RST.
#[test]
fn an_idle_server_connection_the_server_closed_is_closed() {
    for rst in [false, true] {
        let (extra, answers) = closed_by_server(rst, 10);
        assert_eq!(extra, 0, "rst={rst}: {extra} server sockets open after the server closed them");
        assert!(answers.iter().all(|a| a.starts_with("HTTP/1.1 200")), "rst={rst}: {answers:?}");
    }
}
