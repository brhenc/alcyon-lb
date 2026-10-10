// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Idle server connections and the process's file descriptors (`tune.pool-high-fd-ratio`,
//! `tune.pool-low-fd-ratio`, T230).
//!
//! `HAProxy` keeps a released server connection idle only while the fds in use are below
//! `pool-high-fd-ratio` (25) percent of `maxsock`, and keeps more than the server was seen to
//! need only below `pool-low-fd-ratio` (20) percent (`srv_add_to_idle_list`). Measured on
//! `HAProxy 3.5-dev8-885761-29` (`harness/idle_oracle.py`, `nbthread 1`, `maxconn 100`, so
//! `maxsock` 225 with a stats socket): N clients each with one request answered, all kept
//! open; the server connections still open then: N=10 keeps 9, N=30 keeps 11, N=60 keeps 0;
//! with both ratios raised (90 and 80), N=30 keeps 23. The exact numbers move a little with
//! timing. Ibex kept one per client in every case: on devtest7 ~2,000 idle connections after
//! a burst over `maxconn 2000`, where `HAProxy` kept 173.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

struct Ibex(Child);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// A server that answers every request on a connection after 200 ms, and counts its open
/// connections. The wait puts every client's request at the server at once, so the server is
/// seen to need one connection per client: how many are kept then depends on the fds alone,
/// not on how the requests happened to interleave.
fn counting_server() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("server");
    let addr = listener.local_addr().unwrap();
    let open = Arc::new(AtomicUsize::new(0));
    let o = Arc::clone(&open);
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            let o = Arc::clone(&o);
            o.fetch_add(1, Ordering::SeqCst);
            thread::spawn(move || {
                let mut got = Vec::new();
                let mut b = [0u8; 4096];
                loop {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&b[..n]),
                    }
                    while let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                        got.drain(..i + 4);
                        thread::sleep(Duration::from_millis(200));
                        if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                            break;
                        }
                    }
                }
                o.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    (addr, open)
}

/// The server connections still open once `n` clients, kept open, each had one request
/// answered, with `global_extra` in the global section.
fn kept(n: usize, global_extra: &str) -> usize {
    let (srv, open) = counting_server();
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n  nbthread 1\n  maxconn 100\n{global_extra}\
         defaults\n  mode http\n  timeout client 10s\n  timeout connect 2s\n  timeout server 10s\n\
         frontend f\n  bind {fe}\n  default_backend b\n\
         backend b\n  server s {srv}\n"
    );
    let path = std::env::temp_dir().join(format!("ibex-pfr-{}-{n}-{}.cfg", std::process::id(), global_extra.len()));
    std::fs::write(&path, cfg).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let _ibex = Ibex(child);
    assert!(common::wait_listening(fe), "ibex never listened");
    let _ = std::fs::remove_file(&path);

    let mut clients = Vec::new();
    for _ in 0..n {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
        clients.push(c);
    }
    for c in &mut clients {
        let mut got = Vec::new();
        let mut b = [0u8; 1024];
        while !got.ends_with(b"ok") {
            let r = c.read(&mut b).expect("a response");
            assert!(r > 0, "closed before the response");
            got.extend_from_slice(&b[..r]);
        }
    }
    // The server side of a connection Ibex closed counts down when its thread reads the EOF.
    thread::sleep(Duration::from_millis(300));
    open.load(Ordering::SeqCst)
}

/// 60 clients at `maxconn 100`: 60 client and 60 server connections are far over a quarter
/// of `maxsock` (214 without a stats socket), so the server connections are not kept.
/// `HAProxy`: 0.
#[test]
fn over_the_high_fd_ratio_released_server_connections_are_closed() {
    let n = kept(60, "");
    assert!(n <= 30, "{n} of 60 server connections kept idle over the fd ratio (HAProxy: 0)");
}

/// The same with both ratios at 100: under them the connections are kept as before.
#[test]
fn under_raised_fd_ratios_released_server_connections_are_kept() {
    let n = kept(60, "  tune.pool-high-fd-ratio 100\n  tune.pool-low-fd-ratio 100\n");
    assert!(n >= 45, "only {n} of 60 server connections kept with both ratios at 100");
}

/// The two keywords take an integer from 0 to 100, read by `atoi` (text that is not a number
/// is 0), with `HAProxy`'s messages (`cfg_parse_pool_fd_ratio`, measured on 3.5-dev8):
/// `'tune.pool-high-fd-ratio' expects an integer argument between 0 and 100.` and
/// `'tune.pool-high-fd-ratio' cannot handle unexpected argument 'x'.`
#[test]
fn the_fd_ratios_take_a_percentage() {
    let range = "expects an integer argument between 0 and 100.";
    for kw in ["tune.pool-high-fd-ratio", "tune.pool-low-fd-ratio"] {
        for (arg, refused) in [("0", None), ("100", None), ("+5", None), ("abc", None), ("7x", None), ("", Some(range)), ("101", Some(range)), ("-1", Some(range)), ("50 x", Some("cannot handle unexpected argument 'x'."))] {
            let fe = common::reserve_addr();
            let path = std::env::temp_dir().join(format!("ibex-pfr-kw-{}.cfg", std::process::id()));
            std::fs::write(&path, format!("global\n  {kw} {arg}\ndefaults\n  mode http\nlisten l\n  bind {fe}\n  server s 127.0.0.1:1\n")).unwrap();
            let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("ibex -c");
            let _ = std::fs::remove_file(&path);
            let err = String::from_utf8_lossy(&out.stderr);
            match refused {
                None => assert!(out.status.success(), "{kw} {arg:?} refused: {err}"),
                Some(msg) => {
                    assert!(!out.status.success(), "{kw} {arg:?} accepted");
                    assert!(err.contains(&format!("'{kw}' {msg}")), "{kw} {arg:?}: {err}");
                }
            }
        }
    }
}
