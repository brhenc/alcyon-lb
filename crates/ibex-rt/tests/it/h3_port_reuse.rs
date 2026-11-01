// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T567: across a reload, a new QUIC client whose source address and port equal those of a peer
//! the stopping process still holds (its connection is pinned to the old worker by a connected
//! socket) reaches the old process, not the new one: the kernel delivers the datagram to the old
//! process's connected socket. `HAProxy` with the private reload-loss patch (v2) then serves the
//! new connection in the old worker; Ibex does the same (it used to answer `CONNECTION_REFUSED`).
//! Unpatched dev10 completes the handshake there and never answers. See `tradeoff.md` 6.31.

use crate::common;
use crate::h3_mux_drain::{get, Client};

use rustix::process::{kill_process, Pid, Signal};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

fn slow_backend() -> SocketAddr {
    let ls = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = ls.local_addr().expect("addr");
    thread::spawn(move || {
        for s in ls.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                if got.starts_with(b"GET /slow") {
                    thread::sleep(Duration::from_secs(3));
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
            });
        }
    });
    addr
}

fn signal(pid: u32, sig: Signal) {
    if let Some(p) = Pid::from_raw(i32::try_from(pid).unwrap_or(0)) {
        let _ = kill_process(p, sig);
    }
}

#[test]
fn a_new_client_on_the_source_port_of_a_pinned_peer_is_served_by_the_stopping_process() {
    let be = slow_backend();
    let tcp = common::reserve_addr();
    let quic = common::reserve_addr();
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let dir = tempfile::tempdir().expect("tmpdir");
    let cfg = dir.path().join("c.cfg");
    let pidfile = dir.path().join("p.pid");
    std::fs::write(
        &cfg,
        format!(
            "global\n  nbthread 1\n  hard-stop-after 6s\n\
             defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
             frontend fe\n  bind {tcp}\n  bind quic4@{quic} ssl crt {crt} alpn h3\n  default_backend be\n\
             backend be\n  server s1 {be}\n"
        ),
    )
    .expect("cfg");
    let mut first = common::Ibex(
        common::ibex_command(env!("CARGO_BIN_EXE_ibex"))
            .arg("-W")
            .arg("-f")
            .arg(&cfg)
            .arg("-p")
            .arg(&pidfile)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ibex"),
    );
    assert!(common::wait_listening(tcp), "ibex did not start");
    let old = first.0.id();

    // The first client pins a connection to the old process with a request that outlives the reload.
    let sock = UdpSocket::bind("127.0.0.1:0").expect("client socket");
    let sock_b = sock.try_clone().expect("clone");
    let mut a = Client::begin_on(sock, quic);
    a.finish_handshake();
    let slow = a.open(&get(b"/slow"), true);
    a.run_until(Duration::from_millis(300), |_| false);

    signal(old, Signal::Usr2);
    let t0 = Instant::now();
    let mut new = old;
    while new == old && t0.elapsed() < Duration::from_secs(10) {
        new = std::fs::read_to_string(&pidfile).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(old);
        thread::sleep(Duration::from_millis(10));
    }
    assert_ne!(new, old, "no new process");
    thread::sleep(Duration::from_millis(500));

    // A second client, same 4-tuple, while the old process still holds the first.
    let mut b = Client::begin_on(sock_b, quic);
    let t1 = Instant::now();
    b.run_until(Duration::from_secs(3), |c| c.lost.is_some() || !c.conn_is_handshaking());
    let handshook = b.lost.is_none() && !b.conn_is_handshaking();
    let mut status = None;
    if handshook {
        let fast = b.open(&get(b"/fast"), true);
        status = b.outcome(fast).status;
    }
    let verdict = b.lost.clone().map(|l| l.0);
    let took = t1.elapsed();
    let _ = slow;
    signal(new, Signal::Usr1);
    signal(old, Signal::Usr1);
    thread::sleep(Duration::from_millis(200));
    common::stop(&mut first.0);
    assert_eq!(status, Some(200), "the request on the reused port got no answer (closed with {verdict:?}, after {took:?})");
}
