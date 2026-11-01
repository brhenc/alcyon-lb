// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The ACK policy of insreq's HTTP/3 client (T555, `tools/measure/h3bench`) against Ibex:
//! the client datagrams per request are set by the policy, not by timing.
//!
//! h2load, the client before it, sent 1.12 to 1.91 datagrams per request between identical
//! runs (T544); Ibex pays ~6k instructions for each, so the h3 figure moved with the client.
//! Here `best` must send exactly one datagram per request (its ACKs ride with the next
//! request) and `worst` must answer every server datagram with one of its own (an ACK at
//! once), so two runs of either agree. The client's source is compiled here as it is in the
//! tool, so the test pins the code insreq runs.

use crate::common;

#[path = "../../../../tools/measure/h3bench/src/client.rs"]
#[allow(dead_code)]
mod client;

use client::{AckPolicy, Client, Run};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Stdio};
use std::thread;

/// Requests in one counted run (after a warm-up run of the same length on the connection).
const N: u64 = 400;

/// Keep-alive backend: `200 ok` for each request head (and its `content-length` body).
fn backend() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = l.local_addr().expect("backend addr");
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                        let len: usize = head.lines().find_map(|l| l.strip_prefix("content-length:")).map_or(0, |v| v.trim().parse().unwrap_or(0));
                        if buf.len() < end + 4 + len {
                            break;
                        }
                        buf.drain(..end + 4 + len);
                        if c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                            return;
                        }
                    }
                    match c.read(&mut tmp) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
            });
        }
    });
    addr
}

struct Ibex {
    child: Child,
    _cfg: tempfile::NamedTempFile,
    quic: SocketAddr,
}

impl Ibex {
    fn start(be: SocketAddr) -> Self {
        let tcp = common::reserve_addr();
        let quic = common::reserve_addr();
        let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
        let cfg = format!(
            "global\n  nbthread 1\n\
             defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
             frontend fe\n  bind {tcp}\n  bind quic4@{quic} ssl crt {crt} alpn h3\n  default_backend be\n\
             backend be\n  server s1 {be}\n"
        );
        let mut f = tempfile::NamedTempFile::new().expect("tmp");
        f.write_all(cfg.as_bytes()).expect("write cfg");
        let child = common::ibex_command(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
        assert!(common::wait_listening(tcp), "ibex never started listening on {tcp}");
        Self { child, _cfg: f, quic }
    }
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// Two counted runs of `policy` on one connection to a fresh ibex, after a warm-up run.
fn runs(policy: AckPolicy, body: &[u8]) -> [Run; 2] {
    let ibex = Ibex::start(backend());
    let mut c = Client::connect(ibex.quic, policy).expect("connect");
    let req = client::request_bytes(body);
    let warm = c.run(N, &req).expect("warm-up run");
    assert_eq!(warm.ok, N, "warm-up: not every response was a 200");
    let r = [c.run(N, &req).expect("run 1"), c.run(N, &req).expect("run 2")];
    for (i, run) in r.iter().enumerate() {
        assert_eq!(run.ok, N, "run {}: not every response was a 200: {run:?}", i + 1);
    }
    c.close().expect("close");
    r
}

/// `best`: one datagram per request, the request's own (1 % slack for a timer that fired
/// because the host stalled the client for 25 ms).
fn assert_best(r: &[Run; 2]) {
    for run in r {
        let d = run.client_per_request();
        assert!((1.0..=1.01).contains(&d), "best: {d:.4} client datagrams per request, not 1.000: {run:?}");
    }
}

/// `worst`: the request, plus one answer to (nearly) every server datagram; the two runs
/// within 1 % of each other.
fn assert_worst(r: &[Run; 2]) {
    for run in r {
        let answers = run.requests_phase.sent - run.requests;
        let rx = run.requests_phase.received;
        assert!(
            answers <= rx && answers * 100 >= rx * 98,
            "worst: {answers} answers to {rx} server datagrams over {} requests: not one each: {run:?}",
            run.requests
        );
        assert!(run.client_per_request() >= 1.9, "worst: {:.4} client datagrams per request: {run:?}", run.client_per_request());
    }
    let (a, b) = (r[0].client_per_request(), r[1].client_per_request());
    assert!((a - b).abs() <= 0.01 * a, "worst: {a:.4} then {b:.4} client datagrams per request between identical runs");
}

#[test]
fn best_sends_one_datagram_per_get() {
    assert_best(&runs(AckPolicy::Best, b""));
}

#[test]
fn best_sends_one_datagram_per_post() {
    assert_best(&runs(AckPolicy::Best, b"0123456789abcdef0123456789abcdef"));
}

#[test]
fn worst_answers_every_server_datagram_on_a_get() {
    assert_worst(&runs(AckPolicy::Worst, b""));
}

#[test]
fn worst_answers_every_server_datagram_on_a_post() {
    assert_worst(&runs(AckPolicy::Worst, b"0123456789abcdef0123456789abcdef"));
}
