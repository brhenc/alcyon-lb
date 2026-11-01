// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! What a request costs the shared counters and the clock, pinned per request (T579, C1/C2).
//! The counters are the debug-build ones of `ibex_rt::probe`, per thread.

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use ibex_rt::engine::Engine;

const REQS: u64 = 40;

/// Runs `REQS` keep-alive requests through frontend, backend and server with no `log` line;
/// returns what the probes counted over the last `REQS - WARM` of them.
fn run() -> (u64, u64, u64, u64, u64) {
    let be = TcpListener::bind("127.0.0.1:0").unwrap();
    let be_addr = be.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut s, _) = be.accept().unwrap();
        let mut buf = [0u8; 4096];
        loop {
            let Ok(n) = s.read(&mut buf) else { return };
            if n == 0 {
                return;
            }
            if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                return;
            }
        }
    });
    let fe_addr = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe_addr}\n  default_backend b\n\
         backend b\n  server s {be_addr}\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let mut c = TcpStream::connect(fe_addr).unwrap();
    c.set_nonblocking(true).unwrap();
    let passes = std::cell::Cell::new(0u64);
    let mut one = |engine: &mut Engine| {
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut got = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !got.ends_with(b"ok") && Instant::now() < deadline {
            passes.set(passes.get() + 1);
            let _ = engine.run_once();
            let mut b = [0u8; 512];
            if let Ok(n) = c.read(&mut b) {
                got.extend_from_slice(&b[..n]);
            }
        }
        assert!(got.ends_with(b"ok"), "{:?}", String::from_utf8_lossy(&got));
    };
    for _ in 0..4 {
        one(&mut engine);
    }
    let (r0, w0, k0) = (ibex_rt::probe::rmws(), ibex_rt::probe::wall_reads(), ibex_rt::probe::clock_reads());
    let p0 = passes.get();
    for _ in 0..REQS {
        one(&mut engine);
    }
    // The last request's accounting may run a pass later.
    for _ in 0..2 {
        passes.set(passes.get() + 1);
        let _ = engine.run_once();
    }
    (ibex_rt::probe::rmws() - r0, ibex_rt::probe::wall_reads() - w0, ibex_rt::probe::clock_reads() - k0, REQS, passes.get() - p0)
}

#[test]
fn accounting_a_request_does_at_most_n_atomic_rmws() {
    let (rmws, ..) = run();
    let per = rmws as f64 / REQS as f64;
    eprintln!("rmws per request: {per}");
    // frontend: req_tot, hrsp, bin, bout; backend and server: stot, bin, bout, req_tot, hrsp,
    // lbtot, smax = 7 each; timings add no maximum RMW when the sample does not beat it.
    assert!(per <= 20.0, "{per} atomic RMWs per request");
}

#[test]
fn a_request_with_no_log_target_builds_no_log_line() {
    let (_, wall, _, n, _) = run();
    eprintln!("wall clock reads over {n} requests: {wall}");
    assert!(wall <= 1, "{wall} SystemTime reads over {n} requests with no log target");
}
