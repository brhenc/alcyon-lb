// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! What a request costs the shared counters and the clock, pinned per request (T579, C1/C2).
//! The counters are the debug-build ones of `ibex_rt::probe`, per thread.
//!
//! What one pass of the engine loop does (engine track L,
//! `docs/design/engine-architecture-2026-11-01.md` §4.2): the housekeeping runs when its
//! timer is due, not on every pass (L1). Counted with the debug-only `work::Op` counters of
//! this thread; the engine runs on the test's thread.

use crate::common;

use ibex_rt::engine::Engine;
use ibex_sample::work::{on_this_thread, Op};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const REQS: u64 = 40;

/// Runs `REQS` keep-alive requests through frontend, backend and server with no `log` line;
/// returns what the probes counted over the last `REQS - WARM` of them.
fn run() -> (u64, u64, u64, u64, u64) {
    run_with(1)
}

/// [`run`] with `servers` servers in the backend (only the first is reachable); the sixth
/// value is the server rows `account_stream` read.
fn run_with(servers: usize) -> (u64, u64, u64, u64, u64) {
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
         backend b\n  server s {be_addr}\n{}",
        (1..servers).map(|i| format!("  server x{i} 127.0.0.1:9 disabled\n")).collect::<String>()
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

#[test]
fn a_request_reads_the_clock_once_per_pass_and_never_for_a_log_it_does_not_write() {
    let (_, wall, clock, _, n) = run();
    // Each request takes a few passes; `run` runs at least 3 per request. One read a pass.
    eprintln!("monotonic reads {clock} over {n} passes, wall {wall}");
    assert_eq!(wall, 0);
    assert_eq!(clock, n, "{clock} Instant reads over {n} passes");
}

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// A keep-alive backend answering every request head, a thread per connection.
fn backend(listener: TcpListener, running: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking");
        while running.load(Ordering::Relaxed) {
            let Ok((mut s, _)) = listener.accept() else {
                thread::sleep(Duration::from_millis(1));
                continue;
            };
            let running = Arc::clone(&running);
            thread::spawn(move || {
                s.set_nonblocking(false).expect("blocking");
                s.set_nodelay(true).expect("nodelay");
                s.set_read_timeout(Some(Duration::from_millis(200))).expect("timeout");
                let mut pending = Vec::new();
                let mut buf = [0u8; 4096];
                while running.load(Ordering::Relaxed) {
                    match s.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => pending.extend_from_slice(&buf[..n]),
                        Err(_) => continue,
                    }
                    while let Some(p) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                        pending.drain(..p + 4);
                        if s.write_all(RESPONSE).is_err() {
                            return;
                        }
                    }
                }
            });
        }
    })
}

fn setup() -> (Engine, SocketAddr, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let srv = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let srv_addr = srv.local_addr().expect("addr");
    let fe = common::reserve_addr();
    let running = Arc::new(AtomicBool::new(true));
    let be = backend(srv, Arc::clone(&running));
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 5s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n  default_backend be\n\
         backend be\n  server s1 {srv_addr}\n"
    );
    let engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    (engine, fe, running, be)
}

/// One keep-alive client, its requests sent one at a time (`ab -k -c 1`).
struct Client {
    sock: TcpStream,
    rx: Vec<u8>,
}

impl Client {
    fn connect(addr: SocketAddr) -> Self {
        let sock = TcpStream::connect(addr).expect("connect");
        sock.set_nonblocking(true).expect("nonblocking");
        sock.set_nodelay(true).expect("nodelay");
        Client { sock, rx: Vec::new() }
    }

    /// One request, the engine run until its whole response has come.
    fn get(&mut self, engine: &mut Engine) {
        self.sock.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").expect("request");
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut buf = [0u8; 4096];
        loop {
            if let Some(p) = self.rx.windows(4).position(|w| w == b"\r\n\r\n") {
                if self.rx.len() >= p + 4 + 2 {
                    assert!(self.rx.starts_with(b"HTTP/1.1 200"), "{:?}", String::from_utf8_lossy(&self.rx));
                    self.rx.drain(..p + 6);
                    return;
                }
            }
            assert!(Instant::now() < deadline, "no response; have {:?}", String::from_utf8_lossy(&self.rx));
            let _ = engine.run_once();
            match self.sock.read(&mut buf) {
                Ok(0) => panic!("the proxy closed the connection"),
                Ok(n) => self.rx.extend_from_slice(&buf[..n]),
                Err(_) => {}
            }
        }
    }
}

/// (passes, housekeeping runs) on this thread so far.
fn counts() -> (u64, u64) {
    let c = on_this_thread();
    (c[Op::Pass as usize], c[Op::Housekeeping as usize])
}

/// L1: the idle purge, the buffer trim, the stick-table expiry and the pools' publish run
/// when their timers expire (`HAProxy`'s `srv_cleanup_idle_conns` / `process_table_expire`
/// tasks), not on every pass: over a run of keep-alive requests, the housekeeping is bounded
/// by the time elapsed, not by the passes made. Idle, it still runs, once a period.
#[test]
#[cfg(debug_assertions)]
fn a_pass_with_nothing_due_does_no_housekeeping() {
    const N: u64 = 200;
    let (mut engine, fe, running, be) = setup();
    let mut c = Client::connect(fe);
    for _ in 0..20 {
        c.get(&mut engine);
    }

    let (p0, h0) = counts();
    let t0 = Instant::now();
    for _ in 0..N {
        c.get(&mut engine);
    }
    let ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
    let (p1, h1) = counts();
    let (passes, hk) = (p1 - p0, h1 - h0);
    println!("{N} keep-alive requests in {ms} ms: {passes} passes, {hk} housekeeping runs");
    assert!(passes >= N, "{passes} passes for {N} requests: the counter is not counting");
    // The shortest period is 250 ms (the stick tables'; this config has none, the trim's is 500).
    // The bound is loose: a run every 5 ms would still be far below one a pass.
    let bound = ms / 5 + 4;
    assert!(
        hk <= bound,
        "{hk} housekeeping runs in {passes} passes over {ms} ms (at most {bound} are due): \
         the housekeeping runs on every pass"
    );

    // Idle: the buffer trim watches the allocations for 600 ms after the work, then the worker sleeps.
    let (_, h2) = counts();
    let t1 = Instant::now();
    while t1.elapsed() < Duration::from_millis(700) {
        let _ = engine.run_once();
    }
    let ms = u64::try_from(t1.elapsed().as_millis()).unwrap_or(u64::MAX);
    let (_, h3) = counts();
    let idle = h3 - h2;
    println!("idle {ms} ms: {idle} housekeeping runs");
    assert!(idle >= 1, "no housekeeping ran in {ms} idle ms: the timers are never armed");
    assert!(idle <= ms / 5 + 4, "{idle} housekeeping runs in {ms} idle ms");

    drop(c);
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}

fn setup_h2() -> (Engine, SocketAddr, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let srv = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let srv_addr = srv.local_addr().expect("addr");
    let fe = common::reserve_addr();
    let running = Arc::new(AtomicBool::new(true));
    let be = backend(srv, Arc::clone(&running));
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 5s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe} proto h2\n  default_backend be\n\
         backend be\n  server s1 {srv_addr}\n"
    );
    let engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    (engine, fe, running, be)
}

#[allow(clippy::cast_possible_truncation)]
fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("len");
    let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// One cleartext HTTP/2 connection (prior knowledge), one stream at a time (`h2load -c 1 -m 1`).
struct H2Client {
    sock: TcpStream,
    rx: Vec<u8>,
    next: u32,
}

impl H2Client {
    fn connect(engine: &mut Engine, addr: SocketAddr) -> Self {
        let mut sock = TcpStream::connect(addr).expect("connect");
        sock.set_nonblocking(true).expect("nonblocking");
        sock.set_nodelay(true).expect("nodelay");
        let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        hello.extend(frame(0x4, 0, 0, &[]));
        sock.write_all(&hello).expect("preface");
        let mut c = H2Client { sock, rx: Vec::new(), next: 1 };
        c.until(engine, |f| f.0 == 0x4 && f.1 & 1 == 0);
        c.sock.write_all(&frame(0x4, 1, 0, &[])).expect("settings ack");
        c
    }

    fn until(&mut self, engine: &mut Engine, mut done: impl FnMut((u8, u8, u32)) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut buf = [0u8; 4096];
        loop {
            while self.rx.len() >= 9 {
                let len = (usize::from(self.rx[0]) << 16) | (usize::from(self.rx[1]) << 8) | usize::from(self.rx[2]);
                if self.rx.len() < 9 + len {
                    break;
                }
                let head = (self.rx[3], self.rx[4], u32::from_be_bytes([self.rx[5], self.rx[6], self.rx[7], self.rx[8]]) & 0x7fff_ffff);
                assert_ne!(head.0, 0x3, "RST_STREAM");
                assert_ne!(head.0, 0x7, "GOAWAY");
                self.rx.drain(..9 + len);
                if done(head) {
                    return;
                }
            }
            assert!(Instant::now() < deadline, "no frame came; have {:?}", self.rx);
            let _ = engine.run_once();
            match self.sock.read(&mut buf) {
                Ok(0) => panic!("the proxy closed the connection"),
                Ok(n) => self.rx.extend_from_slice(&buf[..n]),
                Err(_) => {}
            }
        }
    }

    /// `GET http://localhost/` (static table, the authority a literal without indexing), to
    /// the response's `END_STREAM`.
    fn get(&mut self, engine: &mut Engine) {
        let id = self.next;
        self.next += 2;
        let mut block = vec![0x82, 0x86, 0x84, 0x01, 9];
        block.extend_from_slice(b"localhost");
        self.sock.write_all(&frame(0x1, 0x5, id, &block)).expect("request");
        self.until(engine, |(kind, flags, stream)| stream == id && (kind == 0x0 || kind == 0x1) && flags & 1 != 0);
    }
}

/// Passes a request takes, over `n` requests after a warm-up, with `get` one request.
fn passes_per_request(n: u64, mut get: impl FnMut()) -> f64 {
    for _ in 0..20 {
        get();
    }
    let (p0, _) = counts();
    for _ in 0..n {
        get();
    }
    let (p1, _) = counts();
    #[allow(clippy::cast_precision_loss)]
    let per = (p1 - p0) as f64 / n as f64;
    per
}

/// L2: the owner of an HTTP/2 connection and its stream wake each other in the pass they run
/// in (instant wakeup, `Dispatch::wake_now`), not a pass later: a request is the client's
/// HEADERS, the server's response and the stream spawned between them, three passes as
/// `HAProxy`'s (X0: 3.00 `epoll_wait` a request). Eight before.
#[test]
#[cfg(debug_assertions)]
fn an_h2_request_completes_in_three_passes() {
    let (mut engine, fe, running, be) = setup_h2();
    let mut c = H2Client::connect(&mut engine, fe);
    let per = passes_per_request(200, || c.get(&mut engine));
    println!("h2: {per:.2} passes a request");
    assert!(per <= 3.2, "{per:.2} passes an HTTP/2 request: the owner and its stream wake each other a pass late");
    drop(c);
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}

/// L2 pins the h1 figure: a keep-alive request is two passes, the client's request and the
/// server's response, under every observer on both proxies.
#[test]
#[cfg(debug_assertions)]
fn an_h1_keepalive_request_completes_in_two() {
    let (mut engine, fe, running, be) = setup();
    let mut c = Client::connect(fe);
    let per = passes_per_request(200, || c.get(&mut engine));
    println!("h1: {per:.2} passes a request");
    assert!(per <= 2.1, "{per:.2} passes an h1 keep-alive request");
    drop(c);
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}

/// L3: a keep-alive stream's run builds nothing from the configuration: the timeouts its
/// fetches read are the proxies' own, converted once, and the capture slots' table is not
/// cloned (Q6: no `Arc` clone a run). Two of each a run before (`stream_timeouts`,
/// `stream_vars_enter`).
#[test]
#[cfg(debug_assertions)]
fn a_keepalive_stream_run_does_only_io_and_http() {
    const N: u64 = 100;
    let (mut engine, fe, running, be) = setup();
    let mut c = Client::connect(fe);
    for _ in 0..20 {
        c.get(&mut engine);
    }
    let s0 = on_this_thread()[Op::RunSetup as usize];
    for _ in 0..N {
        c.get(&mut engine);
    }
    let setups = on_this_thread()[Op::RunSetup as usize] - s0;
    println!("{N} keep-alive requests: {setups} run set-ups");
    assert!(setups <= 2, "{setups} run set-ups for {N} requests: each stream run rebuilds its context");
    drop(c);
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}
