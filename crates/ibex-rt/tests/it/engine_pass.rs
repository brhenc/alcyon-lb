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
    run_global(servers, "")
}

/// [`run_with`] under the `global` section `global` (empty: none).
fn run_global(servers: usize, global: &str) -> (u64, u64, u64, u64, u64) {
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
        "{global}defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
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
    // frontend: req_tot, hrsp, bin, bout; backend: stot, bin, bout, req_tot, hrsp, lbtot,
    // reuse; server: the same and smax; timings add no maximum RMW when the sample does not
    // beat it (the backend's smax is counted where a stream joins it, T583). `CumStreams` is
    // counted per thread in every mode (T582 Q5); `reuse` (or `connect`) was an uncounted
    // `fetch_add` before T582: 20, and one for a maximum beaten under load (21 before T582,
    // pinned at 20 with `reuse` unseen).
    assert!(per <= 21.0, "{per} atomic RMWs per request");
}

#[test]
fn per_thread_counters_take_the_locked_rmws_off_a_request() {
    // `tune.ibex.counters per-thread` (T582): the frontend, backend and server rows of a
    // stream are its thread's own, written with a plain load and store. What is left is a
    // maximum beaten now and then (`smax`, a timing's `*_max`): near 0 a request.
    let (rmws, ..) = run_global(1, "global\n  tune.ibex.counters per-thread\n");
    let per = rmws as f64 / REQS as f64;
    eprintln!("rmws per request, per-thread rows: {per}");
    assert!(per <= 0.25, "{per} atomic RMWs per request with per-thread rows");
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

/// What `op` counted over `n` requests after a warm-up, with `get` one request.
fn ops_per_requests(op: Op, n: u64, mut get: impl FnMut()) -> u64 {
    for _ in 0..20 {
        get();
    }
    let c0 = on_this_thread()[op as usize];
    for _ in 0..n {
        get();
    }
    on_this_thread()[op as usize] - c0
}

/// L3 (T586): a stream run looks at its timers when a timer woke it (`WOKEN_TIMER`), not on
/// every run: a keep-alive request is two I/O wakeups and no timer is due in either. Two
/// `check_timeouts` a request before.
#[test]
#[cfg(debug_assertions)]
fn a_keepalive_stream_run_checks_timers_only_when_one_is_due() {
    const N: u64 = 100;
    let (mut engine, fe, running, be) = setup();
    let mut c = Client::connect(fe);
    let checks = ops_per_requests(Op::TimeoutCheck, N, || c.get(&mut engine));
    println!("{N} keep-alive requests: {checks} timeout checks");
    assert!(checks <= 2, "{checks} timeout checks for {N} requests: every run walks every timer");
    drop(c);
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}

/// L2 for HTTP/3 (T586): the owner of a QUIC connection and its stream wake each other in
/// the pass they run in, as an HTTP/2 owner does: the stream's response is framed and
/// handed to quinn in the pass it came, not a pass later. The engine runs on a thread of
/// its own here (the client drives quinn by hand); its passes are read from the counter it
/// publishes after each.
#[test]
#[cfg(debug_assertions)]
fn an_h3_owner_and_its_stream_wake_each_other_in_the_same_pass() {
    use crate::h3_mux_drain::{get, Client as H3Client};
    use std::sync::atomic::AtomicU64;
    const N: u64 = 40;
    let srv = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let srv_addr = srv.local_addr().expect("addr");
    let quic = common::reserve_addr();
    let running = Arc::new(AtomicBool::new(true));
    let be = backend(srv, Arc::clone(&running));
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 5s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind quic4@{quic} ssl crt {crt} alpn h3\n  default_backend be\n\
         backend be\n  server s1 {srv_addr}\n"
    );
    let passes = Arc::new(AtomicU64::new(0));
    let wakes = Arc::new(AtomicU64::new(0));
    let eng = {
        let (running, passes, wakes) = (Arc::clone(&running), Arc::clone(&passes), Arc::clone(&wakes));
        thread::spawn(move || {
            let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
            while running.load(Ordering::Relaxed) {
                let _ = engine.run_once();
                passes.store(on_this_thread()[Op::Pass as usize], Ordering::Relaxed);
                wakes.store(on_this_thread()[Op::H3OwnerWakeNow as usize], Ordering::Relaxed);
            }
        })
    };
    thread::sleep(Duration::from_millis(100));
    let mut c = H3Client::connect(quic);
    let mut one = || {
        let id = c.open(&get(b"/"), true);
        let o = c.outcome(id);
        assert_eq!(o.status, Some(200), "{o:?}");
    };
    for _ in 0..10 {
        one();
    }
    // The ACKs and timers of the warm-up settle.
    thread::sleep(Duration::from_millis(50));
    let p0 = passes.load(Ordering::Relaxed);
    let w0 = wakes.load(Ordering::Relaxed);
    let mut runs = 0u64;
    let started = Instant::now();
    for _ in 0..N {
        one();
        runs += 1;
    }
    let p1 = passes.load(Ordering::Relaxed);
    let w1 = wakes.load(Ordering::Relaxed);
    #[allow(clippy::cast_precision_loss)]
    let per = (p1 - p0) as f64 / runs as f64;
    println!("h3: {per:.2} passes a request ({:?} for {N}), {} in-pass owner wakes", started.elapsed(), w1 - w0);
    running.store(false, Ordering::Relaxed);
    let _ = eng.join();
    let _ = be.join();
    // The pass count of a request is bimodal with the phase of the client and engine threads
    // (4.0 or 5.0 on a quiet host, T614), so it is printed and not asserted: what L2 changed is
    // counted. Every request's stream wakes its owner (its release at least) for the pass it
    // is in; before L2 each of these wakes went to the next pass (counted 0).
    assert!(w1 - w0 >= runs, "{} in-pass owner wakes for {runs} requests: the owner and its stream wake each other a pass late", w1 - w0);
}

/// (stream runs, `op`) counted over `n` requests after a warm-up, with `get` one request.
fn runs_and_ops(op: Op, n: u64, mut get: impl FnMut()) -> (u64, u64) {
    for _ in 0..20 {
        get();
    }
    let c0 = on_this_thread();
    for _ in 0..n {
        get();
    }
    let c1 = on_this_thread();
    (c1[Op::StreamRun as usize] - c0[Op::StreamRun as usize], c1[op as usize] - c0[op as usize])
}

/// T599: a run derives what the sockets its entry polls want, not a side it has no socket
/// for: a stream of an HTTP/2 connection polls its server only (its client side is the
/// owner's to write: `has_pending_output`, the response window, every run), the owner the
/// client and the server connection it keeps between requests. Here about as many owner
/// runs as stream runs: 1.5 a run at most. Two a run before, every run.
#[test]
#[cfg(debug_assertions)]
fn an_h2_entry_derives_only_the_side_it_polls() {
    const N: u64 = 100;
    let (mut engine, fe, running, be) = setup_h2();
    let mut c = H2Client::connect(&mut engine, fe);
    let (runs, wants) = runs_and_ops(Op::WantDerive, N, || c.get(&mut engine));
    println!("{N} h2 requests: {runs} stream runs, {wants} sides derived");
    assert!(runs > 0, "no stream run counted");
    assert!(wants * 2 <= runs * 3, "{wants} sides derived in {runs} runs: a run derives the side it does not poll");
    drop(c);
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}

/// T599: the rare checks of a stream run (the connect log, `rate_max`, the deferred
/// `tcp-request session` rules, the content inspection, a TCP stream's connect and stick
/// stores, a server TLS failure) are looked at only in a run with one armed: none is on a
/// keep-alive HTTP request or an HTTP/2 one past its first. Every run looked at all before.
#[test]
#[cfg(debug_assertions)]
fn a_stream_run_looks_at_no_rare_check_when_none_is_armed() {
    const N: u64 = 100;
    let (mut engine, fe, running, be) = setup();
    let mut c = Client::connect(fe);
    let (runs, rare) = runs_and_ops(Op::RareCheck, N, || c.get(&mut engine));
    println!("{N} keep-alive requests: {runs} stream runs, {rare} with the rare checks looked at");
    assert!(runs > 0, "no stream run counted");
    assert_eq!(rare, 0, "{rare} of {runs} keep-alive runs looked at the rare checks with none armed");
    drop(c);
    running.store(false, Ordering::Relaxed);
    let _ = be.join();

    let (mut engine, fe, running, be) = setup_h2();
    let mut c = H2Client::connect(&mut engine, fe);
    let (runs, rare) = runs_and_ops(Op::RareCheck, N, || c.get(&mut engine));
    println!("{N} h2 requests: {runs} stream runs, {rare} with the rare checks looked at");
    assert_eq!(rare, 0, "{rare} of {runs} h2 runs looked at the rare checks with none armed");
    drop(c);
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}

/// T599: an HTTP/2 GET is three runs of its stream (its request, the server's response, its
/// end) and four of the owner (the client's HEADERS, then after each of its stream's runs):
/// the owner is not run again in a pass for a stream its run already queued for spawning,
/// nor woken by the spawn before the stream has run. Nine before.
#[test]
#[cfg(debug_assertions)]
fn an_h2_request_runs_its_owner_only_when_there_is_something_to_move() {
    const N: u64 = 100;
    let (mut engine, fe, running, be) = setup_h2();
    let mut c = H2Client::connect(&mut engine, fe);
    let (runs, _) = runs_and_ops(Op::Pass, N, || c.get(&mut engine));
    println!("{N} h2 requests: {runs} stream runs");
    assert!(runs <= 7 * N, "{runs} stream runs for {N} HTTP/2 requests");
    drop(c);
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}
