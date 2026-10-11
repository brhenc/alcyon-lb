// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T260): counts the test process's allocations and bytes (#[global_allocator])

//! Allocation oracle pinning data-path memory allocations per request.
//!
//! Requirement from `nudge-agy-4.md` (Item 1):
//! The work done per request must be bounded and predictable. Ibex tracks global
//! and scoped allocations to pin steady-state requests and drive allocation counts down.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ibex_alloc::CountingAllocator;
use ibex_config::ast::{
    AclCondition, AclRule, AclTerm, BackendSection, Config, FrontendSection, Mode, Server,
    TcpReqContentAction, TcpReqContentRule,
};
use ibex_rt::engine::Engine;

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator::new();

/// Serializes allocation tests within this process so concurrent runners do not
/// cross-pollute global allocation counters.
static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn loopback0() -> (TcpListener, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = l.local_addr().expect("local_addr");
    (l, addr)
}

fn start_dummy_http_backend(
    listener: TcpListener,
    running: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking");
        while running.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if req.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                let _ = stream.flush();
            }
            thread::sleep(Duration::from_millis(1));
        }
    })
}

fn start_dummy_tcp_backend(
    listener: TcpListener,
    running: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking");
        while running.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                if let Ok(n) = stream.read(&mut buf) {
                    if n > 0 {
                        let _ = stream.write_all(&buf[..n]);
                        let _ = stream.flush();
                    }
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
    })
}

fn drive_single_http_request(fe_addr: SocketAddr, engine: &mut Engine) {
    let mut client = TcpStream::connect(fe_addr).expect("connect to frontend");
    client.set_nonblocking(true).expect("set_nonblocking");
    client
        .write_all(b"GET /api/test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write req");

    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 512];
    while start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once();
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                response.extend_from_slice(&buf[..n]);
                if response.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(1));
    }

    for _ in 0..5 {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
}

fn drive_single_tcp_connection(fe_addr: SocketAddr, engine: &mut Engine) {
    let mut client = TcpStream::connect(fe_addr).expect("connect to tcp frontend");
    client.set_nonblocking(true).expect("set_nonblocking");
    client.write_all(b"PING\n").expect("write ping");

    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 512];
    while start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once();
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                response.extend_from_slice(&buf[..n]);
                if response.contains(&b'\n') {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(response, b"PING\n", "the connection was relayed through the backend");

    // Close, and let the session end here, so that its buffers are back in the pool
    // before the next connection is measured. (Until T53 a TCP frontend with a
    // `default_backend` never reached its server, so the session ended with nothing
    // relayed and this never mattered.)
    drop(client);
    for _ in 0..20 {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
}

/// Baseline HTTP/1.1 request allocation test.
///
/// **Date**: 2026-09-22
/// **Initial Measured Baseline**: 89 allocations, 41,130 bytes per steady-state request.
/// **Pinned Bound**: N = 95 allocations.
/// Subsequent pool and scratch buffer optimizations should drive this number down.
#[test]
fn a_steady_state_http_request_allocates_no_more_than_n_times() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

    let (srv_listener, srv_addr) = loopback0();
    let (fe_listener, fe_addr) = loopback0();
    drop(fe_listener);

    let running = Arc::new(AtomicBool::new(true));
    let be = start_dummy_http_backend(srv_listener, Arc::clone(&running));

    let fe = FrontendSection {
        name: "fe_http".into(),
        bind: Some(fe_addr),
        mode: Mode::Http,
        default_backend: Some("be_http".into()),
        clitimeout: Some(Duration::from_secs(5)),
        ..Default::default()
    };

    let config = Config {
        frontends: vec![fe],
        backends: vec![BackendSection {
            name: "be_http".into(),
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(5)),
            srvtimeout: Some(Duration::from_secs(5)),
            servers: vec![Server::new("s1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("Engine::new");

    // 1. Warm-up request to complete one-time engine / socket initialization
    drive_single_http_request(fe_addr, &mut engine);

    // 2. Measure steady-state allocation count
    let before = ibex_alloc::alloc_counters();
    drive_single_http_request(fe_addr, &mut engine);
    let after = ibex_alloc::alloc_counters();

    let diff = before.diff(&after);
    println!(
        "[MEASUREMENT 2026-09-23] HTTP request allocations: {} allocs, {} bytes",
        diff.alloc_count, diff.bytes_allocated
    );

    // Initial baseline recorded: 89 allocs, pinned to <= 95.
    // 2026-09-22: Measured 90 allocs with decoupled pool; bound lowered to <= 93.
    // 2026-09-23 (Nudge 6): Measured 17 allocs, 891 bytes (down from 90 allocs, 41,194 bytes).
    // 2026-09-23 (Nudge 7): HTX buffer pooling & zero-alloc fast path: measured 6 allocs, 186 bytes
    // (allocprofile: 5 allocs, 124 bytes). Zero allocs in HtxBuffer::with_capacity and to_h1_wire.
    // Bound lowered from 25 to <= 10, bytes from 2000 to <= 500.
    let max_allowed_allocs: usize = 10;
    assert!(
        diff.alloc_count <= max_allowed_allocs,
        "a steady state HTTP request allocated {} times (> {}); diff: {:?}",
        diff.alloc_count,
        max_allowed_allocs,
        diff
    );
    let max_allowed_bytes: usize = 500;
    assert!(
        diff.bytes_allocated <= max_allowed_bytes,
        "a steady state HTTP request allocated {} bytes (> {}); diff: {:?}",
        diff.bytes_allocated,
        max_allowed_bytes,
        diff
    );

    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}

/// The request-line version check runs on every HTTP/1 request (proxy.rs, before the
/// head is parsed): it must not allocate. T286 added it with a `Vec` of the line's
/// tokens, 64 bytes per request (measuring gate on 18bddeb: Bytes / req 151 -> 191).
#[test]
fn the_request_version_check_allocates_nothing() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let lines: [&[u8]; 6] = [
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET  /a  HTTP/1.0\r\n",
        b"GET / HTTP/1.9 extra\r\n",
        b"GET /\r\n",
        b"GET / HTTP/1.1",
        b"GET / HTTP/1.1 \r\n",
    ];
    let before = ibex_alloc::alloc_counters();
    let mut invalid = 0;
    for l in lines {
        invalid += usize::from(std::hint::black_box(ibex_rt::txn::request_version_invalid(l)));
    }
    let diff = before.diff(&ibex_alloc::alloc_counters());
    assert_eq!(invalid, 3, "the verdicts did not change: extra token, no version, trailing blank");
    assert_eq!(diff.alloc_count, 0, "request_version_invalid allocated: {diff:?}");
}

/// Baseline TCP connection allocation test.
///
/// **Date**: 2026-09-22
/// **Initial Measured Baseline**: 28 allocations, 52,736 bytes per steady-state connection.
/// **Pinned Bound**: N = 35 allocations.
#[test]
fn a_steady_state_tcp_connection_allocates_no_more_than_n_times() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

    let (srv_listener, srv_addr) = loopback0();
    let (fe_listener, fe_addr) = loopback0();
    drop(fe_listener);

    let running = Arc::new(AtomicBool::new(true));
    let be = start_dummy_tcp_backend(srv_listener, Arc::clone(&running));

    let fe = FrontendSection {
        name: "fe_tcp".into(),
        bind: Some(fe_addr),
        mode: Mode::Tcp,
        default_backend: Some("be_tcp".into()),
        clitimeout: Some(Duration::from_secs(5)),
        ..Default::default()
    };

    let config = Config {
        frontends: vec![fe],
        backends: vec![BackendSection {
            name: "be_tcp".into(),
            mode: Mode::Tcp,
            contimeout: Some(Duration::from_secs(5)),
            srvtimeout: Some(Duration::from_secs(5)),
            servers: vec![Server::new("s1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("Engine::new");

    // 1. Warm-up
    drive_single_tcp_connection(fe_addr, &mut engine);

    // 2. Measure
    let before = ibex_alloc::alloc_counters();
    drive_single_tcp_connection(fe_addr, &mut engine);
    let after = ibex_alloc::alloc_counters();

    let diff = before.diff(&after);
    println!(
        "[MEASUREMENT 2026-09-23] TCP connection allocations: {} allocs, {} bytes",
        diff.alloc_count, diff.bytes_allocated
    );

    // Initial baseline recorded: 28 allocs, 52,736 bytes, pinned to <= 35.
    // 2026-09-22: Measured 26 allocs, 19,968 bytes (-2 allocs, -32,768 bytes allocated).
    // Bound lowered from 35 to <= 30.
    // 2026-09-23 (Nudge 6): Measured 0 allocs, 0 bytes. Buffer reuse and poller event buffer reuse.
    // Bound lowered from 30 to <= 5.
    let max_allowed_allocs: usize = 5;
    assert!(
        diff.alloc_count <= max_allowed_allocs,
        "a steady state TCP connection allocated {} times (> {}); diff: {:?}",
        diff.alloc_count,
        max_allowed_allocs,
        diff
    );
    let max_allowed_bytes: usize = 500;
    assert!(
        diff.bytes_allocated <= max_allowed_bytes,
        "a steady state TCP connection allocated {} bytes (> {}); diff: {:?}",
        diff.bytes_allocated,
        max_allowed_bytes,
        diff
    );

    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}

/// Baseline ACL evaluation & log formatting request allocation test.
///
/// **Date**: 2026-09-22
/// **Initial Measured Baseline**: 93 allocations, 41,804 bytes per request with ACL evaluation.
/// **Pinned Bound**: N = 105 allocations.
#[test]
fn a_request_with_acl_and_log_format_allocates_no_more_than_n_times() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

    let (srv_listener, srv_addr) = loopback0();
    let (fe_listener, fe_addr) = loopback0();
    drop(fe_listener);

    let running = Arc::new(AtomicBool::new(true));
    let be = start_dummy_http_backend(srv_listener, Arc::clone(&running));

    let mut fe = FrontendSection {
        name: "fe_acl_log".into(),
        bind: Some(fe_addr),
        mode: Mode::Http,
        default_backend: Some("be_acl_log".into()),
        clitimeout: Some(Duration::from_secs(5)),
        acls: vec![
            AclRule {
                name: "is_api".into(),
                expr: "path_beg /api".into(),
            },
        ],
        ..Default::default()
    };
    fe.tcp_req_content_rules.push(TcpReqContentRule {
        action: TcpReqContentAction::Accept,
        cond: Some(AclCondition {
            is_if: true,
            terms: vec![AclTerm {
                negated: false,
                name: "is_api".into(),
            }],
        }),
        line: 0,
    });

    let config = Config {
        frontends: vec![fe],
        backends: vec![BackendSection {
            name: "be_acl_log".into(),
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(5)),
            srvtimeout: Some(Duration::from_secs(5)),
            servers: vec![Server::new("s1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("Engine::new");

    // 1. Warm-up
    drive_single_http_request(fe_addr, &mut engine);

    // 2. Measure
    let before = ibex_alloc::alloc_counters();
    drive_single_http_request(fe_addr, &mut engine);
    let after = ibex_alloc::alloc_counters();

    let diff = before.diff(&after);
    println!(
        "[MEASUREMENT 2026-09-23] ACL + log-format request allocations: {} allocs, {} bytes",
        diff.alloc_count, diff.bytes_allocated
    );

    // Initial baseline recorded: 93 allocs, pinned to <= 105.
    // 2026-09-22: Measured 94 allocs with decoupled pool; bound lowered from 105 to <= 98.
    // 2026-09-23 (Nudge 6): Measured 17 allocs, 891 bytes (down from 94 allocs, 41,804 bytes).
    // 2026-09-23 (Nudge 7): HTX buffer pooling & zero-alloc fast path: measured 6 allocs, 186 bytes.
    // Bound lowered from 25 to <= 10, bytes from 2000 to <= 500.
    let max_allowed_allocs: usize = 10;
    assert!(
        diff.alloc_count <= max_allowed_allocs,
        "an ACL + log-format request allocated {} times (> {}); diff: {:?}",
        diff.alloc_count,
        max_allowed_allocs,
        diff
    );
    let max_allowed_bytes: usize = 500;
    assert!(
        diff.bytes_allocated <= max_allowed_bytes,
        "an ACL + log-format request allocated {} bytes (> {}); diff: {:?}",
        diff.bytes_allocated,
        max_allowed_bytes,
        diff
    );

    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}

#[test]
fn pooled_buf_lifecycle_has_zero_allocations() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

    // Counted on this thread only: the process-wide counters also saw the backend threads
    // of the other tests in this binary, and this test went red at random (T45).

    // 1. Warm-up buffer pool
    {
        let _warm = ibex_rt::buf::Buf::with_capacity(ibex_rt::buf::BUFSIZE);
    }

    // 2. Measure lifecycle of a pooled buffer
    let before = ibex_alloc::thread_alloc_counters();
    {
        let mut b = ibex_rt::buf::Buf::with_capacity(ibex_rt::buf::BUFSIZE);
        b.writable()[..4].copy_from_slice(b"test");
        b.commit(4);
        assert_eq!(b.readable(), b"test");
    }
    let after = ibex_alloc::thread_alloc_counters();

    let diff = before.diff(&after);
    assert_eq!(
        diff.alloc_count, 0,
        "a pooled Buf lifecycle must have 0 allocations, got: {diff:?}"
    );
    assert_eq!(
        diff.dealloc_count, 0,
        "a pooled Buf lifecycle must have 0 deallocations, got: {diff:?}"
    );
}

#[test]
#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
fn sixty_thousand_backends_memory_bounded() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

    let before = ibex_alloc::alloc_counters();
    let mut servers = Vec::with_capacity(60_000);
    for i in 0..60_000u32 {
        let port = (1024 + (i % 60000)) as u16;
        let addr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)),
            port,
        );
        servers.push(Server::new(format!("s_{i}"), addr));
    }

    let config = Config {
        backends: vec![BackendSection {
            name: "be_60k".into(),
            mode: Mode::Http,
            servers,
            ..Default::default()
        }],
        ..Default::default()
    };

    let engine = Engine::new(&config, 64).expect("Engine::new 60k backends");
    let after = ibex_alloc::alloc_counters();

    let diff = before.diff(&after);
    println!(
        "[MEASUREMENT] 60,000 backends: {} allocs, {} bytes ({:.2} MB)",
        diff.alloc_count,
        diff.bytes_allocated,
        diff.bytes_allocated as f64 / (1024.0 * 1024.0)
    );

    // HAProxy baseline for 60,000 backends: 3,456 bytes/server = 207 MB.
    // Ibex measured: 14.00 MB (14,684,199 bytes, ~245 bytes/server).
    // Bound pinned to <= 20 MB (over 10x smaller than HAProxy).
    let max_bound_bytes: usize = 20 * 1024 * 1024;
    assert!(
        diff.bytes_allocated <= max_bound_bytes,
        "60,000 backends allocated {} bytes (> {} bytes / 20 MB)",
        diff.bytes_allocated,
        max_bound_bytes
    );

    drop(engine);
}

#[test]
#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
fn sixty_thousand_backends_with_checks_memory_bounded() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

    let before = ibex_alloc::alloc_counters();
    let mut servers = Vec::with_capacity(60_000);
    for i in 0..60_000u32 {
        let port = (1024 + (i % 60000)) as u16;
        let addr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)),
            port,
        );
        let mut s = Server::new(format!("s_{i}"), addr);
        s.check = true;
        s.inter = Some(Duration::from_millis(2000));
        s.fall = Some(3);
        s.rise = Some(2);
        servers.push(s);
    }

    let config = Config {
        backends: vec![BackendSection {
            name: "be_60k_checks".into(),
            mode: Mode::Http,
            servers,
            ..Default::default()
        }],
        ..Default::default()
    };

    let engine = Engine::new(&config, 64).expect("Engine::new 60k backends with checks");
    let after = ibex_alloc::alloc_counters();

    let diff = before.diff(&after);
    println!(
        "[MEASUREMENT] 60,000 backends WITH checks: {} allocs, {} bytes ({:.2} MB)",
        diff.alloc_count,
        diff.bytes_allocated,
        diff.bytes_allocated as f64 / (1024.0 * 1024.0)
    );

    // HAProxy baseline for 60,000 backends: 3,456 bytes/server = 207 MB.
    // Ibex measured (with active health checks enabled on all 60k servers):
    // 29.75 MB (31,195,964 bytes, 120,033 allocations, ~520 bytes/server).
    // Bound pinned to <= 35 MB (7x smaller than HAProxy's 207 MB).
    let max_bound_bytes: usize = 35 * 1024 * 1024;
    assert!(
        diff.bytes_allocated <= max_bound_bytes,
        "60,000 backends with checks allocated {} bytes (> {} bytes / 35 MB)",
        diff.bytes_allocated,
        max_bound_bytes
    );

    drop(engine);
}

/// Builds an engine over 60,000 servers with health checks and returns
/// `(allocations, bytes)` allocated while constructing it.
#[allow(clippy::cast_possible_truncation)]
fn sixty_thousand_with_checks_cost() -> (usize, usize) {
    let before = ibex_alloc::alloc_counters();
    let mut servers = Vec::with_capacity(60_000);
    for i in 0..60_000u32 {
        let port = (1024 + (i % 60000)) as u16;
        let addr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)),
            port,
        );
        let mut s = Server::new(format!("s_{i}"), addr);
        s.check = true;
        s.inter = Some(Duration::from_millis(2000));
        s.fall = Some(3);
        s.rise = Some(2);
        servers.push(s);
    }

    let config = Config {
        backends: vec![BackendSection {
            name: "be_60k_checks".into(),
            mode: Mode::Http,
            servers,
            ..Default::default()
        }],
        ..Default::default()
    };

    let engine = Engine::new(&config, 64).expect("Engine::new 60k backends with checks");
    let after = ibex_alloc::alloc_counters();
    let diff = before.diff(&after);
    drop(engine);
    (diff.alloc_count as usize, diff.bytes_allocated as usize)
}

/// Tripwire under the baselined failure of `sixty_thousand_backends_with_checks_memory_bounded`
/// (T255). That test fails its 35 MB bound on purpose (tradeoff.md 6.5) and the gate only checks
/// that it still fails, so growth from 54 MB to 500 MB would pass unnoticed. This one pins the
/// current cost: measured 2026-10-10 on main 5175acc, 180,072 allocations and 54,034,102 bytes.
/// Bounds: bytes <= measured + 5%, allocations <= measured + 1%. It is a ceiling on regression,
/// not a target: the 35 MB test remains the target.
#[test]
fn sixty_thousand_backends_with_checks_no_further_growth() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

    let (allocs, bytes) = sixty_thousand_with_checks_cost();
    println!("[MEASUREMENT] 60,000 backends WITH checks (tripwire): {allocs} allocs, {bytes} bytes");

    let max_bytes: usize = 54_034_102 / 100 * 105;
    let max_allocs: usize = 180_072 / 100 * 101;
    assert!(bytes <= max_bytes, "60k with checks allocated {bytes} bytes (> {max_bytes}, measured 54034102 + 5%)");
    assert!(allocs <= max_allocs, "60k with checks made {allocs} allocations (> {max_allocs}, measured 180072 + 1%)");
}


