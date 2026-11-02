// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T260): counts the test process's allocations and bytes (#[global_allocator])

//! Allocation oracle pinning data-path memory allocations per request.
//!
//! Requirement from `nudge-agy-4.md` (Item 1):
//! The work done per request must be bounded and predictable. Ibex tracks global
//! and scoped allocations to pin steady-state requests and drive allocation counts down.

mod common;

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
    let fe_addr = common::reserve_addr();

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
    // 2026-10-17: 6 allocs, 202 bytes, one of them a 32-byte `Box<SocketAddr>` for `bc_dst`
    // made on every server connect (853f2b94; measuring gate 4 -> 5 allocs/req). `bc_dst`
    // is derived from the stream's target now: 5 allocs, 170 bytes. Pinned there.
    // 2026-10-18 (Z2): the `Box<H1Parser>` made per request head (56 bytes) is a value on the
    // stack now: 4 allocs, 114 bytes.
    // 2026-10-24 (S1, as fix/t444): the method and URI (`ReqText`, 3 + 9 bytes) of a new
    // connection come from the spare strings the last connection gave back: 2 allocs, 102 bytes.
    let max_allowed_allocs: usize = 2;
    assert!(
        diff.alloc_count <= max_allowed_allocs,
        "a steady state HTTP request allocated {} times (> {}); diff: {:?}",
        diff.alloc_count,
        max_allowed_allocs,
        diff
    );
    let max_allowed_bytes: usize = 102;
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

/// T519: with `retry-on 503` armed the request is kept to be sent again (`l7_buffer`). Its copy
/// came from the heap (`data.to_vec()` in a `Box`: 2 allocations per request, found by T517);
/// it is a buffer of the pool now, given back with the transaction.
#[test]
fn a_request_with_retry_on_a_status_copies_it_into_a_pooled_buffer() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

    let (srv_listener, srv_addr) = loopback0();
    let fe_addr = common::reserve_addr();
    let running = Arc::new(AtomicBool::new(true));
    let be = start_dummy_http_backend(srv_listener, Arc::clone(&running));

    let fe = FrontendSection {
        name: "fe_retry".into(),
        bind: Some(fe_addr),
        mode: Mode::Http,
        default_backend: Some("be_retry".into()),
        clitimeout: Some(Duration::from_secs(5)),
        ..Default::default()
    };
    let config = Config {
        frontends: vec![fe],
        backends: vec![BackendSection {
            name: "be_retry".into(),
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(5)),
            srvtimeout: Some(Duration::from_secs(5)),
            retry_on: ibex_config::RE_CONN_FAILED | 0x2000, // retry-on conn-failure 503
            servers: vec![Server::new("s1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut engine = Engine::new(&config, 64).expect("Engine::new");

    drive_single_http_request(fe_addr, &mut engine);
    drive_single_http_request(fe_addr, &mut engine);
    let before = ibex_alloc::alloc_counters();
    drive_single_http_request(fe_addr, &mut engine);
    let diff = before.diff(&ibex_alloc::alloc_counters());
    println!("[MEASUREMENT T519] retry-on 503 request: {} allocs, {} bytes", diff.alloc_count, diff.bytes_allocated);
    assert!(
        diff.alloc_count <= 2,
        "a retry-on request allocated {} times (> 2, the plain request's); diff: {diff:?}",
        diff.alloc_count
    );
    assert!(diff.bytes_allocated <= 102, "a retry-on request allocated {} bytes (> 102)", diff.bytes_allocated);

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
    let fe_addr = common::reserve_addr();

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
    // 2026-10-17: 2 allocs, 40 bytes, one of them the 32-byte `Box<SocketAddr>` the TCP-mode
    // connect made for `bc_dst` (853f2b94). Without it: 1 alloc, 8 bytes. Pinned there.
    let max_allowed_allocs: usize = 1;
    assert!(
        diff.alloc_count <= max_allowed_allocs,
        "a steady state TCP connection allocated {} times (> {}); diff: {:?}",
        diff.alloc_count,
        max_allowed_allocs,
        diff
    );
    let max_allowed_bytes: usize = 8;
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
    let fe_addr = common::reserve_addr();

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

/// Tripwire under `sixty_thousand_backends_with_checks_memory_bounded` (T255). That test failed
/// its 35 MB bound on purpose from T36 to T304 (tradeoff.md 6.5), and the gate only checked that
/// it still failed. It pinned 180,072 allocations and 54,034,102 bytes (2026-10-10, main
/// 5175acc); T304 shared the check configuration per backend and took the cost to 120,449
/// allocations and 35,525,575 bytes (2026-10-11, the test run alone with `--exact`, as the
/// gate runs it: run after another 60,000 test it is ~378 allocations and ~540 KB less, the
/// process's one-time initialisation, mostly the predefined ACLs' regex), which this pins now.
/// Bounds: bytes at most the measured plus 5%, allocations at most the measured plus 1%: the
/// allocation count is the sharper edge (a fourth allocation per server is +50%). The 35 MB
/// test remains the target.
#[test]
fn sixty_thousand_backends_with_checks_no_further_growth() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

    let (allocs, bytes) = sixty_thousand_with_checks_cost();
    println!("[MEASUREMENT] 60,000 backends WITH checks (tripwire): {allocs} allocs, {bytes} bytes");

    let max_bytes: usize = 35_525_575 / 100 * 105;
    let max_allocs: usize = 120_449 / 100 * 101;
    assert!(bytes <= max_bytes, "60k with checks allocated {bytes} bytes (> {max_bytes}, measured 35525575 + 5%)");
    assert!(allocs <= max_allocs, "60k with checks made {allocs} allocations (> {max_allocs}, measured 120449 + 1%)");
}



/// Sends one request on the keep-alive connection `client` and runs the engine until its whole
/// response (`http-request return ... string ok`, so a 2-byte body) is back.
fn drive_keepalive_request(client: &mut TcpStream, engine: &mut Engine) {
    client.write_all(b"GET /api/test HTTP/1.1\r\nHost: localhost\r\n\r\n").expect("write req");
    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 512];
    while start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once();
        if let Ok(n) = client.read(&mut buf) {
            response.extend_from_slice(&buf[..n]);
            if response.ends_with(b"\r\n\r\nok") {
                break;
            }
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(response.starts_with(b"HTTP/1.1 200"), "response: {:?}", String::from_utf8_lossy(&response));
    assert!(response.ends_with(b"\r\n\r\nok"), "response: {:?}", String::from_utf8_lossy(&response));
    for _ in 0..3 {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
}

/// The allocations of the third request on one keep-alive connection to a frontend running
/// `rules` (then `http-request return`).
fn keepalive_request_allocations(rules: &str) -> usize {
    let addr = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend f\n  bind {addr}\n{rules}  http-request return status 200 content-type text/plain string ok\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let mut client = TcpStream::connect(addr).expect("connect to frontend");
    client.set_nonblocking(true).expect("set_nonblocking");
    drive_keepalive_request(&mut client, &mut engine);
    drive_keepalive_request(&mut client, &mut engine);
    let before = ibex_alloc::alloc_counters();
    drive_keepalive_request(&mut client, &mut engine);
    let diff = before.diff(&ibex_alloc::alloc_counters());
    drop(client);
    for _ in 0..5 {
        let _ = engine.run_once();
    }
    diff.alloc_count
}

/// T364 S6: storing a variable allocates nothing on a keep-alive request. The store keeps its
/// slots and arena from one transaction to the next (design typed-variables-2026-10-18 §2.5).
/// Measured before S6 (release, 2026-10-18): none 7, 1 int 9, 1 str 12, int+str+sess 16, 5 ints
/// 17 (the name copied into two maps per set, the value cloned, and `str()` decoding its
/// argument on every request). After: 7 each.
#[test]
fn set_var_on_a_keep_alive_request_allocates_nothing() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let none = keepalive_request_allocations("");
    let cases = [
        ("1 int", "  http-request set-var(txn.a) int(5)\n".to_string()),
        ("1 str", "  http-request set-var(txn.s) str(hello)\n".to_string()),
        (
            "int+str+sess",
            "  http-request set-var(txn.a) int(5)\n  http-request set-var(txn.s) str(hello)\n  \
             http-request set-var(sess.c) int(1)\n"
                .to_string(),
        ),
        (
            "5 ints",
            ["a", "b", "c", "d", "e"].iter().map(|n| format!("  http-request set-var(txn.{n}) int(5)\n")).collect::<Vec<_>>().concat(),
        ),
    ];
    let mut got = Vec::new();
    for (name, rules) in &cases {
        got.push((*name, keepalive_request_allocations(rules)));
    }
    println!("[MEASUREMENT T364 S6] keep-alive request allocations: none {none}, {got:?}");
    for (name, n) in got {
        assert_eq!(n, none, "set-var ({name}) allocated {n} times on a keep-alive request, {none} without it");
    }
}

/// R4: a rule's format renders with no `String` built for it: `%r` in a `set-header` value is
/// the request line the rule reads from the stream (`request_line_of` built it with `format!`,
/// one allocation a request), and `set-var-fmt` renders its value in a scratch, not a
/// `String::with_capacity`.
#[test]
fn a_format_render_takes_no_string() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let none = keepalive_request_allocations("");
    let cases = [
        ("%r", "  http-request set-header X-L \"%r\"\n"),
        ("%[path]", "  http-request set-header X-L \"%[path]\"\n"),
        ("%HM", "  http-request set-header X-L \"%HM\"\n"),
        ("%[path] %HM", "  http-request set-header X-L \"%[path] %HM\"\n"),
        ("set-var-fmt", "  http-request set-var-fmt(txn.f) \"%[path]-%HM\"\n"),
    ];
    let got: Vec<_> = cases.iter().map(|(n, r)| (*n, keepalive_request_allocations(r))).collect();
    println!("[MEASUREMENT R4] keep-alive request allocations: none {none}, {got:?}");
    for (name, n) in got {
        assert_eq!(n, none, "a rule rendering `{name}` allocated {n} times on a keep-alive request, {none} without it");
    }
}

/// A keep-alive HTTP/1.1 server for `keepalive_proxied_allocations`: answers every head on every
/// connection with a 2-byte body, from a fixed buffer, so the backend thread allocates nothing
/// per request (the counter is process-wide).
fn start_keepalive_backend(listener: TcpListener, running: Arc<AtomicBool>, rsp: &'static [u8]) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking");
        let mut conns: Vec<TcpStream> = Vec::with_capacity(8);
        let mut buf = [0u8; 4096];
        while running.load(Ordering::Relaxed) {
            if let Ok((s, _)) = listener.accept() {
                s.set_nonblocking(true).expect("nonblocking");
                conns.push(s);
            }
            // A closed connection is dropped, so that the list never grows (and reallocates)
            // past what is open.
            conns.retain_mut(|s| {
                // One head per read: the client sends the next request only after the response.
                match s.read(&mut buf) {
                    Ok(0) => false,
                    Ok(n) => {
                        if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                            let _ = s.write_all(rsp);
                        }
                        true
                    }
                    Err(e) => e.kind() == std::io::ErrorKind::WouldBlock,
                }
            });
            thread::sleep(Duration::from_micros(200));
        }
    })
}

/// One request on the keep-alive `client`, the engine run until a response starting with
/// `status` and ending with `tail` is back. Unlike `drive_keepalive_request` it does not idle
/// the engine afterwards (each idle `run_once` sleeps up to 100 ms), and it reads into a fixed
/// buffer: nothing here allocates.
fn drive_request_expecting(client: &mut TcpStream, engine: &mut Engine, status: &[u8], tail: &[u8]) {
    client.write_all(b"GET /api/test HTTP/1.1\r\nHost: localhost\r\n\r\n").expect("write req");
    let start = Instant::now();
    let mut response = [0u8; 512];
    let mut len = 0;
    while start.elapsed() < Duration::from_secs(2) && !response[..len].ends_with(tail) {
        let _ = engine.run_once();
        if let Ok(n) = client.read(&mut response[len..]) {
            len += n;
        }
    }
    let got = &response[..len];
    assert!(got.starts_with(status) && got.ends_with(tail), "response: {:?}", String::from_utf8_lossy(got));
}

/// The allocations of `n` keep-alive requests on one client connection, proxied to a keep-alive
/// server, after three warm-up requests.
fn keepalive_proxied_allocations(n: usize) -> usize {
    keepalive_allocations_with("", PLAIN_RSP, n, b"HTTP/1.1 200", b"\r\n\r\nok").0
}

/// The server's answer for most of these tests.
const PLAIN_RSP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
/// The answer of the server `measure-bench backend` (what the survey's load ran against), with a
/// `Server` header for `del-header` to remove: its `Connection` is one the response rules take out.
const BENCH_RSP: &[u8] = b"HTTP/1.1 200 OK\r\nServer: be\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";

/// The allocations of `n` keep-alive requests on one client connection to a frontend with
/// `fe_lines` (each line indented, newline-terminated) and a keep-alive server behind it, after
/// three warm-up requests; every response must start with `status` and end with `tail`. The
/// allocations, and the reallocations (a `malloc` too, to libc).
fn keepalive_allocations_with(fe_lines: &str, rsp: &'static [u8], n: usize, status: &[u8], tail: &[u8]) -> (usize, usize) {
    let (a, r, _) = keepalive_run(fe_lines, rsp, n, status, tail);
    (a, r)
}

/// [`keepalive_allocations_with`], and the by-name variable lookups the `n` requests made on
/// this thread (the engine runs on it: `Engine::run_once`).
fn keepalive_run(fe_lines: &str, rsp: &'static [u8], n: usize, status: &[u8], tail: &[u8]) -> (usize, usize, u64) {
    let (srv, srv_addr) = loopback0();
    let addr = common::reserve_addr();
    let running = Arc::new(AtomicBool::new(true));
    let be = start_keepalive_backend(srv, Arc::clone(&running), rsp);
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend f\n  bind {addr}\n{fe_lines}  default_backend b\nbackend b\n  server s1 {srv_addr}\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let mut client = TcpStream::connect(addr).expect("connect to frontend");
    client.set_nonblocking(true).expect("set_nonblocking");
    for _ in 0..3 {
        drive_request_expecting(&mut client, &mut engine, status, tail);
    }
    let before = ibex_alloc::alloc_counters();
    let lookups = ibex_sample::vars::name_lookups_on_this_thread();
    for _ in 0..n {
        drive_request_expecting(&mut client, &mut engine, status, tail);
    }
    let lookups = ibex_sample::vars::name_lookups_on_this_thread() - lookups;
    let diff = before.diff(&ibex_alloc::alloc_counters());
    drop(client);
    for _ in 0..5 {
        let _ = engine.run_once();
    }
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
    (diff.alloc_count, diff.realloc_count, lookups)
}

/// T595: a `set-var` whose name the configuration gives is resolved to its number at load: the
/// requests look up no variable name (no `NAMES` lock, no hash). Debug builds count the lookups.
#[cfg(debug_assertions)]
#[test]
fn set_var_with_a_configured_name_looks_up_no_name_per_request() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_, _, n) = keepalive_run(SURVEY_RULES, BENCH_RSP, 50, b"HTTP/1.1 200", b"\r\n\r\nok");
    let (_, _, c) = keepalive_run(
        "  http-request set-var(txn.q,ifnotset) path\n  http-request set-var(sess.k) int(1)\n  http-request unset-var(txn.q)\n",
        BENCH_RSP,
        50,
        b"HTTP/1.1 200",
        b"\r\n\r\nok",
    );
    let (_, _, f) = keepalive_run(
        "  http-request set-var(txn.v) path\n  http-request set-header X-V %[var(txn.v)]\n  http-request set-header X-W %[var(txn.none,\"d\")]\n",
        BENCH_RSP,
        50,
        b"HTTP/1.1 200",
        b"\r\n\r\nok",
    );
    assert_eq!(f, 0, "{f} by-name variable lookups in 50 requests reading var(txn.v)");
    println!("[MEASUREMENT T595] variable name lookups over 50 requests: survey rules {n}, conditions/sess/unset {c}");
    assert_eq!(n, 0, "{n} by-name variable lookups in 50 requests through set-var(txn.p)");
    assert_eq!(c, 0, "{c} by-name variable lookups in 50 requests (conditions, sess, unset-var)");
}

/// T436 A: a steady-state keep-alive request proxied to a server allocates nothing. Measured
/// before (2026-10-19, uprobe on malloc under the pstat load): 2 per request, the method and the
/// URI copied into `TcpSession::req_method` / `req_uri` as owned `String`s. The count for 1100
/// requests must equal the count for 100: whatever is left is one-time, not per request.
#[test]
fn a_proxied_keep_alive_request_allocates_nothing() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let few = keepalive_proxied_allocations(100);
    let many = keepalive_proxied_allocations(1100);
    println!("[MEASUREMENT T436 A] proxied keep-alive allocations: 100 requests {few}, 1100 requests {many}");
    assert_eq!(many, few, "1000 more keep-alive requests made {} more allocations", many as i64 - few as i64);
}

/// The ten request and response rules of the 2026-10-19 allocation survey (`rules.body` in
/// `review/alloc-survey-2026-10-19`): header set/del/add, a `%[rand]` format, set-var, a
/// `path_reg` and a `hdr` ACL, a deny that does not fire.
const SURVEY_RULES: &str = "  acl api path_reg ^/(api|v[0-9]+)/\n  acl hosty hdr(host) -m sub local\n  \
    http-request set-header X-Forwarded-Proto http\n  http-request del-header X-Junk\n  \
    http-request add-header X-Id %[rand]\n  http-request set-var(txn.p) path\n  \
    http-request deny if api !hosty\n  http-response set-header X-Served ibex\n  \
    http-response del-header Server\n";

/// T437 part 2: the survey's request and response rules allocate nothing per steady-state
/// request. Measured before (2026-10-19, uprobe on malloc, main 2bec0ce1): 72.18 per request.
#[test]
fn request_and_response_rules_allocate_nothing_per_request() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let few = keepalive_allocations_with(SURVEY_RULES, BENCH_RSP, 100, b"HTTP/1.1 200", b"\r\n\r\nok");
    let many = keepalive_allocations_with(SURVEY_RULES, BENCH_RSP, 1100, b"HTTP/1.1 200", b"\r\n\r\nok");
    println!("[MEASUREMENT T437 rules] keep-alive (allocations, reallocations): 100 requests {few:?}, 1100 requests {many:?}");
    // A reused string may still grow once while the strings settle into their roles (a
    // reallocation in the first run, none in the next): what counts is that 1000 more requests
    // add none.
    assert!(many.0 == few.0 && many.1 <= few.1, "1000 more requests through the rules: (allocations, reallocations) {few:?} -> {many:?}");
}

/// T437 part 3: `http-request return` builds its reply without allocating per request.
/// Measured before (2026-10-19, uprobe on malloc, main 2bec0ce1): 9.02 per request, 5 in
/// `build_templated_error_response`.
#[test]
fn http_request_return_allocates_nothing_per_request() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let rules = "  option forwardfor\n  http-request return status 404 content-type text/plain string nope\n";
    let few = keepalive_allocations_with(rules, PLAIN_RSP, 100, b"HTTP/1.1 404", b"\r\n\r\nnope");
    let many = keepalive_allocations_with(rules, PLAIN_RSP, 1100, b"HTTP/1.1 404", b"\r\n\r\nnope");
    println!("[MEASUREMENT T437 return] keep-alive (allocations, reallocations): 100 requests {few:?}, 1100 requests {many:?}");
    assert!(many.0 == few.0 && many.1 <= few.1, "1000 more `return` replies: (allocations, reallocations) {few:?} -> {many:?}");
}

/// One request with a `User-Agent` (what a capture reads) on the keep-alive `client`; as
/// `drive_proxied_request`.
fn drive_proxied_request_ua(client: &mut TcpStream, engine: &mut Engine) {
    client.write_all(b"GET /api/test?q=1 HTTP/1.1\r\nHost: localhost\r\nUser-Agent: alloc-test/1.0\r\n\r\n").expect("write req");
    let start = Instant::now();
    let mut response = [0u8; 512];
    let mut len = 0;
    while start.elapsed() < Duration::from_secs(2) && !response[..len].ends_with(b"\r\n\r\nok") {
        let _ = engine.run_once();
        if let Ok(n) = client.read(&mut response[len..]) {
            len += n;
        }
    }
    let got = &response[..len];
    assert!(got.starts_with(b"HTTP/1.1 200") && got.ends_with(b"\r\n\r\nok"), "response: {:?}", String::from_utf8_lossy(got));
}

/// The allocations of `n` keep-alive requests proxied by a frontend with `fe_lines` and a
/// `log` target (a UDP socket held open, never read: the lines are sent and dropped), after
/// three warm-up requests. Also the number of log datagrams that arrived, to show the
/// frontend logged.
fn logged_proxied_allocations(n: usize, fe_lines: &str) -> (usize, usize) {
    let (srv, srv_addr) = loopback0();
    let addr = common::reserve_addr();
    let log = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind log socket");
    let log_addr = log.local_addr().expect("log addr");
    let running = Arc::new(AtomicBool::new(true));
    let be = start_keepalive_backend(srv, Arc::clone(&running), b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n  log {log_addr} local0\n\
         frontend f\n  bind {addr}\n  log global\n{fe_lines}  default_backend b\nbackend b\n  server s1 {srv_addr}\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let mut client = TcpStream::connect(addr).expect("connect to frontend");
    client.set_nonblocking(true).expect("set_nonblocking");
    for _ in 0..3 {
        drive_proxied_request_ua(&mut client, &mut engine);
    }
    let before = ibex_alloc::alloc_counters();
    for _ in 0..n {
        drive_proxied_request_ua(&mut client, &mut engine);
    }
    let diff = before.diff(&ibex_alloc::alloc_counters());
    drop(client);
    for _ in 0..5 {
        let _ = engine.run_once();
    }
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
    log.set_nonblocking(true).expect("nonblocking log");
    let mut lines = 0;
    let mut buf = [0u8; 2048];
    while log.recv(&mut buf).is_ok() {
        lines += 1;
    }
    (diff.alloc_count, lines)
}

/// T437 part 1: a request logged with `option httplog` allocates nothing. Measured before
/// (2026-10-19, uprobe on malloc, main 5bcdce4b): 3 per request, the request line kept for `%r`
/// (`keep_request_line`), the rendered line (`render_bytes`) and `logfmt::alias`.
#[test]
fn a_request_logged_with_httplog_allocates_nothing() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (few, lines) = logged_proxied_allocations(100, "  option httplog\n");
    let (many, _) = logged_proxied_allocations(1100, "  option httplog\n");
    println!("[MEASUREMENT T437 1] httplog allocations: 100 requests {few}, 1100 requests {many}");
    assert!(lines > 0, "no log line arrived");
    assert_eq!(many, few, "1000 more logged requests made {} more allocations", many.abs_diff(few));
}

/// T437 part 1: a custom `log-format` with `%{+Q}r`, `%HU`.. and header captures allocates
/// nothing. Measured before (2026-10-19, this test on main 5bcdce4b): 18 per request (the
/// request line, the line, `%ft`, `%HM`.. each a `String`, and the captures: the headers
/// collected, the values, the slots, request and response).
#[test]
fn a_request_logged_with_a_capture_allocates_nothing() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let fe = "  log-format \"%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %{+Q}r %HM %HU %HP %HPO %HQ %HV %hr %hs %{+Q}hrl\"\n  \
              capture request header User-Agent len 64\n  capture request header Host len 32\n  \
              capture response header Content-Length len 8\n";
    let (few, lines) = logged_proxied_allocations(100, fe);
    let (many, _) = logged_proxied_allocations(1100, fe);
    println!("[MEASUREMENT T437 1] log-format + header capture allocations: 100 requests {few}, 1100 requests {many}");
    assert!(lines > 0, "no log line arrived");
    assert_eq!(many, few, "1000 more logged requests made {} more allocations", many.abs_diff(few));
}

/// The survey's `log-format` scenario (T437): `http-request capture` and `%[capture.req.hdr(0)]`.
/// What is left is the sample engine's, not the log's: the rule's fetch and its value as a
/// `String` (`sample_to_string`), and the log expression's fetch (T437 part 2, rules and
/// samples into a reused scratch). Measured 2026-10-19 (this test): 10 per request on main
/// 5bcdce4b, 3 after part 1. The bound holds part 1's result; part 2 brings it to 0.
#[test]
fn a_request_logged_with_a_capture_rule_allocates_only_in_the_samples() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let fe = "  log-format \"%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %{+Q}r %[capture.req.hdr(0)]\"\n  \
              http-request capture req.hdr(user-agent) len 64\n";
    let (few, lines) = logged_proxied_allocations(100, fe);
    let (many, _) = logged_proxied_allocations(1100, fe);
    println!("[MEASUREMENT T437 1] log-format + capture rule allocations: 100 requests {few}, 1100 requests {many}");
    assert!(lines > 0, "no log line arrived");
    assert!(many.saturating_sub(few) <= 3 * 1000, "1000 more logged requests made {} more allocations (bound 3 per request)", many.abs_diff(few));
}

/// A minimal h2c client on one connection: requests on streams 1, 3, 5.., from fixed
/// buffers, so that nothing on the client side allocates (the counter is process-wide).
struct H2cClient {
    sock: TcpStream,
    rx: [u8; 16384],
    rx_len: usize,
    next_stream: u32,
    /// The request's header block: `GET`, `http`, `/api/test?q=1` from the static table, the
    /// authority and a user agent with incremental indexing (h2load's choice: literals the
    /// first time, indexed after), and a never-indexed Huffman literal, decoded every time.
    block: [u8; 128],
    block_len: usize,
}

impl H2cClient {
    fn connect(addr: SocketAddr) -> H2cClient {
        let mut sock = TcpStream::connect(addr).expect("connect to frontend");
        sock.set_nonblocking(true).expect("set_nonblocking");
        sock.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00").expect("write preface");
        let mut v = vec![0x82, 0x86];
        v.push(0x04); // :path, literal without indexing, indexed name
        ibex_proto::hpack::encode_string_literal("/api/test?q=1", true, &mut v);
        v.push(0x41); // :authority, incremental indexing
        ibex_proto::hpack::encode_string_literal("localhost", true, &mut v);
        v.push(0x40 | 0x3a); // user-agent, static index 58
        ibex_proto::hpack::encode_string_literal("alloc-test/1.0", true, &mut v);
        v.push(0x10); // never indexed, new name
        ibex_proto::hpack::encode_string_literal("x-trace", true, &mut v);
        ibex_proto::hpack::encode_string_literal("abcdef0123456789", true, &mut v);
        let mut block = [0u8; 128];
        block[..v.len()].copy_from_slice(&v);
        H2cClient { sock, rx: [0; 16384], rx_len: 0, next_stream: 1, block, block_len: v.len() }
    }

    /// The second request on: what the encoder's table now holds is referenced.
    fn index_after_first(&mut self) {
        let mut v = vec![0x82, 0x86, 0x04];
        ibex_proto::hpack::encode_string_literal("/api/test?q=1", true, &mut v);
        v.extend_from_slice(&[0xbf, 0xbe]); // localhost (62+1), user-agent (62)
        v.push(0x10);
        ibex_proto::hpack::encode_string_literal("x-trace", true, &mut v);
        ibex_proto::hpack::encode_string_literal("abcdef0123456789", true, &mut v);
        self.block[..v.len()].copy_from_slice(&v);
        self.block_len = v.len();
    }

    /// Sends one GET and runs the engine until its response has ended (END_STREAM).
    fn request(&mut self, engine: &mut Engine) {
        let id = self.next_stream;
        self.next_stream += 2;
        let mut frame = [0u8; 9 + 128];
        let len = self.block_len;
        frame[..3].copy_from_slice(&u32::try_from(len).unwrap().to_be_bytes()[1..]);
        frame[3] = 0x1; // HEADERS
        frame[4] = 0x5; // END_STREAM | END_HEADERS
        frame[5..9].copy_from_slice(&id.to_be_bytes());
        frame[9..9 + len].copy_from_slice(&self.block[..len]);
        self.sock.write_all(&frame[..9 + len]).expect("write HEADERS");
        let start = Instant::now();
        let (mut status_seen, mut ended) = (false, false);
        while !ended {
            assert!(start.elapsed() < Duration::from_secs(2), "no response on stream {id}");
            let _ = engine.run_once();
            if let Ok(n) = self.sock.read(&mut self.rx[self.rx_len..]) {
                assert!(n > 0, "the connection closed");
                self.rx_len += n;
            }
            while self.rx_len >= 9 {
                let flen = (usize::from(self.rx[0]) << 16) | (usize::from(self.rx[1]) << 8) | usize::from(self.rx[2]);
                if self.rx_len < 9 + flen {
                    break;
                }
                let (ty, flags) = (self.rx[3], self.rx[4]);
                let sid = u32::from_be_bytes([self.rx[5], self.rx[6], self.rx[7], self.rx[8]]) & 0x7fff_ffff;
                match ty {
                    0x4 if flags & 1 == 0 => self.sock.write_all(b"\x00\x00\x00\x04\x01\x00\x00\x00\x00").expect("SETTINGS ACK"),
                    0x1 if sid == id => {
                        // `:status: 200`, indexed (0x88), first.
                        assert_eq!(self.rx.get(9), Some(&0x88), "response HEADERS do not start with :status 200");
                        status_seen = true;
                        ended |= flags & 1 != 0;
                    }
                    0x0 if sid == id => ended |= flags & 1 != 0,
                    0x3 | 0x7 => panic!("stream {id}: RST_STREAM or GOAWAY (type {ty})"),
                    _ => {}
                }
                self.rx.copy_within(9 + flen..self.rx_len, 0);
                self.rx_len -= 9 + flen;
            }
        }
        assert!(status_seen, "stream {id} ended without a response head");
    }
}

/// The allocations of `n` requests on one h2c connection, each proxied to a keep-alive
/// HTTP/1.1 server, after three warm-up requests.
fn h2c_proxied_allocations(n: usize) -> usize {
    h2c_allocations_with("", n)
}

/// [`h2c_proxied_allocations`], the frontend with the lines `fe_lines` (each ending in a newline).
fn h2c_allocations_with(fe_lines: &str, n: usize) -> usize {
    let (srv, srv_addr) = loopback0();
    let addr = common::reserve_addr();
    let running = Arc::new(AtomicBool::new(true));
    let be = start_keepalive_backend(srv, Arc::clone(&running), b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend f\n  bind {addr} proto h2\n{fe_lines}  default_backend b\nbackend b\n  server s1 {srv_addr}\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let mut client = H2cClient::connect(addr);
    client.request(&mut engine);
    client.index_after_first();
    for _ in 0..2 {
        client.request(&mut engine);
    }
    let before = ibex_alloc::alloc_counters();
    for _ in 0..n {
        client.request(&mut engine);
    }
    let diff = before.diff(&ibex_alloc::alloc_counters());
    drop(client);
    for _ in 0..5 {
        let _ = engine.run_once();
    }
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
    diff.alloc_count
}

/// T437 part 4: a steady-state h2c request proxied to an HTTP/1.1 server allocates nothing.
/// Measured before (2026-10-19, main 5bcdce4b): 49.7 per request (uprobe on malloc under
/// h2load), 53 in this test: HPACK decode (a `String` per name and value), the HTX of owned
/// blocks, the bridge's owned copies of the head, the response encoded into new `Vec`s, the
/// stream's session and the engine's per-pass queues.
#[test]
fn an_h2c_request_allocates_nothing() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let few = h2c_proxied_allocations(100);
    let many = h2c_proxied_allocations(1100);
    println!("[MEASUREMENT T437 4] h2c allocations: 100 requests {few}, 1100 requests {many}");
    // Measured after (2026-10-19): 0 and 0 or 1, and 1 for 2100, 4100 and 8100 requests: a
    // buffer of the connection grows once, at a moment the timing decides, not per request.
    assert!(many <= few + 1, "1000 more h2c requests made {} more allocations", many.abs_diff(few));
}

/// CP3: starting a stream of an h2 connection allocates nothing with header captures configured:
/// the stream's log takes the connection's by `clone_from`, into the capture lists and strings it
/// kept, not by a clone that builds them anew. Measured before (2026-11-02, main 6b86eb3a, debug):
/// see the commit message.
#[test]
fn a_stream_start_allocates_nothing() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let fe = "  capture request header User-Agent len 32\n  capture request header X-Trace len 32\n";
    let few = h2c_allocations_with(fe, 100);
    let many = h2c_allocations_with(fe, 1100);
    println!("[MEASUREMENT CP3] h2c allocations with two captures: 100 requests {few}, 1100 requests {many}");
    assert!(many <= few + 1, "1000 more h2c requests with captures made {} more allocations", many.abs_diff(few));
}

/// The allocations of `n` keep-alive requests (`Host: localhost`) on one client connection,
/// proxied to a TLS server (`ssl verify none`, then `server_opts`) after three warm-up
/// requests. The TLS server is a second frontend of the same engine (`bind ... ssl crt`),
/// answering `ok` itself, so nothing outside the engine allocates.
fn tls_backend_allocations(server_opts: &str, n: usize) -> usize {
    let addr = common::reserve_addr();
    let tls_addr = common::reserve_addr();
    let pem = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ssl_f_common.pem");
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend f\n  bind {addr}\n  default_backend b\n\
         frontend t\n  bind {tls_addr} ssl crt {pem}\n  http-request return status 200 content-type text/plain string ok\n\
         backend b\n  server s1 {tls_addr} ssl verify none{server_opts}\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let mut client = TcpStream::connect(addr).expect("connect to frontend");
    client.set_nonblocking(true).expect("set_nonblocking");
    for _ in 0..3 {
        drive_request_expecting(&mut client, &mut engine, b"HTTP/1.1 200", b"\r\n\r\nok");
    }
    let before = ibex_alloc::alloc_counters();
    for _ in 0..n {
        drive_request_expecting(&mut client, &mut engine, b"HTTP/1.1 200", b"\r\n\r\nok");
    }
    let diff = before.diff(&ibex_alloc::alloc_counters());
    drop(client);
    for _ in 0..5 {
        let _ = engine.run_once();
    }
    diff.alloc_count
}

/// The automatic SNI of a TLS server in `mode http` (`srv_configure_auto_sni`:
/// `req.hdr(host),field(1,:)`) allocates nothing per request. The kept server connection is
/// reused, but the name is evaluated for every request, to check that the connection was
/// opened for it (`HAProxy` hashes the SNI into the connection's reuse key per stream). The
/// TLS layer allocates on its own, so what is compared is the growth from 100 to 1100
/// requests, with and without `no-sni-auto`. Measured before (2026-10-24, main 6579719c, rustls
/// 0.23, debug): 9000 against 6000, 3 allocations per request for the name (the `field` copy,
/// the sample's string copied out, the header string never given back).
#[test]
fn the_automatic_sni_allocates_nothing_per_request() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = rustls::crypto::ring::default_provider().install_default();
    let growth = |opts: &str| {
        let count = |n| i64::try_from(tls_backend_allocations(opts, n)).expect("count");
        count(1100) - count(100)
    };
    let auto = growth("");
    let none = growth(" no-sni-auto");
    println!("[MEASUREMENT sni-alloc] allocations for 1000 more TLS-backend requests: automatic SNI {auto}, no-sni-auto {none}");
    assert_eq!(auto, none, "1000 more requests with the automatic SNI: {auto} allocations, {none} with no-sni-auto");
}
