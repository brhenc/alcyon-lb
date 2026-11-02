// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (S5): its #[global_allocator] refuses allocations of a buffer's size on demand.

//! A buffer that cannot be had fails the stream that asked for it, not the process
//! (`docs/design/memory-2026-10-24.md` 3.5, 3.10; `tradeoff.md` 6.23).
//!
//! Before S5 the buffer pool's miss path made the memory with `vec!` and, when the allocator
//! refused, called `handle_alloc_error`: the process aborted and every connection on every
//! thread was lost (T446 saw it under `prlimit`, in `buf::alloc_standard`). `HAProxy` 3.5-dev8
//! under `-dMfail` answers such a stream `500` with `IR--` (or closes the connection) and serves
//! the next one (measured, `tasks/S5-progress.md`).

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use ibex_alloc::{fail_thread_allocs_from, refusals_left, refuse_allocs_here, refuse_allocs_of, CountingAllocator};
use ibex_rt::buf::{Buf, BufClass};
use ibex_rt::engine::Engine;

/// The default `tune.bufsize`: what a buffer's memory is.
const BUFSIZE: usize = 16384;

/// Refuses buffer-sized allocations on demand ([`refuse_allocs_of`]).
#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator::new();

/// One engine at a time: the refusals are process-wide.
static ONE: Mutex<()> = Mutex::new(());

const DEFAULTS: &str = "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n";

/// An engine whose frontend has `lines` (each indented, newline-terminated), with nothing cached:
/// the next buffer comes from the allocator.
fn engine_with(global: &str, lines: &str) -> (Engine, SocketAddr) {
    let addr = common::reserve_addr();
    let cfg = format!("{global}{DEFAULTS}frontend f\n  bind {addr}\n{lines}");
    let engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    ibex_alloc::drain_local_pools();
    (engine, addr)
}

fn engine() -> (Engine, SocketAddr) {
    engine_with("", "  http-request return status 200 content-type text/plain string ok\n")
}

/// A server that answers each connection's first head with `rsp`, then closes it.
fn backend(rsp: &'static [u8]) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    let _ = s.write_all(rsp);
                    break;
                }
            }
        }
    });
    addr
}

/// An engine proxying to a [`backend`] answering `rsp`.
fn proxied(rsp: &'static [u8]) -> (Engine, SocketAddr) {
    let srv = backend(rsp);
    engine_with("", &format!("  default_backend b\nbackend b\n  server s1 {srv}\n"))
}

/// Sends `req` on a new connection and runs the engine until the connection is closed (it must
/// be, within 2 s); what came back.
fn send(engine: &mut Engine, addr: SocketAddr, req: &[u8]) -> String {
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_nonblocking(true).expect("nonblocking");
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let mut sent = 0;
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(2), "not closed; got {:?}", String::from_utf8_lossy(&got));
        if sent < req.len() {
            match c.write(&req[sent..]) {
                Ok(n) => sent += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => sent = req.len(),
            }
        }
        let _ = engine.run_once();
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&got).into_owned()
}

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";

fn request(engine: &mut Engine, addr: SocketAddr) -> Vec<u8> {
    send(engine, addr, GET).into_bytes()
}

fn buffer_failures() -> usize {
    ibex_rt::buf::buffer_pool_stats().map_or(0, |h| h.failures)
}

/// The request buffer of the first connection cannot be had, nor after every cache was given
/// back (the retry): that stream is answered `500` (its response buffer can be had), the failure
/// is counted, and the next connection is served.
#[test]
fn a_request_whose_buffer_cannot_be_had_is_answered_500_and_the_next_is_served() {
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut engine, addr) = engine();
    let failures = buffer_failures();
    refuse_allocs_of(BUFSIZE, 0, 2);
    let got = request(&mut engine, addr);
    assert_eq!(refusals_left(), 0, "the buffer was asked for, and once more");
    let text = String::from_utf8_lossy(&got);
    assert!(text.starts_with("HTTP/1.1 500"), "the failed stream: {text:?}");
    assert!(buffer_failures() > failures, "the refused buffer is counted");
    let got = request(&mut engine, addr);
    let text = String::from_utf8_lossy(&got);
    assert!(text.starts_with("HTTP/1.1 200") && text.ends_with("ok"), "the next stream: {text:?}");
}

/// No buffer at all for a while: the streams of that time get nothing and are closed; the
/// engine serves on once memory is back.
#[test]
fn while_no_buffer_can_be_had_streams_are_closed_and_the_engine_serves_on() {
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut engine, addr) = engine();
    refuse_allocs_of(BUFSIZE, 0, usize::MAX);
    let first = request(&mut engine, addr);
    let second = request(&mut engine, addr);
    refuse_allocs_of(BUFSIZE, 0, 0);
    for got in [first, second] {
        let text = String::from_utf8_lossy(&got);
        assert!(!text.contains(" 200 "), "a stream without buffers: {text:?}");
    }
    let got = request(&mut engine, addr);
    let text = String::from_utf8_lossy(&got);
    assert!(text.starts_with("HTTP/1.1 200") && text.ends_with("ok"), "after: {text:?}");
}

/// Each buffer of a proxied request in turn cannot be had (the request's, then its head's):
/// that stream gets a `500`, or is served when it could do without (a head's HTX that cannot
/// have a pooled buffer takes one of its own size), and the next is served.
#[test]
fn whichever_buffer_of_a_proxied_request_cannot_be_had_only_that_stream_fails() {
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut engine, addr) = proxied(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    for skip in 0..3 {
        ibex_alloc::drain_local_pools();
        refuse_allocs_of(BUFSIZE, skip, 2);
        let got = send(&mut engine, addr, GET);
        let refused = refusals_left() == 0;
        refuse_allocs_of(BUFSIZE, 0, 0);
        match skip {
            0 => assert!(refused && got.starts_with("HTTP/1.1 500"), "the request's buffer: {got:?}"),
            _ => assert!(got.starts_with("HTTP/1.1 200"), "skip {skip}: {got:?}"),
        }
        let after = send(&mut engine, addr, GET);
        assert!(after.starts_with("HTTP/1.1 200") && after.ends_with("ok"), "after skip {skip}: {after:?}");
    }
}

/// Set by [`slow_backend`] when it has a request head.
static HEAD_IN: AtomicBool = AtomicBool::new(false);

/// A server that answers each head 200 ms after it is in.
fn slow_backend() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let mut req = Vec::new();
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    HEAD_IN.store(true, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(200));
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                    break;
                }
            }
        }
    });
    addr
}

/// The response's buffer cannot be had once the request has gone to the server: the client
/// gets a `500` (nothing of the response had gone to it), and the next stream is served.
#[test]
fn a_response_whose_buffer_cannot_be_had_is_answered_500() {
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let srv = slow_backend();
    let (mut engine, addr) = engine_with("", &format!("  default_backend b\nbackend b\n  server s1 {srv}\n"));
    HEAD_IN.store(false, Ordering::SeqCst);
    let mut c = TcpStream::connect(addr).expect("connect");
    c.write_all(GET).expect("write");
    let start = Instant::now();
    while !HEAD_IN.load(Ordering::SeqCst) {
        assert!(start.elapsed() < Duration::from_secs(2), "the request never reached the server");
        let _ = engine.run_once();
    }
    // The request's memory is back in the cache: given back, and refused from the allocator.
    ibex_alloc::drain_local_pools();
    refuse_allocs_of(BUFSIZE, 0, 2);
    c.set_nonblocking(true).expect("nonblocking");
    let mut got = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        assert!(start.elapsed() < Duration::from_secs(3), "not closed: {:?}", String::from_utf8_lossy(&got));
        let _ = engine.run_once();
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
    }
    assert_eq!(refusals_left(), 0, "the response's buffer was asked for");
    refuse_allocs_of(BUFSIZE, 0, 0);
    let got = String::from_utf8_lossy(&got);
    assert!(got.starts_with("HTTP/1.1 500"), "{got:?}");
    let after = send(&mut engine, addr, GET);
    assert!(after.starts_with("HTTP/1.1 200"), "after: {after:?}");
}

/// A request held whole for its trailer section, larger than a buffer: the larger buffer cannot
/// be had, so that stream is answered `500`.
#[test]
fn a_request_held_for_its_trailers_whose_larger_buffer_cannot_be_had_is_answered_500() {
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut engine, addr) = proxied(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let mut req = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n7d0\r\n".to_vec();
    req.extend_from_slice(&[b'a'; 2000]);
    req.extend_from_slice(b"\r\n0\r\nx-t: ");
    req.extend_from_slice(&[b'b'; 15000]);
    req.extend_from_slice(b"\r\n\r\n");
    fail_thread_allocs_from(BUFSIZE + 1);
    let got = send(&mut engine, addr, &req);
    fail_thread_allocs_from(usize::MAX);
    assert!(got.starts_with("HTTP/1.1 500"), "{got:?}");
    let after = send(&mut engine, addr, GET);
    assert!(after.starts_with("HTTP/1.1 200"), "after: {after:?}");
}

/// The same for a response held for its trailers: the client gets a `500`, not the response.
#[test]
fn a_response_held_for_its_trailers_whose_larger_buffer_cannot_be_had_is_answered_500() {
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut rsp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7d0\r\n".to_vec();
    rsp.extend_from_slice(&[b'a'; 2000]);
    rsp.extend_from_slice(b"\r\n0\r\nx-t: ");
    rsp.extend_from_slice(&[b'b'; 15000]);
    rsp.extend_from_slice(b"\r\n\r\n");
    let (mut engine, addr) = proxied(Vec::leak(rsp));
    fail_thread_allocs_from(BUFSIZE + 1);
    let got = send(&mut engine, addr, GET);
    fail_thread_allocs_from(usize::MAX);
    assert!(got.starts_with("HTTP/1.1 500"), "{}", &got[..got.len().min(200)]);
    let after = send(&mut engine, addr, GET);
    assert!(after.starts_with("HTTP/1.1 200"), "after: {}", &after[..after.len().min(200)]);
}

/// A rewrite that needs a larger HTX than can be had: the HTX keeps its buffer and the rewrite
/// is refused as one that has no room; nothing aborts and the next stream is served.
#[test]
fn a_rewrite_whose_larger_htx_cannot_be_had_is_refused_as_one_without_room() {
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut engine, addr) = engine_with(
        "",
        "  http-request set-header x-copy %[req.hdr(x-big)]\n  http-request return status 200 content-type text/plain string ok\n",
    );
    let mut req = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nx-big: ".to_vec();
    req.extend_from_slice(&[b'b'; 12000]);
    req.extend_from_slice(b"\r\n\r\n");
    fail_thread_allocs_from(BUFSIZE + 1);
    let got = send(&mut engine, addr, &req);
    fail_thread_allocs_from(usize::MAX);
    assert!(!got.starts_with("HTTP/1.1 200"), "the rewrite had no room: {}", &got[..got.len().min(200)]);
    let after = send(&mut engine, addr, GET);
    assert!(after.starts_with("HTTP/1.1 200"), "after: {after:?}");
}

/// `Buf` itself: a buffer whose memory cannot be had is one without memory, a small buffer that
/// cannot be promoted stays small and full, and a growth that cannot be had leaves it as it was.
#[test]
fn a_buffer_without_memory_writes_nothing_and_says_so() {
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    ibex_alloc::drain_local_pools();
    let failures = buffer_failures();
    refuse_allocs_of(BUFSIZE, 0, 2);
    let mut b = Buf::standard();
    assert_eq!(refusals_left(), 0);
    assert!(!b.is_allocated());
    assert!(buffer_failures() > failures);
    refuse_allocs_of(BUFSIZE, 0, usize::MAX);
    assert!(b.writable().is_empty() && !b.put(b"x"));
    assert!(!b.grow_capacity(100), "no memory for the buffer itself");
    refuse_allocs_of(BUFSIZE, 0, 0);

    let mut small = Buf::small();
    assert!(small.put(&[1u8; 1000]));
    refuse_allocs_of(BUFSIZE, 0, 2);
    assert!(!small.promote_to_standard(), "no standard buffer to be had");
    refuse_allocs_of(BUFSIZE, 0, 0);
    assert_eq!((small.class(), small.len()), (BufClass::Small, 1000));

    let mut std_buf = Buf::standard();
    assert!(std_buf.put(b"abc"));
    fail_thread_allocs_from(BUFSIZE + 1);
    assert!(!std_buf.grow_capacity(2 * BUFSIZE));
    let custom = Buf::with_capacity(BUFSIZE + 7);
    fail_thread_allocs_from(usize::MAX);
    assert_eq!((std_buf.readable(), std_buf.capacity()), (&b"abc"[..], BUFSIZE));
    assert!(!custom.is_allocated());
    assert!(!Buf::unallocated(BufClass::Custom).alloc_if_needed());
    assert!(std_buf.grow_capacity(2 * BUFSIZE) && std_buf.readable() == b"abc");

    // The test hook itself: `refuse_allocs_here` refuses on this thread only.
    refuse_allocs_here(5555, 0, 1);
    let elsewhere = thread::spawn(|| Vec::<u8>::new().try_reserve_exact(5555).is_ok()).join().expect("thread");
    let here = Vec::<u8>::new().try_reserve_exact(5555).is_ok();
    refuse_allocs_of(5555, 0, 0);
    assert!(elsewhere && !here, "another thread's allocation is not refused, this one's is");
}

/// A TLS client's request over a new connection, from another thread (its allocations are not
/// the engine's); what came back, or the error that ended it.
fn tls_get(addr: SocketAddr, ca_der: Vec<u8>) -> thread::JoinHandle<Result<Vec<u8>, std::io::Error>> {
    thread::spawn(move || {
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(ca_der)).expect("root");
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let sock = TcpStream::connect(addr)?;
        sock.set_read_timeout(Some(Duration::from_secs(3)))?;
        let conn = rustls::ClientConnection::new(std::sync::Arc::new(config), "localhost".try_into().expect("name")).expect("conn");
        let mut tls = rustls::StreamOwned::new(conn, sock);
        tls.write_all(GET)?;
        let mut got = Vec::new();
        tls.read_to_end(&mut got)?;
        Ok(got)
    })
}

/// A TLS connection whose input buffer cannot be had is closed (no stream had begun); the
/// engine serves the next one.
#[test]
fn a_tls_connection_whose_input_buffer_cannot_be_had_is_closed_and_the_next_is_served() {
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let dir = tempfile::tempdir().expect("tempdir");
    let crt = dir.path().join("fe.pem");
    std::fs::write(&crt, format!("{}{}", c.cert.pem(), c.key_pair.serialize_pem())).expect("write crt");
    let addr = common::reserve_addr();
    let cfg = format!(
        "{DEFAULTS}frontend f\n  bind {addr} ssl crt {}\n  http-request return status 200 content-type text/plain string ok\n",
        crt.display()
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    ibex_alloc::drain_local_pools();
    let run = |engine: &mut Engine, h: thread::JoinHandle<Result<Vec<u8>, std::io::Error>>| {
        let start = Instant::now();
        while !h.is_finished() {
            assert!(start.elapsed() < Duration::from_secs(3), "the client never finished");
            let _ = engine.run_once();
        }
        h.join().expect("client thread")
    };
    // Exactly a buffer's size (rustls makes larger allocations of its own, which abort when
    // refused, `tradeoff.md` 6.23), and on the engine's thread only (the client's rustls is not
    // the engine's).
    for _ in 0..3 {
        let _ = engine.run_once();
    }
    ibex_alloc::drain_local_pools();
    // The first is the plaintext request buffer (taken before the socket is read), the next the
    // TLS input buffer.
    refuse_allocs_here(BUFSIZE, 1, 2);
    let first = run(&mut engine, tls_get(addr, c.cert.der().to_vec()));
    assert_eq!(refusals_left(), 0, "the input buffer was asked for");
    refuse_allocs_of(BUFSIZE, 0, 0);
    assert!(first.as_ref().map_or(true, |g| !g.starts_with(b"HTTP/1.1 200")), "{first:?}");
    let next = run(&mut engine, tls_get(addr, c.cert.der().to_vec())).expect("the next connection");
    assert!(next.starts_with(b"HTTP/1.1 200"), "{:?}", String::from_utf8_lossy(&next));
}

/// Reads HTTP/2 frames off `sock` while running the engine, until the HEADERS of `stream`: the
/// first byte of its block (`0x88` is `:status 200`), or `None` when the connection closed.
fn h2_status(engine: &mut Engine, sock: &mut TcpStream, stream: u32) -> Option<u8> {
    let mut rx = Vec::new();
    let mut buf = [0u8; 4096];
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(2), "no HEADERS on stream {stream}, not closed");
        let _ = engine.run_once();
        match sock.read(&mut buf) {
            Ok(0) => return None,
            Ok(n) => rx.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return None,
        }
        while rx.len() >= 9 {
            let len = (usize::from(rx[0]) << 16) | (usize::from(rx[1]) << 8) | usize::from(rx[2]);
            if rx.len() < 9 + len {
                break;
            }
            let sid = u32::from_be_bytes([rx[5], rx[6], rx[7], rx[8]]) & 0x7fff_ffff;
            match rx[3] {
                0x4 if rx[4] & 1 == 0 => sock.write_all(b"\x00\x00\x00\x04\x01\x00\x00\x00\x00").expect("SETTINGS ACK"),
                0x1 if sid == stream => return Some(rx[9]),
                _ => {}
            }
            rx.drain(..9 + len);
        }
    }
}

/// An HTTP/2 connection, its preface sent.
fn h2_connect(addr: SocketAddr) -> TcpStream {
    let mut sock = TcpStream::connect(addr).expect("connect");
    sock.set_nonblocking(true).expect("nonblocking");
    sock.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00").expect("preface");
    sock
}

/// `GET`, `http`, `/`, `:authority` x on stream `id`; `END_STREAM` and `END_HEADERS`.
fn h2_get(id: u8) -> [u8; 15] {
    [0, 0, 6, 1, 5, 0, 0, 0, id, 0x82, 0x86, 0x84, 0x41, 0x01, b'x']
}

/// An HTTP/2 stream whose buffer cannot be had is answered `500` on that stream, and the
/// connection goes on: the next stream on it is served (T464). `HAProxy` 3.5-dev8 under `-dMfail`
/// with `tune.fail-alloc 3`, `nghttp` sending four `GET`s on one connection (measured): the failed
/// stream gets HEADERS `:status 500` (`content-length: 97`, the error page as DATA) or, when its
/// mux stream cannot be made, `RST_STREAM` `REFUSED_STREAM`; the other streams complete (`200`)
/// and the connection ends with an idle `GOAWAY NO_ERROR`, never because of the failure.
#[test]
fn an_h2_stream_whose_buffer_cannot_be_had_is_answered_500_and_its_connection_goes_on() {
    const SMALL: usize = 1536;
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for skip in 0..2 {
        let (mut engine, addr) = engine_with(
            &format!("global\n  tune.bufsize.small {SMALL}\n"),
            "  http-request return status 200 content-type text/plain string ok\n",
        );
        let mut sock = h2_connect(addr);
        refuse_allocs_of(SMALL, skip, 2);
        sock.write_all(&h2_get(1)).expect("HEADERS 1");
        let failed = h2_status(&mut engine, &mut sock, 1);
        assert_eq!(refusals_left(), 0, "skip {skip}: the stream's buffer was asked for");
        refuse_allocs_of(SMALL, 0, 0);
        assert_eq!(failed, Some(0x8e), "skip {skip}: the failed stream gets :status 500");
        sock.write_all(&h2_get(3)).expect("HEADERS 3");
        assert_eq!(h2_status(&mut engine, &mut sock, 3), Some(0x88), "skip {skip}: the next stream, same connection");
    }
}

/// Set by [`split_backend`] once the response head is sent; the body follows 200 ms later.
static HEAD_OUT: AtomicBool = AtomicBool::new(false);

fn split_backend() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut buf = [0u8; 4096];
            if s.read(&mut buf).unwrap_or(0) == 0 {
                continue;
            }
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab");
            HEAD_OUT.store(true, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(200));
            let _ = s.write_all(b"cd");
        }
    });
    addr
}

/// Part of the response has gone to the client when the next buffer for it cannot be had: the
/// connection is closed (a `500` can no longer be sent), and the next stream is served.
#[test]
fn a_response_cut_short_by_a_buffer_that_cannot_be_had_closes_the_connection() {
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let srv = split_backend();
    let (mut engine, addr) = engine_with("", &format!("  default_backend b\nbackend b\n  server s1 {srv}\n"));
    HEAD_OUT.store(false, Ordering::SeqCst);
    let mut c = TcpStream::connect(addr).expect("connect");
    c.write_all(GET).expect("write");
    c.set_nonblocking(true).expect("nonblocking");
    let mut got = Vec::new();
    let mut buf = [0u8; 1024];
    let start = Instant::now();
    let mut refused = false;
    loop {
        assert!(start.elapsed() < Duration::from_secs(3), "not closed: {:?}", String::from_utf8_lossy(&got));
        let _ = engine.run_once();
        if !refused && got.ends_with(b"ab") {
            // The head and the first bytes are out, the response buffer given back.
            ibex_alloc::drain_local_pools();
            refuse_allocs_of(BUFSIZE, 0, 2);
            refused = true;
        }
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
    }
    let left = refusals_left();
    refuse_allocs_of(BUFSIZE, 0, 0);
    assert_eq!(left, 0, "the buffer for the rest was asked for");
    let got = String::from_utf8_lossy(&got);
    assert!(got.starts_with("HTTP/1.1 200") && got.ends_with("ab"), "{got:?}");
    let after = send(&mut engine, addr, GET);
    assert!(after.starts_with("HTTP/1.1 200") && after.ends_with("abcd"), "after: {after:?}");
}

/// An HTTP/2 stream whose response has begun when the next buffer for it cannot be had is reset
/// `INTERNAL_ERROR` (a `500` can no longer be sent) and its connection goes on: the next stream on
/// it is served (T464). `HAProxy` cannot be driven to this case with `-dMfail`: its refusals are
/// random, and the one that lands after the HEADERS cannot be aimed.
#[test]
fn an_h2_response_cut_short_by_a_buffer_that_cannot_be_had_resets_its_stream_only() {
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let srv = split_backend();
    let (mut engine, addr) = engine_with("", &format!("  default_backend b\nbackend b\n  server s1 {srv}\n"));
    let mut sock = h2_connect(addr);
    sock.write_all(&h2_get(1)).expect("HEADERS 1");
    let (mut rx, mut buf) = (Vec::new(), [0u8; 4096]);
    let (mut refused, mut rst) = (false, None);
    let start = Instant::now();
    while rst.is_none() {
        assert!(start.elapsed() < Duration::from_secs(3), "no RST_STREAM on stream 1 (refused: {refused}, left {})", refusals_left());
        let _ = engine.run_once();
        match sock.read(&mut buf) {
            Ok(0) => panic!("the connection was closed (refused: {refused})"),
            Ok(n) => rx.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("read: {e}"),
        }
        while rx.len() >= 9 {
            let len = (usize::from(rx[0]) << 16) | (usize::from(rx[1]) << 8) | usize::from(rx[2]);
            if rx.len() < 9 + len {
                break;
            }
            let sid = u32::from_be_bytes([rx[5], rx[6], rx[7], rx[8]]) & 0x7fff_ffff;
            match rx[3] {
                0x4 if rx[4] & 1 == 0 => sock.write_all(b"\x00\x00\x00\x04\x01\x00\x00\x00\x00").expect("SETTINGS ACK"),
                0x0 if sid == 1 && !refused => {
                    // The response has begun and its first bytes are out, its buffer given back
                    // in the pass that sent them (the stream and its owner hand each other the
                    // work in one pass, L2); the buffer for the rest is refused. No pass more is
                    // run first: with nothing left to do it waits in the poller until the rest
                    // comes, and the rest was read before the refusal was in place.
                    ibex_alloc::drain_local_pools();
                    refuse_allocs_of(BUFSIZE, 0, 2);
                    refused = true;
                }
                0x3 if sid == 1 => rst = Some(u32::from_be_bytes([rx[9], rx[10], rx[11], rx[12]])),
                _ => {}
            }
            rx.drain(..9 + len);
        }
    }
    let left = refusals_left();
    refuse_allocs_of(BUFSIZE, 0, 0);
    assert_eq!(left, 0, "the buffer for the rest was asked for");
    assert_eq!(rst, Some(2), "RST_STREAM INTERNAL_ERROR on stream 1");
    sock.write_all(&h2_get(3)).expect("HEADERS 3");
    assert_eq!(h2_status(&mut engine, &mut sock, 3), Some(0x88), "the next stream, same connection");
}

/// The request's target cannot be copied into the session (`ReqText::set`, where T446's run
/// under `RLIMIT_DATA` aborted once the buffers were fallible): that stream is answered `500`.
#[test]
fn a_request_whose_target_cannot_be_copied_is_answered_500() {
    const URI_LEN: usize = 333;
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut engine, addr) = engine();
    let uri = format!("/{}", "u".repeat(URI_LEN - 1));
    let req = format!("GET {uri} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    ibex_alloc::drain_local_pools();
    refuse_allocs_of(URI_LEN, 0, 1);
    let got = send(&mut engine, addr, req.as_bytes());
    let left = refusals_left();
    refuse_allocs_of(URI_LEN, 0, 0);
    assert_eq!(left, 0, "the target's copy was asked for");
    assert!(got.starts_with("HTTP/1.1 500"), "{got:?}");
    let after = send(&mut engine, addr, req.as_bytes());
    assert!(after.starts_with("HTTP/1.1 200"), "after: {after:?}");
}

/// The request is in its buffer, but no memory is left for its head's HTX, pooled or of its
/// own size: that stream fails (closed: its answer has no buffer either), the next is served.
#[test]
fn a_head_whose_htx_cannot_be_had_fails_its_stream() {
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut engine, addr) = engine();
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_nonblocking(true).expect("nonblocking");
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").expect("first part");
    for _ in 0..20 {
        let _ = engine.run_once();
    }
    // The request buffer is taken; from here on nothing of 4 KiB or more can be had here.
    ibex_alloc::drain_local_pools();
    fail_thread_allocs_from(4096);
    c.write_all(b"Connection: close\r\n\r\n").expect("rest");
    let mut got = Vec::new();
    let mut buf = [0u8; 1024];
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(2), "not closed: {:?}", String::from_utf8_lossy(&got));
        let _ = engine.run_once();
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
    }
    fail_thread_allocs_from(usize::MAX);
    let got = String::from_utf8_lossy(&got);
    assert!(got.is_empty() || got.starts_with("HTTP/1.1 500"), "{got:?}");
    let after = send(&mut engine, addr, GET);
    assert!(after.starts_with("HTTP/1.1 200"), "after: {after:?}");
}

/// The error page cannot be copied for its answer (`proxy_error_response`, where T446's run
/// under `RLIMIT_DATA` aborted once the timer tree no longer did, T465): that connection is
/// closed without an answer, as for an empty `errorfile`, and the next is served.
#[test]
fn an_error_page_that_cannot_be_copied_closes_its_connection_only() {
    const BAD: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\nBad Name: y\r\n\r\n";
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut engine, addr) = engine();
    let page = send(&mut engine, addr, BAD);
    assert!(page.starts_with("HTTP/1.1 400"), "{page:?}");
    ibex_alloc::drain_local_pools();
    refuse_allocs_of(page.len(), 0, 1);
    let got = send(&mut engine, addr, BAD);
    let left = refusals_left();
    refuse_allocs_of(page.len(), 0, 0);
    assert_eq!(left, 0, "the page's copy was asked for");
    assert!(got.is_empty(), "{got:?}");
    let after = send(&mut engine, addr, GET);
    assert!(after.starts_with("HTTP/1.1 200"), "after: {after:?}");
}

/// A server that answers every head on a connection with `rsp` and keeps the connection open.
fn keepalive_backend(rsp: &'static [u8]) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            thread::spawn(move || {
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    while let Some(end) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                        req.drain(..end + 4);
                        if s.write_all(rsp).is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Sends a keep-alive `GET` and runs the engine until its 2-byte body is in (within 2 s); the
/// connection is closed after.
fn keepalive_get(engine: &mut Engine, addr: SocketAddr) -> String {
    let mut c = TcpStream::connect(addr).expect("connect");
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("request");
    c.set_nonblocking(true).expect("nonblocking");
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let start = Instant::now();
    while !got.ends_with(b"ok") {
        assert!(start.elapsed() < Duration::from_secs(2), "no answer; got {:?}", String::from_utf8_lossy(&got));
        let _ = engine.run_once();
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(_) => {}
        }
    }
    String::from_utf8_lossy(&got).into_owned()
}

/// The server's idle list cannot grow to keep the released server connection
/// (`WorkerPool::keep_with`, where T446's run under `RLIMIT_DATA` aborted, T465): the
/// connection is closed instead of kept, the request was served, and so is the next.
#[test]
fn a_server_connection_the_idle_list_cannot_hold_is_closed_and_the_request_served() {
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let srv = keepalive_backend(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let (mut engine, addr) = engine_with("", &format!("  default_backend b\nbackend b\n  server s1 {srv}\n  server s2 {srv}\n"));
    // The first request, to s1, makes what the backend makes once; the second goes to s2
    // (round robin: a client's first request takes no idle connection), whose idle list is new.
    let first = keepalive_get(&mut engine, addr);
    assert!(first.starts_with("HTTP/1.1 200"), "{first:?}");
    // A first `VecDeque` allocation is room for 4 entries of up to 1 KiB, else for one.
    let entry = ibex_rt::engine::idle_entry_size();
    let entry = if entry > 1024 { entry } else { 4 * entry };
    refuse_allocs_of(entry, 0, 1);
    let got = keepalive_get(&mut engine, addr);
    let left = refusals_left();
    refuse_allocs_of(entry, 0, 0);
    assert_eq!(left, 0, "the idle list's room was asked for");
    assert!(got.starts_with("HTTP/1.1 200") && got.ends_with("ok"), "{got:?}");
    let after = send(&mut engine, addr, GET);
    assert!(after.starts_with("HTTP/1.1 200") && after.ends_with("ok"), "after: {after:?}");
}

/// The purge of idle server connections closes them without memory of its own
/// (`IdlePool::purge`, where T446's run under `RLIMIT_DATA` aborted on a 96-byte `Vec::push`
/// once the idle lists were fallible, T465).
#[test]
fn idle_server_connections_are_purged_without_memory() {
    // The first push of a `Vec` of (server, count) pairs: room for 4 of 24 bytes.
    const CLOSED: usize = 96;
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let srv = keepalive_backend(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let (mut engine, addr) = engine_with("", &format!("  default_backend b\nbackend b\n  server s1 {srv} pool-purge-delay 20ms\n"));
    let got = keepalive_get(&mut engine, addr);
    assert!(got.starts_with("HTTP/1.1 200"), "{got:?}");
    for _ in 0..20 {
        let _ = engine.run_once();
    }
    thread::sleep(Duration::from_millis(50));
    refuse_allocs_here(CLOSED, 0, usize::MAX);
    for _ in 0..20 {
        let _ = engine.run_once();
    }
    refuse_allocs_of(CLOSED, 0, 0);
    let after = keepalive_get(&mut engine, addr);
    assert!(after.starts_with("HTTP/1.1 200") && after.ends_with("ok"), "after: {after:?}");
}

/// `tune.ibex.counters per-thread` (T582 Q4): a worker whose counter rows cannot be had does not
/// start, and says how many bytes it asked for; it never aborts. One frontend and a backend of
/// seven servers: 2 + 2 + 7 rows and a guard row at each end, 13 rows of 208 bytes.
#[test]
fn a_worker_whose_counter_rows_cannot_be_had_does_not_start_and_names_the_size() {
    let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let addr = common::reserve_addr();
    let servers: String = (1..=7).map(|i| format!("  server s{i} 127.0.0.1:9 disabled\n")).collect();
    let cfg = format!("global\n  tune.ibex.counters per-thread\n{DEFAULTS}frontend f\n  bind {addr}\n  default_backend b\nbackend b\n{servers}");
    let config = ibex_config::parse_str(&cfg).expect("parse");
    let bytes = 13 * 208;
    refuse_allocs_here(bytes, 0, 1);
    let started = Engine::new(&config, 64);
    refuse_allocs_here(bytes, 0, 0);
    let err = started.err().expect("the start fails");
    assert_eq!(err.to_string(), format!("tune.ibex.counters per-thread: cannot allocate the {bytes} bytes of thread 1's counter rows"));
}
