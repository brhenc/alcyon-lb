// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T260): counts the test process's allocations (#[global_allocator])

//! The work an HTTP/2 request costs is the same for the first request of a connection and
//! for the ten-thousandth, and is a write per response (T186).
//!
//! Measured 2026-10-05 with `h2load -n 50000 -c 4 -m 10` against `/small`, nbthread 1:
//! Ibex spent ~500 us of CPU per h2 request (TLS or cleartext alike), `HAProxy` 3.5 ~25 us;
//! h1 over TLS was 28 vs 37 us. `perf` put 88% of Ibex's time in walking the connection's
//! stream map: a finished stream was never taken out of it, so every request scanned every
//! stream the connection had ever carried. `HAProxy` frees a stream when it closes
//! (`h2s_destroy`). And `strace` showed each response leave in two writes, HEADERS then
//! DATA a poller round apart, the second held by Nagle until the client's delayed ACK:
//! ~40 ms per request for a client that waits for the response (`h2load -m 1`).
//!
//! In-process, cleartext h2 (prior knowledge): the cost is in the mux, not in TLS.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ibex_alloc::CountingAllocator;
use ibex_rt::engine::Engine;
use ibex_rt::raw::{read_counters, write_counters};

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator::new();

/// The tests count process-wide allocations and thread-local syscalls: one at a time.
static TEST_MUTEX: Mutex<()> = Mutex::new(());

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// A keep-alive backend: answers every request head on a connection.
fn backend(listener: TcpListener, running: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    backend_after(listener, running, Duration::ZERO)
}

/// A keep-alive backend that takes `delay` to answer each request, a thread per
/// connection (the streams of an h2 connection are served at once, each on a server
/// connection of its own, T280).
fn backend_after(listener: TcpListener, running: Arc<AtomicBool>, delay: Duration) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking");
        while running.load(Ordering::Relaxed) {
            let Ok((s, _)) = listener.accept() else {
                thread::sleep(Duration::from_millis(1));
                continue;
            };
            let running = Arc::clone(&running);
            thread::spawn(move || serve(s, &running, delay));
        }
    })
}

fn serve(mut s: TcpStream, running: &AtomicBool, delay: Duration) {
    s.set_nonblocking(false).expect("blocking");
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
            thread::sleep(delay);
            if s.write_all(RESPONSE).is_err() {
                break;
            }
        }
    }
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("len");
    let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// HEADERS, END_STREAM|END_HEADERS: GET http://localhost/ from the static table, the
/// authority a literal without indexing (so the dynamic table stays empty).
fn request(stream: u32) -> Vec<u8> {
    let mut block = vec![0x82, 0x86, 0x84, 0x01, 9];
    block.extend_from_slice(b"localhost");
    frame(0x1, 0x5, stream, &block)
}

struct Client {
    sock: TcpStream,
    rx: Vec<u8>,
    next: u32,
}

impl Client {
    fn connect(engine: &mut Engine, addr: SocketAddr) -> Self {
        let mut sock = TcpStream::connect(addr).expect("connect");
        sock.set_nonblocking(true).expect("nonblocking");
        sock.set_nodelay(true).expect("nodelay");
        let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        hello.extend(frame(0x4, 0, 0, &[]));
        sock.write_all(&hello).expect("preface");
        let mut c = Client { sock, rx: Vec::new(), next: 1 };
        // The server's SETTINGS, acknowledged before the first request.
        c.until(engine, |f| f.0 == 0x4 && f.1 & 1 == 0);
        c.sock.write_all(&frame(0x4, 1, 0, &[])).expect("settings ack");
        c
    }

    /// Runs the engine until a frame `done` accepts has arrived; frames before it are
    /// dropped (SETTINGS ACK, WINDOW_UPDATE).
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
                assert_ne!(head.0, 0x3, "RST_STREAM: {:?}", &self.rx[..9 + len]);
                assert_ne!(head.0, 0x7, "GOAWAY: {:?}", &self.rx[..9 + len]);
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

    /// One request, and its response to the END_STREAM.
    fn get(&mut self, engine: &mut Engine) {
        let id = self.next;
        self.next += 2;
        self.sock.write_all(&request(id)).expect("request");
        self.until(engine, |(kind, flags, stream)| stream == id && (kind == 0x0 || kind == 0x1) && flags & 1 != 0);
    }
}

fn setup() -> (Engine, SocketAddr, Arc<AtomicBool>, thread::JoinHandle<()>) {
    setup_after(Duration::ZERO)
}

fn setup_after(delay: Duration) -> (Engine, SocketAddr, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let srv = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let srv_addr = srv.local_addr().expect("addr");
    let fe = common::reserve_addr();
    let running = Arc::new(AtomicBool::new(true));
    let be = backend_after(srv, Arc::clone(&running), delay);
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 5s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe} proto h2\n  default_backend be\n\
         backend be\n  server s1 {srv_addr}\n"
    );
    let engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    (engine, fe, running, be)
}

/// The streams a connection has finished are let go: memory held after 2000 more requests
/// on one connection is what it was. Before T186 each held its decoded request for the
/// life of the connection, and every request walked all of them.
#[test]
fn finished_h2_streams_do_not_pile_up_on_the_connection() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut engine, fe, running, be) = setup();
    let mut c = Client::connect(&mut engine, fe);
    for _ in 0..50 {
        c.get(&mut engine);
    }
    let live0 = ibex_alloc::alloc_counters().bytes_live();
    const N: usize = 2000;
    for _ in 0..N {
        c.get(&mut engine);
    }
    let live1 = ibex_alloc::alloc_counters().bytes_live();
    let grown = live1.saturating_sub(live0);
    println!("{N} h2 requests on one connection: live bytes {live0} -> {live1} (+{grown})");
    assert!(
        grown < 64 * 1024,
        "{N} requests on one h2 connection left {grown} more bytes live: finished streams are kept"
    );
    drop(c);
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}

/// A response leaves in one write: HEADERS and DATA together. With the client's request
/// read and the server's request write and response read, 2 writes and 2 reads a request.
#[test]
fn an_h2_request_is_two_writes_and_two_reads() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut engine, fe, running, be) = setup();
    let mut c = Client::connect(&mut engine, fe);
    for _ in 0..5 {
        c.get(&mut engine);
    }
    const N: u64 = 200;
    let (r0, b0) = read_counters();
    let w0 = write_counters();
    for _ in 0..N {
        c.get(&mut engine);
    }
    let (r1, b1) = read_counters();
    let w1 = write_counters();
    let (reads, blocked, writes) = (r1 - r0, b1 - b0, w1 - w0);
    println!("{N} h2 requests: {writes} writes, {reads} reads ({blocked} EAGAIN)");
    assert!(
        writes * 10 <= N * 21,
        "{writes} writes for {N} h2 requests: a response leaves in more than one write"
    );
    assert!(
        blocked * 10 <= N && reads * 10 <= N * 22,
        "{reads} reads ({blocked} EAGAIN) for {N} h2 requests: a socket is read when the \
         poller has not said it is readable"
    );
    drop(c);
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}

/// Streams that wait their turn behind one at the server cost nothing while they wait:
/// the connection's task runs when the server answers, not in a loop until it does.
/// Before T186 a connection with a stream queued requeued itself on every pass while
/// another was at the server, a busy loop as long as the server took (the CPU per
/// request then grew with the server's latency, and with the machine's load).
#[test]
fn queued_h2_streams_do_not_spin_while_one_is_at_the_server() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut engine, fe, running, be) = setup_after(Duration::from_millis(20));
    let mut c = Client::connect(&mut engine, fe);
    c.get(&mut engine);
    const STREAMS: u32 = 10;
    let first = c.next;
    let mut batch = Vec::new();
    for i in 0..STREAMS {
        batch.extend(request(first + 2 * i));
    }
    c.sock.write_all(&batch).expect("requests");
    let mut done = 0;
    let mut passes = 0u32;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 4096];
    while done < STREAMS {
        assert!(Instant::now() < deadline, "{done} of {STREAMS} responses came");
        let _ = engine.run_once();
        passes += 1;
        if let Ok(n) = c.sock.read(&mut buf) {
            assert!(n > 0, "the proxy closed the connection");
            c.rx.extend_from_slice(&buf[..n]);
        }
        while c.rx.len() >= 9 {
            let len = (usize::from(c.rx[0]) << 16) | (usize::from(c.rx[1]) << 8) | usize::from(c.rx[2]);
            if c.rx.len() < 9 + len {
                break;
            }
            let (kind, flags) = (c.rx[3], c.rx[4]);
            assert!(kind != 0x3 && kind != 0x7, "RST_STREAM or GOAWAY: {:?}", &c.rx[..9 + len]);
            c.rx.drain(..9 + len);
            done += u32::from((kind == 0x0 || kind == 0x1) && flags & 1 != 0);
        }
    }
    println!("{STREAMS} streams queued behind a 20 ms server: {passes} engine passes");
    // A handful of passes a stream (its request out, the response in); a loop while the
    // server takes 20 ms is thousands.
    assert!(
        passes <= STREAMS * 20,
        "{passes} engine passes for {STREAMS} streams: the connection spins while a stream is at the server"
    );
    drop(c);
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}

/// Reads frames off a blocking stream until the END_STREAM of `id`.
fn blocking_response(s: &mut impl Read, rx: &mut Vec<u8>, id: u32) {
    let mut buf = [0u8; 4096];
    loop {
        while rx.len() >= 9 {
            let len = (usize::from(rx[0]) << 16) | (usize::from(rx[1]) << 8) | usize::from(rx[2]);
            if rx.len() < 9 + len {
                break;
            }
            let (kind, flags) = (rx[3], rx[4]);
            let stream = u32::from_be_bytes([rx[5], rx[6], rx[7], rx[8]]) & 0x7fff_ffff;
            assert!(kind != 0x3 && kind != 0x7, "RST_STREAM or GOAWAY: {:?}", &rx[..9 + len]);
            rx.drain(..9 + len);
            if stream == id && (kind == 0x0 || kind == 0x1) && flags & 1 != 0 {
                return;
            }
        }
        let n = s.read(&mut buf).expect("read");
        assert!(n > 0, "the proxy closed the connection");
        rx.extend_from_slice(&buf[..n]);
    }
}

/// Over TLS, the client socket is read when the poller says so, as in cleartext: a read
/// that leaves the socket drained (short, or `EAGAIN`) and rustls with no plaintext left
/// over is the last until the next readiness event. Before T186 the TLS side read until
/// `EAGAIN` on every pass, ~9 reads a request where `HAProxy` makes ~3 (`strace -c`,
/// `h2load -m 10`).
#[test]
fn an_h2_request_over_tls_reads_each_socket_once() {
    use rustls::pki_types::{CertificateDer, ServerName};
    use std::sync::mpsc;

    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    params.subject_alt_names.push(rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])));
    let key = rcgen::KeyPair::generate().expect("key");
    let cert = params.self_signed(&key).expect("cert");
    let mut pem = tempfile::NamedTempFile::new().expect("tmp");
    pem.write_all(format!("{}{}", cert.pem(), key.serialize_pem()).as_bytes()).expect("pem");
    let der: CertificateDer<'static> = cert.der().clone();

    let srv = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let srv_addr = srv.local_addr().expect("addr");
    let fe = common::reserve_addr();
    let running = Arc::new(AtomicBool::new(true));
    let be = backend(srv, Arc::clone(&running));
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 5s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe} ssl crt {} alpn h2\n  default_backend be\n\
         backend be\n  server s1 {srv_addr}\n",
        pem.path().display()
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");

    const N: u32 = 200;
    let (to_main, from_client) = mpsc::channel::<&str>();
    let (to_client, from_main) = mpsc::channel::<()>();
    let client = thread::spawn(move || {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).expect("root");
        let mut ccfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        ccfg.alpn_protocols = vec![b"h2".to_vec()];
        let conn = rustls::ClientConnection::new(Arc::new(ccfg), ServerName::try_from("localhost").expect("name")).expect("conn");
        let tcp = TcpStream::connect(fe).expect("connect");
        tcp.set_nodelay(true).expect("nodelay");
        tcp.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        let mut s = rustls::StreamOwned::new(conn, tcp);
        let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        hello.extend(frame(0x4, 0, 0, &[]));
        s.write_all(&hello).expect("preface");
        let mut rx = Vec::new();
        let mut id = 1;
        for i in 0..5 + N {
            if i == 5 {
                to_main.send("warm").expect("send");
                from_main.recv().expect("go");
            }
            s.write_all(&request(id)).expect("request");
            blocking_response(&mut s, &mut rx, id);
            id += 2;
        }
        to_main.send("done").expect("send");
    });

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut start = None;
    let mut end = None;
    while end.is_none() {
        assert!(Instant::now() < deadline, "the TLS client did not finish");
        let _ = engine.run_once();
        match from_client.try_recv() {
            Ok("warm") => {
                start = Some(read_counters());
                to_client.send(()).expect("go");
            }
            Ok(_) => end = Some(read_counters()),
            Err(_) => {}
        }
    }
    client.join().expect("client");
    let ((r0, b0), (r1, b1)) = (start.expect("warm"), end.expect("done"));
    let (reads, blocked) = (r1 - r0, b1 - b0);
    println!("{N} h2 requests over TLS: {reads} reads ({blocked} EAGAIN)");
    // A request's read and the response's read, and slack for a TLS record that arrives
    // in two segments or a readiness event with nothing left to read.
    assert!(
        u64::from(N) * 3 >= reads && blocked * 5 <= u64::from(N),
        "{reads} reads ({blocked} EAGAIN) for {N} h2 requests over TLS: a socket is read \
         when the poller has not said it is readable"
    );
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}

/// E1 (`docs/design/quic-transport-2026-11-01.md` section 3): an h2 request head is decoded
/// once. The mux keeps the decoded fields and the bridge writes the HTX blocks from them;
/// no HTTP/1.1 text is written and parsed again in between (`H1Parser::parse` on the
/// request side, counted in debug builds).
#[test]
fn an_h2_request_head_is_parsed_once() {
    const N: u64 = 20;
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut engine, fe, running, be) = setup();
    let mut c = Client::connect(&mut engine, fe);
    c.get(&mut engine);
    let p0 = ibex_proto::h1::request_parses();
    for _ in 0..N {
        c.get(&mut engine);
    }
    let parses = ibex_proto::h1::request_parses() - p0;
    println!("{N} h2 requests: {parses} HTTP/1 request-head parses");
    if cfg!(debug_assertions) {
        assert_eq!(parses, 0, "{N} h2 requests parsed {parses} request heads as HTTP/1 text");
    }
    drop(c);
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}

/// E2 (`docs/design/quic-transport-2026-11-01.md` section 3): a response head is walked once.
/// `check_response_head` indexes it, and what the engine reads of it after (the websocket
/// check, the head's facts, the names it lowers, the `Connection` it writes) and the HEADERS
/// the client gets are read from that index. Before E2 each of them walked the head again:
/// six passes for an h2 client (`count_head_scan`, debug builds).
#[test]
fn a_response_head_is_scanned_once() {
    const N: u64 = 20;
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut engine, fe, running, be) = setup();
    let mut c = Client::connect(&mut engine, fe);
    c.get(&mut engine);
    let s0 = ibex_proto::response_head::head_scans();
    for _ in 0..N {
        c.get(&mut engine);
    }
    let scans = ibex_proto::response_head::head_scans() - s0;
    println!("{N} h2 responses: {scans} passes over their heads");
    if cfg!(debug_assertions) {
        assert_eq!(scans, N, "{N} h2 responses walked their heads {scans} times");
    }
    drop(c);
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}
