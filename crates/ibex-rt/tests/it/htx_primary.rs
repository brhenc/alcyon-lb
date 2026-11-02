// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! X2 (`docs/design/htx-engine-2026-11-01.md` §3): the request head is HTX-primary. The rules
//! edit the HTX and nothing else; the head goes to the server as the bytes that arrived when
//! nothing edited it, and is written out of its HTX once, at the server send, when something
//! did. Counted on the engine's thread ([`ibex_sample::work::Op::ReqRebuild`]: the head written
//! out of its HTX into the request buffer).

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::engine::Engine;
use ibex_sample::work::Op;

/// `tools/measure/scenarios/rules.body`'s request rules.
const RULES: &str = "  acl api path_reg ^/(api|v[0-9]+)/\n  acl hosty hdr(host) -m sub local\n  \
    http-request set-header X-Forwarded-Proto http\n  http-request del-header X-Junk\n  \
    http-request add-header X-Id %[rand]\n  http-request set-var(txn.p) path\n  \
    http-request deny if api !hosty\n";

const RSP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// A keep-alive server answering each whole request head; the heads it saw, in order.
fn backend(listener: TcpListener, running: Arc<AtomicBool>, seen: Arc<Mutex<Vec<Vec<u8>>>>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking");
        let mut conns: Vec<(TcpStream, Vec<u8>)> = Vec::new();
        let mut buf = vec![0u8; 65536];
        while running.load(Ordering::Relaxed) {
            if let Ok((s, _)) = listener.accept() {
                s.set_nonblocking(true).expect("nonblocking");
                conns.push((s, Vec::new()));
            }
            conns.retain_mut(|(s, acc)| match s.read(&mut buf) {
                Ok(0) => false,
                Ok(n) => {
                    acc.extend_from_slice(&buf[..n]);
                    while let Some(at) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head: Vec<u8> = acc.drain(..at + 4).collect();
                        seen.lock().expect("seen").push(head);
                        let _ = s.write_all(RSP);
                    }
                    true
                }
                Err(e) => e.kind() == std::io::ErrorKind::WouldBlock,
            });
            thread::sleep(Duration::from_micros(200));
        }
    })
}

/// The proxy in this process, its frontend's `rules`, and a backend that records heads.
struct Rig {
    engine: Engine,
    fe: std::net::SocketAddr,
    running: Arc<AtomicBool>,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
    be: Option<thread::JoinHandle<()>>,
}

impl Rig {
    fn new(global: &str, rules: &str) -> Self {
        let srv = TcpListener::bind("127.0.0.1:0").expect("bind");
        let srv_addr = srv.local_addr().expect("addr");
        let fe = common::reserve_addr();
        let running = Arc::new(AtomicBool::new(true));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let be = backend(srv, Arc::clone(&running), Arc::clone(&seen));
        let cfg = format!(
            "global\n{global}defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
             frontend fe\n  bind {fe}\n{rules}  default_backend be\nbackend be\n  server s1 {srv_addr}\n"
        );
        let engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
        Self { engine, fe, running, seen, be: Some(be) }
    }

    fn connect(&self) -> TcpStream {
        let c = TcpStream::connect(self.fe).expect("connect");
        c.set_nonblocking(true).expect("nonblocking");
        c
    }

    /// `req` on `client`, the engine run until a whole response is back; the response.
    fn request(&mut self, client: &mut TcpStream, req: &[u8]) -> String {
        let mut off = 0;
        let start = Instant::now();
        let mut rsp = vec![0u8; 4096];
        let mut len = 0;
        while start.elapsed() < Duration::from_secs(5) && !(off == req.len() && rsp[..len].ends_with(b"\r\n\r\nok")) {
            if off < req.len() {
                if let Ok(n) = client.write(&req[off..]) {
                    off += n;
                }
            }
            let _ = self.engine.run_once();
            if let Ok(n) = client.read(&mut rsp[len..]) {
                len += n;
            }
        }
        String::from_utf8_lossy(&rsp[..len]).into_owned()
    }

    /// The last head the server saw.
    fn last_seen(&self) -> Vec<u8> {
        self.seen.lock().expect("seen").last().cloned().unwrap_or_default()
    }

    /// The `ReqRebuild` count of `rounds` requests on one keep-alive connection, after one to
    /// warm it; the last response.
    fn rebuilds(&mut self, req: &[u8], rounds: u64) -> (u64, String) {
        let mut c = self.connect();
        let mut last = self.request(&mut c, req);
        let before = ibex_sample::work::on_this_thread()[Op::ReqRebuild as usize];
        for _ in 0..rounds {
            last = self.request(&mut c, req);
        }
        (ibex_sample::work::on_this_thread()[Op::ReqRebuild as usize] - before, last)
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        for _ in 0..5 {
            let _ = self.engine.run_once();
        }
        self.running.store(false, Ordering::Relaxed);
        if let Some(be) = self.be.take() {
            let _ = be.join();
        }
    }
}

/// `ab -k`'s request: HTTP/1.0 with `Connection: Keep-Alive`.
const AB_GET: &[u8] = b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: ApacheBench/2.3\r\nAccept: */*\r\nConnection: Keep-Alive\r\n\r\n";

/// The head is written out of its HTX at most once per request: never for a keep-alive GET
/// nothing edits, once for the rules scenario's head however many edits it takes, the
/// `option forwardfor` header after the rules included.
#[test]
fn a_request_head_is_written_at_most_once() {
    const N: u64 = 20;
    let mut plain = Rig::new("", "");
    let (n, rsp) = plain.rebuilds(AB_GET, N);
    assert!(rsp.starts_with("HTTP/1.1 200"), "response: {rsp:?}");
    assert_eq!(n, 0, "head writes for {N} keep-alive GETs nothing edits");

    let mut rules = Rig::new("", &format!("{RULES}  option forwardfor\n"));
    let req = b"GET /api/test HTTP/1.1\r\nHost: localhost\r\nX-Junk: 1\r\n\r\n";
    let (n, rsp) = rules.rebuilds(req, N);
    assert!(rsp.starts_with("HTTP/1.1 200"), "response: {rsp:?}");
    let seen = String::from_utf8_lossy(&rules.last_seen()).to_ascii_lowercase();
    assert!(
        seen.contains("x-forwarded-proto: http\r\n") && seen.contains("x-id: ") && seen.contains("x-forwarded-for: 127.0.0.1\r\n") && !seen.contains("x-junk"),
        "request the server saw: {seen:?}"
    );
    assert_eq!(n, N, "head writes for {N} requests of the rules scenario with forwardfor: one each");
}

/// The HTTP/1 request head is indexed where it is ([`ibex_proto::h1::H1Parser::index_head_in_place`]):
/// its fields are descriptors over the received bytes, not copied into the HTX one by one.
#[test]
fn a_request_head_is_indexed_not_copied() {
    const N: u64 = 10;
    let mut rig = Rig::new("", RULES);
    let mut c = rig.connect();
    let req = b"GET /api/x HTTP/1.1\r\nHost: localhost\r\nX-Junk: 1\r\nAccept: */*\r\n\r\n";
    let _ = rig.request(&mut c, req);
    let (parses, copies) = (ibex_proto::h1::request_parses(), ibex_proto::h1::copied_request_parses());
    for _ in 0..N {
        let rsp = rig.request(&mut c, req);
        assert!(rsp.starts_with("HTTP/1.1 200"), "response: {rsp:?}");
    }
    assert_eq!(ibex_proto::h1::request_parses() - parses, N, "request heads parsed");
    assert_eq!(ibex_proto::h1::copied_request_parses() - copies, 0, "request heads parsed by copying their fields");
    let seen = String::from_utf8_lossy(&rig.last_seen()).to_ascii_lowercase();
    assert!(seen.contains("x-forwarded-proto: http\r\n") && !seen.contains("x-junk"), "request the server saw: {seen:?}");
}

/// D-E, default `off`: a head no rule edited reaches the server as the bytes that arrived,
/// names in the case they came in; `on` lowercases them, as `HAProxy`.
#[test]
fn an_unmodified_head_is_the_bytes_that_arrived() {
    let req = b"GET /a?b=C HTTP/1.1\r\nHost: localhost\r\nX-MiXeD-Case: Some Value\r\nAccept: */*\r\n\r\n";
    let mut off = Rig::new("", "");
    let mut c = off.connect();
    let rsp = off.request(&mut c, req);
    assert!(rsp.starts_with("HTTP/1.1 200"), "response: {rsp:?}");
    assert_eq!(String::from_utf8_lossy(&off.last_seen()), String::from_utf8_lossy(req), "off: the bytes that arrived");

    let mut on = Rig::new("  tune.ibex.h1-lowercase-headers on\n", "");
    let mut c = on.connect();
    let rsp = on.request(&mut c, req);
    assert!(rsp.starts_with("HTTP/1.1 200"), "response: {rsp:?}");
    assert_eq!(
        String::from_utf8_lossy(&on.last_seen()),
        "GET /a?b=C HTTP/1.1\r\nhost: localhost\r\nx-mixed-case: Some Value\r\naccept: */*\r\n\r\n",
        "on: names in lower case"
    );
}

/// A head that leaves little of the buffer, then five 200-byte `set-header`s: the rules'
/// room is `tune.maxrewrite` (1 KiB) and the head still fits what `HAProxy` holds, so the
/// request goes with all five.
#[test]
fn rules_with_a_full_reserve_still_forward() {
    let mut rules = String::new();
    for i in 0..5 {
        rules.push_str(&format!("  http-request set-header X-Big-{i} {}\n", "v".repeat(200)));
    }
    let mut rig = Rig::new("  tune.maxrewrite 1024\n", &rules);
    let mut req = b"GET /big HTTP/1.1\r\nHost: localhost\r\nX-Pad: ".to_vec();
    req.extend(std::iter::repeat_n(b'p', 13_000));
    req.extend_from_slice(b"\r\n\r\n");
    let mut c = rig.connect();
    let rsp = rig.request(&mut c, &req);
    assert!(rsp.starts_with("HTTP/1.1 200"), "response: {rsp:?}");
    let seen = String::from_utf8_lossy(&rig.last_seen()).into_owned();
    for i in 0..5 {
        assert!(seen.contains(&format!("X-Big-{i}: {}\r\n", "v".repeat(200))), "header {i} missing from the request the server saw ({} bytes)", seen.len());
    }
    assert!(seen.contains(&"p".repeat(13_000)), "the client's header went");
}

/// X7: a log line's `%U` does not serialise the head. A head nothing edits is never written
/// out of its HTX (the size is the received one's); a head the parser changed (bare `LF` line
/// ends) is written once, for the buffer, and `%U` is read from that write, not from two more.
#[test]
fn a_log_line_does_not_serialise_the_head() {
    let collector = std::net::UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_nonblocking(true).expect("nonblocking");
    let global = format!("  log {} local0\n", collector.local_addr().expect("addr"));
    let mut rig = Rig::new(&global, "  log global\n  log-format \"U=%U\"\n");
    let mut c = rig.connect();
    let mut plain = b"GET /x HTTP/1.1\r\nHost: localhost\r\n".to_vec();
    for i in 0..40 {
        plain.extend_from_slice(format!("X-Pad-{i:02}: {}\r\n", "p".repeat(20)).as_bytes());
    }
    plain.extend_from_slice(b"\r\n");
    assert!(plain.len() > 1024, "a head over 1 KiB");
    let lf: Vec<u8> = plain.iter().copied().filter(|&b| b != b'\r').collect();
    let mut logged = Vec::new();
    let mut writes = Vec::new();
    for req in [&plain, &lf] {
        let _ = rig.request(&mut c, req);
        let w0 = ibex_proto::h1_encode::head_writes();
        let rsp = rig.request(&mut c, req);
        assert!(rsp.starts_with("HTTP/1.1 200"), "response: {rsp:?}");
        writes.push(ibex_proto::h1_encode::head_writes() - w0);
        let mut line = String::new();
        let mut buf = [0u8; 512];
        for _ in 0..20 {
            let _ = rig.engine.run_once();
            while let Ok(n) = collector.recv(&mut buf) {
                line = String::from_utf8_lossy(&buf[..n]).into_owned();
            }
        }
        logged.push(line.trim_end().rsplit("U=").next().unwrap_or("").to_string());
    }
    assert_eq!(logged[0], logged[1], "%U of the same head with LF ends: {logged:?}");
    assert!(logged[0].parse::<u64>().is_ok_and(|n| n > 1000), "logged: {logged:?}");
    assert_eq!(writes[0], 0, "head writes for a head nothing edits");
    assert_eq!(writes[1], 1, "head writes for a head the parser changed: one, for the buffer");
}

/// X8: a request head the engine holds as blocks reaches an h2 server as blocks: the codec reads
/// no HTTP/1.1 text for it (`ibex_proto::h2_srv::text_heads`), and a head nothing edited is not
/// written out of its HTX either (`head_writes`). Debug builds count; release builds count 0.
#[test]
fn an_h2_server_request_is_not_text() {
    use crate::server_h2::{scripted, Script};
    let srv = scripted(Script::Ok { goaway_after: 0 });
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe}\n  http-request set-header X-Edited %[rand] if {{ path /edited }}\n  default_backend be\n\
         backend be\n  server s1 {} proto h2\n",
        srv.addr
    );
    let engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let mut rig = Rig { engine, fe, running: Arc::new(AtomicBool::new(true)), seen: Arc::new(Mutex::new(Vec::new())), be: None };
    let mut c = rig.connect();
    let plain = b"GET /plain HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let edited = b"GET /edited HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let post = b"POST /post HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello";
    let chunked = b"POST /chunked HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let _ = rig.request(&mut c, plain);
    // X3b-2: an edited head is written at the send, for the server it goes to: as blocks to
    // this h2 server, so not as HTTP/1.1 text (it was, before the server was picked).
    for (name, req, writes) in [("plain", &plain[..], 0), ("edited", &edited[..], 0), ("content-length", &post[..], 0), ("chunked", &chunked[..], 0)] {
        let (t0, w0) = (ibex_proto::h2_srv::text_heads(), ibex_proto::h1_encode::head_writes());
        let rsp = rig.request(&mut c, req);
        assert!(rsp.starts_with("HTTP/1.1 200"), "{name}: {rsp:?}");
        let (texts, wrote) = (ibex_proto::h2_srv::text_heads() - t0, ibex_proto::h1_encode::head_writes() - w0);
        assert_eq!(texts, 0, "{name}: heads the h2 codec read as text");
        assert_eq!(wrote, writes, "{name}: heads written out of the HTX");
    }
    rig.running.store(false, Ordering::Relaxed);
}

/// T618: the bytes `%B` leaves out of an h2 server's response (the reason phrase, the
/// `transfer-encoding` the codec adds) are read from the codec's index of the head, not scanned
/// out of its text; a head too long for the index (34 fields) is scanned. Debug builds count.
#[test]
fn an_h2_server_response_is_not_scanned_for_its_htx_size() {
    use crate::server_h2::{scripted, Script};
    for (script, scans) in [(Script::Ok { goaway_after: 0 }, 0), (Script::ManyFields, 1)] {
        let srv = scripted(script);
        let fe = common::reserve_addr();
        let cfg = format!(
            "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
             frontend fe\n  bind {fe}\n  default_backend be\nbackend be\n  server s1 {} proto h2\n",
            srv.addr
        );
        let engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
        let mut rig = Rig { engine, fe, running: Arc::new(AtomicBool::new(true)), seen: Arc::new(Mutex::new(Vec::new())), be: None };
        let mut c = rig.connect();
        let _ = rig.request(&mut c, b"GET /plain HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let s0 = ibex_rt::engine::h2_overcount_scans();
        let rsp = rig.request(&mut c, b"GET /plain HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(rsp.starts_with("HTTP/1.1 200"), "{rsp:?}");
        let n = ibex_rt::engine::h2_overcount_scans() - s0;
        if cfg!(debug_assertions) {
            assert_eq!(n, scans, "scans of the response head's text per request");
        }
        rig.running.store(false, Ordering::Relaxed);
    }
}

/// X3b-2: an h2 server's response head reaches the client with no HTTP/1 parse of it
/// (`ibex_proto::response_head::response_parses`): the codec indexes the head it writes, and
/// the engine reads that index. A rules-edited request and a body changes nothing of it.
/// Debug builds count; release builds count 0.
#[test]
fn an_h2_server_response_is_not_parsed_again() {
    use crate::server_h2::{scripted, Script};
    {
        let srv = scripted(Script::Ok { goaway_after: 0 });
        let fe = common::reserve_addr();
        let cfg = format!(
            "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
             frontend fe\n  bind {fe}\n  http-request set-header X-Edited %[rand] if {{ path /edited }}\n  default_backend be\n\
             backend be\n  http-response set-header X-Rsp 1 if {{ path /rules }}\n  server s1 {} proto h2\n",
            srv.addr
        );
        let engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
        let mut rig = Rig { engine, fe, running: Arc::new(AtomicBool::new(true)), seen: Arc::new(Mutex::new(Vec::new())), be: None };
        let mut c = rig.connect();
        let _ = rig.request(&mut c, b"GET /plain HTTP/1.1\r\nHost: localhost\r\n\r\n");
        for path in ["/plain", "/edited", "/rules"] {
            let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
            let p0 = ibex_proto::response_head::response_parses();
            let rsp = rig.request(&mut c, req.as_bytes());
            assert!(rsp.starts_with("HTTP/1.1 200"), "{path}: {rsp:?}");
            assert_eq!(rsp.to_ascii_lowercase().contains("x-rsp: 1"), path == "/rules", "{path}: {rsp:?}");
            assert_eq!(ibex_proto::response_head::response_parses() - p0, 0, "{path}: h1 parses of the h2 server's response head");
        }
        rig.running.store(false, Ordering::Relaxed);
    }
}

/// X3b-2: an edited head held back for the session's h2 server connection is written at the
/// send when the text goes after all: to an h1 server the round robin picks next (its names in
/// lower case under `tune.ibex.h1-lowercase-headers on`), and to the h2 server when the request
/// is kept for `retry-on` (the copy is of the text). The edit reaches both servers.
#[test]
fn a_head_held_back_for_an_h2_server_is_written_when_the_text_goes() {
    use crate::server_h2::{scripted, Script};
    let h2 = scripted(Script::Ok { goaway_after: 0 });
    // Both settings: the names are lowered when the head is written only under `on`.
    for (lowercase, retry, with_h1) in [("off", "", true), ("on", "", true), ("on", "  retry-on 503\n", false)] {
        // Each round has its own h1 server and its own record of what it saw.
        let h1 = TcpListener::bind("127.0.0.1:0").expect("bind");
        let h1_addr = h1.local_addr().expect("addr");
        let running = Arc::new(AtomicBool::new(true));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let be = backend(h1, Arc::clone(&running), Arc::clone(&seen));
        let servers = if with_h1 { format!("  server a {} proto h2\n  server b {h1_addr}\n", h2.addr) } else { format!("  server a {} proto h2\n", h2.addr) };
        let fe = common::reserve_addr();
        let cfg = format!(
            "global\n  tune.ibex.h1-lowercase-headers {lowercase}\ndefaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
             frontend fe\n  bind {fe}\n  http-request set-header X-Edited yes\n  default_backend be\n\
             backend be\n  balance roundrobin\n{retry}{servers}"
        );
        let engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
        let mut rig = Rig { engine, fe, running: Arc::clone(&running), seen: Arc::clone(&seen), be: None };
        let mut c = rig.connect();
        let req = b"GET /x HTTP/1.1\r\nHost: localhost\r\nX-Case: 1\r\n\r\n";
        for i in 0..4 {
            let w0 = ibex_proto::h1_encode::head_writes();
            let rsp = rig.request(&mut c, req);
            assert!(rsp.starts_with("HTTP/1.1 200"), "{lowercase} {retry:?} {i}: {rsp:?}");
            // Once per request: before the pick on the first (no h2 connection yet), at the send
            // for the h1 server or the copy kept for a retry, never for blocks alone.
            let wrote = ibex_proto::h1_encode::head_writes() - w0;
            assert!(wrote <= 1, "{retry:?} {i}: {wrote} head writes");
            if retry.is_empty() && i % 2 == 1 {
                let head = String::from_utf8_lossy(&rig.last_seen()).into_owned();
                assert!(head.to_ascii_lowercase().contains("x-edited: yes\r\n"), "{i}: {head:?}");
                // The client's `X-Case` is lowered only under `on`.
                assert_eq!(head.contains("x-case: 1\r\n"), lowercase == "on", "{lowercase} {i}: {head:?}");
                assert_eq!(head.contains("X-Case: 1\r\n"), lowercase == "off", "{lowercase} {i}: {head:?}");
            } else if !retry.is_empty() {
                assert_eq!(wrote, 1, "{i}: the head kept for a retry is text");
            }
        }
        running.store(false, Ordering::Relaxed);
        let _ = be.join();
    }
}
