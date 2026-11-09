// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T96, live connection migration: the acceptance harness.
//!
//! A reload normally leaves established connections in the old process, which drains them
//! and exits; a connection still open when it exits is cut. T96 hands established
//! connections -- client side, server side and protocol state -- to the new process, so
//! the client keeps one TCP connection across any number of reloads. The specification is
//! `patches/T96-live-connection-migration.md`; its "What works means" items are cited by
//! number on every test here.
//!
//! How every test proves a connection migrated, rather than lingered:
//!
//! * The old process is waited for until it has **exited** before anything is asserted
//!   about the connection (`procs::wait_gone`). Every configuration sets
//!   `hard-stop-after 2s`, so a connection the old process kept is cut within two
//!   seconds of the reload instead of draining forever.
//! * The new process then shows it holds the connection: `CurrConns` in `show info`, and
//!   for a connection with a transaction or a TCP stream in progress, `show sess` listing
//!   the client's own address, as `HAProxy` prints it.
//! * HTTP requests made after the reload carry the new configuration's generation number
//!   (`http-request set-header X-Gen <gen>`, echoed by the backend): only the new process
//!   has that configuration.
//! * Streams carry a position-dependent byte pattern, checked byte by byte in both
//!   directions, while data is flowing through the reload; the backend reports which TCP
//!   connection carried them.
//!
//! Every migration test has a control (spec item 11): the same scenario reloaded the way
//! Alcyon reloads today, without `--migrate-conns`, which must observe the connection END
//! when the old process exits. The controls run today; the migration tests are ignored
//! until T96 is implemented, and the implementer removes each `#[ignore]` as it passes.
//!
//! The operator interface (the command-line flag, `-x`/`-sf`, `-W` with `SIGUSR2`) is in
//! `live_migration/iface.rs` and nowhere else.
//!
//! Environment:
//! * `ALCYON_BIN` -- run against another alcyon binary.
//! * `ALCYON_T96_FORCE_CONTROL=1` -- migration tests reload WITHOUT the flag, to show they
//!   fail by losing the connection on a build that rejects the flag.
//! * `ALCYON_T96_NO_SHOW_SESS=1` -- skip the `show sess` check, for a build without it.

use crate::common;
#[path = "../live_migration/mod.rs"]
mod lm;

use lm::backend::{End, Event, HttpBackend, TcpBackend, TcpClient};
use lm::h1::{gen, Failure, Resp, H1};
use lm::h2::H2;
use lm::iface::{self, Reload, MIGRATE_FLAG};
use lm::pattern::{self, Checker};
use lm::procs::{self, Alcyon, TempPath};
use lm::Cfg;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Bound on any single request/response exchange.
const T: Duration = Duration::from_secs(10);
/// How long a control waits, after the old process exited, to see the connection end.
const CONTROL_END: Duration = Duration::from_secs(5);
/// How far a stream must move after the old process has exited before the test believes
/// the new process is carrying it. Several hundred milliseconds of paced data: more than
/// any buffer between the backend and the client could hold back and release later.
const MOVED_AFTER_EXIT: u64 = 256 * 1024;

// ------------------------------------------------------------------------------------
// Shared steps
// ------------------------------------------------------------------------------------

/// The pieces every scenario has: a stats socket, a frontend address, generation files.
struct Rig {
    sock: TempPath,
    fe: SocketAddr,
    cfg: Cfg,
    files: Vec<TempPath>,
}

impl Rig {
    fn new(be: SocketAddr, tweak: impl FnOnce(&mut Cfg)) -> Self {
        let sock = TempPath::new("s", "sock");
        let fe = common::reserve_addr();
        let mut cfg = Cfg::http(sock.path(), fe, be);
        tweak(&mut cfg);
        Self { sock, fe, cfg, files: Vec::new() }
    }

    fn sock(&self) -> &Path {
        self.sock.path()
    }

    /// Writes generation `gen` and returns its path.
    fn gen(&mut self, gen: u32) -> std::path::PathBuf {
        let f = self.cfg.gen(gen).file();
        let p = f.path().to_path_buf();
        self.files.push(f);
        p
    }

    /// Starts generation 1.
    fn start(&mut self) -> Alcyon {
        let p = self.gen(1);
        procs::start(&p, &[], self.sock(), self.fe)
    }

    /// Reloads `old` onto generation `gen` and waits for `old` to exit.
    fn reload(&mut self, old: &mut Alcyon, gen: u32, how: Reload) -> Alcyon {
        let p = self.gen(gen);
        let new = procs::reload(old, &p, self.sock(), how);
        procs::wait_gone(old);
        new
    }
}

fn control_broken(what: &str, saw: &str) -> ! {
    panic!(
        "CONTROL BROKEN ({what}): reloaded without {MIGRATE_FLAG}, the connection must end when \
         the old process exits, and the harness must see it end. It saw: {saw}. Until this \
         passes, a migration test passing here proves nothing."
    )
}

/// A control's verdict on an idle HTTP/1 connection: a request after the old process
/// exited must find the connection gone.
fn control_h1_ended(c: &mut H1, what: &str) {
    match c.get("/echo", "", CONTROL_END) {
        Err(Failure::Ended(_)) => {}
        Ok(r) => control_broken(what, &format!("a response, X-Seen-Gen {:?}", gen(&r))),
        Err(e) => control_broken(what, &format!("{e:?}")),
    }
}

/// An echo response to `GET path` with the request processed by generation `want_gen`.
fn expect_echo(r: &Result<Resp, Failure>, want_gen: &str, what: &str) {
    let r = r.as_ref().unwrap_or_else(|e| panic!("{what}: the request failed: {e:?}"));
    assert_eq!(r.status, 200, "{what}: status; response {r:?}");
    assert_eq!(
        gen(r),
        Some(want_gen),
        "{what}: the request must have been processed by generation {want_gen}'s rules (the \
         {} process); response headers {:?}",
        if want_gen == "1" { "old" } else { "new" },
        r.headers
    );
    let body = String::from_utf8_lossy(&r.body);
    assert!(
        body.contains(&format!("\r\nX-Gen: {want_gen}\r\n")) || body.contains(&format!("\r\nx-gen: {want_gen}\r\n")),
        "{what}: the echoed request head must carry X-Gen {want_gen}: {body:?}"
    );
}

/// The steady counter of bytes a reader thread has checked.
#[derive(Clone, Default)]
struct Progress(Arc<AtomicU64>);

impl Progress {
    fn get(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
    /// Waits until at least `n`; false if `stop` says the reader finished first, or on
    /// timeout.
    fn wait_at_least(&self, n: u64, within: Duration, stop: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if self.get() >= n {
                return true;
            }
            if stop() {
                return self.get() >= n;
            }
            thread::sleep(Duration::from_millis(5));
        }
        false
    }
}

/// An HTTP/1 response body being read, and checked against a pattern, in a thread.
struct BodyReader {
    progress: Progress,
    handle: thread::JoinHandle<(H1, Result<u64, Failure>, Checker)>,
}

impl BodyReader {
    fn spawn(mut c: H1, headers: Vec<(String, String)>, seed: u64) -> Self {
        let progress = Progress::default();
        let p = progress.clone();
        let handle = thread::spawn(move || {
            let mut chk = Checker::new(seed);
            let r = c.read_body(&headers, Duration::from_secs(90), &mut |b| {
                chk.feed(b);
                p.0.store(chk.pos(), Ordering::SeqCst);
            });
            (c, r, chk)
        });
        Self { progress, handle }
    }

    fn done(&self) -> bool {
        self.handle.is_finished()
    }

    fn join(self) -> (H1, Result<u64, Failure>, Checker) {
        self.handle.join().expect("body reader panicked")
    }
}

/// Starts `GET /stream...` or `/chunked...` on `c` and returns its reader, once the head
/// has arrived and `first` body bytes have.
fn start_stream(mut c: H1, path: &str, seed: u64, first: u64) -> BodyReader {
    c.send(format!("GET {path} HTTP/1.1\r\nHost: t96\r\n\r\n").as_bytes()).expect("send stream request");
    let (status, headers) = c.read_head(T).expect("stream response head");
    assert_eq!(status, 200, "stream response: {headers:?}");
    let r = BodyReader::spawn(c, headers, seed);
    let ok = r.progress.wait_at_least(first, T, || r.done());
    assert!(ok, "setup: the stream did not start flowing ({} bytes)", r.progress.get());
    r
}

/// A control's verdict on a body being read: it must end, not complete and not stall.
fn control_reader_ended(r: BodyReader, what: &str) {
    let deadline = Instant::now() + CONTROL_END;
    while !r.done() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    if !r.done() {
        control_broken(what, &format!("the body still open after {CONTROL_END:?}, {} bytes read", r.progress.get()));
    }
    let (_, res, chk) = r.join();
    match res {
        Err(Failure::Ended(_)) => {}
        other => control_broken(what, &format!("{other:?} after {} bytes", chk.pos())),
    }
}

/// Opens `n` keep-alive connections and makes one request on each (generation 1).
fn idle_connections(fe: SocketAddr, n: usize) -> Vec<H1> {
    (0..n)
        .map(|i| {
            let mut c = H1::connect(fe);
            expect_echo(&c.get("/echo", "", T), "1", &format!("setup, connection {i}"));
            c
        })
        .collect()
}

// ------------------------------------------------------------------------------------
// Harness self-checks (always run)
// ------------------------------------------------------------------------------------

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
    v.iter().map(|(a, b)| ((*a).to_string(), (*b).to_string())).collect()
}

/// The harness's own HPACK decoder against RFC 7541 Appendix C.4 (requests, Huffman) and
/// C.6 (responses, Huffman, evictions in a 256-byte table). The H2 tests rely on it to
/// tell a correct Alcyon from a broken one, so it is checked against the RFC, not Alcyon.
#[test]
fn harness_hpack_decoder_matches_rfc7541_examples() {
    use lm::hpack::Decoder;
    let mut d = Decoder::new(4096);
    assert_eq!(
        d.decode(&unhex("828684418cf1e3c2e5f23a6ba0ab90f4ff")).expect("C.4.1"),
        pairs(&[(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com")])
    );
    assert_eq!(
        d.decode(&unhex("828684be5886a8eb10649cbf")).expect("C.4.2"),
        pairs(&[(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com"), ("cache-control", "no-cache")])
    );
    assert_eq!(
        d.decode(&unhex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf")).expect("C.4.3"),
        pairs(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "www.example.com"),
            ("custom-key", "custom-value"),
        ])
    );
    assert_eq!(d.table.entries.len(), 3, "C.4.3 leaves three entries");

    let mut d = Decoder::new(4096);
    d.table.resize(256);
    assert_eq!(
        d.decode(&unhex(
            "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3"
        ))
        .expect("C.6.1"),
        pairs(&[
            (":status", "302"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("location", "https://www.example.com"),
        ])
    );
    assert_eq!(
        d.decode(&unhex("4883640effc1c0bf")).expect("C.6.2"),
        pairs(&[
            (":status", "307"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("location", "https://www.example.com"),
        ])
    );
    assert_eq!(
        d.decode(&unhex(
            "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007"
        ))
        .expect("C.6.3"),
        pairs(&[
            (":status", "200"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
            ("location", "https://www.example.com"),
            ("content-encoding", "gzip"),
            ("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
        ])
    );
    assert_eq!(d.table.entries.len(), 3, "C.6.3 leaves three entries after evictions");

    // An out-of-step table must be an error, not a wrong value.
    let mut d = Decoder::new(4096);
    assert!(d.decode(&[0x80 | 0x3e]).is_err(), "index 62 of an empty dynamic table must fail");
    // The client encoder's table is the one the peer's decoder must be keeping.
    let mut e = lm::hpack::Encoder::new(4096);
    let mut block = e.literal_indexed("x-ta", "one");
    block.extend(e.literal_indexed("x-tb", "two"));
    block.extend(e.indexed("x-ta", "one"));
    assert_eq!(d.decode(&block).expect("roundtrip"), pairs(&[("x-ta", "one"), ("x-tb", "two"), ("x-ta", "one")]));
    assert_eq!(lm::hpack::encode_int(1337, 5, 0), vec![31, 154, 10], "RFC 7541 C.1.2");
}

/// The byte pattern catches a lost, a duplicated and a reordered byte at the place it
/// happened.
#[test]
fn harness_pattern_detects_loss_duplication_and_reordering() {
    let good = pattern::bytes(7, 100_000);
    let mut c = Checker::new(7);
    assert!(c.feed(&good[..33_333]) && c.feed(&good[33_333..]), "{:?}", c.error());
    let mut lost = good.clone();
    lost.remove(50_000);
    let mut dup = good.clone();
    dup.insert(50_000, good[50_000]);
    let mut swapped = good.clone();
    swapped.swap(50_000, 50_008);
    for (name, v) in [("lost", lost), ("duplicated", dup), ("reordered", swapped)] {
        let mut c = Checker::new(7);
        c.feed(&v);
        let at = c.mismatch.map(|m| m.0);
        assert!(at.is_some_and(|a| (50_000..=50_008).contains(&a)), "{name}: first mismatch at {at:?}");
    }
    assert_ne!(pattern::bytes(7, 64), pattern::bytes(8, 64), "different seeds must differ");
}

// ------------------------------------------------------------------------------------
// Items 1, 2, 4: HTTP/1 idle keep-alive
// ------------------------------------------------------------------------------------

fn h1_idle_keepalive(how: Reload) {
    let be = HttpBackend::start();
    let mut rig = Rig::new(be.addr, |_| {});
    let mut old = rig.start();
    let mut c = H1::connect(rig.fe);
    expect_echo(&c.get("/echo", "", T), "1", "before the reload");

    let _new = rig.reload(&mut old, 2, how);
    if how == Reload::Control {
        return control_h1_ended(&mut c, "idle keep-alive");
    }
    procs::assert_holds_at_least(rig.sock(), 1, "idle keep-alive");
    expect_echo(&c.get("/echo", "", T), "2", "the first request after the old process exited");
    expect_echo(&c.get("/echo", "", T), "2", "a second request after the reload");
}

/// Items 1, 2, 4 (idle keep-alive). An HTTP/1.1 connection between requests is still the
/// same connection after the old process has exited, and the new process answers on it.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_h1_idle_keepalive() {
    h1_idle_keepalive(Reload::Migrate);
}

/// Item 11: the control for `migrate_h1_idle_keepalive`.
#[test]
fn control_h1_idle_keepalive_ends_with_the_old_process() {
    h1_idle_keepalive(Reload::Control);
}

// ------------------------------------------------------------------------------------
// Item 4: request head half sent
// ------------------------------------------------------------------------------------

fn h1_request_head_half_sent(how: Reload) {
    let be = HttpBackend::start();
    let mut rig = Rig::new(be.addr, |_| {});
    let mut old = rig.start();
    let mut c = H1::connect(rig.fe);
    expect_echo(&c.get("/echo", "", T), "1", "before the reload");

    let req = "GET /echo?half HTTP/1.1\r\nHost: t96\r\nX-Ta: first-half|second-half\r\nX-Tb: after\r\n\r\n";
    let cut = req.find('|').expect("cut point") + 1;
    c.send(&req.as_bytes()[..cut]).expect("send the first half of the head");
    // The half head must be in the old process (its buffer or its socket's receive queue;
    // the migration must carry both) before the reload starts. On loopback the bytes are
    // queued to the receiving socket by the time `write` returns; this pause only lets the
    // old process read them, so the state migrated is "parser mid-head", not "bytes
    // queued". There is no observable for "has parsed half a head" to wait on.
    thread::sleep(Duration::from_millis(150));

    let _new = rig.reload(&mut old, 2, how);
    if how == Reload::Control {
        // The rest of the head goes to a connection that should no longer exist.
        match c.send(&req.as_bytes()[cut..]).and_then(|()| c.response(CONTROL_END)) {
            Err(Failure::Ended(_)) => return,
            other => control_broken("request head half sent", &format!("{other:?}")),
        }
    }
    procs::assert_holds_at_least(rig.sock(), 1, "request head half sent");
    c.send(&req.as_bytes()[cut..]).expect("send the second half of the head");
    let r = c.response(T);
    // The head was completed after the old process had gone, so the new process parsed it
    // and its rules ran on it: generation 2.
    expect_echo(&r, "2", "the request whose head straddled the migration");
    let r = r.expect("checked");
    assert_eq!(
        r.header("X-Echo-x-ta"),
        Some("first-half|second-half"),
        "the header split across the migration must reach the server whole; got {:?}",
        r.headers
    );
    assert_eq!(r.header("X-Echo-x-tb"), Some("after"), "{:?}", r.headers);
    let body = String::from_utf8_lossy(&r.body);
    assert_eq!(body.matches("GET /echo?half HTTP/1.1\r\n").count(), 1, "the request line exactly once: {body:?}");
    expect_echo(&c.get("/echo", "", T), "2", "the next request");
}

/// Item 4 (request head half sent). Half a request head is in the old process when it
/// exits; the client sends the rest afterwards, on the same connection, and gets its
/// answer.
///
/// Note for the implementer: the design draft (4, H1) allows leaving a connection that
/// stays mid-head past a bounded delay with the old process. That process is then gone
/// two seconds later (`hard-stop-after`), so this test, like spec item 4, requires the
/// half head to migrate.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_h1_request_head_half_sent() {
    h1_request_head_half_sent(Reload::Migrate);
}

/// Item 11: the control for `migrate_h1_request_head_half_sent`.
#[test]
fn control_h1_request_head_half_sent_ends_with_the_old_process() {
    h1_request_head_half_sent(Reload::Control);
}

// ------------------------------------------------------------------------------------
// Item 4: request body half sent
// ------------------------------------------------------------------------------------

fn h1_request_body_half_sent(how: Reload) {
    const LEN: usize = 200_000;
    const HALF: usize = 100_000;
    let seed = 0xB0D1;
    let be = HttpBackend::start();
    let mut rig = Rig::new(be.addr, |_| {});
    let mut old = rig.start();
    let mut c = H1::connect(rig.fe);
    let body = pattern::bytes(seed, LEN);
    c.send(format!("POST /upload HTTP/1.1\r\nHost: t96\r\nContent-Length: {LEN}\r\nX-Body-Seed: {seed}\r\n\r\n").as_bytes())
        .expect("send head");
    // The body is sent only once the head has reached the server. Sent together, they
    // trip a defect outside T96: with an `http-request set-header` rule, a head and body
    // arriving in one read have the body corrupted near 16 KB and its last bytes (the
    // header's length) withheld -- HAProxy forwards them intact. Kept apart, this test
    // measures the migration and nothing else.
    be.wait_head("/upload", T);
    c.send(&body[..HALF]).expect("send first half");
    // Wait until the backend holds the whole first half: the proxy is then mid-body with
    // exactly HALF bytes still to forward.
    let got = be.wait_event(T, |e| matches!(e, Event::Body { path, received, .. } if path == "/upload" && *received >= HALF as u64));
    let Some(Event::Body { conn: be_conn, .. }) = got else {
        panic!("setup: the backend never received the first half; it has {} bytes", be.body_received("/upload"))
    };
    let accepted = be.accepted();

    let _new = rig.reload(&mut old, 2, how);
    if how == Reload::Control {
        match c.send(&body[HALF..]).and_then(|()| c.response(CONTROL_END)) {
            Err(Failure::Ended(_)) => return,
            other => control_broken("request body half sent", &format!("{other:?}")),
        }
    }
    procs::assert_show_sess_lists(rig.sock(), c.local, "fe");
    c.send(&body[HALF..]).expect("send second half");
    let r = c.response(T).unwrap_or_else(|e| panic!("the upload's response: {e:?}"));
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(
        r.header("X-Body"),
        Some(format!("{LEN} ok").as_str()),
        "the server must receive the body exactly: {LEN} bytes, every one in place; headers {:?}",
        r.headers
    );
    assert_eq!(
        r.header("X-Conn"),
        Some(be_conn.to_string().as_str()),
        "the second half must arrive on the same server connection as the first"
    );
    assert_eq!(be.accepted(), accepted, "the server saw a new connection during the upload");
    expect_echo(&c.get("/echo", "", T), "2", "the next request");
}

/// Item 4 (request body half sent), item 3. A POST whose body is half forwarded when the
/// old process exits completes on the same client and server connections, every byte in
/// place.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_h1_request_body_half_sent() {
    h1_request_body_half_sent(Reload::Migrate);
}

/// Item 11: the control for `migrate_h1_request_body_half_sent`.
#[test]
fn control_h1_request_body_half_sent_ends_with_the_old_process() {
    h1_request_body_half_sent(Reload::Control);
}

// ------------------------------------------------------------------------------------
// Item 4: waiting on a slow server
// ------------------------------------------------------------------------------------

fn h1_waiting_on_slow_server(how: Reload) {
    let be = HttpBackend::start();
    let mut rig = Rig::new(be.addr, |_| {});
    let mut old = rig.start();
    let mut c = H1::connect(rig.fe);
    c.send(b"GET /hold HTTP/1.1\r\nHost: t96\r\n\r\n").expect("send");
    let (be_conn, _) = be.wait_head("/hold", T);
    let accepted = be.accepted();

    let _new = rig.reload(&mut old, 2, how);
    if how == Reload::Control {
        be.release_holds();
        return match c.response(CONTROL_END) {
            Err(Failure::Ended(_)) => {}
            other => control_broken("waiting on a slow server", &format!("{other:?}")),
        };
    }
    procs::assert_show_sess_lists(rig.sock(), c.local, "fe");
    be.release_holds();
    let r = c.response(T);
    // The request was processed by the old process before the reload; only its response
    // comes after. Generation 1 here proves it was not sent to the server a second time.
    expect_echo(&r, "1", "the response to the request held across the migration");
    let r = r.expect("checked");
    assert_eq!(r.header("X-Conn"), Some(be_conn.to_string().as_str()), "the response must come from the held server connection");
    assert_eq!(be.accepted(), accepted, "no new server connection may be opened for the held request");
    let dup = be.wait_event(Duration::from_millis(200), |e| matches!(e, Event::Head { path, conn, .. } if path == "/hold" && *conn != be_conn));
    assert!(dup.is_none(), "the held request was sent to the server again: {dup:?}");
    expect_echo(&c.get("/echo", "", T), "2", "the next request");
}

/// Item 4 (waiting on a slow server). The request is with the server, unanswered, when
/// the old process exits; the answer reaches the client on the same connection, from the
/// same server connection, and the request is not sent twice.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_h1_waiting_on_a_slow_server() {
    h1_waiting_on_slow_server(Reload::Migrate);
}

/// Item 11: the control for `migrate_h1_waiting_on_a_slow_server`.
#[test]
fn control_h1_waiting_on_a_slow_server_ends_with_the_old_process() {
    h1_waiting_on_slow_server(Reload::Control);
}

// ------------------------------------------------------------------------------------
// Items 3, 4: response body mid-stream
// ------------------------------------------------------------------------------------

fn h1_response_mid_stream(how: Reload, chunked: bool) {
    let len: u64 = if chunked { 4 << 20 } else { 16 << 20 };
    let seed = if chunked { 0xC4 } else { 0xC1 };
    let kind = if chunked { "chunked" } else { "stream" };
    let what = format!("response body mid-stream ({kind})");
    let be = HttpBackend::start();
    let mut rig = Rig::new(be.addr, |_| {});
    let mut old = rig.start();
    let c = H1::connect(rig.fe);
    let local = c.local;
    let path = format!("/{kind}?len={len}&seed={seed}");
    let r = start_stream(c, &path, seed, 128 * 1024);
    let accepted = be.accepted();

    let _new = rig.reload(&mut old, 2, how);
    if how == Reload::Control {
        be.release_streams();
        return control_reader_ended(r, &what);
    }
    let at_exit = r.progress.get();
    let moved = r.progress.wait_at_least(at_exit + MOVED_AFTER_EXIT, T, || r.done());
    assert!(
        moved,
        "{what}: the body must keep flowing after the old process exited; {} bytes at its exit, \
         {} now",
        at_exit,
        r.progress.get()
    );
    procs::assert_show_sess_lists(rig.sock(), local, "fe");
    be.release_streams();
    let (mut c, res, chk) = r.join();
    assert_eq!(res, Ok(len), "{what}: the body must complete at exactly {len} bytes");
    assert!(chk.mismatch.is_none(), "{what}: {}", chk.error().unwrap_or_default());
    assert_eq!(chk.pos(), len, "{what}: bytes checked");
    let st = be.wait_streamed(&path, T);
    assert!(
        st.len() == 1 && st[0].finished && st[0].written == len && st[0].error.is_none(),
        "{what}: the server must write the whole body on its one connection: {st:?}"
    );
    assert_eq!(be.accepted(), accepted, "{what}: the server saw a new connection mid-response");
    expect_echo(&c.get("/echo", "", T), "2", "the next request on the same connection");
}

/// Items 3, 4 (response body mid-stream; the video case). A `Content-Length` body is
/// flowing, paced, when the old process exits. It keeps flowing in the new process and
/// completes with every byte in place, from the same server connection.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_h1_response_body_mid_stream() {
    h1_response_mid_stream(Reload::Migrate, false);
}

/// Items 3, 4: as `migrate_h1_response_body_mid_stream`, with a chunked body in chunks of
/// 1 to 8000 bytes, so the migration lands inside the chunk parser's state.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_h1_chunked_response_body_mid_stream() {
    h1_response_mid_stream(Reload::Migrate, true);
}

/// Item 11: the control for `migrate_h1_response_body_mid_stream`.
#[test]
fn control_h1_response_body_mid_stream_ends_with_the_old_process() {
    h1_response_mid_stream(Reload::Control, false);
}

/// Item 11: the control for `migrate_h1_chunked_response_body_mid_stream`.
#[test]
fn control_h1_chunked_response_body_mid_stream_ends_with_the_old_process() {
    h1_response_mid_stream(Reload::Control, true);
}

// ------------------------------------------------------------------------------------
// Items 3, 4: TCP-mode bidirectional stream
// ------------------------------------------------------------------------------------

const UP: u64 = 0x5550;
const DOWN: u64 = 0xD0D0;

/// Checks a finished TCP stream: both directions exact, one server connection.
fn tcp_stream_exact(client: &mut TcpClient, be: &TcpBackend, what: &str) {
    let (sent, received, end) = client.finish(T);
    let sent = sent.unwrap_or_else(|e| panic!("{what}: the client's sending side failed: {e}"));
    assert_eq!(end, End::Eof, "{what}: the client must read the server's stream to a clean EOF");
    // The server stops sending when it sees the client's EOF; wait for its view to settle.
    let deadline = Instant::now() + T;
    let seen = loop {
        let s = be.stream_conn().expect("server connection");
        if s.eof || s.recv_error.is_some() || Instant::now() >= deadline {
            break s;
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert!(seen.recv_error.is_none(), "{what}: client-to-server direction: {:?}", seen.recv_error);
    assert!(seen.send_error.is_none(), "{what}: server-to-client direction: {:?}", seen.send_error);
    assert!(seen.eof, "{what}: the server never saw the client's half-close");
    assert_eq!(seen.received, sent, "{what}: the server must receive exactly what the client sent; server side {seen:?}");
    assert_eq!(received, seen.sent, "{what}: the client must receive exactly what the server sent; server side {seen:?}");
    assert_eq!(be.carrying(), 1, "{what}: the server side of the stream must stay on its one connection");
}

fn tcp_stream(how: Reload) {
    let be = TcpBackend::start(UP, DOWN);
    let mut rig = Rig::new(be.addr, |c| c.tcp = true);
    let mut old = rig.start();
    let mut client = TcpClient::connect(rig.fe, UP, DOWN);
    assert!(
        client.wait_progress((0, 0), MOVED_AFTER_EXIT, T),
        "setup: the stream did not start flowing: sent {}, received {}, server {:?}",
        client.sent(),
        client.received(),
        be.stream_conn()
    );

    let _new = rig.reload(&mut old, 2, how);
    if how == Reload::Control {
        return match client.wait_end(CONTROL_END) {
            End::Eof | End::Error(_) => {}
            End::Timeout => control_broken("TCP stream", "the stream still open"),
        };
    }
    let at_exit = (client.sent(), client.received());
    assert!(
        client.wait_progress(at_exit, MOVED_AFTER_EXIT, T),
        "TCP stream: both directions must keep flowing after the old process exited; at its \
         exit {at_exit:?}, now ({}, {})",
        client.sent(),
        client.received()
    );
    procs::assert_show_sess_lists(rig.sock(), client.local, "fe");
    tcp_stream_exact(&mut client, &be, "TCP stream");
}

/// Items 3, 4 (TCP-mode bidirectional stream). Both directions flow, paced, through the
/// migration, and every byte arrives once and in order, on one server connection.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_tcp_bidirectional_stream() {
    tcp_stream(Reload::Migrate);
}

/// Item 11: the control for `migrate_tcp_bidirectional_stream`.
#[test]
fn control_tcp_bidirectional_stream_ends_with_the_old_process() {
    tcp_stream(Reload::Control);
}

// ------------------------------------------------------------------------------------
// Items 4, 5: HTTP/2
// ------------------------------------------------------------------------------------

/// Runs `h` in a thread that keeps reading frames until told to stop: data keeps
/// flowing, and windows keep being credited, while the main thread reloads.
struct Pump {
    stop: Arc<AtomicBool>,
    total: Progress,
    handle: thread::JoinHandle<(H2, Option<Failure>)>,
}

impl Pump {
    fn spawn(mut h: H2) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let total = Progress::default();
        let (s, t) = (Arc::clone(&stop), total.clone());
        let handle = thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match h.pump(Instant::now() + Duration::from_millis(50)) {
                    Ok(_) | Err(Failure::Timeout) => {
                        t.0.store(h.streams.values().map(|st| st.data_len).sum(), Ordering::SeqCst);
                    }
                    Err(e) => return (h, Some(e)),
                }
            }
            (h, None)
        });
        Self { stop, total, handle }
    }

    fn done(&self) -> bool {
        self.handle.is_finished()
    }

    fn join(self) -> (H2, Option<Failure>) {
        self.stop.store(true, Ordering::SeqCst);
        self.handle.join().expect("pump panicked")
    }
}

/// A control's verdict on an HTTP/2 connection being pumped.
fn control_pump_ended(p: Pump, what: &str) {
    let deadline = Instant::now() + CONTROL_END;
    while !p.done() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    if !p.done() {
        control_broken(what, "the connection still open");
    }
    let (_, end) = p.join();
    if !matches!(end, Some(Failure::Ended(_))) {
        control_broken(what, &format!("{end:?}"));
    }
}

/// A summary of an HTTP/2 connection's state, for failure messages.
fn h_state(h: &H2) -> String {
    let mut ids: Vec<_> = h.streams.keys().copied().collect();
    ids.sort_unstable();
    let streams: Vec<String> = ids
        .iter()
        .map(|id| {
            let st = h.stream(*id);
            format!("stream {id}: status {:?}, {} bytes, ended {}, reset {:?}", st.header(":status"), st.data_len, st.ended, st.reset)
        })
        .collect();
    format!("GOAWAY {:?}, violations {:?}, {}", h.goaway, h.violations, streams.join("; "))
}

fn assert_h2_clean(h: &H2, what: &str) {
    assert!(h.goaway.is_none(), "{what}: the server sent GOAWAY {:?}; a migrated connection must not be wound down", h.goaway);
    assert!(h.violations.is_empty(), "{what}: protocol violations: {:?}", h.violations);
}

fn h2_streams_mid_transfer(how: Reload) {
    const LEN: u64 = 4 << 20;
    let seeds = [0x51u64, 0x53, 0x55];
    let be = HttpBackend::start();
    let mut rig = Rig::new(be.addr, |c| c.h2 = true);
    let mut old = rig.start();
    let mut h = H2::connect(rig.fe);
    let local = h.local;
    let ta = format!("ta-{}", std::process::id());
    let f = h.enc.literal_indexed("x-ta", &ta);
    let sids: Vec<u32> = seeds
        .iter()
        .enumerate()
        .map(|(i, &s)| {
            let fields = if i == 0 { vec![f.clone()] } else { vec![] };
            h.open("GET", &format!("/stream?len={LEN}&seed={s}"), &fields, None, Some(s)).expect("open")
        })
        .collect();
    assert_eq!(sids, [1, 3, 5]);
    h.until(Instant::now() + T, |h| sids.iter().all(|s| h.stream(*s).data_len >= 64 * 1024))
        .unwrap_or_else(|e| panic!("setup: the three streams did not all start: {e:?}; {}", h_state(&h)));
    let accepted = be.accepted();
    let p = Pump::spawn(h);

    let _new = rig.reload(&mut old, 2, how);
    if how == Reload::Control {
        be.release_streams();
        return control_pump_ended(p, "HTTP/2 streams mid-transfer");
    }
    let at_exit = p.total.get();
    let moved = p.total.wait_at_least(at_exit + 3 * MOVED_AFTER_EXIT / 2, T, || p.done());
    assert!(moved, "HTTP/2: the streams must keep flowing after the old process exited ({at_exit} then {})", p.total.get());
    procs::assert_show_sess_lists(rig.sock(), local, "fe");
    be.release_streams();
    let (mut h, end) = p.join();
    assert!(end.is_none(), "HTTP/2: the connection failed while the streams flowed: {end:?}");
    h.until(Instant::now() + Duration::from_secs(60), |h| sids.iter().all(|s| h.stream(*s).ended || h.stream(*s).reset.is_some()))
        .unwrap_or_else(|e| panic!("HTTP/2: the streams did not complete: {e:?}"));
    for (sid, seed) in sids.iter().zip(seeds) {
        let st = h.stream(*sid);
        assert_eq!(st.header(":status"), Some("200"), "stream {sid}: {:?}", st.headers);
        assert!(st.reset.is_none(), "stream {sid} was reset: {:?}", st.reset);
        let chk = st.checker.as_ref().expect("checker");
        assert!(chk.mismatch.is_none(), "stream {sid} (seed {seed:#x}): {}", chk.error().unwrap_or_default());
        assert_eq!(st.data_len, LEN, "stream {sid} must deliver exactly {LEN} bytes");
    }
    assert_h2_clean(&h, "HTTP/2 streams mid-transfer");
    assert_eq!(be.accepted(), accepted, "HTTP/2: the server saw a new connection for a stream already in flight");
    for st in be.wait_streamed("/stream", T) {
        assert!(st.finished && st.written == LEN && st.error.is_none(), "server side: {st:?}");
    }

    // A new stream after the migration: the next id, and a header indexed before it.
    let f = h.enc.indexed("x-ta", &ta);
    let sid = h.open("GET", "/echo", &[f], None, None).expect("open after migration");
    assert_eq!(sid, 7, "stream ids continue");
    h.until(Instant::now() + T, |h| h.stream(sid).ended).unwrap_or_else(|e| panic!("stream {sid}: {e:?}"));
    let st = h.stream(sid);
    assert_eq!(st.header(":status"), Some("200"), "{:?}", st.headers);
    assert_eq!(st.header("x-seen-gen"), Some("2"), "the new stream must be processed by the new process: {:?}", st.headers);
    assert_eq!(st.header("x-echo-x-ta"), Some(ta.as_str()), "{:?}", st.headers);
    assert_h2_clean(&h, "HTTP/2 after migration");
    // And the new process knows which ids are spent: a request on stream 5, finished
    // before the migration, is refused, as it is without one.
    assert_reused_id_refused(&mut h, 5, "after the migration");
}

/// Opens `sid` again, after it has been used and closed: RFC 9113 section 5.1.1 makes that
/// a connection error. Alcyon today neither answers it nor sends GOAWAY; `HAProxy` 3.5-dev8
/// sends GOAWAY (last stream 5, `STREAM_CLOSED`) and closes, measured with this test and
/// `ALCYON_BIN` pointing at it. Either way it is not answered, while a server that forgot the connection's
/// history would answer it as a new request. Not being answered is what is checked.
fn assert_reused_id_refused(h: &mut H2, sid: u32, what: &str) {
    h.reuse_id(sid);
    let reopened = h.open("GET", "/echo", &[], None, None);
    let end = h.idle(Duration::from_secs(2));
    let st = h.streams.get(&sid);
    let answered = st.and_then(|s| s.header(":status")).is_some();
    eprintln!("{what}: reused stream id {sid}: answered {answered}, connection {end:?}, GOAWAY {:?}", h.goaway);
    assert!(
        reopened.is_err() || !answered,
        "{what}: a request on spent stream id {sid} must not be answered; got {} and the \
         connection {end:?}, GOAWAY {:?}",
        if answered { "an answer" } else { "no answer" },
        h.goaway
    );
}

/// The premise of the stream-id check in `migrate_h2_concurrent_streams_mid_transfer`,
/// without a reload: Alcyon refuses a request on a stream id already used.
#[test]
fn harness_h2_reused_stream_id_is_refused_without_a_reload() {
    let be = HttpBackend::start();
    let mut rig = Rig::new(be.addr, |c| c.h2 = true);
    let _p = rig.start();
    let mut h = H2::connect(rig.fe);
    for _ in 0..3 {
        h2_echo(&mut h, &[], "setup");
    }
    assert_reused_id_refused(&mut h, 5, "without a reload");
}

/// Items 4, 5 (H2 with several concurrent streams mid-transfer). Three streams flow
/// through the migration and complete exactly; a stream opened afterwards gets the next
/// id, is served by the new process, and no GOAWAY is ever sent.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_h2_concurrent_streams_mid_transfer() {
    h2_streams_mid_transfer(Reload::Migrate);
}

/// Item 11: the control for `migrate_h2_concurrent_streams_mid_transfer`.
#[test]
#[ignore = "pre-existing defect outside T96: Alcyon's HTTP/2 frontend ends a response body after about 16 KB (END_STREAM; curl reports PROTOCOL_ERROR); HAProxy sends all of it"]
fn control_h2_concurrent_streams_end_with_the_old_process() {
    h2_streams_mid_transfer(Reload::Control);
}

/// One echo request on `h` with `fields`; returns the response headers.
fn h2_echo(h: &mut H2, fields: &[Vec<u8>], what: &str) -> Vec<(String, String)> {
    let sid = h.open("GET", "/echo", fields, None, None).unwrap_or_else(|e| panic!("{what}: open: {e:?}"));
    h.until(Instant::now() + T, |h| h.stream(sid).ended || h.stream(sid).reset.is_some())
        .unwrap_or_else(|e| panic!("{what}: stream {sid}: {e:?}"));
    let st = h.stream(sid);
    assert!(st.reset.is_none(), "{what}: stream {sid} reset {:?}", st.reset);
    assert_eq!(st.header(":status"), Some("200"), "{what}: {:?}", st.headers);
    st.headers.clone().unwrap_or_default()
}

fn header<'a>(h: &'a [(String, String)], n: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str())
}

#[allow(clippy::many_single_char_names)]
fn h2_hpack(how: Reload) {
    let be = HttpBackend::start();
    let mut rig = Rig::new(be.addr, |c| c.h2 = true);
    let mut old = rig.start();
    let mut h = H2::connect(rig.fe);
    let tag = std::process::id();
    let (a, b, c) = (format!("alpha-{tag}"), format!("bravo-{tag}"), format!("charlie-{tag}"));

    // Before: two entries into the server's decoder table, then referenced by index, so
    // the references are known to work against this server at all.
    let f = vec![h.enc.literal_indexed("x-ta", &a), h.enc.literal_indexed("x-tb", &b)];
    let r = h2_echo(&mut h, &f, "literals before the reload");
    assert_eq!((header(&r, "x-echo-x-ta"), header(&r, "x-echo-x-tb")), (Some(a.as_str()), Some(b.as_str())), "{r:?}");
    let f = vec![h.enc.indexed("x-ta", &a), h.enc.indexed("x-tb", &b)];
    let r = h2_echo(&mut h, &f, "indexed before the reload");
    assert_eq!((header(&r, "x-echo-x-ta"), header(&r, "x-echo-x-tb")), (Some(a.as_str()), Some(b.as_str())), "{r:?}");
    assert_eq!(header(&r, "x-seen-gen"), Some("1"));

    let _new = rig.reload(&mut old, 2, how);
    if how == Reload::Control {
        return match h.idle(CONTROL_END) {
            Failure::Ended(_) => {}
            other => control_broken("HTTP/2 HPACK", &format!("{other:?}, GOAWAY {:?}", h.goaway)),
        };
    }
    procs::assert_holds_at_least(rig.sock(), 1, "HTTP/2 HPACK");
    // After: references into the table built before the migration -- the server's
    // decoder must still hold it -- plus a new entry, then references to old and new.
    let f = vec![h.enc.indexed("x-ta", &a), h.enc.indexed("x-tb", &b), h.enc.literal_indexed("x-tc", &c)];
    let r = h2_echo(&mut h, &f, "indexed after the migration");
    assert_eq!(
        (header(&r, "x-echo-x-ta"), header(&r, "x-echo-x-tb"), header(&r, "x-echo-x-tc")),
        (Some(a.as_str()), Some(b.as_str()), Some(c.as_str())),
        "dynamic-table references made before the migration must decode to the same values \
         after it: {r:?}"
    );
    assert_eq!(header(&r, "x-seen-gen"), Some("2"), "{r:?}");
    for round in 0..3 {
        // Repeated identical responses give the server's encoder every reason to index;
        // the client's decoder fails on any reference out of step with its table.
        let f = vec![h.enc.indexed("x-tc", &c), h.enc.indexed("x-ta", &a)];
        let r = h2_echo(&mut h, &f, &format!("round {round}"));
        assert_eq!((header(&r, "x-echo-x-tc"), header(&r, "x-echo-x-ta")), (Some(c.as_str()), Some(a.as_str())), "round {round}: {r:?}");
    }
    assert_h2_clean(&h, "HTTP/2 HPACK");
}

/// Item 5 (HPACK). Dynamic-table entries the client created before the migration are
/// referenced by index after it, and the backend's echo proves they decoded to the right
/// values; responses are decoded by an independent decoder, so the server's encoder table
/// must also have come across in step.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_h2_hpack_dynamic_tables() {
    h2_hpack(Reload::Migrate);
}

/// Item 11: the control for `migrate_h2_hpack_dynamic_tables`.
#[test]
fn control_h2_hpack_connection_ends_with_the_old_process() {
    h2_hpack(Reload::Control);
}

fn h2_flow_control(how: Reload) {
    const LEN: u64 = 200_000;
    let (down, up) = (0xF10Du64, 0xF1E0u64);
    let be = HttpBackend::start();
    let mut rig = Rig::new(be.addr, |c| c.h2 = true);
    let mut old = rig.start();
    let mut h = H2::connect(rig.fe);
    h.auto_window = false;

    // Download: the client grants nothing beyond the initial 65535-byte windows, so the
    // server must stop at exactly that and wait.
    let dl = h.open("GET", &format!("/stream?len={LEN}&seed={down}&fast=1"), &[], None, Some(down)).expect("open download");
    #[allow(clippy::cast_sign_loss)]
    let window = lm::h2::WINDOW as u64;
    h.until(Instant::now() + T, |h| h.stream(dl).data_len >= window)
        .unwrap_or_else(|e| panic!("setup: the download did not fill the window: {e:?}; {}", h_state(&h)));
    // Nothing more may arrive: the window is closed. Anything that does is recorded as a
    // violation by the client.
    let quiet = h.idle(Duration::from_millis(300));
    assert_eq!(quiet, Failure::Timeout, "setup: {quiet:?}");
    assert_eq!(h.stream(dl).data_len, window, "the server sent past the window");

    // Upload: half the body now, within the server's windows.
    let ul = h.open("POST", "/upload", &[], Some((up, LEN)), None).expect("open upload");
    // As in `h1_request_body_half_sent`: the body only after the head reached the server.
    be.wait_head("/upload", T);
    h.send_body(ul, Some(LEN / 2), Instant::now() + T).unwrap_or_else(|e| panic!("setup: first half of the upload: {e:?}"));
    let half = h.body_sent(ul);
    be.wait_event(T, |e| matches!(e, Event::Body { path, received, .. } if path == "/upload" && *received >= half))
        .unwrap_or_else(|| panic!("setup: the backend never received the first {half} bytes of the upload"));

    let _new = rig.reload(&mut old, 2, how);
    if how == Reload::Control {
        return match h.idle(CONTROL_END) {
            Failure::Ended(_) => {}
            other => control_broken("HTTP/2 flow control", &format!("{other:?}, GOAWAY {:?}", h.goaway)),
        };
    }
    procs::assert_show_sess_lists(rig.sock(), h.local, "fe");
    // Open the window: the rest of the download must come, exactly.
    h.auto_window = true;
    #[allow(clippy::cast_possible_wrap)]
    h.grant(dl, LEN as i64).expect("window update");
    h.until(Instant::now() + T, |h| h.stream(dl).ended || h.stream(dl).reset.is_some())
        .unwrap_or_else(|e| panic!("the download did not complete after the window opened: {e:?}"));
    let st = h.stream(dl);
    assert!(st.reset.is_none(), "download reset {:?}", st.reset);
    assert_eq!(st.data_len, LEN, "the download must complete at exactly {LEN} bytes");
    let chk = st.checker.as_ref().expect("checker");
    assert!(chk.mismatch.is_none(), "download: {}", chk.error().unwrap_or_default());
    // The rest of the upload, within the windows the new process grants.
    h.send_body(ul, None, Instant::now() + T)
        .unwrap_or_else(|e| panic!("the rest of the upload could not be sent after the migration: {e:?}"));
    h.until(Instant::now() + T, |h| h.stream(ul).ended || h.stream(ul).reset.is_some())
        .unwrap_or_else(|e| panic!("upload response: {e:?}"));
    let st = h.stream(ul);
    assert_eq!(st.header(":status"), Some("200"), "{:?}", st.headers);
    assert_eq!(st.header("x-body"), Some(format!("{LEN} ok").as_str()), "the server must receive the upload exactly: {:?}", st.headers);
    assert_h2_clean(&h, "HTTP/2 flow control");
}

/// Item 5 (flow-control windows). A download larger than the client's window is stopped
/// at exactly the window when the old process exits, and completes once the client opens
/// the window to the new process; an upload larger than the server's window is half sent
/// before and completes after, within the windows the new process grants.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_h2_flow_control_windows() {
    h2_flow_control(Reload::Migrate);
}

/// Item 11: the control for `migrate_h2_flow_control_windows`.
#[test]
#[ignore = "pre-existing defect outside T96: Alcyon's HTTP/2 frontend ends a response body after about 16 KB (END_STREAM; curl reports PROTOCOL_ERROR); HAProxy sends all of it"]
fn control_h2_flow_control_connection_ends_with_the_old_process() {
    h2_flow_control(Reload::Control);
}

// ------------------------------------------------------------------------------------
// Item 6: every worker's connections
// ------------------------------------------------------------------------------------

/// Connections for the `nbthread 4` tests. The kernel spreads them over the four
/// workers' `SO_REUSEPORT` sockets by hash; the chance that some worker gets none of 64
/// is 4 x (3/4)^64, about 4e-8.
const MANY: usize = 64;

fn check_all_survived(conns: &mut [H1], sock: &Path, how: Reload, what: &str) {
    if how == Reload::Control {
        let ended = conns.iter_mut().map(|c| matches!(c.get("/echo", "", CONTROL_END), Err(Failure::Ended(_)))).filter(|e| *e).count();
        if ended != conns.len() {
            control_broken(what, &format!("{ended} of {} connections ended", conns.len()));
        }
        return;
    }
    procs::assert_holds_at_least(sock, conns.len() as u64, what);
    let mut lost = Vec::new();
    for (i, c) in conns.iter_mut().enumerate() {
        match c.get("/echo", "", T) {
            Ok(r) if r.status == 200 && gen(&r) == Some("2") => {}
            other => lost.push((i, format!("{:?}", other.map(|r| (r.status, gen(&r).map(str::to_string)))))),
        }
    }
    assert!(
        lost.is_empty(),
        "{what}: {} of {} connections did not survive into the new process (every worker's \
         connections must migrate, not only those of the worker that answers the CLI): {lost:?}",
        lost.len(),
        conns.len()
    );
}

fn all_workers(how: Reload) {
    let be = HttpBackend::start();
    let mut rig = Rig::new(be.addr, |c| c.nbthread = Some(4));
    let mut old = rig.start();
    let mut conns = idle_connections(rig.fe, MANY);
    let _new = rig.reload(&mut old, 2, how);
    check_all_survived(&mut conns, rig.sock(), how, "nbthread 4, -x/-sf reload");
}

/// Item 6. With `nbthread 4` and 64 connections, every one of them -- whichever worker
/// held it -- is served by the new process after the old one exits.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_every_workers_connections() {
    all_workers(Reload::Migrate);
}

/// Item 11: the control for `migrate_every_workers_connections`.
#[test]
fn control_every_workers_connections_end_with_the_old_process() {
    all_workers(Reload::Control);
}

fn read_pidfile(p: &Path) -> Option<u32> {
    std::fs::read_to_string(p).ok()?.trim().parse().ok()
}

fn master_worker(how: Reload) {
    let be = HttpBackend::start();
    let mut rig = Rig::new(be.addr, |c| c.nbthread = Some(4));
    let pidfile = TempPath::new("pid", "pid");
    let c1 = rig.gen(1);
    let mut args = iface::master_args(how);
    args.extend(["-p".to_string(), pidfile.path().display().to_string()]);
    let mut old = procs::start(&c1, &args, rig.sock(), rig.fe);
    let mut conns = idle_connections(rig.fe, MANY / 2);
    // A `-W` reload re-reads the same file, so generation 2 overwrites it.
    std::fs::write(&c1, rig.cfg.gen(2).render()).expect("write generation 2");
    old.signal(iface::MASTER_RELOAD_SIGNAL);
    let deadline = Instant::now() + procs::START_WITHIN;
    let new_pid = loop {
        if let Some(p) = read_pidfile(pidfile.path()).filter(|p| *p != old.pid()) {
            if procs::cli_pid(rig.sock()) == Some(p) {
                break p;
            }
        }
        assert!(Instant::now() < deadline, "the SIGUSR2 reload never produced a serving process; stderr: {}", old.stderr());
        thread::sleep(Duration::from_millis(20));
    };
    let _new = procs::Foreign(new_pid);
    procs::wait_gone(&mut old);
    check_all_survived(&mut conns, rig.sock(), how, "-W master-worker, SIGUSR2 reload");
}

/// Item 6 and the `-W` interface. A master-worker process started with
/// `-W --migrate-conns` and reloaded with `SIGUSR2` migrates every worker's connections.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_master_worker_sigusr2_reload() {
    master_worker(Reload::Migrate);
}

/// Item 11: the control for `migrate_master_worker_sigusr2_reload`.
#[test]
fn control_master_worker_sigusr2_reload_ends_connections() {
    master_worker(Reload::Control);
}

// ------------------------------------------------------------------------------------
// Item 7: configuration still applies
// ------------------------------------------------------------------------------------

const TIMEOUT_CLIENT: Duration = Duration::from_secs(4);

/// The premise of `migrate_timeout_client_still_closes_an_idle_connection`, checked
/// without a reload: with `timeout client 4s`, an idle keep-alive connection is closed
/// about four seconds after its last response.
#[test]
fn harness_timeout_client_closes_an_idle_connection_without_a_reload() {
    let be = HttpBackend::start();
    let mut rig = Rig::new(be.addr, |c| c.timeout_client = "4s");
    let _p = rig.start();
    let mut c = H1::connect(rig.fe);
    expect_echo(&c.get("/echo", "", T), "1", "request");
    let t0 = Instant::now();
    let r = c.wait_end(TIMEOUT_CLIENT + Duration::from_secs(3));
    let at = t0.elapsed();
    assert_eq!(r, Ok(()), "the idle connection must be closed by timeout client");
    assert!(at + Duration::from_millis(200) >= TIMEOUT_CLIENT, "closed after {at:?}, before timeout client");
}

/// Item 7 (`timeout client`). An idle connection migrated soon after its last response is
/// still closed by `timeout client`: not at the migration, not never, but about four
/// seconds after it went idle (or four seconds after the migration, if the timer is
/// restarted).
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_timeout_client_still_closes_an_idle_connection() {
    let be = HttpBackend::start();
    let mut rig = Rig::new(be.addr, |c| c.timeout_client = "4s");
    let mut old = rig.start();
    let mut c = H1::connect(rig.fe);
    expect_echo(&c.get("/echo", "", T), "1", "request");
    let t0 = Instant::now();
    let _new = rig.reload(&mut old, 2, Reload::Migrate);
    let exited = t0.elapsed();
    assert!(
        exited + Duration::from_millis(500) < TIMEOUT_CLIENT,
        "inconclusive: the reload took {exited:?}, too close to timeout client to tell the two apart"
    );
    procs::assert_holds_at_least(rig.sock(), 1, "timeout client");
    let r = c.wait_end(TIMEOUT_CLIENT + Duration::from_secs(3));
    let at = t0.elapsed();
    assert_eq!(r, Ok(()), "the migrated idle connection was never closed: timeout client no longer applies to it");
    assert!(
        at + Duration::from_millis(200) >= TIMEOUT_CLIENT,
        "the migrated connection was closed {at:?} after going idle, before timeout client \
         ({TIMEOUT_CLIENT:?}); it was cut, not timed out"
    );
}

/// Item 7 (http-response rules). After the migration, later transactions on the
/// connection still have `http-response` rules applied -- the new configuration's.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_http_response_rules_still_run_on_later_transactions() {
    let be = HttpBackend::start();
    let mut rig = Rig::new(be.addr, |c| c.response_rule = true);
    let mut old = rig.start();
    let mut c = H1::connect(rig.fe);
    let r = c.get("/echo", "", T);
    expect_echo(&r, "1", "before");
    assert_eq!(r.as_ref().ok().and_then(|r| r.header("X-Resp-Gen")), Some("1"), "{r:?}");
    let _new = rig.reload(&mut old, 2, Reload::Migrate);
    for i in 0..2 {
        let r = c.get("/echo", "", T);
        expect_echo(&r, "2", "after");
        let r = r.expect("checked");
        let all: Vec<_> = r.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("X-Resp-Gen")).collect();
        assert_eq!(
            all,
            [&("X-Resp-Gen".to_string(), "2".to_string())],
            "transaction {i} after the migration: the new configuration's http-response rule must \
             run, once; headers {:?}",
            r.headers
        );
    }
}

// ------------------------------------------------------------------------------------
// Item 8: chains
// ------------------------------------------------------------------------------------

/// Item 8. One HTTP/1 connection across three successive migrations, served by each new
/// generation in turn.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_h1_connection_across_three_reloads() {
    let be = HttpBackend::start();
    let mut rig = Rig::new(be.addr, |_| {});
    let mut cur = rig.start();
    let mut c = H1::connect(rig.fe);
    expect_echo(&c.get("/echo", "", T), "1", "generation 1");
    for g in 2..=4 {
        cur = rig.reload(&mut cur, g, Reload::Migrate);
        procs::assert_holds_at_least(rig.sock(), 1, &format!("generation {g}"));
        expect_echo(&c.get("/echo", "", T), &g.to_string(), &format!("after migration {}", g - 1));
    }
}

/// Item 8 with item 3. A TCP stream flows through three successive migrations, both
/// directions exact at the end.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_tcp_stream_across_three_reloads() {
    let be = TcpBackend::start(UP, DOWN);
    let mut rig = Rig::new(be.addr, |c| c.tcp = true);
    let mut cur = rig.start();
    let mut client = TcpClient::connect(rig.fe, UP, DOWN);
    assert!(client.wait_progress((0, 0), MOVED_AFTER_EXIT, T), "setup");
    for g in 2..=4 {
        cur = rig.reload(&mut cur, g, Reload::Migrate);
        let at = (client.sent(), client.received());
        assert!(client.wait_progress(at, MOVED_AFTER_EXIT, T), "after migration {}: the stream stopped at {at:?}", g - 1);
        procs::assert_show_sess_lists(rig.sock(), client.local, "fe");
    }
    tcp_stream_exact(&mut client, &be, "TCP stream after three migrations");
}

// ------------------------------------------------------------------------------------
// Item 9: what cannot migrate is not harmed
// ------------------------------------------------------------------------------------

fn cert_file() -> TempPath {
    let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let f = TempPath::new("crt", "pem");
    f.write(&format!("{}{}", c.cert.pem(), c.key_pair.serialize_pem()));
    f
}

type Tls = rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>;

fn tls_connect(addr: SocketAddr) -> Tls {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    #[derive(Debug)]
    struct Any;
    impl ServerCertVerifier for Any {
        fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::CryptoProvider::get_default().map(|p| p.signature_verification_algorithms.supported_schemes()).unwrap_or_default()
        }
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cfg = rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(Any)).with_no_client_auth();
    let conn = rustls::ClientConnection::new(Arc::new(cfg), ServerName::try_from("localhost").expect("name")).expect("tls client");
    let sock = std::net::TcpStream::connect(addr).expect("connect tls");
    sock.set_read_timeout(Some(T)).expect("timeout");
    rustls::StreamOwned::new(conn, sock)
}

/// Reads one response with a `Content-Length` from a TLS stream: (head, body), or how the
/// stream ended first.
fn tls_response(tls: &mut Tls) -> Result<(String, Vec<u8>), String> {
    use std::io::Read;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 16384];
    let read = |tls: &mut Tls, buf: &mut Vec<u8>, tmp: &mut [u8]| match tls.read(tmp) {
        Ok(0) => Err("EOF".to_string()),
        Ok(n) => {
            buf.extend_from_slice(&tmp[..n]);
            Ok(())
        }
        Err(e) => Err(format!("{e} ({:?})", e.kind())),
    };
    let end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        read(tls, &mut buf, &mut tmp)?;
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let cl: usize = head
        .lines()
        .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("content-length")).map(|(_, v)| v.trim().to_string()))
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("no Content-Length in {head:?}"))?;
    while buf.len() < end + cl {
        read(tls, &mut buf, &mut tmp)?;
    }
    Ok((head, buf[end..end + cl].to_vec()))
}

fn tls_stays(how: Reload) {
    use std::io::Write;
    let be = HttpBackend::start();
    let crt = cert_file();
    let fe_tls = common::reserve_addr();
    let mut rig = Rig::new(be.addr, |c| {
        // Long enough for the TLS connection to drain in the old process, as it does today.
        c.hard_stop_after = "15s";
        c.fe_extra = format!("  bind {fe_tls} ssl crt {}\n", crt.path().display());
    });
    let mut old = rig.start();
    let mut plain = H1::connect(rig.fe);
    expect_echo(&plain.get("/echo", "", T), "1", "plain, before");
    let mut tls = tls_connect(fe_tls);
    tls.write_all(b"GET /hold HTTP/1.1\r\nHost: t96\r\n\r\n").expect("tls request");
    be.wait_head("/hold", T);

    let p = rig.gen(2);
    let _new = procs::reload(&old, &p, rig.sock(), how);
    // The old process must still be there, holding the TLS connection.
    assert!(
        old.wait_exit(Duration::from_millis(500)).is_none(),
        "the old process exited with a TLS request in flight: TLS connections must stay and drain"
    );
    if how == Reload::Migrate {
        expect_echo(&plain.get("/echo", "", T), "2", "the plain connection, migrated while TLS stays");
    }
    be.release_holds();
    let r = tls_response(&mut tls).unwrap_or_else(|e| panic!("the TLS request in flight was not answered: {e}"));
    assert!(r.0.starts_with("HTTP/1.1 200"), "{r:?}");
    assert!(
        r.0.to_ascii_lowercase().contains("\r\nx-seen-gen: 1\r\n"),
        "the TLS request must be answered by the old process, which it never left: {}",
        r.0
    );
    assert!(String::from_utf8_lossy(&r.1).starts_with("GET /hold HTTP/1.1\r\n"), "{r:?}");
    // Then the old process closes it and exits, as without migration.
    let next = tls.write_all(b"GET /echo HTTP/1.1\r\nHost: t96\r\n\r\n").map_err(|e| e.to_string()).and_then(|()| tls_response(&mut tls));
    assert!(next.is_err(), "the old process kept the TLS connection open after its last response: {next:?}");
    let st = procs::wait_gone(&mut old);
    assert!(st.success(), "old process: {st}");
    if how == Reload::Migrate {
        expect_echo(&plain.get("/echo", "", T), "2", "the plain connection after the old process exited");
    } else {
        control_h1_ended(&mut plain, "plain connection beside TLS");
    }
}

/// Item 9 (TLS). A TLS connection is not migrated: it stays in the old process, its
/// request in flight is answered there (generation 1), and it is closed as the old
/// process drains -- exactly as without migration -- while the plain connection beside it
/// migrates.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_leaves_tls_connections_to_drain_in_the_old_process() {
    tls_stays(Reload::Migrate);
}

/// Item 11: the control for `migrate_leaves_tls_connections_to_drain_in_the_old_process`:
/// the TLS behaviour asserted there is today's.
#[test]
fn control_tls_connections_drain_in_the_old_process() {
    tls_stays(Reload::Control);
}

fn curl_has_http3() -> bool {
    std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("HTTP3"))
}

fn quic_stays(how: Reload) {
    assert!(
        curl_has_http3(),
        "this test needs a curl with HTTP/3; it fails rather than skips, so a host without one \
         cannot report the QUIC check as passed"
    );
    let be = HttpBackend::start();
    let crt = cert_file();
    let q = common::reserve_addr();
    let mut rig = Rig::new(be.addr, |c| {
        c.hard_stop_after = "15s";
        c.fe_extra = format!("  bind quic4@{q} ssl crt {}\n", crt.path().display());
    });
    let mut old = rig.start();
    let curl = std::process::Command::new("curl")
        .args(["-sS", "--http3-only", "-k", "--max-time", "10", "--resolve", &format!("localhost:{}:127.0.0.1", q.port())])
        .arg(format!("https://localhost:{}/hold", q.port()))
        .args(["-o", "-", "-w", "\n__STATUS__%{http_code} __VER__%{http_version}"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn curl");
    be.wait_head("/hold", Duration::from_secs(15));

    let p = rig.gen(2);
    let _new = procs::reload(&old, &p, rig.sock(), how);
    let early_exit = old.wait_exit(Duration::from_millis(500));
    be.release_holds();
    let out = curl.wait_with_output().expect("curl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let seen = format!(
        "old process exit within 500 ms of the reload: {early_exit:?}\ncurl stdout: {stdout}\ncurl stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(early_exit.is_none(), "the old process exited with a QUIC request in flight: QUIC connections must stay and drain.\n{seen}");
    assert!(
        stdout.contains("__STATUS__200") && stdout.contains("__VER__3"),
        "the HTTP/3 request in flight across the reload must complete over QUIC.\n{seen}"
    );
    // The request was handed to the backend before the reload, so the old process's rules
    // (generation 1) processed it. Not asserted before T130: HTTP/3 ran no `http-request`
    // rule at all, so the header was never added.
    assert!(
        stdout.contains("\r\nX-Gen: 1\r\n") || stdout.contains("\r\nx-gen: 1\r\n"),
        "the HTTP/3 request must have been processed by the old process's rules.\n{seen}"
    );
    let st = procs::wait_gone(&mut old);
    assert!(st.success(), "old process: {st}");
}

/// Item 9 (QUIC). An HTTP/3 request in flight on the old process when the reload happens
/// is answered by the old process over the same QUIC connection, which then drains.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_leaves_quic_connections_to_drain_in_the_old_process() {
    quic_stays(Reload::Migrate);
}

/// Item 11: the control for `migrate_leaves_quic_connections_to_drain_in_the_old_process`.
#[test]
fn control_quic_connections_drain_in_the_old_process() {
    quic_stays(Reload::Control);
}

// ------------------------------------------------------------------------------------
// Item 10: failure is safe
// ------------------------------------------------------------------------------------

/// Item 10. Two reloads that fail -- a configuration that does not parse, and one that
/// parses but cannot bind (so the new process gets as far as fetching connections before
/// dying) -- leave an idle connection, a response mid-stream and a TCP stream all with the
/// old process, working and exact. A third, good reload then migrates all of them, which
/// is what makes the first two meaningful: the flag is accepted and migration is real.
#[test]
#[ignore = "T96: live connection migration not implemented"]
fn migrate_failed_reloads_leave_every_connection_with_the_old_process() {
    let be = HttpBackend::start();
    let tbe = TcpBackend::start(UP, DOWN);
    let fe_tcp = common::reserve_addr();
    let mut rig = Rig::new(be.addr, |c| {
        c.extra_sections = format!("listen lt\n  mode tcp\n  bind {fe_tcp}\n  server t1 {}\n", tbe.addr);
    });
    let mut old = rig.start();
    let mut idle = H1::connect(rig.fe);
    expect_echo(&idle.get("/echo", "", T), "1", "setup");
    let seed = 0x10;
    let len: u64 = 32 << 20;
    let path = format!("/stream?len={len}&seed={seed}");
    let stream = start_stream(H1::connect(rig.fe), &path, seed, 128 * 1024);
    let mut tcp = TcpClient::connect(fe_tcp, UP, DOWN);
    assert!(tcp.wait_progress((0, 0), 64 * 1024, T), "setup: tcp");

    let broken = TempPath::new("bad", "cfg");
    broken.write(&rig.cfg.gen(2).render().replace("  default_backend be\n", "  default_backend be\n  this-is-not-a-keyword\n"));
    let unbindable = TempPath::new("late", "cfg");
    unbindable.write(&rig.cfg.gen(2).render().replace(&format!("  bind {}\n", rig.fe), &format!("  bind {}\n  bind 192.0.2.1:80\n", rig.fe)));
    for (what, cfg, expect_in_stderr) in [
        ("a configuration that does not parse", broken.path(), &["this-is-not-a-keyword"][..]),
        ("a configuration that cannot bind", unbindable.path(), &["192.0.2.1", "Cannot assign requested address"][..]),
    ] {
        let mut failed = Alcyon::spawn(cfg, &iface::reload_args(rig.sock(), old.pid(), Reload::Migrate));
        let st = failed.wait_exit(procs::START_WITHIN).unwrap_or_else(|| panic!("{what}: the new process neither failed nor exited"));
        assert!(!st.success(), "{what}: the new process must fail: {st}");
        assert!(
            expect_in_stderr.iter().any(|m| failed.stderr().contains(m)),
            "{what}: the reload must fail for its configuration, not for anything else; stderr: {}",
            failed.stderr()
        );
        assert!(old.wait_exit(Duration::from_millis(300)).is_none(), "{what}: the old process was stopped");
        // Every connection still works, with the old process.
        expect_echo(&idle.get("/echo", "", T), "1", &format!("idle connection after {what}"));
        let at = stream.progress.get();
        assert!(stream.progress.wait_at_least(at + MOVED_AFTER_EXIT, T, || stream.done()), "{what}: the response stream stopped at {at}");
        let at = (tcp.sent(), tcp.received());
        assert!(tcp.wait_progress(at, MOVED_AFTER_EXIT, T), "{what}: the TCP stream stopped at {at:?}");
        assert_eq!(procs::cli_pid(rig.sock()), Some(old.pid()), "{what}: the stats socket must still be the old process's");
    }

    let _new = rig.reload(&mut old, 3, Reload::Migrate);
    expect_echo(&idle.get("/echo", "", T), "3", "idle connection after the good reload");
    let at = stream.progress.get();
    assert!(stream.progress.wait_at_least(at + MOVED_AFTER_EXIT, T, || stream.done()), "after the good reload: the response stream stopped at {at}");
    be.release_streams();
    let (_, res, chk) = stream.join();
    assert_eq!(res, Ok(len), "the response body");
    assert!(chk.mismatch.is_none(), "{}", chk.error().unwrap_or_default());
    let at = (tcp.sent(), tcp.received());
    assert!(tcp.wait_progress(at, MOVED_AFTER_EXIT, T), "after the good reload: the TCP stream stopped at {at:?}");
    tcp_stream_exact(&mut tcp, &tbe, "TCP stream through two failed reloads and one migration");
}
