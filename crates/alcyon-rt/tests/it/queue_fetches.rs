// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `queue(be)`, `avg_queue(be)`, `connslots(be)`, `srv_queue(be/srv)`,
//! `str(be/srv),srv_queue` and `uptime`, and the load-time behaviour of `maxqueue`.
//!
//! Spec: the oracle reg-test `reg-tests/sample_fetches/proxy_state.vtc`. This test adds the
//! held-backend scenario that reg-test cannot express: one server, `maxconn 1 maxqueue 1`,
//! three concurrent requests. With an assigned server (cookie `srv=c1`), the second request
//! fills the server's queue and the third must fail 503 (no `option redispatch`), or land
//! in the proxy queue when the backend has `option redispatch`. A plain (unassigned)
//! request goes to the proxy queue either way; `maxqueue` does not limit it.
//!
//! The cycle runs repeatedly: a request woken from a server queue re-races the
//! proxy queue's requests for the slot the release just freed. On the worker that serves
//! it, it is still counted in its own queue (`HAProxy` unlinks the stream from its queue
//! before re-checking it, `process_srv_queue` in src/queue.c), so its fullness must be
//! judged on the other entries: a full queue of others is a refusal, an empty one is a
//! re-queue, not a refusal.
//!
//! Every expected value was measured on the `HAProxy` 3.5-dev11 oracle. Set
//! `T281_ORACLE=/var/tmp/qwen-next-eval/oracle/haproxy` to run this test against `HAProxy`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::NamedTempFile;

use crate::common;

/// The cycles of the held/release scenario: each cycle puts a woken server-queue request
/// and a woken proxy-queue request in a millisecond-wide race for the slot the release
/// freed, and the refusal the loser got once (measured: `503`, while `HAProxy` re-queues
/// it) must not survive.
const CYCLES: u32 = 60;

/// The backend holds a connection only while the hold generation recorded at its accept
/// is still the current one (`state` is the holding generation, `0` holds nothing). A
/// cycle raises the generation to hold what it opens and stores `0` to release it: the
/// requests the release wakes connect *after* the store and so are answered at once.
fn held_backend(state: Arc<AtomicU64>, accepted: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
            accepted.fetch_add(1, Ordering::SeqCst);
            let epoch = state.load(Ordering::SeqCst);
            let state = Arc::clone(&state);
            thread::spawn(move || {
                let mut head = Vec::new();
                let mut buf = [0u8; 4096];
                let mut seen_eoh = false;
                while !seen_eoh {
                    match stream.read(&mut buf) {
                        Ok(0) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                        Err(_) => return,
                    }
                    seen_eoh = head.windows(4).any(|w| w == b"\r\n\r\n");
                }
                loop {
                    if epoch == 0 || state.load(Ordering::SeqCst) != epoch {
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        );
                        return;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            });
        }
    });
    addr
}

fn request(host: SocketAddr, req: &str) -> Option<String> {
    let mut stream = TcpStream::connect(host).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = stream.write_all(req.as_bytes());
    let mut out = String::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.push_str(&String::from_utf8_lossy(&buf[..n])),
            Err(_) => break,
        }
    }
    Some(out)
}

fn header(resp: &str, name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    resp.lines()
        .find_map(|l| {
            let l = l.trim();
            let lowered = l.to_ascii_lowercase();
            lowered
                .strip_prefix(&lower)
                .and_then(|rest| rest.strip_prefix(':'))
                .map(str::trim)
                .map(str::to_string)
        })
        .unwrap_or_default()
}

fn status(resp: &str) -> u16 {
    resp.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0)
}

/// A client that sends `req` on connect and reads until the response carries `stop_for`.
fn client(host: SocketAddr, req: &str, stop_for: &[&str]) -> thread::JoinHandle<String> {
    let req = req.to_string();
    let stop: Vec<String> = stop_for.iter().map(|s| s.to_string()).collect();
    thread::spawn(move || {
        let mut s = TcpStream::connect(host).unwrap();
        let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
        let _ = s.write_all(req.as_bytes());
        let mut out = String::new();
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    out.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if stop.iter().any(|w| out.contains(w.as_str())) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        out
    })
}

/// Polls the probe until every header shows its value **in the same response** (up to
/// `ms`). A single response samples the counters one after another, and a queue state
/// change on another worker can land between two samples (a counter read before an
/// enqueue, the next after it), so one header alone does not settle: the whole tuple does.
fn probe_until(pe: SocketAddr, probe: &str, want: &[(&str, &str)], ms: u64, what: &str) -> String {
    let mut last = String::new();
    for _ in 0..(ms / 25) {
        last = request(pe, probe).unwrap();
        if want.iter().all(|(h, w)| header(&last, h) == *w) {
            return last;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("probe did not settle to {want:?} for {what:?}: {last:?}");
}

/// One held/release pass over both backends.
fn cycle(
    cycle: u32,
    fe: SocketAddr,
    fe2: SocketAddr,
    pe: SocketAddr,
    release: Arc<AtomicU64>,
    accepted: Arc<AtomicUsize>,
    get: &str,
    get_cookie: &str,
    get_cookie2: &str,
    probe: &str,
) {
    // New connections are held for this cycle: the generation is raised (from 0, the
    // previous cycle's release) and stays until the release below stores 0.
    release.fetch_add(1, Ordering::SeqCst);
    accepted.store(0, Ordering::SeqCst);

    // A takes the one slot of s1; the backend holds it.
    let a = client(fe, get, &["200 OK"]);
    for _ in 0..400 {
        if accepted.load(Ordering::SeqCst) >= 1 {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "the backend holds exactly one connection");

    // B is assigned to s1 (cookie): the server is at maxconn and its queue is empty, so B
    // is queued on the server (maxqueue still has room).
    let b = client(fe, get_cookie, &["200 OK", "503 "]);
    // B is in s1's server queue: `queue(b)` counts it, `avg_queue` rounds up over the one
    // usable server (s3 stays out, disabled), the `str(...)` converter agrees, and
    // `connslots` is (1-1)+(1-1)=0.
    let _ = probe_until(pe, probe, &[("x-sq", "1"), ("x-q", "1"), ("x-aq", "1"), ("x-sqc", "1"), ("x-cs", "0")], 5000, &format!("cycle {cycle}: B in s1's queue"));

    // C is assigned to s1 with the queue full (maxqueue 1): refused 503, because b has no
    // `option redispatch`.
    let c = request(fe, get_cookie).unwrap();
    assert_eq!(
        status(&c),
        503,
        "cycle {cycle}: the third assigned request fails while the queue is full: {c:?}"
    );
    // D and D2 are not assigned: every server is at maxconn, so they go to the proxy
    // queue, which `maxqueue` does not limit.
    let d = client(fe, get, &["200 OK"]);
    let d2 = client(fe, get, &["200 OK"]);
    // Three are pending in b: B in s1's server queue, D and D2 in the proxy queue. The
    // server queue and the slots are unchanged.
    let _ = probe_until(pe, probe, &[("x-q", "3"), ("x-aq", "3"), ("x-sq", "1"), ("x-sqc", "1"), ("x-cs", "0")], 5000, &format!("cycle {cycle}: D and D2 in b's proxy queue"));

    // b2: the same limits on s1b plus a free second server s2b, and `option redispatch`.
    // r2 is assigned to s1b (cookie) and takes its one slot.
    let r2 = client(fe2, get_cookie, &["200 OK"]);
    for _ in 0..400 {
        if accepted.load(Ordering::SeqCst) >= 2 {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 2, "the backend holds r2's connection too");

    // r2b is assigned: queued on s1b's server queue. The slot shows in `connslots`
    // (s1b: (1-1)+(1-1)=0; s2b is still free: (1-0)+(1-0)=2).
    let r2b = client(fe2, get_cookie, &["200 OK", "503 "]);
    let _ = probe_until(pe, probe, &[("x-q2", "1"), ("x-aq2", "1"), ("x-c2", "2")], 5000, &format!("cycle {cycle}: r2b in s1b's queue"));
    // r2c is assigned with the queue full: not refused (option redispatch) -- the balancer
    // is asked again and gives it the free s2b. Wait for that to settle: the slot shows
    // in `connslots` (s2b: (1-1)+(1-0)=1) and b2's queue still holds only r2b, so the
    // redispatch's success is the only way to read this: the re-pick of `s2b` is not left
    // to the arrival order of the clients.
    let r2c = client(fe2, get_cookie, &["200 OK", "503 "]);
    let _ = probe_until(pe, probe, &[("x-q2", "1"), ("x-aq2", "1"), ("x-c2", "1")], 5000, &format!("cycle {cycle}: r2c redispatched to s2b"));
    // r2d is assigned to s2b (cookie): the server is at maxconn (r2c) and its queue has
    // room, so r2d is queued on s2b.
    let r2d = client(fe2, get_cookie2, &["200 OK", "503 "]);
    // Settle before r2e: r2d's place in s2b's queue and both slots show in `connslots`
    // (s1b (1-1)+(1-1)=0, s2b (1-1)+(1-1)=0). The maxqueue check is a check-then-add that
    // is not atomic in HAProxy either (`pendconn_add` in src/queue.c re-checks nothing):
    // two workers that both see an empty queue can both enqueue it, the queue then holds
    // maxqueue+1 until the drain, and `connslots` underflows (measured: 4294967295).
    // Sending r2e only after r2d's enqueue is visible keeps both binaries on the
    // deterministic path: r2e finds s2b's queue full.
    let _ = probe_until(pe, probe, &[("x-q2", "2"), ("x-aq2", "1"), ("x-c2", "0")], 5000, &format!("cycle {cycle}: r2d in s2b's queue"));
    // r2e is assigned to s2b with the queue full: `option redispatch` asks the balancer
    // again, but every server is at its maxconn, so it gives up and r2e waits in b2's
    // proxy queue, where maxqueue does not limit it.
    let r2e = client(fe2, get_cookie2, &["200 OK", "503 "]);
    // Three requests are pending in b2: r2b and r2d on their servers' queues, r2e in the
    // proxy queue. r2 and r2c hold slots, not queue places, and the slots are settled:
    // s1b (1-1)+(1-1)=0, s2b (1-1)+(1-1)=0.
    let _ = probe_until(pe, probe, &[("x-q2", "3"), ("x-aq2", "2"), ("x-c2", "0")], 5000, &format!("cycle {cycle}: r2e in b2's proxy queue"));

    // Release: every held connection is answered; the queues drain. The drain is where a
    // request woken from a server queue re-races the proxy queue's requests for the slot
    // the release freed, so load the workers across the window.
    release.store(0, Ordering::SeqCst);
    let busy = Instant::now();
    while busy.elapsed() < Duration::from_millis(250) {
        let _ = request(pe, probe);
    }
    for (name, h) in [
        ("a", a), ("b", b), ("d", d), ("d2", d2), ("r2", r2), ("r2b", r2b), ("r2c", r2c), ("r2d", r2d), ("r2e", r2e),
    ] {
        let out = h.join().unwrap();
        assert_eq!(
            status(&out),
            200,
            "cycle {cycle}: {name} is answered 200 after the release, not refused: {out:?}"
        );
    }

    // Everything is over: the queues are drained and all slots and queue places are free
    // again (s3 stays out, disabled), so the averages and the slots settle to their
    // empty-queue values in one response.
    let _ = probe_until(
        pe,
        probe,
        &[("x-q", "0"), ("x-aq", "0"), ("x-q2", "0"), ("x-aq2", "0"), ("x-sq", "0"), ("x-cs", "2"), ("x-c2", "4")],
        5000,
        &format!("cycle {cycle}: drained"),
    );
}

#[test]
fn queue_fetches_match_the_oracle() {
    let bin = std::env::var("T281_ORACLE")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());

    let fe = common::reserve_addr();
    let fe2 = common::reserve_addr();
    let pe = common::reserve_addr();
    let release = Arc::new(AtomicU64::new(0));
    let accepted = Arc::new(AtomicUsize::new(0));
    let be = held_backend(release.clone(), accepted.clone());

    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "defaults\n  mode http\n  timeout connect 3s\n  timeout client 30s\n  timeout server 30s\n\
         timeout queue 30s\n\
         frontend f\n  bind {fe}\n  default_backend b\n\
         frontend f2\n  bind {fe2}\n  default_backend b2\n\
         frontend p\n  bind {pe}\n  http-request return status 200 hdr x-q \"%[queue(b)]\" \
         hdr x-aq \"%[avg_queue(b)]\" hdr x-sq \"%[srv_queue(b/s1)]\" \
         hdr x-sqc \"%[str(b/s1),srv_queue]\" hdr x-cs \"%[connslots(b)]\" \
         hdr x-cs3 \"%[connslots(b3)]\" \
         hdr x-q2 \"%[queue(b2)]\" hdr x-aq2 \"%[avg_queue(b2)]\" hdr x-c2 \"%[connslots(b2)]\" hdr x-up \"%[uptime]\"\n\
         backend b\n  cookie srv insert\n  balance roundrobin\n  server s1 {be} maxconn 1 maxqueue 1 cookie c1\n\
         server s3 {be} maxconn 2 maxqueue 2 cookie c3 disabled\n\
         backend b2\n  cookie srv insert\n  balance roundrobin\n  option redispatch\n\
         server s1b {be} maxconn 1 maxqueue 1 cookie c1\n\
         server s2b {be} maxconn 1 maxqueue 1 cookie c2\n\
         backend b3\n  server s1c {be}\n"
    )
    .expect("write");

    let mut child = Command::new(&bin)
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    assert!(common::wait_listening(pe), "proxy never opened the probe port");
    assert!(common::wait_listening(fe), "proxy never opened the frontend port");

    let get = "GET /a HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
    let get_cookie = "GET /b HTTP/1.1\r\nHost: t\r\nCookie: srv=c1\r\nConnection: close\r\n\r\n";
    let get_cookie2 = "GET /c HTTP/1.1\r\nHost: t\r\nCookie: srv=c2\r\nConnection: close\r\n\r\n";
    let probe = "GET /p HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";

    // No traffic yet: empty queues, two slots free on each server.
    let p0 = request(pe, probe).unwrap();
    assert_eq!(header(&p0, "x-q"), "0");
    assert_eq!(header(&p0, "x-aq"), "0");
    assert_eq!(header(&p0, "x-sq"), "0");
    assert_eq!(header(&p0, "x-sqc"), "0");
    assert_eq!(header(&p0, "x-cs"), "2");
    assert_eq!(header(&p0, "x-q2"), "0");
    assert_eq!(header(&p0, "x-c2"), "4");
    // b3's server has no `maxconn` and no `maxqueue`: "the configuration is stupid",
    // `connslots` is -1, whatever the queue holds.
    assert_eq!(header(&p0, "x-cs3"), "-1");
    assert_eq!(header(&p0, "x-aq2"), "0");
    assert!(
        header(&p0, "x-up").parse::<u64>().is_ok(),
        "uptime is a number: {p0:?}"
    );

    for c in 0..CYCLES {
        cycle(c, fe, fe2, pe, release.clone(), accepted.clone(), get, get_cookie, get_cookie2, probe);
    }

    common::stop(&mut child);
}

#[test]
fn connslots_down_backup_and_avg_queue_match_the_oracle() {
    let bin = std::env::var("T281_ORACLE")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());

    let fe_zero = common::reserve_addr();
    let fe_bak = common::reserve_addr();
    let pe = common::reserve_addr();
    let release = Arc::new(AtomicU64::new(0));
    let accepted = Arc::new(AtomicUsize::new(0));
    let be = held_backend(release.clone(), accepted.clone());

    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "defaults\n  mode http\n  timeout connect 3s\n  timeout client 30s\n  timeout server 30s\n\
         timeout queue 30s\n\
         frontend fz\n  bind {fe_zero}\n  default_backend b_zero\n\
         frontend fb\n  bind {fe_bak}\n  default_backend b_bak_down\n\
         frontend p\n  bind {pe}\n  http-request return status 200 \
         hdr x-d-up2 \"%[srv_is_up(b_down/s2)]\" hdr x-d-up3 \"%[srv_is_up(b_down/s3)]\" \
         hdr x-d-cs \"%[connslots(b_down)]\" \
         hdr x-b-nb \"%[nbsrv(b_bak)]\" hdr x-b-cs \"%[connslots(b_bak)]\" \
         hdr x-bd-up1 \"%[srv_is_up(b_bak_down/s1)]\" hdr x-bd-nb \"%[nbsrv(b_bak_down)]\" \
         hdr x-bd-cs \"%[connslots(b_bak_down)]\" hdr x-bd-q \"%[queue(b_bak_down)]\" hdr x-bd-aq \"%[avg_queue(b_bak_down)]\" \
         hdr x-z-nb \"%[nbsrv(b_zero)]\" hdr x-z-cs \"%[connslots(b_zero)]\" \
         hdr x-z-q \"%[queue(b_zero)]\" hdr x-z-aq \"%[avg_queue(b_zero)]\"\n\
         backend b_down\n\
           server s1 {be} maxconn 2 maxqueue 3\n\
           server s2 127.0.0.1:1 maxconn 5 maxqueue 5 check inter 50ms fall 1\n\
           server s3 127.0.0.1:2 check inter 50ms fall 1\n\
         backend b_bak\n\
           server s1 {be} maxconn 1 maxqueue 1\n\
           server sb {be} maxconn 2 maxqueue 4 backup\n\
         backend b_bak_down\n\
           server s1 127.0.0.1:1 maxconn 3 maxqueue 3 check inter 50ms fall 1\n\
           server sb {be} maxconn 1 maxqueue 2 backup\n\
         backend b_zero\n\
           cookie srv insert\n\
           server s1 {be} weight 0 maxconn 1 maxqueue 2 cookie c1\n"
    )
    .expect("write");

    let mut child = Command::new(&bin)
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    assert!(common::wait_listening(pe), "proxy never opened the probe port");
    assert!(common::wait_listening(fe_zero), "proxy never opened fe_zero");
    assert!(common::wait_listening(fe_bak), "proxy never opened fe_bak");

    let probe = "GET /p HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
    let get = "GET /a HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
    let get_cookie = "GET /z HTTP/1.1\r\nHost: t\r\nCookie: srv=c1\r\nConnection: close\r\n\r\n";

    // Wait for health checks on 127.0.0.1:1 / :2 to mark the Down servers SRV_ST_STOPPED.
    // Once Down:
    // - b_down skips s2 (maxconn 5 maxqueue 5) AND s3 (no maxconn/maxqueue -> would be -1),
    //   leaving only s1: 2 + 3 = 5.
    // - b_bak has active s1 (1+1) and backup sb (2+4): nbsrv = 1, connslots = 8.
    // - b_bak_down skips Down s1, leaving backup sb: nbsrv = 1, connslots = 1 + 2 = 3.
    // - b_zero has weight 0 s1 (still Up): nbsrv = 0, connslots = 1 + 2 = 3.
    let _ = probe_until(
        pe,
        probe,
        &[
            ("x-d-up2", "0"),
            ("x-d-up3", "0"),
            ("x-d-cs", "5"),
            ("x-b-nb", "1"),
            ("x-b-cs", "8"),
            ("x-bd-up1", "0"),
            ("x-bd-nb", "1"),
            ("x-bd-cs", "3"),
            ("x-z-nb", "0"),
            ("x-z-cs", "3"),
        ],
        5000,
        "health checks settled",
    );

    // Hold connections to test avg_queue with nbsrv == 0 (totpend * 2) and backup queueing.
    release.fetch_add(1, Ordering::SeqCst);
    accepted.store(0, Ordering::SeqCst);

    let z1 = client(fe_zero, get_cookie, &["200 OK"]);
    let b1 = client(fe_bak, get, &["200 OK"]);
    for _ in 0..400 {
        if accepted.load(Ordering::SeqCst) >= 2 {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 2, "backend holds both z1 and b1");

    // Queue 1 on b_zero (cookie-assigned -> s1's server queue, nbsrv == 0 -> avg_queue = totpend * 2 = 2)
    // and 1 on b_bak_down (unassigned -> proxy queue, so sb's 2 maxqueue slots remain free: connslots = 2).
    let z2 = client(fe_zero, get_cookie, &["200 OK", "503 "]);
    let b2 = client(fe_bak, get, &["200 OK", "503 "]);
    let _ = probe_until(
        pe,
        probe,
        &[
            ("x-z-q", "1"),
            ("x-z-aq", "2"),
            ("x-z-cs", "1"),
            ("x-bd-q", "1"),
            ("x-bd-aq", "1"),
            ("x-bd-cs", "2"),
        ],
        5000,
        "one queued in b_zero and one in b_bak_down",
    );

    // Queue a second request on b_zero (totpend == 2, nbsrv == 0 -> avg_queue = 4, connslots = 0).
    let z3 = client(fe_zero, get_cookie, &["200 OK", "503 "]);
    let _ = probe_until(
        pe,
        probe,
        &[("x-z-q", "2"), ("x-z-aq", "4"), ("x-z-cs", "0")],
        5000,
        "two queued in b_zero",
    );

    release.store(0, Ordering::SeqCst);
    for (name, h) in [("z1", z1), ("z2", z2), ("z3", z3), ("b1", b1), ("b2", b2)] {
        let out = h.join().unwrap();
        assert_eq!(status(&out), 200, "{name} should return 200 after release: {out:?}");
    }

    common::stop(&mut child);
}
