// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The streams of one HTTP/2 connection are served concurrently (T280).
//!
//! The red team's probe (`tools/battery/repro/h2concurrency.py`, branch `myth/battery-spam`):
//! ten GETs on one h2c connection to a backend that sends its response head at once and then
//! drips the body. Measured 2026-10-11 against `haproxy` 3.5-dev8 and Alcyon (b11c30f), same
//! config (`bind ... proto h2`, one server):
//!
//! ```text
//!   haproxy: HEADERS within 3 s: 10 -- streams 1..19 at 0.002..0.004 s
//!   alcyon:    HEADERS within 3 s:  1 -- stream 1 at 0.002 s; the others wait for it to end
//! ```
//!
//! `HAProxy` runs a stream (its own transaction and server connection) per HTTP/2 stream;
//! Alcyon serves one at a time per connection, so a slow response holds up every other one on
//! the connection: a browser's page stalls behind one slow image.

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// How long the dripping backend takes to finish one response: well past `BOUND`, so that a
/// proxy serving the streams one after the other cannot pass.
const BODY_BYTES: usize = 10;
const DRIP: Duration = Duration::from_millis(300);
/// Every stream's HEADERS must have come within this (`HAProxy`: 4 ms on loopback).
const BOUND: Duration = Duration::from_millis(1500);

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn wait_for_port(port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}

/// A backend that answers every request ([`serve_backend_conn`]): the head at once, then one
/// byte of body per `DRIP` -- unless the path is `/fast`, which gets the whole body at once.
fn spawn_drip_backend() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = l.local_addr().expect("addr").port();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(c) = c else { continue };
            thread::spawn(move || serve_backend_conn(c));
        }
    });
    port
}

/// `/big` is the size of the body of the fairness test: many times the connection window.
const BIG: usize = 4 << 20;

/// One backend connection: request after request (a proxy may reuse it). `/fast`: the whole
/// body at once; `/big`: `BIG` bytes at once; `/small`: 100 bytes after 50 ms; `/slow`: 10
/// bytes after 300 ms; anything else drips `BODY_BYTES` bytes one per `DRIP`.
fn serve_backend_conn(mut c: TcpStream) {
    let mut req = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        let end = loop {
            if let Some(i) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            match c.read(&mut tmp) {
                Ok(0) | Err(_) => return,
                Ok(n) => req.extend_from_slice(&tmp[..n]),
            }
        };
        let path = req.split(|&b| b == b' ').nth(1).map(<[u8]>::to_vec).unwrap_or_default();
        req.drain(..end);
        let (len, delay, drip) = match path.as_slice() {
            b"/fast" => (BODY_BYTES, Duration::ZERO, false),
            b"/big" => (BIG, Duration::ZERO, false),
            b"/small" => (100, Duration::from_millis(50), false),
            p if p.starts_with(b"/slow") => (10, Duration::from_millis(300), false),
            _ => (BODY_BYTES, Duration::ZERO, true),
        };
        thread::sleep(delay);
        let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {len}\r\ncontent-type: text/plain\r\n\r\n");
        if c.write_all(head.as_bytes()).is_err() {
            return;
        }
        if drip {
            for _ in 0..len {
                thread::sleep(DRIP);
                if c.write_all(b"x").is_err() {
                    return;
                }
            }
        } else if c.write_all(&vec![b'f'; len]).is_err() {
            return;
        }
    }
}

fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame payload fits in 24 bits");
    let mut v = Vec::with_capacity(9 + payload.len());
    v.extend_from_slice(&len.to_be_bytes()[1..]);
    v.push(ftype);
    v.push(flags);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// `GET <path>` on `localhost`, static-table indices and literals only (no Huffman).
fn hpack_get(path: &str) -> Vec<u8> {
    let mut v = vec![0x82, 0x86, 0x04, u8::try_from(path.len()).expect("short path")];
    v.extend_from_slice(path.as_bytes());
    v.push(0x01);
    v.push(9);
    v.extend_from_slice(b"localhost");
    v
}

/// Starts alcyon with an h2c frontend in front of the dripping backend; returns the daemon and
/// a client connection that has sent its preface and SETTINGS.
fn start() -> (Daemon, TcpStream, std::path::PathBuf) {
    let backend = spawn_drip_backend();
    let port = common::reserve_port();
    let cfg = std::env::temp_dir().join(format!("alcyon_h2conc_{}_{port}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\t\
             timeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port} proto h2\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend}\n"
        ),
    )
    .expect("write config");
    let d = Daemon(
        Command::new(env!("CARGO_BIN_EXE_alcyon"))
            .arg("-f")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn alcyon"),
    );
    assert!(wait_for_port(port), "the daemon never listened on {port}");
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");
    (d, s, cfg)
}

/// Reads frames for `window`, returning for each stream when its HEADERS came and whether
/// it ended (`END_STREAM` on HEADERS or DATA), with the time of the end.
/// (stream id, when) for each frame of a kind seen.
type Seen = Vec<(u32, Duration)>;

fn collect(s: &mut TcpStream, window: Duration) -> (Seen, Seen) {
    s.set_read_timeout(Some(Duration::from_millis(50))).ok();
    let t0 = Instant::now();
    let (mut buf, mut tmp) = (Vec::new(), [0u8; 4096]);
    let (mut heads, mut ends) = (Vec::new(), Vec::new());
    while t0.elapsed() < window {
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => {}
        }
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let (ty, flags) = (buf[3], buf[4]);
            let sid = u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]);
            if ty == 0x01 {
                heads.push((sid, t0.elapsed()));
            }
            if (ty == 0x00 || ty == 0x01) && flags & 0x01 != 0 {
                ends.push((sid, t0.elapsed()));
            }
            buf.drain(..9 + len);
        }
    }
    (heads, ends)
}

/// The probe as a test: ten streams to the dripping backend, all ten HEADERS within `BOUND`.
#[test]
fn ten_streams_to_a_dripping_backend_all_get_their_headers() {
    let (_d, mut s, cfg) = start();
    let ids: Vec<u32> = (0..10).map(|k| 1 + 2 * k).collect();
    let mut burst = Vec::new();
    for &sid in &ids {
        burst.extend_from_slice(&frame(0x01, 0x05, sid, &hpack_get("/drip")));
    }
    s.write_all(&burst).expect("headers");
    let (heads, _) = collect(&mut s, BOUND);
    let _ = std::fs::remove_file(&cfg);
    let mut got: Vec<u32> = heads.iter().map(|&(sid, _)| sid).collect();
    got.sort_unstable();
    got.dedup();
    assert_eq!(
        got, ids,
        "every stream's response head must come within {BOUND:?} while the backend drips its \
         bodies (HAProxy: all ten in 4 ms); got HEADERS (stream, at) {heads:?} -- the streams \
         of one connection are being served one at a time"
    );
}

/// The browser case: a fast response is not held behind a slow one opened before it on the
/// same connection.
#[test]
fn a_fast_stream_is_not_held_behind_a_slow_one() {
    let (_d, mut s, cfg) = start();
    let mut burst = frame(0x01, 0x05, 1, &hpack_get("/drip"));
    burst.extend_from_slice(&frame(0x01, 0x05, 3, &hpack_get("/fast")));
    s.write_all(&burst).expect("headers");
    let (_, ends) = collect(&mut s, BOUND);
    let _ = std::fs::remove_file(&cfg);
    assert!(
        ends.iter().any(|&(sid, _)| sid == 3),
        "stream 3 (/fast, whole body at once) must end within {BOUND:?} although stream 1 \
         (/drip, {BODY_BYTES} bytes at one per {DRIP:?}) is still running; streams ended: {ends:?}"
    );
}

// ---- Tests measured on `HAProxy` too: `T280_ORACLE=/path/to/haproxy` runs them on it. ----

/// The binary under test, or the oracle with `T280_ORACLE=/path/to/haproxy`.
fn binary() -> String {
    std::env::var("T280_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

struct Proxy {
    child: Child,
    port: u16,
    stats: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// The h2c frontend `fe` with `fe_extra` in front of the backend of [`serve_backend_conn`],
/// with a stats socket.
fn start_proxy(fe_extra: &str) -> Proxy {
    start_proxy_cfg("", fe_extra)
}

/// [`start_proxy`] with `global_extra` lines in the `global` section.
fn start_proxy_cfg(global_extra: &str, fe_extra: &str) -> Proxy {
    let backend = spawn_drip_backend();
    let dir = tempfile::TempDir::new().expect("dir");
    let stats = dir.path().join("s.sock");
    let cfg = dir.path().join("c.cfg");
    let port = common::reserve_port();
    std::fs::write(
        &cfg,
        format!(
            "global\n\tstats socket {} level admin\n{global_extra}\
             defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\ttimeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port} proto h2\n{fe_extra}\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend}\n",
            stats.display()
        ),
    )
    .expect("write config");
    let child = Command::new(binary()).arg("-f").arg(&cfg).arg("-db").stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    assert!(wait_for_port(port), "the proxy never listened on {port}");
    Proxy { child, port, stats, _dir: dir }
}

impl Proxy {
    /// A client connection: the preface and a SETTINGS frame with `settings`.
    fn client(&self, settings: &[(u16, u32)]) -> TcpStream {
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).expect("connect");
        let mut payload = Vec::new();
        for &(id, v) in settings {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&v.to_be_bytes());
        }
        s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
        s.write_all(&frame(0x04, 0, 0, &payload)).expect("settings");
        s
    }

    fn cli(&self, cmd: &str) -> String {
        let mut u = std::os::unix::net::UnixStream::connect(&self.stats).expect("stats socket");
        u.write_all(format!("{cmd}\n").as_bytes()).expect("cli");
        let mut out = String::new();
        let _ = u.read_to_string(&mut out);
        out
    }
}

/// Reads frames until `f` says stop or `limit` passes; `f` gets (type, flags, stream, payload).
fn read_frames(s: &mut TcpStream, limit: Duration, mut f: impl FnMut(&mut TcpStream, u8, u8, u32, &[u8]) -> bool) {
    s.set_read_timeout(Some(Duration::from_millis(50))).ok();
    let t0 = Instant::now();
    let (mut buf, mut tmp) = (Vec::new(), [0u8; 16384]);
    while t0.elapsed() < limit {
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let sid = u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]);
            let (ty, flags) = (buf[3], buf[4]);
            let payload = buf[9..9 + len].to_vec();
            buf.drain(..9 + len);
            if f(s, ty, flags, sid, &payload) {
                return;
            }
        }
        match s.read(&mut tmp) {
            Ok(0) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => {}
        }
    }
}

/// Opens `paths` as streams 1, 3, ... in one write and reads until all have ended: the DATA
/// payload of each, by stream.
fn get_all(s: &mut TcpStream, first_id: u32, paths: &[&str]) -> std::collections::BTreeMap<u32, Vec<u8>> {
    let mut burst = Vec::new();
    for (k, p) in paths.iter().enumerate() {
        burst.extend_from_slice(&frame(0x01, 0x05, first_id + 2 * u32::try_from(k).unwrap(), &hpack_get(p)));
    }
    s.write_all(&burst).expect("headers");
    let mut bodies = std::collections::BTreeMap::new();
    let mut ended = 0;
    read_frames(s, Duration::from_secs(5), |_, ty, flags, sid, payload| {
        if ty == 0x00 {
            bodies.entry(sid).or_insert_with(Vec::new).extend_from_slice(payload);
        }
        if (ty == 0x00 || ty == 0x01) && flags & 0x01 != 0 {
            ended += 1;
        }
        ended == paths.len()
    });
    assert_eq!(ended, paths.len(), "not every stream of {paths:?} ended: {bodies:?}");
    bodies
}

/// Round-robin among the streams (`HAProxy`'s `send_list`): a response with a big body
/// does not hold up a small one that came after it, when the connection's window is what
/// limits. The client opens its streams' windows wide and gives the connection back what
/// each DATA frame took, a millisecond later. Measured on `HAProxy` 3.5-dev8-885761-29:
/// stream 3 (/small, 100 bytes, 50 ms late) ends after 0.5-0.6 MB of stream 1's 4 MB.
#[test]
fn a_big_body_does_not_hold_up_a_small_response_behind_it() {
    let p = start_proxy("");
    let mut s = p.client(&[(0x4, 0x7fff_ffff)]);
    let mut burst = frame(0x01, 0x05, 1, &hpack_get("/big"));
    burst.extend_from_slice(&frame(0x01, 0x05, 3, &hpack_get("/small")));
    s.write_all(&burst).expect("headers");
    let (mut big, mut big_at_small_end, mut big_ended) = (0usize, None, false);
    read_frames(&mut s, Duration::from_secs(20), |s, ty, flags, sid, payload| {
        if ty == 0x00 && !payload.is_empty() {
            if sid == 1 {
                big += payload.len();
            }
            thread::sleep(Duration::from_millis(1));
            let inc = u32::try_from(payload.len()).unwrap().to_be_bytes();
            s.write_all(&frame(0x08, 0, 0, &inc)).expect("window update");
        }
        if (ty == 0x00 || ty == 0x01) && flags & 0x01 != 0 {
            if sid == 3 {
                big_at_small_end = Some(big);
            } else {
                big_ended = true;
            }
        }
        big_ended && big_at_small_end.is_some()
    });
    let at = big_at_small_end.expect("stream 3 never ended");
    assert!(
        at < BIG / 2,
        "stream 3 (/small) must end long before stream 1 (/big, {BIG} bytes) has had half its body \
         (HAProxy: after ~0.5 MB); it ended after {at} bytes of stream 1"
    );
}

/// The tracked counters of a connection whose two streams are served one after the other.
fn tracked_counts(concurrent: bool) -> Vec<String> {
    let p = start_proxy(
        "\tstick-table type ip size 10 store http_req_cnt,bytes_in_cnt,bytes_out_cnt\n\
         \ttcp-request connection track-sc0 src\n",
    );
    let mut s = p.client(&[]);
    let bodies = if concurrent {
        get_all(&mut s, 1, &["/slow", "/slow"])
    } else {
        let mut b = get_all(&mut s, 1, &["/slow"]);
        b.append(&mut get_all(&mut s, 3, &["/slow"]));
        b
    };
    assert_eq!(bodies.values().map(Vec::len).collect::<Vec<_>>(), [10, 10]);
    drop(s);
    thread::sleep(Duration::from_millis(300));
    let table = p.cli("show table fe");
    let row = table.lines().find(|l| l.contains("key=127.0.0.1")).unwrap_or_else(|| panic!("{table}"));
    row.split(' ').filter(|f| f.contains("_cnt=")).map(str::to_string).collect()
}

/// The stick counters a connection tracks count the bytes of every stream once, whether
/// its streams are served one after the other or at once (each stream had a copy of the
/// connection's byte accounting and gave its copy back: the bytes before them were counted
/// twice, those of the stream ending first not at all). Measured on `HAProxy`
/// 3.5-dev8-885761-29: `http_req_cnt=2 bytes_in_cnt=132 bytes_out_cnt=164` both ways
/// (Alcyon counts HTTP/2 bytes differently from `HAProxy` -- 91/150 one after the other --
/// which this test does not cover).
#[test]
fn concurrent_streams_credit_the_tracked_bytes_once() {
    let one_by_one = tracked_counts(false);
    assert_eq!(one_by_one[0], "http_req_cnt=2", "{one_by_one:?}");
    assert_eq!(tracked_counts(true), one_by_one, "two streams at once vs one after the other");
}

/// The bytes of a stream that ends before its http rules ran -- here the connection's
/// second stream, refused by `tcp-request content reject` -- are credited to the counters
/// the connection tracks, as every other byte the client sent (T300): the connection's
/// byte accounting moved past them when the stream started, for the stream to credit at its
/// http rules, which never ran, and they were lost. Not run on `HAProxy` (`T280_ORACLE`),
/// which counts HTTP/2 bytes differently (see above): the property is Alcyon's own.
#[test]
fn a_stream_refused_before_its_rules_still_credits_its_bytes() {
    if std::env::var_os("T280_ORACLE").is_some() {
        return;
    }
    let p = start_proxy(
        "\tstick-table type ip size 10 store bytes_in_cnt\n\
         \ttcp-request connection track-sc0 src\n\
         \ttcp-request content reject if { path /bad }\n",
    );
    let mut s = p.client(&[]);
    let mut sent = 24 + 9;
    get_all(&mut s, 1, &["/fast"]);
    sent += 9 + hpack_get("/fast").len();
    let bad = frame(0x01, 0x05, 3, &hpack_get("/bad"));
    s.write_all(&bad).expect("headers");
    sent += bad.len();
    read_frames(&mut s, Duration::from_secs(2), |_, _, _, _, _| false);
    drop(s);
    thread::sleep(Duration::from_millis(300));
    let table = p.cli("show table fe");
    let row = table.lines().find(|l| l.contains("key=127.0.0.1")).unwrap_or_else(|| panic!("{table}"));
    assert!(row.contains(&format!(" bytes_in_cnt={sent}")), "every byte the client sent ({sent}): {row}");
}

/// A session variable a stream unsets is gone for the connection's next streams too (the
/// stream gives back what it changed, unsets included). Measured on `HAProxy`
/// 3.5-dev8-885761-29 (`T280_ORACLE=haproxy`).
#[test]
fn a_session_variable_unset_by_a_stream_is_gone_for_the_next() {
    let p = start_proxy(
        "\thttp-request set-var(sess.a) str(one) if { query a }\n\
         \thttp-request unset-var(sess.a) if { query u }\n\
         \thttp-request return status 200 content-type text/plain lf-string \"<%[var(sess.a)]>\" if { path /vars }\n",
    );
    let mut s = p.client(&[]);
    get_all(&mut s, 1, &["/slow?a"]);
    assert_eq!(String::from_utf8_lossy(&get_all(&mut s, 3, &["/vars"])[&3]), "<one>");
    get_all(&mut s, 5, &["/slow?u"]);
    assert_eq!(String::from_utf8_lossy(&get_all(&mut s, 7, &["/vars"])[&7]), "<>");
}

/// What the client sees of a stream whose session is killed (`shutdown sessions server`)
/// while its response drips: frames until then, never the response's end, and nothing more
/// on the stream after a moment. Measured on `HAProxy` 3.5-dev8-885761-29 (`T280_ORACLE=`):
/// `RST_STREAM REFUSED_STREAM` for the stream, the connection kept, logged `KC--` before
/// the response; Alcyon ends the whole connection (per-stream semantics: T280 stage 4).
#[test]
fn a_stream_whose_session_is_killed_never_ends_its_response() {
    let p = start_proxy("");
    let mut s = p.client(&[]);
    s.write_all(&frame(0x01, 0x05, 1, &hpack_get("/drip"))).expect("headers");
    thread::sleep(Duration::from_millis(400));
    let out = p.cli("shutdown sessions server be/s1");
    let mut data_after = 0;
    let t0 = Instant::now();
    let mut ended = false;
    read_frames(&mut s, Duration::from_secs(2), |_, ty, flags, sid, payload| {
        ended |= sid == 1 && matches!(ty, 0x00 | 0x01) && flags & 1 != 0;
        if ty == 0x00 && t0.elapsed() > Duration::from_millis(500) {
            data_after += payload.len();
        }
        false
    });
    assert!(!ended && data_after == 0, "killed: the response must stop ({out:?}): ended {ended}, {data_after} bytes later");
}

/// A connection error while a stream waits on its server (a `WINDOW_UPDATE` of 0 on the
/// connection): `GOAWAY PROTOCOL_ERROR`, the connection ends, the stream with it. Measured
/// on `HAProxy` 3.5-dev8-885761-29 (`T280_ORACLE=`): `GOAWAY` (last stream 1, code 1),
/// `RST_STREAM NO_ERROR`, FIN, logged `400 ... CD--`. Alcyon: `GOAWAY` (last stream 0, code 1)
/// then a TCP reset, logged `-1 ... IH--` (T280 stage 4).
#[test]
fn a_connection_error_under_a_stream_ends_both() {
    let p = start_proxy("");
    let mut s = p.client(&[]);
    s.write_all(&frame(0x01, 0x05, 1, &hpack_get("/drip"))).expect("headers");
    thread::sleep(Duration::from_millis(400));
    s.write_all(&frame(0x08, 0, 0, &[0, 0, 0, 0])).expect("window update");
    let mut goaway = None;
    read_frames(&mut s, Duration::from_secs(2), |_, ty, _, _, payload| {
        if ty == 0x07 {
            goaway = Some(u32::from_be_bytes(payload[4..8].try_into().expect("code")));
        }
        false
    });
    assert_eq!(goaway, Some(1), "GOAWAY PROTOCOL_ERROR");
    s.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let end = s.read(&mut [0u8; 64]);
    assert!(matches!(end, Ok(0)) || end.as_ref().is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset), "the connection has ended: {end:?}");
}

/// A stream refused by `tcp-request content reject` (after its inspect delay) while another
/// stream of its connection drips its response: the refused one gets no response, the other
/// its head at once. Measured on `HAProxy` 3.5-dev8-885761-29 (`T280_ORACLE=`): at the
/// delay, `RST_STREAM` on stream 1 and `GOAWAY ENHANCE_YOUR_CALM` (last stream 3), and
/// stream 3 is served to its end. Alcyon ends the whole connection there, stream 3 with it
/// (its owner is freed with the stream still attached, which then ends as when its client
/// leaves): per-stream semantics are T280 stage 4.
#[test]
fn a_stream_rejected_beside_a_dripping_one_gets_no_response() {
    let p = start_proxy("\ttcp-request inspect-delay 1s\n\ttcp-request content reject if { path /bad } WAIT_END\n");
    let mut s = p.client(&[]);
    s.write_all(&frame(0x01, 0x05, 1, &hpack_get("/bad"))).expect("headers");
    thread::sleep(Duration::from_millis(100));
    s.write_all(&frame(0x01, 0x05, 3, &hpack_get("/drip"))).expect("headers");
    let mut heads = Vec::new();
    let t0 = Instant::now();
    read_frames(&mut s, Duration::from_millis(1500), |_, ty, _, sid, _| {
        if ty == 0x01 {
            heads.push((sid, t0.elapsed()));
        }
        false
    });
    assert_eq!(heads.iter().map(|h| h.0).collect::<Vec<_>>(), [3], "a head for stream 3 only: {heads:?}");
    assert!(heads[0].1 < Duration::from_millis(500), "stream 3 is not held by stream 1's rules: {heads:?}");
}

/// Session variables set by a connection's streams are kept for its next streams, served
/// one after the other or at once (a stream's entry was freed with its variables in the
/// running stream's map, so none came back; served at once, the last copy back would win).
/// Measured on `HAProxy` 3.5-dev8-885761-29: `one-two` both ways.
#[test]
fn session_variables_set_by_streams_are_kept_for_the_next() {
    let p = start_proxy(
        "\thttp-request set-var(sess.a) str(one) if { query a }\n\
         \thttp-request set-var(sess.b) str(two) if { query b }\n\
         \thttp-request return status 200 content-type text/plain lf-string \"%[var(sess.a)]-%[var(sess.b)]\" if { path /vars }\n",
    );
    let mut s = p.client(&[]);
    get_all(&mut s, 1, &["/slow?a"]);
    get_all(&mut s, 3, &["/slow?b"]);
    let bodies = get_all(&mut s, 5, &["/vars"]);
    assert_eq!(String::from_utf8_lossy(&bodies[&5]), "one-two", "one after the other");
    let mut s = p.client(&[]);
    get_all(&mut s, 1, &["/slow?a", "/slow?b"]);
    let bodies = get_all(&mut s, 5, &["/vars"]);
    assert_eq!(String::from_utf8_lossy(&bodies[&5]), "one-two", "at once");
}

/// The client's `SETTINGS_MAX_CONCURRENT_STREAMS` limits the streams the proxy would open
/// (pushes), not the client's: with 1, two requests are still served at once. Measured on
/// `HAProxy` 3.5-dev8-885761-29.
#[test]
fn the_clients_stream_limit_does_not_limit_its_own_streams() {
    let p = start_proxy("");
    let mut s = p.client(&[(0x3, 1)]);
    let mut burst = frame(0x01, 0x05, 1, &hpack_get("/drip"));
    burst.extend_from_slice(&frame(0x01, 0x05, 3, &hpack_get("/fast")));
    s.write_all(&burst).expect("headers");
    let mut frames = Vec::new();
    read_frames(&mut s, BOUND, |_, ty, flags, sid, payload| {
        frames.push((ty, flags, sid, payload.len()));
        ty == 0x00 && sid == 3 && flags & 1 != 0
    });
    assert!(
        frames.iter().any(|&(ty, fl, sid, _)| ty == 0 && sid == 3 && fl & 1 != 0),
        "stream 3 (/fast) must end within {BOUND:?}: (type, flags, stream, len) {frames:?}"
    );
}

/// What the client sees of its connection after one request: the frame types that came,
/// and how it ended ("eof", "reset", or "open" at `limit`).
fn connection_end(rule: &str, limit: Duration) -> (Vec<u8>, &'static str) {
    let p = start_proxy(&format!("\t{rule}\n"));
    let mut s = p.client(&[]);
    s.write_all(&frame(0x01, 0x05, 1, &hpack_get("/fast"))).expect("headers");
    s.set_read_timeout(Some(Duration::from_millis(50))).ok();
    let (t0, mut buf, mut tmp) = (Instant::now(), Vec::new(), [0u8; 4096]);
    let end = loop {
        if t0.elapsed() > limit {
            break "open";
        }
        match s.read(&mut tmp) {
            Ok(0) => break "eof",
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break "reset",
            Err(_) => {}
        }
    };
    let mut types = Vec::new();
    let mut at = 0;
    while buf.len() >= at + 9 {
        let len = (usize::from(buf[at]) << 16) | (usize::from(buf[at + 1]) << 8) | usize::from(buf[at + 2]);
        types.push(buf[at + 3]);
        at += 9 + len;
    }
    (types, end)
}

/// A stream's `tcp-request content reject` gets no response and its connection ends (the
/// stream's entry asks its connection's owner to end it, T280). Measured on `HAProxy`
/// 3.5-dev8-885761-29: `SETTINGS` x2, `RST_STREAM`, `GOAWAY`, then FIN. Alcyon resets the TCP
/// connection instead (no `RST_STREAM`, no `GOAWAY`): per-stream semantics are T280 stage 4.
#[test]
fn a_stream_rejected_by_tcp_request_content_ends_its_connection() {
    let (types, end) = connection_end("tcp-request content reject", Duration::from_secs(2));
    assert!(!types.contains(&0x1), "no HEADERS for a rejected stream: {types:?}");
    assert_ne!(end, "open", "{types:?}");
}

/// A stream's `tcp-request content silent-drop` gets no response. Measured on `HAProxy`
/// 3.5-dev8-885761-29: `SETTINGS` x2, `RST_STREAM`, and the connection stays open. Alcyon drops
/// the whole connection (a TCP reset on loopback): T280 stage 4.
#[test]
fn a_stream_silently_dropped_by_tcp_request_content_gets_no_response() {
    let (types, _) = connection_end("tcp-request content silent-drop", Duration::from_secs(2));
    assert!(!types.contains(&0x1), "no HEADERS for a dropped stream: {types:?}");
}

/// The `SETTINGS_MAX_CONCURRENT_STREAMS` the proxy advertises first, and the frames it
/// sends for streams `1, 3, 5` opened at once on a slow backend (type, stream, payload).
fn advertised_and_refused(p: &Proxy) -> (Option<u32>, Vec<(u8, u32, Vec<u8>)>) {
    let mut s = p.client(&[]);
    let mut burst = Vec::new();
    for id in [1u32, 3, 5] {
        burst.extend_from_slice(&frame(0x01, 0x05, id, &hpack_get("/drip")));
    }
    s.write_all(&burst).expect("headers");
    let (mut mcs, mut seen) = (None, Vec::new());
    read_frames(&mut s, Duration::from_millis(1000), |_, ty, flags, sid, payload| {
        if ty == 0x04 && flags & 1 == 0 && mcs.is_none() {
            mcs = payload.chunks(6).find(|c| c[..2] == [0, 3]).map(|c| u32::from_be_bytes([c[2], c[3], c[4], c[5]]));
        }
        seen.push((ty, sid, payload.to_vec()));
        false
    });
    (mcs, seen)
}

fn assert_limit_two(p: &Proxy) {
    let (mcs, seen) = advertised_and_refused(p);
    assert_eq!(mcs, Some(2), "the advertised SETTINGS_MAX_CONCURRENT_STREAMS: {seen:?}");
    let rst: Vec<_> = seen.iter().filter(|f| f.0 == 0x03).collect();
    assert_eq!(rst.len(), 1, "exactly one RST_STREAM: {seen:?}");
    assert_eq!((rst[0].1, rst[0].2.as_slice()), (5, &[0, 0, 0, 7][..]), "REFUSED_STREAM on the third: {seen:?}");
    for id in [1, 3] {
        assert!(seen.iter().any(|f| f.0 == 0x01 && f.1 == id), "stream {id} is served: {seen:?}");
    }
}

/// Measured on `HAProxy` 3.5-dev8-885761-29 (`T280_ORACLE=haproxy`): with the limit 2 the
/// SETTINGS frame carries 2 and the third stream gets RST_STREAM(REFUSED_STREAM), the
/// first two being served.
#[test]
fn the_global_limit_is_advertised_and_enforced() {
    assert_limit_two(&start_proxy_cfg("\ttune.h2.max-concurrent-streams 2\n", ""));
}

/// `tune.h2.fe.max-concurrent-streams` wins over the global one on a frontend.
#[test]
fn the_frontend_limit_overrides_the_global_one() {
    assert_limit_two(&start_proxy_cfg("\ttune.h2.max-concurrent-streams 50\n\ttune.h2.fe.max-concurrent-streams 2\n", ""));
}

/// The default stays 100.
#[test]
fn the_default_limit_is_100() {
    let (mcs, _) = advertised_and_refused(&start_proxy(""));
    assert_eq!(mcs, Some(100));
}

/// `tune.h2.max-concurrent-streams 0` (measured on `HAProxy`): no limit is advertised in
/// SETTINGS and every stream is refused (RST_STREAM REFUSED_STREAM).
#[test]
fn a_zero_global_limit_refuses_every_stream() {
    let (mcs, seen) = advertised_and_refused(&start_proxy_cfg("\ttune.h2.max-concurrent-streams 0\n", ""));
    assert_eq!(mcs, None, "no SETTINGS_MAX_CONCURRENT_STREAMS is sent: {seen:?}");
    let rst: Vec<_> = seen.iter().filter(|f| f.0 == 0x03).map(|f| (f.1, f.2.clone())).collect();
    assert_eq!(rst, vec![(1, vec![0, 0, 0, 7]), (3, vec![0, 0, 0, 7]), (5, vec![0, 0, 0, 7])], "{seen:?}");
}

/// `tune.h2.fe.max-concurrent-streams 0` falls back to the global value (measured).
#[test]
fn a_zero_frontend_limit_falls_back_to_the_global_one() {
    assert_limit_two(&start_proxy_cfg("\ttune.h2.max-concurrent-streams 2\n\ttune.h2.fe.max-concurrent-streams 0\n", ""));
}
