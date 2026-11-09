// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A per-connection receive budget lets the windows open wide (T313 item 2, VV-11).
//!
//! `HAProxy` (`mux_h2.c` `h2c_update_strm_rx_win`, `h2c_send_conn_wu`) bounds what a
//! connection buffers by a budget of receive buffers (`tune.h2.fe.rxbuf`, at least one per
//! allowed stream), and inside it grows the window of a stream that receives and opens the
//! connection window to 2 GB at the first update. Measured on 3.5-dev8-885761-29 (one POST,
//! 64 KB of DATA sent at once, `tools/battery/repro/vv-h2mux`'s probe):
//!
//! ```text
//!   SETTINGS (8,1) (4,16384) (3,100)
//!   WINDOW_UPDATE sid=1 +1409024     <- the stream window, grown once the body starts
//!   WINDOW_UPDATE sid=0 +2147434496  <- the connection window, opened wide
//!   then +16384 per 16 KB consumed
//! ```
//!
//! Alcyon sent the connection 32 KB at a time, so a client with several uploads waited a round
//! trip (and a delayed ACK, ~40 ms) for every 32 KB. That the budget holds -- a backend that
//! reads nothing cannot make the connection hold more -- is `mux_h2`'s unit test and the
//! `h2_mux` fuzz target; through a socket the server's kernel buffers hide it.

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn binary() -> String {
    std::env::var("T280_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
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

/// `POST /up` on `localhost`, the head only (the body follows as DATA).
fn hpack_post() -> Vec<u8> {
    let mut v = vec![0x83, 0x86, 0x04, 3];
    v.extend_from_slice(b"/up");
    v.push(0x01);
    v.push(9);
    v.extend_from_slice(b"localhost");
    v
}

/// A backend that reads and discards, and answers `ok` when a request body has come.
fn spawn_reading_backend() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = l.local_addr().expect("addr").port();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            thread::spawn(move || {
                let mut tmp = [0u8; 65536];
                loop {
                    match c.read(&mut tmp) {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                }
            });
        }
    });
    port
}

struct Proxy {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn start(backend: u16) -> Proxy {
    let dir = tempfile::TempDir::new().expect("dir");
    let cfg = dir.path().join("c.cfg");
    let port = common::reserve_port();
    std::fs::write(
        &cfg,
        format!(
            "global\n\tnbthread 1\n\ndefaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\ttimeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port} proto h2\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend}\n"
        ),
    )
    .expect("write config");
    let child = Command::new(binary()).arg("-f").arg(&cfg).arg("-db").stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the proxy never listened on {port}");
        thread::sleep(Duration::from_millis(25));
    }
    Proxy { child, port, _dir: dir }
}

fn connect(port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    // The probe writes a frame at a time: Nagle on its own side would add the stalls.
    s.set_nodelay(true).expect("nodelay");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");
    s
}

/// Reads frames for `limit`, handing each (type, flags, stream, payload) to `f`. What is
/// left of a partial frame stays in `buf` for the next call.
fn read_frames_buf(s: &mut TcpStream, buf: &mut Vec<u8>, limit: Duration, mut f: impl FnMut(u8, u8, u32, &[u8])) {
    s.set_read_timeout(Some(Duration::from_millis(1))).ok();
    let t0 = Instant::now();
    let mut tmp = [0u8; 65536];
    loop {
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let sid = u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]);
            let (ty, flags) = (buf[3], buf[4]);
            f(ty, flags, sid, &buf[9..9 + len]);
            buf.drain(..9 + len);
        }
        if t0.elapsed() >= limit {
            return;
        }
        match s.read(&mut tmp) {
            Ok(0) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => {}
        }
    }
}

fn read_frames(s: &mut TcpStream, limit: Duration, f: impl FnMut(u8, u8, u32, &[u8])) {
    read_frames_buf(s, &mut Vec::new(), limit, f);
}

fn wu_increment(p: &[u8]) -> u64 {
    u64::from(u32::from_be_bytes([p[0] & 0x7f, p[1], p[2], p[3]]))
}

/// The windows a connection is given once a body starts to flow: the stream's well past the
/// default 64 KB, the connection's to (nearly) 2 GB; the sum of what the stream is granted
/// stays within the budget (HAProxy: 1.4 MB of a 1.6 MB budget).
#[test]
fn a_receiving_stream_gets_a_wide_window_and_the_connection_an_open_one() {
    let p = start(spawn_reading_backend());
    let mut s = connect(p.port);
    s.write_all(&frame(0x01, 0x04, 1, &hpack_post())).expect("headers");
    for _ in 0..4 {
        s.write_all(&frame(0x00, 0, 1, &[b'x'; 16384])).expect("data");
    }
    let (mut stream_wu, mut conn_wu) = (0u64, 0u64);
    read_frames(&mut s, Duration::from_millis(600), |ty, _, sid, pl| {
        if ty == 0x08 {
            if sid == 1 {
                stream_wu += wu_increment(pl);
            } else if sid == 0 {
                conn_wu += wu_increment(pl);
            }
        }
    });
    // 64 KB were sent: the stream's credit is what it was given back plus the growth.
    assert!(stream_wu >= 1 << 20, "stream window grants {stream_wu} bytes (HAProxy: 1409024+), want at least 1 MiB");
    assert!(stream_wu <= 2 << 20, "stream window grants {stream_wu} bytes, more than the budget (1.6 MB) allows");
    assert!(conn_wu >= 1 << 30, "connection window grants {conn_wu} bytes (HAProxy: 2147434496+), want at least 1 GiB");
}

/// The VV-11 round: `streams` POSTs of 256 KB on one h2c connection, each sent as its
/// stream and connection windows allow; the time until every stream is answered.
fn upload_round(s: &mut TcpStream, buf: &mut Vec<u8>, first_id: u32, streams: u32) -> Duration {
    let ids: Vec<u32> = (0..streams).map(|k| first_id + 2 * k).collect();
    let t0 = Instant::now();
    let mut out = Vec::new();
    for &id in &ids {
        out.extend_from_slice(&frame(0x01, 0x04, id, &hpack_post()));
    }
    let mut credit: std::collections::HashMap<u32, i64> = ids.iter().map(|&i| (i, 65535)).collect();
    let mut left: std::collections::HashMap<u32, usize> = ids.iter().map(|&i| (i, 256 * 1024)).collect();
    let mut conn_credit = CONN_CREDIT.with(std::cell::Cell::get);
    let mut ended = 0;
    while ended < ids.len() {
        assert!(t0.elapsed() < Duration::from_secs(5), "the round did not finish");
        for &id in &ids {
            while left[&id] > 0 {
                let n = left[&id].min(16384);
                if credit[&id] < n as i64 || conn_credit < n as i64 {
                    break;
                }
                let last = n == left[&id];
                out.extend_from_slice(&frame(0x00, u8::from(last), id, &vec![b'u'; n]));
                *credit.get_mut(&id).unwrap() -= n as i64;
                *left.get_mut(&id).unwrap() -= n;
                conn_credit -= n as i64;
            }
        }
        if !out.is_empty() {
            s.write_all(&out).expect("write");
            out.clear();
        }
        read_frames_buf(s, buf, Duration::from_millis(1), |ty, flags, sid, pl| {
            if ty == 0x08 {
                let inc = i64::try_from(wu_increment(pl)).unwrap();
                if sid == 0 {
                    conn_credit += inc;
                } else if let Some(c) = credit.get_mut(&sid) {
                    *c += inc;
                }
            } else if (ty == 0x00 || ty == 0x01) && flags & 1 != 0 && sid != 0 && ids.contains(&sid) {
                ended += 1;
            }
        });
    }
    CONN_CREDIT.with(|c| c.set(conn_credit));
    t0.elapsed()
}

thread_local! {
    static CONN_CREDIT: std::cell::Cell<i64> = const { std::cell::Cell::new(65535) };
}

/// A backend that answers each request once its body has come: `ok`, by chunked framing.
fn spawn_answering_backend() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = l.local_addr().expect("addr").port();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            thread::spawn(move || {
                let mut tmp = [0u8; 65536];
                let mut tail: Vec<u8> = Vec::new();
                loop {
                    let n = match c.read(&mut tmp) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    // The last chunk ends the request; only the end of what came is looked at.
                    tail.extend_from_slice(&tmp[n.saturating_sub(5)..n]);
                    if tail.ends_with(b"0\r\n\r\n") {
                        tail.clear();
                        if c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").is_err() {
                            return;
                        }
                    }
                    if tail.len() > 5 {
                        tail.drain(..tail.len() - 5);
                    }
                }
            });
        }
    });
    port
}

fn rounds(bin: &str, streams: u32) -> Vec<Duration> {
    CONN_CREDIT.with(|c| c.set(65535));
    let backend = spawn_answering_backend();
    let dir = tempfile::TempDir::new().expect("dir");
    let cfg = dir.path().join("c.cfg");
    let port = common::reserve_port();
    std::fs::write(
        &cfg,
        format!(
            "global\n\tnbthread 1\n\ndefaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\ttimeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port} proto h2\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend}\n"
        ),
    )
    .expect("write config");
    let child = Command::new(bin).arg("-f").arg(&cfg).arg("-db").stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let _p = Proxy { child, port, _dir: dir };
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the proxy never listened on {port}");
        thread::sleep(Duration::from_millis(25));
    }
    let mut s = connect(port);
    let mut buf = Vec::new();
    (0..8).map(|r| { thread::sleep(Duration::from_millis(30)); upload_round(&mut s, &mut buf, 1 + 2 * r * streams, streams) }).collect()
}

/// VV-11: four concurrent 256 KB uploads on one h2 connection. `HAProxy` takes 7 ms every
/// round (2 GB connection window, 1.4 MB stream windows); Alcyon granted the connection 32 KB
/// at a time and about half its rounds stalled 40 ms and more (Nagle and the client's delayed
/// ACK on the small writes). Every round must come within a few of the oracle's, measured
/// here on the reference binary when it is there (`T280_ORACLE` unset), else a floor.
#[test]
fn four_concurrent_uploads_do_not_stall() {
    let oracle = std::path::Path::new("/home/bhenc/reference/haproxy/haproxy");
    let reference = if std::env::var_os("T280_ORACLE").is_none() && oracle.exists() {
        let mut r = rounds(oracle.to_str().unwrap(), 4);
        r.sort();
        r[r.len() / 2]
    } else {
        Duration::ZERO
    };
    let bound = (reference * 3).max(Duration::from_millis(30));
    let r = rounds(&binary(), 4);
    let worst = r.iter().max().copied().unwrap();
    assert!(worst <= bound, "round times {r:?}: the worst is above {bound:?} (the oracle's median is {reference:?})");
}
