// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The HTTP/2 flood-mitigation knobs, matched to `HAProxy`'s.
//!
//! Ibex currently cuts a connection after roughly 650 resets and sends
//! `GOAWAY ENHANCE_YOUR_CALM` with debug data `"RST_STREAM flood detected"`. That closes
//! the amplification, which was the security concern, but it is not what `HAProxy` does
//! and it is not configurable. `HAProxy` ships four controls and **all of them default to
//! off**, because legitimate clients generate `RST_STREAM` — a user pressing Stop in a
//! browser does — and killing those connections is its own failure mode.
//!
//! These tests describe `HAProxy`'s behaviour, from `doc/configuration.txt`:
//!
//! - `tune.h2.fe.max-rst-at-once`: past the limit the connection handler is moved to a
//!   low-priority queue. It is **not** a protocol error, it is load shedding.
//! - `tune.h2.fe.glitches-threshold`: "a graceful close is attempted at 75% of the
//!   configured threshold by advertising a GOAWAY for a future stream. This ensures that a
//!   slightly non-compliant client will have the opportunity to create a new connection
//!   and continue to work unaffected without ever triggering the hard close."
//! - `tune.h2.fe.max-total-streams`: a cap on streams per connection.
//! - Default for each is zero, meaning no limit.
//!
//! Emulating `HAProxy` here is a compatibility decision, not an endorsement of its
//! defaults — see `tradeoff.md` §6.8.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn ibex_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_ibex"))
}


struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(cfg: &std::path::Path) -> Daemon {
    Daemon(
        Command::new(ibex_bin())
            .arg("-f")
            .arg(cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ibex"),
    )
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

fn spawn_backend() -> (u16, Arc<Mutex<usize>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    let count: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    let sink = Arc::clone(&count);
    thread::spawn(move || {
        for conn in listener.incoming().take(64) {
            let Ok(mut c) = conn else { continue };
            let sink = Arc::clone(&sink);
            thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut tmp = [0u8; 4096];
                while let Ok(n) = c.read(&mut tmp) {
                    if n == 0 {
                        break;
                    }
                    *sink.lock().expect("lock") += 1;
                    let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                }
            });
        }
    });
    (port, count)
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

/// `:method GET` (2), `:scheme http` (6), literal `:path` (4) and `:authority` (1).
fn hpack_get(path: &str) -> Vec<u8> {
    let mut v = vec![0x82, 0x86];
    v.push(0x04);
    v.push(u8::try_from(path.len()).expect("short path"));
    v.extend_from_slice(path.as_bytes());
    v.push(0x01);
    v.push(9);
    v.extend_from_slice(b"localhost");
    v
}

/// A parsed GOAWAY: `(last_stream_id, error_code)`.
fn find_goaway(buf: &[u8]) -> Option<(u32, u32)> {
    let mut i = 0usize;
    while i + 9 <= buf.len() {
        let len = usize::from(buf[i]) << 16 | usize::from(buf[i + 1]) << 8 | usize::from(buf[i + 2]);
        let ftype = buf[i + 3];
        if ftype == 0x07 && len >= 8 && i + 9 + 8 <= buf.len() {
            let p = &buf[i + 9..];
            let last = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff;
            let err = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
            return Some((last, err));
        }
        i += 9 + len;
    }
    None
}

/// Drives `n` `HEADERS`+`RST_STREAM` pairs and returns everything the server sent back.
///
/// Returns `Err` with a diagnosis when the connection cannot be established at all, so a
/// failure reads as "h2 is missing" rather than as "the knob is missing".
fn flood(port: u16, n: u32, reset: bool) -> Result<(Vec<u8>, u32), String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok();
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .map_err(|e| e.to_string())?;
    s.write_all(&frame(0x04, 0, 0, &[])).map_err(|e| e.to_string())?;

    let mut sent = 0u32;
    for i in 0..n {
        let sid = 1 + 2 * i;
        if s.write_all(&frame(0x01, 0x05, sid, &hpack_get("/"))).is_err() {
            break;
        }
        if reset && s.write_all(&frame(0x03, 0, sid, &8u32.to_be_bytes())).is_err() {
            break;
        }
        sent += 1;
    }
    let _ = s.flush();

    let mut got = Vec::new();
    let mut tmp = [0u8; 8192];
    while let Ok(r) = s.read(&mut tmp) {
        if r == 0 {
            break;
        }
        got.extend_from_slice(&tmp[..r]);
        if got.len() > 65536 {
            break;
        }
    }
    Ok((got, sent))
}

fn write_cfg(name: &str, body: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("ibex_h2knob_{}_{}", std::process::id(), name));
    std::fs::write(&p, body).expect("write config");
    p
}

fn cfg_with(global: &str, port: u16, backend_port: u16) -> String {
    format!(
        "{global}defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\t\
         timeout server 10s\n\n\
         frontend fe\n\tbind 127.0.0.1:{port}\n\tdefault_backend be\n\n\
         backend be\n\tserver s1 127.0.0.1:{backend_port}\n"
    )
}

/// With no knobs configured, a reset flood must not be killed.
///
/// `HAProxy` defaults every one of these to zero, and says so: a non-zero
/// `glitches-threshold` "should probably be in the hundreds or thousands to be effective
/// without affecting slightly bogus clients". Ibex currently cuts the connection at around
/// 650 with `GOAWAY ENHANCE_YOUR_CALM` regardless of configuration, which is a behaviour
/// no operator asked for and none can turn off.
///
/// This is the test that says the defence must be *configurable*, not that it must be
/// absent. See `tradeoff.md` §6.8 for why we match `HAProxy` here rather than shipping
/// secure-by-default, and why that may change.
#[test]
fn without_configuration_a_reset_flood_is_not_killed() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (backend_port, _seen) = spawn_backend();
    let port = common::reserve_port();
    let cfg = write_cfg("default.cfg", &cfg_with("", port, backend_port));
    let _d = start(&cfg);
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let (got, sent) = flood(port, 2000, true).expect("h2c connection");
    assert!(
        sent > 100,
        "could not drive h2 at all -- only {sent} streams went out. If this is the only \
         failing assertion, HTTP/2 multiplexing is missing from the tree rather than the \
         knob being unimplemented. Check `git stash list`."
    );

    let _ = std::fs::remove_file(&cfg);
    assert_eq!(
        find_goaway(&got),
        None,
        "a connection was killed with no flood limit configured. HAProxy defaults \
         tune.h2.fe.max-rst-at-once, glitches-threshold and max-total-streams to zero, so \
         an unconfigured proxy does not do this. Sent {sent} streams."
    );
}

/// `tune.h2.fe.max-total-streams` caps streams per connection.
#[test]
fn max_total_streams_closes_the_connection_at_the_cap() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (backend_port, _seen) = spawn_backend();
    let port = common::reserve_port();
    let cfg = write_cfg(
        "maxtotal.cfg",
        &cfg_with("global\n\ttune.h2.fe.max-total-streams 50\n\n", port, backend_port),
    );
    let _d = start(&cfg);
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let (got, sent) = flood(port, 500, false).expect("h2c connection");
    assert!(sent > 60, "could not drive enough streams: {sent}");
    let _ = std::fs::remove_file(&cfg);

    let (last, _err) = find_goaway(&got).unwrap_or_else(|| {
        panic!("no GOAWAY after {sent} streams with tune.h2.fe.max-total-streams 50")
    });
    assert!(
        last <= 201,
        "GOAWAY arrived but named last_stream_id {last}, far past the 50-stream cap"
    );
}

/// `tune.h2.fe.glitches-threshold` closes gracefully at 75% before any hard close.
///
/// The graceful phase is the part that matters and the part Ibex does not have. `HAProxy`
/// advertises a GOAWAY **for a future stream** at three quarters of the threshold, so a
/// client that is only slightly non-compliant can open a new connection and keep working
/// while its in-flight transfers finish. Going straight to a hard close interrupts them.
#[test]
fn glitches_threshold_sends_a_graceful_goaway_before_killing() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (backend_port, _seen) = spawn_backend();
    let port = common::reserve_port();
    let cfg = write_cfg(
        "glitches.cfg",
        &cfg_with("global\n\ttune.h2.fe.glitches-threshold 100\n\n", port, backend_port),
    );
    let _d = start(&cfg);
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    // Enough resets to cross 75% of 100 but not to demand a hard close immediately.
    let (got, sent) = flood(port, 90, true).expect("h2c connection");
    assert!(sent >= 80, "could not drive enough streams: {sent}");
    let _ = std::fs::remove_file(&cfg);

    let (last, err) = find_goaway(&got).unwrap_or_else(|| {
        panic!("no GOAWAY after {sent} resets against a threshold of 100; the graceful \
                close at 75% never happened")
    });
    let highest_sent = 1 + 2 * (sent - 1);
    assert!(
        last > highest_sent,
        "the graceful GOAWAY must name a *future* stream id so the client may finish what \
         is in flight and migrate. Got last_stream_id={last} with the highest stream sent \
         being {highest_sent}; naming a past id is a hard close, not a graceful one."
    );
    assert_ne!(
        err, 0x0b,
        "the graceful close at 75% is not an ENHANCE_YOUR_CALM error -- it is a normal \
         GOAWAY advertising a future stream. Error 0xb belongs to the hard close, if at all."
    );
}
