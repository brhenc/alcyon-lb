// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! An HTTP/2 request body larger than the 65535-byte initial window (T195). `HAProxy
//! 3.5-dev8-885761-29` passes 1 MB over h2 (cleartext and TLS) intact to an HTTP/1 server;
//! the client must be granted window with WINDOW_UPDATE as the body drains.
//!
//! Set `H2_LARGE_BIN` to run the same cases against another binary (the oracle).

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::{NamedTempFile, TempDir};

struct Ibex(Child, NamedTempFile, TempDir);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + i / 251) % 256) as u8).collect()
}

/// An HTTP/1 server: reads the head, waits `stall`, reads `content-length` bytes of body,
/// answers `ok` and sends the body to the test.
fn server(stall: Duration) -> (SocketAddr, Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = channel();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let tx = tx.clone();
            thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(10))).ok();
                let mut got = Vec::new();
                let mut buf = vec![0u8; 65536];
                let mut stalled = false;
                loop {
                    let split = got.windows(4).position(|w| w == b"\r\n\r\n");
                    if let Some(at) = split {
                        if !stalled {
                            stalled = true;
                            thread::sleep(stall);
                        }
                        let head = String::from_utf8_lossy(&got[..at]).to_ascii_lowercase();
                        let len = head.split("content-length: ").nth(1).and_then(|r| r.split("\r\n").next()).and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
                        if got.len() - at - 4 >= len {
                            break;
                        }
                    }
                    let Ok(n) = c.read(&mut buf) else { break };
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
                let at = got.windows(4).position(|w| w == b"\r\n\r\n").map_or(got.len(), |a| a + 4);
                let _ = tx.send(got[at..].to_vec());
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            });
        }
    });
    (addr, rx)
}

fn start(stall: Duration) -> (Ibex, SocketAddr, SocketAddr, Receiver<Vec<u8>>) {
    let dir = TempDir::new().expect("dir");
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let pem = dir.path().join("c.pem");
    std::fs::write(&pem, format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem())).expect("pem");
    let (plain, tls) = (common::reserve_addr(), common::reserve_addr());
    let (srv, rx) = server(stall);
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 3s\n  timeout server 3s\n\
         frontend fe\n  bind {plain} proto h2\n  bind {tls} ssl crt {} alpn h2,http/1.1\n  default_backend be\n\
         backend be\n  server s {srv}\n",
        pem.display()
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let bin = std::env::var("H2_LARGE_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let mut cmd = Command::new(&bin);
    if bin.contains("haproxy") {
        cmd.arg("-db");
    }
    let child = cmd.arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let ibex = Ibex(child, f, dir);
    assert!(common::wait_listening(plain) && common::wait_listening(tls), "never listened:\n{cfg}");
    (ibex, plain, tls, rx)
}

fn frame(kind: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn literal(name: &str, value: &str) -> Vec<u8> {
    let mut v = vec![0, name.len() as u8];
    v.extend_from_slice(name.as_bytes());
    v.push(value.len() as u8);
    v.extend_from_slice(value.as_bytes());
    v
}

/// What a raw client saw: the 200 arrived, and how many body bytes it had sent at `probe`.
struct Outcome {
    ok: bool,
    sent_at_probe: usize,
}

/// POST `body` over cleartext h2, sending DATA only as far as the server's windows allow.
/// `my_window` is the SETTINGS_INITIAL_WINDOW_SIZE the client advertises (None: default).
fn post(fe: SocketAddr, body: &[u8], my_window: Option<u32>, probe: Duration) -> Outcome {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(20))).ok();
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    let settings = my_window.map_or(Vec::new(), |w| [&[0u8, 4][..], &w.to_be_bytes()].concat());
    s.write_all(&frame(4, 0, 0, &settings)).expect("settings");
    let mut h = Vec::new();
    for (n, v) in [(":method", "POST"), (":scheme", "http"), (":authority", "x"), (":path", "/up"), ("content-length", &body.len().to_string())] {
        h.extend(literal(n, v));
    }
    s.write_all(&frame(1, 4, 1, &h)).expect("head");
    let (mut conn_win, mut stream_win, mut initial) = (65535i64, 65535i64, 65535i64);
    let (mut sent, mut at_probe, mut ok) = (0usize, None, false);
    let (t0, deadline) = (Instant::now(), Instant::now() + Duration::from_secs(20));
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = vec![0u8; 65536];
    while Instant::now() < deadline && !ok {
        if at_probe.is_none() && t0.elapsed() >= probe {
            at_probe = Some(sent);
        }
        while sent < body.len() && conn_win > 0 && stream_win > 0 {
            let n = (body.len() - sent).min(16384).min(conn_win as usize).min(stream_win as usize);
            let last = sent + n == body.len();
            if s.write_all(&frame(0, u8::from(last), 1, &body[sent..sent + n])).is_err() {
                break;
            }
            sent += n;
            conn_win -= n as i64;
            stream_win -= n as i64;
        }
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
            let (kind, flags, sid) = (buf[3], buf[4], u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]));
            let pl = buf[9..9 + len].to_vec();
            buf.drain(..9 + len);
            match kind {
                4 if flags & 1 == 0 => {
                    for c in pl.chunks(6) {
                        if c.len() == 6 && c[1] == 4 {
                            let w = i64::from(u32::from_be_bytes([c[2], c[3], c[4], c[5]]));
                            stream_win += w - initial;
                            initial = w;
                        }
                    }
                    let _ = s.write_all(&frame(4, 1, 0, &[]));
                }
                8 => {
                    let inc = i64::from(u32::from_be_bytes([pl[0] & 0x7f, pl[1], pl[2], pl[3]]));
                    if sid == 0 {
                        conn_win += inc;
                    } else if sid == 1 {
                        stream_win += inc;
                    }
                }
                1 if sid == 1 && pl.first() == Some(&0x88) => ok = true,
                3 | 7 => return Outcome { ok: false, sent_at_probe: at_probe.unwrap_or(sent) },
                _ => {}
            }
        }
    }
    Outcome { ok, sent_at_probe: at_probe.unwrap_or(sent) }
}

fn expect_body(rx: &Receiver<Vec<u8>>, want: &[u8]) {
    let got = rx.recv_timeout(Duration::from_secs(15)).expect("the server saw a request");
    assert_eq!(got.len(), want.len(), "body length at the server");
    assert!(got == want, "body content differs");
}

#[test]
fn one_megabyte_cleartext_default_window() {
    let (_i, plain, _tls, rx) = start(Duration::ZERO);
    let body = pattern(1_000_000);
    let o = post(plain, &body, None, Duration::from_secs(1));
    assert!(o.ok, "no 200 (client had sent {} bytes at 1 s)", o.sent_at_probe);
    expect_body(&rx, &body);
}

#[test]
fn one_megabyte_cleartext_small_client_window() {
    let (_i, plain, _tls, rx) = start(Duration::ZERO);
    let body = pattern(1_000_000);
    let o = post(plain, &body, Some(1000), Duration::from_secs(1));
    assert!(o.ok, "no 200 (client had sent {} bytes at 1 s)", o.sent_at_probe);
    expect_body(&rx, &body);
}

#[test]
fn one_megabyte_over_tls() {
    let (_i, _plain, tls, rx) = start(Duration::ZERO);
    let body = pattern(1_000_000);
    let f = NamedTempFile::new().expect("tmp");
    std::fs::write(f.path(), &body).expect("body");
    let out = Command::new("curl")
        .args(["-sSk", "--http2", "-m", "15", "-X", "POST", "--data-binary"])
        .arg(format!("@{}", f.path().display()))
        .args(["-w", " [rc=%{exitcode} http=%{http_version} code=%{http_code}]"])
        .arg(format!("https://{tls}/up"))
        .output()
        .expect("curl");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(text.ends_with("[rc=0 http=2 code=200]"), "{text} {}", String::from_utf8_lossy(&out.stderr));
    expect_body(&rx, &body);
}

/// The server does not read for 1.5 s after the head. The proxy must stop granting window
/// instead of buffering without bound: the client's bytes out at 1 s are printed (and
/// bounded), then the whole body still arrives.
#[test]
fn slow_server_applies_backpressure() {
    let (_i, plain, _tls, rx) = start(Duration::from_millis(1500));
    let body = pattern(32_000_000);
    let o = post(plain, &body, None, Duration::from_secs(1));
    eprintln!("sent at the 1 s probe, server not reading: {}", o.sent_at_probe);
    assert!(o.sent_at_probe < 16_000_000, "{} bytes buffered while the server did not read", o.sent_at_probe);
    assert!(o.ok, "no 200");
    expect_body(&rx, &body);
}
