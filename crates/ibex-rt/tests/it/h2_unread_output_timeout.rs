// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! An HTTP/2 client that opens its windows wide and then reads nothing is let go at the
//! second `timeout client`, at no CPU cost (T288, the red team's MY-3 from `h2_wu_storm`).
//!
//! `HAProxy` 3.5-dev8 sends a GOAWAY at the first expiry and, at the second, tries one
//! more GOAWAY and releases the connection (`h2_timeout_task`, "try to send but no need to
//! insist", then `h2_release`). Ibex queued that second GOAWAY and kept the connection
//! until the output had drained -- never, with this client -- and the timer it left
//! expired fired again on every pass: a core spinning and a GOAWAY more queued each time
//! (the battery's 300 % / +110 MB for the seconds until the attackers were killed).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The process, and its configuration file, kept until the process is stopped.
struct Proxy(Child, #[allow(dead_code)] tempfile::NamedTempFile);

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

impl Proxy {
    /// CPU time (user + system, clock ticks) the proxy has used so far.
    fn cpu_ticks(&self) -> u64 {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.0.id())).expect("read /proc stat");
        let rest = &stat[stat.rfind(')').expect("comm") + 2..];
        let f: Vec<&str> = rest.split_whitespace().collect();
        f[11].parse::<u64>().expect("utime") + f[12].parse::<u64>().expect("stime")
    }
}

/// A server that answers every request head with a 64 MB body, written until the proxy
/// stops taking it or lets the connection go.
fn big_backend() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            std::thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(30))).ok();
                c.set_write_timeout(Some(Duration::from_secs(30))).ok();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut tmp) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                if c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 67108864\r\n\r\n").is_err() {
                    return;
                }
                let chunk = vec![b'y'; 65536];
                for _ in 0..1024 {
                    if c.write_all(&chunk).is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// Starts ibex, one thread, `timeout client 1s`, a cleartext h2 bind.
fn start(backend: SocketAddr) -> (Proxy, SocketAddr) {
    let fe = common::reserve_addr();
    let cfg = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(
        cfg.path(),
        format!(
            "global\n\tnbthread 1\n\
             defaults\n\tmode http\n\ttimeout connect 2s\n\ttimeout client 1s\n\ttimeout server 30s\n\n\
             frontend fe\n\tbind {fe} proto h2\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 {backend}\n"
        ),
    )
    .expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(cfg.path())
        .arg("-db")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let p = Proxy(child, cfg);
    assert!(common::wait_listening(fe), "ibex never listened on {fe}");
    (p, fe)
}

fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame fits");
    let mut v = len.to_be_bytes()[1..].to_vec();
    v.push(ftype);
    v.push(flags);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Reads to the end of the connection, or `wait`: whether it ended, and how many GOAWAY
/// frames came.
fn read_to_end(s: &mut TcpStream, wait: Duration) -> (bool, usize) {
    let start = Instant::now();
    let mut buf = Vec::new();
    let mut tmp = vec![0u8; 1 << 16];
    let mut goaways = 0;
    let mut ended = false;
    s.set_read_timeout(Some(Duration::from_millis(100))).ok();
    while start.elapsed() < wait {
        match s.read(&mut tmp) {
            Ok(0) => {
                ended = true;
                break;
            }
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => {
                ended = true;
                break;
            }
        }
        let mut at = 0;
        while buf.len() >= at + 9 {
            let len = (usize::from(buf[at]) << 16) | (usize::from(buf[at + 1]) << 8) | usize::from(buf[at + 2]);
            if buf.len() < at + 9 + len {
                break;
            }
            goaways += usize::from(buf[at + 3] == 0x07);
            at += 9 + len;
        }
        buf.drain(..at);
    }
    (ended, goaways)
}

/// A client that reads nothing, with `streams` GETs open on its connection.
fn let_go_at_the_second_timeout_client(streams: u32) {
    let (p, fe) = start(big_backend());
    let mut s = TcpStream::connect(fe).expect("connect");
    let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    hello.extend(frame(0x04, 0, 0, &[]));
    // Windows opened as wide as they go without overflowing (65535 + this = 2^31 - 1).
    let inc = (0x7fff_ffffu32 - 65535).to_be_bytes();
    hello.extend(frame(0x08, 0, 0, &inc));
    for id in (0..streams).map(|k| 1 + 2 * k) {
        // GET / (static table: :method GET, :scheme http, :path /), :authority x.
        hello.extend(frame(0x01, 0x05, id, &[0x82, 0x86, 0x84, 0x41, 0x01, b'x']));
        hello.extend(frame(0x08, 0, id, &inc));
    }
    s.write_all(&hello).expect("send request");

    // The output fills both socket buffers within a moment; the first expiry is about
    // 1 s later, the second 1 s after that.
    std::thread::sleep(Duration::from_millis(3000));
    let before = p.cpu_ticks();
    std::thread::sleep(Duration::from_millis(1500));
    let spent = p.cpu_ticks() - before;
    assert!(spent < 30, "ibex spent {spent} ticks in 1.5 s on a connection it should have let go");

    let (ended, goaways) = read_to_end(&mut s, Duration::from_secs(10));
    assert!(ended, "the connection is still open past the second timeout client");
    assert!(goaways <= 2, "{goaways} GOAWAY frames for two expiries");
}

#[test]
fn a_client_that_reads_nothing_is_let_go_at_the_second_timeout_client() {
    let_go_at_the_second_timeout_client(1);
}

/// The same with two streams served at once (T280 stage 3b): neither holds the
/// connection's timer off.
#[test]
fn a_client_that_reads_nothing_of_two_streams_is_let_go_too() {
    let_go_at_the_second_timeout_client(2);
}
