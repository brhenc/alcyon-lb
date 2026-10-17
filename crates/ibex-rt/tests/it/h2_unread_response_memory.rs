// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! An HTTP/2 client that opens its windows to 2^31-1, asks for a large response and reads
//! none of it must not make the proxy hold the response (T342, found by the T243 review).
//!
//! The proxy copies the response into the connection's output only as far as the client's
//! windows AND the room left in the output buffer allow; when the client does not read,
//! the backend is no longer read (backpressure) and the body stays in the kernel's socket
//! buffers. `HAProxy` bounds it by its mux buffer the same way.
//!
//! Measured on this test's shape (one 48 MB GET, the client reads nothing for 3 s; growth
//! of `VmHWM` over the idle process): `HAProxy` 3.5-dev8 +0.3 MB (22 MB flat); Ibex before
//! the fix +47 MB (the whole body), after +0.8 MB. Set `IBEX_H2_RSS_BIN` to run the same test against
//! another binary (the oracle).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const BODY: usize = 48 << 20;

struct Proxy(Child, #[allow(dead_code)] tempfile::NamedTempFile);

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

impl Proxy {
    fn hwm_kb(&self) -> u64 {
        let st = std::fs::read_to_string(format!("/proc/{}/status", self.0.id())).expect("status");
        let l = st.lines().find(|l| l.starts_with("VmHWM")).expect("VmHWM");
        l.split_whitespace().nth(1).expect("value").parse().expect("number")
    }
}

/// Answers every request with a `BODY`-byte response, written until the proxy stops taking it.
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
                if c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {BODY}\r\n\r\n").as_bytes()).is_err() {
                    return;
                }
                let chunk = vec![b'y'; 65536];
                for _ in 0..BODY / chunk.len() {
                    if c.write_all(&chunk).is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn start(backend: SocketAddr) -> (Proxy, SocketAddr) {
    let fe = common::reserve_addr();
    let cfg = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(
        cfg.path(),
        format!(
            "global\n\tnbthread 1\n\
             defaults\n\tmode http\n\ttimeout connect 2s\n\ttimeout client 30s\n\ttimeout server 30s\n\n\
             frontend fe\n\tbind {fe} proto h2\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 {backend}\n"
        ),
    )
    .expect("write config");
    let bin = std::env::var("IBEX_H2_RSS_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin)
        .arg("-f")
        .arg(cfg.path())
        .arg("-db")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn proxy");
    let p = Proxy(child, cfg);
    assert!(common::wait_listening(fe), "the proxy never listened on {fe}");
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

fn get_hello(window: u32) -> Vec<u8> {
    let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    // SETTINGS_INITIAL_WINDOW_SIZE (0x4) = window
    let mut settings = vec![0, 4];
    settings.extend_from_slice(&window.to_be_bytes());
    hello.extend(frame(0x04, 0, 0, &settings));
    hello.extend(frame(0x08, 0, 0, &(0x7fff_ffffu32 - 65535).to_be_bytes()));
    hello.extend(frame(0x01, 0x05, 1, &[0x82, 0x86, 0x84, 0x41, 0x01, b'x']));
    hello
}

#[test]
fn a_client_that_reads_nothing_does_not_make_the_proxy_hold_the_response() {
    let (p, fe) = start(big_backend());
    let idle = p.hwm_kb();
    let mut s = TcpStream::connect(fe).expect("connect");
    s.write_all(&get_hello(0x7fff_ffff)).expect("send request");
    std::thread::sleep(Duration::from_secs(3));
    let grown = p.hwm_kb().saturating_sub(idle);
    eprintln!("peak RSS growth {grown} kB");
    assert!(grown < 12 * 1024, "the proxy's peak RSS grew {grown} kB for a client that reads nothing");
    drop(s);
}

/// Backpressure is lifted when the client reads: the whole body arrives.
#[test]
fn a_client_that_reads_slowly_after_stalling_gets_the_whole_body() {
    let (p, fe) = start(big_backend());
    let mut s = TcpStream::connect(fe).expect("connect");
    s.write_all(&get_hello(0x7fff_ffff)).expect("send request");
    std::thread::sleep(Duration::from_millis(1500));
    s.set_read_timeout(Some(Duration::from_secs(20))).ok();
    let (mut buf, mut tmp) = (Vec::<u8>::new(), vec![0u8; 1 << 16]);
    let (mut data, mut ended) = (0usize, false);
    while !ended {
        let n = s.read(&mut tmp).expect("read");
        assert!(n > 0, "closed after {data} body bytes");
        buf.extend_from_slice(&tmp[..n]);
        let mut at = 0;
        while buf.len() >= at + 9 {
            let len = (usize::from(buf[at]) << 16) | (usize::from(buf[at + 1]) << 8) | usize::from(buf[at + 2]);
            if buf.len() < at + 9 + len {
                break;
            }
            if buf[at + 3] == 0 {
                data += len;
                ended |= buf[at + 4] & 1 != 0;
            }
            at += 9 + len;
        }
        buf.drain(..at);
    }
    assert_eq!(data, BODY);
    drop(p);
}
