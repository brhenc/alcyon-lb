// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `glitch_cnt` and `glitch_rate` count the glitches of an HTTP/2 connection (T149b).
//!
//! Measured on HAProxy 3.5-dev8-885761-29: a `proto h2` frontend with
//! `tcp-request connection track-sc0 src` and a table storing `glitch_cnt,glitch_rate(10s)`;
//! a client that opens five streams (HEADERS without END_STREAM) and resets each (RST_STREAM,
//! CANCEL) leaves `glitch_cnt=5 glitch_rate(10000)=5` on its entry.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

fn frame(ty: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    f.extend_from_slice(&[ty, flags]);
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

struct Ibex(Child, NamedTempFile, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_file(&self.2);
    }
}

fn start(rules: &str) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let be = common::reserve_addr();
    let sock = std::env::temp_dir().join(format!("ibex_t149b_g_{}_{}.sock", std::process::id(), fe.port()));
    let text = format!(
        "global\n  nbthread 1\n  stats socket {sock} mode 600 level admin\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe} proto h2\n  stick-table type ip size 100 expire 60s store glitch_cnt,glitch_rate(10s),http_req_cnt\n{rules}  default_backend b\nbackend b\n  server s1 {be}\n",
        sock = sock.display()
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let ibex = Ibex(child, f, sock);
    assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !ibex.2.exists() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    (ibex, fe)
}

fn show_table(ibex: &Ibex) -> String {
    let mut s = UnixStream::connect(&ibex.2).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(b"show table f\n").expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// Opens `n` streams and resets each; returns the connection, still open.
fn glitchy_client(fe: SocketAddr, n: u32) -> TcpStream {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_millis(300))).expect("timeout");
    let headers = [0x82, 0x86, 0x84, 0x41, 0x01, 0x78]; // GET http / x
    let mut d = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    d.extend(frame(4, 0, 0, &[]));
    for i in 0..n {
        let sid = 1 + 2 * i;
        d.extend(frame(1, 4, sid, &headers));
        d.extend(frame(3, 0, sid, &8u32.to_be_bytes()));
    }
    c.write_all(&d).expect("send frames");
    let mut buf = [0u8; 4096];
    let _ = c.read(&mut buf);
    c
}

#[test]
fn reset_streams_count_as_glitches_on_the_tracked_entry() {
    let (ibex, fe) = start("  tcp-request connection track-sc0 src\n");
    let _c = glitchy_client(fe, 5);
    thread::sleep(Duration::from_millis(300));
    let out = show_table(&ibex);
    assert!(out.contains("glitch_cnt=5 glitch_rate(10000)=5"), "{out}");
}

#[test]
fn a_connection_with_no_glitch_counts_none() {
    let (ibex, fe) = start("  tcp-request connection track-sc0 src\n");
    let _c = glitchy_client(fe, 0);
    thread::sleep(Duration::from_millis(300));
    let out = show_table(&ibex);
    assert!(out.contains("glitch_cnt=0 glitch_rate(10000)=0"), "{out}");
}
