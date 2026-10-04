// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A stream that stops tracking an entry releases it (T139): `sc_trackers`/`table_trackers` and
//! `conn_cur` go back down when the connection closes, when a `tcp-request connection reject`
//! ends it, and when a rule moves a slot to another key.
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29, 2026-10-04, with [`CFG`]: a client that sends
//! `PROXY TCP4 198.51.100.7 ...` and a request to `px` leaves, once it has closed, no tracker
//! and no connection on the peer's entry (`table_trackers`, `table_conn_cur` of 127.0.0.1: 0,0;
//! while it was open: 1,1; the three further numbers are the entries a rule would have moved to), and a connection that `rej` rejects leaves none either (0,0).
//! `HAProxy` tracks the peer only (`http-request track-sc0` does not move a slot that already
//! tracks); Ibex moves the slot to the PROXY address, a divergence that this test does not
//! look at: it reads what both leave behind.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

struct Ibex(Child, #[allow(dead_code)] NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(cfg: &str, wait_on: SocketAddr) -> Ibex {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(wait_on).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening on {wait_on}");
        thread::sleep(Duration::from_millis(20));
    }
    Ibex(child, f)
}

const CFG: &str = r####"defaults
mode http
timeout client 5s
timeout server 5s
timeout connect 5s
backend t
stick-table type ip size 10 expire 1m store conn_cur,conn_cnt,http_req_cnt
frontend px
bind @PX@ accept-proxy
tcp-request connection track-sc0 src table t
http-request track-sc0 src table t
http-request return status 200 content-type text/plain lf-string "%[src]"
frontend rej
bind @REJ@
tcp-request connection track-sc0 src table t
tcp-request connection reject
backend ts
stick-table type string len 8 size 10 expire 1m store conn_cur,conn_cnt
frontend mv
bind @MV@
tcp-request connection track-sc0 src table t
tcp-request connection track-sc1 src table t
tcp-request connection track-sc2 src table t
http-request track-sc0 str(a) table ts
http-request track-sc1 str(b) table ts
http-request track-sc2 str(c) table ts
http-request return status 200
frontend rd
bind @RD@
http-request return status 200 content-type text/plain lf-string "%[ipv4(127.0.0.1),table_trackers(t)],%[ipv4(127.0.0.1),table_conn_cur(t)],%[str(a),table_trackers(ts)],%[str(b),table_conn_cur(ts)],%[str(c),table_trackers(ts)]"
"####;

fn peer_state(rd: SocketAddr) -> String {
    let mut c = TcpStream::connect(rd).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(b"GET / HTTP/1.1\r\nHost: t139\r\nConnection: close\r\n\r\n").expect("send");
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    out.split_once("\r\n\r\n").map_or(String::new(), |(_, b)| b.to_string())
}

/// The state of the peer's entry as `rd` reads it, until it is `want` or a second has passed.
fn settles_to(rd: SocketAddr, want: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let got = peer_state(rd);
        if got == want || Instant::now() > deadline {
            return got;
        }
        thread::sleep(Duration::from_millis(30));
    }
}

#[test]
fn a_closed_connection_a_rejected_one_and_a_moved_slot_release_their_entry() {
    let [px, rej, mv, rd, ready] = std::array::from_fn(|_| common::reserve_addr());
    let cfg = CFG
        .replace("@PX@", &px.to_string())
        .replace("@REJ@", &rej.to_string())
        .replace("@MV@", &mv.to_string())
        .replace("@RD@", &rd.to_string())
        + &format!("frontend ready\n  bind {ready}\n  http-request return status 200\n");
    let _ibex = start(&cfg, ready);

    // A connection with a PROXY header, one request, then closed.
    let mut c = TcpStream::connect(px).expect("connect px");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(b"PROXY TCP4 198.51.100.7 10.0.0.1 1234 80\r\nGET /x HTTP/1.1\r\nHost: t139\r\n\r\n").expect("send");
    let mut buf = [0u8; 512];
    let n = c.read(&mut buf).expect("read");
    assert!(String::from_utf8_lossy(&buf[..n]).contains("198.51.100.7"), "the PROXY address is the source");
    drop(c);
    assert_eq!(settles_to(rd, "0,0,0,0,0"), "0,0,0,0,0", "a closed connection releases the peer's entry");

    // Three slots that a rule moves to another key (`HAProxy` leaves them where they are, which
    // leaves the same counters once the connection is closed: none).
    let mut c = TcpStream::connect(mv).expect("connect mv");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(b"GET /x HTTP/1.1\r\nHost: t139\r\n\r\n").expect("send");
    let _ = c.read(&mut buf).expect("read");
    drop(c);
    assert_eq!(settles_to(rd, "0,0,0,0,0"), "0,0,0,0,0", "slots moved to other keys release the first ones, and all go at the end");

    // A connection that a `reject` rule ends.
    drop(TcpStream::connect(rej).expect("connect rej"));
    assert_eq!(settles_to(rd, "0,0,0,0,0"), "0,0,0,0,0", "a rejected connection releases its entry");
}
