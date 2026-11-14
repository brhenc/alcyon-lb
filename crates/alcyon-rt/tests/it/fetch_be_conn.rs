// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `be_conn(<backend>)`: the streams a backend has been given and not finished with
//! (`px->beconn`), against the real binary.
//!
//! It used to be refused at load ("Alcyon does not count the streams on a backend"), which
//! also made `startup/default_rules.vtc` fail: one of the configurations that test requires
//! to load uses it.
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29, 2026-11-14, on [`cfg`]: frontend `st` reads the
//! two backends while requests sent through `fe` wait at a server that has not answered yet.
//!
//! ```text
//! nothing sent              be=0 be2=0
//! two requests held at s1   be=2 be2=0
//! both answered and closed  be=0 be2=0
//! ```

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// A server that answers nothing until `release` is sent, then answers each held request.
fn held_server() -> (SocketAddr, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            held.push(s);
            if held.len() == 2 {
                break;
            }
        }
        let _ = rx.recv_timeout(Duration::from_secs(10));
        for mut s in held {
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    (addr, tx)
}

struct Alcyon(Child, #[allow(dead_code)] NamedTempFile);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(cfg: &str, wait_on: SocketAddr) -> Alcyon {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(wait_on).is_err() {
        assert!(Instant::now() < deadline, "alcyon never started listening on {wait_on}");
        thread::sleep(Duration::from_millis(20));
    }
    Alcyon(child, f)
}

/// One request on its own connection; the body of the answer.
fn read_st(st: SocketAddr) -> String {
    let mut c = TcpStream::connect(st).expect("connect st");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(b"GET / HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n").expect("send");
    let mut out = String::new();
    c.read_to_string(&mut out).expect("read");
    out.split_once("\r\n\r\n").map(|(_, b)| b.to_owned()).unwrap_or_default()
}

fn cfg(fe: SocketAddr, st: SocketAddr, srv: SocketAddr) -> String {
    format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe}\n  default_backend be\n\
         frontend st\n  bind {st}\n  http-request return status 200 content-type text/plain lf-string \
         \"be=%[be_conn(be)] be2=%[be_conn(be2)]\"\n\
         backend be\n  server s1 {srv}\n\
         backend be2\n  server s1 {srv}\n"
    )
}

#[test]
fn be_conn_counts_the_streams_a_backend_has_in_flight() {
    let (srv, release) = held_server();
    let (fe, st) = (common::reserve_addr(), common::reserve_addr());
    let _alcyon = start(&cfg(fe, st, srv), st);

    assert_eq!(read_st(st), "be=0 be2=0", "nothing sent yet");

    let mut held: Vec<TcpStream> = (0..2)
        .map(|_| {
            let mut c = TcpStream::connect(fe).expect("connect fe");
            c.write_all(b"GET / HTTP/1.1\r\nhost: a\r\n\r\n").expect("send");
            c
        })
        .collect();
    // The two requests reach the server, which holds them.
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut two = read_st(st);
    while two != "be=2 be2=0" && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
        two = read_st(st);
    }
    assert_eq!(two, "be=2 be2=0", "two requests held at be's server; HAProxy gives be=2 be2=0");

    release.send(()).expect("release");
    for c in &mut held {
        c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        let mut buf = [0u8; 256];
        let _ = c.read(&mut buf);
    }
    drop(held);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut after = read_st(st);
    while after != "be=0 be2=0" && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
        after = read_st(st);
    }
    assert_eq!(after, "be=0 be2=0", "both answered and closed; HAProxy gives be=0 be2=0");
}
