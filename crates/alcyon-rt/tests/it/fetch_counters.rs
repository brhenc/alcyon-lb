// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `fe_conn`, `fe_sess_rate`, `fe_req_rate`, `be_sess_rate`, `srv_sess_rate` and `fe_defbe`,
//! against the real binary, with the values `HAProxy` gives for the same traffic.
//!
//! Before this, `fe_conn(<fe>)` ignored its argument and read the connection's own proxy,
//! `fe_sess_rate`, `be_sess_rate` and `srv_sess_rate` all read one `conn_rate` field nothing
//! filled (always 0), `fe_req_rate` read another, and `fe_defbe` returned the *current
//! backend's* name.
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29, 2026-10-03, on [`CFG`] (one Python server behind
//! both backends), reading frontend `st` after each step:
//!
//! ```text
//! 1  nothing yet        besr=0 s1=0 fesr=0 fereq=0 stsr=1 stq=1 bsr2=0 defbe=[]
//! 2  3 connections      besr=3 s1=3 fesr=3 fereq=3 stsr=2 stq=2 bsr2=0 defbe=[]
//! 3  1 connection, 3 requests (keep-alive)
//!                       besr=6 s1=6 fesr=4 fereq=6 stsr=3 stq=3 bsr2=0 defbe=[]
//! 4  2 requests answered by the frontend itself (no backend)
//!                       besr=6 s1=6 fesr=5 fereq=8 stsr=4 stq=4 bsr2=0 defbe=[]
//! 5  2 connections held open, read on `other`
//!                       defbe=be2 fe=2 ot=1 otsr=1 ac=4   (`act_conn`: every frontend's
//!                       connections, with one still being closed)
//! 6  both closed        fe=0
//! ```
//!
//! A rate is a count over the last second (`HAProxy`'s frequency counter), so a scenario that
//! took longer than that to run is run again.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

// The configuration file stays until the daemon is stopped.
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

/// Sends `n` requests for `path` on one connection and returns the bodies.
fn get(addr: SocketAddr, path: &str, n: usize) -> Vec<String> {
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut out = Vec::new();
    for _ in 0..n {
        c.write_all(format!("GET {path} HTTP/1.1\r\nhost: a\r\n\r\n").as_bytes()).expect("send");
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            c.read_exact(&mut byte).expect("read head");
            buf.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&buf).to_ascii_lowercase();
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .map_or(0, |v| v.trim().parse().expect("content-length"));
        let mut body = vec![0u8; len];
        c.read_exact(&mut body).expect("read body");
        out.push(String::from_utf8_lossy(&body).into_owned());
    }
    out
}

fn cfg(fe: SocketAddr, st: SocketAddr, other: SocketAddr, probe: SocketAddr, srv: SocketAddr) -> String {
    format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe}\n  \
         http-request return status 200 content-type text/plain string own if {{ path /own }}\n  \
         default_backend be\n\
         frontend st\n  bind {st}\n  http-request return status 200 content-type text/plain lf-string \
         \"besr=%[be_sess_rate(be)] s1=%[srv_sess_rate(be/s1)] fesr=%[fe_sess_rate(fe)] \
         fereq=%[fe_req_rate(fe)] stsr=%[fe_sess_rate(st)] stq=%[fe_req_rate(st)] \
         bsr2=%[be_sess_rate(be2)] defbe=[%[fe_defbe]]\"\n\
         frontend other\n  bind {other}\n  default_backend be2\n  http-request return status 200 \
         content-type text/plain lf-string \
         \"defbe=%[fe_defbe] fe=%[fe_conn(fe)] ot=%[fe_conn(other)] otsr=%[fe_sess_rate(other)] ac=%[act_conn]\"\n\
         frontend probe\n  bind {probe}\n  http-request return status 200\n\
         backend be\n  server s1 {srv}\n\
         backend be2\n  server s1 {srv}\n"
    )
}

/// One run of the scenario; `Err` if it took long enough for the rates to decay.
fn scenario(srv: SocketAddr) -> Result<(), String> {
    let (fe, st, other, probe) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    // The start-up probe goes to a frontend of its own: a connection to one of the others
    // would be a session in the rates read below.
    let _alcyon = start(&cfg(fe, st, other, probe, srv), probe);
    let t0 = Instant::now();
    let read_st = || get(st, "/", 1).remove(0);
    let settle = || thread::sleep(Duration::from_millis(50));

    let mut got = vec![read_st()];
    for _ in 0..3 {
        get(fe, "/", 1);
    }
    settle();
    got.push(read_st());
    get(fe, "/", 3);
    settle();
    got.push(read_st());
    get(fe, "/own", 2);
    settle();
    got.push(read_st());
    let rates_took = t0.elapsed();

    let held: Vec<TcpStream> = (0..2).map(|_| TcpStream::connect(fe).expect("hold")).collect();
    settle();
    let five = get(other, "/", 1).remove(0);
    drop(held);
    // Closing is seen by the proxy a moment later.
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut six = get(other, "/", 1).remove(0);
    while !six.contains("fe=0 ") && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
        six = get(other, "/", 1).remove(0);
    }
    // The rates are over the last second: a run that took longer than that to get here
    // cannot be compared with HAProxy's.
    if rates_took > Duration::from_millis(800) {
        return Err("too slow".into());
    }

    let want = [
        "besr=0 s1=0 fesr=0 fereq=0 stsr=1 stq=1 bsr2=0 defbe=[]",
        "besr=3 s1=3 fesr=3 fereq=3 stsr=2 stq=2 bsr2=0 defbe=[]",
        "besr=6 s1=6 fesr=4 fereq=6 stsr=3 stq=3 bsr2=0 defbe=[]",
        "besr=6 s1=6 fesr=5 fereq=8 stsr=4 stq=4 bsr2=0 defbe=[]",
    ];
    let mut bad = Vec::new();
    for (i, (g, w)) in got.iter().zip(want).enumerate() {
        if g != w {
            bad.push(format!("step {}: got {g:?}, HAProxy gives {w:?}", i + 1));
        }
    }
    if !five.starts_with("defbe=be2 fe=2 ot=1 otsr=1") {
        bad.push(format!("step 5 (two connections held open): got {five:?}, HAProxy gives \"defbe=be2 fe=2 ot=1 otsr=1\""));
    }
    // `act_conn` is the connections of every frontend: `HAProxy` gave 4 here (the two held,
    // this one, and one still being closed). It is not the connection's own proxy's count.
    let ac: i64 = five.rsplit("ac=").next().and_then(|v| v.trim().parse().ok()).unwrap_or(-1);
    if ac < 3 {
        bad.push(format!("step 5: act_conn is {ac} in {five:?}; two connections held on fe and this one on other make at least 3"));
    }
    if !six.starts_with("defbe=be2 fe=0 ") {
        bad.push(format!("step 6 (both closed): got {six:?}, HAProxy gives fe=0"));
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(bad.join("\n"))
    }
}

#[test]
fn frontend_backend_and_server_counters_follow_the_traffic() {
    let srv = backend();
    let mut last = String::new();
    for _ in 0..3 {
        match scenario(srv) {
            Ok(()) => return,
            Err(e) if e == "too slow" => last = e,
            Err(e) => panic!("{e}"),
        }
    }
    panic!("the scenario never ran inside one second: {last}");
}

/// `fe_defbe` is the frontend's own `default_backend`, wherever it is read; with none it
/// gives no sample.
#[test]
fn fe_defbe_is_the_default_backend_of_the_frontend() {
    let srv = backend();
    let (a, b, c) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend a\n  bind {a}\n  default_backend x\n  use_backend y if {{ path /y }}\n  \
         http-response set-header x-defbe %[fe_defbe]\n\
         frontend b\n  bind {b}\n  default_backend y\n  http-response set-header x-defbe %[fe_defbe]\n\
         frontend c\n  bind {c}\n  use_backend x if {{ path /x }}\n  http-response set-header x-defbe \"[%[fe_defbe]]\"\n\
         backend x\n  server s {srv}\nbackend y\n  server s {srv}\n"
    );
    let _alcyon = start(&cfg, c);
    let hdr = |addr: SocketAddr, path: &str| -> String {
        let mut conn = TcpStream::connect(addr).expect("connect");
        conn.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        conn.write_all(format!("GET {path} HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n").as_bytes()).expect("send");
        let mut out = String::new();
        let _ = conn.read_to_string(&mut out);
        out.lines().find_map(|l| l.strip_prefix("x-defbe: ")).unwrap_or("<absent>").to_string()
    };
    assert_eq!(hdr(a, "/"), "x", "a: default_backend x");
    assert_eq!(hdr(a, "/y"), "x", "a, routed to y by use_backend: still the frontend's default");
    assert_eq!(hdr(b, "/"), "y", "b: default_backend y");
    assert_eq!(hdr(c, "/x"), "[]", "c: no default_backend");
}
