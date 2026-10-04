// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `sc_*`, `sc[0-9]_*` and `src_*` fetches read the stick-table entry they name.
//!
//! Before this they read `SampleContext` fields that were mostly never filled, and where a
//! slot was empty they fell back to an unrelated global: `sc_conn_cnt(1)` with nothing
//! tracked in slot 1 answered the *connection's* counter (0, not "no sample"), a table
//! argument was ignored, and every `src_*` fetch read the same fields as the `sc_*` ones.
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29, 2026-10-03, on [`CFG`], one request per path on
//! its own connection (the values below are in the order of [`FMT`]):
//!
//! * a slot nothing is tracked in gives **no sample** (`a=`), not 0;
//! * `sc_conn_cnt(0,<table>)` looks the same key up in `<table>`: a **0** when it has no
//!   entry for it (even if the table does not store the type), **no sample** when the table's
//!   key type differs from the tracked table's (`i=`);
//! * `src_*(<table>)` looks the client's address up in `<table>`: **0** when there is no
//!   entry, **no sample** when there is one and the table does not store that data type
//!   (`x=`, `E=`, `D=`), and the stored value otherwise.
//!
//! ```text
//! /q0 a= b= c= d= e= f= g= h= i= j= k= l= m= o= p= q= r= s=0 t=0 u=0 v=0 w=0 x=0 y=0 z=0 A= B= C=0 D= E=0
//! /q1 a=1 b= c=1 d= e=1 f=1 g=0 h=0 i= j=1 k=1 l=1 m=0 o=0 p= q= r= s=1 t=1 u=0 v=0 w=0 x=0 y=1 z=0 A=0 B=0 C=1 D= E=
//! /q1 a=2 b= c=2 d= e=2 f=2 g=0 h=0 i= j=1 k=2 l=2 m=0 o=0 p= q= r= s=2 t=2 u=0 v=0 w=0 x=0 y=2 z=0 A=0 B=0 C=1 D= E=
//! /q2 a=3 b=1 c=3 d=1 e=3 f=3 g=0 h=0 i= j=1 k=3 l=3 m=0 o=0 p= q= r=1 s=3 t=3 u=0 v=0 w=0 x=0 y=3 z=0 A=0 B=0 C=1 D= E=
//! /q3 a= b= c= d= e= f= g=0 h=0 i= j= k= l= m= o= p= q= r= s=3 t=3 u=0 v=0 w=0 x= y=3 z=0 A= B= C=0 D= E=
//! /q0 a= b= c= d= e= f= g= h= i= j= k= l= m= o= p= q= r= s=3 t=3 u=0 v=0 w=0 x= y=3 z=0 A= B= C=0 D= E=
//! ```

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

// The configuration file stays until the daemon is stopped.
struct Ibex(Child, #[allow(dead_code)] NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(cfg: &str, fe: SocketAddr) -> Ibex {
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
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
        thread::sleep(Duration::from_millis(20));
    }
    Ibex(child, f)
}

fn body(addr: SocketAddr, path: &str) -> String {
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(format!("GET {path} HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    out.split_once("\r\n\r\n").map_or(String::new(), |(_, b)| b.to_string())
}

const FMT: &str = "a=%[sc_conn_cnt(0)] b=%[sc_conn_cnt(1)] c=%[sc0_conn_cnt] d=%[sc1_conn_cnt] \
e=%[sc_http_req_cnt(0)] f=%[sc0_http_req_cnt] g=%[sc_conn_cnt(0,t3)] h=%[sc_http_req_cnt(0,t3)] \
i=%[sc_conn_cnt(0,t2)] j=%[sc_conn_cur(0)] k=%[sc0_conn_rate] l=%[sc_http_req_rate(0)] \
m=%[sc_http_err_cnt(0)] o=%[sc_sess_cnt(0)] p=%[sc2_conn_cnt] q=%[sc_conn_cnt(2)] r=%[sc1_http_req_cnt] \
s=%[src_conn_cnt(t1)] t=%[src_http_req_cnt(t1)] u=%[src_conn_cnt(t2)] v=%[src_conn_cnt(t3)] \
w=%[src_http_req_cnt(t3)] x=%[src_conn_cnt(t4)] y=%[src_conn_rate(t1)] z=%[src_http_err_cnt(t1)] \
A=%[sc_kbytes_in(0)] B=%[sc_kbytes_out(0)] C=%[src_conn_cur(t1)] D=%[sc_http_err_rate(0)] E=%[src_http_err_rate(t1)]";

#[test]
fn sc_and_src_fetches_read_the_entry_they_name() {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         backend t1\n  stick-table type ip size 100 expire 1m store conn_cnt,conn_cur,conn_rate(10s),http_req_cnt,http_req_rate(10s),http_err_cnt,sess_cnt,bytes_in_cnt,bytes_out_cnt\n\
         backend t2\n  stick-table type string len 10 size 100 expire 1m store conn_cnt,http_req_cnt\n\
         backend t3\n  stick-table type ip size 100 expire 1m store conn_cnt,gpc0_rate(10s),server_id\n\
         backend t4\n  stick-table type ip size 100 expire 1m store gpc0\n\
         frontend fe\n  bind {fe}\n  \
         http-request track-sc0 src table t1 if {{ path /q1 }}\n  \
         http-request track-sc0 src table t1 if {{ path /q2 }}\n  \
         http-request track-sc0 src table t4 if {{ path /q3 }}\n  \
         http-request track-sc1 str(k) table t2 if {{ path /q2 }}\n  \
         http-request return status 200 content-type text/plain lf-string \"{FMT}\"\n"
    );
    let _ibex = start(&cfg, fe);
    let steps = [
        ("/q0", "a= b= c= d= e= f= g= h= i= j= k= l= m= o= p= q= r= s=0 t=0 u=0 v=0 w=0 x=0 y=0 z=0 A= B= C=0 D= E=0"),
        ("/q1", "a=1 b= c=1 d= e=1 f=1 g=0 h=0 i= j=1 k=1 l=1 m=0 o=0 p= q= r= s=1 t=1 u=0 v=0 w=0 x=0 y=1 z=0 A=0 B=0 C=1 D= E="),
        ("/q1", "a=2 b= c=2 d= e=2 f=2 g=0 h=0 i= j=1 k=2 l=2 m=0 o=0 p= q= r= s=2 t=2 u=0 v=0 w=0 x=0 y=2 z=0 A=0 B=0 C=1 D= E="),
        ("/q2", "a=3 b=1 c=3 d=1 e=3 f=3 g=0 h=0 i= j=1 k=3 l=3 m=0 o=0 p= q= r=1 s=3 t=3 u=0 v=0 w=0 x=0 y=3 z=0 A=0 B=0 C=1 D= E="),
        ("/q3", "a= b= c= d= e= f= g=0 h=0 i= j= k= l= m= o= p= q= r= s=3 t=3 u=0 v=0 w=0 x= y=3 z=0 A= B= C=0 D= E="),
        ("/q0", "a= b= c= d= e= f= g= h= i= j= k= l= m= o= p= q= r= s=3 t=3 u=0 v=0 w=0 x= y=3 z=0 A= B= C=0 D= E="),
    ];
    let mut wrong = Vec::new();
    for (path, want) in steps {
        // The tracking request's own connection is released a moment after its response.
        thread::sleep(Duration::from_millis(30));
        let got = body(fe, path);
        if got != want {
            let diff: Vec<String> = got
                .split(' ')
                .zip(want.split(' '))
                .filter(|(g, w)| g != w)
                .map(|(g, w)| format!("{g} (HAProxy: {w})"))
                .collect();
            wrong.push(format!("{path}: {}", diff.join(", ")));
        }
    }
    assert!(wrong.is_empty(), "values that differ from HAProxy's:\n{}", wrong.join("\n"));
}

/// An expression that gives no sample tracks nothing (`track-sc0 req.hdr(x-key)` on a request
/// without the header): no slot is tracked, no entry is made, and `sc0_*` has no sample.
///
/// `HAProxy`, same version and date, a string table `ts` and `http-request track-sc0
/// req.hdr(x-key) table ts`, reading `a=%[sc0_conn_cnt] b=%[str(k1),in_table(ts)]
/// c=%[src,in_table(ts)]` on three requests (no header, `x-key: k1`, no header):
///
/// ```text
/// a= b=0 c=0
/// a=1 b=1 c=0
/// a= b=1 c=0
/// ```
///
/// Ibex fell back to tracking the client's address (`c=1` on the first request).
#[test]
fn an_expression_with_no_sample_tracks_nothing() {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         backend ts\n  stick-table type string len 20 size 10 expire 1m store conn_cnt\n\
         frontend fe\n  bind {fe}\n  http-request track-sc0 req.hdr(x-key) table ts\n  \
         http-request return status 200 content-type text/plain lf-string \
         \"a=%[sc0_conn_cnt] b=%[str(k1),in_table(ts)] c=%[src,in_table(ts)]\"\n"
    );
    let _ibex = start(&cfg, fe);
    let get = |hdr: &str| {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        c.write_all(format!("GET / HTTP/1.1\r\nhost: a\r\n{hdr}connection: close\r\n\r\n").as_bytes()).expect("send");
        let mut out = String::new();
        let _ = c.read_to_string(&mut out);
        out.split_once("\r\n\r\n").map_or(String::new(), |(_, b)| b.to_string())
    };
    assert_eq!(get(""), "a= b=0 c=0", "no header: nothing tracked");
    assert_eq!(get("x-key: k1\r\n"), "a=1 b=1 c=0", "with the header: k1 tracked");
    assert_eq!(get(""), "a= b=1 c=0", "no header again: still nothing tracked, k1 stays");
}

/// Every scope that can track an entry, in every slot: `tcp-request connection`, `session`,
/// `content` and `http-request`, each with `track-sc1 src table t1` and `track-sc2 src table
/// t2`, on its own frontend, two requests each on their own connection.
///
/// `HAProxy`, same version and date, reading `c0=%[sc0_conn_cnt] c1=%[sc1_conn_cnt]
/// c2=%[sc2_conn_cnt] r1=%[sc1_http_req_cnt] r2=%[sc2_http_req_cnt] s1=%[sc1_sess_cnt]
/// k1=%[sc_conn_cur(1)] k2=%[sc2_conn_cur] t1=%[src_conn_cnt(t1)] t2=%[src_conn_cnt(t2)]`:
///
/// ```text
/// connection c0= c1=1 c2=1 r1=1 r2=1 s1=1 k1=1 k2=1 t1=1 t2=1
/// connection c0= c1=2 c2=2 r1=2 r2=2 s1=2 k1=1 k2=1 t1=2 t2=2
/// session    c0= c1=3 c2=3 r1=3 r2=3 s1=3 k1=1 k2=1 t1=3 t2=3
/// session    c0= c1=4 c2=4 r1=4 r2=4 s1=4 k1=1 k2=1 t1=4 t2=4
/// content    c0= c1=5 c2=5 r1=5 r2=5 s1=4 k1=1 k2=1 t1=5 t2=5
/// content    c0= c1=6 c2=6 r1=6 r2=6 s1=4 k1=1 k2=1 t1=6 t2=6
/// http       c0= c1=7 c2=7 r1=7 r2=7 s1=4 k1=1 k2=1 t1=7 t2=7
/// http       c0= c1=8 c2=8 r1=8 r2=8 s1=4 k1=1 k2=1 t1=8 t2=8
/// ```
///
/// A session counts (`sess_cnt`) where it is tracked at connection or session scope, and not
/// at content or request scope; Ibex counted it nowhere.
#[test]
fn every_scope_tracks_slots_one_and_two() {
    let scopes = [
        ("connection", "tcp-request connection"),
        ("session", "tcp-request session"),
        ("content", "tcp-request content"),
        ("http", "http-request"),
    ];
    let fmt = "c0=%[sc0_conn_cnt] c1=%[sc1_conn_cnt] c2=%[sc2_conn_cnt] r1=%[sc1_http_req_cnt] \
r2=%[sc2_http_req_cnt] s1=%[sc1_sess_cnt] k1=%[sc_conn_cur(1)] k2=%[sc2_conn_cur] \
t1=%[src_conn_cnt(t1)] t2=%[src_conn_cnt(t2)]";
    let mut cfg = String::from(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         backend t1\n  stick-table type ip size 10 expire 1m store conn_cnt,conn_cur,http_req_cnt,sess_cnt\n\
         backend t2\n  stick-table type ip size 10 expire 1m store conn_cnt,conn_cur,http_req_cnt,sess_cnt\n",
    );
    let addrs: Vec<SocketAddr> = scopes.iter().map(|_| common::reserve_addr()).collect();
    for ((name, rule), addr) in scopes.iter().zip(&addrs) {
        cfg.push_str(&format!(
            "frontend fe_{name}\n  bind {addr}\n  {rule} track-sc1 src table t1\n  {rule} track-sc2 src table t2\n  \
             http-request return status 200 content-type text/plain lf-string \"{fmt}\"\n"
        ));
    }
    // The start-up probe goes to a frontend of its own: a connection to one of these would be
    // counted in the entries read below.
    let probe = common::reserve_addr();
    cfg.push_str(&format!("frontend probe\n  bind {probe}\n  http-request return status 200\n"));
    let _ibex = start(&cfg, probe);
    let want = [
        "c0= c1=1 c2=1 r1=1 r2=1 s1=1 k1=1 k2=1 t1=1 t2=1",
        "c0= c1=2 c2=2 r1=2 r2=2 s1=2 k1=1 k2=1 t1=2 t2=2",
        "c0= c1=3 c2=3 r1=3 r2=3 s1=3 k1=1 k2=1 t1=3 t2=3",
        "c0= c1=4 c2=4 r1=4 r2=4 s1=4 k1=1 k2=1 t1=4 t2=4",
        "c0= c1=5 c2=5 r1=5 r2=5 s1=4 k1=1 k2=1 t1=5 t2=5",
        "c0= c1=6 c2=6 r1=6 r2=6 s1=4 k1=1 k2=1 t1=6 t2=6",
        "c0= c1=7 c2=7 r1=7 r2=7 s1=4 k1=1 k2=1 t1=7 t2=7",
        "c0= c1=8 c2=8 r1=8 r2=8 s1=4 k1=1 k2=1 t1=8 t2=8",
    ];
    let mut wrong = Vec::new();
    let mut i = 0;
    for ((name, _), addr) in scopes.iter().zip(&addrs) {
        for _ in 0..2 {
            // The previous request's connection is released a moment after its response.
            thread::sleep(Duration::from_millis(30));
            let got = body(*addr, "/");
            if got != want[i] {
                wrong.push(format!("{name}: got {got:?}, HAProxy gives {:?}", want[i]));
            }
            i += 1;
        }
    }
    assert!(wrong.is_empty(), "values that differ from HAProxy's:\n{}", wrong.join("\n"));
}
