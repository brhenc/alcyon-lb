// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The fetches and converters that read the proxies' live state -- `nbsrv`, `srv_is_up`,
//! `srv_conn`, `srv_conn_free`, `be_conn_free`, and the converters `nbsrv`, `srv_is_up`,
//! `fe_exists`, `in_table` -- report the servers' real state.
//!
//! Before this they were constants: `srv_is_up` true, `nbsrv` 1, `srv_conn` 0, the `_free`
//! counts 100, `fe_exists` true for any name. So `use_backend spare if { nbsrv(main) lt 1 }`
//! never fired, and `srv_is_up(be/srv)` was true for a dead server.
//!
//! Every expected value here is `HAProxy`'s, measured on 2026-10-03 against `HAProxy`
//! 3.5-dev8-885761-29 with these configurations (the same text, a Python listener as the
//! live server and a closed port as the dead one), after the checks had settled:
//!
//! ```text
//! be (the same fetches in backend be's rules, arguments defaulted):
//!        nb=2 up1=1 up2=0 cup2=0 bcf=-1 scf1=10
//! state: nb=2 nbb=1 up1=1 up2=0 up3=1 up4=1 scf1=10 scf2=-1 bcf=-1 bcfb=4 sc1=0 cnb=1
//!        cnbx= cup=1 cup2=0 cupx= cupy= fex=1 fex2=0 fex3=0 fex4=1
//! fe1 (main1's server DOWN): spare        fe2 (main2's server UP): main2
//! in_table: before tracking src=0 other=0 u=0; on the tracking request src=1; after, src=1
//! in flight (maxconn 5, two requests held by the server): sc=2 scf=3 bcf=3;
//!            idle: sc=0 scf=5 bcf=5
//! ```
//!
//! Read as `HAProxy`'s rules (`be_usable_srv`, `smp_fetch_srv_is_up`, `src/backend.c`):
//! `nbsrv` counts the usable active servers -- UP and with a non-zero weight, so s1 and the
//! unchecked s3, not the DOWN s2 nor the weight-0 s4 -- and only when there are none, 1 if a
//! backup is usable. `srv_is_up` is "not in maintenance, and not DOWN by its check", so the
//! unchecked s3 and the weight-0 s4 are up. A server without `maxconn` has `-1` free
//! connections, and one such usable server makes the backend's count `-1`; among backups
//! only the first usable one counts (`bcfb=4` is b2's maxconn, not b2's plus b3's).
//! Names the converters cannot resolve give no sample (`cnbx=`, `cupx=`, `cupy=`).

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::Engine;

/// A server that accepts, reads a request and answers 200, until the test ends. With
/// `hold` set it keeps each request unanswered until `hold` is cleared.
fn live_server(hold: Arc<AtomicBool>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let hold = Arc::clone(&hold);
            thread::spawn(move || {
                let _ = c.set_read_timeout(Some(Duration::from_millis(300)));
                let mut buf = [0u8; 4096];
                if matches!(c.read(&mut buf), Ok(n) if n > 0) {
                    while hold.load(Ordering::Relaxed) {
                        thread::sleep(Duration::from_millis(5));
                    }
                    let _ = c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
                }
            });
        }
    });
    addr
}

/// The body of `GET <path>` sent to `addr`, while the engine runs on this thread.
fn get(engine: &mut Engine, addr: SocketAddr, path: &str) -> String {
    let req = format!("GET {path} HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n");
    let client = thread::spawn(move || {
        let mut c = TcpStream::connect(addr).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        c.write_all(req.as_bytes()).expect("send");
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
        out
    });
    while !client.is_finished() {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let raw = client.join().expect("client");
    let text = String::from_utf8_lossy(&raw).into_owned();
    text.split_once("\r\n\r\n").map_or(text.clone(), |(_, b)| b.to_string())
}

/// Runs the engine for `ms` milliseconds, so the health checks settle.
fn settle(engine: &mut Engine, ms: u64) {
    let until = Instant::now() + Duration::from_millis(ms);
    while Instant::now() < until {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
}

const STATE_FMT: &str = "nb=%[nbsrv(be)] nbb=%[nbsrv(beb)] up1=%[srv_is_up(be/s1)] up2=%[srv_is_up(be/s2)] \
up3=%[srv_is_up(be/s3)] up4=%[srv_is_up(be/s4)] scf1=%[srv_conn_free(be/s1)] \
scf2=%[srv_conn_free(be/s2)] bcf=%[be_conn_free(be)] bcfb=%[be_conn_free(beb)] \
sc1=%[srv_conn(be/s1)] cnb=%[str(beb),nbsrv] cnbx=%[str(nope),nbsrv] \
cup=%[str(be/s1),srv_is_up] cup2=%[str(be/s2),srv_is_up] cupx=%[str(be/zz),srv_is_up] \
cupy=%[str(nope/s1),srv_is_up] fex=%[str(fe),fe_exists] fex2=%[str(be),fe_exists] \
fex3=%[str(nope),fe_exists] fex4=%[str(lst),fe_exists]";

/// In the backend, the backend and server arguments default to the backend itself.
const BE_FMT: &str = "nb=%[nbsrv] up1=%[srv_is_up(s1)] up2=%[srv_is_up(s2)] cup2=%[str(s2),srv_is_up] \
bcf=%[be_conn_free] scf1=%[srv_conn_free(s1)]";

#[test]
fn server_state_fetches_report_what_the_checks_found() {
    let live = live_server(Arc::new(AtomicBool::new(false)));
    let dead = common::reserve_addr();
    let (fe, lst, fe1, fe2) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let ck = "check inter 100 rise 1 fall 1";
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe}\n  use_backend be if {{ path /be }}\n  \
         http-request return status 200 content-type text/plain lf-string \"{STATE_FMT}\" unless {{ path /be }}\n\
         backend be\n  http-request return status 200 content-type text/plain lf-string \"{BE_FMT}\"\n  server s1 {live} {ck} maxconn 10\n  server s2 {dead} {ck}\n  server s3 {dead}\n  \
         server s4 {live} {ck} weight 0\n  server s5 {live} {ck} backup\n\
         backend beb\n  server b1 {dead} {ck}\n  server b2 {live} {ck} backup maxconn 4\n  server b3 {live} {ck} backup\n\
         listen lst\n  bind {lst}\n  server x {live}\n\
         frontend fe1\n  bind {fe1}\n  use_backend spare if {{ nbsrv(main1) lt 1 }}\n  default_backend main1\n\
         frontend fe2\n  bind {fe2}\n  use_backend spare if {{ nbsrv(main2) lt 1 }}\n  default_backend main2\n\
         backend main1\n  http-request return status 200 content-type text/plain string main1\n  server m {dead} {ck}\n\
         backend main2\n  http-request return status 200 content-type text/plain string main2\n  server m {live} {ck}\n\
         backend spare\n  http-request return status 200 content-type text/plain string spare\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    settle(&mut engine, 800);

    assert_eq!(
        get(&mut engine, fe, "/"),
        "nb=2 nbb=1 up1=1 up2=0 up3=1 up4=1 scf1=10 scf2=-1 bcf=-1 bcfb=4 sc1=0 cnb=1 cnbx= \
         cup=1 cup2=0 cupx= cupy= fex=1 fex2=0 fex3=0 fex4=1",
        "the server-state fetches and converters do not report what HAProxy reports for the same \
         servers (s2 and b1 are DOWN by their checks, s3 is unchecked, s4 has weight 0)"
    );
    assert_eq!(
        get(&mut engine, fe, "/be"),
        "nb=2 up1=1 up2=0 cup2=0 bcf=-1 scf1=10",
        "in backend be's own rules, `nbsrv`, `srv_is_up(s1)` and `str(s2),srv_is_up` must mean be's servers"
    );
    // The motivating case: content switching on the number of usable servers. fe2 is the
    // control -- the same rule, with main2's server UP.
    assert_eq!(get(&mut engine, fe1, "/"), "spare", "`use_backend spare if {{ nbsrv(main1) lt 1 }}` did not fire although main1's only server is DOWN");
    assert_eq!(get(&mut engine, fe2, "/"), "main2", "`use_backend spare if {{ nbsrv(main2) lt 1 }}` fired although main2's server is UP");
}

/// `srv_conn` and the `_free` counts follow the requests in flight on the server.
#[test]
fn srv_conn_counts_the_requests_in_flight() {
    let hold = Arc::new(AtomicBool::new(false));
    let live = live_server(Arc::clone(&hold));
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe}\n  http-request return status 200 content-type text/plain \
         lf-string \"sc=%[srv_conn(be/s1)] scf=%[srv_conn_free(be/s1)] bcf=%[be_conn_free(be)]\" if {{ path /q }}\n  \
         default_backend be\n\
         backend be\n  server s1 {live} maxconn 5\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    assert_eq!(get(&mut engine, fe, "/q"), "sc=0 scf=5 bcf=5");

    hold.store(true, Ordering::Relaxed);
    let slow: Vec<_> = (0..2)
        .map(|_| {
            thread::spawn(move || {
                let mut c = TcpStream::connect(fe).expect("connect");
                c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
                c.write_all(b"GET /slow HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n").expect("send");
                let mut out = Vec::new();
                let _ = c.read_to_end(&mut out);
            })
        })
        .collect();
    settle(&mut engine, 300);
    let busy = get(&mut engine, fe, "/q");
    hold.store(false, Ordering::Relaxed);
    while slow.iter().any(|t| !t.is_finished()) {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(busy, "sc=2 scf=3 bcf=3", "with two requests held by s1 (maxconn 5)");
    settle(&mut engine, 100);
    assert_eq!(get(&mut engine, fe, "/q"), "sc=0 scf=5 bcf=5", "once both requests completed");
}

/// `in_table(<table>)`: whether the input is a key in the table.
#[test]
fn in_table_reports_whether_the_key_is_tracked() {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe}\n  http-request track-sc0 src table t if {{ path /track }}\n  \
         http-request return status 200 content-type text/plain \
         lf-string \"src=%[src,in_table(t)] other=%[str(9.9.9.9),in_table(t)] u=%[src,in_table(u)]\"\n\
         backend t\n  stick-table type ip size 1k expire 1m store conn_cnt\n\
         backend u\n  stick-table type ip size 1k expire 1m store conn_cnt\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    assert_eq!(get(&mut engine, fe, "/x"), "src=0 other=0 u=0", "before anything was tracked");
    assert_eq!(get(&mut engine, fe, "/track"), "src=1 other=0 u=0", "on the request that tracked src in t");
    assert_eq!(get(&mut engine, fe, "/x"), "src=1 other=0 u=0", "after src was tracked in t");
}

/// `in_table` without an argument reads the current proxy's own table. `HAProxy`, same
/// version and date, a frontend with its own `stick-table` and `track-sc0 src` on `/track`:
/// `own=0`, then `own=1` on the tracking request and after it.
#[test]
fn in_table_without_an_argument_reads_the_proxy_s_own_table() {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe}\n  stick-table type ip size 1k expire 1m store conn_cnt\n  \
         http-request track-sc0 src if {{ path /track }}\n  \
         http-request return status 200 content-type text/plain lf-string \"own=%[src,in_table]\"\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    assert_eq!(get(&mut engine, fe, "/x"), "own=0", "before anything was tracked");
    assert_eq!(get(&mut engine, fe, "/track"), "own=1", "on the tracking request");
    assert_eq!(get(&mut engine, fe, "/x"), "own=1", "after it");
}

/// `in_table` against a table of each key type, with a sample of that type: an IPv6
/// address (`str(...),ipmask(32,128)`, which casts the string to an address first), an
/// integer, a boolean (an integer key), a string that is not an address, the method (a
/// string key), and binary.
///
/// `HAProxy` 3.5-dev8-885761-29, 2026-10-03, this configuration, one request to each path
/// in turn (each `/t*` tracks one key):
///
/// ```text
/// /x   v6=0 v6n=0 i=0 in=0 bo=0 bon=0 s=0 sn=0 m=0 b=0 bn=0
/// /t6  v6=1 v6n=0 i=0 in=0 bo=0 bon=0 s=0 sn=0 m=0 b=0 bn=0
/// /ti  v6=1 v6n=0 i=1 in=0 bo=1 bon=0 s=0 sn=0 m=0 b=0 bn=0
/// /ts  v6=1 v6n=0 i=1 in=0 bo=1 bon=0 s=1 sn=0 m=0 b=0 bn=0
/// /tm  v6=1 v6n=0 i=1 in=0 bo=1 bon=0 s=1 sn=0 m=1 b=0 bn=0
/// /tb  v6=1 v6n=0 i=1 in=0 bo=1 bon=0 s=1 sn=0 m=1 b=1 bn=0
/// ```
#[test]
fn in_table_finds_keys_of_every_type() {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe}\n  \
         http-request track-sc0 str(2001:db8::1) table t6 if {{ path /t6 }}\n  \
         http-request track-sc0 int(1) table ti if {{ path /ti }}\n  \
         http-request track-sc0 str(abc) table ts if {{ path /ts }}\n  \
         http-request track-sc0 str(GET) table ts if {{ path /tm }}\n  \
         http-request track-sc0 bin(616263) table tb if {{ path /tb }}\n  \
         http-request return status 200 content-type text/plain lf-string \"\
         v6=%[str(2001:db8::1),ipmask(32,128),in_table(t6)] v6n=%[str(2001:db8::2),ipmask(32,128),in_table(t6)] \
         i=%[int(1),in_table(ti)] in=%[int(2),in_table(ti)] bo=%[bool(1),in_table(ti)] bon=%[bool(0),in_table(ti)] \
         s=%[str(abc),in_table(ts)] sn=%[str(abd),in_table(ts)] m=%[method,in_table(ts)] \
         b=%[bin(616263),in_table(tb)] bn=%[bin(616264),in_table(tb)]\"\n\
         backend t6\n  stick-table type ipv6 size 1k expire 1m store conn_cnt\n\
         backend ti\n  stick-table type integer size 1k expire 1m store conn_cnt\n\
         backend ts\n  stick-table type string size 1k expire 1m store conn_cnt\n\
         backend tb\n  stick-table type binary len 3 size 1k expire 1m store conn_cnt\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let steps = [
        ("/x", "v6=0 v6n=0 i=0 in=0 bo=0 bon=0 s=0 sn=0 m=0 b=0 bn=0"),
        ("/t6", "v6=1 v6n=0 i=0 in=0 bo=0 bon=0 s=0 sn=0 m=0 b=0 bn=0"),
        ("/ti", "v6=1 v6n=0 i=1 in=0 bo=1 bon=0 s=0 sn=0 m=0 b=0 bn=0"),
        ("/ts", "v6=1 v6n=0 i=1 in=0 bo=1 bon=0 s=1 sn=0 m=0 b=0 bn=0"),
        ("/tm", "v6=1 v6n=0 i=1 in=0 bo=1 bon=0 s=1 sn=0 m=1 b=0 bn=0"),
        ("/tb", "v6=1 v6n=0 i=1 in=0 bo=1 bon=0 s=1 sn=0 m=1 b=1 bn=0"),
    ];
    for (path, want) in steps {
        assert_eq!(get(&mut engine, fe, path), want, "after the request to {path}");
    }
}
