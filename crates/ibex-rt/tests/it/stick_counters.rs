// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The traffic counters of a stick-table entry that Ibex did not measure (T139): session,
//! bytes and failure rates, `http_fail_*`, `glitch_*`, the tracker count, `table_expire`,
//! `table_idle`, `table_server_id`, and the `table_*` converters that read them. [`CFG`] is
//! the configuration of `reg-tests/stick-table/sc_counters.vtc` (without the `chroot`),
//! driven by one keep-alive connection that issues `/one`, `/denied`, `/srv` and `/fail`.
//!
//! The expected values were measured on `HAProxy` 3.5-dev8-885761-29, 2026-10-04, with the
//! same configuration and a Python origin answering `/fail` with a 500:
//!
//! ```text
//! /one    sc-cnt "1 1 1 1 1"  sc-req "1 1 0 0 0 0"  sc-byte "0 0 0 0"        tbl-misc "1 0 1 0 1"  updt 1
//! /denied sc-cnt "1 1 1 1 1"  sc-req "2 2 1 1 0 0"  sc-byte "0 0 <b1> 0"     updt 2
//! /srv    sc-req "3 3 1 1 0 0"                      sc-byte "0 0 <b1+b2> 0"  tbl-exp "3599999 1 42 43 1048575"
//! /fail   sc-req "4 4 1 1 1 1"                      sc-byte "0 0 <b1+b2+b3> <srv response>"
//! ```
//!
//! The bytes of a request are counted once its response has been produced (the request being
//! answered is not yet in the counter), and the bytes out are the ones read from the server:
//! a `return` or a `deny` adds none, and the headers the proxy adds are not counted.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
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

/// What the origin sends for `/srv`; `/fail` gets the same with a 500.
const SRV_RESPONSE: &str = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Origin: t139\r\n\r\n";

fn origin() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind origin");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut c = c;
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match c.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                    let head = String::from_utf8_lossy(&buf[..end]).to_string();
                    buf.drain(..end);
                    let resp = if head.starts_with("GET /fail ") { SRV_RESPONSE.replace("200 OK", "500 Err") } else { SRV_RESPONSE.to_string() };
                    if c.write_all(resp.as_bytes()).is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

type Headers = Vec<(String, String)>;

/// One request on a keep-alive connection: the status, the response headers (lower-cased
/// name, value), and the number of bytes the request took on the wire.
fn request(c: &mut TcpStream, path: &str) -> (u16, Headers, u64) {
    let req = format!("GET {path} HTTP/1.1\r\nHost: t139\r\n\r\n");
    c.write_all(req.as_bytes()).expect("send");
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = c.read(&mut chunk).expect("read");
        assert!(n > 0, "connection closed on {path}");
        buf.extend_from_slice(&chunk[..n]);
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let headers = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
        .collect();
    (status, headers, req.len() as u64)
}

fn h<'a>(hs: &'a Headers, name: &str) -> &'a str {
    hs.iter().find(|(k, _)| k == name).map_or("<absent>", |(_, v)| v.as_str())
}

const CFG: &str = r####"defaults
mode http
timeout connect 5s
timeout client  5s
timeout server  5s
backend st
stick-table type ip size 1m expire 1h store conn_cnt,conn_cur,conn_rate(10s),sess_cnt,sess_rate(10s),http_req_cnt,http_req_rate(10s),http_err_cnt,http_err_rate(10s),http_fail_cnt,http_fail_rate(10s),bytes_in_cnt,bytes_in_rate(10s),bytes_out_cnt,bytes_out_rate(10s),glitch_cnt,glitch_rate(10s),server_id
backend st1
stick-table type ip size 1m expire 1h store conn_cnt,conn_cur,conn_rate(10s),sess_cnt,sess_rate(10s),http_req_cnt,http_req_rate(10s),http_err_cnt,http_err_rate(10s),http_fail_cnt,http_fail_rate(10s),bytes_in_cnt,bytes_in_rate(10s),bytes_out_cnt,bytes_out_rate(10s),glitch_cnt,glitch_rate(10s),server_id
backend st2
stick-table type ip size 1m expire 1h store conn_cnt,conn_cur,conn_rate(10s),sess_cnt,sess_rate(10s),http_req_cnt,http_req_rate(10s),http_err_cnt,http_err_rate(10s),http_fail_cnt,http_fail_rate(10s),bytes_in_cnt,bytes_in_rate(10s),bytes_out_cnt,bytes_out_rate(10s),glitch_cnt,glitch_rate(10s),server_id
backend stu
stick-table type ip size 1m expire 1h store conn_cnt,conn_rate(10s)
frontend fe
bind @FE@
tcp-request connection track-sc0 src table st
tcp-request connection track-sc1 src table st1
tcp-request connection track-sc2 src table st2
http-request deny deny_status 403 if { path /denied }
http-request return status 200 unless { path /srv } || { path /fail }
use_backend be
http-after-response set-header x-sc-cnt   "%[sc_conn_cnt(0)] %[sc_conn_cur(0)] %[sc_conn_rate(0)] %[sc_sess_cnt(0)] %[sc_sess_rate(0)]"
http-after-response set-header x-sc-req   "%[sc_http_req_cnt(0)] %[sc_http_req_rate(0)] %[sc_http_err_cnt(0)] %[sc_http_err_rate(0)] %[sc_http_fail_cnt(0)] %[sc_http_fail_rate(0)]"
http-after-response set-header x-sc-byte  "%[sc_kbytes_in(0)] %[sc_kbytes_out(0)] %[sc_bytes_in_rate(0)] %[sc_bytes_out_rate(0)]"
http-after-response set-header x-sc-misc  "%[sc_glitch_cnt(0)] %[sc_glitch_rate(0)] %[sc_key(0)] %[sc_tracked(0)] %[sc_trackers(0)]"
http-after-response set-header x-sc0      "%[sc0_conn_cnt] %[sc0_conn_cur] %[sc0_conn_rate] %[sc0_sess_cnt] %[sc0_sess_rate]"
http-after-response set-header x-sc0-req  "%[sc0_http_req_cnt] %[sc0_http_req_rate] %[sc0_http_err_cnt] %[sc0_http_err_rate] %[sc0_http_fail_cnt] %[sc0_http_fail_rate]"
http-after-response set-header x-sc0-misc "%[sc0_kbytes_in] %[sc0_kbytes_out] %[sc0_glitch_cnt] %[sc0_glitch_rate] %[sc0_key] %[sc0_tracked] %[sc0_trackers]"
http-after-response set-header x-sc0-rate "%[sc0_bytes_in_rate] %[sc0_bytes_out_rate]"
http-after-response set-header x-sc1      "%[sc1_conn_cnt] %[sc1_conn_cur] %[sc1_conn_rate] %[sc1_sess_cnt] %[sc1_sess_rate]"
http-after-response set-header x-sc1-req  "%[sc1_http_req_cnt] %[sc1_http_req_rate] %[sc1_http_err_cnt] %[sc1_http_err_rate] %[sc1_http_fail_cnt] %[sc1_http_fail_rate]"
http-after-response set-header x-sc1-misc "%[sc1_kbytes_in] %[sc1_kbytes_out] %[sc1_glitch_cnt] %[sc1_glitch_rate] %[sc1_key] %[sc1_tracked] %[sc1_trackers]"
http-after-response set-header x-sc1-rate "%[sc1_bytes_in_rate] %[sc1_bytes_out_rate]"
http-after-response set-header x-sc2      "%[sc2_conn_cnt] %[sc2_conn_cur] %[sc2_conn_rate] %[sc2_sess_cnt] %[sc2_sess_rate]"
http-after-response set-header x-sc2-req  "%[sc2_http_req_cnt] %[sc2_http_req_rate] %[sc2_http_err_cnt] %[sc2_http_err_rate] %[sc2_http_fail_cnt] %[sc2_http_fail_rate]"
http-after-response set-header x-sc2-misc "%[sc2_kbytes_in] %[sc2_kbytes_out] %[sc2_glitch_cnt] %[sc2_glitch_rate] %[sc2_key] %[sc2_tracked] %[sc2_trackers]"
http-after-response set-header x-sc2-rate "%[sc2_bytes_in_rate] %[sc2_bytes_out_rate]"
http-after-response set-header x-scg1     "%[sc_conn_cnt(1)] %[sc_conn_cur(1)] %[sc_conn_rate(1)] %[sc_sess_cnt(1)] %[sc_sess_rate(1)]"
http-after-response set-header x-scg2-req "%[sc_http_req_cnt(2)] %[sc_http_req_rate(2)] %[sc_http_err_cnt(2)] %[sc_http_err_rate(2)] %[sc_http_fail_cnt(2)] %[sc_http_fail_rate(2)]"
http-after-response set-header x-src-cnt  "%[src_conn_cnt(st)] %[src_conn_cur(st)] %[src_conn_rate(st)] %[src_sess_cnt(st)] %[src_sess_rate(st)]"
http-after-response set-header x-src-req  "%[src_http_req_cnt(st)] %[src_http_req_rate(st)] %[src_http_err_cnt(st)] %[src_http_err_rate(st)] %[src_http_fail_cnt(st)] %[src_http_fail_rate(st)]"
http-after-response set-header x-src-byte "%[src_kbytes_in(st)] %[src_kbytes_out(st)] %[src_bytes_in_rate(st)] %[src_bytes_out_rate(st)] %[src_glitch_cnt(st)] %[src_glitch_rate(st)]"
http-after-response set-header x-tbl-cnt  "%[src,table_conn_cnt(st)] %[src,table_conn_cur(st)] %[src,table_conn_rate(st)] %[src,table_sess_cnt(st)] %[src,table_sess_rate(st)]"
http-after-response set-header x-tbl-req  "%[src,table_http_req_cnt(st)] %[src,table_http_req_rate(st)] %[src,table_http_err_cnt(st)] %[src,table_http_err_rate(st)] %[src,table_http_fail_cnt(st)] %[src,table_http_fail_rate(st)]"
http-after-response set-header x-tbl-byte "%[src,table_kbytes_in(st)] %[src,table_kbytes_out(st)] %[src,table_bytes_in_rate(st)] %[src,table_bytes_out_rate(st)] %[src,table_glitch_cnt(st)] %[src,table_glitch_rate(st)]"
http-after-response set-header x-tbl-misc "%[src,table_trackers(st)] %[src,table_server_id(st)] %[src,in_table(st)] %[ipv4(10.9.9.9),in_table(st)] %[table_cnt(st)]"
http-after-response set-header x-updt     "%[src_updt_conn_cnt(stu)]"
http-after-response set-header x-tbl-exp  "%[src,table_expire(st)] %[src,table_idle(st)] %[ipv4(10.9.9.9),table_expire(st,42)] %[ipv4(10.9.9.9),table_idle(st,43)] %[table_avl(st)]"
backend be
server s1 @S1@
"####;

/// The configuration, plus a frontend that tracks nothing, which the readiness probe of
/// [`start`] connects to: a probe on the tracked one would be a connection of its own.
fn config(fe: SocketAddr, s1: SocketAddr, ready: SocketAddr) -> String {
    CFG.replace("@FE@", &fe.to_string()).replace("@S1@", &s1.to_string()) + &ready_frontend(ready)
}

fn ready_frontend(ready: SocketAddr) -> String {
    format!("\nfrontend ready\n  bind {ready}\n  http-request return status 200\n")
}

fn same(hs: &Headers, a: &str, b: &str) {
    assert_eq!(h(hs, a), h(hs, b), "{a} and {b} differ");
}

#[test]
fn the_counters_of_an_entry_read_what_haproxy_measures() {
    let fe = common::reserve_addr();
    let srv = origin();
    let ready = common::reserve_addr();
    let _ibex = start(&config(fe, srv, ready), ready);
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");

    let (st, hs, b1) = request(&mut c, "/one");
    assert_eq!(st, 200);
    assert_eq!(h(&hs, "x-sc-cnt"), "1 1 1 1 1");
    assert_eq!(h(&hs, "x-sc-req"), "1 1 0 0 0 0");
    assert_eq!(h(&hs, "x-sc-byte"), "0 0 0 0");
    assert_eq!(h(&hs, "x-sc-misc"), "0 0 127.0.0.1 1 1");
    assert_eq!(h(&hs, "x-sc0-misc"), "0 0 0 0 127.0.0.1 1 1");
    for n in ["x-sc0", "x-sc1", "x-sc2", "x-scg1", "x-src-cnt", "x-tbl-cnt"] {
        same(&hs, n, "x-sc-cnt");
    }
    for n in ["x-sc0-req", "x-sc1-req", "x-sc2-req", "x-scg2-req", "x-src-req", "x-tbl-req"] {
        same(&hs, n, "x-sc-req");
    }
    same(&hs, "x-sc1-misc", "x-sc0-misc");
    same(&hs, "x-sc2-misc", "x-sc0-misc");
    assert_eq!(h(&hs, "x-tbl-misc"), "1 0 1 0 1");
    let exp = h(&hs, "x-tbl-exp").split(' ').collect::<Vec<_>>();
    assert_eq!(&exp[2..4], ["42", "43"], "x-tbl-exp: {exp:?}");
    // The entry was touched a moment ago: it expires in about the whole 1h, and has been idle for nothing
    // (HAProxy: "3600000 0" on /one, "3599999 1" on /srv).
    let (left, idle) = (exp[0].parse::<i64>().unwrap(), exp[1].parse::<i64>().unwrap());
    assert!((3_599_000..=3_600_000).contains(&left) && (0..1000).contains(&idle) && left + idle <= 3_600_000, "x-tbl-exp: {exp:?}");
    assert_eq!(exp[4], "1048575", "table_avl: the size less the one entry");
    assert_eq!(h(&hs, "x-updt"), "1");

    let (st, hs, b2) = request(&mut c, "/denied");
    assert_eq!(st, 403);
    assert_eq!(h(&hs, "x-sc-cnt"), "1 1 1 1 1");
    assert_eq!(h(&hs, "x-sc-req"), "2 2 1 1 0 0");
    for n in ["x-sc1-req", "x-sc2-req", "x-src-req", "x-tbl-req"] {
        same(&hs, n, "x-sc-req");
    }
    // The first request is counted now that its response is out; this one is not.
    assert_eq!(h(&hs, "x-sc0-rate"), format!("{b1} 0"));
    assert_eq!(h(&hs, "x-sc-byte"), "0 0 ".to_string() + &b1.to_string() + " 0");
    assert_eq!(h(&hs, "x-updt"), "2");

    let (st, hs, b3) = request(&mut c, "/srv");
    assert_eq!(st, 200);
    assert_eq!(h(&hs, "x-sc-req"), "3 3 1 1 0 0");
    assert_eq!(h(&hs, "x-sc0-rate"), format!("{} 0", b1 + b2), "a deny and a return send no byte the server sent");
    assert_eq!(h(&hs, "x-src-byte"), format!("0 0 {} 0 0 0", b1 + b2));
    assert_eq!(h(&hs, "x-tbl-byte"), format!("0 0 {} 0 0 0", b1 + b2));

    let (st, hs, _) = request(&mut c, "/fail");
    assert_eq!(st, 500);
    assert_eq!(h(&hs, "x-sc-req"), "4 4 1 1 1 1");
    for n in ["x-sc1-req", "x-sc2-req", "x-src-req", "x-tbl-req"] {
        same(&hs, n, "x-sc-req");
    }
    let out = SRV_RESPONSE.len();
    assert_eq!(h(&hs, "x-sc0-rate"), format!("{} {out}", b1 + b2 + b3));
    for n in ["x-sc1-rate", "x-sc2-rate"] {
        same(&hs, n, "x-sc0-rate");
    }
    assert_eq!(h(&hs, "x-src-byte"), format!("0 0 {} {out} 0 0", b1 + b2 + b3));
    same(&hs, "x-tbl-byte", "x-src-byte");
    assert_eq!(h(&hs, "x-updt"), "4");
}

/// `sc_trackers` and `table_trackers` count the streams that track the entry; measured on
/// `HAProxy` with `tcp-request connection track-sc0 src table st`, reading
/// `%[sc_trackers(0)] %[src,table_trackers(st)]` on a second connection while the first is
/// open (`1 1`, then `2 2`), and `table_expire`/`table_idle`/`table_trackers`/
/// `table_server_id`/`table_sess_rate` of a key that is not in the table (`<none> <none> 0 0 0`
/// without a default, `42` with one for `table_expire`).
#[test]
fn trackers_count_the_streams_that_track_the_entry() {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         backend st\n  stick-table type ip size 10 expire 1h store conn_cnt,sess_rate(10s),server_id\n\
         frontend fe\n  bind {fe}\n  tcp-request connection track-sc0 src table st\n  \
         http-request return status 200\n  \
         http-after-response set-header x-a \"%[sc_trackers(0)] %[src,table_trackers(st)] %[sc_sess_rate(0)]\"\n  \
         http-after-response set-header x-b \"%[ipv4(10.9.9.9),table_expire(st)]|%[ipv4(10.9.9.9),table_idle(st)]|%[ipv4(10.9.9.9),table_trackers(st)]|%[ipv4(10.9.9.9),table_server_id(st)]|%[ipv4(10.9.9.9),table_sess_rate(st)]\"\n  \
         http-after-response set-header x-c \"%[ipv4(10.9.9.9),table_expire(st,42)] %[ipv4(10.9.9.9),table_idle(st,43)]\"\n"
    );
    let ready = common::reserve_addr();
    let _ibex = start(&(cfg + &ready_frontend(ready)), ready);
    let mut c1 = TcpStream::connect(fe).expect("connect");
    c1.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let (_, hs, _) = request(&mut c1, "/x");
    assert_eq!(h(&hs, "x-a"), "1 1 1");
    assert_eq!(h(&hs, "x-b"), "||0|0|0");
    assert_eq!(h(&hs, "x-c"), "42 43");
    let mut c2 = TcpStream::connect(fe).expect("connect");
    c2.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let (_, hs, _) = request(&mut c2, "/x");
    assert_eq!(h(&hs, "x-a"), "2 2 2");
    drop(c1);
    thread::sleep(Duration::from_millis(100));
    let (_, hs, _) = request(&mut c2, "/x");
    assert_eq!(h(&hs, "x-a"), "1 1 2", "a closed connection no longer tracks the entry");
}

/// In `mode tcp` the bytes of the whole connection are credited when it ends. `HAProxy`, a
/// client sending 3000 bytes to a server that answers 5000 through `mode tcp` with
/// `tcp-request connection track-sc0 src table t`, then `src,table_kbytes_in(t)`,
/// `table_kbytes_out`, `table_bytes_in_rate`, `table_bytes_out_rate` from another frontend:
/// `2,4,3000,5000`.
#[test]
fn a_tcp_connection_credits_the_bytes_of_both_directions() {
    let srv_l = TcpListener::bind("127.0.0.1:0").expect("bind origin");
    let srv = srv_l.local_addr().expect("addr");
    thread::spawn(move || {
        if let Ok((mut c, _)) = srv_l.accept() {
            let mut got = 0;
            let mut buf = [0u8; 4096];
            while got < 3000 {
                match c.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => got += n,
                }
            }
            let _ = c.write_all(&[b'x'; 5000]);
            thread::sleep(Duration::from_millis(300));
        }
    });
    let [fe, rd] = std::array::from_fn(|_| common::reserve_addr());
    let cfg = format!(
        "defaults\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         backend t\n  mode http\n  stick-table type ip size 10 expire 1m store bytes_in_cnt,bytes_out_cnt,bytes_in_rate(10s),bytes_out_rate(10s)\n\
         frontend tcpfe\n  mode tcp\n  bind {fe}\n  tcp-request connection track-sc0 src table t\n  default_backend be\n\
         backend be\n  mode tcp\n  server s {srv}\n\
         frontend rd\n  mode http\n  bind {rd}\n  http-request return status 200 content-type text/plain lf-string \
         \"%[ipv4(127.0.0.1),table_kbytes_in(t)],%[ipv4(127.0.0.1),table_kbytes_out(t)],%[ipv4(127.0.0.1),table_bytes_in_rate(t)],%[ipv4(127.0.0.1),table_bytes_out_rate(t)]\"\n"
    );
    let _ibex = start(&cfg, rd);
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(&[b'y'; 3000]).expect("send");
    let mut got = 0;
    let mut buf = [0u8; 8192];
    while got < 5000 {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    assert_eq!(got, 5000);
    drop(c);
    let ask = || {
        let mut c = TcpStream::connect(rd).expect("connect rd");
        c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        c.write_all(b"GET / HTTP/1.1\r\nHost: t139\r\nConnection: close\r\n\r\n").expect("send");
        let mut out = String::new();
        let _ = c.read_to_string(&mut out);
        out.split_once("\r\n\r\n").map_or(String::new(), |(_, b)| b.to_string())
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut seen = ask();
    while seen != "2,4,3000,5000" && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
        seen = ask();
    }
    assert_eq!(seen, "2,4,3000,5000");
}
