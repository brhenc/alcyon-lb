// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The stick-table converters and fetches that default to the table of the proxy they are
//! written in, `table_expire`/`table_idle` and their default, `sc_key` on every key type (T139).
//! Measured on `HAProxy` 3.5-dev8-885761-29, 2026-10-04, with [`CFG`] and two requests on one
//! keep-alive connection to each frontend. The array forms (`table_gpc(0,)`, `src_get_gpc(0,)`)
//! leave the table argument empty: `HAProxy` refuses them with no second argument at all.

use crate::common;

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

/// One request on a keep-alive connection: the response headers (lower-cased name, value).
fn request(c: &mut TcpStream, path: &str, extra: &str) -> Vec<(String, String)> {
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: t139\r\n{extra}\r\n").as_bytes()).expect("send");
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = c.read(&mut chunk).expect("read");
        assert!(n > 0, "connection closed on {path}");
        buf.extend_from_slice(&chunk[..n]);
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    text.split("\r\n")
        .skip(1)
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
        .collect()
}

const CFG: &str = r####"defaults
mode http
timeout client 5s
timeout server 5s
timeout connect 5s
frontend fe_a
bind @A@
stick-table type ip size 10 expire 1m store gpc(2),gpc_rate(2,10s),gpt(2),conn_cnt
http-request track-sc0 src
http-request return status 200
http-after-response set-header x-a "%[src,table_inc_gpc(0,)],%[src,table_gpc(0,)],%[src_get_gpc(0,)],%[src,table_gpc_rate(0,)],%[src,table_gpt(1,)],%[src_inc_gpc(1,)],%[src,table_clr_gpc(1,)]"
http-after-response set-header x-b "%[src,table_expire],%[src,table_idle],%[ipv4(1.1.1.1),table_expire(,5)]"
frontend fe_l
bind @L@
stick-table type ip size 10 expire 1m store gpc0,gpc0_rate(10s),gpc1,gpc1_rate(10s),gpt0,conn_cnt
http-request track-sc0 src
http-request return status 200
http-after-response set-header x-l "%[src,table_inc_gpc0],%[src,table_gpc0_rate],%[src,table_inc_gpc1],%[src,table_gpc1_rate],%[src,table_clr_gpc0],%[src,table_clr_gpc1]"
frontend fe_k
bind @K@
stick-table type string len 12 size 10 expire 1m store gpc0
http-request track-sc0 req.hdr(x-k)
http-request track-sc1 req.hdr(x-k) table tb
http-request track-sc2 req.hdr(x-k) table ti
http-request return status 200
http-after-response set-header x-key "%[sc_key(0)]|%[sc_key(1)]|%[sc_key(2)]"
backend tb
stick-table type binary len 8 size 10 expire 1m store gpc0
backend ti
stick-table type integer size 10 expire 1m store gpc0
frontend fe_6
bind @S@
stick-table type ipv6 size 10 expire 1m store gpc0
http-request track-sc0 src
http-request return status 200
http-after-response set-header x-key "%[sc_key(0)]"
"####;

fn ask(addr: SocketAddr, extra: &str, n: usize) -> Vec<Vec<(String, String)>> {
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    (0..n).map(|_| request(&mut c, "/x", extra)).collect()
}

fn h<'a>(hs: &'a [(String, String)], name: &str) -> &'a str {
    hs.iter().find(|(k, _)| k == name).map_or("<absent>", |(_, v)| v.as_str())
}

#[test]
fn own_table_defaults_times_and_keys_of_every_type() {
    let [a, l, k, s, ready] = std::array::from_fn(|_| common::reserve_addr());
    let cfg = CFG
        .replace("@A@", &a.to_string())
        .replace("@L@", &l.to_string())
        .replace("@K@", &k.to_string())
        .replace("@S@", &s.to_string())
        + &format!("\nfrontend ready\n  mode http\n  bind {ready}\n  http-request return status 200\n");
    let _ibex = start(&cfg, ready);

    // An array table: the counters of the entry that `track-sc0 src` made, and the times.
    let r = ask(a, "", 2);
    assert_eq!(h(&r[0], "x-a"), "1,1,1,1,0,1,1");
    assert_eq!(h(&r[1], "x-a"), "2,2,2,2,0,1,1");
    let b = h(&r[1], "x-b").split(',').collect::<Vec<_>>();
    let left: i64 = b[0].parse().expect("table_expire");
    assert!((59_000..=60_000).contains(&left), "table_expire {left}");
    assert!(b[1].parse::<i64>().expect("table_idle") < 1000, "table_idle {}", b[1]);
    assert_eq!(b[2], "5", "table_expire of a key that is not there takes its default");

    // A legacy table: the rates and the increments and clears of both counters.
    let r = ask(l, "", 2);
    assert_eq!(h(&r[0], "x-l"), "1,1,1,1,1,1");
    assert_eq!(h(&r[1], "x-l"), "1,2,1,2,1,1");

    // The key of the entry each slot tracks, in the type of its table.
    let r = ask(k, "x-k: 42\r\n", 2);
    assert_eq!(h(&r[0], "x-key"), "42|42|42");
    let r = ask(s, "", 1);
    assert_eq!(h(&r[0], "x-key"), "::ffff:127.0.0.1");
}
