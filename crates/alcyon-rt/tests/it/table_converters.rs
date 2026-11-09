// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `table_<counter>(<table>)` converters that read an entry: the input is cast to the
//! table's key type and looked up, and the converter gives that entry's counter.
//!
//! They were all refused at load ("Alcyon has no stick-table converters"). Measured on
//! `HAProxy` 3.5-dev8-885761-29, 2026-10-03, on [`CFG`]: `t1` stores every data type below,
//! `t3` stores `gpc0` only, `t4` is a string table; `/track` tracks the client in `t1` (slot
//! 0), `t3` (slot 1) and `str(abc)` in `t4` (slot 2), increments `gpc0` twice and `gpc1`
//! once, sets `gpt0` to 7, and increments `t3`'s `gpc0`. Every request reads
//! `%[src,table_<data>(t1)]` for each data type and
//! `absent=%[str(9.9.9.9),table_conn_cnt(t1)]` (a key with no entry),
//! `nostore=%[src,table_conn_cnt(t3)]` (an entry whose table does not store the type),
//! `gpc0t3=%[src,table_gpc0(t3)]`, `intkey=%[int(5),table_conn_cnt(t1)]`,
//! `nokey=%[req.hdr(x-none),table_conn_cnt(t1)]` (no sample) and
//! `str=%[str(abc),table_conn_cnt(t4)]`:
//!
//! ```text
//! /x     conn_cnt=0 conn_cur=0 conn_rate=0 sess_cnt=0 http_req_cnt=0 http_req_rate=0 http_err_cnt=0 http_err_rate=0 kbytes_in=0 kbytes_out=0 gpc0=0 gpc1=0 gpt0=0 absent=0 nostore=0 gpc0t3=0 intkey=0 nokey= str=0
//! /track conn_cnt=1 conn_cur=1 conn_rate=1 sess_cnt=0 http_req_cnt=1 http_req_rate=1 http_err_cnt=0 http_err_rate=0 kbytes_in=0 kbytes_out=0 gpc0=2 gpc1=1 gpt0=7 absent=0 nostore= gpc0t3=1 intkey=0 nokey= str=1
//! /x     conn_cnt=1 conn_cur=0 conn_rate=1 sess_cnt=0 http_req_cnt=1 http_req_rate=1 http_err_cnt=0 http_err_rate=0 kbytes_in=0 kbytes_out=0 gpc0=2 gpc1=1 gpt0=7 absent=0 nostore= gpc0t3=1 intkey=0 nokey= str=1
//! ```
//!
//! The converters that write, or read what Alcyon does not keep, are still refused at load
//! (`server_state_refusals.rs`).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

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

fn body(addr: SocketAddr, path: &str) -> String {
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(format!("GET {path} HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    out.split_once("\r\n\r\n").map_or(String::new(), |(_, b)| b.to_string())
}

const NAMES: &[&str] = &[
    "conn_cnt", "conn_cur", "conn_rate", "sess_cnt", "http_req_cnt", "http_req_rate", "http_err_cnt", "http_err_rate",
    "kbytes_in", "kbytes_out", "gpc0", "gpc1", "gpt0",
];

#[test]
fn the_table_converters_read_the_entry_they_look_up() {
    let fe = common::reserve_addr();
    let fmt = NAMES.iter().map(|n| format!("{n}=%[src,table_{n}(t1)]")).collect::<Vec<_>>().join(" ")
        + " absent=%[str(9.9.9.9),table_conn_cnt(t1)] nostore=%[src,table_conn_cnt(t3)] \
gpc0t3=%[src,table_gpc0(t3)] intkey=%[int(5),table_conn_cnt(t1)] \
nokey=%[req.hdr(x-none),table_conn_cnt(t1)] str=%[str(abc),table_conn_cnt(t4)]";
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         backend t1\n  stick-table type ip size 10 expire 1m store conn_cnt,conn_cur,conn_rate(10s),sess_cnt,http_req_cnt,http_req_rate(10s),http_err_cnt,http_err_rate(10s),bytes_in_cnt,bytes_out_cnt,gpc0,gpc1,gpt0\n\
         backend t3\n  stick-table type ip size 10 expire 1m store gpc0\n\
         backend t4\n  stick-table type string len 10 size 10 expire 1m store conn_cnt\n\
         frontend fe\n  bind {fe}\n  \
         http-request track-sc0 src table t1 if {{ path /track }}\n  \
         http-request track-sc1 src table t3 if {{ path /track }}\n  \
         http-request track-sc2 str(abc) table t4 if {{ path /track }}\n  \
         http-request sc-inc-gpc0(0) if {{ path /track }}\n  \
         http-request sc-inc-gpc0(0) if {{ path /track }}\n  \
         http-request sc-inc-gpc1(0) if {{ path /track }}\n  \
         http-request sc-set-gpt0(0) 7 if {{ path /track }}\n  \
         http-request sc-inc-gpc0(1) if {{ path /track }}\n  \
         http-request return status 200 content-type text/plain lf-string \"{fmt}\"\n"
    );
    let _alcyon = start(&cfg, fe);
    let steps = [
        ("/x", "conn_cnt=0 conn_cur=0 conn_rate=0 sess_cnt=0 http_req_cnt=0 http_req_rate=0 http_err_cnt=0 http_err_rate=0 kbytes_in=0 kbytes_out=0 gpc0=0 gpc1=0 gpt0=0 absent=0 nostore=0 gpc0t3=0 intkey=0 nokey= str=0"),
        ("/track", "conn_cnt=1 conn_cur=1 conn_rate=1 sess_cnt=0 http_req_cnt=1 http_req_rate=1 http_err_cnt=0 http_err_rate=0 kbytes_in=0 kbytes_out=0 gpc0=2 gpc1=1 gpt0=7 absent=0 nostore= gpc0t3=1 intkey=0 nokey= str=1"),
        ("/x", "conn_cnt=1 conn_cur=0 conn_rate=1 sess_cnt=0 http_req_cnt=1 http_req_rate=1 http_err_cnt=0 http_err_rate=0 kbytes_in=0 kbytes_out=0 gpc0=2 gpc1=1 gpt0=7 absent=0 nostore= gpc0t3=1 intkey=0 nokey= str=1"),
    ];
    let mut wrong = Vec::new();
    for (path, want) in steps {
        // The previous request's connection is released a moment after its response.
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

/// Without a table argument a `table_*` converter reads the table of the proxy it is written
/// in. `HAProxy`, same version and date, a frontend with its own table (`store conn_cnt`),
/// `track-sc0 src` on `/track`, reading `own=%[src,table_conn_cnt]
/// explicit=%[src,table_conn_cnt(fe2)]` on `/x`, `/track`, `/x`:
///
/// ```text
/// /x     own=0 explicit=0
/// /track own=1 explicit=1
/// /x     own=1 explicit=1
/// ```
#[test]
fn a_table_converter_without_an_argument_reads_the_proxy_s_own_table() {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe2\n  bind {fe}\n  stick-table type ip size 10 expire 1m store conn_cnt\n  \
         http-request track-sc0 src if {{ path /track }}\n  \
         http-request return status 200 content-type text/plain lf-string \
         \"own=%[src,table_conn_cnt] explicit=%[src,table_conn_cnt(fe2)]\"\n"
    );
    let _alcyon = start(&cfg, fe);
    for (path, want) in [("/x", "own=0 explicit=0"), ("/track", "own=1 explicit=1"), ("/x", "own=1 explicit=1")] {
        thread::sleep(Duration::from_millis(30));
        assert_eq!(body(fe, path), want, "on {path}");
    }
}
