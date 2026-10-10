// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A stick table's key is converted to the table's key type, whatever type the sample that
//! tracks it or looks it up has.
//!
//! Ibex built the key from the sample's own type, so `track-sc0 int(1) table <string table>`
//! stored an integer key that `str(1),in_table(<string table>)` could not find, and
//! `str(10.0.0.11)` was stored in an `ipv6` table as an IPv4 key that `HAProxy` never creates.
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29, 2026-10-03, on [`CFG`], one request per path in
//! turn (each `/<letter>` tracks one key in one table; every row reads all the keys):
//!
//! ```text
//! a  int(1)         -> string table   ts1=1
//! b  str(2)         -> integer table  ti2=1 ti2i=1
//! c  int(3)         -> ip table       tip3=1 tip3i=1   (0.0.0.3)
//! d  str(4)         -> binary table   tb4=1
//! e  src            -> string table   tse=1 tse2=1     ("127.0.0.1")
//! g  str(10.0.0.9)  -> ip table       tip9=1
//! h  str(10.0.0.10) -> string table   ts10=1
//! i  str(10.0.0.11) -> ipv6 table     (nothing is tracked: tip6_11=0 tip6_11b=0)
//! j  str(abc)       -> integer table  tij=1            (the key is 0)
//! k  src            -> ipv6 table     tip6k=1          (::ffff:127.0.0.1)
//! l  int(7)         -> binary table   tb7=1 tb7s=0     (not the bytes of "7")
//! m  src            -> binary table   tbs=1
//! ```
//!
//! (`track-sc0 src table <integer table>` is refused at load by `HAProxy`; it is not in the
//! configuration.)

use crate::common;

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

#[test]
fn keys_are_converted_to_the_type_of_the_table() {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         backend ti\n  stick-table type integer size 10 expire 1m store conn_cnt\n\
         backend ts\n  stick-table type string len 20 size 10 expire 1m store conn_cnt\n\
         backend tip\n  stick-table type ip size 10 expire 1m store conn_cnt\n\
         backend tip6\n  stick-table type ipv6 size 10 expire 1m store conn_cnt\n\
         backend tb\n  stick-table type binary len 8 size 10 expire 1m store conn_cnt\n\
         frontend fe\n  bind {fe}\n  \
         http-request track-sc0 int(1) table ts if {{ path /a }}\n  \
         http-request track-sc0 str(2) table ti if {{ path /b }}\n  \
         http-request track-sc0 int(3) table tip if {{ path /c }}\n  \
         http-request track-sc0 str(4) table tb if {{ path /d }}\n  \
         http-request track-sc0 src table ts if {{ path /e }}\n  \
         http-request track-sc0 str(10.0.0.9) table tip if {{ path /g }}\n  \
         http-request track-sc0 str(10.0.0.10) table ts if {{ path /h }}\n  \
         http-request track-sc0 str(10.0.0.11) table tip6 if {{ path /i }}\n  \
         http-request track-sc0 str(abc) table ti if {{ path /j }}\n  \
         http-request track-sc0 src table tip6 if {{ path /k }}\n  \
         http-request track-sc0 int(7) table tb if {{ path /l }}\n  \
         http-request track-sc0 src table tb if {{ path /m }}\n  \
         http-request return status 200 content-type text/plain lf-string \"\
         ts1=%[str(1),in_table(ts)] ti2=%[str(2),in_table(ti)] ti2i=%[int(2),in_table(ti)] \
         tip3=%[str(0.0.0.3),in_table(tip)] tip3i=%[int(3),in_table(tip)] tb4=%[str(4),in_table(tb)] \
         tse=%[src,in_table(ts)] tse2=%[str(127.0.0.1),in_table(ts)] tif2=%[int(2130706433),in_table(ti)] \
         tip9=%[str(10.0.0.9),in_table(tip)] ts10=%[str(10.0.0.10),in_table(ts)] \
         tip6_11=%[str(10.0.0.11),in_table(tip6)] tip6_11b=%[str(::ffff:10.0.0.11),in_table(tip6)] \
         tij=%[int(0),in_table(ti)] tip6k=%[src,in_table(tip6)] tb7=%[int(7),in_table(tb)] \
         tb7s=%[str(7),in_table(tb)] tbs=%[src,in_table(tb)]\"\n"
    );
    let _ibex = start(&cfg, fe);
    let steps = [
        ("/a", "ts1=1 ti2=0 ti2i=0 tip3=0 tip3i=0 tb4=0 tse=0 tse2=0 tif2=0 tip9=0 ts10=0 tip6_11=0 tip6_11b=0 tij=0 tip6k=0 tb7=0 tb7s=0 tbs=0"),
        ("/b", "ts1=1 ti2=1 ti2i=1 tip3=0 tip3i=0 tb4=0 tse=0 tse2=0 tif2=0 tip9=0 ts10=0 tip6_11=0 tip6_11b=0 tij=0 tip6k=0 tb7=0 tb7s=0 tbs=0"),
        ("/c", "ts1=1 ti2=1 ti2i=1 tip3=1 tip3i=1 tb4=0 tse=0 tse2=0 tif2=0 tip9=0 ts10=0 tip6_11=0 tip6_11b=0 tij=0 tip6k=0 tb7=0 tb7s=0 tbs=0"),
        ("/d", "ts1=1 ti2=1 ti2i=1 tip3=1 tip3i=1 tb4=1 tse=0 tse2=0 tif2=0 tip9=0 ts10=0 tip6_11=0 tip6_11b=0 tij=0 tip6k=0 tb7=0 tb7s=0 tbs=0"),
        ("/e", "ts1=1 ti2=1 ti2i=1 tip3=1 tip3i=1 tb4=1 tse=1 tse2=1 tif2=0 tip9=0 ts10=0 tip6_11=0 tip6_11b=0 tij=0 tip6k=0 tb7=0 tb7s=0 tbs=0"),
        ("/g", "ts1=1 ti2=1 ti2i=1 tip3=1 tip3i=1 tb4=1 tse=1 tse2=1 tif2=0 tip9=1 ts10=0 tip6_11=0 tip6_11b=0 tij=0 tip6k=0 tb7=0 tb7s=0 tbs=0"),
        ("/h", "ts1=1 ti2=1 ti2i=1 tip3=1 tip3i=1 tb4=1 tse=1 tse2=1 tif2=0 tip9=1 ts10=1 tip6_11=0 tip6_11b=0 tij=0 tip6k=0 tb7=0 tb7s=0 tbs=0"),
        ("/i", "ts1=1 ti2=1 ti2i=1 tip3=1 tip3i=1 tb4=1 tse=1 tse2=1 tif2=0 tip9=1 ts10=1 tip6_11=0 tip6_11b=0 tij=0 tip6k=0 tb7=0 tb7s=0 tbs=0"),
        ("/j", "ts1=1 ti2=1 ti2i=1 tip3=1 tip3i=1 tb4=1 tse=1 tse2=1 tif2=0 tip9=1 ts10=1 tip6_11=0 tip6_11b=0 tij=1 tip6k=0 tb7=0 tb7s=0 tbs=0"),
        ("/k", "ts1=1 ti2=1 ti2i=1 tip3=1 tip3i=1 tb4=1 tse=1 tse2=1 tif2=0 tip9=1 ts10=1 tip6_11=0 tip6_11b=0 tij=1 tip6k=1 tb7=0 tb7s=0 tbs=0"),
        ("/l", "ts1=1 ti2=1 ti2i=1 tip3=1 tip3i=1 tb4=1 tse=1 tse2=1 tif2=0 tip9=1 ts10=1 tip6_11=0 tip6_11b=0 tij=1 tip6k=1 tb7=1 tb7s=0 tbs=0"),
        ("/m", "ts1=1 ti2=1 ti2i=1 tip3=1 tip3i=1 tb4=1 tse=1 tse2=1 tif2=0 tip9=1 ts10=1 tip6_11=0 tip6_11b=0 tij=1 tip6k=1 tb7=1 tb7s=0 tbs=1"),
    ];
    let mut wrong = Vec::new();
    for (path, want) in steps {
        let got = body(fe, path);
        if got != want {
            let diff: Vec<String> = got
                .split(' ')
                .zip(want.split(' '))
                .filter(|(g, w)| g != w)
                .map(|(g, w)| format!("{g} (HAProxy: {w})"))
                .collect();
            wrong.push(format!("after {path}: {}", diff.join(", ")));
        }
    }
    assert!(wrong.is_empty(), "keys that differ from HAProxy's:\n{}", wrong.join("\n"));
}
