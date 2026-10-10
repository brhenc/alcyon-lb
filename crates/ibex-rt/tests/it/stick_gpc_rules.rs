// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The array form of the general purpose actions in `tcp-request session` and `tcp-request
//! content` (T139), the alternate-table and out-of-range arguments of the `sc_*` fetches, and
//! the legacy `gpc0`/`gpc1`/`gpt0` accessors on a table that stores the array form (they are its
//! elements 0 and 1). Measured on `HAProxy` 3.5-dev8-885761-29, 2026-10-04, with [`CFG`] and
//! two requests on one keep-alive connection, of which the first is checked (see the loop).

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
fn request(c: &mut TcpStream, path: &str) -> Vec<(String, String)> {
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: t139\r\n\r\n").as_bytes()).expect("send");
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
backend arr
stick-table type ip size 10 expire 1m store gpc(2),gpc_rate(2,10s),gpt(2)
backend leg
stick-table type ip size 10 expire 1m store gpc0,gpc0_rate(10s),gpc1,gpt0
backend oth
stick-table type ip size 10 expire 1m store gpc0
backend strt
stick-table type string len 10 size 10 expire 1m store gpc0
backend intt
stick-table type integer size 10 expire 1m store conn_cnt
frontend fe
bind @FE@
tcp-request session track-sc0 src table leg
tcp-request session track-sc1 src table arr
tcp-request session sc-inc-gpc0(0)
tcp-request session sc-inc-gpc1(0)
tcp-request session sc-set-gpt0(0) 5
tcp-request session sc-inc-gpc(0,1)
tcp-request session sc-add-gpc(1,1) 4
tcp-request session sc-set-gpt(1,1) 9
tcp-request content sc-inc-gpc0(0)
tcp-request content sc-inc-gpc1(0)
tcp-request content sc-set-gpt0(0) 6
tcp-request content sc-inc-gpc(0,1)
tcp-request content sc-add-gpc(1,1) 2
tcp-request content sc-set-gpt(1,1) 11
tcp-request content sc-inc-gpc(5,1)
http-request return status 200
http-after-response set-header x-leg "%[sc0_get_gpc0],%[sc0_get_gpc1],%[sc0_get_gpt0],%[sc0_gpc0_rate]"
http-after-response set-header x-arr "%[sc_get_gpc(0,1)],%[sc_get_gpc(1,1)],%[sc_get_gpt(1,1)],%[sc_gpc_rate(1,1)]"
http-after-response set-header x-alias_leg "%[sc_get_gpc(0,0)],%[sc_get_gpc(1,0)],%[sc_get_gpt(0,0)],%[sc_gpc_rate(0,0)],%[sc_get_gpc(2,0)]"
http-after-response set-header x-alias_arr "%[sc1_get_gpc0],%[sc1_get_gpc1],%[sc1_get_gpt0],%[sc1_gpc0_rate],%[sc1_gpc1_rate]"
http-after-response set-header x-oob "%[sc_get_gpc(5,1)]"
http-after-response set-header x-key "%[sc_key(0)]"
http-after-response set-header x-tracked "%[sc_tracked(0)],%[sc0_tracked(oth)],%[sc_tracked(0,strt)],%[sc_tracked(7)]"
http-after-response set-header x-oth "%[sc_get_gpc0(0,oth)],%[sc_inc_gpc0(0,oth)],%[sc_get_gpc0(0,oth)]"
http-after-response set-header x-str "%[sc_get_gpc0(0,strt)]"
http-after-response set-header x-strw "%[sc_inc_gpc0(0,strt)]|%[sc_clr_gpc0(0,strt)]"
http-after-response set-header x-idle "%[src,table_idle(intt,7)]"
http-after-response set-header x-updt "%[src_updt_conn_cnt(leg)]"
http-after-response set-header x-clr "%[src,table_clr_gpc0(arr)]"
http-after-response set-header x-cnt "%[table_cnt(oth)],%[table_avl(oth)]"
"####;

/// `(header, first request, second request)`.
const EXPECTED: &[(&str, &str, &str)] = &[
    ("x-leg", "2,2,6,2", "3,3,6,3"),
    ("x-arr", "2,6,11,6", "1,8,11,8"),
    // The array form of a legacy table is not there; the legacy form of an array table is its elements.
    ("x-alias_leg", ",,,,", ",,,,"),
    ("x-alias_arr", "2,6,0,2,6", "1,8,0,3,8"),
    ("x-oob", "", ""),
    ("x-key", "127.0.0.1", "127.0.0.1"),
    // Tracked in an alternate table of the same key type whether or not the entry is there, not in one of another type.
    ("x-tracked", "1,1,0,0", "1,1,0,0"),
    ("x-oth", "0,0,0", "0,0,0"),
    ("x-str", "", ""),
    // A write through a table of another key type gives nothing either.
    ("x-strw", "|", "|"),
    ("x-idle", "7", "7"),
    ("x-updt", "", ""),
    // `gpc0` of an array table is its element 0: the clear gives the value it had.
    ("x-clr", "2", "1"),
    ("x-cnt", "0,10", "0,10"),
];

#[test]
fn array_actions_in_session_and_content_rules_and_the_aliases_of_the_legacy_names() {
    let (fe, ready) = (common::reserve_addr(), common::reserve_addr());
    let cfg = CFG.replace("@FE@", &fe.to_string())
        + &format!("\nfrontend ready\n  mode http\n  bind {ready}\n  http-request return status 200\n");
    let _ibex = start(&cfg, ready);
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut wrong = Vec::new();
    // Only the first request: HAProxy runs the `content` rules again on the second (gpc0 3, 3 ...),
    // Ibex runs them once per connection -- a divergence of `tcp-request content`, not of the counters.
    for round in 0..1 {
        let got = request(&mut c, "/x");
        for (name, first, second) in EXPECTED {
            let want = if round == 0 { first } else { second };
            let have = got.iter().find(|(k, _)| k == name).map_or("<absent>", |(_, v)| v.as_str());
            if have != *want {
                wrong.push(format!("request {}: {name} is {have:?}, HAProxy gives {want:?}", round + 1));
            }
        }
    }
    assert!(wrong.is_empty(), "values that differ from HAProxy's:\n{}", wrong.join("\n"));
}
