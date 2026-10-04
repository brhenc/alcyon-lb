// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The general purpose counters and tags of a stick-table entry (T139): the array form
//! (`gpc(<n>)`, `gpc_rate(<n>,<period>)`, `gpt(<n>)`) and the legacy one (`gpc0`, `gpc0_rate`,
//! `gpc1`, `gpc1_rate`, `gpt0`), the actions that write them (`sc-add-gpc`, `sc-inc-gpc`,
//! `sc-inc-gpc0`, `sc-inc-gpc1`, `sc-set-gpt`, `sc-set-gpt0`), the `sc_*`, `sc[0-2]_*` and
//! `src_*` fetches that read, increment and clear them, and the `table_*` converters that do the
//! same on the entry of the key they are given.
//!
//! [`CFG`] is the configuration of `reg-tests/stick-table/sc_gpc_gpt.vtc`, and [`STEPS`] its
//! three clients: a path requested on a keep-alive connection, and the response headers that
//! `HAProxy` 3.5-dev8-885761-29 gave. Before this change Ibex refused the configuration at
//! load (`unknown http-request action <sc-add-gpc(1,1)>`).

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

type Step = (&'static str, &'static [(&'static str, &'static str)]);


const CFG: &str = r####"defaults
mode http
timeout connect 5s
timeout client  5s
timeout server  5s
backend arr
stick-table type ip size 1m expire 1h store gpc(3),gpc_rate(3,10s),gpt(3)
backend leg
stick-table type ip size 1m expire 1h store gpc0,gpc0_rate(10s),gpc1,gpc1_rate(10s),gpt0
frontend fe
bind @FE@
http-request track-sc0 src table leg
http-request track-sc1 src table arr
http-request track-sc2 src table leg
http-request sc-add-gpc(1,1) 5    if { path /upd }
http-request sc-inc-gpc(0,1)      if { path /upd }
http-request sc-set-gpt(2,1) 7    if { path /upd }
http-request sc-inc-gpc0(0)       if { path /upd }
http-request sc-inc-gpc1(0)       if { path /upd }
http-request sc-set-gpt0(0) 9     if { path /upd }
http-request set-var(txn.incf)  sc_inc_gpc(0,1)  if { path /fetch }
http-request set-var(txn.incf0) sc_inc_gpc0(0)   if { path /fetch }
http-request set-var(txn.incf1) sc0_inc_gpc1     if { path /fetch }
http-request set-var(txn.clrf)  sc1_clr_gpc(0)   if { path /clear }
http-request set-var(txn.clrf0) sc_clr_gpc0(0)   if { path /clear }
http-request set-var(txn.clrf1) sc0_clr_gpc1     if { path /clear }
http-request set-var(txn.tinc)  src,table_inc_gpc(0,arr)  if { path /conv }
http-request set-var(txn.tinc0) src,table_inc_gpc0(leg)   if { path /conv }
http-request set-var(txn.tinc1) src,table_inc_gpc1(leg)   if { path /conv }
http-request set-var(txn.tclr)  src,table_clr_gpc(0,arr)  if { path /convclr }
http-request set-var(txn.tclr0) src,table_clr_gpc0(leg)   if { path /convclr }
http-request set-var(txn.tclr1) src,table_clr_gpc1(leg)   if { path /convclr }
http-request return status 200
http-after-response set-header x-incf  "%[var(txn.incf)]"
http-after-response set-header x-incf0 "%[var(txn.incf0)]"
http-after-response set-header x-incf1 "%[var(txn.incf1)]"
http-after-response set-header x-clrf  "%[var(txn.clrf)]"
http-after-response set-header x-clrf0 "%[var(txn.clrf0)]"
http-after-response set-header x-clrf1 "%[var(txn.clrf1)]"
http-after-response set-header x-tinc  "%[var(txn.tinc)]"
http-after-response set-header x-tinc0 "%[var(txn.tinc0)]"
http-after-response set-header x-tinc1 "%[var(txn.tinc1)]"
http-after-response set-header x-tclr  "%[var(txn.tclr)]"
http-after-response set-header x-tclr0 "%[var(txn.tclr0)]"
http-after-response set-header x-tclr1 "%[var(txn.tclr1)]"
http-after-response set-header x-gpc0  "%[sc_get_gpc(0,1)]"
http-after-response set-header x-gpc1  "%[sc_get_gpc(1,1)]"
http-after-response set-header x-gpt2  "%[sc_get_gpt(2,1)]"
http-after-response set-header x-rate0 "%[sc_gpc_rate(0,1)]"
http-after-response set-header x-lgpc0 "%[sc_get_gpc0(0)]"
http-after-response set-header x-lgpc1 "%[sc_get_gpc1(0)]"
http-after-response set-header x-lgpt0 "%[sc_get_gpt0(0)]"
http-after-response set-header x-lr0   "%[sc_gpc0_rate(0)]"
http-after-response set-header x-lr1   "%[sc_gpc1_rate(0)]"
http-after-response set-header x-sc0   "%[sc0_get_gpc0]"
http-after-response set-header x-sc0b  "%[sc0_get_gpc1]"
http-after-response set-header x-sc0t  "%[sc0_get_gpt0]"
http-after-response set-header x-sc0r  "%[sc0_gpc0_rate]"
http-after-response set-header x-sc0r1 "%[sc0_gpc1_rate]"
http-after-response set-header x-sc2   "%[sc2_get_gpc0]"
http-after-response set-header x-sc2b  "%[sc2_get_gpc1]"
http-after-response set-header x-sc2t  "%[sc2_get_gpt0]"
http-after-response set-header x-sc2r  "%[sc2_gpc0_rate]"
http-after-response set-header x-sc2r1 "%[sc2_gpc1_rate]"
http-after-response set-header x-tgpc0 "%[src,table_gpc(0,arr)]"
http-after-response set-header x-tgpc1 "%[src,table_gpc(1,arr)]"
http-after-response set-header x-tgpt2 "%[src,table_gpt(2,arr)]"
http-after-response set-header x-trat0 "%[src,table_gpc_rate(0,arr)]"
http-after-response set-header x-tlgc0 "%[src,table_gpc0(leg)]"
http-after-response set-header x-tlgc1 "%[src,table_gpc1(leg)]"
http-after-response set-header x-tlgt0 "%[src,table_gpt0(leg)]"
http-after-response set-header x-tlr0  "%[src,table_gpc0_rate(leg)]"
http-after-response set-header x-tlr1  "%[src,table_gpc1_rate(leg)]"
http-after-response set-header x-sgpc0 "%[src_get_gpc(0,arr)]"
http-after-response set-header x-sgpt2 "%[src_get_gpt(2,arr)]"
http-after-response set-header x-srat0 "%[src_gpc_rate(0,arr)]"
http-after-response set-header x-slgc0 "%[src_get_gpc0(leg)]"
http-after-response set-header x-slgc1 "%[src_get_gpc1(leg)]"
http-after-response set-header x-slgt0 "%[src_get_gpt0(leg)]"
http-after-response set-header x-slr0  "%[src_gpc0_rate(leg)]"
http-after-response set-header x-slr1  "%[src_gpc1_rate(leg)]"
backend leg2
stick-table type ip size 1m expire 1h store gpc0,gpc0_rate(10s),gpc1,gpc1_rate(10s),gpt0
backend arr2
stick-table type ip size 1m expire 1h store gpc(2),gpc_rate(2,10s),gpt(2)
backend cnt2
stick-table type ip size 1m expire 1h store conn_cnt,conn_rate(10s)
frontend fe2
bind @FE2@
http-request track-sc0 src table leg2
http-request track-sc1 src table leg2
http-request track-sc2 src table leg2
http-request sc-set-gpt0(1) 4                  if { path /inc }
http-request set-var(txn.i00) sc0_inc_gpc0     if { path /inc }
http-request set-var(txn.i10) sc1_inc_gpc0     if { path /inc }
http-request set-var(txn.i20) sc2_inc_gpc0     if { path /inc }
http-request set-var(txn.i11) sc1_inc_gpc1     if { path /inc }
http-request set-var(txn.i21) sc2_inc_gpc1     if { path /inc }
http-request set-var(txn.ig1) sc_inc_gpc1(0)   if { path /inc }
http-request set-var(txn.c00) sc0_clr_gpc0     if { path /clr }
http-request set-var(txn.c10) sc1_clr_gpc0     if { path /clr }
http-request set-var(txn.c11) sc1_clr_gpc1     if { path /clr }
http-request set-var(txn.c20) sc2_clr_gpc0     if { path /clr }
http-request set-var(txn.c21) sc2_clr_gpc1     if { path /clr }
http-request set-var(txn.cg1) sc_clr_gpc1(0)   if { path /clr }
http-request set-var(txn.si)  src_inc_gpc(0,arr2)      if { path /src }
http-request set-var(txn.si0) src_inc_gpc0(leg2)       if { path /src }
http-request set-var(txn.si1) src_inc_gpc1(leg2)       if { path /src }
http-request set-var(txn.su)  src_updt_conn_cnt(cnt2)  if { path /src }
http-request set-var(txn.sc)  src_clr_gpc(0,arr2)      if { path /srcclr }
http-request set-var(txn.sc0) src_clr_gpc0(leg2)       if { path /srcclr }
http-request set-var(txn.sc1) src_clr_gpc1(leg2)       if { path /srcclr }
http-request return status 200
http-after-response set-header x-i0  "%[var(txn.i00)] %[var(txn.i10)] %[var(txn.i20)]"
http-after-response set-header x-i1  "%[var(txn.i11)] %[var(txn.i21)] %[var(txn.ig1)]"
http-after-response set-header x-c0  "%[var(txn.c00)] %[var(txn.c10)] %[var(txn.c20)]"
http-after-response set-header x-c1  "%[var(txn.c11)] %[var(txn.c21)] %[var(txn.cg1)]"
http-after-response set-header x-si  "%[var(txn.si)] %[var(txn.si0)] %[var(txn.si1)] %[var(txn.su)]"
http-after-response set-header x-sc  "%[var(txn.sc)] %[var(txn.sc0)] %[var(txn.sc1)]"
http-after-response set-header x-r1  "%[sc1_get_gpc0] %[sc1_get_gpc1] %[sc1_get_gpt0]"
http-after-response set-header x-r1r "%[sc1_gpc0_rate] %[sc1_gpc1_rate]"
backend arr3
stick-table type ip size 1m expire 1h store gpc(1),gpc_rate(1,10s)
frontend fe3
bind @FE3@
http-request track-sc0 src table arr3
http-request sc-inc-gpc(0,0)
http-request set-var(txn.cg) sc_clr_gpc(0,0)
http-request return status 200
http-after-response set-header x-cg "%[var(txn.cg)]"
http-after-response set-header x-g  "%[sc_get_gpc(0,0)]"
"####;

const STEPS_FE: &[Step] = &[
    ("/read", &[
        ("x-gpc0", "0"),
        ("x-gpc1", "0"),
        ("x-gpt2", "0"),
        ("x-lgpc0", "0"),
        ("x-lgpc1", "0"),
        ("x-lgpt0", "0"),
    ]),
    ("/upd", &[
        ("x-gpc0", "1"),
        ("x-gpc1", "5"),
        ("x-gpt2", "7"),
        ("x-rate0", "1"),
        ("x-lgpc0", "1"),
        ("x-lgpc1", "1"),
        ("x-lgpt0", "9"),
        ("x-lr0", "1"),
        ("x-lr1", "1"),
        ("x-sc0", "1"),
        ("x-sc0b", "1"),
        ("x-sc0t", "9"),
        ("x-sc0r", "1"),
        ("x-sc0r1", "1"),
        ("x-sc2", "1"),
        ("x-sc2b", "1"),
        ("x-sc2t", "9"),
        ("x-sc2r", "1"),
        ("x-sc2r1", "1"),
        ("x-tgpc0", "1"),
        ("x-tgpc1", "5"),
        ("x-tgpt2", "7"),
        ("x-trat0", "1"),
        ("x-tlgc0", "1"),
        ("x-tlgc1", "1"),
        ("x-tlgt0", "9"),
        ("x-tlr0", "1"),
        ("x-tlr1", "1"),
        ("x-sgpc0", "1"),
        ("x-sgpt2", "7"),
        ("x-srat0", "1"),
        ("x-slgc0", "1"),
        ("x-slgc1", "1"),
        ("x-slgt0", "9"),
        ("x-slr0", "1"),
        ("x-slr1", "1"),
    ]),
    ("/fetch", &[
        ("x-incf", "2"),
        ("x-incf0", "2"),
        ("x-incf1", "2"),
        ("x-gpc0", "2"),
        ("x-lgpc0", "2"),
        ("x-lgpc1", "2"),
    ]),
    ("/conv", &[
        ("x-tinc", "3"),
        ("x-tinc0", "3"),
        ("x-tinc1", "3"),
    ]),
    ("/clear", &[
        ("x-clrf", "3"),
        ("x-clrf0", "3"),
        ("x-clrf1", "3"),
        ("x-gpc0", "0"),
        ("x-lgpc0", "0"),
        ("x-lgpc1", "0"),
        ("x-gpt2", "7"),
        ("x-lgpt0", "9"),
    ]),
    ("/convclr", &[
        ("x-tclr", "0"),
        ("x-tclr0", "0"),
        ("x-tclr1", "0"),
    ]),
];

const STEPS_FE2: &[Step] = &[
    ("/inc", &[
        ("x-i0", "1 2 3"),
        ("x-i1", "1 2 3"),
        ("x-r1", "3 3 4"),
        ("x-r1r", "3 3"),
    ]),
    ("/clr", &[
        ("x-c0", "3 0 0"),
        ("x-c1", "3 0 0"),
        ("x-r1", "0 0 4"),
    ]),
    ("/src", &[
        ("x-si", "1 1 1 1"),
    ]),
    ("/srcclr", &[
        ("x-sc", "1 1 1"),
    ]),
];

const STEPS_FE3: &[Step] = &[
    ("/", &[
        ("x-cg", "1"),
        ("x-g", "0"),
    ]),
];


fn run(steps: &[Step], which: &str) {
    let (fe, fe2, fe3, ready) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let cfg = CFG
        .replace("@FE@", &fe.to_string())
        .replace("@FE2@", &fe2.to_string())
        .replace("@FE3@", &fe3.to_string())
        + &format!("\nfrontend ready\n  mode http\n  bind {ready}\n  http-request return status 200\n");
    let _ibex = start(&cfg, ready);
    let addr = match which {
        "fe" => fe,
        "fe2" => fe2,
        _ => fe3,
    };
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut wrong = Vec::new();
    for (path, expected) in steps {
        let got = request(&mut c, path);
        for (name, want) in *expected {
            let have = got.iter().find(|(k, _)| k == name).map_or("<absent>", |(_, v)| v.as_str());
            if have != *want {
                wrong.push(format!("{path}: {name} is {have:?}, HAProxy gives {want:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "values that differ from HAProxy's:\n{}", wrong.join("\n"));
}

/// The array and legacy tables, tracked by `sc0` and `sc2` (legacy) and `sc1` (array): the
/// actions, the fetches in their three families, the converters, and the clears.
#[test]
fn counters_and_tags_of_both_forms_through_actions_fetches_and_converters() {
    run(STEPS_FE, "fe");
}

/// Three counters tracking the same entry see each other's increments, and the `src_*` forms
/// write to an entry that is not tracked at all.
#[test]
fn the_shorthands_and_the_src_forms_write_the_entry_they_name() {
    run(STEPS_FE2, "fe2");
}

/// `sc_clr_gpc(0,0)` of the array form on a counter that tracks an array table.
#[test]
fn the_generic_clear_of_the_array_form() {
    run(STEPS_FE3, "fe3");
}
