// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T364 S5: `tune.vars.*` accounting (`var_accounting_add` / `var_accounting_diff`, src/vars.c).
//!
//! Every variable costs 88 bytes (`sizeof(struct var)` of the x86-64 build) plus the bytes of a
//! `str`, a `bin` or an unusual method; a set that does not fit is refused. Limits nest: `req`/`res`
//! count in `reqres`, `txn` and `sess`, `txn` in `sess`, all of them in `proc`. Expected values are
//! `HAProxy` 3.5-dev8's answers (measured 2026-10-18).
//!
//! One difference is pinned as Alcyon's, not HAProxy's: a `str` that does not fit turns the variable
//! into a `bool` (memory-less) in both, but HAProxy's keeps the old integer in the union, so an
//! `int(7)` that fails to become a 10-byte string still prints `7` and adds as 7. Alcyon stores
//! `Bool(old != 0)`: `1`, and `2` after `add(1)` (T364 Q1, tradeoff.md).

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

/// (name, global lines, rules, lf-string, HAProxy's body).
const CASES: &[(&str, &str, &str, &str, &str)] = &[
    // The cost of an integer variable is 88: 87 refuses it, 88 takes it.
    ("txn 87", "tune.vars.txn-max-size 87", "set-var(txn.a) int(1)", "%[var(txn.a)]|", "|"),
    ("txn 88", "tune.vars.txn-max-size 88", "set-var(txn.a) int(1)", "%[var(txn.a)]|", "1|"),
    // Sess counts every transaction variable too.
    (
        "sess 100",
        "tune.vars.sess-max-size 100",
        "set-var(txn.a) int(1)\n  http-request set-var(txn.b) int(2)",
        "%[var(txn.a)]|%[var(txn.b)]",
        "1|",
    ),
    // Reqres limits req/res, and not txn.
    (
        "reqres 50",
        "tune.vars.reqres-max-size 50",
        "set-var(txn.a) int(1)\n  http-request set-var(req.a) int(2)",
        "%[var(txn.a)]|%[var(req.a)]",
        "1|",
    ),
    (
        "reqres 150",
        "tune.vars.reqres-max-size 150",
        "set-var(req.a) int(1)\n  http-request set-var(req.b) int(2)",
        "%[var(req.a)]|%[var(req.b)]",
        "1|",
    ),
    // A string counts its bytes: 88 + 10 fits 100, the second variable does not.
    (
        "str bytes",
        "tune.vars.txn-max-size 100",
        "set-var(txn.a) str(abcdefghij)\n  http-request set-var(txn.b) str(abcdefghij)",
        "%[var(txn.a)]|%[var(txn.b)]",
        "abcdefghij|",
    ),
    // An unset variable gives its bytes and its 88 back.
    (
        "unset gives back",
        "tune.vars.txn-max-size 100",
        "set-var(txn.a) str(abcdefghij)\n  http-request unset-var(txn.a)\n  http-request set-var(txn.b) str(abcdefghij)",
        "%[var(txn.a)]|%[var(txn.b)]",
        "|abcdefghij",
    ),
    // A longer string that does not fit makes the variable a bool.
    (
        "str grows",
        "tune.vars.txn-max-size 100",
        "set-var(txn.a) str(abcdefghij)\n  http-request set-var(txn.a) str(abcdefghijklmn)",
        "%[var(txn.a)]|%[var(txn.a),length]",
        "0|1",
    ),
    // An integer that cannot become a 10-byte string stays a variable: Alcyon says 1 and 2 (HAProxy: 7 and 8).
    (
        "int to str (Alcyon)",
        "tune.vars.txn-max-size 90",
        "set-var(txn.a) int(7)\n  http-request set-var(txn.a) str(0123456789)",
        "%[var(txn.a)]|%[var(txn.a),add(1)]",
        "1|2",
    ),
    // No limit: nothing refused.
    (
        "no limit",
        "tune.bufsize 16384",
        "set-var(txn.a) int(1)\n  http-request set-var(txn.b) str(abcdefghij)\n  http-request set-var(req.a) int(2)",
        "%[var(txn.a)]|%[var(txn.b)]|%[var(req.a)]",
        "1|abcdefghij|2",
    ),
];

fn run_alcyon(global: &str, rules: &str, lf: &str) -> String {
    let addr = common::reserve_addr();
    let cfg = format!(
        "global\n  {global}\ndefaults\n  mode http\n  timeout client 2s\n  timeout server 2s\n  timeout connect 2s\n\
         frontend f\n  bind {addr}\n  http-request {rules}\n  http-request return status 200 content-type text/plain lf-string \"{lf}\"\n"
    );
    let path = std::env::temp_dir().join(format!("alcyon-t364-s5-{}-{}.cfg", std::process::id(), addr.port()));
    std::fs::write(&path, cfg).expect("write cfg");
    let mut alcyon = common::Alcyon(
        Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-db").arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn alcyon"),
    );
    assert!(common::wait_listening(addr), "alcyon did not listen");
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").expect("send");
    let mut d = Vec::new();
    let _ = s.read_to_end(&mut d);
    common::stop(&mut alcyon);
    let _ = std::fs::remove_file(&path);
    let d = String::from_utf8_lossy(&d).into_owned();
    d.split_once("\r\n\r\n").map_or(String::new(), |(_, b)| b.to_string())
}

#[test]
fn a_variable_that_does_not_fit_its_scope_limit_is_refused() {
    let wrong: Vec<String> = CASES
        .iter()
        .filter_map(|(name, global, rules, lf, want)| {
            let got = run_alcyon(global, rules, lf);
            (got != *want).then(|| format!("{name}: want {want:?}, got {got:?}"))
        })
        .collect();
    assert!(wrong.is_empty(), "{} cases differ from HAProxy:\n{}", wrong.len(), wrong.join("\n"));
}

/// `vars_max_size`: `strtol`, the whole word, no suffix; `-5` and nothing at all are accepted.
#[test]
fn the_limits_parse_as_strtol_and_refuse_a_suffix() {
    for kw in [
        "global-max-size",
        "proc-max-size",
        "sess-max-size",
        "txn-max-size",
        "reqres-max-size",
        "check-max-size",
    ] {
        for (arg, ok) in [("1000", true), ("-5", true), ("12k", false), ("abc", false)] {
            let path = std::env::temp_dir().join(format!("alcyon-t364-s5-kw-{}-{kw}.cfg", std::process::id()));
            std::fs::write(&path, format!("global\n  tune.vars.{kw} {arg}\ndefaults\n  mode http\nfrontend f\n  bind 127.0.0.1:1\n")).expect("write");
            let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&path).output().expect("run");
            let _ = std::fs::remove_file(&path);
            let text = String::from_utf8_lossy(&out.stderr).into_owned() + &String::from_utf8_lossy(&out.stdout);
            assert_eq!(out.status.success(), ok, "tune.vars.{kw} {arg}: {text}");
            if !ok {
                assert!(text.contains(&format!("tune.vars.{kw}: '{arg}' is an invalid size")), "tune.vars.{kw} {arg}: {text}");
            }
        }
    }
    let path = std::env::temp_dir().join(format!("alcyon-t364-s5-fm-{}.cfg", std::process::id()));
    std::fs::write(&path, "global\n  tune.vars.from-map.max 3\ndefaults\n  mode http\nfrontend f\n  bind 127.0.0.1:1\n").expect("write");
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&path).output().expect("run");
    let _ = std::fs::remove_file(&path);
    assert!(out.status.success(), "tune.vars.from-map.max: {}", String::from_utf8_lossy(&out.stderr));
}
