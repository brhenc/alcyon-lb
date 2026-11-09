// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A rule action whose sample expression names a fetch or converter that does not exist is
//! a configuration error, as it is in `HAProxy` (`sample_parse_expr`, `src/sample.c`:
//! "unknown fetch method '%s'", "unknown converter '%s'"). Before this, Alcyon parsed the
//! expression text, loaded the configuration, and evaluated the expression per request,
//! where the unknown name yielded nothing -- so a typo in `set-var`, `set-src`,
//! `track-sc0`, ... loaded and the action silently did nothing on every request.
//!
//! Measured against `HAProxy` 3.5-dev8-885761-29, 2026-10-03, with `haproxy -c -f` on a
//! frontend `fe` and backend `be` (`mode http`) carrying each rule below:
//!
//! * refused, exit 1, "unknown fetch method 'nosuch'": every `REFUSED` rule with
//!   `nosuch`; `set-var(txn.x) 1` names `'1'`; `sc-set-gpt0(0) 0x10` and `1abc` name
//!   `'0x10'` and `'1abc'` (only a plain `strtol` integer is a value there);
//!   `set-var(txn.x) path_beg` and `hdr_beg(host)` (ACL shorthands, not fetches);
//!   `set-var(txn.x) Src` (names are case-sensitive).
//! * refused, "unknown converter 'nosuchconv'": `set-var(txn.x) str(a),nosuchconv`.
//! * accepted, exit 0: every `ACCEPTED` rule, including `set-var-fmt` with a word that is
//!   not a fetch (it is a log-format string, not an expression), `sc-set-gpt0(0) 1` and
//!   `-1`, and `set-retries 0x5` (an integer to `strtol(.., 0)`).
//!
//! At run time, `http-response set-var-fmt(txn.f) abc` sets `txn.f` to `abc`, and
//! `http-after-response set-var-fmt(txn.i) def` sets `txn.i` to `def` (same `HAProxy`,
//! same date, curl against `set-header x-f %[var(txn.f)]`).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use alcyon_rt::Engine;

fn alcyon_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_alcyon"))
}

/// A configuration with `fe_rule` in frontend `fe` and `be_rule` in backend `be`.
fn config(fe_rule: &str, be_rule: &str, bind: SocketAddr) -> String {
    format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {bind}\n  {fe_rule}\n  default_backend be\n\
         backend be\n  stick-table type ip size 10 store gpt0\n  {be_rule}\n  server s1 127.0.0.1:1\n"
    )
}

fn write_cfg(name: &str, body: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("alcyon_fetchnames_{}_{name}.cfg", std::process::id()));
    std::fs::write(&p, body).expect("write config");
    p
}

/// `alcyon -c -f <cfg>`: (exit code, stdout + stderr).
fn check(name: &str, cfg: &str) -> (Option<i32>, String) {
    let path = write_cfg(name, cfg);
    let out = Command::new(alcyon_bin()).arg("-c").arg("-f").arg(&path).output().expect("run alcyon -c");
    let _ = std::fs::remove_file(&path);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.code(), text)
}

/// `(frontend rule, backend rule, text the error must contain)`.
const REFUSED: &[(&str, &str, &str)] = &[
    ("", "http-request set-retries nosuch", "unknown fetch method 'nosuch'"),
    ("http-request set-var(txn.x) nosuch", "", "unknown fetch method 'nosuch'"),
    ("http-request set-var(txn.x) nosuch if TRUE", "", "unknown fetch method 'nosuch'"),
    ("http-request set-var(txn.x) str(a),nosuchconv", "", "unknown converter 'nosuchconv'"),
    ("http-request set-var(txn.x) 1", "", "unknown fetch method '1'"),
    ("http-request set-var(txn.x) path_beg", "", "unknown fetch method 'path_beg'"),
    ("http-request set-var(txn.x) hdr_beg(host)", "", "unknown fetch method 'hdr_beg'"),
    ("http-request set-var(txn.x) Src", "", "unknown fetch method 'Src'"),
    ("http-request set-src nosuch", "", "unknown fetch method 'nosuch'"),
    ("http-request set-dst nosuch", "", "unknown fetch method 'nosuch'"),
    ("http-request set-dst-port nosuch", "", "unknown fetch method 'nosuch'"),
    ("http-request track-sc0 nosuch", "", "unknown fetch method 'nosuch'"),
    ("http-request track-sc1 nosuch table be", "", "unknown fetch method 'nosuch'"),
    ("http-request track-sc2 nosuch", "", "unknown fetch method 'nosuch'"),
    ("http-request capture nosuch len 10", "", "unknown fetch method 'nosuch'"),
    ("http-request sc-set-gpt0(0) nosuch", "", "unknown fetch method 'nosuch'"),
    ("http-request sc-set-gpt0(0) 0x10", "", "unknown fetch method '0x10'"),
    ("http-request sc-set-gpt0(0) 1abc", "", "unknown fetch method '1abc'"),
    ("http-response set-var(txn.x) nosuch", "", "unknown fetch method 'nosuch'"),
    ("http-after-response set-var(txn.x) nosuch", "", "unknown fetch method 'nosuch'"),
    ("tcp-request connection set-src nosuch", "", "unknown fetch method 'nosuch'"),
    ("tcp-request connection set-dst nosuch", "", "unknown fetch method 'nosuch'"),
    ("tcp-request connection track-sc0 nosuch", "", "unknown fetch method 'nosuch'"),
    ("tcp-request session set-var(sess.x) nosuch", "", "unknown fetch method 'nosuch'"),
    ("tcp-request session set-src nosuch", "", "unknown fetch method 'nosuch'"),
    ("tcp-request session track-sc0 nosuch", "", "unknown fetch method 'nosuch'"),
    ("tcp-request session sc-set-gpt0(0) nosuch", "", "unknown fetch method 'nosuch'"),
    ("tcp-request content set-var(txn.x) nosuch", "", "unknown fetch method 'nosuch'"),
    ("tcp-request content set-dst nosuch", "", "unknown fetch method 'nosuch'"),
    ("tcp-request content track-sc0 nosuch", "", "unknown fetch method 'nosuch'"),
    ("tcp-request content sc-set-gpt0(0) nosuch", "", "unknown fetch method 'nosuch'"),
    ("", "tcp-response content set-var(txn.x) nosuch", "unknown fetch method 'nosuch'"),
    ("tcp-request connection track-sc1 nosuch table be", "", "unknown fetch method 'nosuch'"),
    ("tcp-request connection track-sc2 nosuch table be", "", "unknown fetch method 'nosuch'"),
    ("tcp-request session track-sc1 nosuch table be", "", "unknown fetch method 'nosuch'"),
    ("tcp-request session track-sc2 nosuch table be", "", "unknown fetch method 'nosuch'"),
    ("tcp-request session set-dst nosuch", "", "unknown fetch method 'nosuch'"),
    ("tcp-request content track-sc1 nosuch table be", "", "unknown fetch method 'nosuch'"),
    ("tcp-request content track-sc2 nosuch table be", "", "unknown fetch method 'nosuch'"),
    ("tcp-request content set-src nosuch", "", "unknown fetch method 'nosuch'"),
    // The quoted space is part of the argument, so the converter after it is still read.
    ("http-request set-var(txn.x) str('a b'),lowr", "", "unknown converter 'lowr'"),
];

/// The control: the same actions with expressions `HAProxy` accepts.
const ACCEPTED: &[(&str, &str)] = &[
    ("", "http-request set-retries int(3)"),
    ("", "http-request set-retries 0x5"),
    ("http-request set-var(txn.x) str(a) if TRUE", ""),
    ("http-request set-var(txn.x) src,lower", ""),
    ("http-request set-var(txn.x) hdr(host)", ""),
    ("http-request set-var(txn.x) req.hdr(host),lower", ""),
    ("http-request set-var(txn.x) src,ipmask(24)", ""),
    ("http-request set-var-fmt(txn.x) nosuch", ""),
    ("http-request set-dst-port hdr(x-port)", ""),
    ("http-request track-sc0 src table be", ""),
    ("http-request capture req.hdr(host) len 10", ""),
    ("http-request sc-set-gpt0(0) 1", ""),
    ("http-request sc-set-gpt0(0) -1", ""),
    ("http-response set-var(txn.x) str(a)", ""),
    ("http-response set-var-fmt(txn.x) nosuch", ""),
    ("http-after-response set-var-fmt(txn.x) nosuch", ""),
    ("tcp-request connection track-sc0 src table be", ""),
    ("tcp-request content set-var(txn.x) src", ""),
    ("", "tcp-response content set-var(txn.x) str(a)"),
    ("http-request set-var(txn.x) str('a b'),lower", ""),
];

#[test]
fn alcyon_c_refuses_an_action_naming_an_unknown_fetch_or_converter() {
    let bind: SocketAddr = "127.0.0.1:1".parse().expect("addr");
    let mut wrong = Vec::new();
    for (i, &(fe, be, want)) in REFUSED.iter().enumerate() {
        let (code, out) = check(&format!("refused{i}"), &config(fe, be, bind));
        if code != Some(1) || !out.contains(want) {
            wrong.push(format!("[{fe}{be}]: HAProxy exits 1 with \"{want}\"; alcyon -c exited {code:?}: {}", out.trim()));
        }
    }
    assert!(
        wrong.is_empty(),
        "these load in Alcyon and then do nothing on every request; HAProxy refuses them:\n{}",
        wrong.join("\n")
    );
}

#[test]
fn alcyon_c_accepts_the_same_actions_with_expressions_haproxy_accepts() {
    let bind: SocketAddr = "127.0.0.1:1".parse().expect("addr");
    let mut wrong = Vec::new();
    for (i, &(fe, be)) in ACCEPTED.iter().enumerate() {
        let (code, out) = check(&format!("accepted{i}"), &config(fe, be, bind));
        if code != Some(0) {
            wrong.push(format!("[{fe}{be}]: HAProxy accepts it; alcyon -c exited {code:?}: {}", out.trim()));
        }
    }
    assert!(wrong.is_empty(), "refused, though HAProxy accepts them:\n{}", wrong.join("\n"));
}

#[test]
fn the_error_names_the_proxy_and_the_rule() {
    let bind: SocketAddr = "127.0.0.1:1".parse().expect("addr");
    let (code, out) = check("names", &config("", "http-request set-retries nosuch", bind));
    assert_eq!(code, Some(1), "{out}");
    assert!(
        out.contains("backend 'be'") && out.contains("'http-request set-retries'"),
        "HAProxy says \"error detected in backend 'be' while parsing 'http-request \
         set-retries' rule : unknown fetch method 'nosuch'\"; Alcyon said: {out}"
    );
}

#[test]
fn engine_new_refuses_an_unknown_fetch() {
    let bind = common::reserve_addr();
    let cfg = alcyon_config::parse_str(&config("http-request set-src nosuch", "", bind)).expect("parse");
    match Engine::new(&cfg, 16) {
        Ok(_) => panic!("Engine::new built an engine whose set-src names no fetch"),
        Err(e) => assert!(e.to_string().contains("unknown fetch method 'nosuch'"), "{e}"),
    }
}

#[test]
fn the_daemon_does_not_start_on_an_unknown_fetch() {
    let bind = common::reserve_addr();
    let path = write_cfg("daemon", &config("http-request set-var(txn.x) nosuch", "", bind));
    let mut child = Command::new(alcyon_bin())
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn().map(common::Alcyon)
        .expect("spawn alcyon");
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(st) = child.try_wait().expect("wait") {
            break Some(st);
        }
        if Instant::now() > deadline {
            break None;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let listening = TcpStream::connect(bind).is_ok();
    common::stop(&mut child);
    let mut err = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut err);
    }
    let _ = std::fs::remove_file(&path);
    assert!(
        matches!(status, Some(st) if !st.success()) && !listening,
        "alcyon started (exit {status:?}, listening={listening}) on a set-var naming no fetch: {err}"
    );
    assert!(err.contains("unknown fetch method 'nosuch'"), "{err}");
}

/// A backend answering every request with 200 and `ok`.
fn ok_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    addr
}

#[test]
fn response_set_var_fmt_is_a_format_not_an_expression() {
    let origin = ok_backend();
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n  default_backend be\n\
         backend be\n  \
         http-response set-var-fmt(txn.f) abc\n  \
         http-response set-var-fmt(txn.g) \"x-%[str(y)]\"\n  \
         http-response set-var(txn.h) str(lit)\n  \
         http-response set-header x-f \"%[var(txn.f)]\"\n  \
         http-response set-header x-g \"%[var(txn.g)]\"\n  \
         http-response set-header x-h \"%[var(txn.h)]\"\n  \
         http-after-response set-var-fmt(txn.i) def\n  \
         http-after-response set-header x-i \"%[var(txn.i)]\"\n  \
         server s {origin}\n"
    );
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let client = thread::spawn(move || {
        let mut s = TcpStream::connect(fe).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let resp = client.join().expect("client");
    let head = resp.split("\r\n\r\n").next().unwrap_or("").to_ascii_lowercase();
    let wrong: Vec<&str> = ["x-f: abc", "x-g: x-y", "x-h: lit", "x-i: def"]
        .into_iter()
        .filter(|h| !head.lines().any(|l| l == *h))
        .collect();
    assert!(
        wrong.is_empty(),
        "HAProxy sends x-f: abc, x-g: x-y, x-h: lit, x-i: def; missing {wrong:?} in:\n{head}"
    );
}
