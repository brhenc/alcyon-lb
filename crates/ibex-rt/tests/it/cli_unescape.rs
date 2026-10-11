// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The CLI unescapes backslashes in a command line (T287 item 1, `cli_parse_request`).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29`, 2026-10-11, one command per connection, an
//! `acl -f` file (`#0`), a map file, `show acl|map` after each:
//!
//! ```text
//! add acl #0 a\\b        entry  a\b          (two backslashes are one)
//! add acl #0 a\ b        entry  a b          (an escaped space is part of the word)
//! add acl #0 a\tb        entry  atb          (any other escaped character: the backslash goes)
//! add acl #0 a\\ b       entry  a\           (the unescaped space ends the word; `b` is ignored)
//! add acl #0 "q r"       entry  "q           (no quoting)
//! add map #2 k\\1 v\ x   entry  k\1 v x
//! add map #2 <<          payload lines are NOT unescaped: `x\\y v\\1` is stored as is
//! set var proc.s str(a\ b)    value <a b>;  `str(a\\b)` -> <a\b>;  `str(a\nb)` -> <anb>
//! set var proc.y fmt a\ b\\c  value <a b\c>
//! ```
//!
//! Ibex passed the text through: `a\\b` was stored with both backslashes and `a\ b` was
//! cut at the space.

use crate::common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Ibex {
    child: Child,
    sock: PathBuf,
    files: Vec<PathBuf>,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        for p in &self.files {
            let _ = std::fs::remove_file(p);
        }
    }
}

fn start(tag: &str) -> Ibex {
    let tmp = std::env::temp_dir();
    let tag = format!("ibex_t287_{}_{tag}", std::process::id());
    let (sock, cfg, map, acl) = (
        tmp.join(format!("{tag}.sock")),
        tmp.join(format!("{tag}.cfg")),
        tmp.join(format!("{tag}.map")),
        tmp.join(format!("{tag}.acl")),
    );
    std::fs::write(&map, "/a 1\n").expect("map");
    std::fs::write(&acl, "/x\n").expect("acl");
    let fe = common::reserve_addr();
    let text = format!(
        "global\n  stats socket {sock} mode 600 level admin\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
         frontend f\n  bind {fe}\n  acl okpath path -f {acl}\n\
         \x20 http-request set-var(txn.m) path,map({map},none)\n\
         \x20 http-request return status 200 hdr x-m %[var(txn.m)] if okpath\n\
         \x20 http-request return status 200 hdr x-m %[var(txn.m)]\n",
        sock = sock.display(),
        acl = acl.display(),
        map = map.display(),
    );
    std::fs::write(&cfg, &text).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, sock, files: vec![cfg, map, acl] };
    assert!(common::wait_listening(fe), "ibex never listened with:\n{text}");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !ibex.sock.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    ibex
}

fn cli_raw(ibex: &Ibex, input: &str) -> String {
    let mut s = UnixStream::connect(&ibex.sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(input.as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn cli(ibex: &Ibex, cmd: &str) -> String {
    cli_raw(ibex, &format!("{cmd}\n"))
}

/// `key value` lines of a `show acl|map <ref>` answer, addresses dropped.
fn entries(ibex: &Ibex, r: &str) -> Vec<String> {
    cli(ibex, &format!("show {r}"))
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.split_once(' ').map_or("", |x| x.1).to_string())
        .collect()
}

#[test]
fn add_acl_unescapes_backslashes() {
    let ibex = start("acl");
    for c in [r"add acl #0 a\\b", r"add acl #0 a\ b", r"add acl #0 a\tb", r"add acl #0 a\\ b", "add acl #0 \"q r\""] {
        assert_eq!(cli(&ibex, c), "\n", "{c}");
    }
    let got = entries(&ibex, "acl #0");
    assert_eq!(got, ["/x", r"a\b", "a b", "atb", r"a\", "\"q"], "{got:?}");
}

#[test]
fn map_commands_unescape_backslashes() {
    let ibex = start("map");
    assert_eq!(cli(&ibex, r"add map #2 k\\1 v\ x"), "\n");
    assert_eq!(cli(&ibex, r"add map #2 /q v\ y"), "\n");
    assert_eq!(entries(&ibex, "map #2"), ["/a 1", r"k\1 v x", "/q v y"]);
    assert_eq!(cli(&ibex, r"set map #2 k\\1 n\ 1"), "\n");
    assert_eq!(entries(&ibex, "map #2"), ["/a 1", r"k\1 n 1", "/q v y"]);
    assert_eq!(cli(&ibex, r"del map #2 k\\1"), "\n");
    assert_eq!(entries(&ibex, "map #2"), ["/a 1", "/q v y"]);
    // A payload line is taken as it is.
    assert_eq!(cli_raw(&ibex, "add map #2 <<\nx\\\\y v\\\\1\n\n"), "\n");
    assert!(entries(&ibex, "map #2").contains(&r"x\\y v\\1".to_string()));
}

#[test]
fn del_acl_and_set_var_unescape_backslashes() {
    let ibex = start("var");
    cli(&ibex, r"add acl #0 a\\b");
    assert_eq!(cli(&ibex, r"del acl #0 a\\b"), "\n");
    assert_eq!(entries(&ibex, "acl #0"), ["/x"]);
    for (cmd, want) in [
        (r"set var proc.s str(a\ b)", "proc.s: type=str value=<a b>\n\n"),
        (r"set var proc.t str(a\\b)", "proc.t: type=str value=<a\\b>\n\n"),
        (r"set var proc.v str(a\nb)", "proc.v: type=str value=<anb>\n\n"),
        (r"set var proc.y fmt a\ b\\c", "proc.y: type=str value=<a b\\c>\n\n"),
    ] {
        cli(&ibex, cmd);
        let name = cmd.split(' ').nth(2).unwrap();
        assert_eq!(cli(&ibex, &format!("get var {name}")), want, "{cmd}");
    }
}
