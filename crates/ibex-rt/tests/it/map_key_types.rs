// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! What a map file or `add map` does with a key the converter cannot use (T274 J1, J3).
//!
//! Measured against `HAProxy` 3.5-dev8-885761-29, 2026-10-11 (`pat_parse_int`,
//! `pat_parse_ip` in `src/pattern.c`):
//!
//! * Loading: `map_int*` and `map_ip*` refuse a key that is not an integer / range / address
//!   (resp. network), `map_reg*` a regex that does not compile; the other `map_*` accept
//!   any key. The error is
//!   `invalid args in converter '<c>' : <why> at line <n> of file '<path>'.`
//! * `add map` answers the same `<why>` (`'x' is not a number.`, `'x' is not a valid number
//!   range.`, `'x' is not a valid IPv4 or IPv6 address.`, `regex 'x' is invalid (error=...,
//!   erroffset=N).`) and adds nothing.
//! * Integers: digits only (`-` or `:` make a range, `-5` is "up to 5", `5-` "5 or more"),
//!   at most `i64::MAX`; `+4`, `0x10`, `1.5`, `1e3` are not numbers; `5-1`, `a-b`, `1-5-7`
//!   are not ranges.
//! * Addresses: IPv4/IPv6 with an optional `/<bits>` (<= 32 / 128) or `/<dotted mask>`.

use crate::common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn tmp(tag: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("ibex_t274j_{}_{n}_{tag}", std::process::id()))
}

/// `-c` with `converter` (a name, applied to `input`) reading a map file holding `content`.
fn load(input: &str, converter: &str, content: &str) -> (Option<i32>, String, PathBuf) {
    let f = tmp("map");
    std::fs::write(&f, content).expect("write map");
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n\
         frontend fe\n  bind 127.0.0.1:18080\n  http-request set-var(txn.a) {input},{converter}({})\n  http-request return status 200\n",
        f.display()
    );
    let path = tmp("cfg");
    std::fs::write(&path, cfg).expect("write config");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("run -c");
    let _ = std::fs::remove_file(&path);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.code(), text, f)
}

#[test]
fn a_map_int_file_refuses_what_is_not_an_integer_or_a_range() {
    for (key, why) in [
        ("xyz", "is not a number"),
        ("0x10", "is not a number"),
        ("1.5", "is not a number"),
        ("+4", "is not a number"),
        ("1e3", "is not a number"),
        ("9223372036854775808", "is not a number"),
        ("a-b", "is not a valid number range"),
        ("5-x", "is not a valid number range"),
        ("1-5-7", "is not a valid number range"),
        ("5-1", "is not a valid number range"),
        ("1:5:7", "is not a valid number range"),
        ("-3--1", "is not a valid number range"),
        ("1--5", "is not a valid number range"),
        ("-9223372036854775808", "is not a valid number range"),
    ] {
        for conv in ["map_int", "map_int_int", "map_int_ip"] {
            let value = if conv == "map_int_ip" { "1.2.3.4" } else { "v" };
            let (code, out, f) = load("int(1)", conv, &format!("{key} {value}\n"));
            let want = format!("invalid args in converter '{conv}' : '{key}' {why} at line 1 of file '{}'.", f.display());
            assert_eq!(code, Some(1), "{conv} key {key}: must be refused:\n{out}");
            assert!(out.contains(&want), "{conv} key {key}: want {want:?} in:\n{out}");
            let _ = std::fs::remove_file(&f);
        }
    }
}

#[test]
fn a_map_int_file_loads_integers_and_ranges() {
    let keys = "5 a\n-3 b\n1-5 c\n1:5 d\n-5 e\n5- f\n--3 g\n99999999999 h\n9223372036854775807 i\n";
    let (code, out, f) = load("int(1)", "map_int", keys);
    assert_eq!(code, Some(0), "must load:\n{out}");
    let _ = std::fs::remove_file(&f);
}

#[test]
fn the_line_number_counts_comments_and_blank_lines() {
    let (code, out, f) = load("int(1)", "map_int", "# c\n\n5 a\nzz b\n");
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains(&format!("'zz' is not a number at line 4 of file '{}'.", f.display())), "{out}");
    let _ = std::fs::remove_file(&f);
}

#[test]
fn a_map_ip_file_refuses_what_is_not_an_address_or_a_network() {
    for key in [
        "5", "999.1.1.1", "10.0.0.1/33", "10.0.0.1/", "10.0.0.1/x", "::1/129", "1.2.3", "01.2.3.4", "1.2.3.4:80", "[::1]",
    ] {
        for conv in ["map_ip", "map_ip_int", "map_ip_ip"] {
            let value = if conv == "map_ip_ip" { "1.2.3.4" } else { "7" };
            let (code, out, f) = load("src", conv, &format!("{key} {value}\n"));
            let want = format!(
                "invalid args in converter '{conv}' : '{key}' is not a valid IPv4 or IPv6 address at line 1 of file '{}'.",
                f.display()
            );
            assert_eq!(code, Some(1), "{conv} key {key}: must be refused:\n{out}");
            assert!(out.contains(&want), "{conv} key {key}: want {want:?} in:\n{out}");
            let _ = std::fs::remove_file(&f);
        }
    }
}

#[test]
fn a_map_ip_file_loads_addresses_and_networks() {
    let keys = "10.0.0.1 a\n10.0.0.1/24 b\n10.0.0.1/255.255.255.0 c\n::1 d\n::1/64 e\n::ffff:1.2.3.4 f\n10.0.0.1/0 g\n";
    let (code, out, f) = load("src", "map_ip", keys);
    assert_eq!(code, Some(0), "must load:\n{out}");
    let _ = std::fs::remove_file(&f);
}

#[test]
fn string_maps_accept_any_key() {
    for conv in ["map", "map_str", "map_beg", "map_end", "map_sub", "map_dir", "map_dom"] {
        let (code, out, f) = load("str(a)", conv, "999.1.1.1 a\n( b\n-3--1 c\n");
        assert_eq!(code, Some(0), "{conv} must load any key:\n{out}");
        let _ = std::fs::remove_file(&f);
    }
}

#[test]
fn a_map_reg_file_reports_the_line_and_the_file() {
    let (code, out, f) = load("str(a)", "map_reg", "^/ok v\n( b\n");
    assert_eq!(code, Some(1), "{out}");
    assert!(
        out.contains(&format!("invalid args in converter 'map_reg' : regex '(' is invalid (error=")) && out.contains(&format!(") at line 2 of file '{}'.", f.display())),
        "{out}"
    );
    let _ = std::fs::remove_file(&f);
}

struct Ibex {
    child: Child,
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

fn cli(sock: &PathBuf, input: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let _ = s.write_all(input.as_bytes());
    let _ = s.shutdown(std::net::Shutdown::Write);
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// A running Ibex with an int map (#0), an ip map (#1) and a regex map (#2).
fn running() -> (Ibex, PathBuf, [String; 4]) {
    let (sock, cfg, mi, mp, mr, ma) = (tmp("sock"), tmp("cfg"), tmp("mi"), tmp("mp"), tmp("mr"), tmp("acl"));
    std::fs::write(&mi, "5 a\n").expect("map");
    std::fs::write(&mp, "10.0.0.1 a\n").expect("map");
    std::fs::write(&mr, "^/x v\n").expect("map");
    std::fs::write(&ma, "^/y\n").expect("acl");
    let fe = common::reserve_addr();
    let text = format!(
        "global\n  stats socket {} mode 600 level admin\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
         frontend f\n  bind {fe}\n  http-request set-var(txn.a) int(1),map_int({})\n\
         http-request set-var(txn.b) src,map_ip({})\n  http-request set-var(txn.c) path,map_reg({})\n\
         http-request deny if {{ path_reg -f {} }}\n  http-request return status 200\n",
        sock.display(),
        mi.display(),
        mp.display(),
        mr.display(),
        ma.display()
    );
    std::fs::write(&cfg, &text).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let paths = [mi, mp, mr, ma].map(|p| p.display().to_string());
    let ibex = Ibex { child, files: vec![cfg, tmp_path(&paths[0]), tmp_path(&paths[1]), tmp_path(&paths[2]), tmp_path(&paths[3]), sock.clone()] };
    assert!(common::wait_listening(fe), "ibex never listened with:\n{text}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    (ibex, sock, paths)
}

fn tmp_path(s: &str) -> PathBuf {
    PathBuf::from(s)
}

#[test]
fn add_map_refuses_the_keys_the_load_refuses() {
    let (_ibex, sock, files) = running();
    let [mi, mp, mr, ma] = files;
    let _ = (&mr, &ma);
    for (id, key, want) in [
        (&mi, "xyz", "'xyz' is not a number."),
        (&mi, "-3--1", "'-3--1' is not a valid number range."),
        (&mi, "9223372036854775808", "'9223372036854775808' is not a number."),
        (&mi, "5-1", "'5-1' is not a valid number range."),
        (&mp, "foo", "'foo' is not a valid IPv4 or IPv6 address."),
        (&mp, "10.0.0.1/33", "'10.0.0.1/33' is not a valid IPv4 or IPv6 address."),
        (&mp, "::1/129", "'::1/129' is not a valid IPv4 or IPv6 address."),
        (&mp, "1.2.3", "'1.2.3' is not a valid IPv4 or IPv6 address."),
        (&mp, "localhost", "'localhost' is not a valid IPv4 or IPv6 address."),
    ] {
        let out = cli(&sock, &format!("add map {id} {key} v\n"));
        assert_eq!(out.trim_end(), want, "add map {id} {key}: {out:?}");
    }
    for (id, key) in [(&mi, "1-5"), (&mi, "-3"), (&mp, "10.0.0.1/24"), (&mp, "10.0.0.1/255.255.255.0"), (&mp, "::1/64")] {
        let out = cli(&sock, &format!("add map {id} {key} v\n"));
        assert_eq!(out.trim_end(), "", "add map {id} {key} must be accepted: {out:?}");
    }
}

#[test]
fn add_map_and_add_acl_with_a_refused_regex_give_the_offset() {
    let (_ibex, sock, files) = running();
    let [_mi, _mp, mr, ma] = files;
    // erroffset values measured on HAProxy 3.5-dev8-885761-29 (PCRE2).
    for (pat, off) in [("(", 1), ("(a", 2), ("ab(", 3), ("[", 1), ("[a", 2), ("x[", 2), (")", 1), ("abc)", 4), ("*a", 1), ("+", 1)] {
        let out = cli(&sock, &format!("add map {mr} {pat} v\n"));
        assert!(
            out.starts_with(&format!("regex '{pat}' is invalid (error=")) && out.trim_end().ends_with(&format!(", erroffset={off}).")),
            "add map {pat}: want erroffset={off}: {out:?}"
        );
        let out = cli(&sock, &format!("add acl {ma} {pat}\n"));
        assert!(
            out.starts_with(&format!("regex '{pat}' is invalid (error=")) && out.trim_end().ends_with(&format!(", erroffset={off}).")),
            "add acl {pat}: want erroffset={off}: {out:?}"
        );
    }
}
