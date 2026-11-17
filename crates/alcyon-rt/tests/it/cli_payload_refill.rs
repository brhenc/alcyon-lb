// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! CLI payloads with lines longer than the buffer, received in several reads. The Rust
//! counterpart of `reg-tests/cli/payload_parsing.vtc` (HAProxy 3.5-dev11), one test per
//! payload of that reg-test, with `tune.bufsize 1024` to force the payload to span the
//! buffer and arrive in several reads:
//!
//! 1. one payload line longer than `tune.bufsize`, sent in chunks: it is reassembled
//!    line by line and the command runs;
//! 2. several lines shorter than `tune.bufsize` but bigger than the payload buffer as a
//!    whole: the end of the payload is still detected after the buffer grew;
//! 3. a mix of short and long lines: the parsing resumes after a reassembled line;
//! 4. a customized end pattern (`<<123`) split across two reads: the end is detected in
//!    the line reassembled from its two parts;
//!
//! 5. the `get map` answers on the other key types (`int`, `ip`, `reg`, `regm`) and on
//!    the error cases, which the payload answers feed into.
//!
//! Every expected answer was measured byte for byte on `HAProxy` 3.5-dev11 with
//! `tune.bufsize 1024`: the `add map` answer is one empty line; the `get map` answers are
//! one line per the format `type=str, case=sensitive, found=yes, idx=tree, key="K"`, with
//! `, value="V", type="str"` appended only when the whole line fits the buffer (a line of
//! a long value is left without it, as the oracle's fixed-size answer chunk truncates it),
//! and the closing empty line.
//!
//! Set `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`: it passes all.

use crate::common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

struct Proxy {
    child: Child,
    sock: PathBuf,
    map: PathBuf,
    dir: PathBuf,
    _dir: TempDir,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn spawn(dir: TempDir, sock: &Path, map: &Path) -> Proxy {
    let cfg = dir.path().join("cfg");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut child = Command::new(&bin)
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {bin}: {e}"));
    let t0 = Instant::now();
    loop {
        if UnixStream::connect(sock).is_ok() {
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "the stats socket never opened");
        thread::sleep(Duration::from_millis(20));
    }
    Proxy {
        child,
        sock: sock.to_path_buf(),
        map: map.to_path_buf(),
        dir: dir.path().to_path_buf(),
        _dir: dir,
    }
}

/// The proxy of the reg-test: `tune.bufsize 1024`, an admin stats socket, and a map with
/// the one entry the `shell` line of the reg-test puts in the file, read by the frontend.
fn start() -> Proxy {
    let dir = TempDir::new().expect("tmpdir");
    let sock = dir.path().join("stats");
    let map = dir.path().join("map");
    std::fs::write(&map, "k0 v0\n").expect("map");
    let cfg = dir.path().join("cfg");
    std::fs::write(
        &cfg,
        format!(
            "global\n    tune.bufsize 1024\nstats socket {} level admin\n\
             defaults\n    mode http\n    timeout connect 5s\n    timeout client 5s\n    \
             timeout server 5s\nfrontend fe\n    bind {}\n    http-request set-header X-V \
             %[req.hdr(x-t),map(\"{}\")]\n",
            sock.display(),
            common::reserve_addr(),
            map.display()
        ),
    )
    .expect("cfg");
    spawn(dir, &sock, &map)
}

/// A proxy with one map per key type (`map_int_int`, `map_ip_ip`, `map_reg`, `map_regm`),
/// for the `get map` answers on the typed tables.
fn start_typed() -> Proxy {
    let dir = TempDir::new().expect("tmpdir");
    let sock = dir.path().join("stats");
    let mi = dir.path().join("mi");
    let mp = dir.path().join("mp");
    let mr = dir.path().join("mr");
    let mg = dir.path().join("mg");
    std::fs::write(&mi, "10-20 100\n30 300\n").expect("mi");
    std::fs::write(&mp, "10.0.0.0/8 10.9.0.1\n").expect("mp");
    std::fs::write(&mr, "^k(.*)$ g\\1\n").expect("mr");
    std::fs::write(&mg, "^k(.*)$ g\\1\n").expect("mg");
    let cfg = dir.path().join("cfg");
    std::fs::write(
        &cfg,
        format!(
            "global\n    tune.bufsize 1024\nstats socket {} level admin\n\
             defaults\n    mode http\n    timeout connect 5s\n    timeout client 5s\n    \
             timeout server 5s\nfrontend fe\n    bind {}\n    http-request set-header X-I \
             %[req.hdr(x-i),map_int_int(\"{}\")]\n    http-request set-header X-J \
             %[req.hdr(x-j),map_ip_ip(\"{}\")]\n    http-request set-header X-K \
             %[req.hdr(x-k),map_reg(\"{}\")]\n    http-request set-header X-L \
             %[req.hdr(x-l),map_regm(\"{}\")]\n",
            sock.display(),
            common::reserve_addr(),
            mi.display(),
            mp.display(),
            mr.display(),
            mg.display()
        ),
    )
    .expect("cfg");
    spawn(dir, &sock, &mi)
}

/// Sends each part to a fresh stats-socket connection, pausing `pause` ms after each one
/// (as the reg-test's one `send` line per write forces several reads), then reads the
/// whole answer until the server closes. A write that fails is a connection lost mid
/// payload: the assertion message says so.
fn payload_exchange(p: &Proxy, parts: &[(Vec<u8>, u64)]) -> Vec<u8> {
    let mut c = UnixStream::connect(&p.sock).expect("connect to the stats socket");
    c.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    for (bytes, pause) in parts {
        c.write_all(bytes)
            .unwrap_or_else(|e| panic!("connection lost while the payload was in flight: {e}"));
        thread::sleep(Duration::from_millis(*pause));
    }
    let mut got = Vec::new();
    let mut b = [0u8; 65536];
    loop {
        match c.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&b[..n]),
        }
    }
    got
}

/// One CLI command on its own connection; the answer byte for byte.
fn cli(p: &Proxy, cmd: &str) -> Vec<u8> {
    let mut c = UnixStream::connect(&p.sock).expect("connect to the stats socket");
    c.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    c.write_all(cmd.as_bytes()).expect("send the CLI command");
    let mut got = Vec::new();
    let mut b = [0u8; 65536];
    loop {
        match c.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&b[..n]),
        }
    }
    got
}

/// One `get map` command on the reg-test map, on its own connection.
fn get_map(p: &Proxy, key: &str) -> Vec<u8> {
    cli(p, &format!("get map {} {}\n", p.map.display(), key))
}

/// The `get map` answer of a found key of value `val` that fits the 1024-byte buffer.
fn found(map: &Path, key: &str, val: &str) -> Vec<u8> {
    format!(
        "type=str, case=sensitive, found=yes, idx=tree, key=\"{key}\", value=\"{val}\", type=\"str\"\n\n"
    )
    .into_bytes()
}

/// The answer of a found key whose value is too long for the line to fit the buffer: the
/// oracle prints the line without its `value=` part (measured).
fn found_truncated(key: &str) -> Vec<u8> {
    format!("type=str, case=sensitive, found=yes, idx=tree, key=\"{key}\"\n\n").into_bytes()
}

/// 1. A single payload line of 4003 bytes, longer than `tune.bufsize`, sent in chunks:
/// if the line is not reassembled, the CLI is stuck and never closes the connection.
#[test]
fn long_payload_line_in_several_reads() {
    let p = start();
    let parts: Vec<(Vec<u8>, u64)> = vec![
        (format!("add map {} <<", p.map.display()).into_bytes(), 100),
        (b"\n".to_vec(), 100),
        (b"k1 ".to_vec(), 100),
        (vec![b'a'; 2000], 100),
        (vec![b'b'; 2000], 100),
        (b"\n".to_vec(), 100),
        (b"\n".to_vec(), 0),
    ];
    assert_eq!(payload_exchange(&p, &parts), b"\n", "the add map answer");
    assert_eq!(get_map(&p, "k1"), found_truncated("k1"), "the long line was reassembled");
}

/// 2. A payload of 4 lines of 250 bytes each, bigger than the initial payload buffer: the
/// end of the payload arrives after the buffer grew and must still be detected.
#[test]
fn payload_bigger_than_buffer_in_short_lines() {
    let p = start();
    let k2 = format!("k2 a{}", "a".repeat(246));
    let k3 = format!("k3 b{}", "b".repeat(246));
    let k4 = format!("k4 c{}", "c".repeat(246));
    let k5 = format!("k5 d{}", "d".repeat(246));
    let parts: Vec<(Vec<u8>, u64)> = vec![
        (format!("add map {} <<", p.map.display()).into_bytes(), 100),
        (b"\n".to_vec(), 100),
        (k2.into_bytes(), 100),
        (b"\n".to_vec(), 100),
        (k3.into_bytes(), 100),
        (b"\n".to_vec(), 100),
        (k4.into_bytes(), 100),
        (b"\n".to_vec(), 100),
        (k5.into_bytes(), 100),
        (b"\n".to_vec(), 100),
        (b"\n".to_vec(), 0),
    ];
    assert_eq!(payload_exchange(&p, &parts), b"\n", "the add map answer");
    assert_eq!(get_map(&p, "k2"), found(&p.map, "k2", &"a".repeat(247)), "first short line");
    assert_eq!(get_map(&p, "k5"), found(&p.map, "k5", &"d".repeat(247)), "last short line");
}

/// 3. A payload mixing lines shorter and longer than `tune.bufsize`: the parsing resumes
/// correctly after a reassembled line.
#[test]
fn payload_mixed_short_and_long_lines() {
    let p = start();
    let k6 = format!("k6 {}{}", "e".repeat(1500), "f".repeat(1500));
    let k7 = format!("k7 g{}", "g".repeat(246));
    let k8 = format!("k8 {}{}", "h".repeat(1500), "i".repeat(1500));
    let parts: Vec<(Vec<u8>, u64)> = vec![
        (format!("add map {} <<", p.map.display()).into_bytes(), 100),
        (b"\n".to_vec(), 100),
        (k6.into_bytes(), 100),
        (b"\n".to_vec(), 100),
        (k7.into_bytes(), 100),
        (b"\n".to_vec(), 100),
        (k8.into_bytes(), 100),
        (b"\n".to_vec(), 100),
        (b"\n".to_vec(), 0),
    ];
    assert_eq!(payload_exchange(&p, &parts), b"\n", "the add map answer");
    assert_eq!(get_map(&p, "k6"), found_truncated("k6"), "first long line");
    assert_eq!(get_map(&p, "k7"), found(&p.map, "k7", &"g".repeat(247)), "short line after a long one");
}

/// 4. A payload with a customized end pattern, `<<123`, the end split across two reads:
/// the CLI first receives `12`, an incomplete line, then `3\n` completing the pattern.
#[test]
fn custom_end_pattern_split_across_reads() {
    let p = start();
    let parts: Vec<(Vec<u8>, u64)> = vec![
        (format!("add map {} <<123", p.map.display()).into_bytes(), 100),
        (b"\n".to_vec(), 100),
        (b"k9 v9".to_vec(), 100),
        (b"\n".to_vec(), 100),
        (b"12".to_vec(), 500),
        (b"3".to_vec(), 100),
        (b"\n".to_vec(), 0),
    ];
    assert_eq!(payload_exchange(&p, &parts), b"\n", "the add map answer");
    assert_eq!(get_map(&p, "k9"), found(&p.map, "k9", "v9"), "the pattern reassembled across the refill");
    // A marker line with no command before it is refused, and the connection closes
    // right after the error, without the trailing empty line (measured on the oracle).
    assert_eq!(cli(&p, "<<\n"), b"The payload cannot be passed without command.\n", "a bare marker");
    assert_eq!(cli(&p, "<<123\n"), b"The payload cannot be passed without command.\n", "a marker with a pattern");
    // The same refusal closes the session in prompt mode too (measured on the oracle):
    // the prompt, the error line, then EOF -- no second prompt.
    let mut c = UnixStream::connect(&p.sock).expect("connect to the stats socket");
    c.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    c.write_all(b"prompt\n").expect("send prompt");
    let mut got = Vec::new();
    let mut b = [0u8; 65536];
    let mut prompt_seen = false;
    while !prompt_seen {
        match c.read(&mut b) {
            Ok(0) | Err(_) => panic!("connection lost before the prompt"),
            Ok(n) => {
                got.extend_from_slice(&b[..n]);
                prompt_seen = got.ends_with(b"\n> ");
            }
        }
    }
    c.write_all(b"<<\n").expect("send the bare marker");
    loop {
        match c.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&b[..n]),
        }
    }
    assert_eq!(got, b"\n> The payload cannot be passed without command.\n", "the marker without a command in prompt mode");
}

/// 5. The `get map` answers on the other key types and on the error cases, measured byte
/// for byte on the oracle: `int` and `ip` values are named `sint` and `ipv4`, `reg` and
/// `regm` print the stored pattern value (not the group-substituted one), and a missing
/// or unknown identifier is refused with the oracle's message.
#[test]
fn get_map_answers_on_typed_tables() {
    let p = start_typed();
    let mi = p.dir.join("mi");
    let mp = p.dir.join("mp");
    let mr = p.dir.join("mr");
    let mg = p.dir.join("mg");
    assert_eq!(
        cli(&p, &format!("get map {} 15\n", mi.display())),
        b"type=int, case=sensitive, found=yes, idx=list, key=\"10-20\", value=\"100\", type=\"sint\"\n\n",
        "an int range hit"
    );
    assert_eq!(
        cli(&p, &format!("get map {} 99\n", mi.display())),
        b"type=int, case=sensitive, found=no\n\n",
        "an int miss"
    );
    assert_eq!(
        cli(&p, &format!("get map {} 10.1.2.3\n", mp.display())),
        b"type=ip, case=sensitive, found=yes, idx=tree, key=\"10.0.0.0/8\", value=\"10.9.0.1\", type=\"ipv4\"\n\n",
        "an ip hit"
    );
    assert_eq!(
        cli(&p, &format!("get map {} key\n", mr.display())),
        b"type=reg, case=sensitive, found=yes, idx=list, key=\"^k(.*)$\", value=\"g\\1\", type=\"str\"\n\n",
        "reg prints the stored pattern value"
    );
    assert_eq!(
        cli(&p, &format!("get map {} key\n", mg.display())),
        b"type=regm, case=sensitive, found=yes, idx=list, key=\"^k(.*)$\", value=\"g\\1\", type=\"str\"\n\n",
        "regm prints the stored pattern value, not the substituted one"
    );
    assert_eq!(cli(&p, "get map\n"), b"Missing map identifier and/or key.\n\n", "no identifier");
    assert_eq!(
        cli(&p, &format!("get map {}\n", mi.display())),
        b"Missing map identifier and/or key.\n\n",
        "no key"
    );
    assert_eq!(
        cli(&p, &format!("get map {} k\n", p.dir.join("nosuch").display())),
        b"Unknown map identifier. Please use #<id> or <file>.\n\n",
        "an unknown identifier"
    );
}
