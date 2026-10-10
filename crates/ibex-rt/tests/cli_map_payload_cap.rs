// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The payload of a CLI command (`add map <m> <<`) is capped as `HAProxy` caps it
//! (`tune.cli.max-payload-size`, 128 kB by default), and a large one is applied without
//! stalling the worker (T251 item 2).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` (2026-10-10): a payload of 131070 bytes (every
//! line counted with its LF, the closing empty line not counted) is applied; one of 131071
//! bytes is answered `The payload is too big. Please change 'tune.cli.max-payload-size' in
//! the configuration to use a bigger payload.`, the connection is closed, in `prompt` mode
//! too, and no line of it is applied. A 5000-line payload takes 5 ms.

mod common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Ibex {
    child: Child,
    sock: PathBuf,
    files: Vec<PathBuf>,
    map: String,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        for p in &self.files {
            let _ = std::fs::remove_file(p);
        }
    }
}

fn start() -> Ibex {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tag = format!("ibex_t251_{}_{n}", std::process::id());
    let tmp = std::env::temp_dir();
    let (sock, cfg, map) = (tmp.join(format!("{tag}.sock")), tmp.join(format!("{tag}.cfg")), tmp.join(format!("{tag}.map")));
    std::fs::write(&map, "k0 v0\n").expect("map");
    let fe = common::reserve_addr();
    let text = format!(
        "global\n  stats socket {} mode 600 level admin\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
         frontend f\n  bind {fe}\n  http-request return status 200 hdr x-m %[path,map({},none)]\n",
        sock.display(),
        map.display()
    );
    std::fs::write(&cfg, &text).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, sock, files: vec![cfg, map.clone()], map: map.display().to_string() };
    assert!(common::wait_listening(fe), "ibex never listened with:\n{text}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ibex.sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    ibex
}

fn cli(ibex: &Ibex, input: &[u8]) -> String {
    let mut s = UnixStream::connect(&ibex.sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let _ = s.write_all(input);
    let _ = s.shutdown(std::net::Shutdown::Write);
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// A payload of exactly `total` bytes: `k<n> vvv...` lines, each ended by a LF.
fn payload(total: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while total - out.len() > 40 {
        out.extend_from_slice(format!("k{i:07} {}\n", "v".repeat(20)).as_bytes());
        i += 1;
    }
    let rest = total - out.len();
    out.extend_from_slice(format!("z {}\n", "v".repeat(rest - 3)).as_bytes());
    assert_eq!(out.len(), total);
    out
}

fn entries(ibex: &Ibex) -> usize {
    cli(ibex, format!("show map {}\n", ibex.map).as_bytes()).lines().filter(|l| !l.is_empty()).count()
}

const TOO_BIG: &str = "The payload is too big. Please change 'tune.cli.max-payload-size' in the configuration to use a bigger payload.\n";

#[test]
fn a_payload_up_to_the_cap_is_applied() {
    let ibex = start();
    let body = payload(131_070);
    let lines = body.split(|&b| b == b'\n').count() - 1;
    let mut input = format!("add map {} <<\n", ibex.map).into_bytes();
    input.extend_from_slice(&body);
    input.push(b'\n');
    let start = Instant::now();
    let out = cli(&ibex, &input);
    let took = start.elapsed();
    assert!(!out.contains("too big"), "{out:?}");
    assert_eq!(entries(&ibex), lines + 1);
    assert!(took < Duration::from_secs(3), "{lines} lines took {took:?}");
}

#[test]
fn a_payload_over_the_cap_is_refused_whole() {
    let ibex = start();
    let mut input = format!("add map {} <<\n", ibex.map).into_bytes();
    input.extend_from_slice(&payload(131_071));
    input.push(b'\n');
    let out = cli(&ibex, &input);
    assert!(out == TOO_BIG, "{:?}", &out[..out.len().min(300)]);
    assert_eq!(entries(&ibex), 1, "no line of a refused payload is applied");
}

#[test]
fn a_payload_over_the_cap_closes_a_prompt_session() {
    let ibex = start();
    let mut input = format!("prompt\nadd map {} <<\n", ibex.map).into_bytes();
    input.extend_from_slice(&payload(200_000));
    input.extend_from_slice(format!("\nshow map {}\n", ibex.map).as_bytes());
    let out = cli(&ibex, &input);
    let tail = &out[out.len().saturating_sub(300)..];
    assert!(out.ends_with(TOO_BIG), "{tail:?}");
    assert!(!out.contains("k0 v0"), "nothing runs after the refusal: {tail:?}");
    assert_eq!(entries(&ibex), 1);
}

#[test]
fn a_payload_line_without_lf_is_capped_too() {
    let ibex = start();
    let mut s = UnixStream::connect(&ibex.sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    s.write_all(format!("add map {} <<\nk ", ibex.map).as_bytes()).expect("send");
    // No LF: the line is held until it ends, but not past the cap; the client keeps the
    // connection open for writing.
    let _ = s.write_all(&vec![b'v'; 200_000]);
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    assert_eq!(String::from_utf8_lossy(&out), TOO_BIG);
    assert_eq!(entries(&ibex), 1);
}
