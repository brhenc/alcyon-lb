// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T327: xxh32/xxh64 hashes

// The shared helper set is copied whole; this test uses only some of it.
#![allow(dead_code)]

use crate::common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Ibex(Child, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Starts ibex on `cfg` (`{sock}` is replaced by the stats socket path), waits for `addrs` and the
/// socket, then lets the readiness probes slide out of the one-second windows and clears the maxima.
fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> (Ibex, String) {
    let dir = std::env::temp_dir().join(format!("qh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg.replace("{sock}", &sock).replace("{dir}", &dir.display().to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let ibex = Ibex(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "ibex did not listen on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(2200));
    cli(&sock, "clear counters");
    (ibex, sock)
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn info(sock: &str) -> HashMap<String, String> {
    cli(sock, "show info").lines().filter_map(|l| l.split_once(": ")).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn num(i: &HashMap<String, String>, k: &str) -> u64 {
    i.get(k).unwrap_or_else(|| panic!("show info has no {k}")).parse().unwrap_or_else(|_| panic!("{k} is not a number: {:?}", i[k]))
}

/// One request on a new connection; the whole raw answer.
fn get(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";

fn http_cfg(global: &str, body: &str) -> String {
    format!(
        "global\n  stats socket {{sock}} level admin\n{global}\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n{body}"
    )
}

/// A server on a free port that reads each request head, answers `resp` and closes the connection.
fn backend(resp: &'static [u8]) -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
            let (mut head, mut b) = (Vec::new(), [0u8; 4096]);
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&b[..n]),
                }
            }
            let _ = c.write_all(resp);
        }
    });
    addr
}

/// The body of the answer to `req` (what follows the first empty line).
fn body(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    s.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_else(|| panic!("no answer: {s:?}"))
}

/// The value of the `x-out` header in the answer to `req`.
fn xout(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    let head = s.split("\r\n\r\n").next().unwrap_or("");
    head.lines()
        .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("x-out")).map(|(_, v)| v.trim().to_string()))
        .unwrap_or_else(|| panic!("no x-out header in the answer: {s:?}"))
}

const CFG: &str = r#"frontend fe
  bind {A}
  http-request return status 200 content-type text/plain lf-string "[%[str(abc),xxh32]|%[str(abc),xxh64]|%[str(),xxh32]|%[str(abc),xxh32(1)]|%[path,xxh32]|%[path,xxh64]|%[path,xxh64(7)]]"
"#;

#[test]
fn xxh32_xxh64_match_the_reference_library() {
    let a = common::reserve_addr();
    let cfg = http_cfg("  nbthread 1\n", &CFG.replace("{A}", &a.to_string()));
    let (_ibex, _sock) = start("xxh", &cfg, &[a]);
    assert_eq!(body(a, b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"), "[852579327|4952883123889572249|46947589|2856167679|2593267669|-1685236373114725654|6706632717773613526]");
    assert_eq!(body(a, b"GET /0123456789abcdef0123456789abcdef0123456789 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"), "[852579327|4952883123889572249|46947589|2856167679|1052971786|7687958087540669822|8845622410792476331]");
    assert_eq!(body(a, b"GET /xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"), "[852579327|4952883123889572249|46947589|2856167679|73530813|-6618268220350324068|-6737632001074821097]");
}

/// The seed is a SINT argument (`ARG1(0,SINT)`, `read_int64`, saturating), converted as C does:
/// `xxh32` keeps its low 32 bits, `xxh64` its 64 bits as unsigned. A negative or oversized
/// seed is a seed, not 0 (3.5-dev8).
const SEED_CFG: &str = r#"frontend fe
  bind {A}
  http-request return status 200 content-type text/plain lf-string "[%[str(abc),xxh32(-1)]|%[str(abc),xxh32(4294967297)]|%[str(abc),xxh32(99999999999999999999)]|%[str(abc),xxh32(+5)]|%[str(abc),xxh32(-)]|%[str(abc),xxh64(-1)]|%[str(abc),xxh64(99999999999999999999)]|%[str(abc),xxh64(-99999999999999999999)]|%[str(abc),xxh64(+5)]]"
"#;

#[test]
fn xxh32_xxh64_seed_is_a_haproxy_sint() {
    let a = common::reserve_addr();
    let cfg = http_cfg("  nbthread 1\n", &SEED_CFG.replace("{A}", &a.to_string()));
    let (_ibex, _sock) = start("xxhseed", &cfg, &[a]);
    assert_eq!(
        body(a, GET),
        "[2989167648|2856167679|2989167648|1562728233|852579327|2895935887265243510|-6843889581911917747|-2991377997648133420|-1753195980308443340]"
    );
}

/// A seed that is not an integer is a configuration error, not a seed of 0 (3.5-dev8 refuses
/// each of these: "invalid arg 1 in converter 'xxh32' : failed to parse 'abc' as type 'integer'").
#[test]
fn xxh32_xxh64_refuse_a_seed_that_is_no_integer() {
    let dir = std::env::temp_dir().join(format!("qh-xxhbad-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let a = common::reserve_addr();
    for (i, arg) in ["xxh32(abc)", "xxh32(0x10)", "xxh32(1k)", "xxh64(abc)", "xxh64(5x)", "xxh64(--1)"].iter().enumerate() {
        let path = dir.join(format!("c{i}.cfg"));
        std::fs::write(
            &path,
            format!(
                "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
                 frontend fe\n  bind {a}\n  http-request set-var(txn.x) str(abc),{arg}\n"
            ),
        )
        .unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().unwrap();
        assert!(!out.status.success(), "{arg} was accepted: {}", String::from_utf8_lossy(&out.stdout));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("invalid arg 1 in converter 'xxh"), "{arg}: {err}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
