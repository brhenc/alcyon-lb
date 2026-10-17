// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T331f: `http_auth` / `http_auth_group`

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
    s.split_once("\r\n\r\n").map_or_else(|| panic!("no answer: {s:?}"), |(_, b)| b.to_string())
}

/// The value of the `x-out` header in the answer to `req`.
fn xout(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    let head = s.split("\r\n\r\n").next().unwrap_or("");
    head.lines()
        .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("x-out")).map(|(_, v)| v.trim().to_string()))
        .unwrap_or_else(|| panic!("no x-out header in the answer: {s:?}"))
}

const CFG: &str = r#"
userlist L
  group admins
  group dev
  group ops
  group none
  user alice insecure-password pw groups admins
  user bob insecure-password pw2
  user carol insecure-password pw3 groups admins,dev,ops
  user dave insecure-password pw4 groups none
  user nopw
frontend fe
  bind {A}
  http-request return status 200 content-type text/plain lf-string "[%[http_auth(L)]][%[http_auth_group(L)]]"
"#;

fn auth(cred: &str) -> Vec<u8> {
    format!("GET / HTTP/1.1\r\nHost: a\r\nAuthorization: Basic {cred}\r\nConnection: close\r\n\r\n").into_bytes()
}

/// T331f: every row measured on `HAProxy` 3.5-dev8 (`smp_fetch_http_auth`, `smp_fetch_http_auth_grp`).
#[test]
fn http_auth_and_group_match_haproxy() {
    let a = common::reserve_addr();
    let cfg = http_cfg("  nbthread 1\n", &CFG.replace("{A}", &a.to_string()));
    let (_ibex, _sock) = start("t331f", &cfg, &[a]);
    let rows: &[(&str, &str)] = &[
        ("YWxpY2U6cHc=", "[1][alice]"),     // alice:pw, one group
        ("Ym9iOnB3Mg==", "[1][bob]"),       // bob:pw2, no group
        ("YWxpY2U6YmFk", "[0][]"),          // alice:bad, wrong password
        ("Y2Fyb2w6cHcz", "[1][carol]"),     // carol:pw3, three groups
        ("ZGF2ZTpwdzQ=", "[1][dave]"),      // dave:pw4, group `none`
        ("emVkOnB3", "[0][]"),              // zed:pw, unknown user
        ("bm9wdzo=", "[0][]"),              // nopw:, user without a password
        ("YWxpY2U6cHc6eA==", "[0][]"),      // alice:pw:x
        ("OnB3", "[0][]"),                  // :pw
        ("YWxpY2U=", "[][]"),               // alice, no colon: no credentials
        ("!!!!", "[][]"),                   // bad base64
        ("", "[][]"),                       // empty
    ];
    for (cred, want) in rows {
        assert_eq!(body(a, &auth(cred)), *want, "credentials {cred:?}");
    }
    assert_eq!(body(a, GET), "[][]", "no Authorization header");
    let bearer = b"GET / HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer abc\r\nConnection: close\r\n\r\n";
    assert_eq!(body(a, bearer), "[][]", "Bearer");
}
