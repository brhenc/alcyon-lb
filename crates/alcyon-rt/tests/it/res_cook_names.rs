// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T326: the `res.cook_names` fetch

use crate::common;

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Alcyon(Child, std::path::PathBuf);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Starts alcyon on `cfg` (`{sock}` is replaced by the stats socket path), waits for `addrs` and the
/// socket, then lets the readiness probes slide out of the one-second windows and clears the maxima.
fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> (Alcyon, String) {
    let dir = std::env::temp_dir().join(format!("qh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg.replace("{sock}", &sock).replace("{dir}", &dir.display().to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let alcyon = Alcyon(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "alcyon did not listen on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(2200));
    cli(&sock, "clear counters");
    (alcyon, sock)
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
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

/// The value of the `x-out` header in the answer to `req`.
fn xout(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    let head = s.split("\r\n\r\n").next().unwrap_or("");
    head.lines()
        .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("x-out")).map(|(_, v)| v.trim().to_string()))
        .unwrap_or_else(|| panic!("no x-out header in the answer: {s:?}"))
}

#[test]
fn res_cook_names() {
    const RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: s=1; Path=/\r\nSet-Cookie: t=2\r\n\r\nok";
    let be = backend(RESP);
    let a = common::reserve_addr();
    let cfg = format!(
        "global\n  stats socket {{sock}} level admin\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nfrontend fe\n  bind {a}\n  default_backend b\n  http-response set-header x-out \"[%[res.cook_names]][%[res.cook_names(;)]]\"\nbackend b\n  server s {be}"
    );
    let (_alcyon, _sock) = start("res_cook_names", &cfg, &[a]);
    // First request: expect [s,t][s;t]
    let v = xout(a, GET);
    assert_eq!(v, "[s,t][s;t]");
}

/// The names as `http_extract_next_cookie_name` finds them in `Set-Cookie`: the first pair
/// with a `=` whose name does not start with `$`, quotes honoured; a delimiter goes in only
/// behind a non-empty output, so a leading empty name vanishes while a later one keeps its
/// slot (measured on `HAProxy` 3.5-dev8).
#[test]
fn res_cook_names_like_haproxy() {
    const CASES: [(&[u8], &str); 6] = [
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: s=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT\r\nSET-COOKIE:  u = 2\r\nSet-Cookie: nov\r\nSet-Cookie: $d=1\r\nSet-Cookie: w=\r\n\r\nok", "[s,u,w][s;u;w]"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: =1\r\nSet-Cookie: t=2\r\nSet-Cookie: v=\"a;b\"\r\n\r\nok", "[t,v][t;v]"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: $d=1; x=2\r\nSet-Cookie: nov; y=3\r\n\r\nok", "[x,y][x;y]"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: =1\r\nSet-Cookie: =2\r\n\r\nok", "[][]"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: t=2\r\nSet-Cookie: =1\r\nSet-Cookie: v=3\r\n\r\nok", "[t,,v][t;;v]"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: =\r\nSet-Cookie: a=1, b=2\r\n\r\nok", "[a][a]"),
    ];
    let a = common::reserve_addr();
    let mut cfg = format!(
        "global\n  stats socket {{sock}} level admin\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {a}\n  http-response set-header x-out \"[%[res.cook_names]][%[res.cook_names(;)]]\"\n"
    );
    for i in 0..CASES.len() {
        let _ = writeln!(cfg, "  use_backend b{i} if {{ path /{i} }}");
    }
    for (i, (resp, _)) in CASES.iter().enumerate() {
        let _ = writeln!(cfg, "backend b{i}\n  server s {}", backend(resp));
    }
    let (_alcyon, _sock) = start("res_cook_names_ha", &cfg, &[a]);
    for (i, (resp, want)) in CASES.iter().enumerate() {
        let req = format!("GET /{i} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
        assert_eq!(xout(a, req.as_bytes()), *want, "for {:?}", String::from_utf8_lossy(resp));
    }
}
