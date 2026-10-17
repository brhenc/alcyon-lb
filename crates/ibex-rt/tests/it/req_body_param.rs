// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T326: req.body_param fetch

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

/// One POST with `b` as its body; the raw bytes of the answer's body.
fn post(addr: SocketAddr, b: &[u8]) -> Vec<u8> {
    let mut req = format!("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", b.len()).into_bytes();
    req.extend_from_slice(b);
    let out = get(addr, &req);
    let at = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or_else(|| panic!("no answer: {out:?}"));
    out[at + 4..].to_vec()
}

#[test]
fn req_body_param() {
    let a = common::reserve_addr();
    let cfg = http_cfg(
        "nbthread 1\n",
        &format!(
            r#"
frontend fe
  bind {a}
  option http-buffer-request
  http-request return status 200 content-type text/plain lf-string "[%[req.body_param(a)]|%[req.body_param(b)]|%[req.body_param(A,i)]|%[req.body_param]|%[req.body_param(A,ignore)]]"
"#
        ),
    );
    let (_ibex, _sock) = start("req_body_param", &cfg, &[a]);

    // Measured on the oracle (HAProxy 3.5-dev8), body -> [a|b|A,i|no name|A,ignore].
    let cases: &[(&[u8], &[u8])] = &[
        (b"a=1&b=two&a=3", b"[1|two|1|1|1]"),
        (b"B=2&A=9", b"[||9|2|9]"),
        // `;` ends a parameter as `&` does (http_is_param_delimiter).
        (b"a=1;b=2", b"[1|2|1|1|1]"),
        // Bytes, not UTF-8: the value is the raw 0xff and the other parameters still match.
        (b"a=\xff&b=2", b"[\xff|2|\xff|\xff|\xff]"),
        // No name: the value after the first `=` anywhere in the body.
        (b"x&b=2", b"[|2||2|]"),
        (b"&&a=5", b"[5||5|5|5]"),
        (b"a&b", b"[||||]"),
        // Only the first character of the flag counts: `ignore` is case-insensitive too.
        (b"A=1&a=2", b"[2||1|1|1]"),
    ];
    let wrong: Vec<String> = cases
        .iter()
        .filter_map(|(b, want)| {
            let got = post(a, b);
            (got != *want).then(|| format!("body {:?}: got {:?}, want {:?}", b.escape_ascii().to_string(), got.escape_ascii().to_string(), want.escape_ascii().to_string()))
        })
        .collect();
    assert!(wrong.is_empty(), "req.body_param differs from the oracle:\n{}", wrong.join("\n"));

    // A GET: no body, no parameter.
    assert_eq!(body(a, GET), "[||||]");
}
