// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A `return`/`deny` with a `string`/`lf-string` that does not fit the buffer answers 500
//! (T597, left over by T589). `HAProxy` 3.5-dev8-885761-29 accepts the configuration and builds
//! the reply in an HTX message at run time; when it does not fit, the client gets its 500.
//!
//! Measured (`tools` bisection over the string length, `status 200 content-type text/plain`):
//!
//! ```text
//! bufsize 16384  longest string answered 200: 16229   (16230 -> 500, 97 bytes)
//! bufsize  8192  8038     4096  3942     1024  871     1030  887     16385  16245
//! status 404 (reason "Not Found"): 16222      content-type text/plainxxxx: 16225
//! + hdr x-a bbbbb: 16213                      + hdr y 1 too: 16203
//! lf-string: the same as string
//! ```
//!
//! The HTX holds `roundup16(bufsize)` bytes; a reply needs `96 + len(reason)` for the status
//! line and the end of headers, `name + value + 8` per header (`content-length` and
//! `content-type` included), and the payload.

use crate::common;

use std::path::PathBuf;
use std::process::{Command, Stdio};

struct Run {
    child: common::Alcyon,
    d: PathBuf,
    addr: std::net::SocketAddr,
    h2: std::net::SocketAddr,
}

impl Drop for Run {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.d);
    }
}

fn start(tag: &str, bufsize: usize, side: &str, opts: &str, kw: &str, len: usize) -> Run {
    let d = std::env::temp_dir().join(format!("alcyon-t597-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).expect("dir");
    let (addr, h2) = (common::reserve_addr(), common::reserve_addr());
    // HTTP/2 needs a buffer of at least 16384.
    let h2bind = if bufsize >= 16384 { format!("  bind {h2} proto h2\n") } else { String::new() };
    let body = "a".repeat(len);
    let rule = match side {
        "res" => format!("http-response return {opts} {kw} \"{body}\""),
        "deny" => format!("http-request deny {opts} {kw} \"{body}\""),
        _ => format!("http-request return {opts} {kw} \"{body}\""),
    };
    // The response-side rule needs a server to answer.
    let backend = if side == "res" {
        let srv = origin();
        format!("  default_backend b\nbackend b\n  server s {srv}\n")
    } else {
        String::new()
    };
    let c = format!(
        "global\n  nbthread 1\n  tune.bufsize {bufsize}\ndefaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend f\n  bind {addr}\n{h2bind}  {rule}\n{backend}"
    );
    let cfg = d.join("run.cfg");
    std::fs::write(&cfg, c).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Alcyon).expect("spawn");
    assert!(common::wait_listening(addr) && (bufsize < 16384 || common::wait_listening(h2)), "alcyon never listened");
    Run { child, d, addr, h2 }
}

/// A server that answers every request `200 ok`.
fn origin() -> std::net::SocketAddr {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { break };
            std::thread::spawn(move || {
                let mut b = [0u8; 4096];
                while s.read(&mut b).is_ok_and(|n| n > 0) {
                    if s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn curl(args: &[&str], url: &str) -> String {
    let out = Command::new("curl")
        .args(["-s", "-m", "10", "-o", "/dev/null", "-w", "%{http_code} %{size_download}"])
        .args(args)
        .arg(url)
        .output()
        .expect("curl");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

const CT: &str = "status 200 content-type text/plain";

/// (bufsize, rule options, longest string that fits)
const EDGES: &[(usize, &str, usize)] = &[
    (16384, CT, 16229),
    (1030, CT, 887),
    (1024, CT, 871),
    (16385, CT, 16245),
    (16384, "status 404 content-type text/plain", 16222),
    (16384, "status 200 content-type text/plain hdr x-a bbbbb", 16213),
];

/// `max` bytes fit and answer `want`; one more is a 500, on HTTP/1.1 and on HTTP/2.
fn edge(what: &str, side: &str, bufsize: usize, opts: &str, kw: &str, max: usize, want: &str) {
    for proto in ["h1", "h2"] {
        if proto == "h2" && bufsize < 16384 {
            continue;
        }
        let args: &[&str] = if proto == "h2" { &["--http2-prior-knowledge"] } else { &["--http1.1"] };
        let url = |r: &Run| format!("http://{}/", if proto == "h2" { r.h2 } else { r.addr });
        let ok = start(&format!("{what}-ok-{proto}"), bufsize, side, opts, kw, max);
        assert_eq!(curl(args, &url(&ok)), format!("{want} {max}"), "{what} {kw} {opts} bufsize {bufsize} {proto}: {max} bytes must fit");
        let over = start(&format!("{what}-over-{proto}"), bufsize, side, opts, kw, max + 1);
        let got = curl(args, &url(&over));
        assert!(got.starts_with("500 ") && !got.ends_with(&format!(" {}", max + 1)), "{what} {kw} {opts} bufsize {bufsize} {proto}: {} bytes got {got}", max + 1);
    }
}

#[test]
fn a_return_string_over_the_htx_is_a_500_on_http1_and_h2() {
    for kw in ["string", "lf-string"] {
        for (j, &(bufsize, opts, max)) in EDGES.iter().enumerate() {
            let want = opts.split(' ').nth(1).unwrap_or("200");
            edge(&format!("req{j}"), "req", bufsize, opts, kw, max, want);
        }
    }
}

#[test]
fn a_deny_string_and_a_response_return_string_follow_the_same_rule() {
    // deny: reason "Forbidden" (9) instead of "OK" (2): 7 bytes less room.
    edge("deny", "deny", 16384, "deny_status 403 content-type text/plain", "string", 16222, "403");
    edge("res", "res", 16384, CT, "string", 16229, "200");
}
