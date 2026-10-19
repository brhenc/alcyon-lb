// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `option checkcache`: a response that sets a cookie and could be stored by a cache is
//! answered 502 (T388; `http_process_res_common` and `http_check_response_for_cacheability`).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29`, 2026-10-18: a server answering `200` with
//! `Set-Cookie: a=b` plus the header lines named in the request's `X-Resp` (`|` between
//! lines). `Cache-Control: max-age=60` and `ETag` alone give 502 (the 502 page, no cookie);
//! no freshness information, `private`, `no-store` and a POST give the 200 untouched.
//! Without the option nothing is blocked.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let n = c.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let extra = head
                    .split("\r\n")
                    .find_map(|l| l.to_ascii_lowercase().starts_with("x-resp:").then(|| l["x-resp:".len()..].to_string()))
                    .map(|v| v.trim().replace('|', "\r\n"))
                    .unwrap_or_default();
                let extra = if extra.is_empty() { String::new() } else { format!("{extra}\r\n") };
                let _ = c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: a=b\r\n{extra}\r\nok").as_bytes());
            });
        }
    });
    addr
}

fn start(option: &str) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let text = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\nfrontend f\n  bind {fe}\n  default_backend b\nbackend b\n  {option}\n  server s1 {}\n",
        server()
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let ibex = Ibex { child, _cfg: f };
    assert!(common::wait_listening(fe), "ibex never listened:\n{text}");
    (ibex, fe)
}

/// `(status, whether the response carries a Set-Cookie)` for one request.
fn ask(fe: SocketAddr, method: &str, resp: &str) -> (u16, bool) {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let len = if method == "POST" { "Content-Length: 0\r\n" } else { "" };
    c.write_all(format!("{method} / HTTP/1.1\r\nHost: x\r\n{len}X-Resp: {resp}\r\nConnection: close\r\n\r\n").as_bytes()).expect("send");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    let text = String::from_utf8_lossy(&got).to_ascii_lowercase();
    let head = text.split("\r\n\r\n").next().unwrap_or_default();
    let status = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, head.contains("\r\nset-cookie:"))
}

#[test]
fn cacheable_response_with_a_cookie_is_blocked() {
    let (_i, fe) = start("option checkcache");
    for (method, resp, want) in [
        ("GET", "Cache-Control: max-age=60", (502, false)),
        ("GET", "ETag: \"a\"", (502, false)),
        ("GET", "Cache-Control: max-age=60|Expires: x", (502, false)),
        ("GET", "", (200, true)),
        ("GET", "Cache-Control: max-age=60|Cache-Control: private", (200, true)),
        ("GET", "Cache-Control: max-age=60|Cache-Control: no-store", (200, true)),
        ("GET", "Cache-Control: max-age=60|Cache-Control: no-cache=\"set-cookie\"", (200, true)),
        ("GET", "Cache-Control: max-age=60|Pragma: no-cache", (200, true)),
        ("POST", "Cache-Control: max-age=60", (200, true)),
    ] {
        assert_eq!(ask(fe, method, resp), want, "{method} {resp:?}");
    }
}

#[test]
fn without_the_option_nothing_is_blocked() {
    let (_i, fe) = start("option httpclose");
    assert_eq!(ask(fe, "GET", "Cache-Control: max-age=60"), (200, true));
}

#[test]
fn no_option_checkcache_in_the_backend_turns_it_off() {
    let (_i, fe) = start("option checkcache\n  no option checkcache");
    assert_eq!(ask(fe, "GET", "Cache-Control: max-age=60"), (200, true));
}

/// T430 row 7: the block is also logged, at level alert (`<129>` for `local0`), to the
/// backend's `log`, before the stream's own line, and the 502 is 87 bytes in `%B`. Measured on
/// `HAProxy 3.5-dev8-885761-29` on 2026-10-19 (`<129>...: Blocking cacheable cookie in response
/// from instance b, server s1.` then `<134>...: FE 87 502 PH`).
#[test]
fn the_block_is_logged_to_the_backends_log_at_alert_level() {
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("udp");
    udp.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    let log = udp.local_addr().expect("addr");
    let fe = common::reserve_addr();
    let text = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
         frontend f\n  bind {fe}\n  log {log} local0\n  log-format \"FE %B %ST %ts\"\n  default_backend b\n\
         backend b\n  option checkcache\n  log {log} local0\n  server s1 {}\n",
        server()
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let _ibex = Ibex { child, _cfg: f };
    assert!(common::wait_listening(fe), "ibex never listened:\n{text}");
    assert_eq!(ask(fe, "GET", "Cache-Control: max-age=60"), (502, false));
    let mut lines = Vec::new();
    while lines.len() < 2 {
        let mut buf = [0u8; 2048];
        let n = udp.recv(&mut buf).expect("a log line");
        let line = String::from_utf8_lossy(&buf[..n]).trim_end().to_string();
        // The probe `wait_listening` makes is logged too (`FE 0 400 CR`).
        if !line.ends_with("FE 0 400 CR") {
            lines.push(line);
        }
    }
    assert!(lines[0].starts_with("<129>") && lines[0].ends_with(": Blocking cacheable cookie in response from instance b, server s1."), "{lines:?}");
    assert!(lines[1].starts_with("<134>") && lines[1].ends_with(": FE 87 502 PH"), "{lines:?}");
}
