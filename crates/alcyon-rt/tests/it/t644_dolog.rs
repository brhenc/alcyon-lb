// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T644 #13/#14: `http-response` / `http-after-response` `do-log` logs where the rule runs,
//! with the state at that moment, and also on a reply the proxy builds itself.
//! Set `T281_ORACLE=/path/to/haproxy` to run against `HAProxy` 3.5-dev11.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn bin() -> String {
    std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

fn responder() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind responder");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut chunk) {
                    Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                    _ => break,
                }
            }
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
        }
    });
    addr
}

fn get_wait(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut s = loop {
        match TcpStream::connect(addr) {
            Ok(s) => break s,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("no listener on {addr}: {e}"),
        }
    };
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    let mut b = [0u8; 4096];
    while s.read(&mut b).map(|n| n > 0).unwrap_or(false) {}
}

fn drain(sock: UdpSocket, stop: Instant, lines: Arc<Mutex<Vec<String>>>) {
    sock.set_read_timeout(Some(Duration::from_millis(50))).expect("timeout");
    let mut buf = [0u8; 8192];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => lines.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).into_owned()),
            Err(_) if Instant::now() < stop => {}
            Err(_) => break,
        }
    }
}

/// The message part of each rfc5424 line (after `<pri>1 TS host tag pid msgid sd`).
fn msgs(raw: &[String]) -> Vec<String> {
    raw.iter().map(|l| l.splitn(8, ' ').nth(7).unwrap_or(l).trim_end().to_string()).collect()
}

/// Runs `cfg` (with `{c}` the collector and `{f}` the bind, `{be}` the server), makes one
/// request and returns the log messages.
fn lines_for(cfg: &str) -> Vec<String> {
    let be = responder();
    let sock = UdpSocket::bind("127.0.0.1:0").expect("collector");
    let c = sock.local_addr().expect("addr");
    let f = common::reserve_addr();
    let cfg = cfg.replace("{c}", &c.to_string()).replace("{f}", &f.to_string()).replace("{be}", &be.to_string());
    let mut file = tempfile::NamedTempFile::new().expect("tempfile");
    file.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = common::alcyon_command(bin())
        .arg("-f")
        .arg(file.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn");
    let lines = Arc::new(Mutex::new(Vec::new()));
    let (l2, stop) = (lines.clone(), Instant::now() + Duration::from_secs(4));
    thread::spawn(move || drain(sock, stop, l2));
    get_wait(f);
    thread::sleep(Duration::from_millis(600));
    let got = msgs(&lines.lock().unwrap());
    common::stop(&mut child);
    got
}

const HEAD: &str = "defaults\n  mode http\n  timeout connect 5s\n  timeout client 5s\n  timeout server 5s\n\n";

#[test]
fn each_response_do_log_logs_at_its_rule_with_its_state() {
    let cfg = format!(
        "{HEAD}frontend fe\n  bind {{f}}\n  log udp@{{c}} format rfc5424 local0\n  log-format \"std v=%[var(txn.x)] %OG\"\n  log-steps close\n  \
         http-response do-log\n  http-response set-var(txn.x) str(b)\n  http-response do-log\n  \
         http-after-response do-log\n  http-after-response set-var(txn.x) str(c)\n  http-after-response do-log\n  \
         default_backend be\n\nbackend be\n  server app1 {{be}}\n"
    );
    assert_eq!(
        lines_for(&cfg),
        ["std v=- http-res", "std v=b http-res", "std v=b http-after-res", "std v=c http-after-res", "std v=c txn_close"]
    );
}

#[test]
fn an_after_response_do_log_runs_on_a_reply_the_proxy_builds() {
    let cfg = format!(
        "{HEAD}frontend fe\n  bind {{f}}\n  log udp@{{c}} format rfc5424 local0\n  log-format \"std %OG\"\n  \
         http-request return status 200\n  http-after-response do-log\n  default_backend be\n\nbackend be\n  server app1 {{be}}\n"
    );
    assert_eq!(lines_for(&cfg), ["std http-after-res", "std txn_close"]);
}
