// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `option dontlognull`, `option dontlog-normal` and `option log-separate-errors`, with
//! `txn.status` in the log-format (`log/log_filtering.vtc`, T131 item 7). The expectations
//! are that test's, which `HAProxy` 3.5-dev8-885761-29 passes: each message is written at
//! level `info` (6), but a failed request of a frontend with `log-separate-errors` at `err`
//! (3); `dontlog-normal` drops the requests that did not fail.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn live_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n");
            let _ = c.write_all(&[b'x'; 100]);
        }
    });
    port
}

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).lines().next().unwrap_or("").to_string()
}

#[test]
fn the_log_options_filter_and_raise_the_level() {
    let live = live_backend();
    let dead = common::reserve_port();
    let (null, norm, sep, probe, asap) = (common::reserve_port(), common::reserve_port(), common::reserve_port(), common::reserve_port(), common::reserve_port());
    let sink = UdpSocket::bind("127.0.0.1:0").expect("udp");
    sink.set_read_timeout(Some(Duration::from_millis(1500))).ok();
    let log = sink.local_addr().expect("addr");
    let cfg = format!(
        "global\n  log {log} local0 info\n\
         defaults\n  mode http\n  log global\n  timeout connect 1s\n  timeout client 3s\n  timeout server 3s\n\
         frontend fe_null\n  bind 127.0.0.1:{null}\n  option dontlognull\n  \
         log-format \"null uri=%[capture.req.uri] st=%[txn.status] \"\n  http-request return status 200\n\
         frontend fe_norm\n  bind 127.0.0.1:{norm}\n  option dontlog-normal\n  \
         log-format \"norm uri=%[capture.req.uri] st=%[txn.status] \"\n  \
         http-request return status 200 unless {{ path /dead }}\n  use_backend dead\n\
         frontend fe_sep\n  bind 127.0.0.1:{sep}\n  option log-separate-errors\n  \
         log-format \"sep uri=%[capture.req.uri] st=%[txn.status] \"\n  \
         http-request return status 200 unless {{ path /dead }}\n  use_backend dead\n\
         frontend fe_asap\n  bind 127.0.0.1:{asap}\n  option logasap\n  \
         log-format \"asap uri=%[capture.req.uri] st=%[txn.status] bytes=%B tt=%Tt\"\n  default_backend be\n\
         frontend fe_probe\n  bind 127.0.0.1:{probe}\n  option dontlognull\n  log-format \"probe\"\n  http-request return status 200\n\
         backend be\n  server s1 127.0.0.1:{live}\n\
         backend dead\n  timeout connect 100ms\n  retries 0\n  server s1 127.0.0.1:{dead}\n"
    );
    let path = std::env::temp_dir().join(format!("ibex_logfilter_{}", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", probe)).is_err() {
        assert!(Instant::now() < deadline, "the daemon never listened on {probe}");
        thread::sleep(Duration::from_millis(25));
    }
    // A connection on which nothing was sent, then a real request: only the second is logged.
    drop(TcpStream::connect(("127.0.0.1", null)).expect("connect"));
    thread::sleep(Duration::from_millis(100));
    assert_eq!(get(null, "/real"), "HTTP/1.1 200 OK");
    assert_eq!(get(norm, "/ok"), "HTTP/1.1 200 OK");
    assert_eq!(get(norm, "/dead"), "HTTP/1.1 503 Service Unavailable");
    assert_eq!(get(sep, "/ok"), "HTTP/1.1 200 OK");
    assert_eq!(get(sep, "/dead"), "HTTP/1.1 503 Service Unavailable");
    assert_eq!(get(asap, "/ok"), "HTTP/1.1 200 OK");
    let mut got = Vec::new();
    let mut buf = [0u8; 2048];
    while let Ok(n) = sink.recv(&mut buf) {
        let m = String::from_utf8_lossy(&buf[..n]).into_owned();
        let pri: u32 = m.trim_start_matches('<').split('>').next().unwrap_or("0").parse().unwrap_or(0);
        let text = m.split(": ").skip(1).collect::<Vec<_>>().join(": ");
        got.push((pri, text.trim_end().to_string()));
    }
    common::stop(&mut child);
    let _ = std::fs::remove_file(&path);
    // With logasap the line is the one sent with the response head, and the byte count and
    // the total time carry the '+' of "not final".
    let asap_line = got.pop().expect("a last line");
    assert_eq!(asap_line.0, 134, "{got:?}");
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let rest = asap_line.1.strip_prefix("asap uri=/ok st=200 bytes=+").unwrap_or("");
    let (bytes, tt) = rest.split_once(" tt=+").unwrap_or(("", ""));
    assert!(digits(bytes) && digits(tt), "{asap_line:?}");
    let want = [
        (134, "null uri=/real st=200"),
        (134, "norm uri=/dead st=503"),
        (134, "sep uri=/ok st=200"),
        (131, "sep uri=/dead st=503"),
    ];
    assert_eq!(got.iter().map(|(p, t)| (*p, t.as_str())).collect::<Vec<_>>(), want, "{got:?}");
}
