// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `retry-on`, `http-request disable-l7-retry`, `txn.conn_retries` and `txn.redispatched`
//! (`proxy/retry_on.vtc`, T131 item 8). The expectations are that test's, which `HAProxy`
//! 3.5-dev8-885761-29 passes; the `none` case was measured with the same harness
//! (`IBEX_TEST_BIN=/path/to/haproxy cargo test --test retry_on` runs it against `HAProxy`).

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// A server that answers every request with `status` and `extra` headers, counting them.
fn server(status: &str, extra: &'static str) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let (h, status) = (Arc::clone(&hits), status.to_string());
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf);
            h.fetch_add(1, Ordering::Relaxed);
            let _ = write!(c, "HTTP/1.1 {status}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    (port, hits)
}

fn head(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).split("\r\n\r\n").next().unwrap_or("").to_string()
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

#[test]
fn retry_on_statuses_conn_failures_and_the_l7_retry_switch() {
    let (s1, _) = server("200 OK", "");
    let (s2, _) = server("503 Service Unavailable", "");
    let (s3, _) = server("200 OK", "x-second: yes\r\n");
    let (s4, s4_hits) = server("503 Service Unavailable", "");
    let (bad, bad2, bad3) = (common::reserve_port(), common::reserve_port(), common::reserve_port());
    let port = common::reserve_port();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 200ms\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind 127.0.0.1:{port}\n  use_backend redisp if {{ path /redisp }}\n  use_backend l7 if {{ path /l7 }}\n  \
         use_backend nol7 if {{ path /nol7 }}\n  use_backend none if {{ path /none }}\n  default_backend dead\n  \
         http-after-response set-header x-retries \"%[txn.conn_retries]\"\n  \
         http-after-response set-header x-redisp \"%[txn.redispatched]\"\n\
         backend dead\n  retries 2\n  server s1 127.0.0.1:{bad}\n\
         backend none\n  retries 2\n  retry-on none\n  server s1 127.0.0.1:{bad3}\n\
         backend redisp\n  balance first\n  retries 1\n  option redispatch\n  server bad 127.0.0.1:{bad2}\n  server good 127.0.0.1:{s1}\n\
         backend l7\n  balance first\n  retries 1\n  retry-on 503\n  option redispatch\n  server bad 127.0.0.1:{s2}\n  server good 127.0.0.1:{s3}\n\
         backend nol7\n  balance first\n  retries 1\n  retry-on 503\n  option redispatch\n  http-request disable-l7-retry\n  \
         server bad 127.0.0.1:{s4}\n  server good 127.0.0.1:{s3}\n"
    );
    let path = std::env::temp_dir().join(format!("ibex_retryon_{}", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let mut child = Command::new(std::env::var("IBEX_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string())).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the daemon never listened on {port}");
        thread::sleep(Duration::from_millis(25));
    }
    let got: Vec<(String, Option<String>, Option<String>, Option<String>)> = ["/dead", "/none", "/redisp", "/l7", "/nol7"]
        .iter()
        .map(|p| {
            let h = head(port, p);
            (h.lines().next().unwrap_or("").to_string(), header(&h, "x-retries"), header(&h, "x-redisp"), header(&h, "x-second"))
        })
        .collect();
    common::stop(&mut child);
    let _ = std::fs::remove_file(&path);
    let s = |a: &str, b: &str, c: &str, d: Option<&str>| (a.to_string(), Some(b.to_string()), Some(c.to_string()), d.map(str::to_string));
    let want = [
        // 1 attempt and 2 retries, all refused.
        s("HTTP/1.1 503 Service Unavailable", "2", "0", None),
        // `retry-on none`: no retry on a refused connection.
        s("HTTP/1.1 503 Service Unavailable", "0", "0", None),
        // The retry went to the other server.
        s("HTTP/1.1 200 OK", "1", "1", None),
        // The 503 was retried at the HTTP layer, and the second server's response delivered.
        s("HTTP/1.1 200 OK", "1", "1", Some("yes")),
        // `disable-l7-retry` leaves the first server's 503 alone.
        s("HTTP/1.1 503 Service Unavailable", "0", "0", None),
    ];
    assert_eq!(got, want, "{got:?}");
    assert_eq!(s4_hits.load(Ordering::Relaxed), 1);
}

/// A server that does `what` to every request: `close` hangs up with nothing sent back,
/// `junk` answers with something that is no HTTP response, `stall` never answers in time.
fn misbehaving(what: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf);
            match what {
                "junk" => {
                    let _ = c.write_all(b"garbage garbage\r\n\r\n");
                }
                // The head ends before it is whole: a response that is cut short.
                "partial" => {
                    let _ = c.write_all(b"HTTP/1.1 200 OK\r\nCont");
                }
                "stall" => thread::sleep(Duration::from_millis(1500)),
                _ => {}
            }
        }
    });
    port
}

/// `retry-on <keyword>` against a first server that misbehaves and a good second one: with
/// the keyword the request is retried on the second server (200, one retry, redispatched),
/// without it the failure is the answer.
#[test]
fn retry_on_empty_response_junk_response_and_response_timeout() {
    let good = server("200 OK", "").0;
    let cases = [("empty-response", "close", "502"), ("junk-response", "junk", "502"), ("junk-response", "partial", "502"), ("response-timeout", "stall", "504")];
    for (keyword, what, plain) in cases {
        let bad = misbehaving(what);
        let port = common::reserve_port();
        let build = |retry: &str| {
            format!(
                "defaults\n  mode http\n  timeout connect 200ms\n  timeout client 5s\n  timeout server 500ms\n\
                 frontend fe\n  bind 127.0.0.1:{port}\n  default_backend be\n  \
                 http-after-response set-header x-retries \"%[txn.conn_retries]\"\n  \
                 http-after-response set-header x-redisp \"%[txn.redispatched]\"\n\
                 backend be\n  balance first\n  retries 1\n  option redispatch\n{retry}  server bad 127.0.0.1:{bad}\n  server good 127.0.0.1:{good}\n"
            )
        };
        for (retry, want) in [(format!("  retry-on {keyword}\n"), ("200", "1", "1")), (String::new(), (plain, "0", "0"))] {
            let path = std::env::temp_dir().join(format!("ibex_retryon_{}_{keyword}_{what}", std::process::id()));
            std::fs::write(&path, build(&retry)).expect("write config");
            let mut child = Command::new(std::env::var("IBEX_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string()))
                .arg("-f")
                .arg(&path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn ibex");
            let deadline = Instant::now() + Duration::from_secs(5);
            while TcpStream::connect(("127.0.0.1", port)).is_err() {
                assert!(Instant::now() < deadline, "the daemon never listened on {port}");
                thread::sleep(Duration::from_millis(25));
            }
            let h = head(port, "/");
            common::stop(&mut child);
            let _ = std::fs::remove_file(&path);
            let status = h.split(' ').nth(1).unwrap_or("").to_string();
            assert_eq!(
                (status.as_str(), header(&h, "x-retries").unwrap_or_default(), header(&h, "x-redisp").unwrap_or_default()),
                (want.0, want.1.to_string(), want.2.to_string()),
                "retry-on {keyword:?} against a server that does {what}: {h}"
            );
        }
    }
}

/// A retry on a status is not made when no retry is left (`retries 0`), nor when the request
/// was not whole when it was first sent (a body still to come): the 503 is the answer.
#[test]
fn retry_on_a_status_needs_a_retry_left_and_a_request_that_was_kept() {
    let (bad, bad_hits) = server("503 Service Unavailable", "");
    let (bad2, _) = server("503 Service Unavailable", "");
    let good = server("200 OK", "").0;
    let port = common::reserve_port();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 200ms\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind 127.0.0.1:{port}\n  use_backend nor if {{ path /nor }}\n  default_backend body\n\
         backend nor\n  balance first\n  retries 0\n  retry-on 503\n  option redispatch\n  server bad 127.0.0.1:{bad}\n  server good 127.0.0.1:{good}\n\
         backend body\n  balance first\n  retries 1\n  retry-on 503\n  option redispatch\n  server bad 127.0.0.1:{bad2}\n  server good 127.0.0.1:{good}\n"
    );
    let path = std::env::temp_dir().join(format!("ibex_retryon_left_{}", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let mut child = Command::new(std::env::var("IBEX_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string())).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the daemon never listened on {port}");
        thread::sleep(Duration::from_millis(25));
    }
    let nor = head(port, "/nor");
    // The head goes first, the body 300 ms later.
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    write!(s, "POST /body HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nConnection: close\r\n\r\n").expect("write");
    thread::sleep(Duration::from_millis(300));
    let _ = s.write_all(b"hello");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    common::stop(&mut child);
    let _ = std::fs::remove_file(&path);
    let body = String::from_utf8_lossy(&out).lines().next().unwrap_or("").to_string();
    assert_eq!(nor.lines().next(), Some("HTTP/1.1 503 Service Unavailable"), "no retry left: {nor}");
    assert_eq!(bad_hits.load(Ordering::Relaxed), 1);
    assert_eq!(body, "HTTP/1.1 503 Service Unavailable", "the request was not whole when it was sent");
}
