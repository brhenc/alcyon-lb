// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `when()` on a forwarded request, one that fails to reach its server, and one answered by
//! a backend's stats applet (`converter/when_debug.vtc`, T131 item 6). The expected values
//! are the ones that test checks, and `HAProxy` 3.5-dev8-885761-29 passes it.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
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
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    port
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
fn when_tells_forwarded_error_and_applet_streams_apart() {
    let live = live_backend();
    let dead = common::reserve_port();
    let port = common::reserve_port();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 3s\n  timeout server 3s\n\
         frontend fe\n  bind 127.0.0.1:{port}\n  acl yes always_true\n  \
         use_backend dead if {{ path /dead }}\n  use_backend stats if {{ path /stats }}\n  default_backend be\n  \
         http-after-response set-header x-when \"[%[str(v),when(error)]][%[str(v),when(normal)]][%[str(v),when(forwarded)]][%[str(v),when(processed)]][%[str(v),when(toapplet)]][%[str(v),when(stopping)]][%[str(v),when(acl,yes)]][%[str(v),when(!error)]]\"\n\
         backend be\n  server s1 127.0.0.1:{live}\n\
         backend dead\n  retries 0\n  server s1 127.0.0.1:{dead}\n\
         backend stats\n  stats enable\n  stats uri /stats\n"
    );
    let path = std::env::temp_dir().join(format!("ibex_whenapplet_{}", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the daemon never listened on {port}");
        thread::sleep(Duration::from_millis(25));
    }
    let got: Vec<(String, Option<String>)> = ["/srv", "/dead", "/stats"]
        .iter()
        .map(|p| {
            let h = head(port, p);
            (h.lines().next().unwrap_or("").to_string(), header(&h, "x-when"))
        })
        .collect();
    common::stop(&mut child);
    let _ = std::fs::remove_file(&path);
    let want = [
        ("HTTP/1.1 200 OK", "[][v][v][v][][][v][v]"),
        ("HTTP/1.1 503 Service Unavailable", "[v][][v][v][][][v][]"),
        ("HTTP/1.1 200 OK", "[][v][][v][v][][v][v]"),
    ];
    for (g, w) in got.iter().zip(want) {
        assert_eq!((g.0.as_str(), g.1.as_deref()), (w.0, Some(w.1)), "{got:?}");
    }
}

/// A failing `http-after-response` rule (strict mode, a header that does not fit) turns the
/// stats page into the 500 page too (measured on `HAProxy`: `HTTP/1.1 500 Internal Server
/// Error`; `IBEX_TEST_BIN=/path/to/haproxy cargo test --test when_applet` runs it there).
#[test]
fn a_failing_after_response_rule_turns_the_stats_page_into_a_500() {
    let port = common::reserve_port();
    let big = "a".repeat(900);
    let cfg = format!(
        "global\n  tune.bufsize 1024\n  tune.maxrewrite 256\n\
         defaults\n  mode http\n  timeout client 3s\n  timeout server 3s\n  timeout connect 1s\n\
         frontend fe\n  bind 127.0.0.1:{port}\n  stats enable\n  stats uri /stats\n  \
         http-after-response strict-mode on\n  http-after-response set-header x-big \"{big}\"\n"
    );
    let path = std::env::temp_dir().join(format!("ibex_whenapplet_500_{}", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
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
    let h = head(port, "/stats");
    common::stop(&mut child);
    let _ = std::fs::remove_file(&path);
    assert_eq!(h.lines().next(), Some("HTTP/1.1 500 Internal Server Error"), "{h}");
}
