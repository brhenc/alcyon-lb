// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T320: `show info` `CumStreams`.

use crate::common;

use std::collections::HashMap;
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

#[test]
fn test_cum_streams() {
    let a = common::reserve_addr();
    let (alcyon, sock) = start(
        "show_info_cum_streams",
        &http_cfg("  nbthread 4\n", &format!("frontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain string 0123456789\n")),
        &[a],
    );

    let a_info = info(&sock);
    let a_cum = num(&a_info, "CumStreams");

    // 10 requests on 10 separate connections
    for _ in 0..10 {
        get(a, GET);
    }

    // 5 requests on one keep-alive connection
    let mut ka = TcpStream::connect_timeout(&a, Duration::from_secs(2)).expect("ka connect");
    ka.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    for _ in 0..5 {
        ka.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        let mut buf = Vec::new();
        while !buf.windows(10).any(|w| w == b"0123456789") {
            let mut tmp = [0u8; 4096];
            match ka.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        }
        assert!(buf.windows(10).any(|w| w == b"0123456789"), "keep-alive response incomplete: {buf:?}");
    }
    drop(ka);

    // The expected CumStreams after A: 15 (10 single + 5 keep-alive) + number of show info reads since A
    // (each show info connection itself counts as a stream). Poll up to 2s for the streams to be counted.
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut last_cum;
    let mut extra_reads = 0u64;
    loop {
        extra_reads += 1;
        last_cum = num(&info(&sock), "CumStreams");
        let expected = a_cum + 15 + extra_reads;
        if last_cum >= expected {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let expected = a_cum + 15 + extra_reads;
    assert_eq!(last_cum, expected, "CumStreams was {last_cum}, expected {expected} (a_cum={a_cum}, extra_reads={extra_reads})");
    drop(alcyon);
}

/// Measured on `HAProxy` 3.5-dev8, as the change of `CumStreams` between two `show info`
/// reads less the second read's own stream: 3 connect-and-close, 3 unparsable requests
/// (400), 3 partial requests then close, one partial request left to `timeout
/// http-request` (408), 3 x 47 garbage bytes to a `proto h2` bind -> 0 each. A stream
/// exists only once a request was parsed (`stream_new`); 3 good requests -> 3, and 3
/// connect-and-close on a TCP frontend -> 3 (a TCP session is a stream at once).
#[test]
fn connections_without_a_request_are_not_streams() {
    let h1 = common::reserve_addr();
    let h2 = common::reserve_addr();
    let tcp = common::reserve_addr();
    let (_alcyon, sock) = start(
        "cum_streams_probes",
        &http_cfg(
            "",
            &format!(
                "  timeout http-request 1s
                 frontend fe
  bind {h1}
  http-request return status 200
                 frontend h2
  bind {h2} proto h2
  http-request return status 200
                 frontend t
  mode tcp
  bind {tcp}
  tcp-request content reject
"
            ),
        ),
        &[h1, h2, tcp],
    );
    let delta = |what: &str, f: &dyn Fn()| -> u64 {
        let before = num(&info(&sock), "CumStreams");
        f();
        std::thread::sleep(Duration::from_millis(300));
        let after = num(&info(&sock), "CumStreams");
        assert!(after > before, "{what}: CumStreams went from {before} to {after}");
        after - before - 1
    };
    // A TCP frontend that rejects at once may reset the connection before `connect` returns.
    let connect_close = |a: SocketAddr| drop(TcpStream::connect_timeout(&a, Duration::from_secs(2)));
    assert_eq!(delta("connect and close", &|| (0..3).for_each(|_| connect_close(h1))), 0, "connect and close");
    assert_eq!(delta("unparsable request", &|| (0..3).for_each(|_| drop(get(h1, b"BLAH\r\n\r\n")))), 0, "unparsable request");
    assert_eq!(
        delta("partial request then close", &|| (0..3).for_each(|_| {
            let mut s = TcpStream::connect_timeout(&h1, Duration::from_secs(2)).expect("connect");
            s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n").unwrap();
        })),
        0,
        "partial request then close"
    );
    assert_eq!(
        delta("408", &|| {
            let mut s = TcpStream::connect_timeout(&h1, Duration::from_secs(2)).expect("connect");
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            s.write_all(b"GET / HTTP/1.1\r\n").unwrap();
            let mut out = Vec::new();
            let _ = s.read_to_end(&mut out);
            assert!(out.starts_with(b"HTTP/1.1 408"), "expected a 408: {:?}", String::from_utf8_lossy(&out));
        }),
        0,
        "408"
    );
    assert_eq!(delta("h2 garbage", &|| (0..3).for_each(|_| drop(get(h2, &[0x5a; 47])))), 0, "garbage to an h2 bind");
    assert_eq!(delta("good requests", &|| (0..3).for_each(|_| drop(get(h1, GET)))), 3, "good requests");
    assert_eq!(delta("tcp connect", &|| (0..3).for_each(|_| connect_close(tcp))), 3, "TCP connect and close");
}
