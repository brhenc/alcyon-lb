// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T331: `request_date([<unit>])`, the date of the request's first byte: `accept_date`
//! plus the idle time before it (`tcp_sample.c`). Every expected value was measured on
//! `HAProxy` 3.5-dev8-885761-29 with the same configuration.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Alcyon(Child, std::path::PathBuf);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn write_cfg(tag: &str, cfg: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("request-date-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    let full = format!("defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n{cfg}");
    std::fs::write(&path, full).unwrap();
    (dir, path)
}

fn start(tag: &str, cfg: &str, a: SocketAddr) -> Alcyon {
    let (dir, path) = write_cfg(tag, cfg);
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let alcyon = Alcyon(child, dir);
    assert!(common::wait_listening(a), "alcyon did not listen on {a}");
    alcyon
}

/// Sends one keep-alive request on `c` and returns the body of the answer.
fn ask(c: &mut TcpStream) -> String {
    c.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
    let (mut got, mut b) = (Vec::new(), [0u8; 4096]);
    loop {
        if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map_or(0, |v| v.trim().parse().unwrap());
            if got.len() >= end + 4 + len {
                return String::from_utf8_lossy(&got[end + 4..end + 4 + len]).into_owned();
            }
        }
        let n = c.read(&mut b).unwrap_or(0);
        assert!(n > 0, "the answer stopped short: {:?}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&b[..n]);
    }
}

/// `<request_date(ms)>-<accept_date(ms)>`, the leading field of `s`, as the difference.
fn idle(s: &str) -> i64 {
    let (r, a) = s.split('|').next().unwrap().split_once('-').unwrap_or_else(|| panic!("not a pair: {s:?}"));
    r.parse::<i64>().unwrap() - a.parse::<i64>().unwrap()
}

/// A client that waits 1 s before its request, then 0.7 s before a second one on the same
/// connection, then a new client that asks at once (oracle: 1000, 700 and 0, both in an
/// `http-request return` and in the log line). Here within 150 ms either way: the accept
/// of a loaded or just started process can come late, and the idle time is counted from it.
#[test]
fn request_date_adds_the_idle_time_before_the_request() {
    let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
    collector.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let a = common::reserve_addr();
    let cfg = format!(
        "frontend fe\n  bind {a}\n  log {} local0\n  option dontlognull\n  \
         log-format \"LOG %[request_date(ms)]-%[accept_date(ms)]\"\n  \
         http-request return status 200 content-type text/plain lf-string \"%[request_date(ms)]-%[accept_date(ms)]|%[request_date(us)]|%[request_date]\"\n",
        collector.local_addr().unwrap()
    );
    let _alcyon = start("idle", &cfg, a);
    let connect = || {
        let c = TcpStream::connect_timeout(&a, Duration::from_secs(2)).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c
    };
    // The idle time is what the server saw between the accept (or the previous answer) and the
    // request, so a loaded host that oversleeps or delays a send lengthens it. The expected value
    // is therefore the wait this thread measured (not the nominal one), with the same tolerance.
    // The first idle time is counted from the accept, and a loaded server may accept late; the
    // accept date it reports says by how much (the connection has been established since `t0`), and
    // that part of the wait is not idle time.
    let now_ms = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let mut c = connect();
    let t0 = now_ms();
    let t = std::time::Instant::now();
    std::thread::sleep(Duration::from_millis(1000));
    let mut w1 = t.elapsed().as_millis() as i64;
    let first = ask(&mut c);
    let accept1: i64 = first.split('|').next().unwrap().split_once('-').unwrap().1.parse().unwrap();
    w1 -= (accept1 - t0).max(0);
    let t = std::time::Instant::now();
    std::thread::sleep(Duration::from_millis(700));
    let w2 = t.elapsed().as_millis() as i64;
    let second = ask(&mut c);
    drop(c);
    let w3 = 0;
    let third = ask(&mut connect());
    let mut logs = Vec::new();
    for _ in 0..3 {
        let mut buf = [0u8; 2048];
        let n = collector.recv(&mut buf).expect("a log line");
        let line = String::from_utf8_lossy(&buf[..n]).into_owned();
        logs.push(line[line.find("LOG ").expect("the log-format line") + 4..].trim_end().to_string());
    }
    // A connection's line is written when it ends, so the third may reach the collector before
    // the second: order the lines by accept date, which is the order of the connections.
    logs.sort_by_key(|l| l.split_once('-').unwrap().1.parse::<i64>().unwrap());
    for (what, got) in [("rule", [&first, &second, &third].map(|s| idle(s))), ("log", [&logs[0], &logs[1], &logs[2]].map(|s| idle(s)))] {
        for (want, got) in [w1, w2, w3].into_iter().zip(got) {
            assert!((want - 150..want + 150).contains(&got) && got >= 0, "{what}: request_date - accept_date is {got} ms, not {want} (waited {w1}/{w2}/{w3}): {first:?} {second:?} {third:?} {logs:?}");
        }
    }
    // The units are of one date: microseconds, milliseconds, seconds.
    for b in [&first, &second, &third] {
        let f: Vec<&str> = b.split('|').collect();
        let ms: i64 = f[0].split('-').next().unwrap().parse().unwrap();
        assert_eq!((f[1].parse::<i64>().unwrap() / 1000, f[2].parse::<i64>().unwrap()), (ms, ms / 1000), "{b:?}");
    }
}

/// `HAProxy` refuses a unit other than `s`, `ms` or `us`, an empty one and a second argument
/// at load, for `request_date` and `accept_date` alike; it takes no argument, or one of the three.
#[test]
fn request_date_and_accept_date_refuse_a_bad_unit_at_load() {
    for f in ["request_date", "accept_date"] {
        for (arg, why) in [
            ("(min)", Some(format!("invalid args in fetch method '{f}' : expects 's', 'ms' or 'us', got 'min'"))),
            ("()", Some(format!("invalid args in fetch method '{f}' : expects 's', 'ms' or 'us', got ''"))),
            ("(ms,1)", Some(format!("fetch method '{f}' : expected ')' before ',1)'"))),
            ("", None),
            ("(s)", None),
            ("(ms)", None),
            ("(us)", None),
        ] {
            let cfg = format!("frontend fe\n  bind 127.0.0.1:0\n  http-request return status 200 content-type text/plain lf-string \"%[{f}{arg}]\"\n");
            let (dir, path) = write_cfg("load", &cfg);
            let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&path).output().unwrap();
            let _ = std::fs::remove_dir_all(&dir);
            let err = String::from_utf8_lossy(&out.stderr);
            match why {
                Some(why) => assert!(!out.status.success() && err.contains(&why), "{f}{arg}: want {why:?}, got {err:?}"),
                None => assert!(out.status.success(), "{f}{arg} is refused: {err:?}"),
            }
        }
    }
}
