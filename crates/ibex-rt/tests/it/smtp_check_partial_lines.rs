// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T117: `option smtpchk` must not judge a reply before enough of it has arrived.
//!
//! The servers here send their replies in tiny pieces with sleeps in between, so the
//! check sees every split deterministically (the reg-test
//! `checks/4be_1srv_smtpchk_httpchk_layer47errors.vtc` did it by luck of scheduling and
//! passed two runs in three). The expected log fields were measured on the reference
//! binary (3.5-dev8-885761-29) with the same servers.

use ibex_config::parser::parse_str;
use ibex_rt::Engine;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

/// Engines built concurrently in one test process disturb each other (their checks
/// time out), so these tests take turns.
static ENGINE_LOCK: Mutex<()> = Mutex::new(());

type Parts = Vec<&'static [u8]>;

/// Serves one connection: sends `banner`, then (if given) reads the command and sends
/// `reply`, reads QUIT and sends `bye`. Each slice is one `send`, 40 ms apart.
fn spawn_server(
    banner: Parts,
    rest: Option<(Parts, Parts)>,
) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let h = thread::spawn(move || {
        let (mut s, _) = l.accept().expect("accept");
        let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
        let send = |s: &mut std::net::TcpStream, parts: &[&[u8]]| {
            for p in parts {
                let _ = s.write_all(p);
                let _ = s.flush();
                thread::sleep(Duration::from_millis(40));
            }
        };
        send(&mut s, &banner);
        if let Some((reply, bye)) = rest {
            let mut b = [0u8; 64];
            let _ = s.read(&mut b);
            send(&mut s, &reply);
            let _ = s.read(&mut b);
            send(&mut s, &bye);
        }
        thread::sleep(Duration::from_millis(300));
    });
    (addr, h)
}

/// Runs the first check to completion; returns (status code, http code, info).
fn run_check(addr: std::net::SocketAddr) -> (&'static str, Option<u16>, Option<String>) {
    let cfg = format!(
        "defaults\n    mode tcp\n    timeout connect 2s\n    timeout server 5s\n    timeout client 5s\n\
         backend be\n    option smtpchk\n    server s {addr} check inter 4s rise 1 fall 1\n"
    );
    let _turn = ENGINE_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let config = parse_str(&cfg).expect("parse");
    let mut engine = Engine::new(&config, 1024).expect("engine");
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(5) {
        let _ = engine.run_once().expect("run_once");
        let c = &engine.checks[0];
        if c.total_checks >= 1 && !c.in_progress {
            return (c.last_status_code, c.http_code, c.last_status_info.as_deref().map(str::to_string));
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("the check did not complete");
}

/// The reg-test's own server: `2` `2` `0` `\r\n`, then `2` `4` `8` `\r\n`, then `2` `2` `1`
/// ` ok\r\n`. HAProxy: "succeeded, reason: Layer7 check passed, code: 221, info: "ok"".
/// Before the fix Ibex took `248` (no CRLF yet) for the whole reply, sent QUIT, and then
/// read the `\r\n` as the QUIT answer: "Layer7 invalid response".
#[test]
fn smtpchk_reply_arriving_a_byte_at_a_time_is_up() {
    let (addr, h) = spawn_server(
        vec![b"2", b"2", b"0", b"\r\n"],
        Some((
            vec![b"2", b"4", b"8", b"\r\n"],
            vec![b"2", b"2", b"1", b" ok\r\n"],
        )),
    );
    let (code, http, info) = run_check(addr);
    let _ = h.join();
    assert_eq!(
        (code, http, info.as_deref()),
        ("L7OK", Some(221), Some("ok")),
        "HAProxy logs: Layer7 check passed, code: 221, info: \"ok\""
    );
}

/// Same, with the reply cut inside the line instead of at the digits.
#[test]
fn smtpchk_reply_split_after_the_code_is_up() {
    let (addr, h) = spawn_server(
        vec![b"220 smtp\r\n"],
        Some((vec![b"250", b" hi\r\n"], vec![b"221", b" bye\r\n"])),
    );
    let (code, http, info) = run_check(addr);
    let _ = h.join();
    assert_eq!(
        (code, http, info.as_deref()),
        ("L7OK", Some(221), Some("bye"))
    );
}

/// A reply cut off by the server closing keeps the partial tail judged at EOF: the check
/// ends on the close (not on its timeout). HAProxy logs "Layer7 wrong status, code: 0" for
/// this one; Ibex's status for the dead QUIT answer is a separate difference, so only the
/// verdict is pinned here.
#[test]
fn smtpchk_reply_without_crlf_is_judged_at_eof() {
    let (addr, h) = spawn_server(vec![b"220 smtp\r\n"], Some((vec![b"250 hi"], vec![])));
    let (code, _, _) = run_check(addr);
    let _ = h.join();
    assert!(
        code != "L7OK" && code != "L7TOUT",
        "a server that closes after `250 hi` fails the QUIT step, got {code}"
    );
}

/// A refusing banner sent as `5` then `00 err\r\n`. HAProxy: "failed, reason: Layer7 wrong
/// status, code: 500, info: "err"".
#[test]
fn smtpchk_refusing_banner_in_two_pieces_is_wrong_status() {
    let (addr, h) = spawn_server(vec![b"5", b"00 err\r\n"], None);
    let (code, http, info) = run_check(addr);
    let _ = h.join();
    assert_eq!(
        (code, http, info.as_deref()),
        ("L7STS", Some(500), Some("err"))
    );
}

/// Not smtpchk, but the same family (a reply judged before it is complete): an
/// `option httpchk` answer whose status line arrives in two pieces, headers last.
#[test]
fn httpchk_status_line_in_pieces_is_up() {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let h = thread::spawn(move || {
        let (mut s, _) = l.accept().expect("accept");
        let mut b = [0u8; 512];
        let _ = s.read(&mut b);
        for p in [&b"HTTP/1.0 2"[..], b"00 OK\r\nContent-Le", b"ngth: 0\r\n\r\n"] {
            let _ = s.write_all(p);
            let _ = s.flush();
            thread::sleep(Duration::from_millis(40));
        }
        thread::sleep(Duration::from_millis(300));
    });
    let cfg = format!(
        "defaults\n    mode http\n    timeout connect 2s\n    timeout server 5s\n    timeout client 5s\n\
         backend be\n    option httpchk GET /\n    server s {addr} check inter 4s rise 1 fall 1\n"
    );
    let _turn = ENGINE_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let config = parse_str(&cfg).expect("parse");
    let mut engine = Engine::new(&config, 1024).expect("engine");
    let t0 = Instant::now();
    let mut got = None;
    while t0.elapsed() < Duration::from_secs(5) {
        let _ = engine.run_once().expect("run_once");
        let c = &engine.checks[0];
        if c.total_checks >= 1 && !c.in_progress {
            got = Some((c.last_status_code, c.http_code));
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let _ = h.join();
    assert_eq!(got, Some(("L7OK", Some(200))));
}
