// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.maxaccept <n>` (T295 item 2): a listener wakeup accepts at most `n` connections
//! in a row before the thread goes back to its other work (`HAProxy`'s `listener_accept`,
//! `for (; max_accept; max_accept--)`); `-1` is no limit. The rest of the backlog is
//! picked up by the next pass: the listener is polled level-triggered.
//!
//! In-process, one engine pass at a time: six clients have each connected and sent a
//! request before the first pass looks. With `tune.maxaccept 2`, no pass answers more
//! than two of them; with `-1`, one pass answers all six.

use crate::common;

use std::io::{ErrorKind, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use ibex_rt::engine::Engine;

/// Whether `s` has bytes to read (or is closed), without consuming them.
fn has_bytes(s: &TcpStream) -> bool {
    let mut b = [0u8; 1];
    !matches!(s.peek(&mut b), Err(e) if e.kind() == ErrorKind::WouldBlock)
}

/// Six clients queued before the first pass; the most answered in one pass, and the passes
/// it took to answer them all.
fn most_answered_in_one_pass(maxaccept: &str) -> (usize, usize) {
    let addr = common::reserve_addr();
    let cfg = format!(
        "global\n  tune.maxaccept {maxaccept}\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {addr}\n\
         \x20 http-request return status 200 content-type text/plain string ok\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let mut clients: Vec<TcpStream> = Vec::new();
    for _ in 0..6 {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        s.set_nonblocking(true).unwrap();
        clients.push(s);
    }
    // Everything is in the kernel before the first pass looks.
    std::thread::sleep(Duration::from_millis(50));

    let mut answered = vec![false; clients.len()];
    let mut most = 0;
    let mut passes = 0;
    let deadline = Instant::now() + Duration::from_secs(5);
    while answered.iter().any(|a| !a) && Instant::now() < deadline {
        let _ = engine.run_once();
        passes += 1;
        let mut new = 0;
        for (i, s) in clients.iter().enumerate() {
            if !answered[i] && has_bytes(s) {
                answered[i] = true;
                new += 1;
            }
        }
        most = most.max(new);
    }
    assert!(answered.iter().all(|a| *a), "maxaccept {maxaccept}: not every client was answered: {answered:?}");
    (most, passes)
}

#[test]
fn a_wakeup_accepts_at_most_maxaccept_connections() {
    let (most, passes) = most_answered_in_one_pass("2");
    assert!(most <= 2, "{most} connections were accepted and answered in one pass with tune.maxaccept 2");
    assert!(passes >= 3, "six connections took {passes} pass(es) with tune.maxaccept 2");
}

#[test]
fn minus_one_is_no_limit() {
    let (most, _) = most_answered_in_one_pass("-1");
    assert_eq!(most, 6, "with tune.maxaccept -1 one pass accepts the whole backlog");
}
