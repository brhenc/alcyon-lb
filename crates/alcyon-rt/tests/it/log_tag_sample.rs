// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `log-tag` and `log ... sample` on the engine's path to the collector.
//!
//! The lines are health-check transitions (one DOWN per dead server), the one message
//! every proxy emits today. What is checked is `HAProxy`'s `src/log.c`:
//! * `__send_log` takes the proxy's tag, else the global one, and the pid is separate
//!   metadata -- so a proxy's own tag is still followed by `[pid]`.
//! * `log global` and `defaults` copy each logger into the proxy (`dup_logger`), so each
//!   proxy walks its own sampling ranges; a second proxy does not continue the first's.

use crate::common;

use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, Instant};

use alcyon_rt::Engine;

/// Builds `cfg` (with `@C@` replaced by the collector address and `@Dn@` by dead
/// server addresses), drives the checks, and returns every datagram received.
fn datagrams(cfg: &str, dead: usize, expect: usize) -> Vec<String> {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("bind collector");
    collector.set_read_timeout(Some(Duration::from_millis(20))).expect("timeout");
    let mut text = cfg.replace("@C@", &collector.local_addr().expect("addr").to_string());
    for i in 0..dead {
        text = text.replace(&format!("@D{i}@"), &common::reserve_addr().to_string());
    }
    let config = alcyon_config::parse_str(&text).expect("parse");
    let mut engine = Engine::new(&config, 256).expect("Engine::new");
    for check in &mut engine.checks {
        std::sync::Arc::make_mut(&mut check.config).inter = Duration::from_millis(20);
        std::sync::Arc::make_mut(&mut check.config).timeout = Duration::from_millis(50);
        std::sync::Arc::make_mut(&mut check.config).fall = 1;
        std::sync::Arc::make_mut(&mut check.config).rise = 1;
    }
    let mut got = Vec::new();
    let mut buf = [0u8; 2048];
    // Past the point every server has gone DOWN, so a datagram that should have been
    // sampled out has had the time to arrive.
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(800) || got.len() < expect && start.elapsed() < Duration::from_secs(3) {
        let _ = engine.run_once().expect("run_once");
        if let Ok(n) = collector.recv(&mut buf) {
            got.push(String::from_utf8_lossy(&buf[..n]).into_owned());
        }
        thread::sleep(Duration::from_millis(2));
    }
    got
}

#[test]
fn a_proxy_log_tag_is_followed_by_the_pid() {
    let got = datagrams(
        "global\n  log @C@ local0\n  log-tag gtag\n\
         backend tagged\n  mode tcp\n  log global\n  log-tag ptag\n  server s @D0@ check\n\
         backend plain\n  mode tcp\n  log global\n  server s @D1@ check\n",
        2,
        2,
    );
    let pid = std::process::id();
    let tagged = got.iter().find(|l| l.contains("tagged/s")).expect("a line for tagged");
    let plain = got.iter().find(|l| l.contains("plain/s")).expect("a line for plain");
    assert!(tagged.contains(&format!(" ptag[{pid}]: ")), "{tagged:?}");
    assert!(plain.contains(&format!(" gtag[{pid}]: ")), "{plain:?}");
}

#[test]
fn each_proxy_samples_its_own_lines() {
    // sample 1:2 -- the first of every two lines. Each backend sends one, its first.
    let got = datagrams(
        "global\n  log @C@ sample 1:2 local0\n\
         backend a\n  mode tcp\n  log global\n  server s @D0@ check\n\
         backend b\n  mode tcp\n  log global\n  server s @D1@ check\n",
        2,
        2,
    );
    assert_eq!(got.len(), 2, "one line from each backend: {got:#?}");
}

#[test]
fn a_sampled_and_an_unsampled_log_to_one_collector_are_two_loggers() {
    // `sampled` keeps the first of its two lines; `every` keeps both of its own.
    let got = datagrams(
        "backend sampled\n  mode tcp\n  log @C@ sample 1:2 local0\n  server s1 @D0@ check\n  server s2 @D1@ check\n\
         backend every\n  mode tcp\n  log @C@ local0\n  server s1 @D2@ check\n  server s2 @D3@ check\n",
        4,
        3,
    );
    let sampled = got.iter().filter(|l| l.contains("sampled/")).count();
    let every = got.iter().filter(|l| l.contains("every/")).count();
    assert_eq!((sampled, every), (1, 2), "{got:#?}");
}
