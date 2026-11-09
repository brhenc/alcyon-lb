// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The session arena keeps the capacity it was created with (the pre-size for `maxconn`)
//! when its empty tail slots are given back: a burst of sessions after the first one does
//! not grow it (a `realloc` on the request path).

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

use alcyon_rt::Engine;

const CAPACITY: usize = 512;

#[test]
fn the_arena_keeps_its_presize_across_a_first_session_and_a_burst() {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n  http-request return status 200\n"
    );
    let config = alcyon_config::parse_str(&cfg).expect("parse");
    let mut engine = Engine::new(&config, CAPACITY).expect("Engine::new");
    let initial = engine.sessions.capacity();
    assert!(initial >= CAPACITY, "{initial}");

    let drive = |engine: &mut Engine, client: thread::JoinHandle<usize>| {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !client.is_finished() && Instant::now() < deadline {
            let _ = engine.run_once();
            thread::sleep(Duration::from_millis(1));
        }
        client.join().expect("client")
    };
    let get = move |n: usize| {
        thread::spawn(move || {
            // n connections open at once, then all answered
            let mut conns: Vec<TcpStream> = (0..n).map(|_| TcpStream::connect(fe).expect("connect")).collect();
            for c in &mut conns {
                c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                write!(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
            }
            let mut ok = 0;
            for c in &mut conns {
                let mut out = String::new();
                let _ = c.read_to_string(&mut out);
                ok += usize::from(out.starts_with("HTTP/1.1 200"));
            }
            ok
        })
    };
    // one session, freed: the arena trims its tail
    assert_eq!(drive(&mut engine, get(1)), 1);
    for _ in 0..50 {
        let _ = engine.run_once();
    }
    assert_eq!(engine.sessions.live(), 0);
    assert!(engine.sessions.capacity() >= initial, "shrunk to {} from {initial}", engine.sessions.capacity());
    // a burst inside the pre-size, big enough that the arena renews its memory when it drains
    assert_eq!(drive(&mut engine, get(300)), 300);
    for _ in 0..50 {
        let _ = engine.run_once();
    }
    assert_eq!(engine.sessions.capacity(), initial, "the burst grew the arena");
}
