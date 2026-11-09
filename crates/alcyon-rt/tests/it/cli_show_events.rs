// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `show events` on the CLI socket, in a one-shot session and in a prompt session.

use crate::common;

use alcyon_rt::loghdr::Meta;
use alcyon_rt::Engine;
use alcyon_sched::Tick;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

fn engine(sock: &std::path::Path) -> Engine {
    let cfg = alcyon_config::parse_str(&format!(
        "ring cli_ring\n  description \"for the CLI\"\n  size 2048\nlisten l\n  bind {}\n  mode tcp\n  server s 127.0.0.1:29093\n",
        common::reserve_addr()
    ))
    .expect("parses");
    let mut e = Engine::new(&cfg, 64).expect("engine");
    e.bind_cli_socket(sock).expect("cli socket");
    e
}

/// Sends `cmd`, steps the engine until `done` holds for what came back, and returns it.
fn ask(e: &mut Engine, c: &mut UnixStream, cmd: &str, done: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    c.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut got = Vec::new();
    let mut tick = Tick(100);
    for _ in 0..200 {
        let _ = e.step(tick);
        let mut buf = [0u8; 2048];
        if let Ok(n) = c.read(&mut buf) {
            got.extend_from_slice(&buf[..n]);
        }
        if done(&got) {
            return got;
        }
        tick = tick.add(10);
    }
    panic!("no answer to {cmd:?}: {:?}", String::from_utf8_lossy(&got));
}

#[test]
fn show_events_lists_the_sinks_and_dumps_a_ring_one_shot_and_at_the_prompt() {
    let sock = std::path::PathBuf::from(format!("/tmp/alcyon_test_events_{}.sock", std::process::id()));
    let mut e = engine(&sock);
    let ring = alcyon_rt::ring::find("cli_ring").expect("the ring exists");
    ring.write(16, 6, &Meta::default(), 1024, b"one\x1b");

    // One-shot: the answer, a blank line, and the session ends.
    let mut c = UnixStream::connect(&sock).expect("connect");
    c.set_nonblocking(true).expect("nonblocking");
    let got = ask(&mut e, &mut c, "show events cli_ring -s", |g| g.ends_with(b"\n\n"));
    assert_eq!(got, b"one?\n\n");

    // At the prompt: the sinks listed, and the prompt back.
    let mut c = UnixStream::connect(&sock).expect("connect");
    c.set_nonblocking(true).expect("nonblocking");
    ask(&mut e, &mut c, "prompt", |g| g.ends_with(b"> "));
    let got = ask(&mut e, &mut c, "show events", |g| g.ends_with(b"\n> "));
    let text = String::from_utf8_lossy(&got);
    assert!(text.contains("cli_ring   : type=buffer, 0 dropped, for the CLI"), "{text}");
    let got = ask(&mut e, &mut c, "help", |g| g.ends_with(b"\n> "));
    assert!(String::from_utf8_lossy(&got).contains("show events [-0rsn] [<sink>]"));
    let got = ask(&mut e, &mut c, "show events -w cli_ring", |g| g.ends_with(b"\n> "));
    assert!(String::from_utf8_lossy(&got).contains("not implemented"));
    let _ = std::fs::remove_file(&sock);
}
