// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `_getsocks` to a CLI client that does not read (T241 item 4): the worker waited for room on
//! the stream (up to a second) while holding the registry of exposed listeners, so every
//! listener that registered or withdrew in that time waited with it.

use alcyon_rt::handover;
use std::io::Write;
use std::net::TcpListener;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

#[test]
fn a_client_that_does_not_read_does_not_hold_up_the_registry() {
    handover::enable_expose();
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    handover::expose(l.local_addr().expect("addr"), l.as_fd()).expect("expose");

    let (server, _client) = UnixStream::pair().expect("pair");
    server.set_nonblocking(true).expect("nonblocking");
    // Fill the stream so that nothing more can be sent on it.
    let mut s = &server;
    while s.write(&[0u8; 4096]).is_ok() {}

    let busy = std::thread::spawn(move || {
        let start = Instant::now();
        let r = handover::serve_getsocks(&server);
        (start.elapsed(), r.is_err())
    });
    std::thread::sleep(Duration::from_millis(150));
    let start = Instant::now();
    handover::expose("127.0.0.1:1".parse().expect("addr"), l.as_fd()).expect("expose again");
    let waited = start.elapsed();
    assert!(waited < Duration::from_millis(100), "registering a listener waited {waited:?} behind a stuck _getsocks");
    let (took, failed) = busy.join().expect("join");
    assert!(failed, "a send that cannot make progress must fail");
    assert!(took < Duration::from_millis(1500), "the send was not bounded: {took:?}");
    handover::withdraw_all();
}
