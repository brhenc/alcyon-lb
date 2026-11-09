// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T260): lowers the test process's RLIMIT_NOFILE (other tests would get EMFILE)

//! A CLI client arriving while the process is out of descriptors (T246, from T237).
//! `accept_from_cli_listener` broke out of its loop on `EMFILE` with the listener still
//! armed: the level-triggered listener was ready again at once and the worker spun in
//! `accept4`. `HAProxy` stops the listener for 100 ms (`listener_accept`, `CO_AC_PAUSE`).
//!
//! The test lowers this process's `RLIMIT_NOFILE`, so it is the only test in its binary.

use alcyon_rt::Engine;
use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

#[test]
fn out_of_fds_the_cli_listener_pauses_instead_of_spinning_and_resumes() {
    let dir = tempfile::TempDir::new().expect("dir");
    let sock = dir.path().join("s.sock");
    let cfg = alcyon_config::parse_str("global\n").expect("parses");
    let mut e = Engine::new(&cfg, 64).expect("engine");
    e.bind_cli_socket(&sock).expect("cli socket");
    let _ = e.run_once();

    let mut client = UnixStream::connect(&sock).expect("connect");
    client.write_all(b"show cli level\n").expect("write");

    // Every descriptor slot taken: the next `accept` fails with EMFILE.
    let saved = getrlimit(Resource::Nofile);
    let max_fd = std::fs::read_dir("/proc/self/fd").expect("fds").filter_map(|d| d.ok()?.file_name().to_str()?.parse::<u64>().ok()).max().unwrap_or(0);
    setrlimit(Resource::Nofile, Rlimit { current: Some(max_fd + 1), maximum: saved.maximum }).expect("setrlimit");
    let mut fillers: Vec<OwnedFd> = Vec::new();
    while let Ok(fd) = rustix::io::fcntl_dupfd_cloexec(&client, 0) {
        fillers.push(fd);
    }

    let start = Instant::now();
    let mut turns = 0;
    while start.elapsed() < Duration::from_millis(60) {
        let _ = e.run_once();
        turns += 1;
    }
    drop(fillers);
    setrlimit(Resource::Nofile, saved).expect("restore");
    assert!(turns < 50, "{turns} loop turns in 60 ms with a client the worker cannot accept: it spins");

    // After the pause the client is accepted and answered.
    client.set_nonblocking(true).expect("nonblocking");
    let mut got = Vec::new();
    let end = Instant::now() + Duration::from_secs(3);
    while !got.ends_with(b"\n\n") && Instant::now() < end {
        let _ = e.run_once();
        let mut buf = [0u8; 256];
        if let Ok(n) = client.read(&mut buf) {
            got.extend_from_slice(&buf[..n]);
        }
    }
    assert_eq!(String::from_utf8_lossy(&got), "admin\n\n");
}
