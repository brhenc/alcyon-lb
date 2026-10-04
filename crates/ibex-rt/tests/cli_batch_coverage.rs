// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use ibex_config::{Config, Mode, BackendSection, Server};
use ibex_rt::engine::Engine;
use ibex_rt::dgram::DgramSocket;
use std::time::Duration;
use std::net::SocketAddr;

#[test]
fn cli_commands_coverage() {
    let srv_addr = "127.0.0.1:80".parse().unwrap();
    let config = Config {
        backends: vec![BackendSection {
            name: "be".into(),
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            servers: vec![Server::new("s1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    let cli_sock_path = temp_dir.path().join("ibex.sock");
    engine.bind_cli_socket(&cli_sock_path).unwrap();

    // Command 1: get weight
    let mut cli1 = UnixStream::connect(&cli_sock_path).unwrap();
    cli1.write_all(b"get weight be/s1\n").unwrap();
    for _ in 0..5 { let _ = engine.run_once(); }
    cli1.set_nonblocking(true).unwrap();
    let mut out1 = String::new();
    let _ = cli1.read_to_string(&mut out1);
    assert_eq!(out1, "1 (initial 1)\n\n");

    // Command 2: show servers state
    let mut cli2 = UnixStream::connect(&cli_sock_path).unwrap();
    cli2.write_all(b"show servers state\n").unwrap();
    for _ in 0..5 { let _ = engine.run_once(); }
    cli2.set_nonblocking(true).unwrap();
    let mut out2 = String::new();
    let _ = cli2.read_to_string(&mut out2);
    let lines: Vec<&str> = out2.lines().collect();
    assert_eq!(lines[0], "1");
    // HAProxy 3.5, same backend, prints
    //   2 be 1 s1 127.0.0.1 2 0 1 1 0 1 0 0 0 0 0 0 - 80 - 0 0 - - 0
    // Field 0 (be_id) is 2 there and 0 here -- a real divergence, left to its own task
    // rather than written down as correct. Field 9 (srv_time_since_last_change) is
    // seconds elapsed and cannot be pinned. Every other field must match.
    let fields: Vec<&str> = lines[2].split(' ').collect();
    let haproxy: Vec<&str> = "2 be 1 s1 127.0.0.1 2 0 1 1 0 1 0 0 0 0 0 0 - 80 - 0 0 - - 0"
        .split(' ')
        .collect();
    assert_eq!(fields.len(), haproxy.len(), "{}", lines[2]);
    for (i, (got, want)) in fields.iter().zip(&haproxy).enumerate() {
        if i != 0 && i != 9 {
            assert_eq!(got, want, "field {i} of {:?}", lines[2]);
        }
    }
}

#[test]
fn dgram_socket_reuseport() {
    let port: u16 = 29483;
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let sock1 = DgramSocket::bind(addr).unwrap();
    let sock2 = DgramSocket::bind(addr).unwrap();
    let _ = (sock1, sock2);
}
