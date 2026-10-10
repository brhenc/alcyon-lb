// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;

/// Kills the daemonized ibex when the test ends, pass or panic: a leaked daemon keeps its
/// port, and with `SO_REUSEPORT` it shares that port with whatever is started on it next.
struct Daemon(std::path::PathBuf);

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Ok(pid) = std::fs::read_to_string(&self.0) {
            let _ = Command::new("kill").arg(pid.trim()).output();
        }
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn test_multithread_config_initialization() {
    let fe = common::reserve_addr();
    let be = common::reserve_addr();
    let dir = tempfile::tempdir().unwrap();
    // Write a config with nbthread 4 and custom maxrewrite.
    let config_path = dir.path().join("multithread_test.cfg");
    let pid_path = dir.path().join("ibex_test.pid");
    let mut f = std::fs::File::create(&config_path).unwrap();
    f.write_all(b"
global
    nbthread 4
    tune.maxrewrite 2048

defaults
    mode http
    timeout connect 5s
    timeout client  5s
    timeout server  5s

frontend fe
    bind ").unwrap();
    f.write_all(format!("{fe}\n    http-request add-header X-Padding ").as_bytes()).unwrap();

    let padding = "A".repeat(1500);
    f.write_all(padding.as_bytes()).unwrap();

    f.write_all(b"
    default_backend be

backend be
    server s1 ").unwrap();
    f.write_all(format!("{be}\n").as_bytes()).unwrap();
    f.flush().unwrap();

    // Start a dummy backend
    let dummy_be = std::net::TcpListener::bind(be).unwrap();

    let exe = env!("CARGO_BIN_EXE_ibex");
    
    let mut child = Command::new(exe)
        .arg("-D")
        .arg("-p")
        .arg(&pid_path)
        .arg("-f")
        .arg(&config_path)
        .spawn()
        .expect("failed to spawn ibex");

    // Wait for it to daemonize
    let status = child.wait().expect("failed to wait on ibex");
    assert!(status.success(), "ibex failed to start: {:?}", status);
    let _daemon = Daemon(pid_path.clone());

    assert!(common::wait_listening(fe), "ibex did not listen on {fe}");

    // Send 100 requests. If any thread did not initialize its thread_locals,
    // the request will fail because the padding is 1500 > default maxrewrite 1024.
    let mut success_count = 0;
    for _ in 0..100 {
        if let Ok(mut stream) = TcpStream::connect(fe) {
            stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            
            // Accept on dummy backend
            if let Ok((mut be_stream, _)) = dummy_be.accept() {
                let mut buf = [0u8; 4096];
                let n = be_stream.read(&mut buf).unwrap_or(0);
                if n > 0 {
                    be_stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").unwrap();
                    success_count += 1;
                }
            }
        }
    }

    assert_eq!(success_count, 100, "Not all requests succeeded. Some threads might have failed to initialize maxrewrite.");
}
