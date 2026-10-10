// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use ibex_config::parser::parse_str;
use ibex_rt::{Engine, ServerStatus};
use std::io::{Read, Write};
use std::net::{TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn test_httpchk_500_backend_marked_down() {
    // 1. Backend server accepts TCP connections and answers 500 Internal Server Error
    let s500_listener = TcpListener::bind("127.0.0.1:0").expect("bind 500 backend");
    let s500_addr = s500_listener.local_addr().expect("local_addr");

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = Arc::clone(&running);

    let server_thread = thread::spawn(move || {
        // Non-blocking: a blocking `accept()` only notices the shutdown flag between
        // connections, so once the engine stops checking, the thread parks in accept()
        // forever and `join()` below never returns. The test hung for five minutes in
        // futex_do_wait and its assertion was never reached.
        s500_listener.set_nonblocking(true).expect("set_nonblocking");
        while running_clone.load(Ordering::Relaxed) {
            match s500_listener.accept() {
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => {}
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 512];
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                    let _ = stream.read(&mut buf);
                let resp = b"HTTP/1.0 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
                let _ = stream.write_all(resp);
                }
            }
        }
    });

    let config_text = format!(
        r"
defaults
    mode http
    timeout client 5s
    timeout server 5s
    timeout connect 5s

backend be_test
    option httpchk GET /health HTTP/1.0
    server srv1 {s500_addr} check inter 50ms rise 1 fall 1
"
    );

    let config = parse_str(&config_text).expect("parse config with option httpchk");
    let mut engine = Engine::new(&config, 1024).expect("Engine::new");

    // Run engine loop to process checks
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_millis(400) {
        let _ = engine.run_once().expect("engine run_once");
        thread::sleep(Duration::from_millis(10));
    }

    running.store(false, Ordering::Relaxed);
    let _ = server_thread.join();

    // The backend answering 500 MUST be marked DOWN
    let status = ServerStatus::from(engine.proxies[0].server_statuses[0].load(Ordering::Relaxed));
    assert_eq!(
        status,
        ServerStatus::Down,
        "A backend answering 500 to option httpchk MUST be marked DOWN, not UP!"
    );
}
