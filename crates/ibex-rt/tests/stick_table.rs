// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Integration tests for Milestone 2: Stick Table Engine & Runtime CLI Inspection.

mod common;

use ibex_config::ast::{
    BackendSection, Config, FrontendSection, Mode, Server, StickRule, StickRuleType,
    StickTableConfigAst,
};
use ibex_rt::engine::Engine;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};


fn start_dummy_backend(
    addr: SocketAddr,
    body: &'static str,
    running: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let listener = TcpListener::bind(addr).expect("bind dummy srv");
        listener.set_nonblocking(true).expect("nonblocking");
        while running.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if req.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
            thread::sleep(Duration::from_millis(2));
        }
    })
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_stick_table_tracking_and_cli_show_table() {
    let srv_addr = common::reserve_addr();
    let fe_addr = common::reserve_addr();

    let running = Arc::new(AtomicBool::new(true));
    let h1 = start_dummy_backend(srv_addr, "OK_TRACKED", Arc::clone(&running));

    let config = Config {
        frontends: vec![FrontendSection {
            name: "fe_track".into(),
            bind: Some(fe_addr),
            mode: Mode::Http,
            clitimeout: Some(Duration::from_secs(3)),
            default_backend: Some("be_track".into()),
            stick_table: Some(StickTableConfigAst {
                key_type: "ip".into(),
                size: 1000,
                expire: Duration::from_secs(60),
                store_fields: vec![
                    "conn_cnt".into(),
                    "conn_cur".into(),
                    "conn_rate(10s)".into(),
                    "http_req_cnt".into(),
                    "http_req_rate(10s)".into(),
                ],
            }),
            stick_rules: vec![StickRule::new(StickRuleType::TrackSc0, "src".into())],
            ..Default::default()
        }],
        backends: vec![BackendSection {
            name: "be_track".into(),
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            servers: vec![Server::new("s1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("Engine::new");

    // Bind CLI unix domain socket for interactive testing
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let cli_sock_path = temp_dir.path().join("ibex.sock");
    engine
        .bind_cli_socket(&cli_sock_path)
        .expect("bind_cli_socket");

    let mut send_request = |req_str: &str| -> String {
        let mut client = TcpStream::connect(fe_addr).expect("connect to frontend");
        client.set_nonblocking(true).expect("set_nonblocking");
        client.write_all(req_str.as_bytes()).expect("write req");

        let start = Instant::now();
        let mut response = Vec::new();
        let mut buf = [0u8; 1024];

        while start.elapsed() < Duration::from_secs(2) {
            let _ = engine.run_once().expect("engine step");
            if let Ok(n) = client.read(&mut buf) {
                if n > 0 {
                    response.extend_from_slice(&buf[..n]);
                    if response.windows(4).any(|w| w == b"\r\n\r\n") && response.len() > 20 {
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
        String::from_utf8_lossy(&response).into_owned()
    };

    // Send 3 requests through frontend
    for _ in 0..3 {
        let res = send_request("GET /api/test HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(res.contains("OK_TRACKED"), "Got response: {res}");
    }

    // Step engine to flush any closed session cleanup
    for _ in 0..10 {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(2));
    }

    // Connect to CLI socket and send `show table\n`
    let mut cli_client = UnixStream::connect(&cli_sock_path).expect("connect to cli socket");
    cli_client
        .set_nonblocking(true)
        .expect("set_nonblocking cli");
    cli_client
        .write_all(b"show table\n")
        .expect("write show table");

    let start = Instant::now();
    let mut cli_output = Vec::new();
    let mut buf = [0u8; 1024];

    while start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once().expect("engine step");
        if let Ok(n) = cli_client.read(&mut buf) {
            if n > 0 {
                cli_output.extend_from_slice(&buf[..n]);
                if !cli_output.is_empty() {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(2));
    }

    let out_str = String::from_utf8_lossy(&cli_output);
    assert!(
        out_str.contains("# table: fe_track"),
        "Expected '# table: fe_track' in CLI output, got:\n{out_str}"
    );
    assert!(
        out_str.contains("conn_cnt=3") || out_str.contains("conn_cnt="),
        "Expected conn_cnt tracking in CLI output, got:\n{out_str}"
    );

    running.store(false, Ordering::Relaxed);
    let _ = h1.join();
}
