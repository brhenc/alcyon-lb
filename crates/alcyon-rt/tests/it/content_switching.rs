// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Integration tests for Milestone 2: Dynamic Content Switching & ACL-based Routing.

use crate::common;

use alcyon_config::ast::{
    AclCondition, AclRule, AclTerm, BackendSection, Config, FrontendSection, Mode, Server,
    UseBackendRule,
};
use alcyon_rt::engine::Engine;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
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
fn test_acl_content_switching_path_and_default_backend() {
    let api_srv_addr = common::reserve_addr();
    let static_srv_addr = common::reserve_addr();
    let default_srv_addr = common::reserve_addr();
    let fe_addr = common::reserve_addr();

    let running = Arc::new(AtomicBool::new(true));
    let h1 = start_dummy_backend(api_srv_addr, "API_ENDPOINT", Arc::clone(&running));
    let h2 = start_dummy_backend(static_srv_addr, "STATIC_ENDPOINT", Arc::clone(&running));
    let h3 = start_dummy_backend(default_srv_addr, "DEFAULT_ENDPOINT", Arc::clone(&running));

    let config = Config {
        frontends: vec![FrontendSection {
            name: "fe_http".into(),
            bind: Some(fe_addr),
            mode: Mode::Http,
            clitimeout: Some(Duration::from_secs(3)),
            default_backend: Some("be_default".into()),
            acls: vec![
                AclRule {
                    name: "is_api".into(),
                    expr: "path_beg /api".into(),
                },
                AclRule {
                    name: "is_static".into(),
                    expr: "path_beg /static".into(),
                },
            ],
            use_backends: vec![
                UseBackendRule {
                    backend: "be_api".into(),
                    cond: Some(AclCondition {
                        is_if: true,
                        terms: vec![AclTerm {
                            name: "is_api".into(),
                            negated: false,
                        }],
                    }),
                },
                UseBackendRule {
                    backend: "be_static".into(),
                    cond: Some(AclCondition {
                        is_if: true,
                        terms: vec![AclTerm {
                            name: "is_static".into(),
                            negated: false,
                        }],
                    }),
                },
            ],
            ..Default::default()
        }],
        backends: vec![
            BackendSection {
                name: "be_api".into(),
                mode: Mode::Http,
                contimeout: Some(Duration::from_secs(3)),
                srvtimeout: Some(Duration::from_secs(3)),
                servers: vec![Server::new("api1", api_srv_addr)],
                ..Default::default()
            },
            BackendSection {
                name: "be_static".into(),
                mode: Mode::Http,
                contimeout: Some(Duration::from_secs(3)),
                srvtimeout: Some(Duration::from_secs(3)),
                servers: vec![Server::new("static1", static_srv_addr)],
                ..Default::default()
            },
            BackendSection {
                name: "be_default".into(),
                mode: Mode::Http,
                contimeout: Some(Duration::from_secs(3)),
                srvtimeout: Some(Duration::from_secs(3)),
                servers: vec![Server::new("default1", default_srv_addr)],
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("Engine::new");

    // Helper to send request and collect response
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
                    if response.windows(4).any(|w| w == b"\r\n\r\n") && response.len() > 30 {
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
        String::from_utf8_lossy(&response).into_owned()
    };

    // 1. Request matching /api -> should route to be_api
    let res_api = send_request("GET /api/v1/status HTTP/1.1\r\nHost: example.com\r\n\r\n");
    assert!(
        res_api.contains("API_ENDPOINT"),
        "Expected /api request to hit API_ENDPOINT, got: {res_api}"
    );

    // 2. Request matching /static -> should route to be_static
    let res_static = send_request("GET /static/app.js HTTP/1.1\r\nHost: example.com\r\n\r\n");
    assert!(
        res_static.contains("STATIC_ENDPOINT"),
        "Expected /static request to hit STATIC_ENDPOINT, got: {res_static}"
    );

    // 3. Request matching neither -> should route to be_default
    let res_default = send_request("GET /home.html HTTP/1.1\r\nHost: example.com\r\n\r\n");
    assert!(
        res_default.contains("DEFAULT_ENDPOINT"),
        "Expected unrouted request to hit DEFAULT_ENDPOINT, got: {res_default}"
    );

    running.store(false, Ordering::Relaxed);
    let _ = h1.join();
    let _ = h2.join();
    let _ = h3.join();
}

#[test]
fn test_load_balancing_round_robin() {
    let srv1_addr = common::reserve_addr();
    let srv2_addr = common::reserve_addr();
    let fe_addr = common::reserve_addr();

    let running = Arc::new(AtomicBool::new(true));
    let h1 = start_dummy_backend(srv1_addr, "SRV_ONE", Arc::clone(&running));
    let h2 = start_dummy_backend(srv2_addr, "SRV_TWO", Arc::clone(&running));

    let config = Config {
        frontends: vec![FrontendSection {
            name: "fe_lb".into(),
            bind: Some(fe_addr),
            mode: Mode::Http,
            clitimeout: Some(Duration::from_secs(3)),
            default_backend: Some("be_lb".into()),
            ..Default::default()
        }],
        backends: vec![BackendSection {
            name: "be_lb".into(),
            mode: Mode::Http,
            balance: alcyon_config::BalanceAlgorithm::RoundRobin,
            contimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            servers: vec![Server::new("s1", srv1_addr), Server::new("s2", srv2_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("Engine::new");

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
                    if response.windows(4).any(|w| w == b"\r\n\r\n") && response.len() > 30 {
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
        String::from_utf8_lossy(&response).into_owned()
    };

    let res1 = send_request("GET /test1 HTTP/1.1\r\nHost: example.com\r\n\r\n");
    let res2 = send_request("GET /test2 HTTP/1.1\r\nHost: example.com\r\n\r\n");
    let res3 = send_request("GET /test3 HTTP/1.1\r\nHost: example.com\r\n\r\n");
    let res4 = send_request("GET /test4 HTTP/1.1\r\nHost: example.com\r\n\r\n");

    assert!(
        res1.contains("SRV_ONE"),
        "req 1 expected SRV_ONE, got {res1}"
    );
    assert!(
        res2.contains("SRV_TWO"),
        "req 2 expected SRV_TWO, got {res2}"
    );
    assert!(
        res3.contains("SRV_ONE"),
        "req 3 expected SRV_ONE, got {res3}"
    );
    assert!(
        res4.contains("SRV_TWO"),
        "req 4 expected SRV_TWO, got {res4}"
    );

    running.store(false, Ordering::Relaxed);
    let _ = h1.join();
    let _ = h2.join();
}

#[test]
fn test_load_balancing_source_ip() {
    let srv1_addr = common::reserve_addr();
    let srv2_addr = common::reserve_addr();
    let fe_addr = common::reserve_addr();

    let running = Arc::new(AtomicBool::new(true));
    let h1 = start_dummy_backend(srv1_addr, "SRV_ONE", Arc::clone(&running));
    let h2 = start_dummy_backend(srv2_addr, "SRV_TWO", Arc::clone(&running));

    let config = Config {
        frontends: vec![FrontendSection {
            name: "fe_src".into(),
            bind: Some(fe_addr),
            mode: Mode::Http,
            clitimeout: Some(Duration::from_secs(3)),
            default_backend: Some("be_src".into()),
            ..Default::default()
        }],
        backends: vec![BackendSection {
            name: "be_src".into(),
            mode: Mode::Http,
            balance: alcyon_config::BalanceAlgorithm::Source,
            contimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            servers: vec![Server::new("s1", srv1_addr), Server::new("s2", srv2_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("Engine::new");

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
                    if response.windows(4).any(|w| w == b"\r\n\r\n") && response.len() > 30 {
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
        String::from_utf8_lossy(&response).into_owned()
    };

    let res1 = send_request("GET /test1 HTTP/1.1\r\nHost: example.com\r\n\r\n");
    let res2 = send_request("GET /test2 HTTP/1.1\r\nHost: example.com\r\n\r\n");
    let res3 = send_request("GET /test3 HTTP/1.1\r\nHost: example.com\r\n\r\n");

    let target = if res1.contains("SRV_ONE") {
        "SRV_ONE"
    } else {
        "SRV_TWO"
    };

    assert!(
        res2.contains(target),
        "Source hash consistency failed on req 2: {res2}"
    );
    assert!(
        res3.contains(target),
        "Source hash consistency failed on req 3: {res3}"
    );

    running.store(false, Ordering::Relaxed);
    let _ = h1.join();
    let _ = h2.join();
}
