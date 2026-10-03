// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Integration tests for HAProxy Connection Handling and Session Administration.

mod common;

use ibex_config::ast::{Config, ListenSection, Mode, Server, StatsConfig};
use ibex_config::parse_str;
use ibex_rt::{render_stats_html, render_stats_json, Engine, ServerStatus};
use ibex_sched::Tick;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};


fn send_http_request(proxy_addr: SocketAddr, engine: &mut Engine, req: &[u8]) -> String {
    let mut client = TcpStream::connect(proxy_addr).expect("client connect");
    client.set_nonblocking(true).expect("nonblocking");
    client.write_all(req).expect("write req");

    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];

    while start.elapsed() < Duration::from_secs(3) {
        let _ = engine.run_once().expect("engine step");
        match client.read(&mut buf) {
            Ok(n) if n > 0 => {
                response.extend_from_slice(&buf[..n]);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if let Some(pos) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                    let hdr = String::from_utf8_lossy(&response[..pos]);
                    if let Some(cl_line) = hdr
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                    {
                        if let Some(cl_val) = cl_line
                            .split(':')
                            .nth(1)
                            .and_then(|v| v.trim().parse::<usize>().ok())
                        {
                            if response.len() >= pos + 4 + cl_val {
                                break;
                            }
                        }
                    }
                }
            }
            Ok(_) | Err(_) => break,
        }
        thread::sleep(Duration::from_millis(5));
    }

    String::from_utf8_lossy(&response).to_string()
}

fn step_engine_until<F>(engine: &mut Engine, mut condition: F, max_steps: usize)
where
    F: FnMut(&mut Engine) -> bool,
{
    let mut tick = Tick(100);
    for _ in 0..max_steps {
        let _ = engine.step(tick);
        if condition(engine) {
            return;
        }
        tick = tick.add(10);
    }
    panic!("step_engine_until: condition was not met within {max_steps} steps");
}

#[test]
fn test_kill_sessions_web_admin_and_reclaim_actconn() {
    let srv_listener = TcpListener::bind("127.0.0.1:0").expect("bind srv");
    let srv_addr = srv_listener.local_addr().expect("srv addr");
    srv_listener.set_nonblocking(true).expect("nonblocking");

    let proxy_addr = common::reserve_addr();
    let config = Config {
        listens: vec![ListenSection {
            name: "test_proxy".into(),
            addr: proxy_addr,
            mode: Mode::Http,
            servers: vec![Server {
                id: "srv1".into(),
                addr: srv_addr,
                weight: Some(10),
                ..Default::default()
            }],
            stats: StatsConfig {
                enable: true,
                uri: Some("/stats".into()),
                admin: true,
                ..Default::default()
            },
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("engine");

    // 1. Establish an active client connection routed to backend srv1
    let mut client = TcpStream::connect(proxy_addr).expect("client connect");
    client.set_nonblocking(true).expect("nonblocking");
    client
        .write_all(b"GET /data HTTP/1.1\r\nHost: test\r\n\r\n")
        .expect("write req");

    // Step engine to accept client and connect backend
    for _ in 0..10 {
        let _ = engine.run_once();
        if let Ok((srv_conn, _)) = srv_listener.accept() {
            // Keep server socket alive in backend
            std::mem::forget(srv_conn);
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }

    // Step once more to progress session
    for _ in 0..5 {
        let _ = engine.run_once();
    }

    assert!(
        engine.proxies[0].stats[0].act_conn.load(std::sync::atomic::Ordering::Relaxed) >= 1,
        "act_conn should be >= 1, got {}",
        engine.proxies[0].stats[0].act_conn.load(std::sync::atomic::Ordering::Relaxed)
    );
    assert_eq!(
        engine.proxies[0].server_actconn[0].load(std::sync::atomic::Ordering::Relaxed), 1,
        "server_actconn should be 1"
    );

    // 2. Submit kill_sessions via Web Admin API
    let post_req = b"POST /stats HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 48\r\n\r\naction=kill_sessions&backend=test_proxy&server=srv1";
    let resp = send_http_request(proxy_addr, &mut engine, post_req);
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "Got: {resp}");

    // Step engine to process wakeups and cleanup
    for _ in 0..5 {
        let _ = engine.run_once();
    }

    // 3. Verify active connection counts immediately reclaimed
    assert_eq!(
        engine.proxies[0].server_actconn[0].load(std::sync::atomic::Ordering::Relaxed), 0,
        "server_actconn must be reclaimed to 0"
    );
    assert_eq!(
        engine.proxies[0].stats[0].act_conn.load(std::sync::atomic::Ordering::Relaxed), 0,
        "proxy act_conn must be reclaimed to 0"
    );

    // 4. Verify client socket was closed
    let mut read_buf = [0u8; 64];
    let mut closed = false;
    for _ in 0..20 {
        match client.read(&mut read_buf) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                closed = true;
                break;
            }
        }
    }
    assert!(closed, "client connection should be terminated");
}

#[test]
fn test_kill_sessions_cli_socket_and_direct_engine() {
    let socket_path = PathBuf::from(format!(
        "/tmp/ibex_test_kill_sessions_{}.sock",
        std::process::id()
    ));
    let cfg_str = r"
listen test_proxy
    bind 127.0.0.1:0
    mode tcp
    server srv1 127.0.0.1:0
";
    let config = parse_str(cfg_str).expect("parse config");
    let mut engine = Engine::new(&config, 64).expect("engine");
    engine.bind_cli_socket(&socket_path).expect("bind cli");

    // Manually increment actconn to simulate active sessions
    engine.proxies[0].stats[0].act_conn.store(5, std::sync::atomic::Ordering::Relaxed);
    engine.proxies[0].server_actconn[0].store(5, std::sync::atomic::Ordering::Relaxed);

    // 1. Test direct engine API
    let killed = engine.shutdown_sessions(Some("test_proxy"), Some("srv1"));
    // Since no sessions are in arena, killed is 0 but function completes cleanly
    assert_eq!(killed, 0);

    // 2. Test CLI command via socket
    let mut client = UnixStream::connect(&socket_path).expect("connect cli");
    client.set_nonblocking(true).expect("nonblocking");
    engine.step(Tick(100)).expect("step");

    // One-shot shutdown sessions server
    client
        .write_all(b"shutdown sessions server test_proxy/srv1\n")
        .expect("write");
    step_engine_until(
        &mut engine,
        |_eng| {
            let mut buf = [0u8; 128];
            matches!(client.read(&mut buf), Ok(0))
        },
        20,
    );

    // One-shot shutdown sessions backend
    let mut client2 = UnixStream::connect(&socket_path).expect("connect cli 2");
    client2.set_nonblocking(true).expect("nonblocking");
    engine.step(Tick(110)).expect("step");

    client2
        .write_all(b"shutdown sessions backend test_proxy\n")
        .expect("write");
    step_engine_until(
        &mut engine,
        |_eng| {
            let mut buf = [0u8; 128];
            matches!(client2.read(&mut buf), Ok(0))
        },
        20,
    );
}

#[test]
fn test_clear_counters_web_admin_and_cli() {
    let socket_path = PathBuf::from(format!(
        "/tmp/ibex_test_clear_counters_{}.sock",
        std::process::id()
    ));
    let proxy_addr = common::reserve_addr();
    let cfg_str = format!(
        r"
listen stats_proxy
    bind {proxy_addr}
    mode http
    stats enable
    stats uri /stats
    stats admin if TRUE
    server srv1 127.0.0.1:0

backend test_backend
    mode http
    server srv2 127.0.0.1:0
"
    );
    let config = parse_str(&cfg_str).expect("parse config");
    let mut engine = Engine::new(&config, 64).expect("engine");
    engine.bind_cli_socket(&socket_path).expect("bind cli");

    // Populate stats counters on test_backend (proxies[1])
    engine.proxies[1].stats[0].bytes_in.store(1_024_000, std::sync::atomic::Ordering::Relaxed);
    engine.proxies[1].stats[0].bytes_out.store(2_048_000, std::sync::atomic::Ordering::Relaxed);
    engine.proxies[1].stats[0].cum_conn.store(500, std::sync::atomic::Ordering::Relaxed);
    engine.proxies[1].stats[0].act_conn.store(12, std::sync::atomic::Ordering::Relaxed);
    engine.proxies[1].stats[0].max_conn.store(200, std::sync::atomic::Ordering::Relaxed);
    engine.proxies[1].stats[0].failed_conn.store(15, std::sync::atomic::Ordering::Relaxed);
    engine.proxies[1].stats[0].srv_err.store(5, std::sync::atomic::Ordering::Relaxed);
    engine.proxies[1].stats[0].cli_err.store(3, std::sync::atomic::Ordering::Relaxed);

    // 1. Clear via Web Admin POST with action=clear_counters&backend=test_backend
    let post_req = b"POST /stats HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 42\r\n\r\naction=clear_counters&backend=test_backend";
    let resp = send_http_request(proxy_addr, &mut engine, post_req);
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "Got: {resp}");

    assert_eq!(engine.proxies[1].stats[0].bytes_in.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(engine.proxies[1].stats[0].bytes_out.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(engine.proxies[1].stats[0].cum_conn.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(engine.proxies[1].stats[0].failed_conn.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(engine.proxies[1].stats[0].srv_err.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(engine.proxies[1].stats[0].cli_err.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(
        engine.proxies[1].stats[0].max_conn.load(std::sync::atomic::Ordering::Relaxed), engine.proxies[1].stats[0].act_conn.load(std::sync::atomic::Ordering::Relaxed),
        "max_conn must be reset to act_conn"
    );

    // 2. Populate again and clear via JSON request
    engine.proxies[1].stats[0].bytes_in.store(5555, std::sync::atomic::Ordering::Relaxed);
    let json_req = b"POST /stats HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 51\r\n\r\n{\"action\":\"clear_counters\",\"backend\":\"test_backend\"}";
    let json_resp = send_http_request(proxy_addr, &mut engine, json_req);
    assert!(json_resp.starts_with("HTTP/1.1 200 OK\r\n"), "Got: {json_resp}");
    assert!(json_resp.contains("\"status\":\"ok\""));
    assert_eq!(engine.proxies[1].stats[0].bytes_in.load(std::sync::atomic::Ordering::Relaxed), 0);

    // 3. Populate again and clear via CLI socket
    engine.proxies[1].stats[0].bytes_in.store(7777, std::sync::atomic::Ordering::Relaxed);
    let mut client = UnixStream::connect(&socket_path).expect("connect cli");
    client.set_nonblocking(true).expect("nonblocking");
    engine.step(Tick(100)).expect("step");

    client.write_all(b"clear counters test_backend\n").expect("write");
    step_engine_until(
        &mut engine,
        |eng| eng.proxies[1].stats[0].bytes_in.load(std::sync::atomic::Ordering::Relaxed) == 0,
        20,
    );
    assert_eq!(engine.proxies[1].stats[0].bytes_in.load(std::sync::atomic::Ordering::Relaxed), 0);

    // 4. Test direct engine API
    engine.proxies[1].stats[0].bytes_out.store(8888, std::sync::atomic::Ordering::Relaxed);
    assert!(engine.clear_counters(Some("test_backend")));
    assert_eq!(engine.proxies[1].stats[0].bytes_out.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert!(engine.clear_counters(None));
}

#[test]
fn test_health_check_enable_disable_web_and_cli() {
    let socket_path = PathBuf::from(format!(
        "/tmp/ibex_test_health_toggle_{}.sock",
        std::process::id()
    ));
    let proxy_addr = common::reserve_addr();
    let config = Config {
        listens: vec![ListenSection {
            name: "chk_proxy".into(),
            addr: proxy_addr,
            mode: Mode::Http,
            servers: vec![Server {
                id: "srv1".into(),
                addr: common::reserve_addr(),
                check: true,
                inter: Some(Duration::from_millis(50)),
                ..Default::default()
            }],
            stats: StatsConfig {
                enable: true,
                uri: Some("/stats".into()),
                admin: true,
                ..Default::default()
            },
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("engine");
    engine.bind_cli_socket(&socket_path).expect("bind cli");

    assert_eq!(engine.checks.len(), 1);
    assert!(engine.checks[0].enabled, "check should initially be enabled");

    // 1. Disable health check via Web Admin
    let post_disable = b"POST /stats HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 48\r\n\r\naction=disable_health&backend=chk_proxy&server=srv1";
    let resp = send_http_request(proxy_addr, &mut engine, post_disable);
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "Got: {resp}");
    assert!(!engine.checks[0].enabled, "check should now be disabled");

    // Step engine: verify server_status is NOT modified by health checks while disabled
    engine.proxies[0].server_statuses[0].store(ServerStatus::Maint as u8, std::sync::atomic::Ordering::Relaxed);
    for _ in 0..5 {
        let _ = engine.run_once();
    }
    assert_eq!(
        engine.proxies[0].server_statuses[0].load(std::sync::atomic::Ordering::Relaxed), ServerStatus::Maint as u8,
        "administrative status must be preserved while health check is disabled"
    );

    // 2. Enable health check via Web Admin
    let post_enable = b"POST /stats HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 47\r\n\r\naction=enable_health&backend=chk_proxy&server=srv1";
    let resp2 = send_http_request(proxy_addr, &mut engine, post_enable);
    assert!(resp2.starts_with("HTTP/1.1 200 OK\r\n"), "Got: {resp2}");
    assert!(engine.checks[0].enabled, "check should now be re-enabled");

    // 3. CLI socket command: disable health / enable health
    let mut client = UnixStream::connect(&socket_path).expect("connect cli");
    client.set_nonblocking(true).expect("nonblocking");
    engine.step(Tick(100)).expect("step");

    client.write_all(b"disable health chk_proxy/srv1\n").expect("write");
    step_engine_until(
        &mut engine,
        |eng| !eng.checks[0].enabled,
        20,
    );
    assert!(!engine.checks[0].enabled);

    let mut client2 = UnixStream::connect(&socket_path).expect("connect cli 2");
    client2.set_nonblocking(true).expect("nonblocking");
    engine.step(Tick(110)).expect("step");

    client2.write_all(b"enable health chk_proxy/srv1\n").expect("write");
    step_engine_until(
        &mut engine,
        |eng| eng.checks[0].enabled,
        20,
    );
    assert!(engine.checks[0].enabled);

    // 4. Test direct engine API
    assert!(engine.disable_health("chk_proxy", "srv1"));
    assert!(!engine.checks[0].enabled);
    assert!(engine.enable_health("chk_proxy", "srv1"));
    assert!(engine.checks[0].enabled);
}

#[test]
fn test_maxconn_tuning_web_and_cli() {
    let socket_path = PathBuf::from(format!(
        "/tmp/ibex_test_maxconn_tuning_{}.sock",
        std::process::id()
    ));
    let proxy_addr = common::reserve_addr();
    let config = Config {
        listens: vec![ListenSection {
            name: "maxconn_proxy".into(),
            addr: proxy_addr,
            mode: Mode::Http,
            servers: vec![Server {
                id: "srv1".into(),
                addr: common::reserve_addr(),
                maxconn: Some(10),
                ..Default::default()
            }],
            stats: StatsConfig {
                enable: true,
                uri: Some("/stats".into()),
                admin: true,
                ..Default::default()
            },
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("engine");
    engine.bind_cli_socket(&socket_path).expect("bind cli");

    assert_eq!(engine.proxies[0].server_maxconn[0], Some(10));

    // 1. Set server maxconn via Web Admin
    let post_req = b"POST /stats HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 52\r\n\r\naction=maxconn&backend=maxconn_proxy&server=srv1&maxconn=42";
    let resp = send_http_request(proxy_addr, &mut engine, post_req);
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "Got: {resp}");
    assert_eq!(engine.proxies[0].server_maxconn[0], Some(42));

    // 2. Set proxy maxconn via Web Admin
    let post_req2 = b"POST /stats HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 43\r\n\r\naction=maxconn&backend=maxconn_proxy&maxconn=999";
    let resp2 = send_http_request(proxy_addr, &mut engine, post_req2);
    assert!(resp2.starts_with("HTTP/1.1 200 OK\r\n"), "Got: {resp2}");
    assert_eq!(engine.proxies[0].maxconn, 999);

    // 3. Set server maxconn via CLI socket
    let mut client = UnixStream::connect(&socket_path).expect("connect cli");
    client.set_nonblocking(true).expect("nonblocking");
    engine.step(Tick(100)).expect("step");

    client
        .write_all(b"set maxconn server maxconn_proxy/srv1 75\n")
        .expect("write");
    step_engine_until(
        &mut engine,
        |eng| eng.proxies[0].server_maxconn[0] == Some(75),
        20,
    );
    assert_eq!(engine.proxies[0].server_maxconn[0], Some(75));

    // 4. Set backend maxconn via CLI socket
    let mut client2 = UnixStream::connect(&socket_path).expect("connect cli 2");
    client2.set_nonblocking(true).expect("nonblocking");
    engine.step(Tick(110)).expect("step");

    client2
        .write_all(b"set maxconn backend maxconn_proxy 1200\n")
        .expect("write");
    step_engine_until(
        &mut engine,
        |eng| eng.proxies[0].maxconn == 1200,
        20,
    );
    assert_eq!(engine.proxies[0].maxconn, 1200);

    // 5. Test direct engine API
    assert!(engine.set_maxconn("maxconn_proxy", Some("srv1"), 88));
    assert_eq!(engine.proxies[0].server_maxconn[0], Some(88));
    assert!(engine.set_maxconn("maxconn_proxy", None, 2000));
    assert_eq!(engine.proxies[0].maxconn, 2000);
}

#[test]
fn test_html_dashboard_and_json_render_controls() {
    let proxy_addr = common::reserve_addr();
    let config = Config {
        listens: vec![ListenSection {
            name: "web_admin".into(),
            addr: proxy_addr,
            mode: Mode::Http,
            servers: vec![Server {
                id: "srv1".into(),
                addr: common::reserve_addr(),
                weight: Some(10),
                maxconn: Some(50),
                check: true,
                ..Default::default()
            }],
            stats: StatsConfig {
                enable: true,
                uri: Some("/stats".into()),
                admin: true,
                ..Default::default()
            },
            ..Default::default()
        }],
        ..Default::default()
    };

    let engine = Engine::new(&config, 64).expect("engine");
    let html = render_stats_html(&engine.proxies, &engine.checks, 1234);

    // Verify UI buttons and forms
    assert!(html.contains("Clear Counters"), "HTML should have Clear Counters button");
    assert!(html.contains("Kill Sessions"), "HTML should have Kill Sessions backend button");
    assert!(html.contains("KILL"), "HTML should have server KILL button");
    assert!(html.contains("maxconn-input"), "HTML should have maxconn input form");
    assert!(html.contains("Pause") || html.contains("btn-pause"), "HTML should have health toggle button");

    // Verify JSON rendering
    let json = render_stats_json(&engine.proxies, &engine.checks, 1234);
    assert!(json.contains("\"maxconn\":50"), "JSON should report server maxconn");
    assert!(json.contains("\"check_enabled\":true"), "JSON should report health check enabled state");
}
