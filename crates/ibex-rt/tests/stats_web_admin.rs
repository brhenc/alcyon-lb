// SPDX-License-Identifier: GPL-2.0-or-later
// Integration tests for Ibex Modern Stats Dashboard & Web Admin UI.
// Copyright (C) 2000-2026 Willy Tarreau and Ibex contributors. See LICENSE.

use ibex_config::ast::{Config, ListenSection, Mode, Server, StatsConfig};
use ibex_rt::{render_stats_html, Engine, ServerStatus};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

fn free_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    drop(l);
    addr
}

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

#[test]
fn test_render_stats_html_helper_and_status_badges() {
    let srv1_addr = free_addr();
    let srv2_addr = free_addr();
    let proxy_addr = free_addr();

    let config = Config {
        listens: vec![ListenSection {
            name: "test_proxy".into(),
            addr: proxy_addr,
            mode: Mode::Http,
            servers: vec![
                Server {
                    id: "srv1".into(),
                    addr: srv1_addr,
                    weight: Some(10),
                    ..Default::default()
                },
                Server {
                    id: "srv2".into(),
                    addr: srv2_addr,
                    weight: Some(20),
                    backup: true,
                    ..Default::default()
                },
            ],
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
    engine.proxies[0].server_statuses[0].store(ServerStatus::Up as u8, std::sync::atomic::Ordering::Relaxed);
    engine.proxies[0].server_statuses[1].store(ServerStatus::Drain as u8, std::sync::atomic::Ordering::Relaxed);

    let html = render_stats_html(&engine.proxies, &engine.checks, 4242);

    // Verify key UI components
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("IBEX"));
    assert!(html.contains("PID: 4242"));
    assert!(html.contains("Active Connections"));
    assert!(html.contains("Total Connections"));
    assert!(html.contains("Traffic In / Out"));
    assert!(html.contains("Frontends"));
    assert!(html.contains("Backends &amp; Servers"));
    assert!(html.contains("Stick Tables"));

    // Verify status badges
    assert!(html.contains("badge-up"));
    assert!(html.contains("badge-drain"));
    assert!(html.contains("badge-backup"));

    // Verify admin action buttons and form inputs
    assert!(html.contains("READY"));
    assert!(html.contains("DRAIN"));
    assert!(html.contains("MAINT"));
    assert!(html.contains("weight-input"));

    // Verify zero external CDN links
    assert!(!html.contains("http://"));
    assert!(!html.contains("https://"));
}

#[test]
fn test_stats_http_get_dashboard_and_csv() {
    let srv1_addr = free_addr();
    let proxy_addr = free_addr();

    let config = Config {
        listens: vec![ListenSection {
            name: "admin_proxy".into(),
            addr: proxy_addr,
            mode: Mode::Http,
            servers: vec![Server {
                id: "srv1".into(),
                addr: srv1_addr,
                weight: Some(15),
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

    // 1. GET /stats -> HTML Dashboard
    let get_req = b"GET /stats HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let resp = send_http_request(proxy_addr, &mut engine, get_req);

    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "Got: {resp}");
    assert!(resp.contains("Content-Type: text/html; charset=utf-8"));
    assert!(resp.contains("IBEX"));
    assert!(resp.contains("srv1"));
    assert!(resp.contains("badge-up"));

    // 2. GET /stats;csv -> CSV Telemetry
    let csv_req = b"GET /stats;csv HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let csv_resp = send_http_request(proxy_addr, &mut engine, csv_req);

    assert!(
        csv_resp.starts_with("HTTP/1.1 200 OK\r\n"),
        "Got: {csv_resp}"
    );
    assert!(csv_resp.contains("Content-Type: text/plain; charset=utf-8"));
    assert!(csv_resp.contains("# pxname,svname,qcur,qmax,scur"));
    assert!(csv_resp.contains("admin_proxy,FRONTEND"));
    assert!(csv_resp.contains("admin_proxy,srv1"));
    assert!(csv_resp.contains("admin_proxy,BACKEND"));

    // 3. GET /stats/api/data -> JSON Live Telemetry
    let api_req = b"GET /stats/api/data HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let api_resp = send_http_request(proxy_addr, &mut engine, api_req);

    assert!(
        api_resp.starts_with("HTTP/1.1 200 OK\r\n"),
        "Got: {api_resp}"
    );
    assert!(api_resp.contains("Content-Type: application/json; charset=utf-8"));
    assert!(api_resp.contains("\"totals\""));
    assert!(api_resp.contains("\"admin_proxy\""));
    assert!(api_resp.contains("\"srv1\""));
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_stats_server_state_and_weight_mutations() {
    let srv1_addr = free_addr();
    let proxy_addr = free_addr();

    let config = Config {
        listens: vec![ListenSection {
            name: "cluster_px".into(),
            addr: proxy_addr,
            mode: Mode::Http,
            servers: vec![Server {
                id: "web1".into(),
                addr: srv1_addr,
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

    // 1. Initial status is UP
    assert_eq!(engine.proxies[0].server_statuses[0].load(std::sync::atomic::Ordering::Relaxed), ServerStatus::Up as u8);
    assert_eq!(engine.proxies[0].server_weights[0], 10);

    // 2. Mutate state to DRAIN via POST
    let drain_body = "action=drain&backend=cluster_px&server=web1";
    let drain_req = format!(
        "POST /stats HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        drain_body.len(),
        drain_body
    );
    let drain_resp = send_http_request(proxy_addr, &mut engine, drain_req.as_bytes());
    assert!(
        drain_resp.starts_with("HTTP/1.1 200 OK\r\n"),
        "Got: {drain_resp}"
    );
    assert_eq!(engine.proxies[0].server_statuses[0].load(std::sync::atomic::Ordering::Relaxed), ServerStatus::Drain as u8);

    // GET /stats now shows DRAIN badge
    let get_drain = send_http_request(
        proxy_addr,
        &mut engine,
        b"GET /stats HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(get_drain.contains("badge-drain"));
    assert!(get_drain.contains("DRAIN"));

    // GET /stats;csv shows DRAIN in status column
    let csv_drain = send_http_request(
        proxy_addr,
        &mut engine,
        b"GET /stats;csv HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(csv_drain.contains(",DRAIN,"));

    // 3. Mutate state to MAINT via POST
    let maint_body = "action=maint&backend=cluster_px&server=web1";
    let maint_req = format!(
        "POST /stats HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        maint_body.len(),
        maint_body
    );
    let maint_resp = send_http_request(proxy_addr, &mut engine, maint_req.as_bytes());
    assert!(
        maint_resp.starts_with("HTTP/1.1 200 OK\r\n"),
        "Got: {maint_resp}"
    );
    assert_eq!(engine.proxies[0].server_statuses[0].load(std::sync::atomic::Ordering::Relaxed), ServerStatus::Maint as u8);

    // GET /stats shows MAINT badge
    let get_maint = send_http_request(
        proxy_addr,
        &mut engine,
        b"GET /stats HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(get_maint.contains("badge-maint"));
    assert!(get_maint.contains("MAINT"));

    // 4. Mutate state back to READY (UP) via query string in GET
    let ready_req = b"GET /stats?action=ready&backend=cluster_px&server=web1 HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let ready_resp = send_http_request(proxy_addr, &mut engine, ready_req);
    assert!(
        ready_resp.starts_with("HTTP/1.1 200 OK\r\n"),
        "Got: {ready_resp}"
    );
    assert_eq!(engine.proxies[0].server_statuses[0].load(std::sync::atomic::Ordering::Relaxed), ServerStatus::Up as u8);

    // 5. Adjust server weight
    let weight_body = "action=weight&backend=cluster_px&server=web1&weight=64";
    let weight_req = format!(
        "POST /stats HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        weight_body.len(),
        weight_body
    );
    let weight_resp = send_http_request(proxy_addr, &mut engine, weight_req.as_bytes());
    assert!(
        weight_resp.starts_with("HTTP/1.1 200 OK\r\n"),
        "Got: {weight_resp}"
    );
    assert_eq!(engine.proxies[0].server_weights[0], 64);

    // CSV shows new weight
    let csv_w = send_http_request(
        proxy_addr,
        &mut engine,
        b"GET /stats;csv HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(csv_w.contains(",64,"));
}

#[test]
fn test_stats_custom_uri_admin_stats() {
    let srv_addr = free_addr();
    let proxy_addr = free_addr();

    let config = Config {
        listens: vec![ListenSection {
            name: "admin_custom".into(),
            addr: proxy_addr,
            mode: Mode::Http,
            servers: vec![Server {
                id: "srv_cust".into(),
                addr: srv_addr,
                weight: Some(25),
                ..Default::default()
            }],
            stats: StatsConfig {
                enable: true,
                uri: Some("/admin?stats".into()),
                admin: true,
                ..Default::default()
            },
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("engine");

    // 1. GET /admin?stats -> HTML Dashboard
    let get_req = b"GET /admin?stats HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let resp = send_http_request(proxy_addr, &mut engine, get_req);
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "Got: {resp}");
    assert!(resp.contains("IBEX"));
    assert!(resp.contains("srv_cust"));

    // 2. GET /admin?stats;csv -> CSV
    let csv_req = b"GET /admin?stats;csv HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let csv_resp = send_http_request(proxy_addr, &mut engine, csv_req);
    assert!(
        csv_resp.starts_with("HTTP/1.1 200 OK\r\n"),
        "Got: {csv_resp}"
    );
    assert!(csv_resp.contains("admin_custom,srv_cust"));

    // 3. Mutate server state via /admin?stats query string
    let drain_req = b"GET /admin?stats&action=drain&backend=admin_custom&server=srv_cust HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let drain_resp = send_http_request(proxy_addr, &mut engine, drain_req);
    assert!(
        drain_resp.starts_with("HTTP/1.1 200 OK\r\n"),
        "Got: {drain_resp}"
    );
    assert_eq!(engine.proxies[0].server_statuses[0].load(std::sync::atomic::Ordering::Relaxed), ServerStatus::Drain as u8);
}
