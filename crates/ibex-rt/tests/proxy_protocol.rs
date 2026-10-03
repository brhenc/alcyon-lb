// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Integration and End-to-End tests for PROXY protocol (v1 & v2) support in Project Ibex.

mod common;

use ibex_config::ast::{BalanceAlgorithm, Config, ListenSection, Mode, Server};
use ibex_proto::{
    parse_proxy_header, update_crc32c_in_buffer, ProxyCommand, ProxyHeader, ProxyTransport,
    ProxyVersion, TlvBuilder,
};
use ibex_rt::engine::Engine;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};


#[test]
fn test_frontend_accept_proxy_v1_http() {
    let srv_addr = common::reserve_addr();
    let proxy_addr = common::reserve_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");
        while r_clone.load(Ordering::Relaxed) {
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
                let req_str = String::from_utf8_lossy(&req);
                // Downstream handler must ONLY receive clean HTTP payload; PROXY header must be stripped
                assert!(
                    req_str.starts_with("GET /hello HTTP/1.1\r\n"),
                    "Expected clean HTTP request, got: {req_str}"
                );
                assert!(!req_str.contains("PROXY TCP4"));

                let res = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello Client";
                stream.write_all(res).expect("write res");
                stream.flush().expect("flush");
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    let config = Config {
        listens: vec![ListenSection {
            name: "proxy_v1_http_in".into(),
            addr: proxy_addr,
            mode: Mode::Http,
            accept_proxy: true,
            contimeout: Some(Duration::from_secs(3)),
            clitimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            retries: 3,
            maxconn: 100,
            servers: vec![Server::new("srv1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("engine");

    let mut client = TcpStream::connect(proxy_addr).expect("client connect");
    client.set_nonblocking(true).expect("nonblocking");

    // Send PROXY v1 text header followed by HTTP GET request
    let mut payload = Vec::new();
    payload.extend_from_slice(b"PROXY TCP4 203.0.113.195 198.51.100.1 56324 80\r\n");
    payload.extend_from_slice(b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n");
    client.write_all(&payload).expect("write client payload");

    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];

    while start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once().expect("engine step");
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                response.extend_from_slice(&buf[..n]);
                if response.windows(12).any(|w| w == b"Hello Client") {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
    }

    let res_str = String::from_utf8_lossy(&response);
    assert!(res_str.contains("Hello Client"), "got: {res_str}");

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}

#[test]
fn test_frontend_accept_proxy_v2_tcp() {
    let srv_addr = common::reserve_addr();
    let proxy_addr = common::reserve_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");
        while r_clone.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if req.windows(9).any(|w| w == b"PING_TEST") {
                        break;
                    }
                }
                assert_eq!(
                    &req, b"PING_TEST",
                    "Backend must only see application payload"
                );

                stream.write_all(b"PONG_TEST").expect("write pong");
                stream.flush().expect("flush");
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    let config = Config {
        listens: vec![ListenSection {
            name: "proxy_v2_tcp_in".into(),
            addr: proxy_addr,
            mode: Mode::Tcp,
            accept_proxy: true,
            contimeout: Some(Duration::from_secs(3)),
            clitimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            retries: 3,
            maxconn: 100,
            servers: vec![Server::new("srv1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("engine");

    let mut client = TcpStream::connect(proxy_addr).expect("client connect");
    client.set_nonblocking(true).expect("nonblocking");

    // Construct PROXY v2 header with IPv4 endpoints and ALPN TLV
    let mut tlv_buf = [0u8; 64];
    let mut builder = TlvBuilder::new(&mut tlv_buf);
    builder.append_alpn(b"h2").unwrap();
    let tlv_slice = builder.into_slice();

    let hdr_v2 = ProxyHeader::new_v2_ipv4(
        ProxyCommand::Proxy,
        ProxyTransport::Stream,
        Ipv4Addr::new(192, 168, 10, 5),
        Ipv4Addr::new(10, 0, 0, 1),
        44123,
        80,
        tlv_slice,
    );

    let mut out_hdr = [0u8; 128];
    let hdr_len = hdr_v2.encode(&mut out_hdr).expect("encode v2");

    let mut payload = Vec::new();
    payload.extend_from_slice(&out_hdr[..hdr_len]);
    payload.extend_from_slice(b"PING_TEST");

    client.write_all(&payload).expect("write client payload");

    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];

    while start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once().expect("engine step");
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                response.extend_from_slice(&buf[..n]);
                if response == b"PONG_TEST" {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
    }

    assert_eq!(&response, b"PONG_TEST");

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}

#[test]
fn test_frontend_accept_proxy_v2_strict_rejects_v1() {
    let srv_addr = common::reserve_addr();
    let proxy_addr = common::reserve_addr();

    let config = Config {
        listens: vec![ListenSection {
            name: "strict_v2_in".into(),
            addr: proxy_addr,
            mode: Mode::Tcp,
            accept_proxy_v2: true, // Only v2 allowed
            contimeout: Some(Duration::from_secs(3)),
            clitimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            retries: 3,
            maxconn: 100,
            servers: vec![Server::new("srv1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("engine");

    let mut client = TcpStream::connect(proxy_addr).expect("client connect");
    client.set_nonblocking(true).expect("nonblocking");

    // Send PROXY v1 text header to a port configured with accept-proxy-v2
    let payload = b"PROXY TCP4 203.0.113.195 198.51.100.1 56324 80\r\nDATA";
    client.write_all(payload).expect("write client payload");

    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(500) {
        let _ = engine.run_once().expect("engine step");
        thread::sleep(Duration::from_millis(5));
    }

    // Attempting to read from client should return EOF or closed socket
    let mut buf = [0u8; 64];
    match client.read(&mut buf) {
        Ok(0) | Err(_) => {
            // Success: connection was closed immediately by proxy
        }
        Ok(n) => panic!("Expected connection closed, but received {n} bytes"),
    }
}

#[test]
fn test_frontend_rejects_malformed_proxy_header() {
    let srv_addr = common::reserve_addr();
    let proxy_addr = common::reserve_addr();

    let config = Config {
        listens: vec![ListenSection {
            name: "strict_proxy_in".into(),
            addr: proxy_addr,
            mode: Mode::Tcp,
            accept_proxy: true,
            contimeout: Some(Duration::from_secs(3)),
            clitimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            retries: 3,
            maxconn: 100,
            servers: vec![Server::new("srv1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("engine");

    let mut client = TcpStream::connect(proxy_addr).expect("client connect");
    client.set_nonblocking(true).expect("nonblocking");

    // Send invalid header without PROXY signature
    let payload = b"GET /admin/dashboard HTTP/1.1\r\nHost: attacker.com\r\n\r\n";
    client.write_all(payload).expect("write client payload");

    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(500) {
        let _ = engine.run_once().expect("engine step");
        thread::sleep(Duration::from_millis(5));
    }

    // Connection must be immediately terminated
    let mut buf = [0u8; 64];
    match client.read(&mut buf) {
        Ok(0) | Err(_) => {}
        Ok(n) => panic!("Expected connection closed, but received {n} bytes"),
    }
}

#[test]
fn test_backend_send_proxy_v1() {
    let srv_addr = common::reserve_addr();
    let proxy_addr = common::reserve_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");
        while r_clone.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if req.windows(4).any(|w| w == b"ECHO") {
                        break;
                    }
                }
                let (hdr, consumed) = parse_proxy_header(&req)
                    .expect("parse backend proxy header")
                    .expect("complete header");
                assert_eq!(hdr.version, ProxyVersion::V1);
                assert_eq!(hdr.command, ProxyCommand::Proxy);
                assert_eq!(&req[consumed..], b"ECHO");

                stream.write_all(b"ECHO_REPLY").expect("write reply");
                stream.flush().expect("flush");
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    let config = Config {
        listens: vec![ListenSection {
            name: "send_proxy_v1_proxy".into(),
            addr: proxy_addr,
            mode: Mode::Tcp,
            contimeout: Some(Duration::from_secs(3)),
            clitimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            retries: 3,
            maxconn: 100,
            servers: vec![Server {
                id: "srv1".into(),
                addr: srv_addr,
                send_proxy: true,
                send_proxy_v2: false,
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("engine");

    let mut client = TcpStream::connect(proxy_addr).expect("client connect");
    client.set_nonblocking(true).expect("nonblocking");
    client.write_all(b"ECHO").expect("write echo");

    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];

    while start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once().expect("engine step");
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                response.extend_from_slice(&buf[..n]);
                if response == b"ECHO_REPLY" {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
    }

    assert_eq!(&response, b"ECHO_REPLY");

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}

#[test]
fn test_backend_send_proxy_v2() {
    let srv_addr = common::reserve_addr();
    let proxy_addr = common::reserve_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");
        while r_clone.load(Ordering::Relaxed) {
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
                let (hdr, consumed) = parse_proxy_header(&req)
                    .expect("parse backend proxy header")
                    .expect("complete header");
                assert_eq!(hdr.version, ProxyVersion::V2);
                assert_eq!(hdr.command, ProxyCommand::Proxy);
                let app_payload = &req[consumed..];
                let payload_str = String::from_utf8_lossy(app_payload);
                assert!(payload_str.starts_with("GET /api HTTP/1.1\r\n"));

                let res = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nPASS";
                stream.write_all(res).expect("write reply");
                stream.flush().expect("flush");
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    let config = Config {
        listens: vec![ListenSection {
            name: "send_proxy_v2_proxy".into(),
            addr: proxy_addr,
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(3)),
            clitimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            retries: 3,
            maxconn: 100,
            servers: vec![Server {
                id: "srv1".into(),
                addr: srv_addr,
                send_proxy: false,
                send_proxy_v2: true,
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("engine");

    let mut client = TcpStream::connect(proxy_addr).expect("client connect");
    client.set_nonblocking(true).expect("nonblocking");
    client
        .write_all(b"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .expect("write req");

    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];

    while start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once().expect("engine step");
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                response.extend_from_slice(&buf[..n]);
                if response.windows(4).any(|w| w == b"PASS") {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
    }

    let res_str = String::from_utf8_lossy(&response);
    assert!(res_str.contains("PASS"), "got: {res_str}");

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}

#[test]
fn test_chained_proxy_protocol_e2e() {
    // Architecture:
    // Client -> Ibex 1 [accept-proxy, send-proxy-v2] -> Ibex 2 [accept-proxy] -> Backend Server
    let backend_addr = common::reserve_addr();
    let ibex2_addr = common::reserve_addr();
    let ibex1_addr = common::reserve_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(backend_addr).expect("bind backend");
        listener.set_nonblocking(true).expect("nonblocking");
        while r_clone.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if req.windows(12).any(|w| w == b"CHAINED_DATA") {
                        break;
                    }
                }
                assert_eq!(&req, b"CHAINED_DATA");

                stream
                    .write_all(b"CHAINED_RESPONSE_OK")
                    .expect("write response");
                stream.flush().expect("flush");
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    // Ibex 1 configuration: accepts PROXY (v1 or v2) on frontend, sends PROXY v2 to Ibex 2
    let config1 = Config {
        listens: vec![ListenSection {
            name: "ibex1".into(),
            addr: ibex1_addr,
            mode: Mode::Tcp,
            accept_proxy: true,
            contimeout: Some(Duration::from_secs(3)),
            clitimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            retries: 3,
            maxconn: 100,
            servers: vec![Server {
                id: "ibex2_node".into(),
                addr: ibex2_addr,
                send_proxy: false,
                send_proxy_v2: true,
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    // Ibex 2 configuration: accepts PROXY (v2) from Ibex 1, forwards payload to backend
    let config2 = Config {
        listens: vec![ListenSection {
            name: "ibex2".into(),
            addr: ibex2_addr,
            mode: Mode::Tcp,
            accept_proxy: true,
            contimeout: Some(Duration::from_secs(3)),
            clitimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            retries: 3,
            maxconn: 100,
            servers: vec![Server::new("backend_node", backend_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine1 = Engine::new(&config1, 64).expect("engine1");
    let mut engine2 = Engine::new(&config2, 64).expect("engine2");

    let mut client = TcpStream::connect(ibex1_addr).expect("client connect to ibex1");
    client.set_nonblocking(true).expect("nonblocking");

    // Client sends PROXY v1 header with spoofed/real client IP: 198.51.100.42:49152
    let mut client_req = Vec::new();
    client_req.extend_from_slice(b"PROXY TCP4 198.51.100.42 203.0.113.1 49152 443\r\n");
    client_req.extend_from_slice(b"CHAINED_DATA");
    client.write_all(&client_req).expect("write client req");

    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];

    while start.elapsed() < Duration::from_secs(3) {
        let _ = engine1.run_once().expect("engine1 step");
        let _ = engine2.run_once().expect("engine2 step");
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                response.extend_from_slice(&buf[..n]);
                if response == b"CHAINED_RESPONSE_OK" {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
    }

    assert_eq!(&response, b"CHAINED_RESPONSE_OK");

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}

#[test]
fn test_source_ip_hash_uses_real_client_ip_from_proxy_header() {
    let srv1_addr = common::reserve_addr();
    let srv2_addr = common::reserve_addr();
    let proxy_addr = common::reserve_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r1 = Arc::clone(&running);
    let r2 = Arc::clone(&running);

    let srv1_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv1_addr).expect("bind srv1");
        listener.set_nonblocking(true).expect("nonblocking");
        while r1.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 64];
                let _ = stream.read(&mut buf);
                stream.write_all(b"HIT_SRV1").expect("write srv1");
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    let srv2_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv2_addr).expect("bind srv2");
        listener.set_nonblocking(true).expect("nonblocking");
        while r2.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 64];
                let _ = stream.read(&mut buf);
                stream.write_all(b"HIT_SRV2").expect("write srv2");
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    let config = Config {
        listens: vec![ListenSection {
            name: "source_hash_proxy".into(),
            addr: proxy_addr,
            mode: Mode::Tcp,
            accept_proxy: true,
            balance: BalanceAlgorithm::Source,
            contimeout: Some(Duration::from_secs(3)),
            clitimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            retries: 3,
            maxconn: 100,
            servers: vec![
                Server::new("srv1", srv1_addr),
                Server::new("srv2", srv2_addr),
            ],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("engine");

    let mut client = TcpStream::connect(proxy_addr).expect("client connect");
    client.set_nonblocking(true).expect("nonblocking");

    // Send PROXY header with IPv4: 10.0.0.1 (which has u32(10.0.0.1) % 2 = 1 -> srv2)
    // 10.0.0.1 as u32 big endian is 0x0A000001 (167772161), 167772161 % 2 = 1 (srv2)
    let payload = b"PROXY TCP4 10.0.0.1 192.168.1.1 50000 80\r\nREQ";
    client.write_all(payload).expect("write payload");

    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];

    while start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once().expect("engine step");
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                response.extend_from_slice(&buf[..n]);
                if !response.is_empty() {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
    }

    let res_str = String::from_utf8_lossy(&response);
    assert_eq!(
        res_str, "HIT_SRV2",
        "Should route to srv2 based on source hash of PROXY client IP"
    );

    running.store(false, Ordering::Relaxed);
    let _ = srv1_handle.join();
    let _ = srv2_handle.join();
}

#[test]
fn test_frontend_accept_proxy_fragmented_chunks() {
    let srv_addr = common::reserve_addr();
    let proxy_addr = common::reserve_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");
        while r_clone.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if req.windows(8).any(|w| w == b"COMPLETE") {
                        break;
                    }
                }
                assert_eq!(&req, b"COMPLETE");
                stream.write_all(b"FRAGMENT_OK").expect("write res");
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    let config = Config {
        listens: vec![ListenSection {
            name: "fragment_proxy".into(),
            addr: proxy_addr,
            mode: Mode::Tcp,
            accept_proxy: true,
            contimeout: Some(Duration::from_secs(3)),
            clitimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            retries: 3,
            maxconn: 100,
            servers: vec![Server::new("srv1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("engine");

    let mut client = TcpStream::connect(proxy_addr).expect("client connect");

    // Send PROXY header in 3 small fragmented chunks with pauses
    let chunk1 = b"PROXY TCP4 192.168.";
    let chunk2 = b"1.100 10.0.0.1 55443";
    let chunk3 = b" 80\r\nCOMPLETE";

    client.write_all(chunk1).expect("write chunk 1");
    let _ = engine.run_once();
    thread::sleep(Duration::from_millis(10));

    client.write_all(chunk2).expect("write chunk 2");
    let _ = engine.run_once();
    thread::sleep(Duration::from_millis(10));

    client.write_all(chunk3).expect("write chunk 3");

    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    client.set_nonblocking(true).expect("nonblocking");

    while start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once().expect("engine step");
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                response.extend_from_slice(&buf[..n]);
                if response == b"FRAGMENT_OK" {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
    }

    assert_eq!(&response, b"FRAGMENT_OK");

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}

#[test]
fn test_backend_send_proxy_v2_with_forwarded_tlvs() {
    let srv_addr = common::reserve_addr();
    let proxy_addr = common::reserve_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");
        while r_clone.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if req.windows(7).any(|w| w == b"PAYLOAD") {
                        break;
                    }
                }
                let (hdr, consumed) = parse_proxy_header(&req)
                    .expect("parse backend proxy header")
                    .expect("complete header");
                assert_eq!(hdr.version, ProxyVersion::V2);
                assert_eq!(hdr.alpn().unwrap().unwrap(), b"grpc-exp");
                assert_eq!(hdr.authority().unwrap().unwrap(), "service.internal");
                assert_eq!(&req[consumed..], b"PAYLOAD");

                stream.write_all(b"TLV_FORWARD_OK").expect("write response");
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    let config = Config {
        listens: vec![ListenSection {
            name: "tlv_forward_proxy".into(),
            addr: proxy_addr,
            mode: Mode::Tcp,
            accept_proxy: true,
            contimeout: Some(Duration::from_secs(3)),
            clitimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            retries: 3,
            maxconn: 100,
            servers: vec![Server {
                id: "srv1".into(),
                addr: srv_addr,
                send_proxy: false,
                send_proxy_v2: true,
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("engine");

    let mut client = TcpStream::connect(proxy_addr).expect("client connect");
    client.set_nonblocking(true).expect("nonblocking");

    let mut tlv_buf = [0u8; 128];
    let mut builder = TlvBuilder::new(&mut tlv_buf);
    builder.append_alpn(b"grpc-exp").unwrap();
    builder.append_authority("service.internal").unwrap();
    let tlv_slice = builder.into_slice();

    let hdr_v2 = ProxyHeader::new_v2_ipv4(
        ProxyCommand::Proxy,
        ProxyTransport::Stream,
        Ipv4Addr::new(172, 16, 0, 50),
        Ipv4Addr::new(10, 0, 0, 1),
        32100,
        443,
        tlv_slice,
    );

    let mut out_hdr = [0u8; 256];
    let hdr_len = hdr_v2.encode(&mut out_hdr).expect("encode");

    let mut payload = Vec::new();
    payload.extend_from_slice(&out_hdr[..hdr_len]);
    payload.extend_from_slice(b"PAYLOAD");

    client.write_all(&payload).expect("write payload");

    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];

    while start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once().expect("engine step");
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                response.extend_from_slice(&buf[..n]);
                if response == b"TLV_FORWARD_OK" {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
    }

    assert_eq!(&response, b"TLV_FORWARD_OK");

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}

#[test]
fn test_proxy_v2_crc32c_wire_validation() {
    let mut tlv_buf = [0u8; 64];
    let mut builder = TlvBuilder::new(&mut tlv_buf);
    builder.append_alpn(b"h2").unwrap();
    builder.append_crc32c_placeholder().unwrap();
    let tlv_slice = builder.into_slice();

    let hdr = ProxyHeader::new_v2_ipv4(
        ProxyCommand::Proxy,
        ProxyTransport::Stream,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(192, 0, 2, 2),
        12345,
        80,
        tlv_slice,
    );

    let mut wire_buf = [0u8; 128];
    let len = hdr.encode(&mut wire_buf).expect("encode");
    update_crc32c_in_buffer(&mut wire_buf[..len]).expect("update crc");

    // Parse valid buffer with CRC
    let (parsed, consumed) = parse_proxy_header(&wire_buf[..len])
        .expect("parse")
        .expect("complete");
    assert_eq!(consumed, len);
    assert!(parsed.crc32c().is_some());

    // Corrupt one byte of the payload
    wire_buf[16] ^= 0x55;
    let err = parse_proxy_header(&wire_buf[..len]).unwrap_err();
    match err {
        ibex_proto::ProxyParseError::CrcMismatch { .. } => {}
        other => panic!("expected CrcMismatch error, got {other:?}"),
    }
}
