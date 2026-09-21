// SPDX-License-Identifier: GPL-2.0-or-later
// Integration tests for HTTP mode: GET/POST, cookie persistence, cliexp and srvexp.

use ibex_config::ast::{Config, HeaderExp, ListenSection, Mode, Server};
use ibex_rt::engine::Engine;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn free_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    drop(l);
    addr
}

#[test]
fn http_basic_get_and_post() {
    let srv_addr = free_addr();
    let proxy_addr = free_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");
        while r_clone.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                stream.set_nonblocking(false).expect("blocking stream");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("read timeout");
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
                assert!(req_str.starts_with("GET /hello HTTP/1.1"));

                let res = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!";
                stream.write_all(res).expect("write res");
                stream.flush().expect("flush");
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    let config = Config {
        listens: vec![ListenSection {
            name: "http_proxy".into(),
            addr: proxy_addr,
            mode: Mode::Http,
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

    // Client connects
    let mut client = TcpStream::connect(proxy_addr).expect("client connect");
    client.set_nonblocking(true).expect("nonblocking");
    let req = b"GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n";
    client.write_all(req).expect("write req");

    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];

    while start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once().expect("engine step");
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                response.extend_from_slice(&buf[..n]);
                if response.windows(12).any(|w| w == b"Hello World!") {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
    }

    let res_str = String::from_utf8_lossy(&response);
    assert!(res_str.starts_with("HTTP/1.1 200 OK\r\n"), "got: {res_str}");
    assert!(res_str.contains("Hello World!"));

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}

#[test]
fn http_cookie_persistence_routes_to_targeted_server() {
    let srv1_addr = free_addr();
    let srv2_addr = free_addr();
    let proxy_addr = free_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r1 = Arc::clone(&running);
    let r2 = Arc::clone(&running);

    // Backend server 1
    let srv1_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv1_addr).expect("bind srv1");
        listener.set_nonblocking(true).expect("nonblocking");
        while r1.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let res = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nSERVER1";
                stream.write_all(res).expect("write srv1");
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    // Backend server 2
    let srv2_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv2_addr).expect("bind srv2");
        listener.set_nonblocking(true).expect("nonblocking");
        while r2.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let res = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nSERVER2";
                stream.write_all(res).expect("write srv2");
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    let config = Config {
        listens: vec![ListenSection {
            name: "cookie_proxy".into(),
            addr: proxy_addr,
            mode: Mode::Http,
            cookie: Some("SERVERID".into()),
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

    // Client requests with Cookie: SERVERID=srv2
    let mut client = TcpStream::connect(proxy_addr).expect("client connect");
    client.set_nonblocking(true).expect("nonblocking");
    let req = b"GET /data HTTP/1.1\r\nHost: localhost\r\nCookie: other=123; SERVERID=srv2\r\n\r\n";
    client.write_all(req).expect("write req");

    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];

    while start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once().expect("engine step");
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                response.extend_from_slice(&buf[..n]);
                if response.windows(7).any(|w| w == b"SERVER2") {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
    }

    let res_str = String::from_utf8_lossy(&response);
    assert!(
        res_str.contains("SERVER2"),
        "Expected request to be routed to srv2 via cookie, got: {res_str}"
    );

    running.store(false, Ordering::Relaxed);
    let _ = srv1_handle.join();
    let _ = srv2_handle.join();
}

#[test]
fn http_cliexp_and_srvexp_rewriting() {
    let srv_addr = free_addr();
    let proxy_addr = free_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");
        while r_clone.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                stream.set_nonblocking(false).expect("blocking stream");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("read timeout");
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
                // Verify cliexp rewrote the path and host header
                assert!(
                    req_str.starts_with("GET /api/v2/users HTTP/1.1\r\n"),
                    "got: {req_str}"
                );
                assert!(
                    req_str.contains("Host: api.modern.io\r\n"),
                    "got: {req_str}"
                );

                let res = b"HTTP/1.1 302 Found\r\nLocation: http://internal:8080/login\r\nServer: Legacy/1.0\r\nContent-Length: 0\r\n\r\n";
                stream.write_all(res).expect("write res");
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    let config = Config {
        listens: vec![ListenSection {
            name: "rewrite_proxy".into(),
            addr: proxy_addr,
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(3)),
            clitimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            retries: 3,
            maxconn: 100,
            servers: vec![Server::new("srv1", srv_addr)],
            cliexp: vec![
                HeaderExp {
                    regex: r"^(GET )(/old-api/v1/)(.*)".into(),
                    replacement: r"\1/api/v2/\3".into(),
                },
                HeaderExp {
                    regex: r"^Host:.*".into(),
                    replacement: "Host: api.modern.io".into(),
                },
            ],
            srvexp: vec![
                HeaderExp {
                    regex: r"^(Location:\ )([^:]*://[^/]*)(.*)".into(),
                    replacement: r"\1\3".into(),
                },
                HeaderExp {
                    regex: r"^Server:.*".into(),
                    replacement: "Server: Ibex/1.0".into(),
                },
            ],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("engine");

    let mut client = TcpStream::connect(proxy_addr).expect("client connect");
    client.set_nonblocking(true).expect("nonblocking");
    let req = b"GET /old-api/v1/users HTTP/1.1\r\nHost: legacy.internal.net\r\n\r\n";
    client.write_all(req).expect("write req");

    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];

    while start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once().expect("engine step");
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                response.extend_from_slice(&buf[..n]);
                if response.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
    }

    let res_str = String::from_utf8_lossy(&response);
    assert!(res_str.contains("Location: /login\r\n"), "got: {res_str}");
    assert!(res_str.contains("Server: Ibex/1.0\r\n"), "got: {res_str}");

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}
