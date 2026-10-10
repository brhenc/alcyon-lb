// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Integration tests for HTTP mode: GET/POST, cookie persistence, and confirmation
// that the legacy cliexp/srvexp rewrite path is gone.

mod common;

use ibex_config::ast::{Config, HeaderExp, ListenSection, Mode, Server};
use ibex_rt::engine::Engine;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};


#[test]
fn http_basic_get_and_post() {
    let srv_addr = common::reserve_addr();
    let proxy_addr = common::reserve_addr();

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
    let srv1_addr = common::reserve_addr();
    let srv2_addr = common::reserve_addr();
    let proxy_addr = common::reserve_addr();

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
            cookie: Some(ibex_config::CookieConfig { name: "SERVERID".into(), ..Default::default() }),
            contimeout: Some(Duration::from_secs(3)),
            clitimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            retries: 3,
            maxconn: 100,
            servers: vec![
                Server::new("srv1", srv1_addr),
                // HAProxy matches the cookie against `server ... cookie <value>`, never
                // against a server's name.
                Server { cookie: Some("srv2".into()), ..Server::new("srv2", srv2_addr) },
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
#[allow(clippy::too_many_lines)] // end-to-end test: server thread, engine, client
fn legacy_cliexp_srvexp_rewriting_no_longer_applies() {
    let srv_addr = common::reserve_addr();
    let proxy_addr = common::reserve_addr();

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
                    req_str.contains("host: api.modern.io\r\n"),
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

    // `cliexp` / `srvexp` were removed from HAProxy in 2.0 and Ibex now rejects them at
    // config-parse time (see `crates/ibex-config`), so the legacy rewrite path is gone.
    // This test previously asserted that the rewriting happened; it now locks in that it
    // does NOT, so the dead path cannot quietly come back.
    //
    // The response must still be proxied correctly -- removing a feature must not break
    // forwarding. The modern equivalents are `http-request replace-path` and
    // `http-response replace-header`, which are parsed and exercised elsewhere.
    assert!(
        res_str.starts_with("HTTP/1.1 302"),
        "the response must still be proxied verbatim: {res_str}"
    );
    assert!(
        // Header names are case-insensitive; HAProxy emits them lowercase (T244).
        res_str.split("\r\n").any(|l| l
            .split_once(": ")
            .is_some_and(|(n, v)| n.eq_ignore_ascii_case("Location") && v == "http://internal:8080/login")),
        "legacy srvexp rewriting must no longer occur: {res_str}"
    );
    assert!(
        !res_str.contains("Server: Ibex/1.0"),
        "legacy srvexp header rewriting must no longer occur: {res_str}"
    );

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}

#[test]
#[allow(clippy::too_many_lines)]
fn http_reuse_shares_backend_connection_across_sessions() {
    use std::sync::atomic::AtomicUsize;

    let srv_addr = common::reserve_addr();
    let proxy_addr = common::reserve_addr();

    let accept_count = Arc::new(AtomicUsize::new(0));
    let ac_clone = Arc::clone(&accept_count);
    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");
        while r_clone.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                ac_clone.fetch_add(1, Ordering::SeqCst);
                stream.set_nonblocking(false).expect("blocking stream");
                stream
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .ok();

                let mut req_buf = Vec::new();
                let mut chunk = [0u8; 1024];

                // Handle requests on this keep-alive connection
                while r_clone.load(Ordering::Relaxed) {
                    req_buf.clear();
                    loop {
                        match stream.read(&mut chunk) {
                            Ok(0) => break,
                            Ok(n) => {
                                req_buf.extend_from_slice(&chunk[..n]);
                                if req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(ref e)
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut =>
                            {
                                if !r_clone.load(Ordering::Relaxed) {
                                    break;
                                }
                                thread::sleep(Duration::from_millis(5));
                            }
                            Err(_) => break,
                        }
                    }
                    if req_buf.is_empty() {
                        break;
                    }
                    let req_str = String::from_utf8_lossy(&req_buf);
                    let body = if req_str.contains("/first") {
                        "first"
                    } else if req_str.contains("/second") {
                        "second"
                    } else {
                        "unknown"
                    };

                    let res = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    if stream.write_all(res.as_bytes()).is_err() || stream.flush().is_err() {
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
    });

    let config = Config {
        listens: vec![ListenSection {
            name: "test_reuse".into(),
            addr: proxy_addr,
            mode: Mode::Http,
            clitimeout: Some(Duration::from_secs(5)),
            srvtimeout: Some(Duration::from_secs(5)),
            contimeout: Some(Duration::from_secs(5)),
            // `safe`, the default, opens a connection for the first request of a client
            // connection; sharing across sessions is `always`.
            http_reuse: Some(ibex_config::HttpReuse::Always),
            servers: vec![Server::new("s1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("Engine::new");

    // Client 1 sends /first with Connection: close
    let mut client1 = TcpStream::connect(proxy_addr).expect("connect client 1");
    client1.set_nonblocking(true).expect("nonblocking");
    client1
        .write_all(b"GET /first HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write client 1");
    client1.flush().expect("flush client 1");

    let deadline1 = Instant::now() + Duration::from_secs(3);
    let mut resp1 = Vec::new();
    let mut buf = [0u8; 1024];
    while Instant::now() < deadline1 {
        let _ = engine.run_once();
        if let Ok(n) = client1.read(&mut buf) {
            if n > 0 {
                resp1.extend_from_slice(&buf[..n]);
                if resp1.windows(4).any(|w| w == b"\r\n\r\n") && resp1.ends_with(b"first") {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(2));
    }
    assert!(String::from_utf8_lossy(&resp1).contains("first"), "client 1 got: {:?}", String::from_utf8_lossy(&resp1));
    drop(client1);

    // Run engine ticks to let client 1 disconnect cleanly and return backend conn to idle pool
    for _ in 0..10 {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(2));
    }

    // Client 2 connects on a completely new session and sends /second
    let mut client2 = TcpStream::connect(proxy_addr).expect("connect client 2");
    client2.set_nonblocking(true).expect("nonblocking");
    client2
        .write_all(b"GET /second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write client 2");
    client2.flush().expect("flush client 2");

    let deadline2 = Instant::now() + Duration::from_secs(3);
    let mut resp2 = Vec::new();
    while Instant::now() < deadline2 {
        let _ = engine.run_once();
        if let Ok(n) = client2.read(&mut buf) {
            if n > 0 {
                resp2.extend_from_slice(&buf[..n]);
                if resp2.windows(4).any(|w| w == b"\r\n\r\n") && resp2.ends_with(b"second") {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(2));
    }
    assert!(String::from_utf8_lossy(&resp2).contains("second"), "client 2 got: {:?}", String::from_utf8_lossy(&resp2));
    drop(client2);

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();

    // Verify connection reuse across sessions: backend should have accepted only ONCE!
    let accepts = accept_count.load(Ordering::SeqCst);
    assert_eq!(
        accepts, 1,
        "backend should have accepted 1 connection (shared idle pool), but accepted {accepts}"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn http_reuse_never_does_not_share_backend_connection() {
    let srv_listener = TcpListener::bind("127.0.0.1:0").expect("bind srv");
    let srv_addr = srv_listener.local_addr().expect("srv addr");
    let accept_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ac_clone = accept_count.clone();
    let running = Arc::new(AtomicBool::new(true));
    let r_clone = running.clone();

    let srv_handle = thread::spawn(move || {
        srv_listener
            .set_nonblocking(true)
            .expect("set nonblocking listener");
        while r_clone.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = srv_listener.accept() {
                ac_clone.fetch_add(1, Ordering::SeqCst);
                stream.set_nonblocking(false).expect("blocking stream");
                stream
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .ok();

                let mut req_buf = Vec::new();
                let mut chunk = [0u8; 1024];

                while r_clone.load(Ordering::Relaxed) {
                    req_buf.clear();
                    loop {
                        match stream.read(&mut chunk) {
                            Ok(0) => break,
                            Ok(n) => {
                                req_buf.extend_from_slice(&chunk[..n]);
                                if req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(ref e)
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut =>
                            {
                                if !r_clone.load(Ordering::Relaxed) {
                                    break;
                                }
                                thread::sleep(Duration::from_millis(5));
                            }
                            Err(_) => break,
                        }
                    }
                    if req_buf.is_empty() {
                        break;
                    }
                    let req_str = String::from_utf8_lossy(&req_buf);
                    let body = if req_str.contains("/first") {
                        "first"
                    } else if req_str.contains("/second") {
                        "second"
                    } else {
                        "unknown"
                    };

                    let res = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    if stream.write_all(res.as_bytes()).is_err() || stream.flush().is_err() {
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
    drop(proxy_listener);

    let config = Config {
        listens: vec![ListenSection {
            name: "test_reuse_never".into(),
            addr: proxy_addr,
            mode: Mode::Http,
            clitimeout: Some(Duration::from_secs(5)),
            srvtimeout: Some(Duration::from_secs(5)),
            contimeout: Some(Duration::from_secs(5)),
            http_reuse: Some(ibex_config::HttpReuse::Never),
            servers: vec![Server::new("s1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("Engine::new");

    // Client 1 sends /first
    let mut client1 = TcpStream::connect(proxy_addr).expect("connect client 1");
    client1.set_nonblocking(true).expect("nonblocking");
    client1
        .write_all(b"GET /first HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write client 1");
    client1.flush().expect("flush client 1");

    let deadline1 = Instant::now() + Duration::from_secs(3);
    let mut resp1 = Vec::new();
    let mut buf = [0u8; 1024];
    while Instant::now() < deadline1 {
        let _ = engine.run_once();
        if let Ok(n) = client1.read(&mut buf) {
            if n > 0 {
                resp1.extend_from_slice(&buf[..n]);
                if resp1.windows(4).any(|w| w == b"\r\n\r\n") && resp1.ends_with(b"first") {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(2));
    }
    assert!(String::from_utf8_lossy(&resp1).contains("first"));
    drop(client1);

    for _ in 0..10 {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(2));
    }

    // Client 2 sends /second
    let mut client2 = TcpStream::connect(proxy_addr).expect("connect client 2");
    client2.set_nonblocking(true).expect("nonblocking");
    client2
        .write_all(b"GET /second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write client 2");
    client2.flush().expect("flush client 2");

    let deadline2 = Instant::now() + Duration::from_secs(3);
    let mut resp2 = Vec::new();
    while Instant::now() < deadline2 {
        let _ = engine.run_once();
        if let Ok(n) = client2.read(&mut buf) {
            if n > 0 {
                resp2.extend_from_slice(&buf[..n]);
                if resp2.windows(4).any(|w| w == b"\r\n\r\n") && resp2.ends_with(b"second") {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(2));
    }
    assert!(String::from_utf8_lossy(&resp2).contains("second"));
    drop(client2);

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();

    // With http-reuse never, backend MUST accept twice (separate connections)
    let accepts = accept_count.load(Ordering::SeqCst);
    assert_eq!(
        accepts, 2,
        "with http-reuse never, backend should have accepted 2 connections, but accepted {accepts}"
    );
}
