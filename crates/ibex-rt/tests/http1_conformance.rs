// SPDX-License-Identifier: GPL-2.0-or-later
// Ibex Runtime HTTP/1.1 Conformance & Stress Test Harness

#![forbid(unsafe_code)]
#![allow(
    clippy::too_many_lines,
    clippy::uninlined_format_args,
    clippy::useless_vec
)]

use ibex_config::ast::{Config, ListenSection, Mode, Server};
use ibex_rt::engine::Engine;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn free_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind free addr");
    let addr = l.local_addr().expect("local addr");
    drop(l);
    addr
}

fn create_test_engine(proxy_addr: SocketAddr, srv_addr: SocketAddr) -> Engine {
    let config = Config {
        listens: vec![ListenSection {
            name: "http_conformance".into(),
            addr: proxy_addr,
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(5)),
            clitimeout: Some(Duration::from_secs(5)),
            srvtimeout: Some(Duration::from_secs(5)),
            retries: 3,
            maxconn: 500,
            servers: vec![Server::new("srv1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    Engine::new(&config, 256).expect("init engine")
}

// ============================================================================
// 1. Chunked Transfer Encoding E2E (Varying Chunks & Trailers)
// ============================================================================

#[test]
fn test_rt_chunked_transfer_encoding() {
    let srv_addr = free_addr();
    let proxy_addr = free_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_srv = Arc::clone(&running);

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");

        while r_srv.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                stream.set_nonblocking(false).expect("blocking");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("timeout");

                let mut req = Vec::new();
                let mut buf = [0u8; 1024];

                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if req.windows(5).any(|w| w == b"0\r\n\r\n")
                        || req.windows(4).filter(|w| *w == b"\r\n\r\n").count() >= 2
                    {
                        break;
                    }
                }

                let req_str = String::from_utf8_lossy(&req);
                assert!(req_str.starts_with("POST /chunked-endpoint HTTP/1.1\r\n"));
                assert!(req_str.contains("Transfer-Encoding: chunked"));
                assert!(req_str.contains("Hello"));
                assert!(req_str.contains("World"));
                assert!(req_str.contains("-from-Ibex-Chunked-Test"));
                assert!(req_str.contains("X-Trailer-Check: client_trailer_ok"));

                // Reply with chunked response and response trailer
                let resp = b"HTTP/1.1 200 OK\r\n\
                             Transfer-Encoding: chunked\r\n\
                             Trailer: X-Server-Trailer\r\n\
                             \r\n\
                             5\r\n\
                             Chunk\r\n\
                             7\r\n\
                             -Server\r\n\
                             0\r\n\
                             X-Server-Trailer: srv_trailer_ok\r\n\
                             \r\n";
                stream.write_all(resp).expect("write resp");
                stream.flush().expect("flush resp");
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
    });

    let mut engine = create_test_engine(proxy_addr, srv_addr);

    // Client connects to proxy and writes chunked request with varying chunks and trailers
    let mut client = TcpStream::connect(proxy_addr).expect("client connect");
    client.set_nonblocking(true).expect("nonblocking");

    let chunked_req = b"POST /chunked-endpoint HTTP/1.1\r\n\
                        Host: localhost\r\n\
                        Transfer-Encoding: chunked\r\n\
                        Trailer: X-Trailer-Check\r\n\
                        \r\n\
                        5\r\n\
                        Hello\r\n\
                        1\r\n\
                        -\r\n\
                        5\r\n\
                        World\r\n\
                        17\r\n\
                        -from-Ibex-Chunked-Test\r\n\
                        0\r\n\
                        X-Trailer-Check: client_trailer_ok\r\n\
                        \r\n";

    client.write_all(chunked_req).expect("client write");

    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];

    while start.elapsed() < Duration::from_secs(3) {
        let _ = engine.run_once().expect("engine step");
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                response.extend_from_slice(&buf[..n]);
                if response.windows(5).any(|w| w == b"0\r\n\r\n")
                    || response.windows(4).filter(|w| *w == b"\r\n\r\n").count() >= 2
                {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(1));
    }

    let resp_str = String::from_utf8_lossy(&response);
    assert!(
        resp_str.starts_with("HTTP/1.1 200 OK\r\n"),
        "got: {resp_str}"
    );
    assert!(resp_str.contains("Chunk"), "got: {resp_str}");
    assert!(resp_str.contains("-Server"), "got: {resp_str}");
    assert!(
        resp_str.contains("X-Server-Trailer: srv_trailer_ok"),
        "got: {resp_str}"
    );

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}

// ============================================================================
// 2. HTTP Keep-Alive & Connection Reuse (50+ Sequential Requests)
// ============================================================================

#[test]
fn test_rt_keep_alive_50_plus_sequential_requests() {
    let srv_addr = free_addr();
    let proxy_addr = free_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_srv = Arc::clone(&running);

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");

        while r_srv.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                stream.set_nonblocking(false).expect("blocking");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("timeout");

                // Process 55 sequential requests on this single connection
                for i in 1..=55 {
                    let mut req_buf = Vec::new();
                    let mut buf = [0u8; 1024];

                    while let Ok(n) = stream.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        req_buf.extend_from_slice(&buf[..n]);
                        if req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }

                    let req_str = String::from_utf8_lossy(&req_buf);
                    assert!(
                        req_str.starts_with(&format!("GET /seq/{i} HTTP/1.1")),
                        "expected /seq/{i}, got: {req_str}"
                    );

                    let body = format!("ACK_SEQ_{i:04}");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Length: {}\r\n\
                         Connection: keep-alive\r\n\
                         \r\n\
                         {}",
                        body.len(),
                        body
                    );
                    stream.write_all(resp.as_bytes()).expect("srv write");
                    stream.flush().expect("srv flush");
                }
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
    });

    let mut engine = create_test_engine(proxy_addr, srv_addr);

    // Client connects once and sends 55 requests sequentially on that same connection
    let mut client = TcpStream::connect(proxy_addr).expect("client connect");
    client.set_nonblocking(true).expect("nonblocking");

    for i in 1..=55 {
        let req = format!(
            "GET /seq/{} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            i
        );
        client.write_all(req.as_bytes()).expect("client write");

        let expected_body = format!("ACK_SEQ_{i:04}");
        let mut resp = Vec::new();
        let mut buf = [0u8; 1024];
        let req_start = Instant::now();

        while req_start.elapsed() < Duration::from_secs(3) {
            let _ = engine.run_once().expect("engine step");
            if let Ok(n) = client.read(&mut buf) {
                if n > 0 {
                    resp.extend_from_slice(&buf[..n]);
                    if resp
                        .windows(expected_body.len())
                        .any(|w| w == expected_body.as_bytes())
                    {
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(1));
        }

        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            resp_str.contains(&expected_body),
            "Request {i} failed: {resp_str}"
        );
    }

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}

// ============================================================================
// 3. HTTP Keep-Alive & Connection Reuse (50+ Pipelined Requests)
// ============================================================================

#[test]
fn test_rt_keep_alive_50_plus_pipelined_requests() {
    let srv_addr = free_addr();
    let proxy_addr = free_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_srv = Arc::clone(&running);

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");

        while r_srv.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                stream.set_nonblocking(false).expect("blocking");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("timeout");

                let mut read_buf = Vec::new();
                let mut buf = [0u8; 4096];
                let mut handled = 0;

                while handled < 50 {
                    if let Ok(n) = stream.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        read_buf.extend_from_slice(&buf[..n]);
                    }

                    while let Some(pos) = read_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let total_len = pos + 4;
                        handled += 1;
                        read_buf.drain(..total_len);

                        let body = format!("ACK_PIPE_{handled:03}");
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Length: {}\r\n\
                             \r\n\
                             {}",
                            body.len(),
                            body
                        );
                        stream.write_all(resp.as_bytes()).expect("write resp");
                        stream.flush().expect("flush resp");
                    }
                }
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
    });

    let mut engine = create_test_engine(proxy_addr, srv_addr);

    let mut client = TcpStream::connect(proxy_addr).expect("client connect");
    client.set_nonblocking(true).expect("nonblocking");

    let mut pipelined_payload = Vec::new();
    for i in 1..=50 {
        let req = format!(
            "GET /pipe/{} HTTP/1.1\r\n\
             Host: localhost\r\n\
             \r\n",
            i
        );
        pipelined_payload.extend_from_slice(req.as_bytes());
    }

    client
        .write_all(&pipelined_payload)
        .expect("write pipelined");

    let mut resp_buf = Vec::new();
    let mut buf = [0u8; 4096];
    let start = Instant::now();

    while start.elapsed() < Duration::from_secs(5) {
        let _ = engine.run_once().expect("engine step");
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                resp_buf.extend_from_slice(&buf[..n]);
                if resp_buf.windows(12).any(|w| w == b"ACK_PIPE_050") {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(1));
    }

    let resp_str = String::from_utf8_lossy(&resp_buf);
    for i in 1..=50 {
        assert!(
            resp_str.contains(&format!("ACK_PIPE_{i:03}")),
            "Missing ACK_PIPE_{i:03} in pipelined responses"
        );
    }

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}

// ============================================================================
// 4. HTTP/1.0 Fallback Without Content-Length (Close Delimiter)
// ============================================================================

#[test]
fn test_rt_http10_fallback_close_delimiter() {
    let srv_addr = free_addr();
    let proxy_addr = free_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_srv = Arc::clone(&running);

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");

        while r_srv.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                stream.set_nonblocking(false).expect("blocking");
                let mut req = Vec::new();
                let mut buf = [0u8; 512];
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
                assert!(req_str.starts_with("GET /legacy HTTP/1.0"));

                // HTTP/1.0 response with NO Content-Length, closed via EOF
                let resp = b"HTTP/1.0 200 OK\r\n\
                             Content-Type: text/plain\r\n\
                             Server: LegacyHttp10\r\n\
                             \r\n\
                             STREAMING_UNTIL_CONNECTION_CLOSE_DELIMITER_DATA";
                stream.write_all(resp).expect("write resp");
                stream.flush().expect("flush resp");
                let _ = stream.shutdown(std::net::Shutdown::Both);
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
    });

    let mut engine = create_test_engine(proxy_addr, srv_addr);

    let mut client = TcpStream::connect(proxy_addr).expect("client connect");
    client.set_nonblocking(true).expect("nonblocking");

    let req = b"GET /legacy HTTP/1.0\r\nHost: localhost\r\n\r\n";
    client.write_all(req).expect("client write");

    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];

    while start.elapsed() < Duration::from_secs(3) {
        let _ = engine.run_once().expect("engine step");
        match client.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(_) => {}
        }
        thread::sleep(Duration::from_millis(1));
    }

    let resp_str = String::from_utf8_lossy(&response);
    assert!(
        resp_str.starts_with("HTTP/1.0 200 OK\r\n"),
        "got: {resp_str}"
    );
    assert!(resp_str.contains("STREAMING_UNTIL_CONNECTION_CLOSE_DELIMITER_DATA"));

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}

// ============================================================================
// 5. HTTP Method Handling (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH)
// ============================================================================

#[test]
fn test_rt_http_methods_suite() {
    let srv_addr = free_addr();
    let proxy_addr = free_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_srv = Arc::clone(&running);

    let methods = vec![
        ("GET", "/items", ""),
        ("POST", "/items", "{\"test\": 1}"),
        ("PUT", "/items/1", "{\"update\": true}"),
        ("DELETE", "/items/1", ""),
        ("HEAD", "/items", ""),
        ("OPTIONS", "*", ""),
        ("PATCH", "/items/1", "{\"patch\": 42}"),
    ];

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");

        let mut current_idx = 0;
        while r_srv.load(Ordering::Relaxed) && current_idx < 7 {
            if let Ok((mut stream, _)) = listener.accept() {
                stream.set_nonblocking(false).expect("blocking");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("timeout");

                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if req.windows(4).any(|w| w == b"\r\n\r\n") {
                        let req_str = String::from_utf8_lossy(&req);
                        if let Some(pos) = req_str.find("Content-Length:") {
                            let rest = &req_str[pos + 15..];
                            let clen_str = rest.lines().next().unwrap_or("0").trim();
                            if let Ok(clen) = clen_str.parse::<usize>() {
                                let hdr_end =
                                    req.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                                let body_len = req.len() - hdr_end;
                                if body_len >= clen {
                                    break;
                                }
                                continue;
                            }
                        }
                        break;
                    }
                }

                let req_str = String::from_utf8_lossy(&req);
                let (expected_method, expected_uri, expected_body) = methods[current_idx];
                assert!(
                    req_str.starts_with(&format!("{expected_method} {expected_uri} HTTP/1.1")),
                    "method {expected_method} mismatch: {req_str}"
                );
                if !expected_body.is_empty() {
                    assert!(req_str.contains(expected_body));
                }

                let resp_body = format!("ACK_{expected_method}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    resp_body.len(),
                    resp_body
                );
                stream.write_all(resp.as_bytes()).expect("write");
                stream.flush().expect("flush");
                current_idx += 1;
            }
            thread::sleep(Duration::from_millis(2));
        }
    });

    let mut engine = create_test_engine(proxy_addr, srv_addr);

    let client_cases = vec![
        ("GET", "/items", ""),
        ("POST", "/items", "{\"test\": 1}"),
        ("PUT", "/items/1", "{\"update\": true}"),
        ("DELETE", "/items/1", ""),
        ("HEAD", "/items", ""),
        ("OPTIONS", "*", ""),
        ("PATCH", "/items/1", "{\"patch\": 42}"),
    ];

    for (m, uri, body) in client_cases {
        let mut client = TcpStream::connect(proxy_addr).expect("client connect");
        client.set_nonblocking(true).expect("nonblocking");

        let req = if body.is_empty() {
            format!(
                "{m} {uri} HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Connection: close\r\n\
                 \r\n"
            )
        } else {
            format!(
                "{m} {uri} HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {}",
                body.len(),
                body
            )
        };

        client.write_all(req.as_bytes()).expect("client write");

        let start = Instant::now();
        let mut response = Vec::new();
        let mut buf = [0u8; 1024];

        while start.elapsed() < Duration::from_secs(3) {
            let _ = engine.run_once().expect("engine step");
            if let Ok(n) = client.read(&mut buf) {
                if n > 0 {
                    response.extend_from_slice(&buf[..n]);
                    if response.windows(4).any(|w| w == b"\r\n\r\n") && response.len() > 10 {
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(1));
        }

        let resp_str = String::from_utf8_lossy(&response);
        assert!(
            resp_str.starts_with("HTTP/1.1 200 OK"),
            "{m} failed: {resp_str}"
        );
        assert!(
            resp_str.contains(&format!("ACK_{m}")),
            "{m} missing body: {resp_str}"
        );
    }

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}

// ============================================================================
// 6. Header Boundary Edge Cases: LF-only, CR-only, Multiline Fold
// ============================================================================

#[test]
fn test_rt_header_boundary_edge_cases() {
    let srv_addr = free_addr();
    let proxy_addr = free_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_srv = Arc::clone(&running);

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");

        let mut handled = 0;
        while r_srv.load(Ordering::Relaxed) && handled < 3 {
            if let Ok((mut stream, _)) = listener.accept() {
                stream.set_nonblocking(false).expect("blocking");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("timeout");

                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if req.windows(4).any(|w| w == b"\r\n\r\n")
                        || req.windows(2).any(|w| w == b"\n\n")
                        || req.windows(2).any(|w| w == b"\r\r")
                    {
                        break;
                    }
                }

                let req_str = String::from_utf8_lossy(&req);
                match handled {
                    0 => {
                        // LF-only request
                        assert!(req_str.starts_with("GET /lf-path HTTP/1.1"));
                        assert!(req_str.contains("X-LF-Header: lf_ok"));
                    }
                    1 => {
                        // CR-only request
                        assert!(req_str.starts_with("GET /cr-path HTTP/1.1"));
                        assert!(req_str.contains("X-CR-Header: cr_ok"));
                    }
                    2 => {
                        // Multiline obs-fold request
                        assert!(req_str.starts_with("GET /obs-path HTTP/1.1"));
                        assert!(
                            req_str.contains("X-Folded: line1")
                                && req_str.contains("line2")
                                && req_str.contains("line3")
                        );
                    }
                    _ => {}
                }

                let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
                stream.write_all(resp).expect("write");
                stream.flush().expect("flush");
                handled += 1;
            }
            thread::sleep(Duration::from_millis(2));
        }
    });

    let mut engine = create_test_engine(proxy_addr, srv_addr);

    // 1. LF-only request
    {
        let mut client = TcpStream::connect(proxy_addr).expect("client connect");
        client.set_nonblocking(true).expect("nonblocking");
        let req =
            b"GET /lf-path HTTP/1.1\nHost: localhost\nX-LF-Header: lf_ok\nConnection: close\n\n";
        client.write_all(req).expect("write lf");

        let start = Instant::now();
        let mut resp = Vec::new();
        let mut buf = [0u8; 512];
        while start.elapsed() < Duration::from_secs(3) {
            let _ = engine.run_once().expect("engine step");
            if let Ok(n) = client.read(&mut buf) {
                if n > 0 {
                    resp.extend_from_slice(&buf[..n]);
                    if resp.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
        let s = String::from_utf8_lossy(&resp);
        assert!(s.starts_with("HTTP/1.1 200 OK"), "LF-only failed: {s}");
    }

    // 2. CR-only request
    {
        let mut client = TcpStream::connect(proxy_addr).expect("client connect");
        client.set_nonblocking(true).expect("nonblocking");
        let req =
            b"GET /cr-path HTTP/1.1\rHost: localhost\rX-CR-Header: cr_ok\rConnection: close\r\r";
        client.write_all(req).expect("write cr");

        let start = Instant::now();
        let mut resp = Vec::new();
        let mut buf = [0u8; 512];
        while start.elapsed() < Duration::from_secs(3) {
            let _ = engine.run_once().expect("engine step");
            if let Ok(n) = client.read(&mut buf) {
                if n > 0 {
                    resp.extend_from_slice(&buf[..n]);
                    if resp.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
        let s = String::from_utf8_lossy(&resp);
        assert!(s.starts_with("HTTP/1.1 200 OK"), "CR-only failed: {s}");
    }

    // 3. Multiline header (obs-fold with SP and TAB)
    {
        let mut client = TcpStream::connect(proxy_addr).expect("client connect");
        client.set_nonblocking(true).expect("nonblocking");
        let req = b"GET /obs-path HTTP/1.1\r\n\
                    Host: localhost\r\n\
                    X-Folded: line1\r\n\
                     line2\r\n\
                    \tline3\r\n\
                    Connection: close\r\n\
                    \r\n";
        client.write_all(req).expect("write obs");

        let start = Instant::now();
        let mut resp = Vec::new();
        let mut buf = [0u8; 512];
        while start.elapsed() < Duration::from_secs(3) {
            let _ = engine.run_once().expect("engine step");
            if let Ok(n) = client.read(&mut buf) {
                if n > 0 {
                    resp.extend_from_slice(&buf[..n]);
                    if resp.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
        let s = String::from_utf8_lossy(&resp);
        assert!(s.starts_with("HTTP/1.1 200 OK"), "obs-fold failed: {s}");
    }

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}
