// SPDX-License-Identifier: GPL-2.0-or-later
// Integration tests for client-side keep-alive when backend closes or specifies Connection: close (T71).

mod common;

use ibex_config::ast::{BackendSection, Config, FrontendSection, Mode, Server};
use ibex_rt::engine::Engine;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};


#[test]
#[allow(clippy::too_many_lines)]
fn client_keepalive_when_backend_sends_connection_close() {
    let srv_addr = common::reserve_addr();
    let fe_addr = common::reserve_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);
    let be_conn_count = Arc::new(AtomicUsize::new(0));
    let be_conns = Arc::clone(&be_conn_count);

    // Mock backend that closes each incoming connection with Connection: close
    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");
        while r_clone.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let conn_idx = be_conns.fetch_add(1, Ordering::SeqCst);
                stream.set_nonblocking(false).expect("blocking");
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
                eprintln!("[SRV] conn_idx={conn_idx}, req: {req_str:?}");
                let (body, body_len) = if conn_idx == 0 {
                    ("first", 5)
                } else {
                    ("second", 6)
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n{body}"
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
                // Explicitly close / drop the backend socket
                drop(stream);
            }
            thread::sleep(Duration::from_millis(2));
        }
    });

    let config = Config {
        frontends: vec![FrontendSection {
            name: "fe".into(),
            bind: Some(fe_addr),
            mode: Mode::Http,
            default_backend: Some("be".into()),
            clitimeout: Some(Duration::from_secs(3)),
            ..Default::default()
        }],
        backends: vec![BackendSection {
            name: "be".into(),
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            servers: vec![Server::new("s1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("Engine::new");

    // Client connects ONCE over TCP
    let mut client = TcpStream::connect(fe_addr).expect("client connect");
    client.set_nonblocking(true).expect("set_nonblocking");

    // Helper to run engine and read a response from the client socket
    let read_response = |engine: &mut Engine, client: &mut TcpStream, expected_body: &str| -> (String, bool) {
        let start = Instant::now();
        let mut response = Vec::new();
        let mut buf = [0u8; 1024];
        let mut got_eof = false;

        while start.elapsed() < Duration::from_secs(3) {
            let _ = engine.run_once().expect("engine step");
            match client.read(&mut buf) {
                Ok(0) => {
                    got_eof = true;
                    break;
                }
                Ok(n) => {
                    response.extend_from_slice(&buf[..n]);
                    if response.windows(expected_body.len()).any(|w| w == expected_body.as_bytes()) {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    got_eof = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
        (String::from_utf8_lossy(&response).to_string(), got_eof)
    };

    // --- Request 1 ---
    let req1 = b"GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n";
    client.write_all(req1).expect("write req1");

    let (resp1, eof1) = read_response(&mut engine, &mut client, "first");
    assert!(!eof1, "Client received unexpected EOF on request 1");
    assert!(
        resp1.starts_with("HTTP/1.1 200 OK"),
        "Request 1 expected 200 OK, got: {resp1}"
    );
    assert!(
        resp1.contains("first"),
        "Request 1 expected body 'first', got: {resp1}"
    );
    assert!(
        !resp1.to_ascii_lowercase().contains("connection: close"),
        "HAProxy strips backend 'Connection: close' from client response in keep-alive mode, but Ibex sent: {resp1}"
    );

    // --- Request 2 on the SAME client socket ---
    let req2 = b"GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n";
    client.write_all(req2).expect("write req2 on same connection");

    let (resp2, eof2) = read_response(&mut engine, &mut client, "second");
    assert!(
        !eof2 && !resp2.is_empty(),
        "Client connection died on request 2 with EOF -- client keepalive was coupled to backend close. Resp: '{resp2}'"
    );
    assert!(
        resp2.starts_with("HTTP/1.1 200 OK"),
        "Request 2 expected 200 OK, got: {resp2}"
    );
    assert!(
        resp2.contains("second"),
        "Request 2 expected body 'second', got: {resp2}"
    );

    // Backend must have seen 2 separate connections
    assert_eq!(
        be_conn_count.load(Ordering::SeqCst),
        2,
        "Proxy should have opened a fresh backend connection for request 2"
    );

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}

#[test]
fn client_connection_close_header_is_respected_as_control() {
    let srv_addr = common::reserve_addr();
    let fe_addr = common::reserve_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");
        while r_clone.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                stream.set_nonblocking(false).expect("blocking");
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone";
                let _ = stream.write_all(resp);
                let _ = stream.flush();
            }
            thread::sleep(Duration::from_millis(2));
        }
    });

    let config = Config {
        frontends: vec![FrontendSection {
            name: "fe".into(),
            bind: Some(fe_addr),
            mode: Mode::Http,
            default_backend: Some("be".into()),
            clitimeout: Some(Duration::from_secs(3)),
            ..Default::default()
        }],
        backends: vec![BackendSection {
            name: "be".into(),
            mode: Mode::Http,
            servers: vec![Server::new("s1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("Engine::new");

    let mut client = TcpStream::connect(fe_addr).expect("client connect");
    client.set_nonblocking(true).expect("set_nonblocking");

    // Client explicitly asks for Connection: close
    let req = b"GET /close HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    client.write_all(req).expect("write req");

    let start = Instant::now();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    let mut got_eof = false;

    while start.elapsed() < Duration::from_secs(3) {
        let _ = engine.run_once().expect("engine step");
        match client.read(&mut buf) {
            Ok(0) => {
                got_eof = true;
                break;
            }
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {
                got_eof = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(5));
    }

    let resp_str = String::from_utf8_lossy(&response);
    assert!(resp_str.starts_with("HTTP/1.1 200 OK"));
    assert!(
        resp_str.to_ascii_lowercase().contains("connection: close"),
        "When client sends Connection: close, proxy response must contain Connection: close, got: {resp_str}"
    );

    // Give engine time to close client socket
    let close_start = Instant::now();
    while !got_eof && close_start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once().expect("engine step");
        if let Ok(0) = client.read(&mut buf) {
            got_eof = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(got_eof, "Proxy must close client connection when client sends Connection: close");

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}

/// The acceptance case from `tasks/T71-client-keepalive.md`, which the test above stops
/// one request short of: **three** requests down one client connection, each answered by
/// a backend that says `Connection: close`.
///
/// HAProxy 3.5-dev7, measured on this config:
///
///     /cl OK  [content-length: 5]
///     /cl OK  [content-length: 5]
///     /cl OK  [content-length: 5]
///
/// Every response has the backend's `Connection: close` removed, because it is hop-by-hop
/// and the client connection is still in keep-alive. The test above checks that request 2
/// *returns*, but not what it returned: with a raw socket, a leaked `Connection: close` on
/// response 2 is invisible until request 3 finds the connection gone. A real client obeys
/// the header, so it never gets that far.
#[test]
#[allow(clippy::too_many_lines)]
fn every_response_on_a_keepalive_connection_drops_the_backends_connection_close() {
    const N: usize = 3;
    let srv_addr = common::reserve_addr();
    let fe_addr = common::reserve_addr();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);
    let be_conn_count = Arc::new(AtomicUsize::new(0));
    let be_conns = Arc::clone(&be_conn_count);

    let srv_handle = thread::spawn(move || {
        let listener = TcpListener::bind(srv_addr).expect("bind srv");
        listener.set_nonblocking(true).expect("nonblocking");
        while r_clone.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let idx = be_conns.fetch_add(1, Ordering::SeqCst);
                stream.set_nonblocking(false).expect("blocking");
                stream.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
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
                let body = format!("resp-{idx}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                drop(stream);
            }
            thread::sleep(Duration::from_millis(2));
        }
    });

    let config = Config {
        frontends: vec![FrontendSection {
            name: "fe".into(),
            bind: Some(fe_addr),
            mode: Mode::Http,
            default_backend: Some("be".into()),
            clitimeout: Some(Duration::from_secs(3)),
            ..Default::default()
        }],
        backends: vec![BackendSection {
            name: "be".into(),
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            servers: vec![Server::new("s1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut engine = Engine::new(&config, 64).expect("Engine::new");
    let mut client = TcpStream::connect(fe_addr).expect("client connect");
    client.set_nonblocking(true).expect("set_nonblocking");

    for i in 0..N {
        client
            .write_all(format!("GET /r{i} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .expect("write request");
        let want = format!("resp-{i}");
        let start = Instant::now();
        let mut response = Vec::new();
        let mut buf = [0u8; 1024];
        let mut eof = false;
        while start.elapsed() < Duration::from_secs(3) {
            let _ = engine.run_once().expect("engine step");
            match client.read(&mut buf) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => {
                    response.extend_from_slice(&buf[..n]);
                    if response.windows(want.len()).any(|w| w == want.as_bytes()) {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    eof = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
        let resp = String::from_utf8_lossy(&response);
        assert!(
            !eof && resp.contains(&want),
            "request {} of {N}: connection died or wrong body -- got {resp:?}",
            i + 1
        );
        assert!(
            !resp.to_ascii_lowercase().contains("connection: close"),
            "request {} of {N}: the backend's hop-by-hop `Connection: close` reached a \
             keep-alive client; a real client would now close. Got {resp:?}",
            i + 1
        );
    }

    running.store(false, Ordering::Relaxed);
    let _ = srv_handle.join();
}
