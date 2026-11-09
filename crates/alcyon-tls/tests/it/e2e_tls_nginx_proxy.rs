// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! End-to-end integration test demonstrating an HAProxy-configured Alcyon Load Balancer
//! terminating TLS on a frontend port, reverse proxying traffic to an upstream Nginx server,
//! and verifying the transaction with an actual `curl https://localhost:...` command.

//!
//! On the binary's TLS ([`alcyon_tls::blocking::BlockingTls`] serving a [`BindTls`], rustls
//! 0.24) and threads since T479; it ran on tokio-rustls (rustls 0.23).

use crate::common::TestCert;
use alcyon_config::parse_str;
use alcyon_tls::blocking::BlockingTls;
use alcyon_tls::tcp::BindTls;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::Arc;

/// Upstream Nginx server mock.
fn run_mock_nginx(listener: &TcpListener) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            break;
        };

        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            if n == 0 {
                return;
            }

            let body = "<h1>Welcome to nginx proxied by Alcyon!</h1>\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Server: nginx/1.24.0\r\n\
                 Content-Type: text/html; charset=UTF-8\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {}",
                body.len(),
                body
            );

            let _ = stream.write_all(response.as_bytes());
            let _ = stream.shutdown(std::net::Shutdown::Write);
        });
    }
}

/// Alcyon TLS Reverse Proxy daemon task.
fn run_alcyon_tls_proxy(frontend_listener: &TcpListener, backend_addr: std::net::SocketAddr, bind: &Arc<BindTls>) {
    for tcp_stream in frontend_listener.incoming() {
        let Ok(tcp_stream) = tcp_stream else {
            break;
        };

        let bind = Arc::clone(bind);
        std::thread::spawn(move || {
            // 1. Terminate TLS with the client (the handshake runs on the first read)
            let mut tls_stream = BlockingTls::accept(&bind, tcp_stream);

            // 2. Read client HTTP request from TLS stream
            let mut client_req_buf = vec![0u8; 8192];
            let n = match tls_stream.read(&mut client_req_buf) {
                Ok(n) if n > 0 => n,
                Ok(_) => return,
                Err(e) => {
                    eprintln!("Alcyon TLS handshake or read error: {e}");
                    return;
                }
            };
            client_req_buf.truncate(n);

            // 3. Connect to upstream Nginx backend
            let mut srv_stream = match TcpStream::connect(backend_addr) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to connect to backend {backend_addr}: {e}");
                    let err_resp = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
                    let _ = tls_stream.write_all(err_resp);
                    return;
                }
            };

            // 4. Forward HTTP request to backend
            if let Err(e) = srv_stream.write_all(&client_req_buf) {
                eprintln!("Failed to write request to backend: {e}");
                return;
            }

            // 5. Read HTTP response from backend
            let mut srv_resp_buf = Vec::new();
            if let Err(e) = srv_stream.read_to_end(&mut srv_resp_buf) {
                eprintln!("Failed to read response from backend: {e}");
                return;
            }

            // 6. Return response to client encrypted over TLS
            let _ = tls_stream.write_all(&srv_resp_buf);
            let _ = tls_stream.flush();
        });
    }
}

/// The frontend's bind: the certificate for `localhost` and `127.0.0.1`, offering HTTP/1.1.
fn frontend_bind(cert: &TestCert) -> Arc<BindTls> {
    cert.bind(vec![b"http/1.1".to_vec()])
}

/// `curl` against `https://localhost:<port>/`, trusting `ca`.
fn curl(frontend_port: u16, ca: &std::path::Path) -> std::process::Output {
    let url = format!("https://localhost:{frontend_port}/");
    println!("Executing curl command: curl -4 -vk --cacert {} {}", ca.display(), url);
    Command::new("curl")
        .arg("-4")
        .arg("-vk")
        .arg("--connect-timeout")
        .arg("5")
        .arg("--cacert")
        .arg(ca)
        .arg("--resolve")
        .arg(format!("localhost:{frontend_port}:127.0.0.1"))
        .arg(&url)
        .output()
        .expect("Failed to execute curl")
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_e2e_haproxy_cfg_tls_frontend_proxy_to_nginx_with_curl() {
    // 1. Generate test certificate & key for localhost and 127.0.0.1
    let cert = TestCert::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]);
    let cert_pem = &cert.cert_pem;

    // Write CA cert to a temporary file for curl --cacert
    let mut cert_file = tempfile::NamedTempFile::new().expect("Create temp cert file");
    cert_file
        .write_all(cert_pem.as_bytes())
        .expect("Write cert pem");
    cert_file.flush().expect("Flush cert file");
    let cert_file_path = cert_file.path().to_path_buf();

    // 2. Start upstream Nginx mock server
    let nginx_listener = TcpListener::bind("127.0.0.1:0").expect("Bind mock nginx");
    let nginx_addr = nginx_listener.local_addr().expect("Get mock nginx addr");
    let nginx_port = nginx_addr.port();
    std::thread::spawn(move || run_mock_nginx(&nginx_listener));

    // 3. Bind Alcyon TLS frontend listener
    let frontend_listener = TcpListener::bind("127.0.0.1:0").expect("Bind frontend");
    let frontend_addr = frontend_listener.local_addr().expect("Get frontend addr");
    let frontend_port = frontend_addr.port();

    // 4. Parse HAProxy configuration referencing the frontend and backend server
    let haproxy_cfg_text = format!(
        r"
listen nginx_https_proxy
    bind 127.0.0.1:{frontend_port}
    mode http
    timeout client 5000
    timeout server 5000
    timeout connect 2000
    balance roundrobin
    maxconn 2048
    server nginx_backend 127.0.0.1:{nginx_port}
"
    );

    let parsed_cfg = parse_str(&haproxy_cfg_text).expect("Parse HAProxy configuration");
    assert_eq!(parsed_cfg.listens.len(), 1);
    let listen = &parsed_cfg.listens[0];
    assert_eq!(listen.name, "nginx_https_proxy");
    assert_eq!(listen.servers.len(), 1);
    assert_eq!(listen.servers[0].addr.port(), nginx_port);

    // 5. Build Alcyon TLS engine configuration (its resolver serves the certificate for
    // both names, and by default)
    let bind = frontend_bind(&cert);

    // 6. Start Alcyon TLS Reverse Proxy
    let backend = listen.servers[0].addr;
    std::thread::spawn(move || run_alcyon_tls_proxy(&frontend_listener, backend, &bind));

    // 7. Execute actual `curl` command against https://localhost:{frontend_port}/
    let curl_output = curl(frontend_port, &cert_file_path);

    let stdout = String::from_utf8_lossy(&curl_output.stdout);
    let stderr = String::from_utf8_lossy(&curl_output.stderr);

    println!("--- curl stdout ---\n{stdout}");
    println!("--- curl stderr (verbose handshake) ---\n{stderr}");

    assert!(
        curl_output.status.success(),
        "curl exited with non-zero status: {:?}",
        curl_output.status
    );
    assert!(
        stdout.contains("<h1>Welcome to nginx proxied by Alcyon!</h1>"),
        "Response body mismatch"
    );
    assert!(
        stderr.contains("200 OK") || stdout.contains("200 OK") || stderr.contains("HTTP/1.1 200"),
        "HTTP 200 OK status expected"
    );
    assert!(
        stderr.contains("Server: nginx/1.24.0") || stderr.contains("server: nginx/1.24.0"),
        "Nginx server header expected in curl trace"
    );
    assert!(
        stderr.contains("TLSv1.3")
            || stderr.contains("SSL connection using TLSv1.3")
            || stderr.contains("TLS"),
        "TLS 1.3 negotiated"
    );

    println!("SUCCESS: End-to-end TLS termination and Nginx proxying verified with curl!");
}

#[test]
fn test_e2e_frontend_backend_syntax_tls_proxy_with_curl() {
    // 1. Generate test certificate & key for localhost and 127.0.0.1
    let cert = TestCert::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]);
    let cert_pem = &cert.cert_pem;

    let mut cert_file = tempfile::NamedTempFile::new().expect("Create temp cert file");
    cert_file
        .write_all(cert_pem.as_bytes())
        .expect("Write cert pem");
    cert_file.flush().expect("Flush cert file");
    let cert_file_path = cert_file.path().to_path_buf();

    // 2. Start upstream Nginx mock server
    let nginx_listener = TcpListener::bind("127.0.0.1:0").expect("Bind mock nginx");
    let nginx_addr = nginx_listener.local_addr().expect("Get mock nginx addr");
    let nginx_port = nginx_addr.port();
    std::thread::spawn(move || run_mock_nginx(&nginx_listener));

    // 3. Bind Alcyon TLS frontend listener
    let frontend_listener = TcpListener::bind("127.0.0.1:0").expect("Bind frontend");
    let frontend_addr = frontend_listener.local_addr().expect("Get frontend addr");
    let frontend_port = frontend_addr.port();

    // 4. Parse HAProxy configuration with separate frontend / backend syntax
    let haproxy_cfg_text = format!(
        r"
frontend fe_main
    bind 127.0.0.1:{frontend_port}
    mode http
    timeout client 5000
    default_backend be_test

backend be_test
    mode http
    timeout server 5000
    timeout connect 2000
    server nginx_backend 127.0.0.1:{nginx_port}
"
    );

    let parsed_cfg = parse_str(&haproxy_cfg_text).expect("Parse HAProxy configuration");
    assert_eq!(parsed_cfg.frontends.len(), 1);
    assert_eq!(parsed_cfg.backends.len(), 1);

    let fe = &parsed_cfg.frontends[0];
    let be = &parsed_cfg.backends[0];
    assert_eq!(fe.name, "fe_main");
    assert_eq!(fe.default_backend, Some("be_test".into()));
    assert_eq!(be.name, "be_test");
    assert_eq!(be.servers[0].addr.port(), nginx_port);

    // 5. Build Alcyon TLS engine configuration (its resolver serves the certificate for
    // both names, and by default)
    let bind = frontend_bind(&cert);

    // 6. Start Alcyon TLS Reverse Proxy
    let backend = be.servers[0].addr;
    std::thread::spawn(move || run_alcyon_tls_proxy(&frontend_listener, backend, &bind));

    // 7. Execute curl command against https://localhost:{frontend_port}/
    let curl_output = curl(frontend_port, &cert_file_path);

    let stdout = String::from_utf8_lossy(&curl_output.stdout);
    let stderr = String::from_utf8_lossy(&curl_output.stderr);

    assert!(
        curl_output.status.success(),
        "curl failed: {:?}",
        curl_output.status
    );
    assert!(stdout.contains("<h1>Welcome to nginx proxied by Alcyon!</h1>"));
    assert!(
        stderr.contains("200 OK") || stdout.contains("200 OK") || stderr.contains("HTTP/1.1 200")
    );
    assert!(stderr.contains("Server: nginx/1.24.0") || stderr.contains("server: nginx/1.24.0"));
    assert!(stderr.contains("TLSv1.3") || stderr.contains("SSL connection using TLSv1.3"));
}
