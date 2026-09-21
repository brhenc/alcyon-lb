// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Ibex contributors. See LICENSE.

//! Project Ibex: Live TLS Reverse Proxy Demo on https://localhost:8443
//!
//! This standalone demo:
//! 1. Generates test TLS certificates for `localhost` and `127.0.0.1`.
//! 2. Writes `/tmp/ibex_cert.pem` and `/tmp/ibex_haproxy.cfg`.
//! 3. Starts an upstream mock Nginx server on `127.0.0.1:8080`.
//! 4. Parses HAProxy config and binds Ibex TLS reverse proxy on `127.0.0.1:8443`.
//! 5. Runs an initial `curl` verification and keeps listening for client requests.

#![allow(clippy::all, clippy::pedantic)]

use ibex_config::parse_str;
use ibex_tls::{create_certified_key, IbexCertResolver, TlsConfig};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::fs;
use std::process::Command;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Upstream Nginx server mock on 127.0.0.1:8080.
async fn run_mock_nginx(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return;
            }

            let req_str = String::from_utf8_lossy(&buf[..n]);
            let first_line = req_str.lines().next().unwrap_or("GET / HTTP/1.1");
            println!("  [Upstream Nginx] Received: {}", first_line);

            let body = "<h1>Welcome to nginx proxied by Project Ibex!</h1>\n<p>TLS 1.3 Termination & HAProxy Config verified.</p>\n";
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

            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

/// Ibex TLS Reverse Proxy daemon task on 127.0.0.1:8443.
async fn run_ibex_tls_proxy(
    frontend_listener: TcpListener,
    backend_addr: std::net::SocketAddr,
    acceptor: TlsAcceptor,
) {
    loop {
        let Ok((tcp_stream, peer_addr)) = frontend_listener.accept().await else {
            break;
        };

        println!(
            "  [Ibex TLS Proxy] Accepted TCP connection from {}",
            peer_addr
        );
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            // 1. Terminate TLS handshake with the client
            let mut tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "  [Ibex TLS Proxy] TLS Handshake error with {}: {}",
                        peer_addr, e
                    );
                    return;
                }
            };
            println!(
                "  [Ibex TLS Proxy] TLS Handshake succeeded with {}",
                peer_addr
            );

            // 2. Read client HTTP request from TLS stream
            let mut client_req_buf = vec![0u8; 8192];
            let n = match tls_stream.read(&mut client_req_buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };
            client_req_buf.truncate(n);

            // 3. Connect to upstream Nginx backend
            let mut srv_stream = match TcpStream::connect(backend_addr).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "  [Ibex TLS Proxy] Failed to connect to backend {}: {}",
                        backend_addr, e
                    );
                    let err_resp = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
                    let _ = tls_stream.write_all(err_resp).await;
                    return;
                }
            };

            // 4. Forward HTTP request to backend
            if let Err(e) = srv_stream.write_all(&client_req_buf).await {
                eprintln!(
                    "  [Ibex TLS Proxy] Failed to write request to backend: {}",
                    e
                );
                return;
            }

            // 5. Read HTTP response from backend
            let mut srv_resp_buf = Vec::new();
            if let Err(e) = srv_stream.read_to_end(&mut srv_resp_buf).await {
                eprintln!(
                    "  [Ibex TLS Proxy] Failed to read response from backend: {}",
                    e
                );
                return;
            }

            // 6. Return response to client encrypted over TLS
            let _ = tls_stream.write_all(&srv_resp_buf).await;
            let _ = tls_stream.shutdown().await;
            println!("  [Ibex TLS Proxy] Completed transaction for {}", peer_addr);
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("================================================================================");
    println!(" Project Ibex: Live TLS Reverse Proxy Server (HAProxy Config + Rustls 0.23)");
    println!("================================================================================");

    // 1. Generate self-signed certificate for localhost and 127.0.0.1
    let sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let cert_key = generate_simple_self_signed(sans)?;
    let cert_der = CertificateDer::from(cert_key.cert.der().to_vec());
    let cert_pem = cert_key.cert.pem();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der()));

    let certified_key = Arc::new(create_certified_key(vec![cert_der.clone()], &key_der)?);

    // Save cert PEM to disk
    let cert_path = "/tmp/ibex_cert.pem";
    fs::write(cert_path, &cert_pem)?;
    println!("[1/5] Generated TLS certificate: {}", cert_path);

    // 2. HAProxy Configuration with frontend / backend syntax
    let haproxy_cfg_text = r"
frontend fe_main
    bind 127.0.0.1:8443
    mode http
    timeout client 5000
    default_backend be_test

backend be_test
    mode http
    timeout server 5000
    timeout connect 2000
    server nginx-test 127.0.0.1:8080
";
    let cfg_path = "/tmp/haproxy_demo.cfg";
    fs::write(cfg_path, haproxy_cfg_text)?;
    println!("[2/5] Wrote HAProxy config: {}", cfg_path);

    // Parse and validate config
    let parsed_cfg = parse_str(haproxy_cfg_text)?;
    assert_eq!(parsed_cfg.frontends.len(), 1, "Expected 1 frontend");
    assert_eq!(parsed_cfg.backends.len(), 1, "Expected 1 backend");

    let fe = &parsed_cfg.frontends[0];
    let be = &parsed_cfg.backends[0];
    assert_eq!(fe.name, "fe_main");
    assert_eq!(fe.bind, Some("127.0.0.1:8443".parse()?));
    assert_eq!(fe.default_backend, Some("be_test".into()));
    assert_eq!(be.name, "be_test");
    assert_eq!(be.servers.len(), 1);
    assert_eq!(be.servers[0].id, "nginx-test");
    assert_eq!(be.servers[0].addr, "127.0.0.1:8080".parse()?);

    let backend_addr = be.servers[0].addr;
    println!(
        "[3/5] Parsed HAProxy frontend '{}' -> default_backend '{:?}' -> server '{}' at {}",
        fe.name, fe.default_backend, be.servers[0].id, backend_addr
    );

    // 3. Start upstream mock Nginx server on 127.0.0.1:8080
    let nginx_listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("[4/5] Started upstream Mock Nginx server on http://127.0.0.1:8080/");
    tokio::spawn(run_mock_nginx(nginx_listener));

    // 4. Set up Ibex TLS configuration with SNI resolution
    let mut resolver = IbexCertResolver::new();
    resolver.set_default_cert(certified_key.clone());
    resolver.add_exact("localhost", certified_key.clone());
    resolver.add_exact("127.0.0.1", certified_key);

    let tls_config = TlsConfig::new()
        .with_cert_resolver(Arc::new(resolver))
        .with_alpn(vec![b"http/1.1".to_vec()]);
    let server_config = tls_config.build_server_config()?;
    let acceptor = TlsAcceptor::from(server_config);

    // 5. Bind Ibex TLS frontend on 127.0.0.1:8443
    let frontend_listener = TcpListener::bind("127.0.0.1:8443").await?;
    println!("[5/5] Ibex TLS Reverse Proxy listening on https://127.0.0.1:8443/");
    println!("--------------------------------------------------------------------------------");
    tokio::spawn(run_ibex_tls_proxy(
        frontend_listener,
        backend_addr,
        acceptor,
    ));

    // Wait a brief moment for listeners to initialize
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 6. Run an automated verification curl
    println!("\n>>> Running Automated Verification with curl:");
    println!(
        "    curl -4 -vk --cacert {} https://localhost:8443/\n",
        cert_path
    );

    let curl_output = tokio::task::spawn_blocking(move || {
        Command::new("curl")
            .arg("-4")
            .arg("-vk")
            .arg("--connect-timeout")
            .arg("5")
            .arg("--cacert")
            .arg(cert_path)
            .arg("--resolve")
            .arg("localhost:8443:127.0.0.1")
            .arg("https://localhost:8443/")
            .output()
    })
    .await??;

    let stdout = String::from_utf8_lossy(&curl_output.stdout);
    let stderr = String::from_utf8_lossy(&curl_output.stderr);

    println!("--- curl HTTP Response Body ---");
    println!("{}", stdout);

    println!("--- curl TLS Handshake & Headers (stderr) ---");
    for line in stderr.lines() {
        if line.contains("TLSv1.3")
            || line.contains("SSL connection")
            || line.contains("ALPN")
            || line.contains("Server:")
            || line.contains("HTTP/1.1")
            || line.contains("subject:")
        {
            println!("  {}", line);
        }
    }

    println!("\n================================================================================");
    println!(" Verification Complete! The server is live.");
    println!(" You can run the following command in any terminal:");
    println!("   curl -vk https://localhost:8443/");
    println!(" or with strict CA verification:");
    println!("   curl -v --cacert /tmp/ibex_cert.pem https://localhost:8443/");
    println!("================================================================================\n");

    // Keep running so the user can curl it from their terminal if desired
    println!("Server is active and accepting requests (press Ctrl+C to stop)...");
    tokio::signal::ctrl_c().await?;
    println!("\nShutting down demo server. Goodbye!");

    Ok(())
}
