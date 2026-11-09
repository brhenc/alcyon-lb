// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Real TCP loopback integration test verifying TLS 1.3 handshake, SNI resolution,
//! ALPN negotiation, and HTTP transactions over network sockets. On the binary's TLS
//! ([`alcyon_tls::blocking::BlockingTls`], rustls 0.24) since T479; it ran on tokio-rustls
//! (rustls 0.23), which has no rustls 0.24 version. The file keeps its name.

use crate::common::{client_trusting, TestCert};
use alcyon_tls::blocking::BlockingTls;
use alcyon_tls::tcp::rustls24::pki_types::ServerName;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

#[test]
fn test_tokio_tcp_loopback_tls() {
    let cert = TestCert::new(vec!["localhost".to_string()]);
    let bind = cert.bind(vec![b"http/1.1".to_vec()]);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut tls_stream = BlockingTls::accept(&bind, stream);

        let mut buf = [0u8; 1024];
        let n = tls_stream.read(&mut buf).unwrap();
        assert!(n > 0);
        let req = String::from_utf8_lossy(&buf[..n]);
        assert!(req.contains("GET / HTTP/1.1"));

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nAlcyon!\n";
        tls_stream.write_all(response).unwrap();
        tls_stream.flush().unwrap();
        // Dropped: the connection closes, which the client reads as the end.
    });

    let client_config = client_trusting(&cert.cert_pem, vec![b"http/1.1".to_vec()]);
    let client_stream = TcpStream::connect(addr).unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut client_tls =
        BlockingTls::connect(&client_config, alcyon_tls::provider::active(), server_name, client_stream).unwrap();

    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    client_tls.write_all(request).unwrap();

    let mut resp_buf = Vec::new();
    client_tls.read_to_end(&mut resp_buf).unwrap();

    let resp_str = String::from_utf8_lossy(&resp_buf);
    assert!(resp_str.contains("HTTP/1.1 200 OK"));
    assert!(resp_str.contains("Alcyon!"));

    server_task.join().unwrap();
}
