// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The error edges of the raw socket reads and of the plaintext prefix a TLS server
//! transport writes before its ClientHello (a `send-proxy` header): a peek that finds
//! nothing, a peer that reset, a descriptor that is no socket, a prefix larger than the
//! socket will take, and a peer that leaves while it is being written.

use alcyon_rt::{raw, Io, ServerXprt};
use alcyon_tls::tcp::build_backend_client_config;
use alcyon_tls::BackendTlsOptions;
use rustls::pki_types::ServerName;
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsFd;

fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let client = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    client.set_nonblocking(true).expect("nonblocking");
    (client, server)
}

#[test]
fn peek_reports_what_the_socket_holds_and_what_it_cannot() {
    let (client, server) = pair();
    assert!(matches!(raw::peek(client.as_fd(), &mut []), Ok(Io::Done(0))), "an empty buffer reads nothing");
    assert!(matches!(raw::peek(client.as_fd(), &mut [0u8; 8]), Ok(Io::WouldBlock)), "nothing queued yet");

    // A peer that resets: the peek says closed, not an error.
    rustix::net::sockopt::set_socket_linger(&server, Some(std::time::Duration::ZERO)).expect("linger");
    drop(server);
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(matches!(raw::peek(client.as_fd(), &mut [0u8; 8]), Ok(Io::Closed)), "RST on peek is a closed peer");

    // A descriptor that is no socket is a genuine error.
    let file = std::fs::File::open("/dev/null").expect("open");
    assert!(raw::peek(file.as_fd(), &mut [0u8; 8]).is_err(), "a file is not a socket");
}

fn tls_server_xprt(sock: &TcpStream) -> ServerXprt {
    let cfg = build_backend_client_config(&BackendTlsOptions { verify_required: false, ..Default::default() }).expect("config");
    alcyon_rt::connect_tls(sock, cfg, ServerName::try_from("backend.example.com").expect("name"))
}

#[test]
fn a_plain_prefix_larger_than_the_socket_waits_and_a_leaving_peer_fails_it() {
    let (client, server) = pair();
    let mut xprt = tls_server_xprt(&client);
    let ServerXprt::Tls(t) = &mut xprt else { panic!("a TLS transport") };
    t.set_plain_prefix(vec![b'x'; 64 << 20]);
    assert!(matches!(xprt.handshake(client.as_fd()), Ok(false)), "the peer is not reading: the prefix is not all out");
    assert!(!xprt.handshake_failed());

    // The peer leaves with the prefix half written.
    rustix::net::sockopt::set_socket_linger(&server, Some(std::time::Duration::ZERO)).expect("linger");
    drop(server);
    std::thread::sleep(std::time::Duration::from_millis(100));
    let mut failed = false;
    for _ in 0..50 {
        if xprt.handshake(client.as_fd()).is_err() {
            failed = true;
            break;
        }
    }
    assert!(failed, "writing the prefix to a peer that is gone is a handshake failure");
    assert!(xprt.handshake_failed());
}
