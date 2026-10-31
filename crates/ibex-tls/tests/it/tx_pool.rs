// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T541: a TLS session holds a ciphertext buffer only while it has ciphertext for the socket.
//! HAProxy releases an empty buffer; an idle connection must not keep ~33 KB.

use crate::common::{client_trusting, TestCert};

fn pair() -> crate::common::Pair {
    let cert = TestCert::new(vec!["localhost".into()]);
    let cfg = client_trusting(&cert.cert_pem, vec![]);
    crate::common::Pair::new(cert.bind(vec![]), &cfg, "localhost")
}

#[test]
fn an_idle_session_holds_no_ciphertext_buffer() {
    let mut p = pair();
    p.complete();
    assert_eq!(p.srv.tx_capacity(), 0, "server, handshake done and drained");
    assert_eq!(p.cli.tx_capacity(), 0, "client, handshake done and drained");
    assert_eq!(p.send_to_server(b"GET / HTTP/1.1\r\n\r\n"), b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(p.send_to_client(b"HTTP/1.1 200 OK\r\n\r\n"), b"HTTP/1.1 200 OK\r\n\r\n");
    assert_eq!(p.srv.tx_capacity(), 0, "server, after a response");
    assert_eq!(p.cli.tx_capacity(), 0, "client, after a request");
}

#[test]
fn the_buffer_is_held_while_ciphertext_waits_and_covers_two_full_records() {
    let mut p = pair();
    p.complete();
    let data = vec![b'x'; 32_000];
    let n = p.srv.write_plain(&data).expect("write");
    assert!(n > 16_384, "more than one record fits ({n})");
    assert!(p.srv.wants_write());
    assert!(p.srv.tx_capacity() >= p.srv.pending_tx().len());
    assert!(p.srv.tx_capacity() >= ibex_tls::conn::TX_CAP, "the pool's chunk is TX_CAP");
    let out = p.srv.pending_tx().len();
    p.srv.tx_done(out);
    assert_eq!(p.srv.tx_capacity(), 0, "given back once drained");
    assert!(ibex_tls::conn::tx_pool_cached() >= 1, "into the pool, not freed");
}

#[test]
fn a_session_dropped_with_ciphertext_waiting_gives_the_buffer_back() {
    let mut p = pair();
    p.complete();
    p.srv.write_plain(b"hello").expect("write");
    assert!(p.srv.tx_capacity() > 0);
    let before = ibex_tls::conn::tx_pool_cached();
    drop(p);
    assert_eq!(ibex_tls::conn::tx_pool_cached(), before + 1, "the buffer is in the pool, not freed");
}

/// What the receive side queues for the peer while the session holds no chunk (an alert after a
/// record that does not decrypt) is moved into one, and goes back to the pool once sent.
#[test]
fn an_alert_queued_by_a_read_gets_a_buffer_and_gives_it_back() {
    use ibex_tls::conn::Plain;
    let mut p = pair();
    p.complete();
    assert_eq!(p.srv.tx_capacity(), 0);
    // An application-data record whose contents are not a valid ciphertext.
    let mut junk = vec![0x17, 0x03, 0x03, 0x00, 0x20];
    junk.extend_from_slice(&[0x5a; 32]);
    p.sin.extend(&junk, &p.srv);
    let mut dst = [0u8; 64];
    let r = p.srv.read_plain(&mut p.sin, &mut dst);
    assert!(!matches!(r, Ok(Plain::Data(_))), "junk decrypted: {r:?}");
    assert!(p.srv.wants_write(), "the alert is queued");
    assert!(p.srv.tx_capacity() > 0, "in a pooled chunk");
    let n = p.srv.pending_tx().len();
    p.srv.tx_done(n);
    assert_eq!(p.srv.tx_capacity(), 0);
}
