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

/// A take the pool refuses (`tune.fail-alloc` at 100 %, as a failed `malloc`) falls back to an
/// allocation of the chunk's size, which the release frees rather than gives to the pool.
#[test]
fn a_refused_take_falls_back_to_an_allocation_that_the_release_frees() {
    use ibex_tls::conn::{tx_pool_cached, TX_CAP};
    // Every chunk this thread's cache holds goes to a session that keeps ciphertext waiting, so
    // that the next take is a miss (the cache is served before any refusal).
    let mut holders = Vec::new();
    while tx_pool_cached() > 0 {
        let mut h = pair();
        h.complete();
        h.srv.write_plain(b"held").expect("write");
        holders.push(h);
    }
    ibex_alloc::pool::set_fail_alloc(100);
    // `connect` takes a buffer for the ClientHello: refused, so an allocation of its own.
    let mut p = pair();
    ibex_alloc::pool::set_fail_alloc(0);
    assert!(p.cli.tx_capacity() >= TX_CAP, "the ClientHello is in a buffer of the chunk's size");
    assert_eq!(tx_pool_cached(), 0, "nothing came from the pool");
    let hello = p.cli.pending_tx().to_vec();
    assert!(!hello.is_empty(), "a ClientHello is queued");
    p.cli.tx_done(hello.len());
    assert_eq!(p.cli.tx_capacity(), 0, "released once drained");
    assert_eq!(tx_pool_cached(), 0, "an allocation the pool refused is freed, not given to it");
    // The session is whole: the handshake and a request go through with pooled buffers after.
    p.sin.extend(&hello, &p.srv);
    p.complete();
    assert_eq!(p.send_to_server(b"GET / HTTP/1.1\r\n\r\n"), b"GET / HTTP/1.1\r\n\r\n");
    assert!(tx_pool_cached() >= 1, "the later takes were pooled and came back");
    drop(holders);
}

/// A buffer written long, drained at the front after a partial send, written short, then
/// released: the wipe covers the high-water mark, not only what `len` says is left.
#[test]
fn a_release_after_a_partial_send_wipes_to_the_high_water_mark() {
    use ibex_tls::conn::tx_pool_cached;
    let mut p = pair();
    p.complete();
    let long = vec![b'L'; 1000];
    assert_eq!(p.srv.write_plain(&long).expect("write"), 1000);
    let hw = p.srv.pending_tx().len();
    assert!(hw > 1000, "one record of 1000 bytes plus its overhead ({hw})");
    // Part of it reaches the wire; the next write drains that part from the front.
    p.srv.tx_done(400);
    assert_eq!(p.srv.write_plain(b"short").expect("write"), 5);
    let len = p.srv.pending_tx().len();
    assert!(len < hw, "what is left ({len}) is shorter than what the buffer once held ({hw})");
    let cached = tx_pool_cached();
    let wiped = ibex_alloc::wiped_ssl_fast_bytes();
    p.srv.tx_done(len);
    assert_eq!(p.srv.tx_capacity(), 0, "released once drained");
    assert_eq!(ibex_alloc::wiped_ssl_fast_bytes() - wiped, hw, "wiped up to the high-water mark, not to len");
    assert_eq!(tx_pool_cached(), cached + 1, "and given back to the pool");
}

/// T553: under `tune.ibex.ssl-zero-buffers on-free` a give-back does not wipe the chunk; the
/// pool's free does (its whole capacity: the chunk carries the last connection's ciphertext
/// until then). Under `on` the give-back wipes, as before.
#[test]
fn on_free_wipes_when_the_pool_frees_not_on_give_back() {
    use ibex_alloc::stack_probe::set_thread_ssl_zero_on_free;
    use ibex_tls::conn::tx_pool_cached;
    let mut p = pair();
    p.complete();
    ibex_alloc::drain_local_pools();
    set_thread_ssl_zero_on_free(true);
    assert_eq!(p.srv.write_plain(b"ciphertext-to-keep").expect("write"), 18);
    let hw = p.srv.pending_tx().len();
    let wiped = ibex_alloc::wiped_ssl_fast_bytes();
    p.srv.tx_done(hw);
    assert_eq!(p.srv.tx_capacity(), 0, "released once drained");
    assert_eq!(ibex_alloc::wiped_ssl_fast_bytes(), wiped, "on-free: the give-back does not wipe");
    assert_eq!(tx_pool_cached(), 1, "and the chunk is in the pool");
    ibex_alloc::drain_local_pools();
    assert_eq!(tx_pool_cached(), 0);
    assert!(ibex_alloc::wiped_ssl_fast_bytes() - wiped >= hw, "the pool's free wipes the chunk");
    // `on`: the give-back wipes to the high-water mark, the later free again (cheap, rare).
    set_thread_ssl_zero_on_free(false);
    assert_eq!(p.srv.write_plain(b"ciphertext-to-keep").expect("write"), 18);
    let hw = p.srv.pending_tx().len();
    let wiped = ibex_alloc::wiped_ssl_fast_bytes();
    p.srv.tx_done(hw);
    assert_eq!(ibex_alloc::wiped_ssl_fast_bytes() - wiped, hw, "on: wiped at the give-back");
}

/// `show pools` for `tls_tx`: (allocated, used).
fn tls_tx_line() -> (usize, usize) {
    let dump = ibex_alloc::global_pool_registry().show_pools(&[]);
    let line = dump.lines().find(|l| l.starts_with("  - Pool tls_tx (")).expect("tls_tx listed");
    let num = |after: &str, before: &str| -> usize {
        let s = &line[line.find(after).expect(after) + after.len()..];
        s[..s.find(before).expect(before)].trim().parse().expect("number")
    };
    (num(") : ", " allocated"), num("bytes), ", " used"))
}

/// With this thread's cache empty, the session's first take is a miss that builds a chunk, it works, and it goes back to the pool on release.
#[test]
fn a_take_from_an_empty_pool_builds_a_chunk_that_works_and_returns() {
    use ibex_tls::conn::{tx_pool_cached, TX_CAP};
    ibex_tls::conn::register_pools();
    ibex_alloc::drain_local_pools();
    assert_eq!(tx_pool_cached(), 0, "the pool is empty: the take is a miss");
    let mut p = pair(); // the client's ClientHello takes a chunk
    assert!(p.cli.tx_capacity() >= TX_CAP, "a chunk of the pool's size");
    assert_eq!(tx_pool_cached(), 0, "taken, not cached");
    // The counts are the process's (tests of this binary run on other threads): at least ours.
    let (alloc1, used1) = tls_tx_line();
    assert!(alloc1 >= 1 && used1 >= 1, "show pools: allocated {alloc1}, used {used1}");
    let hello = p.cli.pending_tx().to_vec();
    assert!(!hello.is_empty(), "the chunk holds the ClientHello");
    p.sin.extend(&hello, &p.srv);
    p.cli.tx_done(hello.len());
    p.complete();
    assert_eq!(p.send_to_server(b"GET / HTTP/1.1\r\n\r\n"), b"GET / HTTP/1.1\r\n\r\n");
    drop(p);
    assert!(tx_pool_cached() >= 1, "back in the pool");
    let (alloc2, _) = tls_tx_line();
    assert!(alloc2 >= 1, "show pools: kept, not freed");
}
