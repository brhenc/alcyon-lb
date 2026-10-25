// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `BlockingTls` (T461): a rustls 0.24 session over a blocking `Read + Write`, as the log
//! forwarder's `server` lines use it. Over loopback TCP, and over streams that misbehave.

use ibex_tls::blocking::BlockingTls;
use ibex_tls::conn::{TlsCtx, VecInput};
use ibex_tls::tcp::{build_backend_client_config, rustls24, BindTls};
use ibex_tls::BackendTlsOptions;
use rustls24::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

fn bind() -> Arc<BindTls> {
    let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(c.key_pair.serialize_der()));
    BindTls::single(vec![CertificateDer::from(c.cert.der().to_vec())], key, vec![]).expect("bind")
}

fn client_config() -> Arc<rustls24::ClientConfig> {
    let opts = BackendTlsOptions { verify_required: false, ..Default::default() };
    build_backend_client_config(&opts).expect("client config")
}

fn name() -> ServerName<'static> {
    ServerName::try_from("localhost").expect("name")
}

fn provider() -> ibex_tls::TlsCryptoProvider {
    ibex_tls::provider::active()
}

/// A stream that reads from a fixed script and records what is written; `zero_write` makes
/// every write accept nothing.
struct Script {
    rx: io::Cursor<Vec<u8>>,
    tx: Vec<u8>,
    zero_write: bool,
}

impl Script {
    fn new(rx: &[u8], zero_write: bool) -> Self {
        Self { rx: io::Cursor::new(rx.to_vec()), tx: Vec::new(), zero_write }
    }
}

impl Read for Script {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.rx.read(b)
    }
}

impl Write for Script {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.zero_write {
            return Ok(0);
        }
        self.tx.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reads until `n` plaintext bytes are in.
fn read_n<S: Read + Write>(t: &mut BlockingTls<S>, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    let mut got = 0;
    while got < n {
        let k = t.read(&mut out[got..]).expect("read");
        assert!(k > 0, "stream ended after {got} of {n} bytes");
        got += k;
    }
    out
}

#[test]
fn round_trip_over_tcp_ends_with_eof() {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let b = bind();
    let before = ibex_tls::provider::handshakes(provider());
    let srv = std::thread::spawn(move || {
        let (s, _) = l.accept().expect("accept");
        let mut t = BlockingTls::accept(&b, s);
        // Nothing to read into, nothing to write: no handshake, no I/O.
        assert_eq!(t.read(&mut []).expect("empty read"), 0);
        assert_eq!(t.write(&[]).expect("empty write"), 0);
        assert_eq!(read_n(&mut t, 4), b"ping");
        t.write_all(b"pong").expect("write");
        t.flush().expect("flush");
        // The client drops the socket without close_notify: end of stream.
        let mut b = [0u8; 8];
        assert_eq!(t.read(&mut b).expect("eof"), 0);
    });
    let mut c = BlockingTls::connect(&client_config(), provider(), name(), TcpStream::connect(addr).expect("connect")).expect("tls");
    c.write_all(b"ping").expect("write");
    assert_eq!(read_n(&mut c, 4), b"pong");
    drop(c);
    srv.join().expect("server thread");
    assert!(ibex_tls::provider::handshakes(provider()) >= before + 2, "each completed handshake is counted once");
}

#[test]
fn a_large_write_goes_out_in_pieces() {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let b = bind();
    let srv = std::thread::spawn(move || {
        let (s, _) = l.accept().expect("accept");
        let mut t = BlockingTls::accept(&b, s);
        read_n(&mut t, 300_000)
    });
    let mut c = BlockingTls::connect(&client_config(), provider(), name(), TcpStream::connect(addr).expect("connect")).expect("tls");
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    c.write_all(&data).expect("write");
    assert_eq!(srv.join().expect("server thread"), data);
}

#[test]
fn close_notify_reads_as_end_of_stream() {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let b = bind();
    let srv = std::thread::spawn(move || {
        let (s, _) = l.accept().expect("accept");
        let mut t = BlockingTls::accept(&b, s);
        let mut buf = [0u8; 8];
        assert_eq!(t.read(&mut buf).expect("closed"), 0);
    });
    // A hand-driven client: handshake, then close_notify.
    let mut s = TcpStream::connect(addr).expect("connect");
    let mut ctx = TlsCtx::connect(&client_config(), name(), Some("localhost".into()));
    let mut input = VecInput::default();
    while ctx.is_handshaking() {
        let r = ctx.handshake(&mut input);
        s.write_all(ctx.pending_tx()).expect("send");
        let n = ctx.pending_tx().len();
        ctx.tx_done(n);
        r.expect("handshake");
        if ctx.is_handshaking() {
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).expect("recv");
            assert!(n > 0);
            input.extend(&buf[..n], &ctx);
        }
    }
    ctx.close_notify();
    s.write_all(ctx.pending_tx()).expect("send close_notify");
    srv.join().expect("server thread");
}

#[test]
fn garbage_from_the_peer_is_invalid_data() {
    let mut t = BlockingTls::accept(&bind(), Script::new(&[0x16, 0x03, 0x01, 0x00, 0x04, 1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff, 0xff], false));
    let e = t.read(&mut [0u8; 8]).expect_err("garbage");
    assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
}

#[test]
fn a_stream_that_ends_inside_the_handshake_is_unexpected_eof() {
    let mut t = BlockingTls::accept(&bind(), Script::new(&[], false));
    let e = t.write(b"x").expect_err("no hello");
    assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn a_client_whose_stream_takes_no_bytes_is_write_zero() {
    let mut t = BlockingTls::connect(&client_config(), provider(), name(), Script::new(&[], true)).expect("tls");
    let e = t.write(b"x").expect_err("nothing goes out");
    assert_eq!(e.kind(), io::ErrorKind::WriteZero);
}
