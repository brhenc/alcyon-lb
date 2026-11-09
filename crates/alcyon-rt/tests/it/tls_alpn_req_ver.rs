// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! TLS front: a client whose ALPN list has nothing in common with the bind's, `req.ver` on
//! an HTTP/2 request, and `ssl_fc_alpn` (T284, VV-7).
//!
//! `HAProxy` 3.5-dev8-885761-29 with `bind ... ssl crt ... alpn h2,http/1.1`:
//! - a client offering only `foo` completes the handshake with no ALPN and is served HTTP/1.1
//!   (`proto=1.1 alpn=`);
//! - `req.ver` is `2.0` on an h2 request (`smp_fetch_rqver` reads the client-side version);
//! - `ssl_fc_alpn` is the negotiated protocol, and no sample (empty in a `lf-string`) when
//!   none was negotiated.
//!
//! `T284_ORACLE=<haproxy path>` runs the same cases against that binary instead of Alcyon.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

struct Fixture {
    port: u16,
    der: Vec<u8>,
    _daemon: Daemon,
}

fn start() -> Fixture {
    let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let pem = format!("{}{}", c.cert.pem(), c.key_pair.serialize_pem());
    let dir = std::env::temp_dir();
    let id = std::process::id();
    let port = common::reserve_port();
    let crt = dir.join(format!("t284_{id}_{port}.pem"));
    std::fs::write(&crt, pem).expect("write pem");
    let cfg = dir.join(format!("t284_{id}_{port}.cfg"));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n  mode http\n  timeout connect 5s\n  timeout client 10s\n  timeout server 10s\n\
             frontend fe\n  bind 127.0.0.1:{port} ssl crt {} alpn h2,http/1.1\n  \
             http-request return status 200 content-type text/plain lf-string \"proto=%[req.ver] alpn=%[ssl_fc_alpn]\"\n",
            crt.display()
        ),
    )
    .expect("write cfg");
    let bin = std::env::var("T284_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(bin)
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "nothing listening on {port}");
        std::thread::sleep(Duration::from_millis(25));
    }
    Fixture { port, der: c.cert.der().to_vec(), _daemon: d }
}

/// A TLS client offering `alpn`; the handshake is completed and the negotiated ALPN returned.
fn connect(f: &Fixture, alpn: &[&str]) -> StreamOwned<ClientConnection, TcpStream> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(f.der.clone())).expect("root");
    let mut cfg = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    let conn = ClientConnection::new(Arc::new(cfg), ServerName::try_from("localhost").expect("name")).expect("conn");
    let sock = TcpStream::connect(("127.0.0.1", f.port)).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
    StreamOwned::new(conn, sock)
}

fn http1(f: &Fixture, alpn: &[&str]) -> (Option<Vec<u8>>, String) {
    let mut tls = connect(f, alpn);
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("handshake and send");
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out);
    let got = tls.conn.alpn_protocol().map(<[u8]>::to_vec);
    let text = String::from_utf8_lossy(&out).into_owned();
    (got, text.rsplit("\r\n\r\n").next().unwrap_or("").to_string())
}

fn frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut v = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, ty, flags];
    v.extend_from_slice(&stream.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn h2_body(f: &Fixture) -> String {
    let mut tls = connect(f, &["h2"]);
    let mut req = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    req.extend(frame(4, 0, 0, &[]));
    let mut hdrs = vec![0x82, 0x87, 0x84, 0x01, 9];
    hdrs.extend_from_slice(b"localhost");
    req.extend(frame(1, 0x05, 1, &hdrs));
    tls.write_all(&req).expect("send");
    let mut body = Vec::new();
    'frames: loop {
        let mut h = [0u8; 9];
        if tls.read_exact(&mut h).is_err() {
            break;
        }
        let len = (usize::from(h[0]) << 16) | (usize::from(h[1]) << 8) | usize::from(h[2]);
        let mut p = vec![0u8; len];
        if tls.read_exact(&mut p).is_err() {
            break;
        }
        match h[3] {
            4 if h[4] & 1 == 0 => {
                let _ = tls.write_all(&frame(4, 1, 0, &[]));
            }
            0 => {
                body.extend_from_slice(&p);
                if h[4] & 1 != 0 {
                    break 'frames;
                }
            }
            7 => break,
            _ => {}
        }
    }
    String::from_utf8_lossy(&body).into_owned()
}

#[test]
fn unknown_alpn_only_client_is_served_http11_without_alpn() {
    let f = start();
    for offered in [&["foo"][..], &["http/1.0", "spdy/3.1"][..]] {
        let (alpn, body) = http1(&f, offered);
        assert_eq!(alpn, None, "offered {offered:?}");
        assert_eq!(body, "proto=1.1 alpn=", "offered {offered:?}");
    }
}

#[test]
fn ssl_fc_alpn_is_the_negotiated_protocol() {
    let f = start();
    assert_eq!(http1(&f, &["http/1.1"]), (Some(b"http/1.1".to_vec()), "proto=1.1 alpn=http/1.1".into()));
    assert_eq!(http1(&f, &["foo", "http/1.1"]), (Some(b"http/1.1".to_vec()), "proto=1.1 alpn=http/1.1".into()));
    assert_eq!(http1(&f, &[]), (None, "proto=1.1 alpn=".into()));
}

#[test]
fn req_ver_is_2_0_on_an_h2_request() {
    let f = start();
    assert_eq!(h2_body(&f), "proto=2.0 alpn=h2");
}
