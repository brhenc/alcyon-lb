// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T320: show info SSL counters

use crate::common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Ibex(Child, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Starts ibex on `cfg` (`{sock}` is replaced by the stats socket path), waits for `addrs` and the
/// socket, then lets the readiness probes slide out of the one-second windows and clears the maxima.
fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> (Ibex, String) {
    let dir = std::env::temp_dir().join(format!("qh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg.replace("{sock}", &sock).replace("{dir}", &dir.display().to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let ibex = Ibex(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "ibex did not listen on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(2200));
    cli(&sock, "clear counters");
    (ibex, sock)
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn info(sock: &str) -> HashMap<String, String> {
    cli(sock, "show info").lines().filter_map(|l| l.split_once(": ")).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn num(i: &HashMap<String, String>, k: &str) -> u64 {
    i.get(k).unwrap_or_else(|| panic!("show info has no {k}")).parse().unwrap_or_else(|_| panic!("{k} is not a number: {:?}", i[k]))
}

/// One request on a new connection; the whole raw answer.
fn get(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";

fn http_cfg(global: &str, body: &str) -> String {
    format!(
        "global\n  stats socket {{sock}} level admin\n{global}\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n{body}"
    )
}

fn cert() -> (std::path::PathBuf, rustls::pki_types::CertificateDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let path = std::env::temp_dir().join(format!("qh-ssl-{}.pem", std::process::id()));
    std::fs::write(&path, format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem())).expect("write pem");
    (path, ck.cert.der().clone())
}

type Tls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

fn tls_connect(addr: SocketAddr, cert: &rustls::pki_types::CertificateDer<'static>) -> Tls {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).expect("root");
    let cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(cfg), name).expect("client");
    let tcp = TcpStream::connect(addr).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    rustls::StreamOwned::new(conn, tcp)
}

/// One request; reads until the body `ok` arrived. The connection stays open unless the request closes it.
fn tls_request(tls: &mut Tls, close: bool) -> String {
    let conn = if close { "Connection: close\r\n" } else { "" };
    tls.write_all(format!("GET / HTTP/1.1\r\nHost: localhost\r\n{conn}\r\n").as_bytes()).expect("write");
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while !out.ends_with(b"ok") {
        match tls.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn four(sock: &str) -> [u64; 4] {
    let i = info(sock);
    ["CurrSslConns", "CumSslConns", "SslRate", "MaxSslRate"].map(|k| num(&i, k))
}

#[test]
fn show_info_ssl_counters() {
    let (pem, der) = cert();
    let (a, b) = (common::reserve_addr(), common::reserve_addr());
    let cfg = http_cfg(
        "  nbthread 4\n",
        &format!("frontend fe\n  bind {a}\n  bind {b} ssl crt {}\n  http-request return status 200 content-type text/plain string ok\n", pem.display()),
    );
    let (_ibex, sock) = start("ssl", &cfg, &[a, b]);
    assert_eq!(four(&sock), [0, 0, 0, 0], "at start");

    for _ in 0..10 {
        let mut t = tls_connect(b, &der);
        assert!(tls_request(&mut t, true).starts_with("HTTP/1.1 200"));
    }
    let mut kept = tls_connect(b, &der);
    assert!(tls_request(&mut kept, false).starts_with("HTTP/1.1 200"));
    assert_eq!(four(&sock), [1, 11, 11, 11], "after 10 TLS requests + 1 kept open");

    for _ in 0..5 {
        assert!(get(a, GET).starts_with(b"HTTP/1.1 200"));
    }
    assert_eq!(four(&sock), [1, 11, 11, 11], "plain requests are no TLS connection");

    drop(kept);
    let deadline = Instant::now() + Duration::from_secs(3);
    while four(&sock)[0] != 0 {
        assert!(Instant::now() < deadline, "CurrSslConns stays {}", four(&sock)[0]);
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(four(&sock)[1], 11, "CumSslConns after close");
    cli(&sock, "clear counters");
    let f = four(&sock);
    assert_eq!((f[1], f[3]), (11, 0), "clear counters resets only MaxSslRate");
    let _ = std::fs::remove_file(&pem);
}
