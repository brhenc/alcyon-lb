// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T320: `show info` `TotalBytesOut`.

use crate::common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::os::unix::net::UnixStream;
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

#[test]
fn show_info_total_bytes_out() {
    let addr = common::reserve_addr();
    let cfg = http_cfg("  nbthread 4\n", &format!("frontend fe\n  bind {addr}\n  http-request return status 200 content-type text/plain string 0123456789\n"));
    let (_ibex, sock) = start("show_info_total_bytes_out", &cfg, &[addr]);
    let r = get(addr, GET).len();
    let a_text = cli(&sock, "show info");
    let a_map: HashMap<String, String> = a_text.lines().filter_map(|l| l.split_once(": ")).map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let a_total = num(&a_map, "TotalBytesOut");
    for _ in 0..15 {
        let _ = get(addr, GET);
    }
    let b_total = num(&info(&sock), "TotalBytesOut");
    // The first read's own output left after its value was taken; nothing else was sent.
    assert_eq!(b_total - a_total, 15 * r as u64 + a_text.len() as u64, "15 responses of {r} bytes and one show info");
}

/// A backend that counts every byte it receives (requests and health checks) and answers
/// each request with a fixed response.
fn counting_backend() -> (SocketAddr, Arc<AtomicU64>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = l.local_addr().unwrap();
    let got = Arc::new(AtomicU64::new(0));
    let g = got.clone();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let g = g.clone();
            std::thread::spawn(move || {
                let mut c = c;
                c.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut head = Vec::new();
                let mut buf = [0u8; 4096];
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    g.fetch_add(n as u64, Ordering::SeqCst);
                    head.extend_from_slice(&buf[..n]);
                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                        let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789");
                        break;
                    }
                }
            });
        }
    });
    (addr, got)
}

/// Counts the bytes read from the socket under a TLS client: the bytes on the wire.
struct Wire<'a>(&'a mut TcpStream, u64);

impl Read for Wire<'_> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.0.read(b)?;
        self.1 += n as u64;
        Ok(n)
    }
}

impl Write for Wire<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// One request over TLS; the bytes received on the wire, handshake and alerts included.
fn tls_get(addr: SocketAddr, cert: &rustls::pki_types::CertificateDer<'static>) -> u64 {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).expect("root");
    let cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), name).expect("client");
    let mut tcp = TcpStream::connect(addr).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut wire = Wire(&mut tcp, 0);
    let mut out = Vec::new();
    {
        let mut tls = rustls::Stream::new(&mut conn, &mut wire);
        tls.write_all(GET).expect("write");
        let _ = tls.read_to_end(&mut out);
    }
    // Whatever follows the close_notify, up to the FIN.
    let _ = wire.read_to_end(&mut Vec::new());
    assert!(out.starts_with(b"HTTP/1.1 200"), "TLS response: {:?}", String::from_utf8_lossy(&out));
    wire.1
}

/// Measured on `HAProxy` 3.5-dev8 (`raw_sock_from_buf` counts every socket write): over a
/// plain and an `ssl` frontend proxying to a server with `option httpchk` and `check inter
/// 100`, the change of `TotalBytesOut` between two `show info` reads is exactly the bytes
/// the clients received on the wire (TLS records, handshake included: 3 requests gave
/// 9435 to 9499 bytes for 204 plaintext), plus every byte the server received (requests
/// as forwarded and health checks), plus the first read's own output.
#[test]
fn total_bytes_out_counts_wire_bytes_to_clients_servers_and_checks() {
    let (be, got) = counting_backend();
    let plain = common::reserve_addr();
    let tls = common::reserve_addr();
    let dir = tempfile::TempDir::new().expect("tmp");
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let pem = dir.path().join("c.pem");
    std::fs::write(&pem, format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem())).expect("write pem");
    let cert = ck.cert.der().clone();
    let cfg = http_cfg(
        "  nbthread 4\n",
        &format!(
            "frontend fe\n  bind {plain}\n  bind {tls} ssl crt {}\n  default_backend be\n\
             backend be\n  option httpchk GET /chk\n  server s {be} check inter 100\n",
            pem.display()
        ),
    );
    let (_ibex, sock) = start("total_bytes_out_wire", &cfg, &[plain, tls]);
    for kind in ["plain", "tls"] {
        let r0 = got.load(Ordering::SeqCst);
        let a_text = cli(&sock, "show info");
        let r0_after = got.load(Ordering::SeqCst);
        let a_total = num(&a_text.lines().filter_map(|l| l.split_once(": ")).map(|(k, v)| (k.to_string(), v.to_string())).collect(), "TotalBytesOut");
        let client: u64 = (0..3)
            .map(|_| if kind == "plain" { get(plain, GET).len() as u64 } else { tls_get(tls, &cert) })
            .sum();
        std::thread::sleep(Duration::from_millis(300));
        let r1 = got.load(Ordering::SeqCst);
        let b_total = num(&info(&sock), "TotalBytesOut");
        let r2 = got.load(Ordering::SeqCst);
        let rest = (b_total - a_total).checked_sub(client + a_text.len() as u64).unwrap_or_else(|| {
            panic!("{kind}: TotalBytesOut moved {} for {client} bytes to clients and {} of show info", b_total - a_total, a_text.len())
        });
        assert!(
            r1 - r0_after <= rest && rest <= r2 - r0,
            "{kind}: {rest} bytes beyond the clients' and the CLI's, but the server received {}..{}",
            r1 - r0_after,
            r2 - r0
        );
        assert!(r1 > r0_after, "{kind}: the server received nothing");
    }
}
