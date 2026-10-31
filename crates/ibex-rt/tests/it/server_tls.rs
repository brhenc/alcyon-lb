// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! TLS towards servers (T113), against the real binary and a real rustls server.
//!
//! Everything asserted here was measured on `HAProxy` 3.5-dev8-885761-29 on 2026-10-03
//! with a python TLS server that logs each handshake (SNI, ALPN, client certificate):
//!
//! * `server s ... ssl verify none` in `mode http`: SNI is the request's Host header
//!   without its port (`req.hdr(host),field(1,:)`, `srv_configure_auto_sni`), no ALPN is
//!   offered, 200; `sni str(explicit.example)` sends that; `no-sni-auto` sends none;
//!   `alpn http/1.1` offers it; in `mode tcp` no SNI is sent;
//! * `ssl verify required ca-file <ca>` with a certificate the CA signed: 200 when the
//!   SNI (the Host) matches the certificate, 503 `SC--` with 3 retries when it does not,
//!   whatever `verifyhost` says (the SNI takes precedence); `sni str(<matching>)` passes
//!   with any Host; `no-sni-auto` with `verifyhost <matching>` passes, with a CN-only
//!   certificate too, and with a mismatching `verifyhost` fails; with neither SNI nor
//!   `verifyhost` the name is not checked; a wrong CA fails; `verify none` ignores
//!   `verifyhost`;
//! * `ssl verify none` towards a plaintext server: 503 `SC--`, the attempts retried;
//! * `crt <client.pem>`: the server sees the client certificate;
//! * checks: `check check-ssl verify none` with `option httpchk` passes over TLS (L7OK);
//!   a plain `check` inherits `ssl` unless it has its own `port`; `check-sni` names the
//!   SNI, else the `http-check send hdr Host` value; a plaintext check against a TLS
//!   server fails; a TLS check against a plaintext server is "Layer6 invalid response,
//!   SSL handshake failure".

use crate::common;

use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca(name: &str) -> Ca {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, name);
    let key = KeyPair::generate().expect("key");
    Ca { cert: params.self_signed(&key).expect("ca"), key }
}

/// A certificate `ca` signed: `sans` as dNSNames (none for CN only), `cn` the subject.
fn leaf(ca: &Ca, sans: &[&str], cn: &str, client: bool) -> (CertificateDer<'static>, PrivateKeyDer<'static>, String) {
    let mut params = CertificateParams::new(sans.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()).expect("params");
    params.distinguished_name.push(DnType::CommonName, cn);
    if client {
        params.extended_key_usages.push(ExtendedKeyUsagePurpose::ClientAuth);
    }
    let key = KeyPair::generate().expect("key");
    let cert = params.signed_by(&key, &ca.cert, &ca.key).expect("sign");
    let pem = format!("{}{}", cert.pem(), key.serialize_pem());
    (cert.der().clone(), PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())), pem)
}

/// What one TLS handshake on the test server carried.
#[derive(Debug, Clone)]
struct Seen {
    sni: Option<String>,
    alpn: Option<Vec<u8>>,
    client_cert: bool,
    requests: usize,
    /// The PROXY v2 header that preceded the handshake, in plaintext, when the server
    /// expects one (`accept-proxy`).
    proxy_v2: Option<Vec<u8>>,
}

/// The PROXY protocol v2 signature.
const PP2_SIG: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

/// Reads a PROXY v2 header off the raw socket, as `accept-proxy` does before TLS.
fn read_proxy_v2(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut head = [0u8; 16];
    s.read_exact(&mut head).ok()?;
    if &head[..12] != PP2_SIG {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([head[14], head[15]]));
    let mut rest = vec![0u8; len];
    s.read_exact(&mut rest).ok()?;
    let mut all = head.to_vec();
    all.extend_from_slice(&rest);
    Some(all)
}

struct Server {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    fn handshakes(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

fn server_config(cert: &CertificateDer<'static>, key: &PrivateKeyDer<'static>, client_ca: Option<&Ca>, alpn: &[&str]) -> Arc<ServerConfig> {
    let builder = ServerConfig::builder();
    let builder = if let Some(ca) = client_ca {
        let mut roots = RootCertStore::empty();
        roots.add(ca.cert.der().clone()).expect("root");
        builder.with_client_cert_verifier(WebPkiClientVerifier::builder(Arc::new(roots)).build().expect("client verifier"))
    } else {
        builder.with_no_client_auth()
    };
    let mut cfg = builder.with_single_cert(vec![cert.clone()], key.clone_key()).expect("server config");
    cfg.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Arc::new(cfg)
}

fn read_request(r: &mut impl Read) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) | Err(_) => return None,
            Ok(_) => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    return Some(buf);
                }
            }
        }
    }
}

/// A TLS (or, with `None`, plaintext) HTTP server that answers 200 to every request on
/// a kept-alive connection and records each handshake.
fn serve(cfg: Option<Arc<ServerConfig>>) -> Server {
    serve_with(cfg, false)
}

/// [`serve`], expecting a PROXY v2 header in plaintext before the TLS handshake when
/// `accept_proxy` is set, as `bind ... ssl accept-proxy` does.
fn serve_with(cfg: Option<Arc<ServerConfig>>, accept_proxy: bool) -> Server {
    serve_opts(cfg, accept_proxy, false)
}

/// [`serve_with`]; with `close_after_one`, a TLS connection is ended (`close_notify`, then
/// FIN) 50 ms after its first response, as a server with a keep-alive limit of one does.
fn serve_opts(cfg: Option<Arc<ServerConfig>>, accept_proxy: bool, close_after_one: bool) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = Arc::clone(&seen);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let cfg = cfg.clone();
            let seen = Arc::clone(&seen2);
            thread::spawn(move || {
                stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
                let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                let proxy_v2 = if accept_proxy {
                    let Some(h) = read_proxy_v2(&mut stream) else { return };
                    Some(h)
                } else {
                    None
                };
                match cfg {
                    Some(cfg) => {
                        let mut conn = ServerConnection::new(cfg).expect("conn");
                        let mut tls = rustls::Stream::new(&mut conn, &mut stream);
                        // Record the handshake as soon as it completes: a bare connect
                        // check sends no request, and still counts.
                        while tls.conn.is_handshaking() {
                            if tls.conn.complete_io(tls.sock).is_err() {
                                return;
                            }
                        }
                        let idx = {
                            let mut s = seen.lock().unwrap();
                            s.push(Seen {
                                sni: tls.conn.server_name().map(str::to_string),
                                alpn: tls.conn.alpn_protocol().map(<[u8]>::to_vec),
                                client_cert: tls.conn.peer_certificates().is_some_and(|c| !c.is_empty()),
                                requests: 0,
                                proxy_v2,
                            });
                            s.len() - 1
                        };
                        while read_request(&mut tls).is_some() {
                            seen.lock().unwrap()[idx].requests += 1;
                            if tls.write_all(reply).is_err() {
                                break;
                            }
                            if close_after_one {
                                let _ = tls.flush();
                                thread::sleep(Duration::from_millis(50));
                                break;
                            }
                        }
                        tls.conn.send_close_notify();
                        let _ = tls.flush();
                    }
                    None => {
                        // Plaintext: answer whatever arrives, at once, as a web server does.
                        let mut buf = [0u8; 4096];
                        if matches!(stream.read(&mut buf), Ok(n) if n > 0) {
                            let _ = stream.write_all(reply);
                        }
                    }
                }
            });
        }
    });
    Server { addr, seen }
}

struct Ibex(Child);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 500ms\n  timeout client 3s\n  timeout server 3s\n";

/// Starts ibex on `cfg` (written to `dir`) and waits for `fronts` to listen.
fn start(dir: &TempDir, cfg: &str, fronts: &[SocketAddr]) -> Ibex {
    let path = dir.path().join("ibex.cfg");
    std::fs::write(&path, cfg).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex(child);
    for &addr in fronts {
        assert!(common::wait_listening(addr), "ibex never listened on {addr}");
    }
    ibex
}

/// `ibex -c` on `cfg`: the exit code and everything it printed.
fn check(dir: &TempDir, cfg: &str) -> (Option<i32>, String) {
    let path = dir.path().join("check.cfg");
    std::fs::write(&path, cfg).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("run ibex -c");
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

/// One frontend per backend, so a test can reach each server line through its own port.
fn config(backends: &[(SocketAddr, &str)]) -> String {
    let mut cfg = String::from(DEFAULTS);
    for (i, (front, lines)) in backends.iter().enumerate() {
        cfg.push_str(&format!("frontend f{i}\n  bind {front}\n  default_backend b{i}\nbackend b{i}\n{lines}\n"));
    }
    cfg
}

/// One request on its own connection: the status, and the body.
fn get(front: SocketAddr, host: &str) -> (u16, String) {
    let mut s = TcpStream::connect(front).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    write!(s, "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out).into_owned();
    let status = text.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

/// `n` requests on one kept-alive client connection, with `hosts[i]` as the Host.
fn get_keepalive(front: SocketAddr, hosts: &[&str]) -> Vec<u16> {
    let mut s = TcpStream::connect(front).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut statuses = Vec::new();
    for (i, host) in hosts.iter().enumerate() {
        let close = if i + 1 == hosts.len() { "Connection: close\r\n" } else { "" };
        write!(s, "GET / HTTP/1.1\r\nHost: {host}\r\n{close}\r\n").expect("write");
        // Each response is `Content-Length: 2`, so read its head and two bytes.
        let head = read_request(&mut s).expect("response head");
        let text = String::from_utf8_lossy(&head).into_owned();
        statuses.push(text.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0));
        let mut body = [0u8; 2];
        let _ = s.read_exact(&mut body);
    }
    statuses
}

fn wait_for(deadline: Duration, mut ok: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + deadline;
    while Instant::now() < end {
        if ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    ok()
}

/// A CA, a server certificate for `backend.example.com` it signed, and the CA's PEM on disk.
struct Pki {
    dir: TempDir,
    ca: Ca,
    ca_pem: String,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn pki() -> Pki {
    let dir = TempDir::new().expect("tmp");
    let ca = make_ca("T113 Root");
    let ca_pem = dir.path().join("ca.pem");
    std::fs::write(&ca_pem, ca.cert.pem()).expect("write ca");
    let (cert, key, _) = leaf(&ca, &["backend.example.com"], "other.example.com", false);
    Pki { ca_pem: ca_pem.display().to_string(), dir, ca, cert, key }
}

#[test]
fn ssl_verify_none_reaches_the_server_with_the_host_as_sni_and_no_alpn() {
    let p = pki();
    let srv = serve(Some(server_config(&p.cert, &p.key, None, &["h2", "http/1.1"])));
    let front = common::reserve_addr();
    let _ibex = start(&p.dir, &config(&[(front, &format!("  server s {} ssl verify none", srv.addr))]), &[front]);

    let (status, body) = get(front, "www.test1.com:8080");
    assert_eq!((status, body.as_str()), (200, "ok"), "the request must reach the TLS server");
    let seen = srv.handshakes();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].sni.as_deref(), Some("www.test1.com"), "HAProxy sends the Host header, port stripped, as SNI");
    assert_eq!(seen[0].alpn, None, "HAProxy offers no ALPN without `alpn`");
    assert!(!seen[0].client_cert);
}

#[test]
fn sni_expression_no_sni_auto_alpn_and_tcp_mode() {
    let p = pki();
    let srv = serve(Some(server_config(&p.cert, &p.key, None, &["h2", "http/1.1"])));
    let fronts: Vec<SocketAddr> = (0..4).map(|_| common::reserve_addr()).collect();
    let mut cfg = config(&[
        (fronts[0], &format!("  server s {} ssl verify none sni str(explicit.example)", srv.addr)),
        (fronts[1], &format!("  server s {} ssl verify none no-sni-auto", srv.addr)),
        (fronts[2], &format!("  server s {} ssl verify none alpn http/1.1", srv.addr)),
    ]);
    cfg.push_str(&format!("listen t\n  mode tcp\n  bind {}\n  server s {} ssl verify none\n", fronts[3], srv.addr));
    let _ibex = start(&p.dir, &cfg, &fronts);

    assert_eq!(get(fronts[0], "www.test1.com").0, 200);
    assert_eq!(get(fronts[1], "www.test1.com").0, 200);
    assert_eq!(get(fronts[2], "www.test1.com").0, 200);
    assert_eq!(get(fronts[3], "www.test1.com").0, 200, "mode tcp");
    // `start` probes each listener with a connect and close. On the `mode tcp` listener the
    // probe is forwarded and may reach the server as a handshake with no request; HAProxy
    // completes one for every probe (20 of 20 measured), Ibex usually not. Count the
    // handshakes that carried a request.
    let mut seen = srv.handshakes();
    seen.retain(|s| s.requests > 0);
    assert_eq!(seen.len(), 4, "{seen:?}");
    assert_eq!(seen[0].sni.as_deref(), Some("explicit.example"), "`sni str(...)`");
    assert_eq!(seen[1].sni, None, "`no-sni-auto`");
    assert_eq!(seen[2].alpn.as_deref(), Some(&b"http/1.1"[..]), "`alpn http/1.1`");
    assert_eq!(seen[3].sni, None, "mode tcp has no Host header to send");
}

#[test]
fn verify_required_checks_the_chain_and_the_name_as_haproxy_does() {
    let p = pki();
    let srv = serve(Some(server_config(&p.cert, &p.key, None, &[])));
    let (cn_cert, cn_key, _) = leaf(&p.ca, &[], "backend.example.com", false);
    let cn_srv = serve(Some(server_config(&cn_cert, &cn_key, None, &[])));
    let other = make_ca("Another Root");
    let other_pem = p.dir.path().join("other.pem");
    std::fs::write(&other_pem, other.cert.pem()).expect("write");
    let other_pem = other_pem.display().to_string();
    let ca = &p.ca_pem;
    let a = srv.addr;
    let fronts: Vec<SocketAddr> = (0..8).map(|_| common::reserve_addr()).collect();
    let cfg = config(&[
        (fronts[0], &format!("  server s {a} ssl verify required ca-file {ca}")),
        (fronts[1], &format!("  server s {a} ssl verify required ca-file {ca} verifyhost backend.example.com")),
        (fronts[2], &format!("  server s {a} ssl verify required ca-file {ca} no-sni-auto")),
        (fronts[3], &format!("  server s {a} ssl verify required ca-file {ca} sni str(backend.example.com)")),
        (fronts[4], &format!("  server s {} ssl verify required ca-file {ca} verifyhost backend.example.com no-sni-auto", cn_srv.addr)),
        (fronts[5], &format!("  server s {a} ssl verify required ca-file {ca} verifyhost other.example.com no-sni-auto")),
        (fronts[6], &format!("  server s {a} ssl verify required ca-file {other_pem}")),
        (fronts[7], &format!("  server s {a} ssl verify none verifyhost other.example.com no-sni-auto")),
    ]);
    let _ibex = start(&p.dir, &cfg, &fronts);

    let m = "backend.example.com";
    let x = "mismatch.example";
    assert_eq!(get(fronts[0], m).0, 200, "auto SNI matching the certificate");
    assert_eq!(get(fronts[0], x).0, 503, "auto SNI mismatching: HAProxy fails the connection");
    assert_eq!(get(fronts[1], m).0, 200);
    assert_eq!(get(fronts[1], x).0, 503, "the SNI sent takes precedence over `verifyhost`");
    assert_eq!(get(fronts[2], x).0, 200, "no SNI, no verifyhost: the name is not checked");
    assert_eq!(get(fronts[3], x).0, 200, "`sni str(<matching>)` with any Host");
    assert_eq!(get(fronts[4], x).0, 200, "a CN-only certificate against a matching `verifyhost`");
    assert_eq!(get(fronts[5], m).0, 503, "a mismatching `verifyhost` with no SNI");
    assert_eq!(get(fronts[6], m).0, 503, "a CA that did not sign the certificate");
    assert_eq!(get(fronts[7], m).0, 200, "`verify none` ignores `verifyhost`");
}

#[test]
fn a_plaintext_server_behind_ssl_is_a_connect_failure() {
    let p = pki();
    let plain = serve(None);
    let front = common::reserve_addr();
    let _ibex = start(&p.dir, &config(&[(front, &format!("  server s {} ssl verify none", plain.addr))]), &[front]);
    let (status, _) = get(front, "www.test1.com");
    assert_eq!(status, 503, "HAProxy: 503, `SC--`, after retrying");
}

#[test]
fn a_client_certificate_is_presented_with_crt() {
    let p = pki();
    let client_ca = make_ca("Client CA");
    let (_, _, client_pem) = leaf(&client_ca, &[], "client1", true);
    let crt = p.dir.path().join("client.pem");
    std::fs::write(&crt, client_pem).expect("write");
    let srv = serve(Some(server_config(&p.cert, &p.key, Some(&client_ca), &[])));
    let fronts = [common::reserve_addr(), common::reserve_addr()];
    let cfg = config(&[
        (fronts[0], &format!("  server s {} ssl verify none crt {}", srv.addr, crt.display())),
        (fronts[1], &format!("  server s {} ssl verify none", srv.addr)),
    ]);
    let _ibex = start(&p.dir, &cfg, &fronts);
    assert_eq!(get(fronts[0], "www.test1.com").0, 200);
    assert!(srv.handshakes()[0].client_cert, "the server must have seen the client certificate");
    // Measured: the TLS 1.3 handshake completes on the client's side before the server's
    // `certificate_required` alert arrives, so HAProxy logs it as a server that hung up
    // ("0/0/4/-1/4 502 ... SH--"), not as a failed connect.
    assert_eq!(get(fronts[1], "www.test1.com").0, 502, "without `crt` the server refuses: HAProxy answers 502 SH");
}

#[test]
fn health_checks_follow_ssl_and_check_ssl() {
    let p = pki();
    let srv = serve(Some(server_config(&p.cert, &p.key, None, &[])));
    let srv2 = serve(Some(server_config(&p.cert, &p.key, None, &[])));
    let srv3 = serve(Some(server_config(&p.cert, &p.key, None, &[])));
    let plain = serve(None);
    let fronts: Vec<SocketAddr> = (0..5).map(|_| common::reserve_addr()).collect();
    let chk = "inter 100ms fall 1 rise 1";
    let cfg = config(&[
        // check-ssl with an http check: the checks run over TLS, with the Host as SNI.
        (fronts[0], &format!("  option httpchk GET /\n  http-check send hdr Host hc.example\n  server s {} ssl verify none check check-ssl {chk}", srv.addr)),
        // check-sni wins over the Host header; `ssl` is inherited by the check.
        (fronts[1], &format!("  option httpchk GET /\n  http-check send hdr Host hc.example\n  server s {} ssl verify none check check-sni chk.example {chk}", srv2.addr)),
        // a plaintext check against a TLS server: the server goes DOWN.
        (fronts[2], &format!("  option httpchk GET /\n  server s {} check {chk}", srv3.addr)),
        // a TLS check against a plaintext server: DOWN too.
        (fronts[3], &format!("  server s {} check check-ssl verify none {chk}", plain.addr)),
        // `port`: the check is plaintext on that port while the traffic is TLS.
        (fronts[4], &format!("  server s {} ssl verify none check port {} {chk}", srv.addr, plain.addr.port())),
    ]);
    let _ibex = start(&p.dir, &cfg, &fronts);

    assert!(wait_for(Duration::from_secs(3), || srv.count() >= 2), "checks over TLS: {:?}", srv.handshakes());
    let seen = srv.handshakes();
    assert_eq!(seen[0].sni.as_deref(), Some("hc.example"), "the http-check Host header is the check's SNI");
    assert_eq!(get(fronts[0], "www.test1.com").0, 200, "the server is UP");

    assert!(wait_for(Duration::from_secs(3), || srv2.count() >= 2));
    assert_eq!(srv2.handshakes()[0].sni.as_deref(), Some("chk.example"), "`check-sni`");

    assert!(wait_for(Duration::from_secs(3), || get(fronts[2], "x").0 == 503), "a plaintext check must take the TLS server DOWN");
    assert!(wait_for(Duration::from_secs(3), || get(fronts[3], "x").0 == 503), "a TLS check must take the plaintext server DOWN");
    thread::sleep(Duration::from_millis(400));
    assert_eq!(get(fronts[4], "www.test1.com").0, 200, "a plaintext check on `port` keeps the TLS server UP");
}

#[test]
fn tls_server_connections_are_reused_per_sni() {
    let p = pki();
    let srv = serve(Some(server_config(&p.cert, &p.key, None, &[])));
    let front = common::reserve_addr();
    let _ibex = start(&p.dir, &config(&[(front, &format!("  http-reuse always\n  server s {} ssl verify none", srv.addr))]), &[front]);

    // Two requests on one client connection, same Host: one handshake.
    assert_eq!(get_keepalive(front, &["a.example", "a.example"]), [200, 200]);
    assert!(wait_for(Duration::from_secs(1), || srv.handshakes().first().is_some_and(|s| s.requests == 2)), "{:?}", srv.handshakes());
    assert_eq!(srv.count(), 1, "{:?}", srv.handshakes());
    // A new client connection with the same Host: the idle TLS connection is reused.
    assert_eq!(get(front, "a.example").0, 200);
    thread::sleep(Duration::from_millis(100));
    assert_eq!(srv.count(), 1, "the pooled connection (SNI a.example) must be reused: {:?}", srv.handshakes());
    // A different Host is a different SNI: HAProxy keys idle connections by it.
    assert_eq!(get(front, "b.example").0, 200);
    assert!(wait_for(Duration::from_secs(1), || srv.count() == 2), "{:?}", srv.handshakes());
    assert_eq!(srv.handshakes()[1].sni.as_deref(), Some("b.example"));
}

/// T538. The automatic SNI of a request whose Host is an IP address (`127.0.0.1:<port>`, what
/// `curl http://127.0.0.1:<port>/` sends) is that address: `HAProxy` 3.5-dev8 sends it in SNI
/// (OpenSSL does) and keys the connection by it; rustls sends no SNI for an address. The
/// connection must still be keyed by the name the expression gave, or no request ever finds
/// it again. Measured on `HAProxy` 3.5-dev8 (`/tmp/t538/rig`, 2026-10-31), Host
/// `127.0.0.1:<port>`: three requests on one client connection, 1 server connection (Ibex
/// before T538: 3); then five clients one after the other, `safe` 5 and `aggressive`/`always` 1
/// (Ibex before: 5 under every mode); Host `127.0.0.1` twice then `127.0.0.2`, `always`: 2.
#[test]
fn a_tls_connection_whose_sni_is_an_ip_address_is_kept_for_the_next_request() {
    let p = pki();
    let srv = serve(Some(server_config(&p.cert, &p.key, None, &[])));
    let front = common::reserve_addr();
    let _ibex = start(&p.dir, &config(&[(front, &format!("  server s {} ssl verify none", srv.addr))]), &[front]);
    let host = front.to_string();
    assert_eq!(get_keepalive(front, &[&host, &host, &host]), [200, 200, 200]);
    assert!(wait_for(Duration::from_secs(1), || srv.handshakes().first().is_some_and(|s| s.requests == 3)), "{:?}", srv.handshakes());
    assert_eq!(srv.count(), 1, "one server connection for one client's three requests, as HAProxy: {:?}", srv.handshakes());
    assert_eq!(srv.handshakes()[0].sni, None, "rustls sends no SNI for an address");
}

#[test]
fn an_idle_tls_connection_whose_sni_is_an_ip_address_follows_the_reuse_mode() {
    let p = pki();
    let (safe, aggressive) = (serve(Some(server_config(&p.cert, &p.key, None, &[]))), serve(Some(server_config(&p.cert, &p.key, None, &[]))));
    let fronts = [common::reserve_addr(), common::reserve_addr()];
    let cfg = config(&[
        (fronts[0], &format!("  http-reuse safe\n  server s {} ssl verify none", safe.addr)),
        (fronts[1], &format!("  http-reuse aggressive\n  server s {} ssl verify none", aggressive.addr)),
    ]);
    let _ibex = start(&p.dir, &cfg, &fronts);
    // Two requests on one client connection make it one that was reused (safe), then two
    // clients of one request each: the rig's `ka3` then `seq5`, which HAProxy serves on
    // 6 connections under `safe` and 1 under `aggressive`.
    for &front in &fronts {
        assert_eq!(get_keepalive(front, &["127.0.0.1", "127.0.0.1"]), [200, 200]);
    }
    thread::sleep(Duration::from_millis(150));
    for _ in 0..2 {
        assert_eq!(get(fronts[0], "127.0.0.1").0, 200);
        assert_eq!(get(fronts[1], "127.0.0.1").0, 200);
        thread::sleep(Duration::from_millis(150));
    }
    assert_eq!(safe.count(), 3, "`safe`: a first request does not take an idle connection: {:?}", safe.handshakes());
    assert_eq!(aggressive.count(), 1, "`aggressive`: the idle TLS connection, reused once, is taken again: {:?}", aggressive.handshakes());
}

#[test]
fn tls_connections_for_two_ip_address_hosts_are_not_shared() {
    let p = pki();
    let srv = serve(Some(server_config(&p.cert, &p.key, None, &[])));
    let front = common::reserve_addr();
    let _ibex = start(&p.dir, &config(&[(front, &format!("  http-reuse always\n  server s {} ssl verify none", srv.addr))]), &[front]);
    for host in ["127.0.0.1", "127.0.0.1", "127.0.0.2"] {
        assert_eq!(get(front, host).0, 200);
        thread::sleep(Duration::from_millis(150));
    }
    assert_eq!(srv.count(), 2, "127.0.0.1 shares its connection, 127.0.0.2 gets its own, as HAProxy: {:?}", srv.handshakes());
}

/// The connection the server ended while it was idle is not taken again (T434, T516): each
/// client is answered, on a new connection. `HAProxy`: the same (`idle_conn_events.rs`).
#[test]
fn an_ip_address_sni_connection_its_server_ended_while_idle_is_not_reused() {
    let p = pki();
    let srv = serve_opts(Some(server_config(&p.cert, &p.key, None, &[])), false, true);
    let front = common::reserve_addr();
    let _ibex = start(&p.dir, &config(&[(front, &format!("  http-reuse always\n  server s {} ssl verify none", srv.addr))]), &[front]);
    for _ in 0..3 {
        assert_eq!(get(front, "127.0.0.1").0, 200);
        thread::sleep(Duration::from_millis(300));
    }
    assert_eq!(srv.count(), 3, "{:?}", srv.handshakes());
}

#[test]
fn ibex_c_opens_the_ca_file_and_the_crt_and_parses_the_sni_expression() {
    let p = pki();
    let (code, text) = check(&p.dir, &format!("{DEFAULTS}backend b\n  server s 127.0.0.1:443 ssl verify required ca-file /nonexistent/ca.pem\n"));
    assert_ne!(code, Some(0), "HAProxy: Couldn't open the ca-file '/nonexistent/ca.pem'\n{text}");
    assert!(text.contains("/nonexistent/ca.pem"), "{text}");
    let (code, text) = check(&p.dir, &format!("{DEFAULTS}backend b\n  server s 127.0.0.1:443 ssl verify none crt /nonexistent/client.pem\n"));
    assert_ne!(code, Some(0), "{text}");
    assert!(text.contains("/nonexistent/client.pem"), "{text}");
    let (code, text) = check(&p.dir, &format!("{DEFAULTS}backend b\n  server s 127.0.0.1:443 ssl verify none sni bogus(\n"));
    assert_ne!(code, Some(0), "HAProxy: unknown fetch method 'bogus'\n{text}");
    assert!(text.contains("bogus"), "{text}");
    let (code, text) = check(&p.dir, &format!("{DEFAULTS}backend b\n  server s 127.0.0.1:443 ssl verify required ca-file {} sni str(x) alpn h2,http/1.1 check check-sni y\n", p.ca_pem));
    assert_eq!(code, Some(0), "{text}");
}

/// Accepts connections and never answers: a TLS handshake against it hangs until the
/// check's timeout (`L6TOUT`, as HAProxy reports a handshake that times out).
fn serve_silent() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let Ok(s) = stream else { break };
            held.push(s);
        }
    });
    addr
}

/// A backend with one TLS server and one plaintext server: each connection takes the
/// transport of its own server line, and the pool keys them apart.
#[test]
fn a_backend_mixes_tls_and_plaintext_servers() {
    let p = pki();
    let tls = serve(Some(server_config(&p.cert, &p.key, None, &[])));
    let plain = serve(None);
    let front = common::reserve_addr();
    let cfg = config(&[(
        front,
        &format!("  balance roundrobin\n  server a {} ssl verify none\n  server b {}", tls.addr, plain.addr),
    )]);
    let _ibex = start(&p.dir, &cfg, &[front]);
    let statuses: Vec<u16> = (0..4).map(|_| get(front, "www.test1.com").0).collect();
    assert_eq!(statuses, [200, 200, 200, 200]);
    // Two of the four reached the TLS server -- over one pooled connection, as the idle
    // pool keeps TLS connections per server line.
    assert!(
        wait_for(Duration::from_secs(1), || tls.handshakes().iter().map(|h| h.requests).sum::<usize>() == 2),
        "two of the four went to the TLS server: {:?}",
        tls.handshakes()
    );
}

/// The other check shapes over TLS: a bare connect check passes at layer 6, a tcp-check
/// script runs over the TLS connection, an HTTP check against a plaintext server fails
/// the handshake (L6RSP), and a server that accepts and never answers times the
/// handshake out (L6TOUT). HAProxy measured: "Layer6 check passed", "Layer6 invalid
/// response, SSL handshake failure".
#[test]
fn check_shapes_over_tls() {
    let p = pki();
    let srv = serve(Some(server_config(&p.cert, &p.key, None, &[])));
    let srv2 = serve(Some(server_config(&p.cert, &p.key, None, &[])));
    let plain = serve(None);
    let silent = serve_silent();
    let fronts: Vec<SocketAddr> = (0..7).map(|_| common::reserve_addr()).collect();
    let ca = &p.ca_pem;
    // The check results, as `option log-health-checks` reports them (HAProxy's words,
    // measured: "Layer6 check passed", "Layer6 invalid response, info: \"SSL handshake
    // failure\"", "Layer6 timeout").
    let syslog = std::net::UdpSocket::bind("127.0.0.1:0").expect("udp");
    syslog.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let log = format!("  log 127.0.0.1:{} local0\n  option log-health-checks\n", syslog.local_addr().unwrap().port());
    let chk = "inter 100ms fall 1 rise 1";
    let cfg = config(&[
        (fronts[0], &format!("{log}  server s {} ssl verify none check {chk}", srv.addr)),
        (fronts[1], &format!("{log}  option tcp-check\n  tcp-check connect\n  tcp-check send \"GET / HTTP/1.1\\r\\nHost: tc.example\\r\\n\\r\\n\"\n  tcp-check expect string 200\n  server s {} ssl verify none check {chk}", srv2.addr)),
        (fronts[2], &format!("{log}  option httpchk GET /\n  server s {} ssl verify none check {chk}", plain.addr)),
        (fronts[3], &format!("{log}  timeout check 150ms\n  server s {} ssl verify none check {chk}", silent)),
        // A protocol check over TLS drives the handshake from its own connect state.
        (fronts[4], &format!("{log}  option redis-check\n  server s {} ssl verify none check {chk}", plain.addr)),
        // A bare tcp-check connect is a layer-4 pass.
        (fronts[6], &format!("{log}  option tcp-check\n  tcp-check connect\n  server s {} check {chk}", plain.addr)),
        // A certificate the name check refuses is reported apart (HAProxy's
        // `conn_err_code_str`, measured on 3.5-dev8).
        (fronts[5], &format!("{log}  server s {} ssl verify required ca-file {ca} verifyhost other.example.com no-sni-auto check {chk}", srv.addr)),
    ]);
    let _ibex = start(&p.dir, &cfg, &fronts);

    assert!(wait_for(Duration::from_secs(3), || srv.count() >= 2), "L6 connect checks: {:?}", srv.handshakes());
    assert_eq!(get(fronts[0], "www.test1.com").0, 200, "a connect check over TLS keeps the server UP");
    assert!(wait_for(Duration::from_secs(3), || srv2.handshakes().iter().any(|h| h.requests >= 1)), "tcp-check over TLS: {:?}", srv2.handshakes());
    assert_eq!(get(fronts[1], "www.test1.com").0, 200, "the tcp-check script passed over TLS");
    assert!(wait_for(Duration::from_secs(3), || get(fronts[2], "x").0 == 503), "an http check over TLS against plaintext takes the server DOWN");
    assert!(wait_for(Duration::from_secs(3), || get(fronts[3], "x").0 == 503), "a handshake that never completes times out and takes the server DOWN");

    // The reasons, from the log lines.
    let mut lines = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut buf = [0u8; 2048];
    let want = |lines: &[String]| {
        [
            "Layer6 invalid response, info: \"SSL handshake failure\"",
            "Layer6 timeout",
            "Layer4 check passed, info: \"(tcp-check)\"",
            "Layer7 check passed, code: 0, info: \"(tcp-check)\"",
            "Layer6 invalid response, info: \"Server presented an SSL certificate different from the configured one\"",
        ]
            .iter()
            .all(|w| lines.iter().any(|l| l.contains(w)))
    };
    while Instant::now() < deadline && !want(&lines) {
        if let Ok((n, _)) = syslog.recv_from(&mut buf) {
            lines.push(String::from_utf8_lossy(&buf[..n]).into_owned());
        }
    }
    assert!(want(&lines), "the check reasons must be HAProxy's:\n{}", lines.join("\n"));
    assert!(
        !lines.iter().any(|l| l.contains("b0/s") && l.contains("DOWN")),
        "the connect check over TLS must not take its server down:\n{}",
        lines.join("\n")
    );
}

/// `send-proxy-v2` with `ssl`: the PROXY header goes on the wire in plaintext before the
/// ClientHello, as `HAProxy`'s `xprt_handshake` layer sends it under `ssl_sock` -- the
/// peer is `bind ... ssl accept-proxy`, which reads it before its own handshake
/// (`reg-tests/connection/proxy_protocol_send_unique_id_alpn.vtc`). The unique-id TLV
/// (type 0x05) carries the stream's ID.
#[test]
fn the_proxy_header_precedes_the_tls_handshake() {
    let p = pki();
    let srv = serve_with(Some(server_config(&p.cert, &p.key, None, &[])), true);
    let front = common::reserve_addr();
    let cfg = format!(
        "{DEFAULTS}  unique-id-format TEST-%[req.hdr(in)]\nfrontend f\n  bind {front}\n  default_backend b\nbackend b\n  server s {} send-proxy-v2 proxy-v2-options unique-id ssl verify none\n",
        srv.addr
    );
    let _ibex = start(&p.dir, &cfg, &[front]);
    let mut s = TcpStream::connect(front).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    write!(s, "GET / HTTP/1.1\r\nHost: x\r\nin: foo\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    assert!(out.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&out));
    let seen = srv.handshakes();
    assert_eq!(seen.len(), 1, "{seen:?}");
    let hdr = seen[0].proxy_v2.as_deref().expect("a PROXY v2 header before the handshake");
    assert!(hdr.starts_with(PP2_SIG));
    let tlvs = &hdr[16 + 12..]; // v2 header, then the IPv4 addresses, then the TLVs
    assert!(tlvs.windows(3 + 8).any(|w| w[0] == 0x05 && &w[3..3 + 8] == b"TEST-foo"), "unique-id TLV in {tlvs:02x?}");
    assert_eq!(seen[0].sni.as_deref(), Some("x"), "and the handshake came after it");
}

/// The receiving half: `bind ... ssl accept-proxy` reads the PROXY header in plaintext
/// before its own handshake, so an Ibex sender and an Ibex receiver interoperate the way
/// `reg-tests/connection/proxy_protocol_send_unique_id_alpn.vtc` has HAProxy do it, and
/// `fc_pp_unique_id` on the receiver is the sender's unique ID.
#[test]
fn accept_proxy_on_a_tls_bind_reads_the_header_before_the_handshake() {
    let p = pki();
    let (_, _, pem) = leaf(&p.ca, &["backend.example.com"], "x", false);
    let crt = p.dir.path().join("srv.pem");
    std::fs::write(&crt, pem).expect("write");
    let front = common::reserve_addr();
    let recv = common::reserve_addr();
    let cfg = format!(
        "{DEFAULTS}  unique-id-format TEST-%[req.hdr(in)]\n\
         listen sender\n  bind {front}\n  server s {recv} send-proxy-v2 proxy-v2-options unique-id ssl verify none\n\
         listen receiver\n  bind {recv} ssl crt {} accept-proxy\n  http-request set-var(txn.id) fc_pp_unique_id\n  \
         http-after-response set-header x-id %[var(txn.id)]\n  http-request return status 200\n",
        crt.display()
    );
    let _ibex = start(&p.dir, &cfg, &[front, recv]);
    let mut s = TcpStream::connect(front).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    write!(s, "GET / HTTP/1.1\r\nHost: x\r\nin: foo\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.to_ascii_lowercase().contains("x-id: test-foo"), "the receiver must see the unique-id TLV:\n{text}");

    // What arrives raw at that bind and is not a PROXY header is refused, as HAProxy's
    // `conn_recv_proxy` refuses it: bytes that are not a header close the connection;
    // a header that has not fully arrived is refused too; a peer that leaves is let go.
    let mut raw = TcpStream::connect(recv).expect("connect");
    raw.set_read_timeout(Some(Duration::from_secs(3))).ok();
    raw.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("write");
    let mut b = [0u8; 16];
    assert!(matches!(raw.read(&mut b), Ok(0) | Err(_)), "a bind expecting PROXY must close on a request in its place");
    let mut partial = TcpStream::connect(recv).expect("connect");
    partial.set_read_timeout(Some(Duration::from_millis(400))).ok();
    partial.write_all(&PP2_SIG[..8]).expect("write");
    // Measured on HAProxy 3.5-dev8 (T128): half a header is "Truncated PROXY protocol header
    // received", and the connection is closed; `conn_recv_proxy` peeks once.
    assert!(matches!(partial.read(&mut b), Ok(0) | Err(_)), "half a header is refused, not waited for");
    drop(partial);
    drop(TcpStream::connect(recv).expect("connect and leave"));
    thread::sleep(Duration::from_millis(100));
    assert_eq!(get(front, "x").0, 200, "the receiver still serves after those");

    // `accept-proxy-v2`: a v1 header is a complete, valid PROXY header of the wrong
    // version, and is refused before the handshake.
    let strict = common::reserve_addr();
    let cfg = format!(
        "{DEFAULTS}listen strict\n  bind {strict} ssl crt {} accept-proxy-v2\n  http-request return status 200\n",
        crt.display()
    );
    let _ibex2 = start(&p.dir, &cfg, &[strict]);
    let mut v1 = TcpStream::connect(strict).expect("connect");
    v1.set_read_timeout(Some(Duration::from_secs(3))).ok();
    v1.write_all(b"PROXY TCP4 10.0.0.1 10.0.0.2 1234 443\r\n").expect("write");
    assert!(matches!(v1.read(&mut b), Ok(0) | Err(_)), "a v1 header to accept-proxy-v2 must close the connection");
}

/// `-c` refuses what the start refuses: a rule naming a fetch the registry lacks, on a
/// configuration whose TLS is otherwise valid.
#[test]
fn ibex_c_refuses_a_bad_rule_expression_beside_a_valid_tls_server() {
    let p = pki();
    let (code, text) = check(
        &p.dir,
        &format!("{DEFAULTS}backend b\n  http-request set-var(txn.a) nosuchfetch\n  server s 127.0.0.1:443 ssl verify required ca-file {}\n", p.ca_pem),
    );
    assert_ne!(code, Some(0), "{text}");
    assert!(text.contains("nosuchfetch"), "{text}");
}
