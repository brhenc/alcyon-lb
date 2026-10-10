// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `ssl_fc*`, `ssl_c_used` and `ssl_bc*` fetches answer from the TLS session (T150).
//!
//! Nothing set them: on a TLS bind `%[ssl_fc]` gave `0` and the SNI, cipher and protocol
//! headers were empty. Measured with `HAProxy` 3.5-dev8-885761-29, an ECDSA certificate and
//! one client suite at a time:
//!
//! * TLS 1.2 with `ECDHE-ECDSA-AES128-GCM-SHA256` offered: `ssl_fc` 1, `ssl_fc_protocol`
//!   `TLSv1.2`, `ssl_fc_cipher` `ECDHE-ECDSA-AES128-GCM-SHA256` (OpenSSL's name, not IANA's;
//!   that table is unit-tested in `ibex-tls`: this build of rustls has no TLS 1.2 to drive);
//! * TLS 1.3 with `TLS_CHACHA20_POLY1305_SHA256`: `TLSv1.3`, `TLS_CHACHA20_POLY1305_SHA256`;
//! * `ssl_fc_sni` is the name the client sent, and no sample (the header is left out) when it sent none;
//! * on a plain bind: `ssl_fc` 0, the others no sample;
//! * `ssl_c_used` is 0 when the client sent no certificate;
//! * `ssl_fc_version` is not a `HAProxy` fetch: "unknown fetch method";
//! * `ssl_bc` in a request rule is refused at load ("needs 'server-side connection'"; Ibex
//!   does not do that refusal, and answers 0 there); in a response rule over a TLS server it is 1 with `ssl_bc_protocol` `TLSv1.3` and
//!   `ssl_bc_cipher` a `TLS_*` name, over a plain server `ssl_bc` is 0 and the others give
//!   no sample, and `ssl_fc` is 0 on the plain frontend.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;

use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::{CertificateDer, IpAddr, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, Stream, SupportedCipherSuite};

struct Ibex(std::process::Child, #[allow(dead_code)] Vec<NamedTempFile>);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// A certificate for `localhost` and 127.0.0.1 (ECDSA, as rcgen makes it): the combined PEM
/// in a temp file, and the DER for the client to trust.
fn cert() -> (NamedTempFile, CertificateDer<'static>) {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.subject_alt_names.push(rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])));
    let key = rcgen::KeyPair::generate().unwrap();
    let c = params.self_signed(&key).unwrap();
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(format!("{}{}", c.pem(), key.serialize_pem()).as_bytes()).unwrap();
    (f, c.der().clone())
}

fn start(cfg: &str, files: Vec<NamedTempFile>, ports: &[SocketAddr]) -> Ibex {
    let _ = ring::default_provider().install_default();
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(cfg.as_bytes()).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let mut files = files;
    files.push(f);
    let ibex = Ibex(child, files);
    for p in ports {
        assert!(common::wait_listening(*p), "ibex never listened on {p}");
    }
    ibex
}

fn suite(name: &str) -> SupportedCipherSuite {
    let all = ring::default_provider().cipher_suites;
    all.into_iter()
        .find(|s| format!("{:?}", s.suite()) == name)
        .unwrap_or_else(|| panic!("no suite {name}"))
}

/// One GET over TLS offering only `suite` (so the server has no choice) with the SNI of
/// `localhost`, or the address itself (no SNI) when `sni` is false. The response, lowercased.
fn https(addr: SocketAddr, cert: &CertificateDer<'static>, suite: SupportedCipherSuite, sni: bool, path: &str) -> String {
    let provider = Arc::new(CryptoProvider { cipher_suites: vec![suite], ..ring::default_provider() });
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = if sni { ServerName::try_from("localhost").unwrap() } else { ServerName::IpAddress(IpAddr::try_from(addr.ip()).unwrap()) };
    let mut conn = ClientConnection::new(Arc::new(cfg), name).unwrap();
    let mut tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut tls = Stream::new(&mut conn, &mut tcp);
    tls.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = tls.read(&mut buf) {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&out).to_lowercase()
}

fn plain(addr: SocketAddr, path: &str) -> String {
    let mut tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    tcp.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = tcp.read_to_end(&mut out);
    String::from_utf8_lossy(&out).to_lowercase()
}

/// The value of header `name` in a response, or `<none>` when the header is absent: `HAProxy`
/// leaves out a header whose value came out empty, as a fetch with no sample does.
fn hdr(resp: &str, name: &str) -> String {
    resp.lines()
        .find_map(|l| l.strip_prefix(&format!("{name}:")))
        .map_or_else(|| "<none>".to_string(), |v| v.trim().to_string())
}

const FRONT_RULE: &str = "  http-request return status 200 hdr x-fc \"%[ssl_fc]\" hdr x-sni \"%[ssl_fc_sni]\" \
    hdr x-cipher \"%[ssl_fc_cipher]\" hdr x-proto \"%[ssl_fc_protocol]\" hdr x-cused \"%[ssl_c_used]\"\n";

fn frontend_cfg(tls: SocketAddr, plain_addr: SocketAddr, crt: &std::path::Path) -> String {
    format!(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend t\n  bind {tls} ssl crt {}\n{FRONT_RULE}\
         frontend p\n  bind {plain_addr}\n{FRONT_RULE}",
        crt.display()
    )
}

#[test]
fn tls13_frontend_fetches_come_from_the_session() {
    let (crt, der) = cert();
    let (t, p) = (common::reserve_addr(), common::reserve_addr());
    let cfg = frontend_cfg(t, p, crt.path());
    let _ibex = start(&cfg, vec![crt], &[t, p]);
    let r = https(t, &der, suite("TLS13_CHACHA20_POLY1305_SHA256"), true, "/");
    assert_eq!(hdr(&r, "x-fc"), "1", "{r}");
    assert_eq!(hdr(&r, "x-sni"), "localhost", "{r}");
    assert_eq!(hdr(&r, "x-cipher"), "tls_chacha20_poly1305_sha256", "{r}");
    assert_eq!(hdr(&r, "x-proto"), "tlsv1.3", "{r}");
    // A client that sent no server name: no sample, so the header is left out.
    let r = https(t, &der, suite("TLS13_AES_128_GCM_SHA256"), false, "/");
    assert_eq!(hdr(&r, "x-fc"), "1", "{r}");
    assert_eq!(hdr(&r, "x-sni"), "<none>", "{r}");
    assert_eq!(hdr(&r, "x-cipher"), "tls_aes_128_gcm_sha256", "{r}");
}

#[test]
fn plain_frontend_has_no_tls_facts() {
    let (crt, _der) = cert();
    let (t, p) = (common::reserve_addr(), common::reserve_addr());
    let cfg = frontend_cfg(t, p, crt.path());
    let _ibex = start(&cfg, vec![crt], &[t, p]);
    let r = plain(p, "/");
    assert_eq!(hdr(&r, "x-fc"), "0", "{r}");
    assert_eq!(hdr(&r, "x-sni"), "<none>", "{r}");
    assert_eq!(hdr(&r, "x-cipher"), "<none>", "{r}");
    assert_eq!(hdr(&r, "x-proto"), "<none>", "{r}");
    assert_eq!(hdr(&r, "x-cused"), "0", "{r}");
}

#[test]
fn backend_fetches_come_from_the_server_side_session() {
    let (crt, _der) = cert();
    let (up, plain_up, front) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend up\n  bind {up} ssl crt {}\n  http-request return status 200\n\
         frontend plainup\n  bind {plain_up}\n  http-request return status 200\n\
         frontend f\n  bind {front}\n  use_backend bp if {{ path /plain }}\n  default_backend b\n\
         backend b\n  http-response set-header x-bc \"%[ssl_bc]\"\n  http-response set-header x-bcc \"%[ssl_bc_cipher]\"\n\
         \x20 http-response set-header x-bcp \"%[ssl_bc_protocol]\"\n  http-response set-header x-fc \"%[ssl_fc]\"\n\
         \x20 server s {up} ssl verify none\n\
         backend bp\n  http-response set-header x-bc \"%[ssl_bc]\"\n  http-response set-header x-bcc \"%[ssl_bc_cipher]\"\n\
         \x20 server s {plain_up}\n",
        crt.path().display()
    );
    let _ibex = start(&cfg, vec![crt], &[up, plain_up, front]);
    let r = plain(front, "/");
    assert_eq!(hdr(&r, "x-bc"), "1", "{r}");
    assert_eq!(hdr(&r, "x-bcp"), "tlsv1.3", "{r}");
    assert!(hdr(&r, "x-bcc").starts_with("tls_"), "{r}");
    assert_eq!(hdr(&r, "x-fc"), "0", "{r}");
    let r = plain(front, "/plain");
    assert_eq!(hdr(&r, "x-bc"), "0", "{r}");
    // `set-header` with no sample sets the header empty; only `return hdr` leaves it out.
    assert_eq!(hdr(&r, "x-bcc"), "", "{r}");
}

fn refusal(rule: &str) -> String {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, "defaults\n  mode http\n  timeout client 5s\nfrontend f\n  bind 127.0.0.1:0\n  {rule}\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().unwrap();
    assert!(!out.status.success(), "{rule} loaded");
    String::from_utf8_lossy(&out.stderr).to_string()
}

#[test]
fn ssl_fc_version_is_not_a_haproxy_fetch() {
    let e = refusal("http-request set-header x-v \"%[ssl_fc_version]\"");
    assert!(e.contains("unknown fetch method 'ssl_fc_version'"), "{e}");
}

/// Global `ssl-server-verify none` reaches the connection: a `server ... ssl` with no
/// `verify` and no CA file connects to a self-signed server (measured on `HAProxy`: the
/// same config answers 200, and is refused at load without the keyword).
#[test]
fn global_ssl_server_verify_none_makes_the_server_connection_unverified() {
    let (crt, _der) = cert();
    let (up, front) = (common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "global\n  ssl-server-verify none\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend up\n  bind {up} ssl crt {}\n  http-request return status 200 string up\n\
         frontend f\n  bind {front}\n  default_backend b\n\
         backend b\n  server s {up} ssl\n",
        crt.path().display()
    );
    let _ibex = start(&cfg, vec![crt], &[up, front]);
    let r = plain(front, "/");
    assert!(r.starts_with("http/1.1 200"), "{r}");
}
