// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! TLS 1.2, on `bind ... ssl` and towards `server ... ssl` (T153).
//!
//! rustls was built without its `tls12` feature, so Ibex spoke TLS 1.3 only while
//! `HAProxy` 3.5-dev8-885761-29 accepts 1.2 and 1.3 by default. The clients and servers
//! here are `openssl s_client` and `openssl s_server`, not rustls, so that a build
//! without TLS 1.2 is a failure of the proxy and not a test that does not compile.
//!
//! Measured on `HAProxy` with an ECDSA P-256 certificate and curl / `openssl s_client`:
//!
//! * a default bind answers a 1.2 client with `TLSv1.2` and `ECDHE-ECDSA-AES256-GCM-SHA384`,
//!   a 1.3 client with `TLSv1.3` and `TLS_AES_256_GCM_SHA384`;
//! * `ssl-min-ver TLSv1.3` and `no-tlsv12` turn a 1.2 client away (alert 70, protocol
//!   version); `ssl-max-ver TLSv1.2`, `force-tlsv12` and `no-tlsv13` turn a 1.3 client away;
//! * behind `server ... ssl` a 1.2-only server is reached by default (`ssl_bc_protocol`
//!   `TLSv1.2`, `ECDHE-ECDSA-AES256-GCM-SHA384`) and with `ssl-max-ver TLSv1.3`; with
//!   `ssl-min-ver TLSv1.3` the request is a 503, and so is a 1.3-only server reached with
//!   `ssl-max-ver TLSv1.2`;
//! * `ssl-default-bind-options` / `ssl-default-server-options` apply when the line says nothing.

use crate::common;

use std::io::Write;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use tempfile::NamedTempFile;

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// A certificate for `localhost` (ECDSA, as rcgen makes it) and its key, as one PEM file.
fn cert() -> NamedTempFile {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.subject_alt_names.push(rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])));
    let key = rcgen::KeyPair::generate().unwrap();
    let c = params.self_signed(&key).unwrap();
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(format!("{}{}", c.pem(), key.serialize_pem()).as_bytes()).unwrap();
    f
}

fn ibex(cfg: &str, listening: &[SocketAddr]) -> (Proc, NamedTempFile) {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(cfg.as_bytes()).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let p = Proc(child);
    for a in listening {
        assert!(common::wait_listening(*a), "ibex never listened on {a}");
    }
    (p, f)
}

/// One GET with `openssl s_client` limited to `version` (`tls1_2` or `tls1_3`): the
/// response, or the text of the failure (empty output and the alert on stderr).
fn s_client(addr: SocketAddr, version: &str) -> String {
    let mut child = Command::new("openssl")
        .args(["s_client", "-connect", &addr.to_string(), &format!("-{version}"), "-quiet", "-servername", "localhost"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("openssl s_client");
    child.stdin.take().unwrap().write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    let out = child.wait_with_output().unwrap();
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)).to_lowercase()
}

fn hdr(resp: &str, name: &str) -> String {
    resp.lines().find_map(|l| l.strip_prefix(&format!("{name}:"))).map_or_else(|| "<none>".to_string(), |v| v.trim().to_string())
}

const RULE: &str = "  http-request return status 200 hdr x-proto \"%[ssl_fc_protocol]\" hdr x-cipher \"%[ssl_fc_cipher]\"\n";

fn front(global: &str, bind_opts: &str) -> (String, SocketAddr, NamedTempFile) {
    let crt = cert();
    let a = common::reserve_addr();
    let cfg = format!(
        "{global}defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\nfrontend t\n  bind {a} ssl crt {} {bind_opts}\n{RULE}",
        crt.path().display()
    );
    (cfg, a, crt)
}

/// `Some(response)` when `version` got through, `None` when the handshake was refused.
fn through(global: &str, bind_opts: &str, version: &str) -> Option<String> {
    let (cfg, a, _crt) = front(global, bind_opts);
    let (_p, _f) = ibex(&cfg, &[a]);
    let r = s_client(a, version);
    r.starts_with("http/1.1 200").then_some(r)
}

#[test]
fn tls12_client_is_served_on_a_default_bind() {
    let r = through("", "", "tls1_2").expect("a TLS 1.2 client is served");
    assert_eq!(hdr(&r, "x-proto"), "tlsv1.2", "{r}");
    assert!(hdr(&r, "x-cipher").starts_with("ecdhe-ecdsa-"), "{r}");
}

#[test]
fn tls13_client_is_still_served() {
    let r = through("", "", "tls1_3").expect("a TLS 1.3 client is served");
    assert_eq!(hdr(&r, "x-proto"), "tlsv1.3", "{r}");
}

#[test]
fn bind_version_bounds_decide_who_is_served() {
    // (bind options, serves 1.2, serves 1.3)
    let cases = [
        ("ssl-min-ver TLSv1.3", false, true),
        ("no-tlsv12", false, true),
        ("ssl-max-ver TLSv1.2", true, false),
        ("force-tlsv12", true, false),
        ("no-tlsv13", true, false),
        ("ssl-min-ver TLSv1.2 ssl-max-ver TLSv1.3", true, true),
        ("force-tlsv13", false, true),
    ];
    for (opts, v12, v13) in cases {
        assert_eq!(through("", opts, "tls1_2").is_some(), v12, "{opts}: TLS 1.2");
        assert_eq!(through("", opts, "tls1_3").is_some(), v13, "{opts}: TLS 1.3");
    }
}

#[test]
fn global_bind_options_apply_and_the_bind_overrides_them() {
    let g = "global\n  ssl-default-bind-options ssl-min-ver TLSv1.3\n";
    assert!(through(g, "", "tls1_2").is_none());
    assert!(through(g, "", "tls1_3").is_some());
    assert!(through(g, "ssl-min-ver TLSv1.2", "tls1_2").is_some());
}

/// A 1.2-only or 1.3-only upstream (`openssl s_server -www` answers a GET with a status
/// page), and a plain frontend in front of a `server ssl` line with `server_opts`.
fn via_server(global: &str, upstream: &str, server_opts: &str) -> String {
    let crt = cert();
    let up = common::reserve_addr();
    let child = Command::new("openssl")
        .args(["s_server", "-accept", &up.port().to_string(), "-cert", &crt.path().display().to_string(), "-key", &crt.path().display().to_string(), &format!("-{upstream}"), "-www", "-quiet"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("openssl s_server");
    let _srv = Proc(child);
    assert!(common::wait_listening(SocketAddr::from(([127, 0, 0, 1], up.port()))), "s_server never listened");
    let fe = common::reserve_addr();
    let cfg = format!(
        "{global}defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\nfrontend f\n  bind {fe}\n  default_backend b\n\
         backend b\n  http-response set-header x-bcp \"%[ssl_bc_protocol]\"\n  http-response set-header x-bcc \"%[ssl_bc_cipher]\"\n  server s 127.0.0.1:{} ssl verify none {server_opts}\n",
        up.port()
    );
    let (_p, _f) = ibex(&cfg, &[fe]);
    let mut tcp = std::net::TcpStream::connect(fe).unwrap();
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = std::io::Read::read_to_end(&mut tcp, &mut out);
    String::from_utf8_lossy(&out).to_lowercase()
}

#[test]
fn a_tls12_only_server_is_reached() {
    let r = via_server("", "tls1_2", "");
    assert!(r.starts_with("http/1.1 200") || r.starts_with("http/1.0 200"), "{r}");
    assert_eq!(hdr(&r, "x-bcp"), "tlsv1.2", "{r}");
    assert!(hdr(&r, "x-bcc").starts_with("ecdhe-ecdsa-"), "{r}");
    let r = via_server("", "tls1_2", "ssl-max-ver TLSv1.3");
    assert_eq!(hdr(&r, "x-bcp"), "tlsv1.2", "{r}");
}

#[test]
fn server_version_bounds_decide_who_is_reached() {
    let r = via_server("", "tls1_2", "ssl-min-ver TLSv1.3");
    assert!(r.starts_with("http/1.1 503"), "{r}");
    let r = via_server("", "tls1_3", "ssl-max-ver TLSv1.2");
    assert!(r.starts_with("http/1.1 503"), "{r}");
    let r = via_server("", "tls1_2", "force-tlsv12");
    assert_eq!(hdr(&r, "x-bcp"), "tlsv1.2", "{r}");
    let r = via_server("", "tls1_3", "");
    assert_eq!(hdr(&r, "x-bcp"), "tlsv1.3", "{r}");
}

#[test]
fn global_server_options_apply() {
    let r = via_server("global\n  ssl-default-server-options ssl-min-ver TLSv1.3\n", "tls1_2", "");
    assert!(r.starts_with("http/1.1 503"), "{r}");
    let r = via_server("global\n  ssl-default-server-options ssl-min-ver TLSv1.3\n", "tls1_2", "ssl-min-ver TLSv1.2");
    assert_eq!(hdr(&r, "x-bcp"), "tlsv1.2", "{r}");
}
