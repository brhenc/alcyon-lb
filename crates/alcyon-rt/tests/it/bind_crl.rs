// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Client certificate CRL verification, `ca-verify-file`, `crt-ignore-err`,
//! `ca-ignore-err`, and `no-ca-names` on `bind ... ssl` (T655 slice C1b).
//!
//! Every outcome and `ssl_c_*` / `x509_v_err_str` value below was measured on
//! `HAProxy` 3.5-dev11-ce79f339c (`ADB_ORACLE=<haproxy>` runs this file against
//! the oracle too):
//!
//! * `crl-file` (X.509 v3 cert chain + v2 SHA-256 CRLs in `tests/data/client_auth/`):
//!   - valid leaf (direct or via intermediate) with full chain CRLs: 200 OK, `1/0/0/0`, `X509_V_OK`;
//!   - revoked leaf (direct or via intermediate): fails with alert 44, error-log `err=23 ca_err=0`;
//!   - valid leaf under revoked intermediate: fails with alert 44, error-log `err=0 ca_err=23`;
//!   - **partial-chain CRL rule**: `HAProxy` checks CRLs for the whole chain (`X509_V_FLAG_CRL_CHECK |
//!     X509_V_FLAG_CRL_CHECK_ALL`). With only the root CRL (missing intermediate CRL), even a valid
//!     leaf fails with `err=3 ca_err=0` (`X509_V_ERR_UNABLE_TO_GET_CRL`); with only the intermediate
//!     CRL (missing root CRL), it fails with `err=0 ca_err=3`;
//!   - expired CRL (`nextUpdate` in past): valid leaf fails with `err=12 ca_err=0`;
//!   - `verify optional` + `crl-file`: no cert → 200 OK (`0/0/0/0`), valid → 200 OK (`1/0/0/0`),
//!     revoked → fails with alert 44.
//! * `crt-ignore-err` vs `ca-ignore-err` split (measured on 2-level chain):
//!   - `crt-ignore-err X509_V_ERR_CERT_REVOKED`: revoked leaf passes (`1/23/23/0`, `X509_V_ERR_CERT_REVOKED`),
//!     revoked intermediate still fails (`err=0 ca_err=23`), expired leaf still fails (`err=10 ca_err=0`);
//!   - `ca-ignore-err X509_V_ERR_CERT_REVOKED`: revoked intermediate passes (`1/23/0/23`,
//!     `X509_V_ERR_CERT_REVOKED`), revoked leaf still fails (`err=23 ca_err=0`);
//!   - `ca-ignore-err 10`: expired intermediate passes (`1/10/0/10`, `X509_V_ERR_CERT_HAS_EXPIRED`),
//!     expired leaf still fails (`err=10 ca_err=0`);
//!   - `crt-ignore-err all ca-ignore-err all` on expired leaf under revoked intermediate: passes with
//!     `1/10/10/23`, `X509_V_ERR_CERT_HAS_EXPIRED`;
//!   - `crt-ignore-err X509_V_ERR_CERT_HAS_EXPIRED` does NOT bypass an expired cert from an untrusted CA.
//! * `ca-verify-file`:
//!   - with `ca-file`: accepts clients from both CAs, advertises ONLY `ca-file` subjects in
//!     `CertificateRequest`;
//!   - without `ca-file`: accepted at load, sends NO CA names in `CertificateRequest`, verifies
//!     against `ca-verify-file`.
//! * `no-ca-names`: sends an empty CA list (`No client certificate CA names sent`) while still
//!   enforcing verification.
//! * Documented difference (`docs/differences.md`): X.509 v1 `client1.pem` under `crt-ignore-err all`:
//!   `HAProxy` accepts (`200 OK`, `1/0/0/0`); Alcyon ignores `UnsupportedCertVersion` (1) during
//!   `VerifyClientIdentity` (`err=1`), and then fails at `CertificateVerify` (alert 46) because
//!   `rustls24::crypto::verify_tls13_signature` parses the leaf with `rustls-webpki` (v3 only).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/client_auth")
}

fn proxy_bin() -> String {
    std::env::var("ADB_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

fn is_oracle() -> bool {
    std::env::var("ADB_ORACLE").is_ok()
}

struct Daemon {
    child: Child,
    dir: PathBuf,
    stop: Arc<AtomicBool>,
    origin: Option<thread::JoinHandle<()>>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.origin.take() {
            let _ = h.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start_origin() -> (u16, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind origin");
    let port = listener.local_addr().expect("origin addr").port();
    listener.set_nonblocking(true).expect("nonblocking");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut conn, _)) => {
                    let _ = conn.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut buf = [0u8; 2048];
                    let _ = conn.read(&mut buf);
                    let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                    let _ = conn.flush();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (port, stop, handle)
}

fn s_client(addr: SocketAddr, tls_flag: &str, cert: Option<&Path>, chain: Option<&Path>) -> String {
    let mut cmd = Command::new("openssl");
    cmd.arg("s_client")
        .arg("-connect")
        .arg(addr.to_string())
        .arg(tls_flag)
        .arg("-ign_eof");
    if let Some(c) = cert {
        cmd.arg("-cert").arg(c).arg("-key").arg(c);
    }
    if let Some(ch) = chain {
        cmd.arg("-cert_chain").arg(ch);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn openssl s_client");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    }
    let out = child.wait_with_output().expect("wait openssl s_client");
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    combined
}

fn header_value(output: &str, name: &str) -> Option<String> {
    let prefix = format!("{}:", name.to_ascii_lowercase());
    for line in output.lines() {
        let trimmed = line.trim_end_matches('\r');
        let lower = trimmed.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix(&prefix) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn assert_ok_headers(
    label: &str,
    out: &str,
    used: &str,
    verify: &str,
    verify_str: &str,
    err: &str,
    ca_err: &str,
) {
    assert!(out.contains("HTTP/1.1 200 OK"), "{label}: expected HTTP/1.1 200 OK, got:\n{out}");
    assert_eq!(header_value(out, "x-used").as_deref(), Some(used), "{label}: x-used in:\n{out}");
    assert_eq!(header_value(out, "x-verify").as_deref(), Some(verify), "{label}: x-verify in:\n{out}");
    assert_eq!(
        header_value(out, "x-verify-str").as_deref(),
        Some(verify_str.to_ascii_lowercase().as_str()),
        "{label}: x-verify-str in:\n{out}"
    );
    assert_eq!(header_value(out, "x-err").as_deref(), Some(err), "{label}: x-err in:\n{out}");
    assert_eq!(header_value(out, "x-ca-err").as_deref(), Some(ca_err), "{label}: x-ca-err in:\n{out}");
}

fn assert_handshake_failed(label: &str, out: &str, expected_alert: Option<u8>) {
    assert!(
        !out.contains("HTTP/1.1 200 OK"),
        "{label}: handshake should have failed, but got HTTP 200:\n{out}"
    );
    if let Some(alert) = expected_alert {
        let needle = format!("SSL alert number {alert}");
        assert!(out.contains(&needle), "{label}: expected `{needle}`, got:\n{out}");
    } else {
        assert!(out.contains("SSL alert number"), "{label}: expected a TLS alert, got:\n{out}");
    }
}

fn drain_udp(udp: &UdpSocket) {
    let _ = udp.set_read_timeout(Some(Duration::from_millis(20)));
    let mut buf = [0u8; 4096];
    while udp.recv(&mut buf).is_ok() {}
    let _ = udp.set_read_timeout(Some(Duration::from_secs(3)));
}

fn recv_errlog(udp: &UdpSocket, label: &str) -> String {
    let mut buf = [0u8; 4096];
    for _ in 0..8 {
        let n = udp.recv(&mut buf).unwrap_or_else(|e| panic!("{label}: expected ERRLOG syslog line: {e}"));
        let line = String::from_utf8_lossy(&buf[..n]).into_owned();
        if line.contains("ERRLOG ") {
            return line;
        }
    }
    panic!("{label}: never saw ERRLOG syslog line");
}

struct CrlPorts {
    crl_all: SocketAddr,
    crl_root_only: SocketAddr,
    crl_inter_only: SocketAddr,
    crl_expired: SocketAddr,
    crl_opt: SocketAddr,
    ign_crt_rev: SocketAddr,
    ign_ca_rev: SocketAddr,
    ign_ca_exp: SocketAddr,
    ign_both_all: SocketAddr,
    ign_crt_exp_only: SocketAddr,
    ign_v1_all: SocketAddr,
}

fn check_crl_cases(p: &CrlPorts, fx: &Path, udp: &UdpSocket) {
    let inter1 = fx.join("crl-inter1.crt");
    let inter2 = fx.join("crl-inter2-revoked.crt");
    let direct_ok = fx.join("crl-direct-ok.pem");
    let direct_rev = fx.join("crl-direct-revoked.pem");
    let leaf_ok = fx.join("crl-leaf-ok.pem");
    let leaf_rev = fx.join("crl-leaf-revoked.pem");
    let leaf_under_rev = fx.join("crl-leaf-under-rev-inter.pem");

    // 1. Valid direct and chained certs with full chain CRLs (TLS 1.3 & 1.2).
    for ver in ["-tls1_3", "-tls1_2"] {
        let out = s_client(p.crl_all, ver, Some(&direct_ok), None);
        assert!(out.contains("Alcyon Test CRL Root CA v3"), "crl_all ({ver}) CA name:\n{out}");
        assert_ok_headers(&format!("crl_all + direct_ok ({ver})"), &out, "1", "0", "X509_V_OK", "0", "0");

        let out = s_client(p.crl_all, ver, Some(&leaf_ok), Some(&inter1));
        assert_ok_headers(&format!("crl_all + leaf_ok + inter1 ({ver})"), &out, "1", "0", "X509_V_OK", "0", "0");
    }

    // 2. Revoked leaf (direct and under inter1) -> alert 44, err=23 ca_err=0.
    for (label, cert, chain) in [
        ("crl_all + direct_revoked", &direct_rev, None),
        ("crl_all + leaf_revoked + inter1", &leaf_rev, Some(inter1.as_path())),
    ] {
        drain_udp(udp);
        let out = s_client(p.crl_all, "-tls1_3", Some(cert), chain);
        assert_handshake_failed(label, &out, Some(44));
        let log = recv_errlog(udp, label);
        assert!(
            log.contains("used=1 verify=- err=23 ca_err=0"),
            "{label}: expected `used=1 verify=- err=23 ca_err=0`, got:\n{log}"
        );
    }

    // 3. Valid leaf under revoked intermediate -> alert 44, err=0 ca_err=23.
    drain_udp(udp);
    let out = s_client(p.crl_all, "-tls1_3", Some(&leaf_under_rev), Some(&inter2));
    assert_handshake_failed("crl_all + revoked intermediate", &out, Some(44));
    let log = recv_errlog(udp, "crl_all + revoked intermediate");
    assert!(
        log.contains("used=1 verify=- err=0 ca_err=23"),
        "revoked intermediate: expected `used=1 verify=- err=0 ca_err=23`, got:\n{log}"
    );

    // 4. Partial-chain CRL rule (HAProxy checks CRLs for the entire chain:
    //    X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL, webpki RevocationCheckDepth::Chain
    //    with UnknownStatusPolicy::Deny). Even a valid leaf fails with code 3 and alert 48 when
    //    any CA's CRL is absent: missing inter1 CRL -> err=3 ca_err=0; missing root CRL -> err=0 ca_err=3.
    drain_udp(udp);
    let out = s_client(p.crl_root_only, "-tls1_3", Some(&leaf_ok), Some(&inter1));
    assert_handshake_failed("partial CRL (root only, missing inter1 CRL)", &out, Some(48));
    let log = recv_errlog(udp, "partial CRL root only");
    assert!(
        log.contains("used=1 verify=- err=3 ca_err=0"),
        "partial CRL root only: expected `used=1 verify=- err=3 ca_err=0`, got:\n{log}"
    );

    drain_udp(udp);
    let out = s_client(p.crl_inter_only, "-tls1_3", Some(&leaf_ok), Some(&inter1));
    assert_handshake_failed("partial CRL (inter1 only, missing root CRL)", &out, Some(48));
    let log = recv_errlog(udp, "partial CRL inter only");
    assert!(
        log.contains("used=1 verify=- err=0 ca_err=3"),
        "partial CRL inter only: expected `used=1 verify=- err=0 ca_err=3`, got:\n{log}"
    );

    // 5. Expired CRL -> valid leaf rejected with err=12 ca_err=0 (OpenSSL alert 45; rustls alert 48).
    drain_udp(udp);
    let out = s_client(p.crl_expired, "-tls1_3", Some(&direct_ok), None);
    let exp_crl_alert = if is_oracle() { 45 } else { 48 };
    assert_handshake_failed("expired CRL + direct_ok", &out, Some(exp_crl_alert));
    let log = recv_errlog(udp, "expired CRL");
    assert!(
        log.contains("used=1 verify=- err=12 ca_err=0"),
        "expired CRL: expected `used=1 verify=- err=12 ca_err=0`, got:\n{log}"
    );

    // 6. `verify optional` + `crl-file`: no cert passes (0/0/0/0), valid passes, revoked fails.
    let out = s_client(p.crl_opt, "-tls1_3", None, None);
    assert_ok_headers("crl_opt + no cert", &out, "0", "0", "X509_V_OK", "0", "0");
    let out = s_client(p.crl_opt, "-tls1_3", Some(&direct_ok), None);
    assert_ok_headers("crl_opt + direct_ok", &out, "1", "0", "X509_V_OK", "0", "0");
    drain_udp(udp);
    let out = s_client(p.crl_opt, "-tls1_3", Some(&direct_rev), None);
    assert_handshake_failed("crl_opt + direct_revoked", &out, Some(44));
    let log = recv_errlog(udp, "crl_opt + direct_revoked");
    assert!(log.contains("used=1 verify=- err=23 ca_err=0"), "crl_opt revoked:\n{log}");
}

fn check_ignore_err_cases(p: &CrlPorts, fx: &Path, udp: &UdpSocket) {
    let inter1 = fx.join("crl-inter1.crt");
    let inter2 = fx.join("crl-inter2-revoked.crt");
    let inter3 = fx.join("crl-inter3-expired.crt");
    let leaf_rev = fx.join("crl-leaf-revoked.pem");
    let leaf_exp = fx.join("crl-leaf-expired.pem");
    let leaf_under_rev = fx.join("crl-leaf-under-rev-inter.pem");
    let leaf_under_exp = fx.join("crl-leaf-under-exp-inter.pem");
    let leaf_exp_under_rev = fx.join("crl-leaf-exp-under-rev-inter.pem");
    let untrusted_exp = fx.join("v3-client-expired.pem");
    let v1_client1 = fx.join("client1.pem");

    // 1. `crt-ignore-err X509_V_ERR_CERT_REVOKED`:
    //    revoked leaf passes (1/23/23/0); revoked inter and expired leaf still fail!
    let out = s_client(p.ign_crt_rev, "-tls1_3", Some(&leaf_rev), Some(&inter1));
    assert_ok_headers(
        "crt-ignore-err revoked + leaf_revoked",
        &out,
        "1",
        "23",
        "X509_V_ERR_CERT_REVOKED",
        "23",
        "0",
    );

    drain_udp(udp);
    let out = s_client(p.ign_crt_rev, "-tls1_3", Some(&leaf_under_rev), Some(&inter2));
    assert_handshake_failed("crt-ignore-err revoked + revoked inter", &out, Some(44));
    let log = recv_errlog(udp, "crt-ignore-err revoked + revoked inter");
    assert!(log.contains("used=1 verify=- err=0 ca_err=23"), "got:\n{log}");

    drain_udp(udp);
    let out = s_client(p.ign_crt_rev, "-tls1_3", Some(&leaf_exp), Some(&inter1));
    assert_handshake_failed("crt-ignore-err revoked + expired leaf", &out, Some(45));
    let log = recv_errlog(udp, "crt-ignore-err revoked + expired leaf");
    assert!(log.contains("used=1 verify=- err=10 ca_err=0"), "got:\n{log}");

    // 2. `ca-ignore-err X509_V_ERR_CERT_REVOKED`:
    //    revoked intermediate passes (1/23/0/23); revoked leaf still fails!
    let out = s_client(p.ign_ca_rev, "-tls1_3", Some(&leaf_under_rev), Some(&inter2));
    assert_ok_headers(
        "ca-ignore-err revoked + revoked inter",
        &out,
        "1",
        "23",
        "X509_V_ERR_CERT_REVOKED",
        "0",
        "23",
    );

    drain_udp(udp);
    let out = s_client(p.ign_ca_rev, "-tls1_3", Some(&leaf_rev), Some(&inter1));
    assert_handshake_failed("ca-ignore-err revoked + revoked leaf", &out, Some(44));
    let log = recv_errlog(udp, "ca-ignore-err revoked + revoked leaf");
    assert!(log.contains("used=1 verify=- err=23 ca_err=0"), "got:\n{log}");

    // 3. `ca-ignore-err 10` (expired CA):
    //    expired intermediate passes (1/10/0/10); expired leaf still fails!
    let out = s_client(p.ign_ca_exp, "-tls1_3", Some(&leaf_under_exp), Some(&inter3));
    assert_ok_headers(
        "ca-ignore-err 10 + expired inter",
        &out,
        "1",
        "10",
        "X509_V_ERR_CERT_HAS_EXPIRED",
        "0",
        "10",
    );

    drain_udp(udp);
    let out = s_client(p.ign_ca_exp, "-tls1_3", Some(&leaf_exp), Some(&inter1));
    assert_handshake_failed("ca-ignore-err 10 + expired leaf", &out, Some(45));
    let log = recv_errlog(udp, "ca-ignore-err 10 + expired leaf");
    assert!(log.contains("used=1 verify=- err=10 ca_err=0"), "got:\n{log}");

    // 4. `crt-ignore-err all ca-ignore-err all` on dual-error chain (expired leaf + revoked inter):
    //    passes with verify=10, err=10, ca_err=23 (measured on oracle).
    let out = s_client(p.ign_both_all, "-tls1_3", Some(&leaf_exp_under_rev), Some(&inter2));
    assert_ok_headers(
        "both ignore all + expired leaf under revoked inter",
        &out,
        "1",
        "10",
        "X509_V_ERR_CERT_HAS_EXPIRED",
        "10",
        "23",
    );

    // 5. Security control: `crt-ignore-err X509_V_ERR_CERT_HAS_EXPIRED` accepts a trusted expired
    //    leaf (1/10/10/0), but MUST still reject an expired leaf issued by an UNTRUSTED CA!
    let out = s_client(p.ign_crt_exp_only, "-tls1_3", Some(&leaf_exp), Some(&inter1));
    assert_ok_headers(
        "crt-ignore-err expired + trusted expired leaf",
        &out,
        "1",
        "10",
        "X509_V_ERR_CERT_HAS_EXPIRED",
        "10",
        "0",
    );
    let out = s_client(p.ign_crt_exp_only, "-tls1_3", Some(&untrusted_exp), None);
    assert_handshake_failed("crt-ignore-err expired + untrusted expired leaf", &out, Some(48));

    // 6. Documented X.509 v1 difference under `crt-ignore-err all`:
    //    HAProxy accepts v1 client1.pem (200 OK, 1/0/0/0).
    //    Alcyon ignores UnsupportedCertVersion (code 1) in VerifyClientIdentity (recording err=1),
    //    then rustls's CertificateVerify signature check still rejects the v1 cert with alert 46.
    drain_udp(udp);
    let out = s_client(p.ign_v1_all, "-tls1_3", Some(&v1_client1), None);
    if is_oracle() {
        assert_ok_headers("ign_v1_all + v1 client1 (oracle)", &out, "1", "0", "X509_V_OK", "0", "0");
    } else {
        assert_handshake_failed("ign_v1_all + v1 client1 (alcyon)", &out, Some(46));
        let log = recv_errlog(udp, "ign_v1_all + v1 client1");
        assert!(
            log.contains("used=1 verify=- err=1 ca_err=0"),
            "alcyon v1 under crt-ignore-err all: expected `used=1 verify=- err=1 ca_err=0`, got:\n{log}"
        );
    }
}

fn format_crl_cfg(fx: &Path, ports: &CrlPorts, log_port: u16, origin_port: u16) -> String {
    let srv_crt = fx.join("common.pem");
    let root_ca = fx.join("crl-root-ca.crt");
    let crl_all = fx.join("crl-all.pem");
    let crl_root = fx.join("crl-root.pem");
    let crl_inter1 = fx.join("crl-inter1.pem");
    let crl_exp = fx.join("crl-root-expired.pem");
    let regtest_ca = fx.join("ca-auth.crt");
    let srv = srv_crt.display();
    let root = root_ca.display();
    let all = crl_all.display();
    format!(
        "global\n\
         \x20 nbthread 1\n\
         defaults\n\
         \x20 mode http\n\
         \x20 timeout connect 5s\n\
         \x20 timeout client 5s\n\
         \x20 timeout server 5s\n\
         \x20 log 127.0.0.1:{log_port} local0\n\
         \x20 option dontlognull\n\
         \x20 error-log-format \"ERRLOG fe=%f used=%[ssl_c_used] verify=%[ssl_c_verify] err=%[ssl_c_err] ca_err=%[ssl_c_ca_err]\"\n\
         \n\
         frontend fe_crl_all\n\
         \x20 bind {} ssl crt {srv} ca-file {root} crl-file {all} verify required\n\
         \x20 default_backend be\n\
         \n\
         frontend fe_crl_root_only\n\
         \x20 bind {} ssl crt {srv} ca-file {root} crl-file {} verify required\n\
         \x20 default_backend be\n\
         \n\
         frontend fe_crl_inter_only\n\
         \x20 bind {} ssl crt {srv} ca-file {root} crl-file {} verify required\n\
         \x20 default_backend be\n\
         \n\
         frontend fe_crl_expired\n\
         \x20 bind {} ssl crt {srv} ca-file {root} crl-file {} verify required\n\
         \x20 default_backend be\n\
         \n\
         frontend fe_crl_opt\n\
         \x20 bind {} ssl crt {srv} ca-file {root} crl-file {all} verify optional\n\
         \x20 default_backend be\n\
         \n\
         frontend fe_ign_crt_rev\n\
         \x20 bind {} ssl crt {srv} ca-file {root} crl-file {all} verify required crt-ignore-err X509_V_ERR_CERT_REVOKED\n\
         \x20 default_backend be\n\
         \n\
         frontend fe_ign_ca_rev\n\
         \x20 bind {} ssl crt {srv} ca-file {root} crl-file {all} verify required ca-ignore-err X509_V_ERR_CERT_REVOKED\n\
         \x20 default_backend be\n\
         \n\
         frontend fe_ign_ca_exp\n\
         \x20 bind {} ssl crt {srv} ca-file {root} crl-file {all} verify required ca-ignore-err 10\n\
         \x20 default_backend be\n\
         \n\
         frontend fe_ign_both_all\n\
         \x20 bind {} ssl crt {srv} ca-file {root} crl-file {all} verify required crt-ignore-err all ca-ignore-err all\n\
         \x20 default_backend be\n\
         \n\
         frontend fe_ign_crt_exp_only\n\
         \x20 bind {} ssl crt {srv} ca-file {root} verify required crt-ignore-err X509_V_ERR_CERT_HAS_EXPIRED\n\
         \x20 default_backend be\n\
         \n\
         frontend fe_ign_v1_all\n\
         \x20 bind {} ssl crt {srv} ca-file {} verify required crt-ignore-err all\n\
         \x20 default_backend be\n\
         \n\
         backend be\n\
         \x20 http-response set-header X-Used %[ssl_c_used]\n\
         \x20 http-response set-header X-Verify %[ssl_c_verify]\n\
         \x20 http-response set-header X-Verify-Str %[ssl_c_verify,x509_v_err_str]\n\
         \x20 http-response set-header X-Err %[ssl_c_err]\n\
         \x20 http-response set-header X-Ca-Err %[ssl_c_ca_err]\n\
         \x20 server s1 127.0.0.1:{origin_port}\n",
        ports.crl_all,
        ports.crl_root_only,
        crl_root.display(),
        ports.crl_inter_only,
        crl_inter1.display(),
        ports.crl_expired,
        crl_exp.display(),
        ports.crl_opt,
        ports.ign_crt_rev,
        ports.ign_ca_rev,
        ports.ign_ca_exp,
        ports.ign_both_all,
        ports.ign_crt_exp_only,
        ports.ign_v1_all,
        regtest_ca.display(),
    )
}

#[test]
fn bind_crl_and_ignore_err_end_to_end() {
    let fx = fixtures_dir();
    let ports = CrlPorts {
        crl_all: common::reserve_addr(),
        crl_root_only: common::reserve_addr(),
        crl_inter_only: common::reserve_addr(),
        crl_expired: common::reserve_addr(),
        crl_opt: common::reserve_addr(),
        ign_crt_rev: common::reserve_addr(),
        ign_ca_rev: common::reserve_addr(),
        ign_ca_exp: common::reserve_addr(),
        ign_both_all: common::reserve_addr(),
        ign_crt_exp_only: common::reserve_addr(),
        ign_v1_all: common::reserve_addr(),
    };
    let (origin_port, stop, origin_handle) = start_origin();
    let udp = UdpSocket::bind("127.0.0.1:0").expect("bind udp log");
    udp.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    let log_port = udp.local_addr().expect("udp addr").port();

    let dir = std::env::temp_dir().join(format!("alcyon-bind-crl-{}-{}", std::process::id(), ports.crl_all.port()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let cfg_path = dir.join("crl.cfg");
    std::fs::write(&cfg_path, format_crl_cfg(&fx, &ports, log_port, origin_port)).expect("write cfg");

    let child = Command::new(proxy_bin())
        .arg("-f")
        .arg(&cfg_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proxy");
    let daemon = Daemon { child, dir: dir.clone(), stop, origin: Some(origin_handle) };

    assert!(common::wait_listening(ports.crl_all), "proxy never listened on fe_crl_all");
    assert!(common::wait_listening(ports.ign_v1_all), "proxy never listened on fe_ign_v1_all");

    check_crl_cases(&ports, &fx, &udp);
    check_ignore_err_cases(&ports, &fx, &udp);
    drop(daemon);
}

#[test]
fn bind_ca_verify_file_and_no_ca_names() {
    let fx = fixtures_dir();
    let srv_crt = fx.join("common.pem");
    let root_ca = fx.join("crl-root-ca.crt");
    let cav_ca = fx.join("crl-ca-verify-only.crt");
    let direct_ok = fx.join("crl-direct-ok.pem");
    let cab_leaf = fx.join("crl-cab-leaf.pem");
    let untrusted = fx.join("v3-client-valid.pem");

    let fe_cav = common::reserve_addr();
    let fe_cav_only = common::reserve_addr();
    let fe_no_ca = common::reserve_addr();
    let (origin_port, stop, origin_handle) = start_origin();

    let dir = std::env::temp_dir().join(format!("alcyon-bind-cav-{}-{}", std::process::id(), fe_cav.port()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let cfg_path = dir.join("cav.cfg");
    let srv = srv_crt.display();
    let root = root_ca.display();
    let cav = cav_ca.display();
    let cfg = format!(
        "global\n\
         \x20 nbthread 1\n\
         defaults\n\
         \x20 mode http\n\
         \x20 timeout connect 5s\n\
         \x20 timeout client 5s\n\
         \x20 timeout server 5s\n\
         \n\
         frontend fe_cav\n\
         \x20 bind {fe_cav} ssl crt {srv} ca-file {root} ca-verify-file {cav} verify required\n\
         \x20 default_backend be\n\
         \n\
         frontend fe_cav_only\n\
         \x20 bind {fe_cav_only} ssl crt {srv} ca-verify-file {cav} verify required\n\
         \x20 default_backend be\n\
         \n\
         frontend fe_no_ca\n\
         \x20 bind {fe_no_ca} ssl crt {srv} ca-file {root} verify required no-ca-names\n\
         \x20 default_backend be\n\
         \n\
         backend be\n\
         \x20 http-response set-header X-Used %[ssl_c_used]\n\
         \x20 http-response set-header X-Verify %[ssl_c_verify]\n\
         \x20 http-response set-header X-Verify-Str %[ssl_c_verify,x509_v_err_str]\n\
         \x20 http-response set-header X-Err %[ssl_c_err]\n\
         \x20 http-response set-header X-Ca-Err %[ssl_c_ca_err]\n\
         \x20 server s1 127.0.0.1:{origin_port}\n",
    );
    std::fs::write(&cfg_path, &cfg).expect("write cfg");

    let child = Command::new(proxy_bin())
        .arg("-f")
        .arg(&cfg_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proxy");
    let daemon = Daemon { child, dir: dir.clone(), stop, origin: Some(origin_handle) };

    assert!(common::wait_listening(fe_cav), "fe_cav did not listen");
    assert!(common::wait_listening(fe_cav_only), "fe_cav_only did not listen");
    assert!(common::wait_listening(fe_no_ca), "fe_no_ca did not listen");

    // 1. `ca-file` + `ca-verify-file`: both roots verify, ONLY `ca-file` subject is advertised.
    for (label, cert) in [("fe_cav + ca-file leaf", &direct_ok), ("fe_cav + ca-verify-file leaf", &cab_leaf)] {
        let out = s_client(fe_cav, "-tls1_3", Some(cert), None);
        assert_ok_headers(label, &out, "1", "0", "X509_V_OK", "0", "0");
        assert!(out.contains("Alcyon Test CRL Root CA v3"), "{label}: ca-file subject missing:\n{out}");
        assert!(
            !out.contains("Alcyon Test CA-Verify-Only B v3"),
            "{label}: ca-verify-file subject must NOT be advertised:\n{out}"
        );
    }
    let out = s_client(fe_cav, "-tls1_3", Some(&untrusted), None);
    assert_handshake_failed("fe_cav + untrusted", &out, Some(48));

    // 2. `ca-verify-file` alone (no `ca-file`): empty CA list, still verifies against ca-verify-file.
    let out = s_client(fe_cav_only, "-tls1_3", Some(&cab_leaf), None);
    assert_ok_headers("fe_cav_only + cab_leaf", &out, "1", "0", "X509_V_OK", "0", "0");
    assert!(
        out.contains("No client certificate CA names sent"),
        "fe_cav_only must send no CA names:\n{out}"
    );
    let out = s_client(fe_cav_only, "-tls1_3", Some(&direct_ok), None);
    assert_handshake_failed("fe_cav_only + wrong CA leaf", &out, Some(48));

    // 3. `no-ca-names`: empty CA list (TLS 1.3 & 1.2), still enforces `ca-file` verification.
    for ver in ["-tls1_3", "-tls1_2"] {
        let out = s_client(fe_no_ca, ver, Some(&direct_ok), None);
        assert_ok_headers(&format!("fe_no_ca + direct_ok ({ver})"), &out, "1", "0", "X509_V_OK", "0", "0");
        assert!(
            out.contains("No client certificate CA names sent"),
            "fe_no_ca ({ver}) must send no CA names:\n{out}"
        );
    }
    let out = s_client(fe_no_ca, "-tls1_3", Some(&cab_leaf), None);
    assert_handshake_failed("fe_no_ca + untrusted leaf", &out, Some(48));

    drop(daemon);
}

#[test]
fn bind_c1b_config_check_cli_matches_haproxy() {
    let fx = fixtures_dir();
    let srv_crt = fx.join("common.pem");
    let root_ca = fx.join("crl-root-ca.crt");
    let cav_ca = fx.join("crl-ca-verify-only.crt");
    let crl_all = fx.join("crl-all.pem");
    let dir = std::env::temp_dir().join(format!("alcyon-c1b-cfgchk-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");

    let run_check = |name: &str, bind_line: &str| -> (i32, String) {
        let p = dir.join(format!("{name}.cfg"));
        std::fs::write(
            &p,
            format!(
                "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n\
                 frontend fe\n  {bind_line}\n"
            ),
        )
        .expect("write cfg");
        let out = Command::new(proxy_bin()).arg("-c").arg("-f").arg(&p).output().expect("run -c");
        let code = out.status.code().unwrap_or(-1);
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        (code, text)
    };

    let srv = srv_crt.display();
    let root = root_ca.display();
    let cav = cav_ca.display();
    let all = crl_all.display();

    let (rc, out) = run_check(
        "missing_crl",
        &format!("bind 127.0.0.1:8443 ssl crt {srv} ca-file {root} crl-file /nonexistent/no.crl verify required"),
    );
    assert_eq!(rc, 1, "missing crl-file must exit 1:\n{out}");
    assert!(out.contains("'crl-file' : unable to load /nonexistent/no.crl"), "{out}");

    let (rc, out) = run_check(
        "missing_cav",
        &format!("bind 127.0.0.1:8443 ssl crt {srv} ca-verify-file /nonexistent/no.crt verify required"),
    );
    assert_eq!(rc, 1, "missing ca-verify-file must exit 1:\n{out}");
    assert!(out.contains("'ca-verify-file' : unable to load /nonexistent/no.crt"), "{out}");

    let (rc, out) = run_check("bad_id", &format!("bind 127.0.0.1:8443 ssl crt {srv} crt-ignore-err 99999"));
    assert_eq!(rc, 1, "crt-ignore-err 99999 must exit 1:\n{out}");
    assert!(out.contains("'crt-ignore-err' : ID '99999' out of range (1..94) in error IDs list '99999'"), "{out}");

    let (rc, out) = run_check("bad_name", &format!("bind 127.0.0.1:8443 ssl crt {srv} ca-ignore-err X509_V_ERR_BOGUS"));
    assert_eq!(rc, 1, "ca-ignore-err unknown name must exit 1:\n{out}");
    assert!(
        out.contains("'ca-ignore-err' : error constant 'X509_V_ERR_BOGUS' unknown in error IDs list 'X509_V_ERR_BOGUS'"),
        "{out}"
    );

    let (rc, out) = run_check("missing_ids", &format!("bind 127.0.0.1:8443 ssl crt {srv} crt-ignore-err"));
    assert_eq!(rc, 1, "crt-ignore-err missing arg must exit 1:\n{out}");
    assert!(out.contains("'crt-ignore-err' : missing error IDs list"), "{out}");

    let (rc, out) = run_check(
        "cav_only_ok",
        &format!("bind 127.0.0.1:8443 ssl crt {srv} ca-verify-file {cav} verify required"),
    );
    assert_eq!(rc, 0, "ca-verify-file without ca-file must exit 0:\n{out}");

    let (rc, out) = run_check(
        "full_c1b_ok",
        &format!(
            "bind 127.0.0.1:8443 ssl crt {srv} ca-file {root} ca-verify-file {cav} crl-file {all} \
             verify required no-ca-names crt-ignore-err X509_V_ERR_CERT_REVOKED,X509_V_ERR_CERT_HAS_EXPIRED ca-ignore-err 10,23"
        ),
    );
    assert_eq!(rc, 0, "full C1b config must exit 0:\n{out}");

    let _ = std::fs::remove_dir_all(&dir);
}

fn format_evil_cfg(
    fx: &Path,
    ports: (SocketAddr, SocketAddr, SocketAddr, SocketAddr),
    log_port: u16,
    origin_port: u16,
) -> String {
    let srv = fx.join("common.pem");
    let ca = fx.join("v3-ca.crt");
    let (srv, ca) = (srv.display(), ca.display());
    let (fe_exp_both, fe_all_both, fe_exp_ca19, fe_exp_crt19) = ports;
    format!(
        "global\n  nbthread 1\n\
         defaults\n  mode http\n  timeout connect 5s\n  timeout client 5s\n  timeout server 5s\n\
         \x20 log 127.0.0.1:{log_port} local0\n  option dontlognull\n\
         \x20 error-log-format \"ERRLOG fe=%f used=%[ssl_c_used] verify=%[ssl_c_verify] err=%[ssl_c_err] ca_err=%[ssl_c_ca_err]\"\n\
         frontend fe_exp_both\n  bind {fe_exp_both} ssl crt {srv} ca-file {ca} verify required crt-ignore-err X509_V_ERR_CERT_HAS_EXPIRED ca-ignore-err X509_V_ERR_CERT_HAS_EXPIRED\n  default_backend be\n\
         frontend fe_all_both\n  bind {fe_all_both} ssl crt {srv} ca-file {ca} verify required crt-ignore-err all ca-ignore-err all\n  default_backend be\n\
         frontend fe_exp_ca19\n  bind {fe_exp_ca19} ssl crt {srv} ca-file {ca} verify required crt-ignore-err 10 ca-ignore-err 10,19\n  default_backend be\n\
         frontend fe_exp_crt19\n  bind {fe_exp_crt19} ssl crt {srv} ca-file {ca} verify required crt-ignore-err 10,19 ca-ignore-err 10\n  default_backend be\n\
         backend be\n\
         \x20 http-response set-header X-Used %[ssl_c_used]\n\
         \x20 http-response set-header X-Verify %[ssl_c_verify]\n\
         \x20 http-response set-header X-Verify-Str %[ssl_c_verify,x509_v_err_str]\n\
         \x20 http-response set-header X-Err %[ssl_c_err]\n\
         \x20 http-response set-header X-Ca-Err %[ssl_c_ca_err]\n\
         \x20 server s1 127.0.0.1:{origin_port}\n"
    )
}

#[test]
fn bind_ignore_expired_never_accepts_untrusted_disjoint_chain() {
    let fx = fixtures_dir();
    let evil_leaf = fx.join("crl-evil-leaf.pem");
    let evil_inter = fx.join("crl-evil-inter.crt");
    let evil_inv = fx.join("crl-evil-inverted.pem");

    let fe_exp_both = common::reserve_addr();
    let fe_all_both = common::reserve_addr();
    let fe_exp_ca19 = common::reserve_addr();
    let fe_exp_crt19 = common::reserve_addr();
    let (origin_port, stop, origin_handle) = start_origin();
    let udp = UdpSocket::bind("127.0.0.1:0").expect("bind udp log");
    udp.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    let log_port = udp.local_addr().expect("udp addr").port();

    let dir = std::env::temp_dir().join(format!("alcyon-bind-evil-{}-{}", std::process::id(), fe_exp_both.port()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let cfg_path = dir.join("evil.cfg");
    let cfg = format_evil_cfg(&fx, (fe_exp_both, fe_all_both, fe_exp_ca19, fe_exp_crt19), log_port, origin_port);
    std::fs::write(&cfg_path, &cfg).expect("write cfg");

    let child = Command::new(proxy_bin())
        .arg("-f")
        .arg(&cfg_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proxy");
    let daemon = Daemon { child, dir: dir.clone(), stop, origin: Some(origin_handle) };

    assert!(common::wait_listening(fe_exp_both), "fe_exp_both did not listen");
    assert!(common::wait_listening(fe_exp_crt19), "fe_exp_crt19 did not listen");

    // 1. Untrusted disjoint-expired chain (leaf 2024 + self-signed inter 2010..2011) under
    //    crt-ignore-err 10 + ca-ignore-err 10 MUST FAIL with alert 48 and ca_err=19.
    drain_udp(&udp);
    let out = s_client(fe_exp_both, "-tls1_3", Some(&evil_leaf), Some(&evil_inter));
    assert_handshake_failed("evil leaf+inter under exp_both", &out, Some(48));
    let log = recv_errlog(&udp, "evil leaf+inter under exp_both");
    assert!(
        log.contains("used=1 verify=-") && log.contains("ca_err=19"),
        "expected untrusted ca_err=19 in error log, got:\n{log}"
    );

    // Without intermediate chain, leaf alone also fails with alert 48 and err=20.
    drain_udp(&udp);
    let out = s_client(fe_exp_both, "-tls1_3", Some(&evil_leaf), None);
    assert_handshake_failed("evil leaf alone under exp_both", &out, Some(48));
    let log = recv_errlog(&udp, "evil leaf alone under exp_both");
    assert!(log.contains("used=1 verify=- err=20 ca_err=0"), "got:\n{log}");

    // 2. Same untrusted chain under `crt-ignore-err 10,19 ca-ignore-err 10` (19 at wrong depth)
    //    MUST STILL FAIL with alert 48 and ca_err=19.
    drain_udp(&udp);
    let out = s_client(fe_exp_crt19, "-tls1_3", Some(&evil_leaf), Some(&evil_inter));
    assert_handshake_failed("evil leaf+inter under exp_crt19", &out, Some(48));
    let log = recv_errlog(&udp, "evil leaf+inter under exp_crt19");
    assert!(log.contains("ca_err=19"), "got:\n{log}");

    // 3. Same untrusted chain under `crt-ignore-err all ca-ignore-err all` AND under
    //    `crt-ignore-err 10 ca-ignore-err 10,19` MUST PASS with 1/10/10/19 (measured on oracle).
    for (label, addr) in [
        ("evil leaf+inter under all_both", fe_all_both),
        ("evil leaf+inter under exp_ca19", fe_exp_ca19),
    ] {
        let out = s_client(addr, "-tls1_3", Some(&evil_leaf), Some(&evil_inter));
        assert_ok_headers(label, &out, "1", "10", "X509_V_ERR_CERT_HAS_EXPIRED", "10", "19");
    }

    // 4. Untrusted self-signed cert with inverted validity (notBefore > notAfter):
    //    under exp_both -> MUST FAIL with alert 48 and err=18 ca_err=0 (matches HAProxy).
    drain_udp(&udp);
    let out = s_client(fe_exp_both, "-tls1_3", Some(&evil_inv), None);
    assert_handshake_failed("evil inverted under exp_both", &out, Some(48));
    let log = recv_errlog(&udp, "evil inverted under exp_both");
    assert!(log.contains("used=1 verify=- err=18 ca_err=0"), "got:\n{log}");

    // Under all_both -> 200 OK, used=1, err=18, ca_err=0 (oracle reports verify=10, webpki 14).
    let out = s_client(fe_all_both, "-tls1_3", Some(&evil_inv), None);
    let expected_verify = if is_oracle() { ("10", "X509_V_ERR_CERT_HAS_EXPIRED") } else { ("14", "X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD") };
    assert_ok_headers("evil inverted under all_both", &out, "1", expected_verify.0, expected_verify.1, "18", "0");

    drop(daemon);
}
