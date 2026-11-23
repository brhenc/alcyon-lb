// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Client certificate authentication on `bind ... ssl`: `verify`, `ca-file`,
//! `ssl_c_used`, `ssl_c_verify`, `ssl_c_err`, `ssl_c_ca_err` (T655 slice C1a).
//!
//! Every outcome and alert below was measured on `HAProxy` 3.5-dev11-ce79f339c
//! (`ADB_ORACLE=<haproxy>` runs this file against the oracle too):
//!
//! * `verify required ca-file v3-ca.crt` (X.509 v3 fixtures; generation commands in
//!   `tests/data/client_auth/README.md`):
//!   - advertises `Alcyon Test Client Auth CA v3` in `CertificateRequest`;
//!   - `v3-client-valid.pem` (TLS 1.3 & 1.2): 200 OK, `ssl_c_used=1`, `ssl_c_verify=0`,
//!     `ssl_c_err=0`, `ssl_c_ca_err=0`;
//!   - `v3-client-expired.pem` (TLS 1.3 & 1.2): handshake fails with alert 45 (`certificate expired`);
//!   - untrusted `common.pem` (TLS 1.3 & 1.2): handshake fails with alert 48 (`unknown ca`);
//!   - no client certificate: fails with alert 116 (`certificate required`) on TLS 1.3 and
//!     alert 40 (`handshake failure`) on TLS 1.2.
//! * `verify optional ca-file v3-ca.crt`:
//!   - advertises `Alcyon Test Client Auth CA v3` in `CertificateRequest`;
//!   - no client certificate (TLS 1.3 & 1.2): 200 OK, `ssl_c_used=0`, `ssl_c_verify=0`,
//!     `ssl_c_err=0`, `ssl_c_ca_err=0`;
//!   - `v3-client-valid.pem` (TLS 1.3 & 1.2): 200 OK, `ssl_c_used=1`, `ssl_c_verify=0`,
//!     `ssl_c_err=0`, `ssl_c_ca_err=0`;
//!   - `v3-client-expired.pem` (TLS 1.3 & 1.2): handshake fails with alert 45 (`certificate expired`);
//!   - untrusted `common.pem` (TLS 1.3): handshake fails with alert 48 (`unknown ca`).
//! * `verify none` (control):
//!   - sends no `CertificateRequest` CA names;
//!   - even when the client holds `v3-client-valid.pem`, no client cert is requested or sent:
//!     200 OK, `ssl_c_used=0`, `ssl_c_verify=0`, `ssl_c_err=0`, `ssl_c_ca_err=0`.
//! * Documented difference (`docs/differences.md`): `ca-auth.crt` (v3 CA) + `client1.pem`
//!   (`HAProxy` reg-test X.509 v1 client cert). `HAProxy` accepts v1 client certs (200 OK, 1/0/0/0);
//!   Alcyon validates exclusively with `rustls-webpki` (v3 only), refusing `client1.pem` with
//!   `UnsupportedCertVersion` (`X509_V_ERR_UNSPECIFIED` = 1, alert 46 `certificate_unknown`).
//! * `-c` configuration checks match `HAProxy`'s messages, framing, and exit code 1.
//! * `error-log-format` exposes `ssl_c_used`, `ssl_c_verify`, `ssl_c_err`, `ssl_c_ca_err` on
//!   rejected client handshakes (expired leaf = 10/0, untrusted issuer = 20/0, self-signed = 18/0,
//!   wrong EKU = 26/0, expired intermediate CA = 0/10, missing cert = 0/0, `ssl_c_verify` = `-`).

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

/// Runs `openssl s_client` against `addr` sending one `GET /` and returns combined stdout+stderr.
fn s_client(addr: SocketAddr, tls_flag: &str, cert: Option<&Path>) -> String {
    s_client_chain(addr, tls_flag, cert, None)
}

/// Runs `openssl s_client` with an optional intermediate chain file (`-cert_chain`).
fn s_client_chain(addr: SocketAddr, tls_flag: &str, cert: Option<&Path>, chain: Option<&Path>) -> String {
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

/// Extracts a response header value (case-insensitive header name) from `s_client` output.
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

fn assert_ok_headers(label: &str, out: &str, used: &str, verify: &str, err: &str, ca_err: &str) {
    assert!(
        out.contains("HTTP/1.1 200 OK"),
        "{label}: expected HTTP/1.1 200 OK, got:\n{out}"
    );
    assert_eq!(header_value(out, "x-used").as_deref(), Some(used), "{label}: x-used mismatch in:\n{out}");
    assert_eq!(header_value(out, "x-verify").as_deref(), Some(verify), "{label}: x-verify mismatch in:\n{out}");
    assert_eq!(header_value(out, "x-err").as_deref(), Some(err), "{label}: x-err mismatch in:\n{out}");
    assert_eq!(header_value(out, "x-ca-err").as_deref(), Some(ca_err), "{label}: x-ca-err mismatch in:\n{out}");
}

fn assert_alert(label: &str, out: &str, alert_num: u8) {
    assert!(
        !out.contains("HTTP/1.1 200 OK"),
        "{label}: handshake should have failed, but got HTTP 200:\n{out}"
    );
    let needle = format!("SSL alert number {alert_num}");
    assert!(
        out.contains(&needle),
        "{label}: expected `{needle}`, got:\n{out}"
    );
}

fn check_required_frontend(fe_req: SocketAddr, v3_valid: &Path, v3_expired: &Path, srv_crt: &Path) {
    for ver in ["-tls1_3", "-tls1_2"] {
        let out = s_client(fe_req, ver, Some(v3_valid));
        assert!(
            out.contains("Alcyon Test Client Auth CA v3"),
            "fe_req ({ver}): expected CA name from v3-ca.crt in CertificateRequest, got:\n{out}"
        );
        assert_ok_headers(&format!("fe_req + v3-client-valid ({ver})"), &out, "1", "0", "0", "0");
    }
    for ver in ["-tls1_3", "-tls1_2"] {
        let out = s_client(fe_req, ver, Some(v3_expired));
        assert_alert(&format!("fe_req + v3-client-expired ({ver})"), &out, 45);
    }
    for ver in ["-tls1_3", "-tls1_2"] {
        let out = s_client(fe_req, ver, Some(srv_crt));
        assert_alert(&format!("fe_req + untrusted common.pem ({ver})"), &out, 48);
    }
    let out_13 = s_client(fe_req, "-tls1_3", None);
    assert_alert("fe_req + no cert (tls1_3)", &out_13, 116);
    let out_12 = s_client(fe_req, "-tls1_2", None);
    assert_alert("fe_req + no cert (tls1_2)", &out_12, 40);
}

fn check_optional_none_and_v1(
    fe_opt: SocketAddr,
    fe_none: SocketAddr,
    fe_v1: SocketAddr,
    v3_valid: &Path,
    v3_expired: &Path,
    srv_crt: &Path,
    v1_client1: &Path,
) {
    for ver in ["-tls1_3", "-tls1_2"] {
        let out = s_client(fe_opt, ver, None);
        assert!(
            out.contains("Alcyon Test Client Auth CA v3"),
            "fe_opt ({ver}): expected CA name from v3-ca.crt in CertificateRequest, got:\n{out}"
        );
        assert_ok_headers(&format!("fe_opt + no cert ({ver})"), &out, "0", "0", "0", "0");
    }
    for ver in ["-tls1_3", "-tls1_2"] {
        let out = s_client(fe_opt, ver, Some(v3_valid));
        assert_ok_headers(&format!("fe_opt + v3-client-valid ({ver})"), &out, "1", "0", "0", "0");
    }
    for ver in ["-tls1_3", "-tls1_2"] {
        let out = s_client(fe_opt, ver, Some(v3_expired));
        assert_alert(&format!("fe_opt + v3-client-expired ({ver})"), &out, 45);
    }
    let out = s_client(fe_opt, "-tls1_3", Some(srv_crt));
    assert_alert("fe_opt + untrusted common.pem (tls1_3)", &out, 48);

    // Control: verify none -> no CertificateRequest CA names, no client cert used
    let out = s_client(fe_none, "-tls1_3", Some(v3_valid));
    assert!(
        !out.contains("Acceptable client certificate CA names"),
        "fe_none (control): bind with verify none must not send CertificateRequest, got:\n{out}"
    );
    assert_ok_headers("fe_none + v3-client-valid (control)", &out, "0", "0", "0", "0");

    // Documented difference (docs/differences.md): reg-test X.509 v1 client1.pem against
    // v3 trust anchor ca-auth.crt. HAProxy/OpenSSL accepts v1 client certs (200 OK, 1/0/0/0);
    // Alcyon uses webpki only (v3) and refuses v1 client certs with alert 46 (code 1).
    let v1_out = s_client(fe_v1, "-tls1_3", Some(v1_client1));
    assert!(
        v1_out.contains("HAProxy Technologies CA Test Client Auth"),
        "fe_v1: expected CA name from ca-auth.crt in CertificateRequest, got:\n{v1_out}"
    );
    if is_oracle() {
        assert_ok_headers("fe_v1 + v1 client1.pem (oracle)", &v1_out, "1", "0", "0", "0");
    } else {
        assert_alert("fe_v1 + v1 client1.pem (alcyon: webpki v3 only)", &v1_out, 46);
    }
}

#[test]
fn bind_client_auth_required_optional_and_none() {
    let fx = fixtures_dir();
    let srv_crt = fx.join("common.pem");
    let v3_ca = fx.join("v3-ca.crt");
    let v3_valid = fx.join("v3-client-valid.pem");
    let v3_expired = fx.join("v3-client-expired.pem");
    let regtest_ca = fx.join("ca-auth.crt");
    let v1_client1 = fx.join("client1.pem");

    let fe_req = common::reserve_addr();
    let fe_opt = common::reserve_addr();
    let fe_none = common::reserve_addr();
    let fe_v1 = common::reserve_addr();
    let (origin_port, stop, origin_handle) = start_origin();

    let dir = std::env::temp_dir().join(format!("alcyon-bind-cauth-{}-{}", std::process::id(), fe_req.port()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let cfg_path = dir.join("cauth.cfg");
    let cfg = format!(
        "global\n\
         \x20 nbthread 1\n\
         defaults\n\
         \x20 mode http\n\
         \x20 timeout connect 5s\n\
         \x20 timeout client 5s\n\
         \x20 timeout server 5s\n\
         \n\
         frontend fe_req\n\
         \x20 bind {fe_req} ssl crt {} ca-file {} verify required\n\
         \x20 default_backend be\n\
         \n\
         frontend fe_opt\n\
         \x20 bind {fe_opt} ssl crt {} ca-file {} verify optional\n\
         \x20 default_backend be\n\
         \n\
         frontend fe_none\n\
         \x20 bind {fe_none} ssl crt {} verify none\n\
         \x20 default_backend be\n\
         \n\
         frontend fe_v1\n\
         \x20 bind {fe_v1} ssl crt {} ca-file {} verify required\n\
         \x20 default_backend be\n\
         \n\
         backend be\n\
         \x20 http-response set-header X-Used %[ssl_c_used]\n\
         \x20 http-response set-header X-Verify %[ssl_c_verify]\n\
         \x20 http-response set-header X-Err %[ssl_c_err]\n\
         \x20 http-response set-header X-Ca-Err %[ssl_c_ca_err]\n\
         \x20 server s1 127.0.0.1:{origin_port}\n",
        srv_crt.display(),
        v3_ca.display(),
        srv_crt.display(),
        v3_ca.display(),
        srv_crt.display(),
        srv_crt.display(),
        regtest_ca.display(),
    );
    std::fs::write(&cfg_path, &cfg).expect("write cfg");

    let child = Command::new(proxy_bin())
        .arg("-f")
        .arg(&cfg_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proxy");
    let _daemon = Daemon { child, dir, stop, origin: Some(origin_handle) };

    assert!(common::wait_listening(fe_req), "proxy never listened on fe_req ({fe_req})");
    assert!(common::wait_listening(fe_opt), "proxy never listened on fe_opt ({fe_opt})");
    assert!(common::wait_listening(fe_none), "proxy never listened on fe_none ({fe_none})");
    assert!(common::wait_listening(fe_v1), "proxy never listened on fe_v1 ({fe_v1})");

    check_required_frontend(fe_req, &v3_valid, &v3_expired, &srv_crt);
    check_optional_none_and_v1(fe_opt, fe_none, fe_v1, &v3_valid, &v3_expired, &srv_crt, &v1_client1);
}

fn recv_log_line(udp: &UdpSocket) -> String {
    let mut buf = [0u8; 4096];
    let n = udp.recv(&mut buf).expect("expected syslog error-log-format line");
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

fn write_pem_bundle(path: &Path, cert_pem: &str, key_pem: &str) {
    std::fs::write(path, format!("{cert_pem}{key_pem}")).expect("write pem");
}

struct ErrLogCerts {
    ca: PathBuf,
    expired: PathBuf,
    self_signed: PathBuf,
    wrong_eku: PathBuf,
    exp_inter: PathBuf,
    leaf_under_exp_inter: PathBuf,
}

fn make_errlog_certs(dir: &Path) -> ErrLogCerts {
    use rcgen::{date_time_ymd, BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair};

    let mut ca_p = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_p.distinguished_name.push(DnType::CommonName, "Ephemeral Client Auth CA");
    let ca_k = KeyPair::generate().expect("ca key");
    let ca_c = ca_p.self_signed(&ca_k).expect("ca cert");
    let ca = dir.join("ca.crt");
    std::fs::write(&ca, ca_c.pem()).expect("write ca");

    // 1. Expired leaf -> alert 45, err=10, ca_err=0
    let mut exp_p = CertificateParams::new(Vec::<String>::new()).expect("exp");
    exp_p.distinguished_name.push(DnType::CommonName, "expired-leaf");
    exp_p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    exp_p.not_before = date_time_ymd(2020, 1, 1);
    exp_p.not_after = date_time_ymd(2021, 1, 1);
    let exp_k = KeyPair::generate().expect("exp k");
    let exp_c = exp_p.signed_by(&exp_k, &ca_c, &ca_k).expect("exp c");
    let expired = dir.join("expired.pem");
    write_pem_bundle(&expired, &exp_c.pem(), &exp_k.serialize_pem());

    // 2. Self-signed untrusted leaf -> alert 48, err=18, ca_err=0
    let ss = rcgen::generate_simple_self_signed(vec!["self.example".to_string()]).expect("ss");
    let self_signed = dir.join("selfsigned.pem");
    write_pem_bundle(&self_signed, &ss.cert.pem(), &ss.key_pair.serialize_pem());

    // 3. Wrong EKU (ServerAuth only) under trusted CA -> alert 43, err=26, ca_err=0
    let mut eku_p = CertificateParams::new(Vec::<String>::new()).expect("eku");
    eku_p.distinguished_name.push(DnType::CommonName, "wrong-eku-leaf");
    eku_p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let eku_k = KeyPair::generate().expect("eku k");
    let eku_c = eku_p.signed_by(&eku_k, &ca_c, &ca_k).expect("eku c");
    let wrong_eku = dir.join("wrong_eku.pem");
    write_pem_bundle(&wrong_eku, &eku_c.pem(), &eku_k.serialize_pem());

    // 4. Valid leaf under expired intermediate CA -> alert 45, err=0, ca_err=10
    let mut inter_p = CertificateParams::new(Vec::<String>::new()).expect("inter");
    inter_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    inter_p.distinguished_name.push(DnType::CommonName, "Expired Inter CA");
    inter_p.not_before = date_time_ymd(2020, 1, 1);
    inter_p.not_after = date_time_ymd(2021, 1, 1);
    let inter_k = KeyPair::generate().expect("inter k");
    let inter_c = inter_p.signed_by(&inter_k, &ca_c, &ca_k).expect("inter c");
    let exp_inter = dir.join("exp_inter.crt");
    std::fs::write(&exp_inter, inter_c.pem()).expect("write inter");

    let mut leaf_p = CertificateParams::new(Vec::<String>::new()).expect("leaf");
    leaf_p.distinguished_name.push(DnType::CommonName, "leaf-under-exp-inter");
    leaf_p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let leaf_k = KeyPair::generate().expect("leaf k");
    let leaf_c = leaf_p.signed_by(&leaf_k, &inter_c, &inter_k).expect("leaf c");
    let leaf_under_exp_inter = dir.join("leaf_under_exp_inter.pem");
    write_pem_bundle(&leaf_under_exp_inter, &leaf_c.pem(), &leaf_k.serialize_pem());

    ErrLogCerts { ca, expired, self_signed, wrong_eku, exp_inter, leaf_under_exp_inter }
}

#[test]
fn bind_client_auth_error_log_exposes_x509_codes() {
    let fx = fixtures_dir();
    let srv_crt = fx.join("common.pem");
    let fe = common::reserve_addr();
    let udp = UdpSocket::bind("127.0.0.1:0").expect("bind udp log collector");
    udp.set_read_timeout(Some(Duration::from_secs(3))).expect("udp timeout");
    let log_port = udp.local_addr().expect("udp addr").port();

    let dir = std::env::temp_dir().join(format!("alcyon-bind-cauth-errlog-{}-{}", std::process::id(), fe.port()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let certs = make_errlog_certs(&dir);

    let cfg_path = dir.join("errlog.cfg");
    let cfg = format!(
        "global\n\
         \x20 nbthread 1\n\
         \x20 log 127.0.0.1:{log_port} local0\n\
         defaults\n\
         \x20 mode http\n\
         \x20 log global\n\
         \x20 option dontlognull\n\
         \x20 timeout connect 5s\n\
         \x20 timeout client 5s\n\
         \x20 timeout server 5s\n\
         frontend fe\n\
         \x20 bind {fe} ssl crt {} ca-file {} verify required\n\
         \x20 error-log-format \"used=%[ssl_c_used] verify=%[ssl_c_verify] err=%[ssl_c_err] ca_err=%[ssl_c_ca_err]\"\n\
         \x20 http-request return status 200 content-type text/plain string ok\n",
        srv_crt.display(),
        certs.ca.display(),
    );
    std::fs::write(&cfg_path, &cfg).expect("write cfg");

    let child = Command::new(proxy_bin())
        .arg("-f")
        .arg(&cfg_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proxy");
    let _daemon = Daemon { child, dir, stop: Arc::new(AtomicBool::new(false)), origin: None };
    assert!(common::wait_listening(fe), "proxy never listened on fe ({fe})");

    let cases = [
        ("expired leaf", Some(certs.expired.as_path()), None, 45u8, "used=1 verify=- err=10 ca_err=0"),
        ("untrusted issuer", Some(srv_crt.as_path()), None, 48, "used=1 verify=- err=20 ca_err=0"),
        ("self-signed untrusted", Some(certs.self_signed.as_path()), None, 48, "used=1 verify=- err=18 ca_err=0"),
        ("wrong EKU", Some(certs.wrong_eku.as_path()), None, 43, "used=1 verify=- err=26 ca_err=0"),
        ("expired intermediate CA", Some(certs.leaf_under_exp_inter.as_path()), Some(certs.exp_inter.as_path()), 45, "used=1 verify=- err=0 ca_err=10"),
        ("no client cert", None, None, 116, "used=0 verify=- err=0 ca_err=0"),
    ];
    for (label, cert, chain, alert, expected_log) in cases {
        let out = s_client_chain(fe, "-tls1_3", cert, chain);
        assert_alert(label, &out, alert);
        let line = recv_log_line(&udp);
        assert!(
            line.contains(expected_log),
            "{label}: expected error-log `{expected_log}`, got:\n{line}"
        );
    }
}

#[test]
fn bind_client_auth_config_checks_match_oracle() {
    let fx = fixtures_dir();
    let srv_crt = fx.join("common.pem");
    let ca_file = fx.join("v3-ca.crt");
    let dir = std::env::temp_dir().join(format!("alcyon-bind-cauth-cfg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");

    let run_check = |name: &str, bind_rest: &str| -> (i32, String, PathBuf) {
        let path = dir.join(format!("{name}.cfg"));
        let cfg = format!(
            "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n\
             frontend fe\n  bind 127.0.0.1:19443 {bind_rest}\n"
        );
        std::fs::write(&path, cfg).expect("write cfg");
        let out = Command::new(proxy_bin())
            .arg("-c")
            .arg("-f")
            .arg(&path)
            .output()
            .expect("run -c");
        let code = out.status.code().unwrap_or(-1);
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        (code, text, path)
    };

    // 1. Unknown verify method
    let (code, text, path) = run_check("verify_maybe", &format!("ssl crt {} verify maybe", srv_crt.display()));
    assert_eq!(code, 1, "verify maybe must exit 1:\n{text}");
    assert!(
        text.contains(&format!("parsing [{}:7]", path.display()))
            && text.contains("'verify' : unknown verify method 'maybe', only 'none', 'optional', and 'required' are supported"),
        "verify maybe message mismatch:\n{text}"
    );

    // 2. Missing CA file
    let missing = "/nonexistent/alcyon-c1a-missing-ca.crt";
    let (code, text, path) = run_check("missing_ca", &format!("ssl crt {} ca-file {missing} verify required", srv_crt.display()));
    assert_eq!(code, 1, "missing ca-file must exit 1:\n{text}");
    assert!(
        text.contains(&format!("parsing [{}:7]", path.display()))
            && text.contains(&format!("'ca-file' : unable to load {missing}")),
        "missing ca-file message mismatch:\n{text}"
    );

    // 3. verify required / optional without ca-file
    for mode in ["required", "optional"] {
        let (code, text, path) = run_check(&format!("no_ca_{mode}"), &format!("ssl crt {} verify {mode}", srv_crt.display()));
        assert_eq!(code, 1, "verify {mode} without ca-file must exit 1:\n{text}");
        let expected = format!(
            "Proxy 'fe': verify is enabled but no CA file specified for bind '127.0.0.1:19443' at [{}:7].",
            path.display()
        );
        assert!(text.contains(&expected), "verify {mode} no ca-file mismatch; expected `{expected}` in:\n{text}");
    }

    // 4. Valid configurations exit 0
    for (name, rest) in [
        ("ok_req", format!("ssl crt {} ca-file {} verify required", srv_crt.display(), ca_file.display())),
        ("ok_opt", format!("ssl crt {} ca-file {} verify optional", srv_crt.display(), ca_file.display())),
        ("ok_none", format!("ssl crt {} verify none", srv_crt.display())),
    ] {
        let (code, text, _) = run_check(name, &rest);
        assert_eq!(code, 0, "{name} should be valid, got exit {code}:\n{text}");
    }

    // 5. C1b keywords stay refused in Alcyon (HAProxy accepts them)
    if !is_oracle() {
        for kw in [
            format!("ssl crt {} ca-file {} verify required crl-file /tmp/crl.pem", srv_crt.display(), ca_file.display()),
            format!("ssl crt {} ca-verify-file {} verify required", srv_crt.display(), ca_file.display()),
            format!("ssl crt {} ca-file {} verify required crt-ignore-err all", srv_crt.display(), ca_file.display()),
            format!("ssl crt {} ca-file {} verify required ca-ignore-err all", srv_crt.display(), ca_file.display()),
            format!("ssl crt {} ca-file {} verify required no-ca-names", srv_crt.display(), ca_file.display()),
        ] {
            let (code, text, _) = run_check("c1b_refused", &kw);
            assert_eq!(code, 1, "C1b keyword must stay refused ({kw}):\n{text}");
            assert!(text.contains("not supported"), "C1b keyword refusal must explain why ({kw}):\n{text}");
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}
