// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T328: `x509_v_err_str` converter

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Alcyon(Child, std::path::PathBuf);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Starts alcyon on `cfg` (`{sock}` is replaced by the stats socket path), waits for `addrs` and the
/// socket, then lets the readiness probes slide out of the one-second windows and clears the maxima.
fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> (Alcyon, String) {
    let dir = std::env::temp_dir().join(format!("qh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg.replace("{sock}", &sock).replace("{dir}", &dir.display().to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let alcyon = Alcyon(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "alcyon did not listen on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(2200));
    cli(&sock, "clear counters");
    (alcyon, sock)
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
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

/// The request every case answers; `x-c` feeds the `hdr(x-c)` cases.
const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\nx-c: 20\r\nConnection: close\r\n\r\n";

fn http_cfg(global: &str, body: &str) -> String {
    format!(
        "global\n  stats socket {{sock}} level admin\n{global}\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n{body}"
    )
}

/// The body of the answer to `req` (what follows the first empty line).
fn body(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    s.split_once("\r\n\r\n").map_or_else(|| panic!("no answer: {s:?}"), |(_, b)| b.to_string())
}

#[test]
fn x509_v_err_str_converter() {
    let a = common::reserve_addr();
    let cfg = http_cfg(
        "",
        &format!(
            "frontend fe\n  bind {a}\n\
             http-request return status 200 content-type text/plain lf-string \
             \"[%[int(0),x509_v_err_str]|%[int(10),x509_v_err_str]|%[int(20),x509_v_err_str]|%[int(94),x509_v_err_str]|%[int(95),x509_v_err_str]|%[int(-1),x509_v_err_str]|%[str(abc),x509_v_err_str]\
             |%[str(10),x509_v_err_str]|%[hdr(x-c),x509_v_err_str]|%[str(),x509_v_err_str]|%[int(4294967306),x509_v_err_str]|%[hdr(x-none),x509_v_err_str]]\
             {{%[str(10),sub(3)]|%[str(10),mul(2)]|%[hdr(x-c),add(1)]|%[str(7),neg]|%[str(1),bool]|%[str(3),odd]|%[str(1),htonl,hex]|%[str(5),div(2)]\
             |%[str(10),add(5)]|%[bool(1),add(1)]|%[str(abc),add(5)]}}\""
        ),
    );
    let (_alcyon, _sock) = start("x509_v_err_str", &cfg, &[a]);
    // Measured on HAProxy 3.5-dev8 with `x-c: 20`. The input is cast to an integer first, as for
    // every integer converter: str(10) is 10, an empty string or a missing header gives no
    // sample, and the code is read as a 32-bit int (4294967306 is 10).
    let expected = "[X509_V_OK|X509_V_ERR_CERT_HAS_EXPIRED|X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY|X509_V_ERR_EC_KEY_EXPLICIT_PARAMS|95|18446744073709551615|X509_V_OK\
                    |X509_V_ERR_CERT_HAS_EXPIRED|X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY||X509_V_ERR_CERT_HAS_EXPIRED|]\
                    {7|20|21|-7|1|1|00000001|2|15|2|5}";
    assert_eq!(body(a, GET), expected);
}

/// Every code the table names, 0 to 94, and the first two it does not (95, 96), one line each.
/// Measured on HAProxy 3.5-dev8 (`int(N),x509_v_err_str` for N in 0..=96). Covers the whole
/// `x509_v_err_name` table of alcyon-sample's registry.
#[test]
fn x509_v_err_str_every_code() {
    const NAMES: [&str; 95] = [
    "X509_V_OK",
    "X509_V_ERR_UNSPECIFIED",
    "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT",
    "X509_V_ERR_UNABLE_TO_GET_CRL",
    "X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE",
    "X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE",
    "X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY",
    "X509_V_ERR_CERT_SIGNATURE_FAILURE",
    "X509_V_ERR_CRL_SIGNATURE_FAILURE",
    "X509_V_ERR_CERT_NOT_YET_VALID",
    "X509_V_ERR_CERT_HAS_EXPIRED",
    "X509_V_ERR_CRL_NOT_YET_VALID",
    "X509_V_ERR_CRL_HAS_EXPIRED",
    "X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD",
    "X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD",
    "X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD",
    "X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD",
    "X509_V_ERR_OUT_OF_MEM",
    "X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT",
    "X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN",
    "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
    "X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE",
    "X509_V_ERR_CERT_CHAIN_TOO_LONG",
    "X509_V_ERR_CERT_REVOKED",
    "X509_V_ERR_NO_ISSUER_PUBLIC_KEY",
    "X509_V_ERR_PATH_LENGTH_EXCEEDED",
    "X509_V_ERR_INVALID_PURPOSE",
    "X509_V_ERR_CERT_UNTRUSTED",
    "X509_V_ERR_CERT_REJECTED",
    "X509_V_ERR_SUBJECT_ISSUER_MISMATCH",
    "X509_V_ERR_AKID_SKID_MISMATCH",
    "X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH",
    "X509_V_ERR_KEYUSAGE_NO_CERTSIGN",
    "X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER",
    "X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION",
    "X509_V_ERR_KEYUSAGE_NO_CRL_SIGN",
    "X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION",
    "X509_V_ERR_INVALID_NON_CA",
    "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED",
    "X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE",
    "X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED",
    "X509_V_ERR_INVALID_EXTENSION",
    "X509_V_ERR_INVALID_POLICY_EXTENSION",
    "X509_V_ERR_NO_EXPLICIT_POLICY",
    "X509_V_ERR_DIFFERENT_CRL_SCOPE",
    "X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE",
    "X509_V_ERR_UNNESTED_RESOURCE",
    "X509_V_ERR_PERMITTED_VIOLATION",
    "X509_V_ERR_EXCLUDED_VIOLATION",
    "X509_V_ERR_SUBTREE_MINMAX",
    "X509_V_ERR_APPLICATION_VERIFICATION",
    "X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE",
    "X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX",
    "X509_V_ERR_UNSUPPORTED_NAME_SYNTAX",
    "X509_V_ERR_CRL_PATH_VALIDATION_ERROR",
    "X509_V_ERR_PATH_LOOP",
    "X509_V_ERR_SUITE_B_INVALID_VERSION",
    "X509_V_ERR_SUITE_B_INVALID_ALGORITHM",
    "X509_V_ERR_SUITE_B_INVALID_CURVE",
    "X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM",
    "X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED",
    "X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256",
    "X509_V_ERR_HOSTNAME_MISMATCH",
    "X509_V_ERR_EMAIL_MISMATCH",
    "X509_V_ERR_IP_ADDRESS_MISMATCH",
    "X509_V_ERR_DANE_NO_MATCH",
    "X509_V_ERR_EE_KEY_TOO_SMALL",
    "X509_V_ERR_CA_KEY_TOO_SMALL",
    "X509_V_ERR_CA_MD_TOO_WEAK",
    "X509_V_ERR_INVALID_CALL",
    "X509_V_ERR_STORE_LOOKUP",
    "X509_V_ERR_NO_VALID_SCTS",
    "X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION",
    "X509_V_ERR_OCSP_VERIFY_NEEDED",
    "X509_V_ERR_OCSP_VERIFY_FAILED",
    "X509_V_ERR_OCSP_CERT_UNKNOWN",
    "X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM",
    "X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH",
    "X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY",
    "X509_V_ERR_INVALID_CA",
    "X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA",
    "X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN",
    "X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA",
    "X509_V_ERR_ISSUER_NAME_EMPTY",
    "X509_V_ERR_SUBJECT_NAME_EMPTY",
    "X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER",
    "X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER",
    "X509_V_ERR_EMPTY_SUBJECT_ALT_NAME",
    "X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL",
    "X509_V_ERR_CA_BCONS_NOT_CRITICAL",
    "X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL",
    "X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL",
    "X509_V_ERR_CA_CERT_MISSING_KEY_USAGE",
    "X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3",
    "X509_V_ERR_EC_KEY_EXPLICIT_PARAMS",
    ];
    let lf: String = (0..=96).map(|n| format!("{n}=%[int({n}),x509_v_err_str]\\n")).collect();
    let a = common::reserve_addr();
    let cfg = http_cfg(
        "",
        &format!("frontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"{lf}\"\n"),
    );
    let (_alcyon, _sock) = start("x509_v_err_all", &cfg, &[a]);
    let mut expected: String = NAMES.iter().enumerate().map(|(n, s)| format!("{n}={s}\n")).collect();
    expected.push_str("95=95\n96=96\n");
    assert_eq!(body(a, GET), expected);
}
