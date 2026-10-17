// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `ClientHello` capture (`tune.ssl.capture-buffer-size`) and the two fetches of T344 C1:
//! `ssl_fc_cipherlist_bin` and `ssl_fc_protocol_hello_id`.
//!
//! Before: the keyword was accepted and dropped, and either fetch was refused at load as
//! unknown. The client is `openssl s_client` (or `curl`), not rustls, so the offered lists are
//! the ones its options name. The expected values were recorded on `HAProxy`
//! 3.5-dev8-885761-29 (`OpenSSL` 3.5) with the same rule and the same clients (`OpenSSL` 3.5.9,
//! curl 8.18.0), `bind ... ssl crt <ECDSA P-256 pem>`:
//!
//! * N = 1024: every client's whole cipher list; the legacy version is 771 for all of them;
//! * N = 16: the list cut at 16 bytes (only the default client offers more);
//! * N = 0, and the keyword unset: no sample, so both headers are left out;
//! * curl negotiates HTTP/2 (`HTTP/2 200`), the `s_client` rows HTTP/1.1.
//!
//! Client 7 offers P-521 first, the only group it sends a key share for. `OpenSSL` takes it;
//! rustls does not have it and answers with a `HelloRetryRequest`, so on Ibex the capture is of
//! the second `ClientHello` -- the same lists, as `HAProxy`'s re-parse would give.

use crate::common;

use std::io::Write;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;

struct Ibex(std::process::Child, #[allow(dead_code)] Vec<NamedTempFile>);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn cert() -> NamedTempFile {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.subject_alt_names.push(rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])));
    let key = rcgen::KeyPair::generate().unwrap();
    let c = params.self_signed(&key).unwrap();
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(format!("{}{}", c.pem(), key.serialize_pem()).as_bytes()).unwrap();
    f
}

fn start(size: Option<u32>) -> (Ibex, SocketAddr) {
    let crt = cert();
    let addr = common::reserve_addr();
    let global = size.map_or_else(String::new, |n| format!("global\n  tune.ssl.capture-buffer-size {n}\n"));
    let cfg = format!(
        "{global}defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend t\n  bind {addr} ssl crt {}\n  http-request return status 200 \
         hdr x-cl \"%[ssl_fc_cipherlist_bin,hex]\" hdr x-hid \"%[ssl_fc_protocol_hello_id]\"\n",
        crt.path().display()
    );
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(cfg.as_bytes()).unwrap();
    // `-c` first: a refused configuration says why, instead of a port that never listens.
    let check = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run ibex -c");
    assert!(check.status.success(), "config refused: {}", String::from_utf8_lossy(&check.stderr));
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex(child, vec![crt, f]);
    assert!(common::wait_listening(addr), "ibex never listened on {addr}");
    (ibex, addr)
}

const C1: &str = "-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256 -groups X25519:P-256 \
                  -sigalgs ECDSA+SHA256:RSA-PSS+SHA256 -servername localhost -alpn http/1.1";
const C2: &str = "-tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305 -groups X25519:P-256 \
                  -sigalgs ECDSA+SHA256:RSA-PSS+SHA256 -servername localhost -alpn http/1.1";
const C3: &str = "-servername localhost";
const C4: &str = "-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256 -groups X25519:P-256 \
                  -sigalgs ECDSA+SHA256:RSA-PSS+SHA256 -noservername -alpn http/1.1";
const C7: &str = "-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups P-521:X25519 -servername localhost";

/// The response headers of one GET: `openssl s_client` with `opts` for clients 1-4 and 7,
/// `curl --tlsv1.3 -k` for client 6.
fn get(addr: SocketAddr, client: u8) -> String {
    let out = if client == 6 {
        Command::new("curl")
            .args(["-s", "-k", "--tlsv1.3", "-m", "5", "-D", "-", "-o", "/dev/null"])
            .arg(format!("https://{addr}/"))
            .output()
            .expect("run curl")
    } else {
        let opts = match client {
            1 => C1,
            2 => C2,
            3 => C3,
            4 => C4,
            _ => C7,
        };
        let mut child = Command::new("openssl")
            .arg("s_client")
            .arg("-connect")
            .arg(addr.to_string())
            .args(opts.split_whitespace())
            .args(["-ign_eof", "-quiet"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("run openssl s_client");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        child.wait_with_output().unwrap()
    };
    String::from_utf8_lossy(&out.stdout).replace('\r', "")
}

fn hdr(resp: &str, name: &str) -> String {
    resp.lines()
        .find_map(|l| l.strip_prefix(&format!("{name}: ")))
        .map_or_else(|| "<none>".to_string(), |v| v.trim().to_string())
}

const DEFAULT_LIST: &str = "1302130313011304C02CC030CCA9CCA8C0ADC02BC02FC0ACC023C027C00AC014C009C013009DC09D009CC09C\
                            003D003C0035002F009FCCAAC09F009EC09E006B006700390033";

/// (client, x-cl at N = 1024, x-cl at N = 16), as `HAProxy` answered.
const ROWS: &[(u8, &str, &str)] = &[
    (1, "13011303", "13011303"),
    (2, "C02BCCA8", "C02BCCA8"),
    (3, DEFAULT_LIST, "1302130313011304C02CC030CCA9CCA8"),
    (4, "13011303", "13011303"),
    (6, "1302130313011304", "1302130313011304"),
    (7, "1301", "1301"),
];

fn check(size: Option<u32>) {
    let (_ibex, addr) = start(size);
    for &(client, full, cut) in ROWS {
        let r = get(addr, client);
        // curl gets HTTP/2 from both proxies (the bind's default ALPN), the others HTTP/1.1.
        assert!(r.starts_with("HTTP/1.1 200") || r.starts_with("HTTP/2 200"), "client {client}, N {size:?}: {r}");
        let (cl, hid) = match size {
            Some(1024) => (full, "771"),
            Some(16) => (cut, "771"),
            _ => ("<none>", "<none>"),
        };
        assert_eq!(hdr(&r, "x-cl"), cl, "client {client}, N {size:?}: {r}");
        assert_eq!(hdr(&r, "x-hid"), hid, "client {client}, N {size:?}: {r}");
    }
}

#[test]
fn capture_1024_holds_every_list() {
    check(Some(1024));
}

#[test]
fn capture_16_cuts_the_cipher_list() {
    check(Some(16));
}

#[test]
fn capture_0_gives_no_sample() {
    check(Some(0));
}

#[test]
fn capture_unset_gives_no_sample() {
    check(None);
}

/// The `GREASE` filter (`ssl_fc_cipherlist_bin(1)`) comes with the next slice: until then the
/// argument is refused, so it cannot load and do nothing.
#[test]
fn the_grease_argument_is_refused_for_now() {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(
        b"frontend t\n  mode http\n  bind 127.0.0.1:1\n  http-request return status 200 hdr x \"%[ssl_fc_cipherlist_bin(1),hex]\"\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "accepted: {err}");
    assert!(err.contains("GREASE"), "{err}");
}
