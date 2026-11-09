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
//! rustls does not have it and answers with a `HelloRetryRequest`, so on Alcyon the capture is of
//! the second `ClientHello` -- the same lists, as `HAProxy`'s re-parse would give.

use crate::common;

use std::io::Write;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;

struct Alcyon(std::process::Child, #[allow(dead_code)] Vec<NamedTempFile>);

impl Drop for Alcyon {
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

/// The response headers: each new fetch of C2, the bins through `,hex`; `x-ja3` is the
/// documented JA3 line set as a request header first, then read back (and hashed).
const HEADERS: &[(&str, &str)] = &[
    ("x-cl", "%[ssl_fc_cipherlist_bin,hex]"),
    ("x-cl1", "%[ssl_fc_cipherlist_bin(1),hex]"),
    ("x-clhex", "%[ssl_fc_cipherlist_hex]"),
    ("x-clhex1", "%[ssl_fc_cipherlist_hex(1)]"),
    ("x-clstr", "%[ssl_fc_cipherlist_str]"),
    ("x-clstr1", "%[ssl_fc_cipherlist_str(1)]"),
    ("x-xxh", "%[ssl_fc_cipherlist_xxh]"),
    ("x-hid", "%[ssl_fc_protocol_hello_id]"),
    ("x-ext", "%[ssl_fc_extlist_bin,hex]"),
    ("x-ext1", "%[ssl_fc_extlist_bin(1),hex]"),
    ("x-ec", "%[ssl_fc_eclist_bin,hex]"),
    ("x-ec1", "%[ssl_fc_eclist_bin(1),hex]"),
    ("x-ecf", "%[ssl_fc_ecformats_bin,hex]"),
    ("x-sv", "%[ssl_fc_supported_versions_bin,hex]"),
    ("x-sv1", "%[ssl_fc_supported_versions_bin(1),hex]"),
    ("x-sa", "%[ssl_fc_sigalgs_bin,hex]"),
    ("x-sa1", "%[ssl_fc_sigalgs_bin(1),hex]"),
    ("x-ja3", "%[req.fhdr(x-ja3)]"),
    ("x-ja3md5", "%[req.fhdr(x-ja3),digest(md5),hex]"),
];

fn start(size: Option<u32>) -> (Alcyon, SocketAddr) {
    start_with(size, HEADERS)
}

fn start_with(size: Option<u32>, headers: &[(&str, &str)]) -> (Alcyon, SocketAddr) {
    start_cfg(size, headers, "")
}

/// `extra`: more `global` lines (`alcyon.ja4-compat`).
fn start_cfg(size: Option<u32>, headers: &[(&str, &str)], extra: &str) -> (Alcyon, SocketAddr) {
    let crt = cert();
    let addr = common::reserve_addr();
    let global = format!(
        "global\n{}{extra}",
        size.map_or_else(String::new, |n| format!("  tune.ssl.capture-buffer-size {n}\n"))
    );
    let ja3 = "%[ssl_fc_protocol_hello_id],%[ssl_fc_cipherlist_bin(1),be2dec(-,2)],%[ssl_fc_extlist_bin(1),be2dec(-,2)],\
               %[ssl_fc_eclist_bin(1),be2dec(-,2)],%[ssl_fc_ecformats_bin,be2dec(-,1)]";
    let hdrs: String = headers.iter().map(|(n, e)| format!(" hdr {n} \"{e}\"")).collect();
    let cfg = format!(
        "{global}defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend t\n  bind {addr} ssl crt {}\n  http-request set-header x-ja3 \"{ja3}\"\n  \
         http-request return status 200{hdrs}\n",
        crt.path().display()
    );
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(cfg.as_bytes()).unwrap();
    // `-c` first: a refused configuration says why, instead of a port that never listens.
    let check = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(f.path()).output().expect("run alcyon -c");
    assert!(check.status.success(), "config refused: {}", String::from_utf8_lossy(&check.stderr));
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    let alcyon = Alcyon(child, vec![crt, f]);
    assert!(common::wait_listening(addr), "alcyon never listened on {addr}");
    (alcyon, addr)
}

const C1: &str = "-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256 -groups X25519:P-256 \
                  -sigalgs ECDSA+SHA256:RSA-PSS+SHA256 -servername localhost -alpn http/1.1";
const C2: &str = "-tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305 -groups X25519:P-256 \
                  -sigalgs ECDSA+SHA256:RSA-PSS+SHA256 -servername localhost -alpn http/1.1";
const C3: &str = "-servername localhost";
const C4: &str = "-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256 -groups X25519:P-256 \
                  -sigalgs ECDSA+SHA256:RSA-PSS+SHA256 -noservername -alpn http/1.1";
/// Client 1 with a first ALPN value that is not a letter or digit at either end (`/x`).
const C9: &str = "-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256 -groups X25519:P-256 \
                  -sigalgs ECDSA+SHA256:RSA-PSS+SHA256 -servername localhost -alpn /x";
const C7: &str = "-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups P-521:X25519 -servername localhost";
/// 164 bytes of ciphers: `ALL:COMPLEMENTOFALL` with the TLS 1.3 suites (OpenSSL only offers
/// what the protocol range allows, so not the 300+ bytes the plan hoped for).
const C8: &str = "-cipher ALL:COMPLEMENTOFALL:@SECLEVEL=0 -ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:\
                  TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256 -servername localhost";

/// The response headers of one GET: `openssl s_client` with `opts` for clients 1-4 and 7,
/// `curl --tlsv1.3 -k` for client 6.
fn get(addr: SocketAddr, client: u8) -> String {
    let out = if client == 5 {
        // A python `ssl` client with default settings (OpenSSL underneath, no verification).
        let script = "import ssl,socket,sys\nc=ssl.create_default_context();c.check_hostname=False;c.verify_mode=ssl.CERT_NONE\n\
            h,p=sys.argv[1].rsplit(':',1)\ns=c.wrap_socket(socket.create_connection((h,int(p)),5),server_hostname='localhost')\n\
            s.sendall(b'GET / HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n')\nd=b''\n\
            while True:\n b=s.recv(65536)\n if not b: break\n d+=b\nsys.stdout.write(d.decode())\n";
        Command::new("python3").args(["-c", script]).arg(addr.to_string()).output().expect("run python3")
    } else if client == 6 {
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
            8 => C8,
            9 => C9,
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
    let (_alcyon, addr) = start(size);
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

/// Every fetch of C2 against `HAProxy`'s answers (`ssl_capture_table.rs`, recorded with the
/// same config and clients): sizes 1024, 128, 16, 0 and unset; `x-ja3`/`x-ja3md5` too.
fn table(size: Option<u32>) {
    let (_alcyon, addr) = start(size);
    let key = size.map_or_else(|| "unset".to_string(), |n| n.to_string());
    for &(n, client, expect) in crate::ssl_capture_table::HAPROXY {
        if n != key {
            continue;
        }
        let r = get(addr, client);
        for (name, _) in HEADERS {
            let want = expect.iter().find(|(k, _)| k == name).map_or("<none>", |(_, v)| v);
            assert_eq!(hdr(&r, name), want, "N {key}, client {client}, {name}: {r}");
        }
    }
}

#[test]
fn table_1024() {
    table(Some(1024));
}

#[test]
fn table_128() {
    table(Some(128));
}

#[test]
fn table_16() {
    table(Some(16));
}

#[test]
fn table_0() {
    table(Some(0));
}

#[test]
fn table_unset() {
    table(None);
}

/// The argument checks match `HAProxy`'s texts (measured with `haproxy -c`): a fetch without
/// an argument spec refuses `(1)`, an integer argument refuses a word. (`HAProxy` quotes the
/// rest of the line, `')]'`, where Alcyon stops at the `]`: the texts are compared up to there.)
#[test]
fn argument_errors() {
    for (expr, text) in [
        ("ssl_fc_cipherlist_xxh(1)", "fetch method 'ssl_fc_cipherlist_xxh' : expected ')' before '1)"),
        ("ssl_fc_ecformats_bin(1)", "fetch method 'ssl_fc_ecformats_bin' : expected ')' before '1)"),
        ("ssl_fc_extlist_bin(abc)", "fetch method 'ssl_fc_extlist_bin' : failed to parse 'abc' as type 'integer' at position 1."),
        ("ssl_fc_cipherlist_hex(x)", "fetch method 'ssl_fc_cipherlist_hex' : failed to parse 'x' as type 'integer' at position 1."),
        ("ssl_fc_sigalgs_bin(1,2)", "fetch method 'ssl_fc_sigalgs_bin' : expected ')' before ',2)"),
    ] {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "frontend t\n  mode http\n  bind 127.0.0.1:1\n  http-request return status 200 hdr x \"%[{expr}]\"\n").unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(f.path()).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{expr} accepted: {err}");
        assert!(err.contains(text), "{expr}: wanted `{text}` in {err}");
    }
}

/// `ssl_fc_ja4` is Alcyon-only (T344 JA4, user decision 2026-10-18): `HAProxy` refuses it, Alcyon
/// answers. No oracle for the value; the expected strings are the JA4 rule of FoxIO's
/// `technical_details/JA4.md` applied to the lists `HAProxy` measured for the same clients
/// (`ssl_capture_table.rs`, N = 1024: `x-cl1`, `x-ext1`, `x-sa1`, `x-sv1`) and the ALPN each
/// client offers (`http/1.1` for 1, 2 and 4, curl `h2,http/1.1`, none for the others). The rule
/// itself is checked against FoxIO's published vectors in `alcyon-sample`'s `ja4` tests.
const JA4: &[(u8, &str)] = &[
    (1, "t13d0212h1_88d8eb61a8ee_f7b8ee8a4e9e"),
    (2, "t12d0209h1_d23a474016f0_7a0c0693ab17"),
    (3, "t13d351200_bfa337485184_a141b6f9fa1c"),
    (4, "t13i0211h1_88d8eb61a8ee_f7b8ee8a4e9e"),
    (5, "t13d351200_bfa337485184_a141b6f9fa1c"),
    (6, "t13i0411h2_9caa18292e23_e6e6d98f61e7"),
    (7, "t13d011100_0f2cb44170f4_c657c3cd4f7d"),
    (8, "t13d821200_ce333ca46318_a141b6f9fa1c"),
];

fn ja4_check(size: Option<u32>) {
    let (_alcyon, addr) = start_with(size, &[("x-ja4", "%[ssl_fc_ja4]")]);
    for &(client, want) in JA4 {
        let r = get(addr, client);
        let want = if matches!(size, Some(n) if n > 0) { want } else { "<none>" };
        assert_eq!(hdr(&r, "x-ja4"), want, "client {client}, N {size:?}: {r}");
    }
}

#[test]
fn ja4_is_answered_with_the_capture_on() {
    ja4_check(Some(1024));
}

/// The fingerprint reads the whole hello, so a small buffer does not change it.
#[test]
fn ja4_does_not_depend_on_the_buffer_size() {
    ja4_check(Some(16));
}

#[test]
fn ja4_gives_no_sample_without_a_capture() {
    ja4_check(Some(0));
    ja4_check(None);
}

/// `HAProxy -c` refuses the fetch (so a configuration using it does not run on HAProxy), Alcyon
/// accepts it. Skipped when the reference binary is not installed.
#[test]
fn haproxy_refuses_ja4() {
    let haproxy = std::path::Path::new("/home/bhenc/reference/haproxy/haproxy");
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(
        b"frontend t\n  mode http\n  bind 127.0.0.1:1\n  http-request return status 200 hdr x \"%[ssl_fc_ja4]\"\n",
    )
    .unwrap();
    let alcyon = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(f.path()).output().unwrap();
    assert!(alcyon.status.success(), "{}", String::from_utf8_lossy(&alcyon.stderr));
    if haproxy.exists() {
        let out = Command::new(haproxy).arg("-c").arg("-f").arg(f.path()).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success() && err.contains("unknown fetch method 'ssl_fc_ja4'"), "{err}");
    }
}

/// `alcyon.ja4-compat`: a first ALPN value `/x` is `/x` for FoxIO's tools and `28` (hex digits of
/// `2f78`) for the specification text; everything else of the fingerprint is client 1's. The
/// default is `foxio`. (The non-ASCII case, `99` against `bd`, is in the `alcyon-sample` vectors:
/// a TLS client library cannot be made to offer it.)
#[test]
fn ja4_compat_picks_the_alpn_rule() {
    for (extra, want) in [
        ("", "t13d0212/x_88d8eb61a8ee_f7b8ee8a4e9e"),
        ("  alcyon.ja4-compat foxio\n", "t13d0212/x_88d8eb61a8ee_f7b8ee8a4e9e"),
        ("  alcyon.ja4-compat spec\n", "t13d021228_88d8eb61a8ee_f7b8ee8a4e9e"),
    ] {
        let (_alcyon, addr) = start_cfg(Some(1024), &[("x-ja4", "%[ssl_fc_ja4]")], extra);
        let r = get(addr, 9);
        assert_eq!(hdr(&r, "x-ja4"), want, "{extra:?}: {r}");
    }
}
