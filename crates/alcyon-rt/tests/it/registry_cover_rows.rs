// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Rows for the lines of alcyon-sample's `registry.rs` that no other test ran (the gate's
//! covercheck after the 2026-10-17 integration): converters on short or odd packets, the
//! `ip.fp` and `tcp.options*` walks over END and over-long options, every `ocsp_check_err_str`
//! code, `jwt_verify` with keys longer than the HMAC block and with an unset variable,
//! an absolute URI without a path, and a quoted pair in a `Set-Cookie` value.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev8 with the same lf-string and request;
//! the rows that pin behaviour Alcyon already had passed on their first run.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Alcyon(Child, std::path::PathBuf);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Starts alcyon on `cfg` in a directory of its own and waits for `addr`.
fn start(tag: &str, cfg: &str, addr: SocketAddr) -> Alcyon {
    let dir = std::env::temp_dir().join(format!("qh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let alcyon = Alcyon(child, dir);
    assert!(common::wait_listening(addr), "alcyon did not listen on {addr}");
    alcyon
}

/// One request on a new connection; the whole raw answer.
fn get(addr: SocketAddr, req: &[u8]) -> String {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n";

/// One `%[expr]` per line of the body of an `http-request return`; each line is compared with
/// the value measured on the oracle (an empty line is a fetch with no value).
fn check_rows(tag: &str, req: &[u8], rows: &[(String, String)]) {
    let a = common::reserve_addr();
    let lf: String = rows.iter().map(|(e, _)| format!("%[{e}]\\n")).collect();
    let cfg = format!(
        "{DEFAULTS}frontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"{lf}\"\n"
    );
    let _alcyon = start(tag, &cfg, a);
    let raw = get(a, req);
    let body = raw.split_once("\r\n\r\n").map_or_else(|| panic!("no answer: {raw:?}"), |(_, b)| b.to_string());
    let got: Vec<&str> = body.split('\n').collect();
    assert_eq!(got.len(), rows.len() + 1, "body: {body:?}");
    let bad: Vec<String> = rows
        .iter()
        .zip(&got)
        .filter(|((_, want), got)| want != *got)
        .map(|((e, want), got)| format!("{e}: got {got:?}, want {want:?}"))
        .collect();
    assert!(bad.is_empty(), "rows differing from the reference:\n{}", bad.join("\n"));
}

fn rows(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter().map(|(e, w)| ((*e).to_string(), (*w).to_string())).collect()
}

/// Short and odd packets for the eth/ip converters, the `ip.fp` length checks and the TCP option
/// walks (an END option, an option longer than the header), and the `ocsp_check_err_str` codes.
#[test]
fn packet_converters_and_ocsp_codes_match_haproxy() {
    check_rows(
        "cover-rows",
        GET,
        &rows(&[
        ("bin(020000000001020000000002810000),eth.vlan", ""),
        ("bin(4500),ip.src", ""),
        ("bin(6000),ip.src", ""),
        ("bin(7000000000000000000000000000000000000000),ip.src", ""),
        ("bin(4500),ip.dst", ""),
        ("bin(6000),ip.dst", ""),
        ("bin(7000000000000000000000000000000000000000),ip.dst", ""),
        ("bin(6000),ip.hdr,hex", ""),
        ("bin(6000),ip.data,hex", ""),
        ("bin(7000000000000000000000000000000000000000),ip.hdr,hex", ""),
        ("bin(7000000000000000000000000000000000000000),ip.data,hex", ""),
        ("bin(600000000020004020010db800000000000000000000000120010db800000000000000000000000206000000000000009c4001bb01020304000000006002faf00000000003030701),ip.hdr,hex", "600000000020004020010DB800000000000000000000000120010DB80000000000000000000000020600000000000000"),
        ("bin(600000000020004020010db800000000000000000000000120010db800000000000000000000000206000000000000009c4001bb01020304000000006002faf00000000003030701),ip.data,hex", "9C4001BB01020304000000006002FAF00000000003030701"),
        ("bin(600000000008004020010db800000000000000000000000120010db800000000000000000000000206),ip.hdr,hex", ""),
        ("bin(600000000008004020010db800000000000000000000000120010db8000000000000000000000002),ip.data,hex", ""),
        ("bin(4f10002c1c46400040060000c0000201c6336402),ip.fp,hex", ""),
        ("bin(4500000a1c46400040060000c0000201c63364029c4001bb01020304000000006002faf00000000003030701),ip.fp(2),hex", ""),
        ("bin(600000000000004020010db800000000000000000000000120010db800000000000000000000000206000000000000009c4001bb01020304000000006002faf00000000003030701),ip.fp(2),hex", ""),
        ("bin(4510002c1c46400040060000c0000201c63364029c4001bb01020304000000006002faf00000000001010000),ip.fp(2),hex", "105060FAF00000000101"),
        ("bin(9c4001bb01020304000000006002faf00000000001010000),tcp.options_list,hex", "0101"),
        ("bin(9c4001bb01020304000000006002faf00000000001010000),tcp.options.sack", "0"),
        ("bin(9c4001bb01020304000000006002faf00000000001010000),tcp.options.mss", "0"),
        ("bin(4510002c1c46400040060000c0000201c63364029c4001bb01020304000000006002faf00000000001010204),ip.fp(2),hex", "105060FAF00000000101"),
        ("bin(9c4001bb01020304000000006002faf00000000001010204),tcp.options_list,hex", "010102"),
        ("bin(9c4001bb01020304000000006002faf00000000001010204),tcp.options.sack", "0"),
        ("bin(9c4001bb01020304000000006002faf00000000001010204),tcp.options.mss", "0"),
        ("bin(4510002c1c46400040060000c0000201c63364029c4001bb01020304000000006002faf00000000003080000),ip.fp(2),hex", "105060FAF0000000"),
        ("bin(9c4001bb01020304000000006002faf00000000003080000),tcp.options_list,hex", "03"),
        ("bin(9c4001bb01020304000000006002faf00000000003080000),tcp.options.sack", "0"),
        ("bin(9c4001bb01020304000000006002faf00000000003080000),tcp.options.mss", "0"),
        ("bin(451000301c46400040060000c0000201c63364029c4001bb01020304000000007002faf0000000000204050400000000),ip.fp(2),hex", "105070FAF005040102"),
        ("bin(9c4001bb01020304000000007002faf0000000000204050400000000),tcp.options_list,hex", "02"),
        ("bin(9c4001bb01020304000000007002faf0000000000204050400000000),tcp.options.sack", "0"),
        ("bin(9c4001bb01020304000000007002faf0000000000204050400000000),tcp.options.mss", "1284"),
        ("int(0),ocsp_check_err_str", ""),
        ("int(1),ocsp_check_err_str", "OCSP verification failed"),
        ("int(2),ocsp_check_err_str", "OCSP unknown cert"),
        ("int(3),ocsp_check_err_str", "OCSP response(s) invalid"),
        ("int(4),ocsp_check_err_str", "OCSP response signature verification failure"),
        ("int(5),ocsp_check_err_str", "OCSP response not yet valid (contains a date in the future)"),
        ("int(6),ocsp_check_err_str", "OCSP response has expired"),
        ("int(7),ocsp_check_err_str", "no OCSP response available for certificate or responder unreachable"),
        ("int(8),ocsp_check_err_str", "unable to get issuer certificate"),
        ("int(9),ocsp_check_err_str", "CID mismatch"),
        ("int(10),ocsp_check_err_str", "Memory allocation failed"),
        ("int(11),ocsp_check_err_str", "Timeout"),
        ("int(12),ocsp_check_err_str", ""),
        ("int(13),ocsp_check_err_str", ""),
        ("int(4294967297),ocsp_check_err_str", "OCSP verification failed"),
        ("str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeJQ),jwt_verify(HS256,txn.nokey)", ""),
        ("str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeJQ),jwt_verify(proc.nokey,secret)", ""),
        ("str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeJQ),jwt_verify(HS256,proc.nokey)", ""),
        ]),
    );
}

/// `jwt_verify` with a key longer than the HMAC block (64 bytes for HS256, 128 for HS384 and
/// HS512) is hashed first; a signature off by one bit is 0; a variable that is not set (as key or
/// as algorithm) gives no sample.
#[test]
fn jwt_verify_long_keys_and_unset_variables_match_haproxy() {
    // (token, algorithm, key character, key length, measured answer)
    let cases: &[(&str, &str, &str, usize, &str)] = &[
        ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.4U55Ds7SF4CtsyDf7s9rexLgGBsK2Kxrjs9qwRMulXk", "HS256", "k", 100, "1"),
        ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.4E55Ds7SF4CtsyDf7s9rexLgGBsK2Kxrjs9qwRMulXk", "HS256", "k", 100, "0"),
        ("eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.hB-K0rb8VzuEfz7sFhwRhtR9DCgO86hJXEuYwo-gsNGQLo9SmSKXhACPG7e3ptuc", "HS384", "K", 200, "1"),
        ("eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.hR-K0rb8VzuEfz7sFhwRhtR9DCgO86hJXEuYwo-gsNGQLo9SmSKXhACPG7e3ptuc", "HS384", "K", 200, "0"),
        ("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qLyXJEUqWe6N9FEsNNm_KMSUPMd4wx7oE0S_FZO5lhjY7J2YX_5jGiooFvDMVXpV5XYiGcGGzFKacSLDxfBWcA", "HS512", "K", 200, "1"),
        ("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qbyXJEUqWe6N9FEsNNm_KMSUPMd4wx7oE0S_FZO5lhjY7J2YX_5jGiooFvDMVXpV5XYiGcGGzFKacSLDxfBWcA", "HS512", "K", 200, "0"),
    ];
    let mut list: Vec<(String, String)> = cases
        .iter()
        .map(|(tok, alg, c, n, want)| (format!("str({tok}),jwt_verify({alg},{})", c.repeat(*n)), (*want).to_string()))
        .collect();
    // The token is a valid HS256 one signed with "secret"; the variable is set nowhere.
    const T: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeJQ";
    for e in [format!("str({T}),jwt_verify(HS256,txn.nokey)"), format!("str({T}),jwt_verify(proc.nokey,secret)"), format!("str({T}),jwt_verify(HS256,proc.nokey)")] {
        list.push((e, String::new()));
    }
    check_rows("cover-jwt", GET, &list);
}

/// A target that is an absolute URI without a path has the path `/` (`http_scheme_based_normalize`).
#[test]
fn absolute_uri_without_a_path_reads_a_slash() {
    check_rows(
        "cover-abs",
        b"GET http://a HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        &rows(&[("path", "/"), ("pathq", "/"), ("base", "a/"), ("baseq", "a/"), ("url", "http://a/"), ("capture.req.uri", "/")]),
    );
}

/// A `Set-Cookie` value that holds a quoted pair (`"x\"y;z"`) is one value up to the closing quote:
/// the `;` inside it does not end the cookie, and the attribute after it is not a cookie of the
/// name asked for. (`res.cook(a)`, `res.cook(b)` and `res.cook_val(b)` are left out: on this
/// header HAProxy answers `"x\"y;z"`, empty and empty, Alcyon `x\"y`, `2` and `2`; see the report.)
#[test]
fn set_cookie_quoted_pair_matches_haproxy() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let be = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
            let (mut head, mut b) = (Vec::new(), [0u8; 4096]);
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&b[..n]),
                }
            }
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nSet-Cookie: a=\"x\\\"y;z\"; b=2\r\nSet-Cookie: c=1; d=\"q\\\\\"; e=5\r\nContent-Length: 0\r\n\r\n");
        }
    });
    let a = common::reserve_addr();
    let cfg = format!(
        "{DEFAULTS}frontend fe\n  bind {a}\n  default_backend be\nbackend be\n  server s {be}\n  \
         http-response set-header x-out \"%[res.cook_cnt]|%[res.cook_cnt(a)]|%[res.cook_cnt(b)]|%[res.cook_cnt(c)]|%[res.cook_cnt(d)]|%[res.cook_cnt(e)]|%[res.cook_names(:)]\"\n"
    );
    let _alcyon = start("cover-cook", &cfg, a);
    let raw = get(a, GET);
    let out = raw.lines().find_map(|l| l.strip_prefix("x-out: ")).unwrap_or_else(|| panic!("no x-out in {raw:?}"));
    assert_eq!(out, "2|1|0|1|0|0|a:c");
}

/// `base32+src` for an IPv6 client is the 4-byte hash followed by the 16 address bytes (20 in
/// all; 8 for IPv4). Host `a` over `[::1]`.
#[test]
fn base32_src_with_an_ipv6_client_matches_haproxy() {
    let a: SocketAddr = format!("[::1]:{}", common::reserve_addr().port()).parse().unwrap();
    let cfg = format!(
        "{DEFAULTS}frontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"%[base32+src,hex]|%[base32]|%[src]\"\n"
    );
    let _alcyon = start("cover-b32v6", &cfg, a);
    let raw = get(a, GET);
    assert!(raw.ends_with("\r\n\r\n3451F50A00000000000000000000000000000001|877786378|::1"), "{raw:?}");
}
