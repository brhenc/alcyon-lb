// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `fc_pp_authority`: the authority TLV (type 0x02) of the PROXY protocol v2 header the
//! client connection was accepted with, as the first occurrence only
//! (`smp_fetch_fc_pp_authority`, `src/connection.c`; the spec is the reg-test
//! `reg-tests/connection/proxy_protocol_tlv_validation.vtc`).
//!
//! The frontend's `bind` carries `accept-proxy`, so the PROXY protocol is enforced
//! (`doc/configuration.txt`, `bind` options): a connection without a header is refused
//! and closed without an answer, as are a header whose TLV runs past its declared length
//! and one whose TLVs stop before it. A TLV after the end of the header is not a TLV:
//! the header is consumed, the stray bytes reach the HTTP parser and are a 400 with no
//! after-response header on it. Where the fetch is empty, `set-header` still adds the
//! header, with no value.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev11 (the reg-test above plus
//! `/tmp/pp_authority_measure.vtc`). Set `T281_ORACLE=/path/to/haproxy` to run these
//! tests against `HAProxy`: it passes all.

use crate::common;

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// The PROXY protocol v2 signature, version/`PROXY` and `TCP4` bytes.
const PP2_HEAD: &[u8] = &[
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11,
];
/// 127.0.0.1:42 -> 127.0.0.1:1337.
const PP2_ADDR: &[u8] = &[
    0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x2a, 0x05, 0x39,
];
const PP2_AUTH_12345: &[u8] = &[0x02, 0x00, 0x05, 0x31, 0x32, 0x33, 0x34, 0x35];
const PP2_AUTH_54321: &[u8] = &[0x02, 0x00, 0x05, 0x35, 0x34, 0x33, 0x32, 0x31];
const REQ: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";

/// A PROXY v2 header: the 16 fixed bytes (its length field set) and `payload`.
fn pp2(len: u16, payload: &[u8]) -> Vec<u8> {
    let mut h = PP2_HEAD.to_vec();
    h.extend_from_slice(&len.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

/// A TLV of `type` and `value`.
fn tlv(t: u8, value: &[u8]) -> Vec<u8> {
    let mut v = vec![t, (value.len() >> 8) as u8, value.len() as u8];
    v.extend_from_slice(value);
    v
}

struct Proxy {
    child: Child,
    addr: SocketAddr,
    stderr: std::fs::File,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn proxy() -> Proxy {
    let addr = common::reserve_addr();
    let mut cfg = NamedTempFile::new().expect("cfg");
    use std::io::Write as _;
    write!(
        cfg,
        "global\n    nbthread 1\ndefaults\n    mode http\n    timeout client 3s\n    timeout server 3s\n    \
         timeout connect 1s\nfrontend f\n    bind {addr} accept-proxy\n    \
         http-after-response set-header echo %[fc_pp_authority,hex]\n    \
         http-after-response set-header raw %[fc_pp_authority]\n    http-request return status 200\n"
    )
    .expect("write cfg");
    let stderr = std::fs::File::create(cfg.path().with_file_name(format!(
        "pp_authority_{}.err",
        addr.port()
    )))
    .expect("stderr file");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = common::alcyon_command(&bin)
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::null())
        .stderr(stderr.try_clone().expect("stderr dup"))
        .spawn()
        .expect("spawn proxy");
    assert!(
        common::wait_listening(addr),
        "proxy never listened (config: unknown fetch method 'fc_pp_authority' until implemented; stderr: {})",
        read_to_string_lossy(&stderr)
    );
    Proxy { child, addr, stderr, _cfg: cfg }
}

fn read_to_string_lossy(f: &std::fs::File) -> String {
    use std::io::Read as _;
    let mut s = String::new();
    let _ = std::io::Read::read_to_string(&mut f.try_clone().unwrap(), &mut s);
    s
}

/// Sends `raw` whole, then reads until the proxy closes, resets or goes quiet: the bytes
/// it answered, and whether the connection ended before any answer.
fn exchange(p: &Proxy, raw: &[u8]) -> Vec<u8> {
    let mut c = TcpStream::connect(p.addr).expect("connect");
    c.write_all(raw).expect("send");
    let _ = c.set_read_timeout(Some(Duration::from_secs(3)));
    let (mut out, mut buf) = (Vec::new(), [0u8; 16384]);
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    out
}

/// The status word and header lines (name lower-cased, value as sent) of an answer.
fn head(out: &[u8]) -> Option<(&str, Vec<(String, String)>)> {
    let eoh = out.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&out[..eoh]).ok()?;
    let mut it = head.split("\r\n");
    let status = it.next()?.get(9..12)?;
    Some((
        status,
        it.filter_map(|line| {
            line.find(':').map(|i| (
                line[..i].trim().to_ascii_lowercase(),
                line[i + 1..].trim_matches(' ').to_string(),
            ))
        }).collect(),
    ))
}

fn hdr<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

/// The reg-test's case 1: the authority TLV's value, hex-encoded.
#[test]
fn the_authority_tlv_is_returned() {
    let p = proxy();
    let raw = [
        pp2(20, &[PP2_ADDR, PP2_AUTH_12345].concat()),
        REQ.to_vec(),
    ]
    .concat();
    let out = exchange(&p, &raw);
    let (status, h) = head(&out).expect("no answer");
    assert_eq!(status, "200");
    assert_eq!(hdr(&h, "echo"), Some("3132333435"), "{h:?}");
}

/// The reg-test's case 2: bytes after the end of the header are not TLVs; they reach the
/// HTTP parser and are a 400 whose reply carries no after-response header.
#[test]
fn a_tlv_after_the_header_end_is_not_a_tlv() {
    let p = proxy();
    let raw = [
        pp2(20, &[PP2_ADDR, PP2_AUTH_12345].concat()),
        PP2_AUTH_54321.to_vec(),
        REQ.to_vec(),
    ]
    .concat();
    let out = exchange(&p, &raw);
    let (status, h) = head(&out).expect("no answer");
    assert_eq!(status, "400", "{h:?}");
    assert_eq!(hdr(&h, "echo"), None, "{h:?}");
}

/// The reg-test's case 3: a TLV running past the header's declared length is refused;
/// the connection ends without an answer.
#[test]
fn a_tlv_longer_than_the_header_is_refused() {
    let p = proxy();
    let raw = [pp2(20, &[PP2_ADDR, &tlv(0x02, b"1234512345")].concat()), REQ.to_vec()].concat();
    assert!(!exchange(&p, &raw).starts_with(b"HTTP/"), "answered a refused header");
}

/// The reg-test's case 4: TLVs that stop before the end of the header are refused; the
/// connection ends without an answer.
#[test]
fn tlvs_stopping_before_the_header_end_are_refused() {
    let p = proxy();
    let raw = [pp2(20, &[PP2_ADDR, &tlv(0x02, b"1234")].concat()), REQ.to_vec()].concat();
    assert!(!exchange(&p, &raw).starts_with(b"HTTP/"), "answered a refused header");
}

/// `accept-proxy` enforces the protocol: a connection with no header ends without an
/// answer (measured: the oracle resets it).
#[test]
fn a_connection_without_a_proxy_header_is_refused() {
    let p = proxy();
    assert!(!exchange(&p, REQ).starts_with(b"HTTP/"), "answered a refused connection");
}

/// A header with no authority TLV: the fetch is empty, but `set-header` adds the header
/// with no value (measured: `echo: ` is sent, so it is present and empty, not absent).
#[test]
fn a_header_without_an_authority_tlv_is_empty() {
    let p = proxy();
    let raw = [pp2(12, PP2_ADDR), REQ.to_vec()].concat();
    let out = exchange(&p, &raw);
    let (status, h) = head(&out).expect("no answer");
    assert_eq!(status, "200");
    assert_eq!(hdr(&h, "echo"), Some(""), "{h:?}");
}

/// A TLV of another type before the authority is walked past, as `HAProxy` walks its whole
/// TLV list (`conn_get_tlv`'s loop); the authority still comes back.
#[test]
fn a_tlv_before_the_authority_is_walked_past() {
    let p = proxy();
    let raw = [pp2(25, &[PP2_ADDR, &tlv(0x04, b"zz"), &tlv(0x02, b"12345")].concat()), REQ.to_vec()].concat();
    let out = exchange(&p, &raw);
    let (status, h) = head(&out).expect("no answer");
    assert_eq!(status, "200");
    assert_eq!(hdr(&h, "echo"), Some("3132333435"), "{h:?}");
}

/// Only a TLV of another type: the fetch is empty, the header is present with no value.
#[test]
fn only_other_tlvs_is_empty() {
    let p = proxy();
    let raw = [pp2(17, &[PP2_ADDR, &tlv(0x04, b"zz")].concat()), REQ.to_vec()].concat();
    let out = exchange(&p, &raw);
    let (status, h) = head(&out).expect("no answer");
    assert_eq!(status, "200");
    assert_eq!(hdr(&h, "echo"), Some(""), "{h:?}");
}

/// Two authority TLVs: the first is returned only (`smp->flags &= ~SMP_F_NOT_LAST`,
/// "return only the first authority").
#[test]
fn the_first_of_two_authority_tlvs_is_returned() {
    let p = proxy();
    let raw = [
        pp2(28, &[PP2_ADDR, PP2_AUTH_12345, PP2_AUTH_54321].concat()),
        REQ.to_vec(),
    ]
    .concat();
    let out = exchange(&p, &raw);
    let (status, h) = head(&out).expect("no answer");
    assert_eq!(status, "200");
    assert_eq!(hdr(&h, "echo"), Some("3132333435"), "{h:?}");
}

/// The value the fetch returns is the TLV's raw value: `fc_pp_authority` without a
/// converter sets a header to the value itself, unencoded.
#[test]
fn the_fetch_prints_the_raw_value() {
    let p = proxy();
    let raw = [pp2(20, &[PP2_ADDR, PP2_AUTH_12345].concat()), REQ.to_vec()].concat();
    let out = exchange(&p, &raw);
    let (_, h) = head(&out).expect("no answer");
    assert_eq!(hdr(&h, "raw"), Some("12345"), "{h:?}");
}
