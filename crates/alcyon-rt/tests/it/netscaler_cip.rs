// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `bind ... accept-netscaler-cip <magic>` and `tcp-request connection
//! expect-netscaler-cip layer4` (reg-test connection/netscaler_cip). Measured against
//! HAProxy 3.5-dev11, the same way `expect-proxy` is measured in `expect_proxy.rs`:
//!
//! * the header is a NetScaler Client IP insertion header; the bind keyword makes it
//!   mandatory for every connection and declares its magic number (305419896 = 0x12345678
//!   in the reg-test), and the `tcp-request connection` action expects it only on the
//!   connections its rule matches, reading the magic from the bind line (0 when it has
//!   none);
//! * a valid header replaces `src`/`dst` and not `fc_src`, in its IPv4 and IPv6 forms,
//!   in the standard (12-byte prefix) and the legacy (8-byte prefix) shape;
//! * a connection without a header on the mandatory bind, one whose magic is not the
//!   declared one, one whose encapsulated protocol is not TCP (v4 or v6), one whose type
//!   byte or IP version is unhandled, one whose header is shorter than its own form, and
//! * one whose header arrives in two writes -- with its first write of 20 bytes or even
//!   8 -- are all closed with no reply (measured: each is refused on the first peek, not
//!   waited for);
//! * on a TLS bind the header must precede the ClientHello: header then handshake is
//!   served with the header's addresses, a ClientHello in its place or a wrong-magic
//!   header is refused before any handshake, and a silent client is closed by
//!   `timeout client` with no data;
//! * the rejections carry the `CO_ER_CIP_*` connection-error table (number, name, string);
//! * `expect-netscaler-cip` with no argument or `layer7`: "only supports 'layer4'";
//!   `tcp-request session expect-netscaler-cip layer4`: "not allowed in 'tcp-request
//!   session' rules".
//!
//! Run against the oracle with `T281_ORACLE=/path/to/haproxy`.

use crate::common;

/// The binary under test: alcyon, or the oracle when `T281_ORACLE` is set.
fn bin() -> String {
    std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

/// The reg-test's IPv4 CIP header: magic, CIP length (not checked), type 0, 40 announced
/// header bytes (IPv4 20 + TCP 20), 192.168.0.1:1234 -> 10.0.0.2:81.
fn cip_v4(magic: [u8; 4]) -> [u8; 52] {
    let mut h = [0u8; 52];
    h[..4].copy_from_slice(&magic);
    h[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x2c]);
    h[10..12].copy_from_slice(&[0x00, 0x28]);
    let body: [u8; 40] = [
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, // IPv4: ver/hl, len 40, proto 6
        0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, // 192.168.0.1 -> 10.0.0.2
        0x04, 0xd2, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // TCP: 1234 -> 81, seq
        0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, // ack, dataoff 5, flags, window
    ];
    h[12..].copy_from_slice(&body);
    h
}

/// The reg-test's IPv6 CIP header: same magic, 60 announced bytes (IPv6 40 + TCP 20),
/// 2001:db8::1:1234 -> 2001:db8::2:81.
fn cip_v6(magic: [u8; 4]) -> [u8; 72] {
    let mut h = [0u8; 72];
    h[..4].copy_from_slice(&magic);
    h[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x40]);
    h[10..12].copy_from_slice(&[0x00, 0x3c]);
    let body: [u8; 60] = [
        0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x06, 0x40, // IPv6: ver, payload len 20, nxt 6
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // 2001:db8::2
        0x04, 0xd2, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, // TCP: 1234 -> 81
        0x00, 0x00, 0x00, 0x00, // checksum, urgent
    ];
    h[12..].copy_from_slice(&body);
    h
}

fn talk(addr: SocketAddr, pre: &[u8], req: bool) -> String {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut out = pre.to_vec();
    if req {
        out.extend_from_slice(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    }
    let _ = s.write_all(&out);
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    buf
}

fn check(rule: &str) -> (Option<i32>, String) {
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend f\n  bind 127.0.0.1:18081\n  {rule}\n  default_backend be\nbackend be\n  server s1 127.0.0.1:1\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let out = Command::new(bin()).arg("-c").arg("-f").arg(f.path()).output().expect("alcyon -c");
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

#[test]
fn netscaler_cip_is_per_connection() {
    let (a, b, c, d, e) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe1\n  bind {a} accept-netscaler-cip 305419896\n\
         \x20 http-request return status 200\n\
         \x20 http-after-response set-header x-src \"%[src]:%[src_port]\"\n\
         \x20 http-after-response set-header x-dst \"%[dst]:%[dst_port]\"\n\
         \x20 http-after-response set-header x-fcsrc \"%[fc_src]\"\n\
         frontend fe2\n  bind {b}\n  tcp-request connection expect-netscaler-cip layer4 if {{ src 127.0.0.0/8 }}\n\
         \x20 http-request return status 200\n\
         \x20 http-after-response set-header x-src \"%[src]:%[src_port]\"\n\
         \x20 http-after-response set-header x-dst \"%[dst]:%[dst_port]\"\n\
         frontend fe3\n  bind {c}\n  tcp-request connection expect-netscaler-cip layer4 if {{ src 10.0.0.0/8 }}\n\
         \x20 http-request return status 200\n\
         \x20 http-after-response set-header x-src \"%[src]:%[src_port]\"\n\
         listen l1\n  bind {d} accept-netscaler-cip 305419896\n\
         \x20 http-request return status 200\n\
         \x20 http-after-response set-header x-src \"%[src]:%[src_port]\"\n\
         \x20 server s1 127.0.0.1:1\n\
         frontend fe4\n  bind {e} accept-netscaler-cip 305419896\n\
         \x20 timeout client 1s\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let mut child = Command::new(bin())
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Alcyon)
        .expect("spawn");
    assert!(common::wait_listening(a), "fe1 (accept-netscaler-cip) did not come up");

    // fe1: the header is mandatory, magic 0x12345678, IPv4 form.
    let r1 = talk(a, &cip_v4([0x12, 0x34, 0x56, 0x78]), true);
    assert!(r1.starts_with("HTTP/1.1 200"), "{r1}");
    assert!(r1.contains("x-src: 192.168.0.1:1234\r\n"), "{r1}");
    assert!(r1.contains("x-dst: 10.0.0.2:81\r\n"), "{r1}");
    // only the session addresses are replaced: fc_src still reports the real peer
    assert!(r1.contains("x-fcsrc: 127.0.0.1\r\n"), "{r1}");

    // the same in IPv6.
    let r2 = talk(a, &cip_v6([0x12, 0x34, 0x56, 0x78]), true);
    assert!(r2.starts_with("HTTP/1.1 200"), "{r2}");
    assert!(r2.contains("x-src: 2001:db8::1:1234\r\n"), "{r2}");
    assert!(r2.contains("x-dst: 2001:db8::2:81\r\n"), "{r2}");

    // a header whose magic is not the declared one is rejected
    let r3 = talk(a, &cip_v4([0xde, 0xad, 0xbe, 0xef]), false);
    assert!(r3.is_empty(), "bad magic: closed, got {r3}");

    // a valid magic, but the encapsulated protocol is not TCP (17 = UDP, IP byte 9)
    let mut udp = cip_v4([0x12, 0x34, 0x56, 0x78]);
    udp[21] = 0x11;
    let r4 = talk(a, &udp, false);
    assert!(r4.is_empty(), "non-TCP header: closed, got {r4}");

    // the header is mandatory here, a request without one is rejected
    let r5 = talk(a, b"", true);
    assert!(r5.is_empty(), "no header: closed, got {r5}");

    // the header arrives in two writes: `HAProxy` peeks the first 20 bytes, refuses the
    // header as truncated, and the close is a RST (measured)
    let mut s = TcpStream::connect(a).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let split = cip_v4([0x12, 0x34, 0x56, 0x78]);
    s.write_all(&split[..20]).expect("first half");
    std::thread::sleep(Duration::from_millis(400));
    let _ = s.write_all(&split[20..]); // may fail: the oracle answers with a RST here
    let mut out = String::new();
    let n = s.read_to_string(&mut out);
    let dead = n.is_err() || out.is_empty();
    assert!(dead, "split header: the connection must be closed, got {out:?}");
    drop(s);

    // and a first write shorter than the 12-byte prefix: the peek sees 8 bytes, which is
    // not even a prefix, and is refused as truncated (measured: closed, no reply)
    let mut s = TcpStream::connect(a).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    s.write_all(&split[..8]).expect("first bytes");
    std::thread::sleep(Duration::from_millis(400));
    let _ = s.write_all(&split[8..]); // may fail: the close may already be out
    let mut out = String::new();
    let n = s.read_to_string(&mut out);
    assert!(n.is_err() || out.is_empty(), "8-byte first write: the connection must be closed, got {out:?}");
    drop(s);

    // the legacy form: 8-byte prefix, the 32-bit header length at byte 4, the IP header
    // at byte 8. `HAProxy` accepts it the same way (measured: served, same swap).
    let legacy: [u8; 48] = [
        0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x28, // magic, header length 40
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, // IPv4: ver/hl, len, proto 6
        0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, // 192.168.0.1 -> 10.0.0.2
        0x04, 0xd2, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // TCP: 1234 -> 81
        0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let r9 = talk(a, &legacy, true);
    assert!(r9.starts_with("HTTP/1.1 200"), "{r9}");
    assert!(r9.contains("x-src: 192.168.0.1:1234\r\n"), "{r9}");
    assert!(r9.contains("x-dst: 10.0.0.2:81\r\n"), "{r9}");

    // a type byte that is neither the legacy marker nor 0: refused (measured: RST)
    let mut type1 = cip_v4([0x12, 0x34, 0x56, 0x78]);
    type1[8] = 0x01;
    let r10 = talk(a, &type1, false);
    assert!(r10.is_empty(), "unknown type: closed, got {r10}");

    // the IPv6 form with an encapsulated protocol that is not TCP (next header 17, byte 18)
    let mut v6udp = cip_v6([0x12, 0x34, 0x56, 0x78]);
    v6udp[18] = 0x11;
    let r11 = talk(a, &v6udp, false);
    assert!(r11.is_empty(), "IPv6 non-TCP: closed, got {r11}");

    // an IP version that is neither 4 nor 6 (the first header byte, byte 12)
    let mut ver2 = cip_v4([0x12, 0x34, 0x56, 0x78]);
    ver2[12] = 0x20;
    let r12 = talk(a, &ver2, false);
    assert!(r12.is_empty(), "IP version 2: closed, got {r12}");

    // fewer than 40 bytes in for the IPv4 form, whatever the announced length: refused
    let v4short: [u8; 30] = [
        0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x12, // magic, 18 announced
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, // v4, proto 6
        0xc0, 0xa8, 0x00, 0x01, 0x0a, 0x00, // 18 header bytes in
    ];
    let r13 = talk(a, &v4short, false);
    assert!(r13.is_empty(), "IPv4 shorter than 40: closed, got {r13}");

    // fewer than 60 bytes in for the IPv6 form: refused
    let v6short: [u8; 52] = [
        0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x28, // magic, 40 announced
        0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x06, 0x40, // IPv6: ver, payload 20, next 6
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // 2001:db8::2
    ];
    let r14 = talk(a, &v6short, false);
    assert!(r14.is_empty(), "IPv6 shorter than 60: closed, got {r14}");

    // fe2: the action expects the header only from the loopback, and with a zero magic
    // since its bind line declares none
    let r6 = talk(b, &cip_v4([0x00, 0x00, 0x00, 0x00]), true);
    assert!(r6.starts_with("HTTP/1.1 200"), "{r6}");
    assert!(r6.contains("x-src: 192.168.0.1:1234\r\n"), "{r6}");
    assert!(r6.contains("x-dst: 10.0.0.2:81\r\n"), "{r6}");

    // fe3: the condition does not match the loopback, so no header is expected and the
    // real addresses are reported
    let r7 = talk(c, b"", true);
    assert!(r7.starts_with("HTTP/1.1 200"), "{r7}");
    assert!(
        r7.lines().any(|l| l.starts_with("x-src: 127.0.0.1:") && l[11..].split(':').count() == 2),
        "{r7}"
    );

    // the keyword on a `listen` section's bind works the same (T110: listen keeps its
    // bind keywords, as the frontend's)
    let r8 = talk(d, &cip_v4([0x12, 0x34, 0x56, 0x78]), true);
    assert!(r8.starts_with("HTTP/1.1 200"), "{r8}");
    assert!(r8.contains("x-src: 192.168.0.1:1234\r\n"), "{r8}");

    // a client that sends nothing: `timeout client` expires while the header is missing,
    // and the connection is closed with no reply (as the oracle does)
    let mut s = TcpStream::connect(e).expect("connect fe4");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout fe4");
    let mut out = String::new();
    let n = s.read_to_string(&mut out);
    assert!(n.is_err() || out.is_empty(), "client timeout on a missing header must close, got {out:?}");
    drop(s);
    common::stop(&mut child);
}

/// Oracle (3.5-dev11): the minimum CIP header is the IP header plus the 4 port bytes
/// (`sizeof(struct my_tcphdr)`): 24 bytes for IPv4, 44 for IPv6, not IP + a full 20-byte
/// TCP header. Such a header is accepted and the addresses/ports are taken from it.
#[test]
fn t644_20_a_ports_only_cip_header_is_accepted() {
    let a = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe1\n  bind {a} accept-netscaler-cip 305419896\n\
         \x20 http-request return status 200\n\
         \x20 http-after-response set-header x-src \"%[src]:%[src_port]\"\n\
         \x20 http-after-response set-header x-dst \"%[dst]:%[dst_port]\"\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let child = Command::new(bin())
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Alcyon)
        .expect("spawn");
    assert!(common::wait_listening(a), "fe1 did not come up");

    // IPv4: 12-byte prefix (announced header length 24), IPv4 header, then the 4 port bytes.
    let full = cip_v4([0x12, 0x34, 0x56, 0x78]);
    let mut v4 = full[..12 + 20 + 4].to_vec();
    v4[10..12].copy_from_slice(&[0x00, 0x18]);
    let r = talk(a, &v4, true);
    assert!(r.starts_with("HTTP/1.1 200"), "ports-only IPv4 header: {r:?}");
    assert!(r.contains("x-src: 192.168.0.1:1234\r\n"), "{r:?}");
    assert!(r.contains("x-dst: 10.0.0.2:81\r\n"), "{r:?}");

    // IPv6: 40-byte header + 4 port bytes (announced 44).
    let full = cip_v6([0x12, 0x34, 0x56, 0x78]);
    let mut v6 = full[..12 + 40 + 4].to_vec();
    v6[10..12].copy_from_slice(&[0x00, 0x2c]);
    let r = talk(a, &v6, true);
    assert!(r.starts_with("HTTP/1.1 200"), "ports-only IPv6 header: {r:?}");
    assert!(r.contains("x-src: 2001:db8::1:1234\r\n"), "{r:?}");
    assert!(r.contains("x-dst: 2001:db8::2:81\r\n"), "{r:?}");
    drop(child);
}

#[test]
fn expect_netscaler_cip_arguments_are_checked_at_load() {
    let (c, o) = check("tcp-request connection expect-netscaler-cip");
    assert_ne!(c, Some(0), "{o}");
    assert!(o.contains("'tcp-request connection expect-netscaler-cip' only supports 'layer4'"), "{o}");
    let (c, o) = check("tcp-request connection expect-netscaler-cip layer7");
    assert_ne!(c, Some(0), "{o}");
    assert!(o.contains("only supports 'layer4'"), "{o}");
    let (c, o) = check("tcp-request session expect-netscaler-cip layer4");
    assert_ne!(c, Some(0), "{o}");
    assert!(o.contains("'expect-netscaler-cip layer4' is not allowed in 'tcp-request session' rules"), "{o}");
    // HAProxy: "only accepts 'if' or 'unless'" (got 'foo').
    let (c, o) = check("tcp-request connection expect-netscaler-cip layer4 foo");
    assert_ne!(c, Some(0), "{o}");
    assert!(o.contains("only accepts 'if' or 'unless'"), "{o}");
    let (c, o) = check("tcp-request connection expect-netscaler-cip layer4 if { src 10.0.0.0/8 }");
    assert_eq!(c, Some(0), "{o}");
    // the bind keyword takes a magic number
    let (c, o) = check("bind 127.0.0.1:18081 accept-netscaler-cip 305419896");
    assert_eq!(c, Some(0), "{o}");
}

/// `accept-netscaler-cip` on a TLS bind: the header comes in plaintext ahead of the
/// ClientHello (measured on the oracle: the header then the handshake is served with the
/// header's addresses; a ClientHello in its place, or a header with the wrong magic, is
/// refused with a RST before any handshake; a client that sends nothing is closed by
/// `timeout client` with no data).
#[test]
fn the_cip_header_precedes_the_tls_handshake() {
    let dir = tempfile::TempDir::new().expect("dir");
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let crt = dir.path().join("c.pem");
    std::fs::write(&crt, format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem())).expect("pem");
    let t = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 1s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend f\n  bind {t} ssl crt {} accept-netscaler-cip 305419896\n\
         \x20 http-request return status 200\n\
         \x20 http-after-response set-header x-src \"%[src]:%[src_port]\"\n\
         \x20 http-after-response set-header x-dst \"%[dst]:%[dst_port]\"\n",
        crt.display()
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let mut child = Command::new(bin())
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Alcyon)
        .expect("spawn");
    assert!(common::wait_listening(t), "the TLS CIP bind did not come up");
    let der = ck.cert.der().clone();

    // the header, then the handshake: served with the header's addresses.
    let mut raw = TcpStream::connect(t).expect("connect");
    raw.write_all(&cip_v4([0x12, 0x34, 0x56, 0x78])).expect("header");
    let got = cip_https(raw, &der).expect("the handshake must follow the header");
    assert!(got.starts_with("HTTP/1.1 200"), "{got}");
    assert!(got.contains("x-src: 192.168.0.1:1234\r\n"), "{got}");
    assert!(got.contains("x-dst: 10.0.0.2:81\r\n"), "{got}");

    // a client that leaves before anything: the close is let go (measured).
    drop(TcpStream::connect(t).expect("connect and leave"));
    std::thread::sleep(Duration::from_millis(100));

    // a header with the wrong magic: refused before the handshake (measured: a RST).
    let mut bad = TcpStream::connect(t).expect("connect");
    bad.write_all(&cip_v4([0xde, 0xad, 0xbe, 0xef])).expect("header");
    let served = match cip_https(bad, &der) {
        Ok(got) => got.starts_with("HTTP/1.1 200"),
        Err(_) => false,
    };
    assert!(!served, "the wrong-magic header must not reach the handshake");

    // a client that sends nothing: `timeout client` closes the connection with no data.
    let mut silent = TcpStream::connect(t).expect("connect");
    silent.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut out = String::new();
    let n = silent.read_to_string(&mut out);
    assert!(n.is_err() || out.is_empty(), "a silent TLS client must be closed with no data, got {out:?}");
    common::stop(&mut child);
}

/// A rustls `GET /` on `raw`, completing the handshake there: the response, or an error
/// when the server refuses before the handshake completes.
fn cip_https(mut raw: TcpStream, cert: &rustls::pki_types::CertificateDer<'static>) -> std::io::Result<String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).expect("root");
    let cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
    let mut conn = rustls::ClientConnection::new(std::sync::Arc::new(cfg), name).expect("client");
    raw.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    let mut tls = rustls::Stream::new(&mut conn, &mut raw);
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = tls.read(&mut buf) {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// The connection-error table of the CIP rejections (`CO_ER_CIP_*`, `connection.c`): the
/// number, name and logged string of each, as `%[fc_err]`, `%[fc_err_name]` and the log
/// line read them.
#[test]
fn cip_rejections_carry_the_conn_error_table() {
    use alcyon_rt::proxy::CipError;
    let table = [
        (CipError::Empty, 18, "CIP_EMPTY", "Connection closed while waiting for NetScaler Client IP header"),
        (CipError::Abort, 19, "CIP_ABORT", "Connection error while waiting for NetScaler Client IP header"),
        (CipError::Timeout, 20, "CIP_TIMEOUT", "Timeout while waiting for a NetScaler Client IP header"),
        (CipError::Truncated, 21, "CIP_TRUNCATED", "Truncated NetScaler Client IP header received"),
        (CipError::BadMagic, 22, "CIP_BAD_MAGIC", "Received an invalid NetScaler Client IP magic number"),
        (CipError::BadProto, 23, "CIP_BAD_PROTO", "Received an unhandled protocol in the NetScaler Client IP header"),
    ];
    for (e, code, name, msg) in table {
        assert_eq!(e.code(), code, "{name}");
        assert_eq!(e.name(), name);
        assert_eq!(e.message(), msg, "{name}");
    }
    // `option dontlognull` drops exactly the ones that took nothing in, as for PROXY.
    assert!(CipError::Empty.is_null());
    assert!(CipError::Abort.is_null());
    assert!(CipError::Timeout.is_null());
    assert!(!CipError::Truncated.is_null());
    assert!(!CipError::BadMagic.is_null());
    assert!(!CipError::BadProto.is_null());
}
