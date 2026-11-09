// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `set-src-port` and `set-dst-port` from `tcp-request connection|session|content` and
//! `http-request`, and the port preserved by `set-src`/`set-dst` (T125; reg-test
//! tcp-rules/set_src_dst, run on HAProxy 3.5-dev8-885761-29 where it passes).
//!
//! * connection level rewrites the connection itself, so `fc_src`/`fc_dst` follow;
//! * session level leaves `fc_*` at the real addresses;
//! * `set-src`/`set-dst` keep the port, also from `http-request`
//!   (`tcp_action_req_set_src`: `port = get_net_port(src)`), and `set-*-port` keep the
//!   address.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

fn get(addr: SocketAddr, path: &str) -> (String, u16) {
    let mut s = TcpStream::connect(addr).expect("connect");
    let local = s.local_addr().expect("local").port();
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let _ = s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes());
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    (out.to_ascii_lowercase(), local)
}

#[test]
fn set_src_dst_and_ports_from_every_rule_set() {
    let addrs: Vec<SocketAddr> = (0..5).map(|_| common::reserve_addr()).collect();
    let (a1, a2, a3, a4, a5) = (addrs[0], addrs[1], addrs[2], addrs[3], addrs[4]);
    let hdrs = "\x20 http-after-response set-header x-src \"%[src]:%[src_port]\"\n\
                \x20 http-after-response set-header x-dst \"%[dst]:%[dst_port]\"\n";
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe1\n  bind {a1}\n  tcp-request connection set-src ipv4(10.0.0.1)\n\
         \x20 tcp-request connection set-dst ipv4(10.0.0.2)\n  http-request return status 200\n{hdrs}\
         \x20 http-after-response set-header x-fcsrc \"%[fc_src]\"\n\
         \x20 http-after-response set-header x-fcdst \"%[fc_dst]\"\n\
         frontend fe2\n  bind {a2}\n  tcp-request session set-src-port int(4000)\n\
         \x20 tcp-request session set-dst-port int(4001)\n  http-request return status 200\n{hdrs}\
         \x20 http-after-response set-header x-fcsrc \"%[fc_src]:%[fc_src_port]\"\n\
         \x20 http-after-response set-header x-fcdst \"%[fc_dst]:%[fc_dst_port]\"\n\
         frontend fe3\n  bind {a3}\n  tcp-request content set-src ipv4(10.0.0.3)\n\
         \x20 tcp-request content set-src-port int(4002)\n  tcp-request content set-dst ipv4(10.0.0.4)\n\
         \x20 tcp-request content set-dst-port int(4003)\n\
         \x20 http-request set-src ipv4(10.0.0.5) if {{ path /http }}\n\
         \x20 http-request set-src-port int(4004) if {{ path /http }}\n\
         \x20 http-request set-dst ipv4(10.0.0.6) if {{ path /http }}\n\
         \x20 http-request set-dst-port int(4005) if {{ path /http }}\n\
         \x20 http-request return status 200\n{hdrs}\
         frontend fe4\n  bind {a4}\n  http-request set-src str(garbage)\n  http-request set-src ipv4(10.0.0.7)\n\
         \x20 http-request set-dst ipv4(10.0.0.8)\n  http-request return status 200\n{hdrs}\
         frontend fe5\n  bind {a5}\n  tcp-request connection set-src-port int(5000)\n\
         \x20 tcp-request connection set-dst-port int(5001)\n  http-request return status 200\n{hdrs}\
         \x20 http-after-response set-header x-fcsrc \"%[fc_src]:%[fc_src_port]\"\n\
         \x20 http-after-response set-header x-fcdst \"%[fc_dst]:%[fc_dst_port]\"\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Alcyon)
        .expect("spawn");
    assert!(common::wait_listening(a1));
    assert!(common::wait_listening(a4));
    let (r1, p1) = get(a1, "/");
    let (r2, p2) = get(a2, "/");
    let (r3a, _) = get(a3, "/tcp");
    let (r3b, _) = get(a3, "/http");
    let (r4, p4) = get(a4, "/");
    let (r5, _) = get(a5, "/");
    common::stop(&mut child);

    assert!(r1.starts_with("http/1.1 200"), "{r1}");
    assert!(r1.contains(&format!("x-src: 10.0.0.1:{p1}\r\n")), "{r1}");
    assert!(r1.contains(&format!("x-dst: 10.0.0.2:{}\r\n", a1.port())), "{r1}");
    assert!(r1.contains("x-fcsrc: 10.0.0.1\r\n"), "{r1}");
    assert!(r1.contains("x-fcdst: 10.0.0.2\r\n"), "{r1}");

    assert!(r2.contains("x-src: 127.0.0.1:4000\r\n"), "{r2}");
    assert!(r2.contains("x-dst: 127.0.0.1:4001\r\n"), "{r2}");
    assert!(r2.contains(&format!("x-fcsrc: 127.0.0.1:{p2}\r\n")), "{r2}");
    assert!(r2.contains(&format!("x-fcdst: 127.0.0.1:{}\r\n", a2.port())), "{r2}");

    assert!(r3a.contains("x-src: 10.0.0.3:4002\r\n"), "{r3a}");
    assert!(r3a.contains("x-dst: 10.0.0.4:4003\r\n"), "{r3a}");
    assert!(r3b.contains("x-src: 10.0.0.5:4004\r\n"), "{r3b}");
    assert!(r3b.contains("x-dst: 10.0.0.6:4005\r\n"), "{r3b}");

    // http-request set-src / set-dst keep the port, as the other rule sets do.
    assert!(r4.contains(&format!("x-src: 10.0.0.7:{p4}\r\n")), "{r4}");
    assert!(r4.contains(&format!("x-dst: 10.0.0.8:{}\r\n", a4.port())), "{r4}");

    // connection level: the connection's own addresses follow, fc_* included.
    assert!(r5.contains("x-src: 127.0.0.1:5000\r\n"), "{r5}");
    assert!(r5.contains("x-dst: 127.0.0.1:5001\r\n"), "{r5}");
    assert!(r5.contains("x-fcsrc: 127.0.0.1:5000\r\n"), "{r5}");
    assert!(r5.contains("x-fcdst: 127.0.0.1:5001\r\n"), "{r5}");
}

#[test]
fn port_rules_need_an_expression() {
    // HAProxy: "missing fetch method" for each of these.
    for rule in [
        "tcp-request connection set-src-port",
        "tcp-request connection set-dst-port",
        "tcp-request session set-src-port",
        "tcp-request session set-dst-port",
        "tcp-request content set-src-port",
        "tcp-request content set-dst-port",
        "http-request set-src-port",
    ] {
        let cfg = format!("defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\nfrontend f\n  bind 127.0.0.1:18082\n  {rule}\n");
        let mut f = NamedTempFile::new().expect("tmp");
        f.write_all(cfg.as_bytes()).expect("cfg");
        let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(f.path()).output().expect("-c");
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert_ne!(out.status.code(), Some(0), "{rule}: {text}");
        assert!(text.contains("missing fetch method"), "{rule}: {text}");
    }
}
