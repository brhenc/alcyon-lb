// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `url_ip` and `url_port` (T144b 10): the address and port of an absolute-form request
//! target. Every expected value was measured on `HAProxy 3.5-dev8-885761-29` (2026-10-04)
//! with a raw-socket client and `http-request return ... hdr x "ip=%[url_ip] ..."`.
//!
//! ```text
//! http://1.2.3.4:8080/x    ip=1.2.3.4 port=8080       ftp://1.2.3.4/x         none
//! http://1.2.3.4/x         ip=1.2.3.4 port=80         http://localhost/x      none
//! https://1.2.3.4/x        ip=1.2.3.4 port=443        http://[::1]:90/x       none
//! HTTP://1.2.3.4/x         ip=1.2.3.4 port=80         http://u@1.2.3.4:7/x    none
//! http://1.2.3.4:/x        port=80                    http://1.2.3/x          none
//! http://1.2.3.4:99999/x   port=34463                 http://256.2.3.4/x      none
//! http://1.2.3.4:8x/       port=8                      http://127.1/x          none
//! http://1.2.3.4:-1/x      port=0                      /x                      none
//! http://01.2.3.4:5/x      ip=1.2.3.4 port=5
//! ```

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use tempfile::NamedTempFile;

struct Ibex(Child, NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start() -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n  http-request set-var(txn.ip) url_ip\n  http-request set-var(txn.port) url_port\n  \
         acl net url_ip 1.2.3.0/24\n  acl p81 url_port 81\n  acl pge url_port ge 8000\n  \
         http-request return status 200 hdr x \"ip=%[url_ip] port=%[url_port] v=%[var(txn.ip)]/%[var(txn.port)] \
         net=%[acl(net)] p81=%[acl(p81)] pge=%[acl(pge)]\"\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ibex");
    let mut ibex = Ibex(child, f);
    if !common::wait_listening(fe) {
        common::stop(&mut ibex.0);
        let mut err = String::new();
        if let Some(mut e) = ibex.0.stderr.take() {
            let _ = e.read_to_string(&mut err);
        }
        panic!("ibex never listened:\n{err}\n{cfg}");
    }
    (ibex, fe)
}

fn x_header(fe: SocketAddr, target: &str) -> String {
    let host = target.split_once("://").map_or("a", |(_, r)| r.split('/').next().unwrap_or("a").rsplit('@').next().unwrap_or("a"));
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(std::time::Duration::from_secs(3))).ok();
    write!(c, "GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").expect("send");
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    let out = String::from_utf8_lossy(&out).into_owned();
    assert!(out.starts_with("HTTP/1.1 200"), "{target}: {out:?}");
    out.split("\r\n").find_map(|l| l.strip_prefix("x: ")).unwrap_or_else(|| panic!("{target}: {out:?}")).to_string()
}

#[test]
fn url_ip_and_url_port_read_the_authority_of_an_absolute_target() {
    let (_ibex, fe) = start();
    let some = |ip: &str, port: &str| format!("ip={ip} port={port} v={ip}/{port}");
    let none = "ip= port= v=/";
    let cases: [(&str, String); 19] = [
        ("http://1.2.3.4:8080/x", some("1.2.3.4", "8080")),
        ("http://1.2.3.4/x", some("1.2.3.4", "80")),
        ("https://1.2.3.4/x", some("1.2.3.4", "443")),
        ("HTTP://1.2.3.4/x", some("1.2.3.4", "80")),
        ("http://1.2.3.4:/x", some("1.2.3.4", "80")),
        ("http://1.2.3.4:0/x", some("1.2.3.4", "0")),
        ("http://1.2.3.4:99999/x", some("1.2.3.4", "34463")),
        ("http://1.2.3.4:8x/", some("1.2.3.4", "8")),
        ("http://1.2.3.4:-1/x", some("1.2.3.4", "0")),
        ("http://1.2.3.4:80:80/", some("1.2.3.4", "80")),
        ("http://01.2.3.4:5/x", some("1.2.3.4", "5")),
        ("http://localhost/x", none.to_string()),
        ("http://[::1]:90/x", none.to_string()),
        ("ftp://1.2.3.4/x", none.to_string()),
        ("http://u@1.2.3.4:7/x", none.to_string()),
        ("http://1.2.3/x", none.to_string()),
        ("http://256.2.3.4/x", none.to_string()),
        ("http://127.1/x", none.to_string()),
        ("/x", none.to_string()),
    ];
    for (target, want) in cases {
        let got = x_header(fe, target);
        assert!(got.starts_with(&want), "{target}: {got:?}, want {want:?}");
    }
}

#[test]
fn url_ip_and_url_port_are_usable_as_acls() {
    let (_ibex, fe) = start();
    assert_eq!(x_header(fe, "http://1.2.3.4:81/x"), "ip=1.2.3.4 port=81 v=1.2.3.4/81 net=1 p81=1 pge=0");
    assert_eq!(x_header(fe, "http://1.2.3.4/x"), "ip=1.2.3.4 port=80 v=1.2.3.4/80 net=1 p81=0 pge=0");
    assert_eq!(x_header(fe, "http://5.6.7.8:8080/"), "ip=5.6.7.8 port=8080 v=5.6.7.8/8080 net=0 p81=0 pge=1");
    assert_eq!(x_header(fe, "/x"), "ip= port= v=/ net=0 p81=0 pge=0");
    assert_eq!(x_header(fe, "http://example.com:81/"), "ip= port= v=/ net=0 p81=0 pge=0");
}
