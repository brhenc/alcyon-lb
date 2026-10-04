// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Sample fetch edge cases against the real binary (T137). Every expected value was measured
//! on `HAProxy` 3.5-dev8-885761-29 with the same configuration.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0
                        || s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    addr
}

struct Ibex(Child, NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(cfg: &str, fe: SocketAddr) -> Ibex {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
        thread::sleep(Duration::from_millis(20));
    }
    Ibex(child, f)
}

/// One request on its own connection; the whole response.
fn get(fe: SocketAddr, extra: &str) -> String {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    write!(s, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{extra}\r\n").expect("send");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn header(resp: &str, name: &str) -> Option<String> {
    resp.split("\r\n").find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n";

#[test]
fn acl_fetch_evaluates_named_acls_with_negation_and_the_predefined_ones() {
    let fe = common::reserve_addr();
    let _ibex = start(
        &format!(
            "{DEFAULTS}frontend fe\n  bind {fe}\n  acl ACL1 always_true\n  acl ACL2 acl(ACL1)\n  \
             acl ACL3 acl(!ACL2)\n  acl ACL4 acl(ACL2,!ACL3)\n  \
             http-request return status 200 hdr x-acl \"ACL1=%[acl(ACL1)] ACL2=%[acl(ACL2)] \
             ACL3=%[acl(ACL3)] ACL4=%[acl(ACL4)] TRUE=%[acl(TRUE)] FALSE=%[acl(FALSE)] \
             both=%[acl(ACL1,ACL3)] mix=%[acl(ACL1,!ACL3)]\"\n"
        ),
        fe,
    );
    let r = get(fe, "");
    assert_eq!(
        header(&r, "x-acl").as_deref(),
        Some("ACL1=1 ACL2=1 ACL3=0 ACL4=1 TRUE=1 FALSE=0 both=0 mix=1"),
        "{r}"
    );
}
