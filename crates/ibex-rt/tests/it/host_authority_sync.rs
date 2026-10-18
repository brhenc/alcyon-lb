// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T363g: a rule that rewrites `Host` rewrites the authority of an absolute-form request target,
//! and `set-uri` rewrites `Host` from the new target (`http_update_authority`,
//! `http_update_host`). Every expected value was measured on `HAProxy` 3.5-dev8.

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

/// What the server receives (head only) when ibex, configured with `rule`, gets `req`.
fn upstream_head(tag: &str, rule: &str, req: &str) -> String {
    let srv = TcpListener::bind("127.0.0.1:0").unwrap();
    let sp = srv.local_addr().unwrap().port();
    let bind = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("qh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 5s\n  timeout client 5s\n  timeout server 5s\nfrontend fe\n  bind {bind}\n  {rule}\n  default_backend be\nbackend be\n  server s1 127.0.0.1:{sp}\n"
    );
    std::fs::write(&path, cfg).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    assert!(common::wait_listening(bind), "ibex did not listen");
    let h = std::thread::spawn(move || {
        let (mut c, _) = srv.accept().unwrap();
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut d = Vec::new();
        let mut b = [0u8; 4096];
        while !d.windows(4).any(|w| w == b"\r\n\r\n") {
            match c.read(&mut b) {
                Ok(0) | Err(_) => break,
                Ok(n) => d.extend_from_slice(&b[..n]),
            }
        }
        let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        String::from_utf8_lossy(&d).into_owned()
    });
    let mut c = TcpStream::connect(bind).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    c.write_all(req.as_bytes()).unwrap();
    let mut sink = [0u8; 256];
    let _ = c.read(&mut sink);
    let head = h.join().unwrap();
    common::stop(&mut child);
    let _ = std::fs::remove_dir_all(&dir);
    head
}

/// The request line and the `host` lines the server got.
fn line_and_hosts(head: &str) -> (String, Vec<String>) {
    let mut l = head.split("\r\n");
    let first = l.next().unwrap_or("").to_string();
    (first, l.filter(|x| x.to_ascii_lowercase().starts_with("host:")).map(str::to_string).collect())
}

fn check(tag: &str, rule: &str, req: &str, line: &str, hosts: &[&str]) {
    let (l, h) = line_and_hosts(&upstream_head(tag, rule, req));
    assert_eq!((l.as_str(), h.iter().map(String::as_str).collect::<Vec<_>>()), (line, hosts.to_vec()), "{rule} on {req:?}");
}

#[test]
fn a_host_rewrite_updates_the_authority() {
    let abs = "GET http://a.com/p?q HTTP/1.1\r\nHost: a.com\r\n\r\n";
    check("ha1", "http-request set-header host n.org", abs, "GET http://n.org/p?q HTTP/1.1", &["host: n.org"]);
    check("ha2", "http-request add-header host n.org", abs, "GET http://n.org/p?q HTTP/1.1", &["host: a.com", "host: n.org"]);
    check("ha3", "http-request replace-value host a n", abs, "GET http://n/p?q HTTP/1.1", &["host: n"]);
    check("ha4", "http-request replace-header host (.*) x\\1", abs, "GET http://xa.com/p?q HTTP/1.1", &["host: xa.com"]);
    check("ha5", "http-request set-header host n.org:81", "GET http://a.com?q HTTP/1.1\r\nHost: a.com\r\n\r\n", "GET http://n.org:81?q HTTP/1.1", &["host: n.org:81"]);
    // The user information stays.
    check(
        "ha6",
        "http-request replace-header host (.*) x\\1",
        "GET http://u:p@a.com/p HTTP/1.1\r\nHost: a.com\r\n\r\n",
        "GET http://u:p@xa.com/p HTTP/1.1",
        &["host: xa.com"],
    );
}

#[test]
fn only_a_host_header_and_an_absolute_target_are_concerned() {
    check("hb1", "http-request set-header host n.org", "GET /p HTTP/1.1\r\nHost: a.com\r\n\r\n", "GET /p HTTP/1.1", &["host: n.org"]);
    check(
        "hb2",
        "http-request set-header x-host n.org",
        "GET http://a.com/p HTTP/1.1\r\nHost: a.com\r\n\r\n",
        "GET http://a.com/p HTTP/1.1",
        &["host: a.com"],
    );
}

#[test]
fn set_uri_updates_host() {
    let abs = "GET http://a.com/p HTTP/1.1\r\nHost: a.com\r\n\r\n";
    check("hc1", "http-request set-uri http://z.com/zz", abs, "GET http://z.com/zz HTTP/1.1", &["host: z.com"]);
    check("hc2", "http-request set-uri /zz", abs, "GET /zz HTTP/1.1", &["host: a.com"]);
}
