// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Which backup server takes the traffic when every active server is down.
//!
//! Without `option allbackups` (which Ibex refuses), `HAProxy` sends everything to the
//! first usable backup in declaration order (`lbprm.fbck`, set by `recount_servers`), under
//! every balance algorithm. Measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-03: an
//! active server on a closed port with `check inter 100ms fall 1`, three backups, a second
//! for the check to fail, then six `GET /p<n>` requests on their own connections; every
//! one went to `s1`. With `s1` itself down as well, every one went to `s2`.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// A server answering every request with `X-Server: <name>`.
fn server(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        buf.drain(..end + 4);
                        let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Server: {name}\r\n\r\nok");
                        if c.write_all(resp.as_bytes()).is_err() {
                            return;
                        }
                    }
                    match c.read(&mut chunk) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
            });
        }
    });
    addr
}

fn start(cfg: &str) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let mut text = cfg.replace("{fe}", &fe.to_string());
    for name in ["s1", "s2", "s3"] {
        text = text.replace(&format!("{{{name}}}"), &server(name).to_string());
    }
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, _cfg: f };
    assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}");
    (ibex, fe)
}

/// The `X-Server` of the answer to `GET <path>`.
fn served_by(fe: SocketAddr, path: &str) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes()).expect("send");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    let text = String::from_utf8_lossy(&got).into_owned();
    text.split("\r\n")
        // Header names are case-insensitive; HAProxy emits them lowercase (T244).
        .find_map(|l| l.split_once(": ").filter(|(n, _)| n.eq_ignore_ascii_case("X-Server")).map(|(_, v)| v))
        .map_or_else(|| format!("<no X-Server in {:?}>", text.lines().next().unwrap_or_default()), str::to_string)
}

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n";

#[test]
fn only_the_first_backup_takes_traffic_under_every_algorithm() {
    for algo in ["roundrobin", "static-rr", "leastconn", "first", "uri", "source", "random"] {
        let (_ibex, fe) = start(&format!(
            "{DEFAULTS}frontend f\n  bind {{fe}}\n  default_backend b\nbackend b\n  balance {algo}\n  \
             server p 127.0.0.1:1 check inter 100ms fall 1\n  \
             server s1 {{s1}} backup\n  server s2 {{s2}} backup\n  server s3 {{s3}} backup\n"
        ));
        thread::sleep(Duration::from_millis(1000));
        let got: Vec<String> = (0..6).map(|i| served_by(fe, &format!("/p{i}"))).collect();
        assert!(got.iter().all(|s| s == "s1"), "balance {algo}: {got:?}");
    }
}

#[test]
fn the_next_backup_takes_over_when_the_first_is_down() {
    let (_ibex, fe) = start(&format!(
        "{DEFAULTS}frontend f\n  bind {{fe}}\n  default_backend b\nbackend b\n  \
         server p 127.0.0.1:1 check inter 100ms fall 1\n  \
         server s1 127.0.0.1:2 backup check inter 100ms fall 1\n  server s2 {{s2}} backup\n  server s3 {{s3}} backup\n"
    ));
    thread::sleep(Duration::from_millis(1000));
    let got: Vec<String> = (0..4).map(|i| served_by(fe, &format!("/p{i}"))).collect();
    assert!(got.iter().all(|s| s == "s2"), "{got:?}");
}
