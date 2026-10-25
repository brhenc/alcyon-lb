// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T474: `%bi` and `%bp`, the local address and port of the connection opened to the server.
//! Every expected shape was measured on `HAProxy` 3.5-dev8-885761-29 with the same configuration:
//! a request rule (before any server connection) prints nothing, a response rule and
//! `http-after-response` print the address the server sees as its peer, an access log line prints
//! the same, `-` when the stream has no server connection, and the address of a refused connect
//! is still printed.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Ibex(Child, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> Ibex {
    let dir = std::env::temp_dir().join(format!("bc-src-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    let full = format!("defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n{cfg}");
    std::fs::write(&path, full).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let ibex = Ibex(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "ibex did not listen on {a}");
    }
    ibex
}

/// A keep-alive server on `bind`. Every answer carries `x-peer: <ip>|<port>`, the address the
/// connection came from, and `echo-x-req`, the request's `x-req` header.
fn backend(bind: &str) -> SocketAddr {
    let l = TcpListener::bind(bind).unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            std::thread::spawn(move || {
                let peer = c.peer_addr().unwrap();
                let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
                let (mut pending, mut b) = (Vec::new(), [0u8; 4096]);
                loop {
                    while let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&pending[..end]).into_owned();
                        pending.drain(..end + 4);
                        let xreq = head.lines().find_map(|l| l.strip_prefix("x-req: ")).unwrap_or("absent");
                        let r = format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nx-peer: {}|{}\r\necho-x-req: {xreq}\r\n\r\nok", peer.ip(), peer.port());
                        if c.write_all(r.as_bytes()).is_err() {
                            return;
                        }
                    }
                    match c.read(&mut b) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => pending.extend_from_slice(&b[..n]),
                    }
                }
            });
        }
    });
    addr
}

fn connect(a: SocketAddr) -> TcpStream {
    let c = TcpStream::connect_timeout(&a, Duration::from_secs(2)).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c
}

/// Sends `GET <path>` on `c`, returns the answer's header block.
fn get(c: &mut TcpStream, path: &str) -> String {
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: a\r\n\r\n").as_bytes()).unwrap();
    let (mut got, mut b) = (Vec::new(), [0u8; 4096]);
    loop {
        if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            let cl = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
            let want: usize = cl.lines().find_map(|l| l.strip_prefix("content-length: ")).map_or(0, |v| v.trim().parse().unwrap());
            if got.len() >= end + 4 + want {
                return String::from_utf8_lossy(&got[..end]).into_owned();
            }
        }
        let n = c.read(&mut b).unwrap_or(0);
        assert!(n > 0, "the answer stopped short: {:?}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&b[..n]);
    }
}

fn header(head: &str, name: &str) -> String {
    head.lines()
        .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string()))
        .unwrap_or_else(|| panic!("no {name} header in {head:?}"))
}

fn config(be: SocketAddr, a: SocketAddr, extra: &str) -> String {
    format!(
        "frontend fe\n  bind {a}\n  default_backend b\n  http-request set-header x-req \"%bi|%bp\"\n  \
         http-response set-header x-res \"%bi|%bp\"\n  http-after-response set-header x-aft \"%bi|%bp\"\n\
         acl lr path /deny\n  http-request deny if lr\n{extra}backend b\n  tcp-response inspect-delay 1s\n  tcp-response content set-var-fmt(txn.bi) \"%bi|%bp\"\n  http-response set-header x-tcp \"%[var(txn.bi)]\"\n  server s {be}\n"
    )
}

/// The request rule runs before the server connection and prints nothing; the response rule and
/// `http-after-response` print the address the server saw (oracle: `|` / `127.0.0.1|<port>`);
/// the second request of a keep-alive connection is on the same server connection; a request
/// denied by a rule on a new connection has no server connection (oracle: `|` in `http-after-response`).
#[test]
fn rules_print_the_address_the_server_saw() {
    let be = backend("127.0.0.1:0");
    let a = common::reserve_addr();
    let _ibex = start("rules", &config(be, a, ""), &[a]);
    let mut c = connect(a);
    for _ in 0..2 {
        let h = get(&mut c, "/");
        let peer = header(&h, "x-peer");
        assert_eq!(header(&h, "echo-x-req"), "|");
        assert_eq!(header(&h, "x-res"), peer);
        assert_eq!(header(&h, "x-aft"), peer);
        assert_eq!(header(&h, "x-tcp"), peer);
    }
    let h = get(&mut connect(a), "/deny");
    assert_eq!(header(&h, "x-aft"), "|");
}

/// A server on `::1`: the address is an IPv6 one.
#[test]
fn ipv6_server() {
    let be = backend("[::1]:0");
    let a = common::reserve_addr();
    let _ibex = start("v6", &config(be, a, ""), &[a]);
    let mut c = connect(a);
    let h = get(&mut c, "/");
    let peer = header(&h, "x-peer");
    assert!(peer.starts_with("::1|"), "{peer}");
    assert_eq!(header(&h, "x-res"), peer);
}

/// The access log: the address the server saw; `-` and `-` for a stream with no server connection
/// (oracle: `bi=- bp=-`); a refused connect still shows the address it used (oracle:
/// `bi=127.0.0.1 bp=<port>`, with a log line of 503).
#[test]
fn access_log_prints_the_address() {
    let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
    collector.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let log = collector.local_addr().unwrap();
    let (be, dead) = (backend("127.0.0.1:0"), common::reserve_addr());
    let (ok, refused) = (common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "frontend f1\n  bind {ok}\n  log {log} local0\n  option dontlognull\n  log-format \"LOG %ST bi=%bi bp=%bp si=%si\"\n  \
         acl lr path /deny\n  http-request deny if lr\n  default_backend good\n\
         frontend f2\n  bind {refused}\n  log {log} local0\n  option dontlognull\n  log-format \"LOG %ST bi=%bi bp=%bp\"\n  default_backend dead\n\
         backend good\n  server s {be}\n\
         backend dead\n  retries 0\n  server s {dead}\n"
    );
    let _ibex = start("log", &cfg, &[ok, refused]);
    let line = |collector: &UdpSocket| {
        let mut buf = [0u8; 2048];
        let n = collector.recv(&mut buf).expect("a log line");
        let l = String::from_utf8_lossy(&buf[..n]).into_owned();
        l[l.find("LOG ").unwrap()..].trim_end().to_string()
    };
    let mut c = connect(ok);
    let h = get(&mut c, "/");
    let (ip, port) = header(&h, "x-peer").split_once('|').map(|(i, p)| (i.to_string(), p.to_string())).unwrap();
    drop(c);
    get(&mut connect(ok), "/deny");
    assert_eq!(line(&collector), format!("LOG 200 bi={ip} bp={port} si=127.0.0.1"));
    assert_eq!(line(&collector), "LOG 403 bi=- bp=- si=-");
    let mut c = connect(refused);
    c.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").unwrap();
    let _ = c.read_to_end(&mut Vec::new());
    let l = line(&collector);
    let rest = l.strip_prefix("LOG 503 bi=127.0.0.1 bp=").unwrap_or_else(|| panic!("{l}"));
    assert!(rest.parse::<u16>().unwrap() > 0, "{l}");
}

/// T474b: a request denied on a keep-alive connection whose server connection is still attached
/// has no server connection of its own. Oracle (same configuration, `GET /` then `GET /deny` on
/// one connection): `http-after-response` of the first `127.0.0.1|127.0.0.1|<port>`, of the
/// denied one `||`; the access log `LOG 127.0.0.1|127.0.0.1|<port>` then `LOG -|-|-`.
#[test]
fn deny_on_a_reused_connection_has_no_server_address() {
    let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
    collector.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let log = collector.local_addr().unwrap();
    let (be, a) = (backend("127.0.0.1:0"), common::reserve_addr());
    let cfg = format!(
        "frontend fe\n  bind {a}\n  log {log} local0\n  option dontlognull\n  log-format \"LOG %si|%bi|%bp\"\n  acl lr path /deny\n  http-request deny if lr\n  \
         http-after-response set-header x-aft \"%si|%bi|%bp\"\n  default_backend b\nbackend b\n  server s {be}\n"
    );
    let _ibex = start("reused-deny", &cfg, &[a]);
    let line = |collector: &UdpSocket| {
        let mut buf = [0u8; 2048];
        let n = collector.recv(&mut buf).expect("a log line");
        let l = String::from_utf8_lossy(&buf[..n]).into_owned();
        l[l.find("LOG ").unwrap()..].trim_end().to_string()
    };
    let mut c = connect(a);
    let h = get(&mut c, "/");
    let (ip, port) = header(&h, "x-peer").split_once('|').map(|(i, p)| (i.to_string(), p.to_string())).unwrap();
    assert_eq!(header(&h, "x-aft"), format!("127.0.0.1|{ip}|{port}"));
    let h = get(&mut c, "/deny");
    assert_eq!(header(&h, "x-aft"), "||");
    assert_eq!(line(&collector), format!("LOG 127.0.0.1|{ip}|{port}"));
    assert_eq!(line(&collector), "LOG -|-|-");
    // The next request that goes to the server prints its connection again. (The oracle also
    // reuses the same connection here; Ibex opens a new one: T474b found-not-fixed.)
    let h = get(&mut c, "/");
    assert_eq!(header(&h, "x-aft"), format!("127.0.0.1|{ip}|{}", header(&h, "x-peer").split_once('|').unwrap().1));
}
