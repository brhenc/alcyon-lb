// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T330: ip.fp converter

use crate::common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Ibex(Child, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> (Ibex, String) {
    let dir = std::env::temp_dir().join(format!("qh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg.replace("{sock}", &sock).replace("{dir}", &dir.display().to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let ibex = Ibex(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "ibex did not listen on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(2200));
    cli(&sock, "clear counters");
    (ibex, sock)
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn info(sock: &str) -> HashMap<String, String> {
    cli(sock, "show info").lines().filter_map(|l| l.split_once(": ")).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn num(i: &HashMap<String, String>, k: &str) -> u64 {
    i.get(k).unwrap_or_else(|| panic!("show info has no {k}")).parse().unwrap_or_else(|_| panic!("{k} is not a number: {:?}", i[k]))
}

fn get(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";

fn http_cfg(global: &str, body: &str) -> String {
    format!("global\n  stats socket {{sock}} level admin\n{global}defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n{body}")
}

fn backend(resp: &'static [u8]) -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
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
            let _ = c.write_all(resp);
        }
    });
    addr
}

fn body(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    s.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_else(|| panic!("no answer: {s:?}"))
}

fn xout(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    let head = s.split("\r\n\r\n").next().unwrap_or("");
    head.lines()
        .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("x-out")).map(|(_, v)| v.trim().to_string()))
        .unwrap_or_else(|| panic!("no x-out header in the answer: {s:?}"))
}

#[test]
fn ip_fp_converter() {
    let a = common::reserve_addr();
    let cfg = format!("global\n  stats socket {{sock}} level admin\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nfrontend fe\n  bind {}\n  http-request return status 200 content-type text/plain lf-string \"%[bin(4510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.fp,hex]|%[bin(4510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.fp(1),hex]|%[bin(4510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.fp(2),hex]|%[bin(4510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.fp(4),hex]|%[bin(4510003c1c46400040060000c0000201c63364029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.fp(7),hex]|%[bin(600000000028064020010db800000000000000000000000120010db80000000000000000000000029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.fp,hex]|%[bin(600000000028064020010db800000000000000000000000120010db80000000000000000000000029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.fp(1),hex]|%[bin(600000000028064020010db800000000000000000000000120010db80000000000000000000000029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.fp(2),hex]|%[bin(600000000028064020010db800000000000000000000000120010db80000000000000000000000029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.fp(4),hex]|%[bin(600000000028064020010db800000000000000000000000120010db80000000000000000000000029c4001bb0102030400000000a002faf000000000020405b40402080a112233440000000001030307),ip.fp(7),hex]\"",
        a);
    let (ibex, _sock) = start("ip_fp", &cfg, &[a]);
    let b = body(a, GET);
    let expected = "1050A8FAF005B447|1050A8FAF005B44740|1050A8FAF005B4470204080103|1050A8FAF005B447C0000201|1050A8FAF005B447400204080103C0000201|00D0A8FAF005B447|00D0A8FAF005B44740|00D0A8FAF005B4470204080103|00D0A8FAF005B44720010DB8000000000000000000000001|00D0A8FAF005B44740020408010320010DB8000000000000000000000001";
    assert_eq!(b, expected);
}
