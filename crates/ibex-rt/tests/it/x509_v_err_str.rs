// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T328: `x509_v_err_str` converter

use crate::common;

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

/// Starts ibex on `cfg` (`{sock}` is replaced by the stats socket path), waits for `addrs` and the
/// socket, then lets the readiness probes slide out of the one-second windows and clears the maxima.
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

/// One request on a new connection; the whole raw answer.
fn get(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

/// The request every case answers; `x-c` feeds the `hdr(x-c)` cases.
const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\nx-c: 20\r\nConnection: close\r\n\r\n";

fn http_cfg(global: &str, body: &str) -> String {
    format!(
        "global\n  stats socket {{sock}} level admin\n{global}\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n{body}"
    )
}

/// The body of the answer to `req` (what follows the first empty line).
fn body(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    s.split_once("\r\n\r\n").map_or_else(|| panic!("no answer: {s:?}"), |(_, b)| b.to_string())
}

#[test]
fn x509_v_err_str_converter() {
    let a = common::reserve_addr();
    let cfg = http_cfg(
        "",
        &format!(
            "frontend fe\n  bind {a}\n\
             http-request return status 200 content-type text/plain lf-string \
             \"[%[int(0),x509_v_err_str]|%[int(10),x509_v_err_str]|%[int(20),x509_v_err_str]|%[int(94),x509_v_err_str]|%[int(95),x509_v_err_str]|%[int(-1),x509_v_err_str]|%[str(abc),x509_v_err_str]\
             |%[str(10),x509_v_err_str]|%[hdr(x-c),x509_v_err_str]|%[str(),x509_v_err_str]|%[int(4294967306),x509_v_err_str]|%[hdr(x-none),x509_v_err_str]]\
             {{%[str(10),sub(3)]|%[str(10),mul(2)]|%[hdr(x-c),add(1)]|%[str(7),neg]|%[str(1),bool]|%[str(3),odd]|%[str(1),htonl,hex]|%[str(5),div(2)]\
             |%[str(10),add(5)]|%[bool(1),add(1)]|%[str(abc),add(5)]}}\""
        ),
    );
    let (_ibex, _sock) = start("x509_v_err_str", &cfg, &[a]);
    // Measured on HAProxy 3.5-dev8 with `x-c: 20`. The input is cast to an integer first, as for
    // every integer converter: str(10) is 10, an empty string or a missing header gives no
    // sample, and the code is read as a 32-bit int (4294967306 is 10).
    let expected = "[X509_V_OK|X509_V_ERR_CERT_HAS_EXPIRED|X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY|X509_V_ERR_EC_KEY_EXPLICIT_PARAMS|95|18446744073709551615|X509_V_OK\
                    |X509_V_ERR_CERT_HAS_EXPIRED|X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY||X509_V_ERR_CERT_HAS_EXPIRED|]\
                    {7|20|21|-7|1|1|00000001|2|15|2|5}";
    assert_eq!(body(a, GET), expected);
}
