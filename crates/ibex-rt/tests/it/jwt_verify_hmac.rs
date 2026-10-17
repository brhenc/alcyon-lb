// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T331: `jwt_verify` (HMAC)

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

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";

/// The body of the answer to `req` (what follows the first empty line).
fn body(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    s.split_once("\r\n\r\n").map_or_else(|| panic!("no answer: {s:?}"), |(_, b)| b.to_string())
}

#[test]
fn jwt_verify_hmac() {
    let a = common::reserve_addr();
    let cfg = format!(
        "global\n  stats socket {{sock}} level admin\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nfrontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeJQ),jwt_verify(HS256,secret)]|%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeJQ),jwt_verify(HS256,wrong)]|%[str(eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiIn0.uQcCTiqKrIb7KNZEPslsm0ssheQ5IsgM4l5jzXYsqifQIY9_ImDqO0t5pUOT_e2w_1qxTkrjIGERnv13JdYMSA),jwt_verify(HS512,secret)]|%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeAA),jwt_verify(HS256,secret)]|%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeJQ),jwt_verify(HS512,secret)]|%[str(abc),jwt_verify(HS256,secret)]\"",
    );
    let (_ibex, _sock) = start("jwt_verify_hmac", &cfg, &[a]);
    let b = body(a, GET);
    // Expected: 1|0|1|0|0|-3
    assert_eq!(b, "1|0|1|0|0|-3");
}

/// T331: codes measured on the `HAProxy` oracle for malformed tokens and algorithm names (the
/// algorithm in a variable, as a literal one is checked at load time).
#[test]
fn jwt_verify_hmac_codes() {
    let a = common::reserve_addr();
    let cfg = format!(
        "global\n  stats socket {{sock}} level admin\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nfrontend fe\n  bind {a}\n  http-request set-var(txn.a) str(HS256)\n  http-request set-var(txn.k) str(secret)\n  http-request set-var(txn.a_hs256) str(hs256)\n  http-request set-var(txn.a_none) str(none)\n  http-request set-var(txn.a_RS256) str(RS256)\n  http-request set-var(txn.a_XX999) str(XX999)\n  http-request set-var(txn.a_HS384) str(HS384)\n  http-request return status 200 content-type text/plain lf-string \"%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeJQ),jwt_verify(txn.a,secret)]|%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeJQ.x),jwt_verify(HS256,secret)]|%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.),jwt_verify(HS256,secret)]|%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qB=),jwt_verify(HS256,secret)]|%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.q),jwt_verify(HS256,secret)]|%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeJQ=),jwt_verify(HS256,secret)]|%[str(a.b),jwt_verify(HS256,secret)]|%[str(),jwt_verify(HS256,secret)]|%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeJQ),jwt_verify(HS384,secret)]|%[str(abc),jwt_verify(HS256,txn.k)]|%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.q-dA),jwt_verify(HS256,secret)]|%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeJQ),jwt_verify(HS256,txn.k)]|%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeJQ),jwt_verify(txn.a_hs256,secret)]|%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeJQ),jwt_verify(txn.a_none,secret)]|%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeJQ),jwt_verify(txn.a_RS256,secret)]|%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeJQ),jwt_verify(txn.a_XX999,secret)]|%[str(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.qBdA9L_PTGPhu7ipY7Xs4Eol-m79U_HNIifGEFJXeJQ),jwt_verify(txn.a_HS384,secret)]|\"\n",
    );
    let (_ibex, _sock) = start("jwt_verify_codes", &cfg, &[a]);
    assert_eq!(body(a, GET), "1|-3|-3|0|-3|0|-3|-3|0|-3|0|1|-1|-2|-5|-1|0|");
}

/// T331: a literal algorithm `HAProxy` refuses at load time is refused by Ibex too, as is one
/// whose public key Ibex cannot load.
#[test]
fn jwt_verify_refused_algs() {
    for alg in ["hs256", "XX999", "RS256", "none"] {
        let dir = std::env::temp_dir().join(format!("qh-jwt-ref-{alg}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.cfg");
        let a = common::reserve_addr();
        std::fs::write(&path, format!("defaults\n  mode http\n  timeout client 5s\nfrontend fe\n  bind {a}\n  http-request return status 200 lf-string \"%[str(abc),jwt_verify({alg},/nonexistent/key.pem)]\"\n")).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!out.status.success(), "{alg} was accepted");
    }
}
