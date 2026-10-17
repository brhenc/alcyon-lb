// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T326: process-wide fetches

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

fn info(sock: &str) -> HashMap<String, String> {
    cli(sock, "show info").lines().filter_map(|l| l.split_once(": ")).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn num(i: &HashMap<String, String>, k: &str) -> u64 {
    i.get(k).unwrap_or_else(|| panic!("show info has no {k}")).parse().unwrap_or_else(|_| panic!("{k} is not a number: {:?}", i[k]))
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

fn http_cfg(global: &str, body: &str) -> String {
    format!(
        "global\n  stats socket {{sock}} level admin\n{global}\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n{body}"
    )
}

/// A server on a free port that reads each request head, answers `resp` and closes the connection.
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

/// The body of the answer to `req` (what follows the first empty line).
fn body(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    s.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_else(|| panic!("no answer: {s:?}"))
}

/// The value of the `x-out` header in the answer to `req`.
fn xout(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    let head = s.split("\r\n\r\n").next().unwrap_or("");
    head.lines()
        .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("x-out")).map(|(_, v)| v.trim().to_string()))
        .unwrap_or_else(|| panic!("no x-out header in the answer: {s:?}"))
}

#[test]
fn process_fetches() {
    let a = common::reserve_addr();
    let cfg = http_cfg(
        "nbthread 1\n",
        &format!(
            "frontend fe\n  bind {A}\n  http-request return status 200 content-type text/plain lf-string \"[%[pid]|%[hostname]|%[nbproc]|%[proc]|%[thread]|%[stopping]]\"\n",
            A = a
        ),
    );
    let (ibex, sock) = start("t326", &cfg, &[a]);

    let expected_pid = ibex.0.id() as i64;
    let expected_host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let resp = body(a, GET);
    assert_eq!(
        resp,
        format!("[{expected_pid}|{expected_host}|1|1|0|0]"),
        "process fetches mismatch"
    );

    let _ = sock;
    let _ = ibex;
}

/// `thread` on the response side (the oracle: "0" with nbthread 1). The candidate set the thread
/// only in three of the sample contexts, so http-response rules saw no sample.
#[test]
fn thread_in_http_response() {
    let a = common::reserve_addr();
    let be = backend(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
    let cfg = http_cfg(
        "nbthread 1\n",
        &format!(
            "frontend fe\n  bind {a}\n  http-response set-header x-out \"%[thread]\"\n  default_backend be\n\
             backend be\n  server s {be}\n"
        ),
    );
    let (_ibex, _sock) = start("t326-res", &cfg, &[a]);
    assert_eq!(xout(a, GET), "0", "thread in an http-response rule");
}

/// `thread` in a tcp-request content rule (the oracle accepts: the variable is 0).
#[test]
fn thread_in_tcp_request_content() {
    let a = common::reserve_addr();
    let be = backend(b"ok\n");
    let cfg = format!(
        "global\n  stats socket {{sock}} level admin\n  nbthread 1\n\
         defaults\n  mode tcp\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {a}\n  tcp-request content set-var(sess.t) thread\n  \
         tcp-request content reject unless {{ var(sess.t) -m int 0 }}\n  default_backend be\n\
         backend be\n  server s {be}\n"
    );
    let (_ibex, _sock) = start("t326-tcp", &cfg, &[a]);
    let out = get(a, b"hello\r\n\r\n");
    assert_eq!(String::from_utf8_lossy(&out), "ok\n", "tcp-request content saw no thread and rejected");
}

/// `stopping` during a soft stop: a request whose head is still incomplete when SIGUSR1 arrives
/// is answered with stopping = 1 on the oracle. The candidate hard-coded false.
#[test]
fn stopping_during_soft_stop() {
    let a = common::reserve_addr();
    let cfg = http_cfg(
        "nbthread 1\n",
        &format!("frontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"[%[stopping]]\"\n"),
    );
    let (ibex, _sock) = start("t326-stop", &cfg, &[a]);
    let mut s = TcpStream::connect_timeout(&a, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let pid = rustix::process::Pid::from_raw(i32::try_from(ibex.0.id()).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::Usr1).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    s.write_all(b"Connection: close\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let out = String::from_utf8_lossy(&out).into_owned();
    let body = out.split_once("\r\n\r\n").map_or_else(|| panic!("no answer: {out:?}"), |(_, b)| b.to_string());
    assert_eq!(body, "[1]", "stopping after SIGUSR1");
}
