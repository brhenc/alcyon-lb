// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `del backend` on the stats socket (T637 S6a). Every answer was measured on `HAProxy`
//! 3.5-dev11 (`ADB_ORACLE=<haproxy>` runs this file against it). The refusals come in
//! `be_check_for_deletion`'s order; a deleted backend is gone from the switching rules, from
//! `show stat`, `show backend`, `show servers state` and the Prometheus exporter, and the
//! listing of the others goes on in declaration order, including past the first declared one.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Proc(Child, std::path::PathBuf);

impl Drop for Proc {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

const CFG: &str = r####"global
  stats socket {sock} mode 600 level admin
defaults
  mode http
  timeout client 10s
  timeout server 5s
  timeout connect 5s

backend be_first

frontend fe
  bind {f1}
  force-be-switch if { req.hdr(x-admin) 1 }
  http-request set-header x-n %[nbsrv(be_fetch)]
  use_backend %[req.hdr(x-be)] if { req.hdr(x-be) -m found }
  use_backend be_ref if { path /ref }
  default_backend be_dflt

{prom}
listen li
  bind {lm}

listen lx
  bind {lx}

backend be_ref

backend be_dflt
  server d1 127.0.0.1:{od}

backend be_srv
  server s1 127.0.0.1:{od} disabled

backend be_tbl
  stick-table type ip size 1k

backend be_fetch

backend be_tcp
  mode tcp

backend be_mid

backend be_empty
  http-request wait-for-body time 5s

backend be_last
"####;

/// One command on the stats socket, as one connection: `HAProxy` closes after the answer.
fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(5)).into()).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// `GET path` to `addr` with `extra` header lines: the whole reply.
fn get(addr: SocketAddr, path: &str, extra: &str) -> String {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(4)).into()).unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n{extra}Connection: close\r\n\r\n").as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// An origin that answers `200` with `body`.
fn origin(body: &'static str) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("origin");
    let port = l.local_addr().expect("origin addr").port();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let mut buf = [0u8; 1024];
            let _ = c.read(&mut buf);
            let _ = c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
        }
    });
    port
}

struct Rig {
    sock: String,
    f1: SocketAddr,
    f2: SocketAddr,
    _p: Proc,
}

fn start() -> Rig {
    let f1 = common::reserve_addr();
    let f2 = common::reserve_addr();
    let lm = common::reserve_addr();
    let lx = common::reserve_addr();
    let od = origin("DEFAULT\n");
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!("adb-delbe-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    // The exporter is an Alcyon-side check: the reference build has none.
    let oracle = std::env::var("ADB_ORACLE").is_ok();
    let prom = if oracle { String::new() } else { format!("frontend prom\n  bind {f2}\n  http-request use-service prometheus-exporter if {{ path /metrics }}\n") };
    let cfg = CFG
        .replace("{prom}", &prom)
        .replace("{sock}", &sock)
        .replace("{od}", &od.to_string())
        .replace("{lm}", &lm.to_string())
        .replace("{lx}", &lx.to_string())
        .replace("{f1}", &f1.to_string())
        .replace("{f2}", &f2.to_string());
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let bin = std::env::var("ADB_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(bin).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let p = Proc(child, dir);
    assert!(common::wait_listening(f1), "no listener on fe");
    assert!(oracle || common::wait_listening(f2), "no listener on prom");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    Rig { sock, f1, f2, _p: p }
}

/// The proxy names `show stat` lists, in order, once each (backend rows).
fn stat_backends(sock: &str) -> Vec<String> {
    cli(sock, "show stat -1 2 -1").lines().filter_map(|l| l.split(',').next().filter(|n| !n.is_empty() && !n.starts_with('#')).map(str::to_string)).collect()
}

/// Whether a stream is attached to `be`, as `show sess` lists it.
fn attached(sock: &str, be: &str) -> bool {
    cli(sock, "show sess").contains(&format!("be={be} "))
}

macro_rules! check {
    ($what:expr, $got:expr, $want:expr) => {
        assert_eq!($got, $want, "{}", $what)
    };
}

#[test]
fn del_backend_refusals_in_haproxy_order() {
    let r = start();
    let s = &r.sock;
    check!("bare", cli(s, "del backend"), "No such backend.\n\n");
    check!("extra word", cli(s, "del backend be_mid x"), "Usage: del backend <name>.\n\n");
    check!("unknown", cli(s, "del backend nosuch"), "No such backend.\n\n");
    check!("a frontend is no backend", cli(s, "del backend fe"), "No such backend.\n\n");
    check!("listen", cli(s, "del backend li"), "Cannot delete a listen section.\n\n");
    check!("any listen, whatever its name", cli(s, "del backend lx"), "Cannot delete a listen section.\n\n");
    check!("stick-table", cli(s, "del backend be_tbl"), "Cannot remove a backend with stick-table.\n\n");
    let pointing = "This proxy cannot be removed at runtime due to other configuration elements pointing to it.\n\n";
    check!("use_backend target", cli(s, "del backend be_ref"), pointing);
    check!("default_backend target", cli(s, "del backend be_dflt"), pointing);
    check!("fetch argument", cli(s, "del backend be_fetch"), pointing);
    check!("published", cli(s, "del backend be_srv"), "Backend must be unpublished prior to its deletion.\n\n");
    check!("unpublish", cli(s, "unpublish backend be_srv"), "Backend unpublished.\n\n");
    check!("with a server", cli(s, "del backend be_srv"), "Only a backend without server can be deleted.\n\n");
    // Nothing was deleted by a refusal.
    assert!(stat_backends(s).contains(&"be_srv".to_string()));
}

#[test]
fn del_backend_deletes_and_every_listing_agrees() {
    let r = start();
    let s = &r.sock;
    let before = stat_backends(s);
    assert_eq!(before.first().map(String::as_str), Some("be_first"));
    for be in ["be_mid", "be_first", "be_tcp"] {
        check!("unpublish", cli(s, &format!("unpublish backend {be}")), "Backend unpublished.\n\n");
    }
    // The middle one, the first declared one, then a tcp one.
    check!("mid", cli(s, "del backend be_mid"), "Backend deleted.\n\n");
    check!("first", cli(s, "del backend be_first"), "Backend deleted.\n\n");
    check!("tcp", cli(s, "del backend be_tcp"), "Backend deleted.\n\n");
    for be in ["be_mid", "be_first", "be_tcp"] {
        check!("again", cli(s, &format!("del backend {be}")), "No such backend.\n\n");
        check!("publish", cli(s, &format!("publish backend {be}")), "No such backend.\n\n");
        check!("show stat", cli(s, &format!("show stat {be} 2 -1")), "No such proxy.\n\n");
        // (Alcyon ends this one answer with one newline; the oracle with a blank line more.)
        assert!(cli(s, &format!("show servers state {be}")).starts_with("Can't find backend.\n"), "servers state {be}");
    }
    // `show stat` goes on in declaration order from the first row, past both holes.
    let want: Vec<String> = before.iter().filter(|n| !["be_mid", "be_first", "be_tcp"].contains(&n.as_str())).cloned().collect();
    check!("show stat", stat_backends(s), want);
    let sb = cli(s, "show backend");
    assert!(sb.starts_with("# name\n"), "{sb:?}");
    assert!(!sb.contains("\n\n") || sb.ends_with("\n\n") && !sb[..sb.len() - 1].contains("\n\n"), "no empty line in show backend: {sb:?}");
    for be in ["be_mid", "be_first", "be_tcp"] {
        assert!(!sb.lines().any(|l| l == be), "{be} listed by show backend");
    }
    assert!(sb.lines().any(|l| l == "be_last"));
    let prom = if std::env::var("ADB_ORACLE").is_ok() { String::from("proxy=\"be_last\"") } else { get(r.f2, "/metrics", "") };
    assert!(prom.contains("proxy=\"be_last\""), "promex lists the others: {}", &prom[..prom.len().min(300)]);
    for be in ["be_mid", "be_first", "be_tcp"] {
        assert!(!prom.contains(&format!("proxy=\"{be}\"")), "promex lists {be}");
    }
    // A dynamic rule naming a deleted backend goes on to the default.
    assert!(get(r.f1, "/", "x-be: be_mid\r\n").ends_with("DEFAULT\n"));
    // A fresh deletion of the others still works (the table the second command sees is current).
    check!("unpublish", cli(s, "unpublish backend be_last"), "Backend unpublished.\n\n");
    check!("last", cli(s, "del backend be_last"), "Backend deleted.\n\n");
}

#[test]
fn del_backend_refused_while_a_stream_is_attached() {
    let r = start();
    let s = &r.sock;
    check!("unpublish", cli(s, "unpublish backend be_empty"), "Backend unpublished.\n\n");
    // `force-be-switch` enters the unpublished backend, where `wait-for-body` holds the request.
    let mut held = TcpStream::connect_timeout(&r.f1, Duration::from_secs(3)).expect("connect");
    held.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nx-be: be_empty\r\nx-admin: 1\r\nContent-Length: 10\r\n\r\n").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !attached(s, "be_empty") {
        assert!(Instant::now() < deadline, "the request never reached be_empty");
        std::thread::sleep(Duration::from_millis(20));
    }
    check!("attached", cli(s, "del backend be_empty"), "Backend still has attached streams on it.\n\n");
    // The refusal leaves it as it was: unpublished, and still enterable by `force-be-switch`.
    assert!(cli(s, "show stat be_empty 2 -1").contains("UP (UNPUB)"), "still unpublished");
    drop(held);
    let deadline = Instant::now() + Duration::from_secs(5);
    while attached(s, "be_empty") {
        assert!(Instant::now() < deadline, "the stream never left be_empty");
        std::thread::sleep(Duration::from_millis(20));
    }
    check!("deleted", cli(s, "del backend be_empty"), "Backend deleted.\n\n");
}

#[test]
fn requests_keep_being_answered_while_backends_are_deleted() {
    let r = start();
    let s = r.sock.clone();
    let f1 = r.f1;
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let st = std::sync::Arc::clone(&stop);
    let load = std::thread::spawn(move || {
        let mut bad = Vec::new();
        let mut n = 0;
        while !st.load(std::sync::atomic::Ordering::Relaxed) {
            n += 1;
            let a = get(f1, "/", "");
            let b = get(f1, "/", "x-be: be_mid\r\n");
            for x in [a, b] {
                if !x.starts_with("HTTP/1.1 200") || !x.ends_with("DEFAULT\n") {
                    bad.push(x);
                }
            }
        }
        (n, bad)
    });
    for be in ["be_mid", "be_first", "be_last", "be_tcp"] {
        check!("unpublish", cli(&s, &format!("unpublish backend {be}")), "Backend unpublished.\n\n");
        check!("del", cli(&s, &format!("del backend {be}")), "Backend deleted.\n\n");
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let (n, bad) = load.join().expect("load");
    assert!(n > 0 && bad.is_empty(), "{n} rounds, bad answers: {bad:?}");
}

/// `cli_del_backend.vtc`: `unpublish backend be_first; del backend be_first` is one line. The
/// second command waits for the workers, and the connection stays open for its answer.
#[test]
fn del_backend_as_the_second_command_of_a_line() {
    let r = start();
    let out = cli(&r.sock, "unpublish backend be_first; del backend be_first");
    assert!(out.contains("Backend unpublished.") && out.contains("Backend deleted."), "{out:?}");
    check!("gone", cli(&r.sock, "del backend be_first"), "No such backend.\n\n");
}
