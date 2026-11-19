// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `del server <backend>/<server>` on the stats socket (T637 S4).
//!
//! Every answer below was measured on `HAProxy` 3.5-dev11
//! (`DELSRV_ORACLE=<haproxy>` runs this file against it). The refused forms, the "pointed to"
//! refusals (a `use-server` target, a `track` target, a server named in a fetch argument, a
//! server with `resolvers`), the maintenance refusal, the in-use refusal and `Server deleted.`
//! are `cli_parse_delete_server` + `srv_check_for_deletion` + `srv_in_use`
//! (`src/server.c`). After a delete the server is `No such server.` to every command, `show
//! servers state` and `show stat` list it no more, and no path (persistence cookie, stick
//! table, the server found by its address, the queue) may assign it any more: a request that
//! would have matched its persistence is load-balanced.

use crate::common;

use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
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
  nbthread 4
defaults
  mode http
  timeout connect 1s
  timeout client 30s
  timeout server 30s
frontend fe
  bind {fe}
  use_backend be_slow if { path_beg /slow }
  use_backend be_ka if { path_beg /ka }
  use_backend be_ck if { path_beg /ck }
  use_backend be_same if { path_beg /same }
  use_backend be_stk if { path_beg /stk }
  default_backend be
backend be
  server s1 127.0.0.1:{o1}
  server s2 127.0.0.1:{o2}
  server s3 127.0.0.1:{o3}
  use-server s3 if { path /s3 }
backend be_trk
  server t1 127.0.0.1:{o1} track be_trk/t2
  server t2 127.0.0.1:{o2} check inter 1s
backend be_fetch
  http-request set-header x-up %[srv_is_up(be_fetch/f1)]
  server f1 127.0.0.1:{o1}
  server f2 127.0.0.1:{o2}
backend be_static
  balance static-rr
  server x1 127.0.0.1:{o1}
  server x2 127.0.0.1:{o2}
backend be_ck
  cookie SRV insert indirect nocache
  option persist
  server k1 127.0.0.1:{o1} cookie k1
  server k2 127.0.0.1:{o2} cookie k2
backend be_slow
  server w1 127.0.0.1:{held}
  server w2 127.0.0.1:{o2}
backend be_ka
  server ka1 127.0.0.1:{keep}
  server ka2 127.0.0.1:{o2}
backend be_same
  server a1 127.0.0.1:{o1}
  server a2 127.0.0.1:{o1}
backend be_stk
  balance first
  stick-table type ip size 10
  stick on src
  option persist
  server st1 127.0.0.1:{o1}
  server st2 127.0.0.1:{o2}
resolvers r
  nameserver ns1 127.0.0.1:{dns}
backend be_res
  server r1 example.invalid:80 resolvers r init-addr none
  server r2 127.0.0.1:{o2}
backend be_dis
  server d1 127.0.0.1:{o1} disabled
  server d2 127.0.0.1:{o2}
backend be_chk
  server ch1 127.0.0.1:{o1} check inter 100ms
  server ch2 127.0.0.1:{o2}
listen li
  bind {li}
  server l1 127.0.0.1:{o1}
  server l2 127.0.0.1:{o2}
"####;

/// One command on the stats socket, as one connection: HAProxy closes after the answer.
fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3)).into())
        .unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// `GET <path>` to `addr`, with `cookie` as a `Cookie` header when set: the whole reply.
fn get(addr: SocketAddr, path: &str, cookie: Option<&str>) -> String {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(8)).into())
        .unwrap();
    let cookie = cookie.map_or(String::new(), |c| format!("Cookie: {c}\r\n"));
    let _ = s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: x\r\n{cookie}Connection: close\r\n\r\n").as_bytes(),
    );
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// An origin that answers `200` with `body` and counts its connections.
fn count_origin(body: &str) -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("origin");
    let port = l.local_addr().expect("origin addr").port();
    let n = Arc::new(AtomicUsize::new(0));
    let b = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let c = Arc::clone(&n);
    let h = std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(mut conn) = conn else { continue };
            c.fetch_add(1, Ordering::Relaxed);
            let mut buf = [0u8; 1024];
            let _ = conn.read(&mut buf);
            let _ = conn.write_all(b.as_bytes());
            let _ = conn.flush();
        }
    });
    let _ = h;
    (port, n)
}

/// An origin that holds each request's answer until the test sends its release token: the
/// proxy's stream to it then sits on the server, as `srv_in_use` counts it. When a connection
/// has its request read, it hands its release `Sender` to the test.
fn held_origin() -> (u16, mpsc::Receiver<mpsc::Sender<()>>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("held origin");
    let port = l.local_addr().expect("held addr").port();
    let (ready_tx, ready_rx) = mpsc::channel::<mpsc::Sender<()>>();
    let h = std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(mut conn) = conn else { break };
            let ready = ready_tx.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                        Err(_) => break,
                    }
                }
                let (rel_tx, rel_rx) = mpsc::channel::<()>();
                let _ = ready.send(rel_tx);
                let _ = rel_rx.recv();
                let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nW1\n");
                let _ = conn.flush();
            });
        }
    });
    let _ = h;
    (port, ready_rx)
}

/// `GET <path>` to `addr` with the client connection kept open (no `Connection: close`):
/// the reply and the still-open `TcpStream`. While the client waits, the proxy's released
/// connection to the server sits idle in its pool, as the keep-alive row needs.
fn get_keepalive(addr: SocketAddr, path: &str) -> (String, TcpStream) {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(8)).into())
        .unwrap();
    let _ = s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes(),
    );
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
        let s = String::from_utf8_lossy(&out);
        let head = s.find("\r\n\r\n").map_or(usize::MAX, |i| i + 4);
        if let Some(i) = s.find("Content-Length: ") {
            let v = s[i + "Content-Length: ".len()..].split(['\r', '\n']).next().unwrap_or("");
            if let Ok(cl) = v.parse::<usize>() {
                if out.len() >= head + cl {
                    break;
                }
            }
        }
    }
    (String::from_utf8_lossy(&out).into_owned(), s)
}

/// An origin that answers `200` and keeps the connection open: the proxy's released
/// connection to it waits idle in its pool.
fn keepalive_origin() -> (u16, mpsc::Receiver<()>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("ka origin");
    let port = l.local_addr().expect("ka addr").port();
    let (eof_tx, eof_rx) = mpsc::channel();
    let h = std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(mut conn) = conn else { break };
            let eof_tx = eof_tx.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                        Err(_) => break,
                    }
                }
                let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nKA1\n");
                let _ = conn.flush();
                loop {
                    match conn.read(&mut buf) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                let _ = eof_tx.send(());
            });
        }
    });
    let _ = h;
    (port, eof_rx)
}

fn start(dir: &std::path::Path, sock: &str, ports: &[(&str, &str)]) -> Proc {
    let mut cfg = CFG.to_string();
    for (k, v) in ports {
        cfg = cfg.replace(&format!("{{{k}}}"), v);
    }
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let bin =
        std::env::var("DELSRV_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(bin)
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::from(File::create(dir.join("proxy.err")).unwrap()))
        .spawn()
        .unwrap();
    Proc(child, dir.to_path_buf())
}

/// The `stot` column (8th) of the `show stat be_same 4 -1` row of `server`, `-1` if gone.
fn stot(out: &str, px: &str, server: &str) -> i64 {
    out.lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(',').collect();
            (f.len() > 7 && f[0] == px && f[1] == server)
                .then(|| f[7].parse::<i64>().unwrap_or(-1))
        })
        .unwrap_or(-2)
}

#[test]
fn del_server_branches() {
    let fe = common::reserve_addr();
    let li = common::reserve_addr();
    let (o1, c1) = count_origin("O1\n");
    let (o2, _c2) = count_origin("O2\n");
    let (o3, c3) = count_origin("O3\n");
    let (held, _ready) = held_origin();
    let keep = keepalive_origin().0;
    let dns = common::reserve_port();
    let dir = std::env::temp_dir().join(format!("delsrv-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let _p = start(
        &dir,
        &sock,
        &[
            ("sock", &sock),
            ("fe", &fe.to_string()),
            ("li", &li.to_string()),
            ("o1", &o1.to_string()),
            ("o2", &o2.to_string()),
            ("o3", &o3.to_string()),
            ("held", &held.to_string()),
            ("keep", &keep.to_string()),
            ("dns", &dns.to_string()),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }

    let mut bad: Vec<String> = Vec::new();
    macro_rules! check {
        ($what:expr, $got:expr, $want:expr) => {
            if $got != $want {
                bad.push(format!("{}: want {:?}, got {:?}", $what, $want, $got));
            }
        };
    }
    macro_rules! has {
        ($what:expr, $got:expr, $needle:expr) => {
            if !$got.contains($needle) {
                bad.push(format!("{}: {:?} missing from {:?}", $what, $needle, $got));
            }
        };
    }
    macro_rules! lacks {
        ($what:expr, $got:expr, $needle:expr) => {
            if $got.contains($needle) {
                bad.push(format!("{}: {:?} present in {:?}", $what, $needle, $got));
            }
        };
    }
    const REF: &str = "This server cannot be removed at runtime due to other configuration elements pointing to it.\n\n";

    // --- parse refusals, rows 2-5 ----------------------------------------
    check!("no slash", &cli(&sock, "del server"), "Require 'backend/server'.\n\n");
    check!("no server", &cli(&sock, "del server be"), "Require 'backend/server'.\n\n");
    check!("empty server name", &cli(&sock, "del server be/"), "Require 'backend/server'.\n\n");
    check!("no such backend", &cli(&sock, "del server nope/s1"), "No such backend.\n\n");
    check!("empty backend name", &cli(&sock, "del server /s1"), "No such backend.\n\n");
    check!("a frontend is not a backend", &cli(&sock, "del server fe/s1"), "No such backend.\n\n");
    check!("no such server", &cli(&sock, "del server be/nope"), "No such server.\n\n");
    // Row 1: below the admin level.
    check!("operator level", &cli(&sock, "operator; del server be/s2"), "\nPermission denied\n\n");

    // --- the "pointed to" refusals, rows 6-9: before and after disable ----
    check!("use-server target, running", &cli(&sock, "del server be/s3"), REF);
    check!("disable s3", &cli(&sock, "disable server be/s3"), "\n");
    check!("use-server target, disabled", &cli(&sock, "del server be/s3"), REF);
    check!("enable s3", &cli(&sock, "enable server be/s3"), "\n");
    check!("disable tracked t2", &cli(&sock, "disable server be_trk/t2"), "\n");
    check!("tracked target", &cli(&sock, "del server be_trk/t2"), REF);
    check!("enable t2", &cli(&sock, "enable server be_trk/t2"), "\n");
    check!("disable fetch f1", &cli(&sock, "disable server be_fetch/f1"), "\n");
    check!("fetch-named server", &cli(&sock, "del server be_fetch/f1"), REF);
    check!("enable f1", &cli(&sock, "enable server be_fetch/f1"), "\n");
    check!("disable resolvers r1", &cli(&sock, "disable server be_res/r1"), "\n");
    check!("resolvers server", &cli(&sock, "del server be_res/r1"), REF);
    check!("enable r1", &cli(&sock, "enable server be_res/r1"), "\n");

    // --- the maintenance refusal, rows 10/10b ------------------------------
    check!("not in maintenance", &cli(&sock, "del server be/s1"), "Only servers in maintenance mode can be deleted.\n\n");
    check!("extra words are ignored", &cli(&sock, "del server be/s2 extra"), "Only servers in maintenance mode can be deleted.\n\n");

    // --- the delete, row 12 ------------------------------------------------
    // s3 in maintenance, then s1: `be` balances s1 and s2.
    check!("disable s3", &cli(&sock, "disable server be/s3"), "\n");
    // `be` still serves before the delete (from s1 or s2; which one is round-robin's).
    has!("serves before the delete", &get(fe, "/", None), "O");
    check!("disable s1", &cli(&sock, "disable server be/s1"), "\n");
    check!("del s1", &cli(&sock, "del server be/s1"), "Server deleted.\n\n");

    // --- after the delete: every command says No such server ---------------
    check!("del again", &cli(&sock, "del server be/s1"), "No such server.\n\n");
    check!("enable", &cli(&sock, "enable server be/s1"), "No such server.\n\n");
    check!("disable", &cli(&sock, "disable server be/s1"), "No such server.\n\n");
    check!("set state", &cli(&sock, "set server be/s1 state ready"), "No such server.\n\n");
    check!("set weight", &cli(&sock, "set server be/s1 weight 10"), "No such server.\n\n");
    check!("get weight", &cli(&sock, "get weight be/s1"), "No such server.\n\n");
    check!("enable health", &cli(&sock, "enable health be/s1"), "No such server.\n\n");
    check!("disable health", &cli(&sock, "disable health be/s1"), "No such server.\n\n");
    check!("enable health no be", &cli(&sock, "enable health nope/s1"), "No such backend.\n\n");
    check!("disable health no be", &cli(&sock, "disable health nope/s1"), "No such backend.\n\n");
    check!("set addr", &cli(&sock, "set server be/s1 addr 127.0.0.1 port 28713"), "No such server.\n\n");
    check!("shutdown sessions", &cli(&sock, "shutdown sessions server be/s1"), "No such server.\n\n");
    check!("clear counters", &cli(&sock, "clear counters server be/s1"), "No such server.\n\n");
    let st = cli(&sock, "show servers state be");
    lacks!("servers state lists s1", &st, " s1 ");
    has!("servers state lists s2", &st, " 2 s2 ");
    has!("servers state lists s3", &st, " 3 s3 ");
    let stat = cli(&sock, "show stat be 4 -1");
    lacks!("show stat lists s1", &stat, "be,s1,");
    has!("show stat lists s2", &stat, "be,s2,");
    has!("show stat lists s3", &stat, "be,s3,");

    // --- traffic: none of the 20 reaches s1's (nor maint s3's) origin ------
    // Baseline taken now: only s2 is active, so none of the 20 may reach o1 or o3.
    let base1 = c1.load(Ordering::Relaxed);
    let base3 = c3.load(Ordering::Relaxed);
    let mut all_s2 = true;
    for _ in 0..20 {
        let r = get(fe, "/", None);
        if !r.contains("O2") || r.contains("O1") {
            all_s2 = false;
        }
    }
    if !all_s2 {
        bad.push("post-delete traffic: a request did not go to s2's origin".to_string());
    }
    assert_eq!(c1.load(Ordering::Relaxed), base1, "a request reached the deleted server's origin");
    assert_eq!(c3.load(Ordering::Relaxed), base3, "a request reached the maint s3's origin");

    // --- the persistence cookie, `option persist` ---------------------------
    let r = get(fe, "/ck", Some("SRV=k1"));
    has!("cookie k1 chooses k1", &r, "O1");
    // The cookie's own server answered: `HAProxy` keeps the client's cookie and writes
    // no `set-cookie`. It only re-inserts once that server is gone and another answers.
    lacks!("no set-cookie while k1 answers", &r.to_lowercase(), "set-cookie: srv=");
    check!("disable k1", &cli(&sock, "disable server be_ck/k1"), "\n");
    has!("persist keeps the disabled k1", &get(fe, "/ck", Some("SRV=k1")), "O1");
    check!("del k1", &cli(&sock, "del server be_ck/k1"), "Server deleted.\n\n");
    let r = get(fe, "/ck", Some("SRV=k1"));
    has!("the cookie is re-balanced to k2", &r, "O2");
    has!("k2's cookie re-inserted", &r.to_lowercase(), "set-cookie: srv=k2; path=/");

    // --- the stick table, `option persist` ----------------------------------
    let r = get(fe, "/stk", None);
    has!("stick goes to st1 first", &r, "O1");
    let t = cli(&sock, "show table be_stk");
    has!("stick table stores st1", &t, "server_id=1");
    has!("stick table stores st1's key", &t, "server_key=st1");
    has!("stick keeps st1", &get(fe, "/stk", None), "O1");
    check!("disable st1", &cli(&sock, "disable server be_stk/st1"), "\n");
    has!("persist keeps the disabled st1", &get(fe, "/stk", None), "O1");
    check!("del st1", &cli(&sock, "del server be_stk/st1"), "Server deleted.\n\n");
    has!("the stick table re-balances to st2", &get(fe, "/stk", None), "O2");
    let t = cli(&sock, "show table be_stk");
    has!("stick table re-stored on st2", &t, "server_id=2");
    has!("stick table re-stored on st2's key", &t, "server_key=st2");

    // --- two servers at one address -----------------------------------------
    check!("disable a1", &cli(&sock, "disable server be_same/a1"), "\n");
    check!("del a1", &cli(&sock, "del server be_same/a1"), "Server deleted.\n\n");
    for _ in 0..2 {
        has!("same address goes to a2", &get(fe, "/same", None), "O1");
    }
    let stat = cli(&sock, "show stat be_same 4 -1");
    lacks!("show stat lists a1", &stat, "be_same,a1,");
    check!("a2 counted both", stot(&stat, "be_same", "a2"), 2);

    // --- the other deletable rows: 12b, 12c, 7b, 12d -------------------------
    check!("disabled in the configuration", &cli(&sock, "del server be_dis/d1"), "Server deleted.\n\n");
    check!("disable tracker t1", &cli(&sock, "disable server be_trk/t1"), "\n");
    check!("del the tracker", &cli(&sock, "del server be_trk/t1"), "Server deleted.\n\n");
    check!("its target is still pointed to", &cli(&sock, "del server be_trk/t2"), REF);
    check!("disable li/l1", &cli(&sock, "disable server li/l1"), "\n");
    check!("del the listen's server", &cli(&sock, "del server li/l1"), "Server deleted.\n\n");
    check!("disable static-rr x1", &cli(&sock, "disable server be_static/x1"), "\n");
    check!("del the static-rr server", &cli(&sock, "del server be_static/x1"), "Server deleted.\n\n");

    // A health check of a deleted server must never run again: t1 (the tracker of t2,
    // itself checked) is gone; t2 still answers and the socket is alive. And a checked
    // server (ch1, `check inter 100ms`) that is deleted: its next step disables it.
    check!("disable ch1", &cli(&sock, "disable server be_chk/ch1"), "\n");
    check!("del checked ch1", &cli(&sock, "del server be_chk/ch1"), "Server deleted.\n\n");
    std::thread::sleep(Duration::from_millis(1500));
    let st = cli(&sock, "show servers state be_trk");
    lacks!("t1 is gone from be_trk", &st, " t1 ");
    has!("t2 still listed", &st, " t2 ");
    let st = cli(&sock, "show servers state be_chk");
    lacks!("ch1 is gone from be_chk", &st, " ch1 ");
    has!("ch2 still listed", &st, " ch2 ");

    if !bad.is_empty() {
        panic!("{} row(s) off:\n{}", bad.len(), bad.join("\n"));
    }
}

fn del_server_in_flight_and_keepalive() {
    let fe = common::reserve_addr();
    let li = common::reserve_addr();
    let (o1, _c1) = count_origin("O1\n");
    let (o2, _c2) = count_origin("O2\n");
    let (o3, _c3) = count_origin("O3\n");
    let (held, ready_rx) = held_origin();
    let (keep, ka_eof) = keepalive_origin();
    let dns = common::reserve_port();
    let dir = std::env::temp_dir().join(format!("delsrv-if-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let _p = start(
        &dir,
        &sock,
        &[
            ("sock", &sock),
            ("fe", &fe.to_string()),
            ("li", &li.to_string()),
            ("o1", &o1.to_string()),
            ("o2", &o2.to_string()),
            ("o3", &o3.to_string()),
            ("held", &held.to_string()),
            ("keep", &keep.to_string()),
            ("dns", &dns.to_string()),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }

    let mut bad: Vec<String> = Vec::new();
    macro_rules! check {
        ($what:expr, $got:expr, $want:expr) => {
            if $got != $want {
                bad.push(format!("{}: want {:?}, got {:?}", $what, $want, $got));
            }
        };
    }
    macro_rules! has {
        ($what:expr, $got:expr, $needle:expr) => {
            if !$got.contains($needle) {
                bad.push(format!("{}: {:?} missing from {:?}", $what, $needle, $got));
            }
        };
    }
    macro_rules! lacks {
        ($what:expr, $got:expr, $needle:expr) => {
            if $got.contains($needle) {
                bad.push(format!("{}: {:?} present in {:?}", $what, $needle, $got));
            }
        };
    }

    // w2 out of the way: every /slow stream sits on w1.
    check!("disable w2", &cli(&sock, "disable server be_slow/w2"), "\n");
    // Eight requests held on w1 at once, on more than one of the four workers.
    let mut clients = Vec::new();
    for _ in 0..8 {
        clients.push(std::thread::spawn(move || {
            let mut s = TcpStream::connect_timeout(&fe, Duration::from_secs(3)).expect("client");
            s.set_read_timeout(Some(Duration::from_secs(25)).into())
                .unwrap();
            let _ = s.write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            let mut out = Vec::new();
            let _ = s.read_to_end(&mut out);
            String::from_utf8_lossy(&out).into_owned()
        }));
    }
    let mut rels: Vec<mpsc::Sender<()>> = Vec::new();
    for _ in 0..8 {
        rels.push(ready_rx.recv_timeout(Duration::from_secs(5)).expect("a request never reached w1"));
    }

    // While the eight are held the proxy must still serve other backends.
    has!("alive while held", &get(fe, "/same", None), "200");
    // In maintenance, so the delete is asked; the held streams are what refuse it.
    check!("disable w1", &cli(&sock, "disable server be_slow/w1"), "\n");
    check!("in use", &cli(&sock, "del server be_slow/w1"), "Server still has connections attached to it, cannot remove it.\n\n");
    // The refused delete left w1 exactly as it was: still listed, still in maintenance.
    let st = cli(&sock, "show servers state be_slow");
    match st.lines().find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() > 6 && f[3] == "w1").then(|| (f[5].to_string(), f[6].to_string()))
    }) {
        Some((op, adm)) if op == "0" && adm == "1" => {}
        Some((op, adm)) => {
            bad.push(format!("w1 after the refusal: want op 0 admin 1, got op {op} admin {adm}"))
        }
        None => bad.push("w1 is not listed after the refusal".to_string()),
    }
    check!("enable w1", &cli(&sock, "enable server be_slow/w1"), "\n");
    check!("enabled is not maintenance", &cli(&sock, "del server be_slow/w1"), "Only servers in maintenance mode can be deleted.\n\n");
    check!("disable w1 again", &cli(&sock, "disable server be_slow/w1"), "\n");

    // Release seven of the eight; the held origin is whichever of `rels` stays, and it
    // may map to any of the eight clients (ready order is not the clients' order), so the
    // clients are only joined once every origin has been released.
    for _ in 0..7 {
        rels.pop().unwrap().send(()).unwrap();
    }
    // Let the seven released streams finish; the eighth still holds, so the delete is refused.
    std::thread::sleep(Duration::from_millis(500));
    check!("still one in use", &cli(&sock, "del server be_slow/w1"), "Server still has connections attached to it, cannot remove it.\n\n");

    // Release the last, wait for every answer, and delete.
    rels.pop().unwrap().send(()).unwrap();
    for h in clients.drain(..) {
        let r = h.join().expect("client");
        if !r.contains("200") || !r.contains("W1") {
            bad.push(format!("released request: want 200 W1, got {:?}", r));
        }
    }
    // The last stream ends a moment after its client reads the reply.
    std::thread::sleep(Duration::from_millis(300));
    check!("del now succeeds", &cli(&sock, "del server be_slow/w1"), "Server deleted.\n\n");
    let st = cli(&sock, "show servers state be_slow");
    lacks!("w1 is gone", &st, " w1 ");
    check!("del again", &cli(&sock, "del server be_slow/w1"), "No such server.\n\n");

    // --- the keep-alive server: the idle connection is closed, not counted --
    check!("disable ka2", &cli(&sock, "disable server be_ka/ka2"), "\n");
    // The request goes out without `Connection: close`. Once the answer is read the worker
    // parks the ka1 connection, then releases it idle into its pool; the client stays open so
    // the connection is not torn down with the session. The worker that owns the idle connection
    // closes it when the delete asks, and does not count it as a connection attached to the server.
    let (r, cli_conn) = get_keepalive(fe, "/ka");
    has!("ka1 answers", &r, "KA1");
    // Past the park release: the ka1 connection is now idle in the worker's pool.
    std::thread::sleep(Duration::from_millis(300));
    check!("disable ka1", &cli(&sock, "disable server be_ka/ka1"), "\n");
    check!("del over the idle connection", &cli(&sock, "del server be_ka/ka1"), "Server deleted.\n\n");
    if ka_eof.recv_timeout(Duration::from_secs(2)).is_err() {
        bad.push("ka1 idle connection was not closed (no EOF at origin)".to_string());
    }
    let st = cli(&sock, "show servers state be_ka");
    lacks!("ka1 is gone", &st, " ka1 ");
    drop(cli_conn);

    if !bad.is_empty() {
        panic!("{} row(s) off:\n{}", bad.len(), bad.join("\n"));
    }
}

#[test]
fn del_server_concurrent_busy() {
    let fe = common::reserve_addr();
    let li = common::reserve_addr();
    let (o1, _c1) = count_origin("O1\n");
    let (o2, _c2) = count_origin("O2\n");
    let (o3, _c3) = count_origin("O3\n");
    let (held, _ready_rx) = held_origin();
    let keep = keepalive_origin().0;
    let dns = common::reserve_port();
    let dir = std::env::temp_dir().join(format!("delsrv-conc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let _p = start(
        &dir,
        &sock,
        &[
            ("sock", &sock),
            ("fe", &fe.to_string()),
            ("li", &li.to_string()),
            ("o1", &o1.to_string()),
            ("o2", &o2.to_string()),
            ("o3", &o3.to_string()),
            ("held", &held.to_string()),
            ("keep", &keep.to_string()),
            ("dns", &dns.to_string()),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }

    assert_eq!(cli(&sock, "disable server be/s1"), "\n");
    assert_eq!(cli(&sock, "disable server be/s2"), "\n");

    let sock1 = sock.clone();
    let sock2 = sock.clone();
    let t1 = std::thread::spawn(move || cli(&sock1, "del server be/s1"));
    let t2 = std::thread::spawn(move || cli(&sock2, "del server be/s2"));
    let r1 = t1.join().expect("t1");
    let r2 = t2.join().expect("t2");

    for r in [&r1, &r2] {
        assert!(
            r == "Server deleted.\n\n" || r == "Another server deletion is in progress.\n\n",
            "unexpected concurrent del server answer: {r:?}"
        );
    }
    if r1 != "Server deleted.\n\n" {
        assert_eq!(cli(&sock, "del server be/s1"), "Server deleted.\n\n");
    }
    if r2 != "Server deleted.\n\n" {
        assert_eq!(cli(&sock, "del server be/s2"), "Server deleted.\n\n");
    }
}

#[test]
fn del_server_client_disconnect_mid_delete() {
    let fe = common::reserve_addr();
    let li = common::reserve_addr();
    let (o1, _c1) = count_origin("O1\n");
    let (o2, _c2) = count_origin("O2\n");
    let (o3, _c3) = count_origin("O3\n");
    let (held, _ready_rx) = held_origin();
    let keep = keepalive_origin().0;
    let dns = common::reserve_port();
    let dir = std::env::temp_dir().join(format!("delsrv-disc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let _p = start(
        &dir,
        &sock,
        &[
            ("sock", &sock),
            ("fe", &fe.to_string()),
            ("li", &li.to_string()),
            ("o1", &o1.to_string()),
            ("o2", &o2.to_string()),
            ("o3", &o3.to_string()),
            ("held", &held.to_string()),
            ("keep", &keep.to_string()),
            ("dns", &dns.to_string()),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }

    assert_eq!(cli(&sock, "disable server be/s1"), "\n");
    {
        let mut s = UnixStream::connect(&sock).unwrap();
        s.write_all(b"del server be/s1\n").unwrap();
        s.flush().unwrap();
    }
    std::thread::sleep(Duration::from_millis(200));

    let r = cli(&sock, "enable server be/s1");
    assert!(
        r == "\n" || r == "No such server.\n\n",
        "server stuck in RETIRING or unexpected answer after client disconnect: {r:?}"
    );
    if r == "\n" {
        assert_eq!(cli(&sock, "disable server be/s1"), "\n");
        assert_eq!(cli(&sock, "del server be/s1"), "Server deleted.\n\n");
    }
}
