// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `set server <b>/<s> name <new>` on the stats socket: every refusal in HAProxy's order and
//! words (`srv_update_server_name`, `server.c`), then a rename that `show servers state`,
//! `show stat` and the other server commands see (`SRVNAME_ORACLE=<haproxy>` runs it on HAProxy).

use crate::common;

use std::io::{Read, Write};
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
backend pool
  server alpha 127.0.0.1:1
  server beta 127.0.0.1:1
backend pinned
  server alpha 127.0.0.1:1
  server beta 127.0.0.1:1
  use-server alpha if { always_true }
backend chain
  server head 127.0.0.1:1 check disabled
  server tail 127.0.0.1:1 track chain/head
backend refs
  http-request set-var(txn.b) srv_is_up(bare)
  server byvar 127.0.0.1:1
  server byacl 127.0.0.1:1
  server byfmt 127.0.0.1:1
  server bare 127.0.0.1:1
  server free 127.0.0.1:1
frontend f
  bind {f}
  http-request set-var(txn.a) srv_is_up(refs/byvar)
  http-request deny if { srv_conn(refs/byacl) -m int 99 }
  http-request set-header x-w %[srv_weight(refs/byfmt)]
  default_backend pool
"####;

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn set_server_name() {
    let f = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("ssn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    std::fs::write(&path, CFG.replace("{sock}", &sock).replace("{f}", &f.to_string())).unwrap();
    let bin = std::env::var("SRVNAME_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(bin).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _p = Proc(child, dir);
    assert!(common::wait_listening(f), "no listener");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    let c = |cmd: &str| cli(&sock, cmd);
    assert_eq!(c("set server pool/alpha name"), "set server <b>/<s> name requires a new name.\n\n");
    assert_eq!(c("set server pool/alpha name gamma"), "Server must be in maintenance mode to be renamed (set server <b>/<s> state maint).\n\n");
    c("disable server pool/alpha");
    assert_eq!(c("set server pool/alpha name bad/name"), "Server name contains invalid characters.\n\n");
    assert_eq!(c(&format!("set server pool/alpha name {}", "x".repeat(64))), "Server name too long.\n\n");
    assert_eq!(c("set server pool/alpha name beta"), "A server with the same name already exists in this backend.\n\n");
    let refd = "Cannot rename: server's name is statically referenced (use-server, track, or sample argument).\n\n";
    c("disable server pinned/alpha");
    assert_eq!(c("set server pinned/alpha name gamma"), refd);
    c("disable server chain/head");
    assert_eq!(c("set server chain/head name gamma"), refd);
    // A sample fetch's server argument (`ARGT_SRV`) references the name too, wherever the
    // expression is written: a rule's sample, an ACL, a `%[...]`, and a bare name in its own
    // backend. Alcyon's `srv_*` fetches look the server up by name, so a rename would leave
    // them reading nothing. Measured on HAProxy 3.5-dev8-885761-29, 2026-11-15.
    for s in ["byvar", "byacl", "byfmt", "bare"] {
        c(&format!("disable server refs/{s}"));
        assert_eq!(c(&format!("set server refs/{s} name {s}2")), refd, "refs/{s} is named by a sample fetch");
    }
    c("disable server refs/free");
    assert_eq!(c("set server refs/free name free2"), "Server name updated.\n\n", "refs/free is named by nothing");
    // The longest name taken is 63 characters (64 is refused above).
    let long = "y".repeat(63);
    assert_eq!(c(&format!("set server pool/alpha name {long}")), "Server name updated.\n\n");
    assert_eq!(c(&format!("set server pool/{long} name alpha")), "Server name updated.\n\n");
    assert_eq!(c("set server pool/alpha name alpha"), "Server name updated.\n\n");
    assert_eq!(c("set server pool/alpha name gamma"), "Server name updated.\n\n");
    assert!(c("show servers state pool").contains("pool 1 gamma "));
    assert!(c("show stat").contains("\npool,gamma,"));
    assert!(!c("show stat").contains("\npool,alpha,"));
    assert_eq!(c("set server pool/alpha state ready"), "No such server.\n\n");
    assert_eq!(c("set server pool/gamma state ready"), "\n");
    assert_eq!(c("disable server pool/gamma"), "\n");
}

/// A server answering one 200 per connection, until the test ends.
fn answering_server() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind server");
    let addr = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        }
    });
    addr
}

/// What a rename leaves behind: `HAProxy`'s notice on stderr (`ha_notice` in
/// `srv_update_server_name`, none for a rename to the same name), and the new name in the
/// log line of a request the server then answers (`%s`). Measured on `HAProxy`
/// 3.5-dev8-885761-29, 2026-11-15.
#[test]
fn a_rename_is_noticed() {
    let (f, srv) = (common::reserve_addr(), answering_server());
    let collector = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind collector");
    collector.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let coll = collector.local_addr().unwrap();
    let dir = std::env::temp_dir().join(format!("ssn2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    let cfg = format!(
        "global\n  stats socket {sock} mode 600 level admin\ndefaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  \
         timeout connect 5s\nfrontend f\n  bind {f}\n  log {coll} local0\n  log-format \"srv=%s\"\n  default_backend pool\nbackend pool\n  server alpha {srv}\n"
    );
    std::fs::write(&path, cfg).unwrap();
    let stderr = std::fs::File::create(dir.join("stderr")).unwrap();
    let bin = std::env::var("SRVNAME_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(bin).arg("-f").arg(&path).stdout(Stdio::null()).stderr(stderr).spawn().unwrap();
    let mut p = Proc(child, dir.clone());
    assert!(common::wait_listening(f), "no listener");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    let c = |cmd: &str| cli(&sock, cmd);
    c("disable server pool/alpha");
    assert_eq!(c("set server pool/alpha name alpha"), "Server name updated.\n\n");
    assert_eq!(c("set server pool/alpha name gamma"), "Server name updated.\n\n");
    assert_eq!(c("set server pool/gamma state ready"), "\n");
    let mut conn = std::net::TcpStream::connect(f).expect("connect f");
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.write_all(b"GET / HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n").unwrap();
    let mut resp = String::new();
    let _ = conn.read_to_string(&mut resp);
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp:?}");
    // `wait_listening`'s probe connection logs first, with no server (`srv=<NOSRV>`).
    let line = loop {
        let mut buf = [0u8; 1024];
        let n = collector.recv(&mut buf).expect("the request's log line");
        let line = String::from_utf8_lossy(&buf[..n]).trim_end().to_string();
        if !line.ends_with("srv=<NOSRV>") {
            break line;
        }
    };
    assert!(line.ends_with("srv=gamma"), "the log line names the server by its new name: {line:?}");
    common::stop(&mut p.0);
    let err = std::fs::read_to_string(dir.join("stderr")).unwrap();
    let notices: Vec<&str> = err.lines().filter(|l| l.contains("renamed")).collect();
    assert_eq!(notices.len(), 1, "one notice, none for the rename to the same name: {err:?}");
    assert!(notices[0].starts_with("[NOTICE]   ("), "{:?}", notices[0]);
    assert!(notices[0].ends_with(") : Server pool/gamma renamed from 'alpha'."), "{:?}", notices[0]);
}
