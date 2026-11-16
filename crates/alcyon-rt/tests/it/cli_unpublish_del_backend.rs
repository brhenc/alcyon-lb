// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `unpublish backend`, `publish backend`, `del backend` and `del server` on the stats socket.
//!
//! Every answer below was measured on `HAProxy` 3.5-dev8 (`ADB_ORACLE=<haproxy> runs this file
//! against it`). `del backend` refuses in `be_check_for_deletion`'s order -- unknown proxy,
//! `listen` section, stick-table, other configuration pointing at it, still published, still
//! holding a server -- and only deletes when all of them pass, which takes it out of
//! `show stat` and out of every lookup by name. `del server` needs the server in maintenance,
//! which is why `beta`'s is declared `disabled`. A backend that is unpublished is no target
//! for the switching rules: a request that would have gone there is answered 503 by the
//! frontend it stayed on, and `publish backend` puts it back.

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

backend alpha
  server a1 127.0.0.1:{origin}

backend beta
  server b1 127.0.0.1:{origin} disabled

backend gamma

backend delta
  stick-table type string len 8 size 10

backend keeper
  server k1 127.0.0.1:{origin}

listen mixed
  bind {lm}

frontend fe_ref
  bind {f1}
  use_backend alpha

frontend fe_keep
  bind {f2}
  default_backend keeper
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

/// `GET /` to `addr`: the whole reply.
fn get(addr: SocketAddr) -> String {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(4)).into())
        .unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// An origin that answers `200` with `ORIGIN`: what a request through `keeper` gets.
fn origin() -> (u16, std::thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("origin");
    let port = l.local_addr().expect("origin addr").port();
    let h = std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let mut buf = [0u8; 1024];
            let _ = c.read(&mut buf);
            let _ = c.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nORIGIN\n",
            );
            let _ = c.flush();
        }
    });
    (port, h)
}

#[test]
fn unpublish_then_del_backend() {
    let f1 = common::reserve_addr();
    let f2 = common::reserve_addr();
    let lm = common::reserve_addr();
    let (op, _h) = origin();
    let dir = std::env::temp_dir().join(format!("adb-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let cfg = CFG
        .replace("{sock}", &sock)
        .replace("{origin}", &op.to_string())
        .replace("{lm}", &lm.to_string())
        .replace("{f1}", &f1.to_string())
        .replace("{f2}", &f2.to_string());
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let bin =
        std::env::var("ADB_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(bin)
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _p = Proc(child, dir);
    assert!(common::wait_listening(f1), "no listener on fe_ref");
    assert!(common::wait_listening(f2), "no listener on fe_keep");
    assert!(common::wait_listening(lm), "no listener on mixed");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }

    let mut bad: Vec<String> = Vec::new();
    // Macros rather than closures: three of them cannot borrow `bad` at the same time.
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

    // A request that reaches `keeper` gets the origin's answer.
    let ok = get(f2);
    has!("request before unpublish", &ok, "ORIGIN");

    // The refusals, in `be_check_for_deletion`'s order.
    check!(
        "unknown backend",
        cli(&sock, "del backend nosuch"),
        "No such backend.\n\n"
    );
    check!(
        "a frontend is no backend",
        cli(&sock, "del backend fe_ref"),
        "No such backend.\n\n"
    );
    check!(
        "listen section",
        cli(&sock, "del backend mixed"),
        "Cannot delete a listen section.\n\n"
    );
    check!(
        "stick-table",
        cli(&sock, "del backend delta"),
        "Cannot remove a backend with stick-table.\n\n"
    );
    check!(
        "pointed at",
        cli(&sock, "del backend alpha"),
        "This proxy cannot be removed at runtime due to other configuration elements pointing to it.\n\n"
    );
    check!(
        "still published",
        cli(&sock, "del backend beta"),
        "Backend must be unpublished prior to its deletion.\n\n"
    );
    check!(
        "still published 2",
        cli(&sock, "del backend gamma"),
        "Backend must be unpublished prior to its deletion.\n\n"
    );

    // `unpublish backend` answers, marks the backend in `show stat`, and takes it out of the
    // switching rules: the request is answered 503 by the frontend it stayed on.
    check!(
        "unpublish keeper",
        cli(&sock, "unpublish backend keeper"),
        "Backend unpublished.\n\n"
    );
    has!(
        "unpub in show stat",
        &cli(&sock, "show stat keeper 2 -1"),
        "(UNPUB)"
    );
    let refused = get(f2);
    has!("503 after unpublish", &refused, " 503 ");
    has!(
        "503 body after unpublish",
        &refused,
        "No server is available to handle this request."
    );
    // ... and `publish backend` gives it back.
    check!(
        "publish keeper",
        cli(&sock, "publish backend keeper"),
        "Backend published.\n\n"
    );
    lacks!(
        "published again in show stat",
        &cli(&sock, "show stat keeper 2 -1"),
        "(UNPUB)"
    );
    has!("request after publish", &get(f2), "ORIGIN");

    check!(
        "unpublish unknown",
        cli(&sock, "unpublish backend nosuch"),
        "No such backend.\n\n"
    );
    check!(
        "publish unknown",
        cli(&sock, "publish backend nosuch"),
        "No such backend.\n\n"
    );
    check!(
        "unpublish a frontend",
        cli(&sock, "unpublish backend fe_ref"),
        "No such backend.\n\n"
    );

    // `del server` wants maintenance; `beta`'s server has it from `disabled`.
    check!(
        "del server not in maint",
        cli(&sock, "del server keeper/k1"),
        "Only servers in maintenance mode can be deleted.\n\n"
    );
    check!(
        "del server no slash",
        cli(&sock, "del server keeper"),
        "Require 'backend/server'.\n\n"
    );
    check!(
        "del server empty name",
        cli(&sock, "del server beta/"),
        "Require 'backend/server'.\n\n"
    );
    check!(
        "unpublish no name",
        cli(&sock, "unpublish backend  "),
        "No such backend.\n\n"
    );
    check!("unpublish bare", cli(&sock, "unpublish backend"), "No such backend.\n\n");
    check!("publish bare", cli(&sock, "publish backend"), "No such backend.\n\n");
    check!("del server bare", cli(&sock, "del server"), "Require 'backend/server'.\n\n");
    check!(
        "del server unknown server",
        cli(&sock, "del server delta/nope"),
        "No such server.\n\n"
    );
    check!(
        "del server unknown backend",
        cli(&sock, "del server nosuch/x"),
        "No such backend.\n\n"
    );

    check!(
        "unpublish beta",
        cli(&sock, "unpublish backend beta"),
        "Backend unpublished.\n\n"
    );
    check!(
        "beta still holds a server",
        cli(&sock, "del backend beta"),
        "Only a backend without server can be deleted.\n\n"
    );
    check!(
        "del server beta/b1",
        cli(&sock, "del server beta/b1"),
        "Server deleted.\n\n"
    );
    check!(
        "del server twice",
        cli(&sock, "del server beta/b1"),
        "No such server.\n\n"
    );
    check!(
        "del beta",
        cli(&sock, "del backend beta"),
        "Backend deleted.\n\n"
    );
    lacks!(
        "beta out of show stat",
        &cli(&sock, "show stat"),
        "beta,BACKEND,"
    );
    lacks!(
        "beta out of show backend",
        &cli(&sock, "show backend"),
        "\nbeta\n"
    );
    check!(
        "del beta twice",
        cli(&sock, "del backend beta"),
        "No such backend.\n\n"
    );
    check!(
        "unpublish beta after del",
        cli(&sock, "unpublish backend beta"),
        "No such backend.\n\n"
    );

    // A backend with no server at all goes the same way, and `show stat` stops listing it.
    check!(
        "unpublish gamma",
        cli(&sock, "unpublish backend gamma"),
        "Backend unpublished.\n\n"
    );
    check!(
        "del gamma",
        cli(&sock, "del backend gamma"),
        "Backend deleted.\n\n"
    );
    lacks!(
        "gamma out of show stat",
        &cli(&sock, "show stat"),
        "gamma,BACKEND,"
    );
    // The backends that were never deleted are still listed.
    has!(
        "alpha still listed",
        &cli(&sock, "show stat"),
        "alpha,BACKEND,"
    );
    has!(
        "keeper still listed",
        &cli(&sock, "show stat"),
        "keeper,BACKEND,"
    );
    // The `listen` can be unpublished as a backend, but never deleted.
    check!(
        "unpublish mixed",
        cli(&sock, "unpublish backend mixed"),
        "Backend unpublished.\n\n"
    );
    check!(
        "mixed still there",
        cli(&sock, "del backend mixed"),
        "Cannot delete a listen section.\n\n"
    );

    if !bad.is_empty() {
        panic!("{}\n{}", bad.len(), bad.join("\n"));
    }
}
