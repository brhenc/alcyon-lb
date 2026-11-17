// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `unpublish backend` and `publish backend` on the stats socket.
//!
//! Every answer below was measured on `HAProxy` 3.5-dev11 (`ADB_ORACLE=<haproxy>` runs this
//! file against it). `unpublish backend` answers, marks the backend in `show stat` with
//! `(UNPUB)`, and takes it out of the switching rules: a request that would have gone there
//! goes on to the next rule, then to the `default_backend`, and when none of those applies
//! the request is answered 503 by the frontend it stayed on. `publish backend` puts the
//! backend back, answering the same when it is already published. `del backend` and
//! `del server` live in their own slices.

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
  server a1 127.0.0.1:{oa}

backend keeper
  server k1 127.0.0.1:{ok}

listen mixed
  bind {lm}

frontend fe_ref
  bind {f1}
  use_backend alpha
  default_backend keeper

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

/// An origin that answers `200` with `body`.
fn origin(body: &str) -> (u16, std::thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("origin");
    let port = l.local_addr().expect("origin addr").port();
    let b = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let h = std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let mut buf = [0u8; 1024];
            let _ = c.read(&mut buf);
            let _ = c.write_all(b.as_bytes());
            let _ = c.flush();
        }
    });
    (port, h)
}

#[test]
fn unpublish_then_publish_backend() {
    let f1 = common::reserve_addr();
    let f2 = common::reserve_addr();
    let lm = common::reserve_addr();
    let (oa, _ha) = origin("ORIGIN-A\n");
    let (ok, _hk) = origin("ORIGIN-K\n");
    let dir = std::env::temp_dir().join(format!("adb-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let cfg = CFG
        .replace("{sock}", &sock)
        .replace("{oa}", &oa.to_string())
        .replace("{ok}", &ok.to_string())
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

    // Where the two frontends answer before anything is unpublished: `fe_ref` follows its
    // `use_backend`, `fe_keep` its `default_backend`.
    has!("fe_ref before unpublish", &get(f1), "ORIGIN-A");
    has!("fe_keep before unpublish", &get(f2), "ORIGIN-K");

    // The switching rules skip an unpublished backend and go on to the `default_backend`.
    check!(
        "unpublish alpha",
        cli(&sock, "unpublish backend alpha"),
        "Backend unpublished.\n\n"
    );
    has!(
        "alpha unpub in show stat",
        &cli(&sock, "show stat alpha 2 -1"),
        "UP (UNPUB)"
    );
    has!(
        "use_backend to an unpublished backend goes to the default",
        &get(f1),
        "ORIGIN-K"
    );
    // ... and `publish backend` gives it back; answering again on an already-published
    // backend answers the same.
    check!(
        "publish alpha",
        cli(&sock, "publish backend alpha"),
        "Backend published.\n\n"
    );
    check!(
        "publish alpha twice in a row",
        cli(&sock, "publish backend alpha"),
        "Backend published.\n\n"
    );
    lacks!(
        "alpha published in show stat",
        &cli(&sock, "show stat alpha 2 -1"),
        "(UNPUB)"
    );
    has!(
        "use_backend back to the published backend",
        &get(f1),
        "ORIGIN-A"
    );

    // When nothing else can take the request, the frontend answers 503 itself.
    check!(
        "unpublish keeper",
        cli(&sock, "unpublish backend keeper"),
        "Backend unpublished.\n\n"
    );
    has!(
        "keeper unpub in show stat",
        &cli(&sock, "show stat keeper 2 -1"),
        "UP (UNPUB)"
    );
    let refused = get(f2);
    has!("503 after unpublish", &refused, " 503 ");
    has!(
        "503 body after unpublish",
        &refused,
        "No server is available to handle this request."
    );
    check!(
        "publish keeper",
        cli(&sock, "publish backend keeper"),
        "Backend published.\n\n"
    );
    lacks!(
        "keeper published in show stat",
        &cli(&sock, "show stat keeper 2 -1"),
        "(UNPUB)"
    );
    has!("request after publish", &get(f2), "ORIGIN-K");

    // Unknown names, and things that are not backends.
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
    check!(
        "publish a frontend",
        cli(&sock, "publish backend fe_ref"),
        "No such backend.\n\n"
    );
    check!(
        "unpublish no name",
        cli(&sock, "unpublish backend  "),
        "No such backend.\n\n"
    );
    check!("unpublish bare", cli(&sock, "unpublish backend"), "No such backend.\n\n");
    check!("publish bare", cli(&sock, "publish backend"), "No such backend.\n\n");

    // A `listen` section is a backend too: it can be unpublished, and `show stat` spells
    // the mark on its backend line.
    check!(
        "unpublish mixed",
        cli(&sock, "unpublish backend mixed"),
        "Backend unpublished.\n\n"
    );
    has!(
        "mixed unpub in show stat",
        &cli(&sock, "show stat mixed 2 -1"),
        "UP (UNPUB)"
    );
    check!(
        "publish mixed",
        cli(&sock, "publish backend mixed"),
        "Backend published.\n\n"
    );
    lacks!(
        "mixed published in show stat",
        &cli(&sock, "show stat mixed 2 -1"),
        "(UNPUB)"
    );

    if !bad.is_empty() {
        panic!("{}\n{}", bad.len(), bad.join("\n"));
    }
}
