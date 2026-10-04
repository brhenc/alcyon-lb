// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `global maxconn` is enforced, and `set maxconn global` changes it (T146 item 3).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` (`nbthread 1`, `maxconn 4`, an idle client
//! connection each, a request sent on each afterwards):
//!
//! * `set maxconn global 2` answers an empty line; `show info` then says `Maxconn: 2`,
//!   `Hard_maxconn: 4`;
//! * with the limit at 2 the first two connections are answered and the third waits (it is
//!   in the backlog, `CurrConns` stays 2); the stats socket is not counted;
//! * `set maxconn global 0` goes back to the configured 4, and the waiting connection is
//!   then served; `set maxconn global 9` is `Value out of range.`; no argument is
//!   `Expects an integer value.`.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

struct Ibex {
    child: Child,
    sock: PathBuf,
    dir: PathBuf,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn backend() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 || c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn start(maxconn: u32) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("ibex_t146mc_{}_{}", std::process::id(), fe.port()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sock = dir.join("s.sock");
    let cfg = format!(
        "global\n  nbthread 1\n  maxconn {maxconn}\n  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout client 5s\n  timeout connect 1s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  default_backend be\nbackend be\n  server s {}\n",
        sock.display(),
        backend()
    );
    std::fs::write(dir.join("cfg"), cfg).expect("cfg");
    let child =
        Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(dir.join("cfg")).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let ibex = Ibex { child, sock, dir };
    assert!(common::wait_listening(fe));
    (ibex, fe)
}

fn cli(sock: &Path, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn info(sock: &Path, key: &str) -> String {
    cli(sock, "show info")
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{key}: ")).map(str::to_string))
        .unwrap_or_default()
}

/// Sends a request on `c` and says whether the answer comes within 500 ms.
fn answered(c: &mut TcpStream) -> bool {
    c.set_read_timeout(Some(Duration::from_millis(500))).expect("timeout");
    let _ = c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    let mut b = [0u8; 12];
    c.read(&mut b).is_ok_and(|n| n > 0)
}

#[test]
fn the_limit_stops_accepting_until_it_is_raised() {
    let (ibex, fe) = start(4);
    assert_eq!((info(&ibex.sock, "Maxconn"), info(&ibex.sock, "Hard_maxconn")), ("4".into(), "4".into()));
    assert_eq!(cli(&ibex.sock, "set maxconn global 2"), "\n");
    assert_eq!((info(&ibex.sock, "Maxconn"), info(&ibex.sock, "Hard_maxconn")), ("2".into(), "4".into()));

    let mut conns = Vec::new();
    for _ in 0..3 {
        conns.push(TcpStream::connect(fe).expect("connect"));
        thread::sleep(Duration::from_millis(200));
    }
    let got: Vec<bool> = conns.iter_mut().map(answered).collect();
    assert_eq!(got, [true, true, false], "the third connection must wait");
    assert_eq!(info(&ibex.sock, "CurrConns"), "2");

    assert_eq!(cli(&ibex.sock, "set maxconn global 0"), "\n");
    assert_eq!(info(&ibex.sock, "Maxconn"), "4");
    thread::sleep(Duration::from_millis(300));
    let mut b = [0u8; 12];
    conns[2].set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    assert!(conns[2].read(&mut b).is_ok_and(|n| n > 0), "the waiting connection is served once the limit is back to 4");
}

#[test]
fn a_closed_connection_lets_the_next_one_in() {
    let (ibex, fe) = start(1);
    let mut first = TcpStream::connect(fe).expect("connect");
    assert!(answered(&mut first));
    let mut second = TcpStream::connect(fe).expect("connect");
    assert!(!answered(&mut second), "the limit is 1");
    drop(first);
    let mut b = [0u8; 12];
    second.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    assert!(second.read(&mut b).is_ok_and(|n| n > 0), "closing the first must admit the second");
    drop(ibex);
}

#[test]
fn set_maxconn_global_is_checked_like_haproxy() {
    let (ibex, _fe) = start(4);
    assert_eq!(cli(&ibex.sock, "set maxconn global 9"), "Value out of range.\n\n");
    assert_eq!(cli(&ibex.sock, "set maxconn global"), "Expects an integer value.\n\n");
    assert_eq!(cli(&ibex.sock, "set maxconn global x"), "\n");
    assert_eq!(info(&ibex.sock, "Maxconn"), "4");
}
