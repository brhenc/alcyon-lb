// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A non-interactive stats-socket connection runs one command line and closes (T146 item 4).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29`, whatever the way the lines arrive (one write
//! of two lines, two writes, a `quit` first):
//!
//! * `show cli level\nshow cli level\n` answers `admin\n\n` once, then the connection is
//!   closed: the second line is not run;
//! * the lines of a `;` list are all run: `show version;show cli level` answers both;
//! * after `prompt` the connection stays open and every line is answered, each followed by
//!   `\n> `.
//!
//! This is why vtest opens a new connection for every `send`, and so does the runner.

mod common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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

fn start() -> Ibex {
    let fe = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("ibex_t146cli_{}_{}", std::process::id(), fe.port()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sock = dir.join("s.sock");
    let cfg = format!(
        "global\n  stats socket {} level admin\ndefaults\n  mode http\n  timeout client 5s\n  timeout connect 1s\n  timeout server 5s\n\
         frontend f\n  bind {}\n  http-request return status 200\n",
        sock.display(),
        fe
    );
    std::fs::write(dir.join("cfg"), cfg).expect("cfg");
    let child =
        Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(dir.join("cfg")).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let end = Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(&sock).is_err() {
        assert!(Instant::now() < end, "the stats socket never came up");
        std::thread::sleep(Duration::from_millis(50));
    }
    Ibex { child, sock, dir }
}

/// Writes `chunks` one after the other, and returns what came back until EOF or 1 s of
/// silence, with whether the server closed.
fn talk(ibex: &Ibex, chunks: &[&str]) -> (String, bool) {
    let mut s = UnixStream::connect(&ibex.sock).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(400))).expect("timeout");
    let mut out = Vec::new();
    let mut closed = false;
    for c in chunks {
        let _ = s.write_all(c.as_bytes());
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf) {
                Ok(0) => {
                    closed = true;
                    break;
                }
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        if closed {
            break;
        }
    }
    (String::from_utf8_lossy(&out).into_owned(), closed)
}

#[test]
fn only_the_first_line_runs_and_the_connection_closes() {
    let ibex = start();
    assert_eq!(talk(&ibex, &["show cli level\nshow cli level\n"]), ("admin\n\n".into(), true), "two lines in one write");
    assert_eq!(talk(&ibex, &["show cli level\n", "show cli level\n"]), ("admin\n\n".into(), true), "two writes");
    assert_eq!(talk(&ibex, &["show cli level\nquit\nshow cli level\n"]), ("admin\n\n".into(), true), "a line after quit");
}

#[test]
fn a_semicolon_list_is_one_line() {
    let ibex = start();
    assert_eq!(talk(&ibex, &["show cli level;show cli level\n"]), ("admin\n\nadmin\n\n".into(), true));
}

#[test]
fn after_prompt_every_line_is_answered() {
    let ibex = start();
    let (out, closed) = talk(&ibex, &["prompt\n", "show cli level\n", "show cli level\n"]);
    assert_eq!((out.as_str(), closed), ("\n> admin\n\n> admin\n\n> ", false));
}
