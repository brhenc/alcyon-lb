// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! How a CLI connection ends: after its whole answer, and at `stats timeout` (T226).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-05:
//! - `echo "show sess" | socat -t2 - UNIX-CONNECT:...` sends the command and shuts its write
//!   side. HAProxy answers (its own CLI stream and the blank line). Ibex freed the
//!   connection on the EOF while the workers were still collecting their streams, and
//!   answered nothing: `show sess` counted 0 streams on devtest7 with 4,000 open.
//! - `show stat` for 2,000 servers, read after a 0.5 s pause: HAProxy sends 479,823 bytes,
//!   2,004 lines. Ibex sent the 219,264 bytes the socket buffer took and closed.
//! - `stats timeout 2s` and a connection that sends nothing, or a command without its
//!   newline: HAProxy closes it after 2.0 s. Ibex kept it open (6 s and more).

mod common;

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

struct Ibex {
    child: Child,
    sock: PathBuf,
    cfg: PathBuf,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
        let _ = std::fs::remove_file(&self.cfg);
    }
}

/// Ibex with a stats socket, `global_extra` in `global` and `rest` after the defaults.
fn start(global_extra: &str, rest: &str) -> Ibex {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    // A Unix socket path is at most 107 bytes: /tmp, not the target directory.
    let sock = PathBuf::from(format!("/tmp/ibex-cli-answer-{}-{n}.sock", std::process::id()));
    let cfg = std::env::temp_dir().join(format!("ibex-cli-answer-{}-{n}.cfg", std::process::id()));
    let fe = common::reserve_addr();
    let text = format!(
        "global\n  nbthread 4\n  stats socket {} level admin\n{global_extra}\
         defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n{rest}",
        sock.display()
    );
    std::fs::write(&cfg, text).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened");
    Ibex { child, sock, cfg }
}

fn read_all(c: &mut UnixStream) -> String {
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn show_sess_from_a_client_that_shut_its_write_side_is_answered() {
    let ibex = start("", "");
    let mut c = UnixStream::connect(&ibex.sock).expect("connect cli");
    c.write_all(b"show sess\n").expect("send");
    c.shutdown(Shutdown::Write).expect("shutdown");
    let out = read_all(&mut c);
    assert!(out.contains("fe=GLOBAL"), "no answer to show sess: {out:?}");
    assert!(out.ends_with("\n\n"), "answer not complete: {out:?}");
}

#[test]
fn an_answer_larger_than_the_socket_buffer_arrives_whole() {
    let servers: String = (0..2000).map(|i| format!("  server s{i} 127.0.0.1:9 disabled\n")).collect();
    let ibex = start("", &format!("  default_backend b\nbackend b\n{servers}"));
    let mut c = UnixStream::connect(&ibex.sock).expect("connect cli");
    c.write_all(b"show stat\n").expect("send");
    // The client reads late, as a slow reader or a full pipe would: the answer is queued.
    std::thread::sleep(Duration::from_millis(500));
    let out = read_all(&mut c);
    assert!(out.contains("\nb,s1999,"), "the last server is missing ({} bytes received)", out.len());
    assert!(out.contains("\nb,BACKEND,"), "the backend line is missing ({} bytes received)", out.len());
}

#[test]
fn an_idle_cli_connection_is_closed_at_stats_timeout() {
    let ibex = start("  stats timeout 1s\n", "");
    for sent in [&b""[..], b"show sess"] {
        let mut c = UnixStream::connect(&ibex.sock).expect("connect cli");
        c.write_all(sent).expect("send");
        let t0 = Instant::now();
        let out = read_all(&mut c);
        let took = t0.elapsed();
        assert!(out.is_empty(), "{out:?}");
        assert!(
            took < Duration::from_secs(3),
            "a connection that sent {sent:?} was open after {took:?}, stats timeout is 1s"
        );
    }
}

/// `stats timeout` was accepted and dropped whatever followed it. HAProxy's refusals, measured
/// with `haproxy -c` on the same lines.
#[test]
fn a_stats_timeout_that_is_not_a_positive_delay_is_refused() {
    for (arg, expected) in [
        ("", "'stats timeout' : unexpected character ''"),
        ("abc", "'stats timeout' : unexpected character 'a'"),
        ("-1s", "'stats timeout' : unexpected character '-'"),
        ("0", "'stats timeout' expects a positive value"),
    ] {
        let cfg = tempfile::NamedTempFile::new().expect("tmp");
        std::fs::write(cfg.path(), format!("global\n  stats timeout {arg}\n")).expect("write cfg");
        let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(cfg.path()).output().expect("run ibex -c");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "`stats timeout {arg}` was accepted");
        assert!(err.contains(expected), "`stats timeout {arg}`: {err}");
    }
}
