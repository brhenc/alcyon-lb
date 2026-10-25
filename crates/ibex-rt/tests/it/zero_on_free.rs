// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.ibex.zero-on-free off|soft|hard` (T459) reaches the `ibex` binary's allocator: after a
//! few connections, `show info` counts the blocks wiped on their free (`hard`) or put in a
//! quarantine (`soft`), and leaves the Ibex-only lines out with `off`, as `HAProxy` 3.5-dev8 (which
//! has no such setting: its `-dM` options poison pool objects for debugging, `docs/differences.md`).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::common;

struct Proxy {
    child: Child,
    port: u16,
    sock: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn start(global: &str) -> Proxy {
    let dir = tempfile::TempDir::new().expect("dir");
    let cfg = dir.path().join("c.cfg");
    let sock = dir.path().join("s.sock");
    let port = common::reserve_port();
    std::fs::write(
        &cfg,
        format!(
            "global\n\tnbthread 1\n\tstats socket {}\n{global}\
             defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 5s\n\ttimeout server 5s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\thttp-request return status 200 content-type text/plain string ok\n",
            sock.display()
        ),
    )
    .expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).arg("-db").stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    assert!(common::wait_listening(([127, 0, 0, 1], port).into()), "the proxy never listened on {port}");
    Proxy { child, port, sock, _dir: dir }
}

fn get(port: u16) {
    let mut c = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).ok();
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    assert!(got.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&got));
}

/// `show info`'s value for `name`, or `None` when the line is not there.
fn info(p: &Proxy, name: &str) -> Option<String> {
    let mut s = UnixStream::connect(&p.sock).expect("cli");
    s.write_all(b"show info\n").expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out.lines().find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix(": ")).map(str::to_string))
}

/// Waits (the figures are published every 10 ms) until `name` is a number above 0.
fn counted(p: &Proxy, name: &str) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let n = info(p, name).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        if n > 0 || Instant::now() > deadline {
            return n;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn hard_wipes_what_the_connections_free() {
    let p = start("\ttune.ibex.zero-on-free hard\n");
    for _ in 0..20 {
        get(p.port);
    }
    assert_eq!(info(&p, "ZeroOnFree").as_deref(), Some("hard"));
    assert!(counted(&p, "ZeroOnFreeWiped") > 0, "the binary's allocator wiped nothing");
    assert_eq!(info(&p, "ZeroOnFreeQueued").as_deref(), Some("0"));
}

#[test]
fn soft_quarantines_what_the_connections_free_and_empties_it_when_idle() {
    let p = start("\ttune.ibex.zero-on-free soft\n");
    for _ in 0..20 {
        get(p.port);
    }
    assert_eq!(info(&p, "ZeroOnFree").as_deref(), Some("soft"));
    assert!(counted(&p, "ZeroOnFreeQueued") > 0, "nothing went into the quarantine");
    // Idle: the passes empty it (the CLI's own frees come and go).
    std::thread::sleep(Duration::from_millis(300));
    let bytes: u64 = info(&p, "ZeroOnFreeBytes").and_then(|v| v.parse().ok()).expect("ZeroOnFreeBytes");
    assert!(bytes < 64 * 1024, "{bytes} bytes still waiting while idle");
    let oldest: u64 = info(&p, "ZeroOnFreeOldest_ms").and_then(|v| v.parse().ok()).expect("ZeroOnFreeOldest_ms");
    assert!(oldest <= 200, "a block waited {oldest} ms");
    for f in ["ZeroOnFreeBlocks", "ZeroOnFreeForced", "ZeroOnFreeExpired", "ZeroOnFreeWiped"] {
        assert!(info(&p, f).is_some_and(|v| v.parse::<u64>().is_ok()), "{f}");
    }
}

#[test]
fn off_shows_no_ibex_lines() {
    let p = start("");
    get(p.port);
    assert!(info(&p, "Uptime_sec").is_some());
    assert_eq!(info(&p, "ZeroOnFree"), None);
}
