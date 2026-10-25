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

/// `show pools` output.
fn pools(p: &Proxy) -> String {
    let mut s = UnixStream::connect(&p.sock).expect("cli");
    s.write_all(b"show pools\n").expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// (blocks, bytes, users) of the quarantine's line, `None` when there is none.
fn quarantine_line(out: &str) -> Option<(u64, u64, u64)> {
    let l = out.lines().find(|l| l.starts_with("  - Pool zero_quarantine "))?;
    let num = |after: &str, before: &str| -> u64 {
        let r = l.split_once(after).expect(after).1;
        r.split(before).next().expect(before).trim().parse().expect("number")
    };
    Some((num(": ", " allocated"), num("allocated (", " bytes)"), num("failures, ", " users")))
}

#[test]
fn soft_lists_the_quarantine_in_show_pools_and_counts_it_in_total() {
    let p = start("\ttune.ibex.zero-on-free soft\n");
    let deadline = Instant::now() + Duration::from_secs(10);
    // Blocks wait only across busy passes (an idle pass empties the quarantine before it
    // publishes), so keep the proxy busy while looking.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let port = p.port;
    let loaders: Vec<_> = (0..2)
        .map(|_| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    get(port);
                }
            })
        })
        .collect();
    let out = loop {
        let out = pools(&p);
        if quarantine_line(&out).is_some_and(|(b, _, _)| b > 0) || Instant::now() > deadline {
            break out;
        }
    };
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for l in loaders {
        l.join().expect("loader");
    }
    let (blocks, bytes, users) = quarantine_line(&out).unwrap_or_else(|| panic!("no quarantine line in show pools:\n{out}"));
    assert!(blocks > 0 && bytes > 0, "nothing counted:\n{out}");
    assert_eq!(users, 1);
    let total = out.lines().find(|l| l.starts_with("Total: ")).expect("Total");
    let allocated: u64 = total.split(", ").nth(1).and_then(|s| s.split(' ').next()).and_then(|s| s.parse().ok()).expect("total bytes");
    assert!(allocated >= bytes, "Total ({allocated}) leaves out the quarantine ({bytes}):\n{out}");
    // Idle: the passes empty it.
    std::thread::sleep(Duration::from_millis(400));
    let (_, bytes, _) = quarantine_line(&pools(&p)).expect("line stays with soft");
    assert!(bytes < 64 * 1024, "{bytes} bytes still waiting while idle");
}

#[test]
fn off_and_hard_list_no_quarantine_in_show_pools() {
    for g in ["", "\ttune.ibex.zero-on-free hard\n"] {
        let p = start(g);
        get(p.port);
        let out = pools(&p);
        assert!(out.contains("Dumping pools usage"), "{out}");
        assert_eq!(quarantine_line(&out), None, "{g:?}:\n{out}");
    }
}
