// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T207: keywords Ibex used to parse and drop must either act or be refused.
//!
//! Measured on HAProxy 3.5-dev8-885761-29 (`ss -tlnie`, and a raw backend timestamping the
//! checks): `backlog 7` is Send-Q 7, `v6only` / `v4v6` are `v6only:1` / `v6only:0`,
//! `cc reno` shows `reno`; with `inter 1000ms fastinter 200ms downinter 300ms fall 3
//! rise 2` the gaps between checks are 200 (first gap only), 1000, 1000, 1000, then (first
//! failure) 200, 200, and 300 from the third failure, which marks the server DOWN.

use crate::common;

use ibex_config::ast::SocketTuning;
use ibex_rt::listener::Listener;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn spawn(cfg: &str) -> (common::Ibex, NamedTempFile) {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Ibex)
        .expect("spawn");
    (child, f)
}

const DEFAULTS: &str = "defaults\n  mode tcp\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n";

/// `ss -tlnie` lines for the listening sockets on `port`, each with the line that follows.
fn ss_lines(port: u16) -> Vec<String> {
    let out = Command::new("ss").args(["-tlnie"]).output().expect("ss");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let lines: Vec<&str> = text.lines().collect();
    let mut found = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if l.starts_with("LISTEN") && l.split_whitespace().nth(3).is_some_and(|a| a.ends_with(&format!(":{port}"))) {
            found.push(format!("{l} {}", lines.get(i + 1).unwrap_or(&"")));
        }
    }
    found
}

fn send_q(line: &str) -> u32 {
    line.split_whitespace().nth(2).and_then(|v| v.parse().ok()).expect("send-q")
}

#[test]
fn bind_backlog_is_the_listen_backlog() {
    let (a, b) = (common::reserve_addr(), common::reserve_addr());
    let cfg = format!("{DEFAULTS}frontend fe\n  bind {a} backlog 7\n  bind {b}\n  default_backend be\nbackend be\n  server s 127.0.0.1:9\n");
    let (mut child, _f) = spawn(&cfg);
    assert!(common::wait_listening(a));
    let (la, lb) = (ss_lines(a.port()), ss_lines(b.port()));
    common::stop(&mut child);
    assert!(!la.is_empty() && la.iter().all(|l| send_q(l) == 7), "{la:?}");
    assert!(!lb.is_empty() && lb.iter().all(|l| send_q(l) != 7), "{lb:?}");
}

#[test]
fn v6only_and_v4v6_set_ipv6_v6only() {
    let (p6, p46) = (common::reserve_port(), common::reserve_port());
    let cfg = format!(
        "{DEFAULTS}frontend fe\n  bind [::]:{p6} v6only\n  bind [::]:{p46} v4v6\n  default_backend be\nbackend be\n  server s 127.0.0.1:9\n"
    );
    let (mut child, _f) = spawn(&cfg);
    assert!(common::wait_listening(SocketAddr::from(([127, 0, 0, 1], p46))));
    let (l6, l46) = (ss_lines(p6), ss_lines(p46));
    common::stop(&mut child);
    assert!(!l6.is_empty() && l6.iter().all(|l| l.contains("v6only:1")), "{l6:?}");
    assert!(!l46.is_empty() && l46.iter().all(|l| l.contains("v6only:0")), "{l46:?}");
}

#[test]
fn cc_sets_the_congestion_control() {
    let allowed = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_allowed_congestion_control").unwrap_or_default();
    if !allowed.contains("reno") {
        return;
    }
    let a = common::reserve_addr();
    let cfg = format!("{DEFAULTS}frontend fe\n  bind {a} cc reno\n  default_backend be\nbackend be\n  server s 127.0.0.1:9\n");
    let (mut child, _f) = spawn(&cfg);
    assert!(common::wait_listening(a));
    let l = ss_lines(a.port());
    common::stop(&mut child);
    assert!(!l.is_empty() && l.iter().all(|l| l.contains("reno")), "{l:?}");
}

/// `tcp-ut` is not shown by `ss`: read it back from the socket `Listener` opens, the one
/// the engine opens for a bind line.
#[test]
fn tcp_ut_reaches_the_listening_socket() {
    let a = common::reserve_addr();
    let tuning = SocketTuning { tcp_user_timeout: Some(Duration::from_millis(4321)), ..SocketTuning::default() };
    let l = Listener::bind_tuned(a, 128, 0, &tuning).expect("bind");
    assert_eq!(rustix::net::sockopt::get_tcp_user_timeout(l.borrowed_fd()).expect("get"), 4321);
    let plain = Listener::bind(common::reserve_addr(), 128, 0).expect("bind");
    assert_eq!(rustix::net::sockopt::get_tcp_user_timeout(plain.borrowed_fd()).expect("get"), 0);
}

/// T209: `mss` is `TCP_MAXSEG` on the listening socket (HAProxy: `setsockopt(TCP_MAXSEG, [1200])`).
/// Read back from the socket `Listener` opens for a bind line.
#[test]
fn mss_reaches_the_listening_socket() {
    use nix::sys::socket::{getsockopt, sockopt::TcpMaxSeg};
    let tuning = SocketTuning { mss: Some(1200), ..SocketTuning::default() };
    let l = Listener::bind_tuned(common::reserve_addr(), 128, 0, &tuning).expect("bind");
    assert_eq!(getsockopt(&l.borrowed_fd(), TcpMaxSeg).expect("get"), 1200);
    let plain = Listener::bind(common::reserve_addr(), 128, 0).expect("bind");
    assert_ne!(getsockopt(&plain.borrowed_fd(), TcpMaxSeg).expect("get"), 1200);
}

/// `setsockopt` calls (as strace prints them) made by an Ibex running `cfg` while one
/// client connection to `probe` is served.
fn strace_setsockopt(cfg: &str, probe: SocketAddr) -> String {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let log = NamedTempFile::new().expect("tmp");
    let mut child = Command::new("strace")
        .args(["-f", "-e", "trace=setsockopt,connect", "-o"])
        .arg(log.path())
        .arg(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn strace");
    assert!(common::wait_listening(probe));
    if let Ok(mut c) = std::net::TcpStream::connect(probe) {
        let _ = c.write_all(b"x");
        // The options of the connecting socket are set before its `connect`: wait for the
        // connect to the server to show in the log (strace writes as it goes), not for a
        // fixed time that a loaded host overruns.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while std::time::Instant::now() < deadline && !std::fs::read_to_string(log.path()).unwrap_or_default().contains("connect(") {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    // SIGUSR1 goes to ibex, not strace: find it as strace's child.
    let kids = std::fs::read_to_string(format!("/proc/{0}/task/{0}/children", child.id())).unwrap_or_default();
    let ibex_pid: i32 = kids.split_whitespace().next().and_then(|p| p.parse().ok()).expect("ibex pid");
    let _ = Command::new("kill").args(["-USR1", &ibex_pid.to_string()]).status();
    let _ = child.wait();
    std::fs::read_to_string(log.path()).unwrap_or_default()
}

#[test]
fn bind_mss_is_set_by_the_engine_listener() {
    if Command::new("strace").arg("-V").output().is_err() {
        return;
    }
    let a = common::reserve_addr();
    let cfg = format!("{DEFAULTS}frontend fe\n  bind {a} mss 1200\n  default_backend be\nbackend be\n  server s 127.0.0.1:9\n");
    let log = strace_setsockopt(&cfg, a);
    assert!(log.contains("TCP_MAXSEG, [1200]"), "{log}");
}

/// Server `tfo`: HAProxy sends the first bytes in the SYN (`MSG_FASTOPEN`); Ibex's safe
/// equivalent is `TCP_FASTOPEN_CONNECT` on the connecting socket.
#[test]
fn server_tfo_sets_fastopen_on_the_connecting_socket() {
    if Command::new("strace").arg("-V").output().is_err() {
        return;
    }
    let backend = TcpListener::bind("127.0.0.1:0").expect("bind");
    let bp = backend.local_addr().expect("addr").port();
    let a = common::reserve_addr();
    // The backend never answers nor closes: the tunnel ends with `timeout server`, and the
    // soft stop waits for it -- 500 ms here rather than DEFAULTS' 5 s (T259).
    const DEFAULTS: &str = "defaults\n  mode tcp\n  timeout client 500ms\n  timeout server 500ms\n  timeout connect 5s\n";
    let cfg = format!("{DEFAULTS}frontend fe\n  bind {a}\n  default_backend be\nbackend be\n  server s 127.0.0.1:{bp} tfo\n");
    let log = strace_setsockopt(&cfg, a);
    assert!(log.contains("TCP_FASTOPEN_CONNECT"), "{log}");
    let cfg = format!("{DEFAULTS}frontend fe\n  bind {a}\n  default_backend be\nbackend be\n  server s 127.0.0.1:{bp}\n");
    let log = strace_setsockopt(&cfg, a);
    assert!(!log.contains("TCP_FASTOPEN_CONNECT"), "{log}");
}

/// HAProxy (`cc no_such_algo`): a warning per listener, and the listener still serves.
#[test]
fn a_refused_socket_option_warns_and_the_listener_still_serves() {
    let a = common::reserve_addr();
    let mut f = NamedTempFile::new().expect("tmp");
    let cfg = format!("{DEFAULTS}frontend fe\n  bind {a} cc no_such_algo\n  default_backend be\nbackend be\n  server s 127.0.0.1:9\n");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn().map(common::Ibex)
        .expect("spawn");
    assert!(common::wait_listening(a), "the listener must serve despite the refused option");
    common::stop(&mut child);
    let mut err = String::new();
    child.stderr.take().expect("stderr").read_to_string(&mut err).expect("read");
    assert!(err.contains("cannot set the congestion control"), "{err}");
}

/// Runs `ibex -c` on `cfg`: the exit status and its output.
fn check(cfg: &str) -> (bool, String) {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned() + &String::from_utf8_lossy(&out.stdout))
}

#[test]
fn standalone_accept_proxy_is_refused_like_haproxy() {
    for sect in ["frontend", "listen"] {
        for kw in ["accept-proxy", "accept-proxy-v2"] {
            let (ok, msg) = check(&format!("{DEFAULTS}{sect} x\n  bind 127.0.0.1:1\n  {kw}\n"));
            assert!(!ok, "{sect} {kw}: {msg}");
            assert!(msg.contains(&format!("unknown keyword '{kw}' in '{sect}' section")), "{sect} {kw}: {msg}");
        }
    }
}

#[test]
fn bind_keywords_without_a_safe_implementation_are_refused() {
    for kw in [
        "tfo", "defer-accept", "process 1", "thread 1", "nbconn 1", "nice 5", "shards 2", "tcp-ss 1",
        "idle-ping 1s", "label foo", "guid-prefix g",
    ] {
        let (ok, msg) = check(&format!("{DEFAULTS}frontend x\n  bind 127.0.0.1:1 {kw}\n"));
        let name = kw.split(' ').next().unwrap_or(kw);
        assert!(!ok && msg.contains(&format!("'{name}'")), "{kw}: {msg}");
    }
    let (ok, msg) = check(&format!("{DEFAULTS}frontend x\n  bind 127.0.0.1:1 thread all\n"));
    assert!(ok, "thread all is a no-op: {msg}");
}

/// A raw backend that timestamps every connection and answers `OK` to the first
/// `ok_for` of them and `NO` afterwards. Returns the gaps between checks in ms.
fn check_gaps(server_opts: &str, ok_for: usize, run: Duration) -> Vec<u128> {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("addr").port();
    let stamps = Arc::new(Mutex::new(Vec::<Instant>::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let (st, sp) = (Arc::clone(&stamps), Arc::clone(&stop));
    l.set_nonblocking(true).expect("nb");
    let th = std::thread::spawn(move || {
        while !sp.load(Ordering::Relaxed) {
            match l.accept() {
                Ok((mut c, _)) => {
                    let n = {
                        let mut g = st.lock().expect("lock");
                        g.push(Instant::now());
                        g.len()
                    };
                    let _ = c.set_nonblocking(false);
                    let _ = c.write_all(if n <= ok_for { b"OK" } else { b"NO" });
                    let mut b = [0u8; 8];
                    let _ = c.set_read_timeout(Some(Duration::from_millis(5)));
                    let _ = c.read(&mut b);
                }
                Err(_) => std::thread::sleep(Duration::from_millis(2)),
            }
        }
    });
    let a = common::reserve_addr();
    let cfg = format!(
        "{DEFAULTS}  timeout check 500ms\nlisten l\n  bind {a}\n  option tcp-check\n  tcp-check expect string OK\n  server s 127.0.0.1:{port} check {server_opts}\n"
    );
    let (mut child, _f) = spawn(&cfg);
    std::thread::sleep(run);
    common::stop(&mut child);
    stop.store(true, Ordering::Relaxed);
    th.join().expect("join");
    let v = stamps.lock().expect("lock").clone();
    v.windows(2).map(|w| (w[1] - w[0]).as_millis()).collect()
}

fn near(got: u128, want: u128) -> bool {
    got + 90 >= want && got <= want + 130
}

#[test]
fn fastinter_and_downinter_pace_the_checks() {
    let g = check_gaps("inter 1000ms fastinter 200ms downinter 300ms fall 3 rise 2", 4, Duration::from_millis(8500));
    // HAProxy's very first gap is 200 ms (it schedules the first check's successor before
    // the counter reaches its ceiling); Ibex's is `inter`. Not part of T207: gap 0 is skipped.
    let want = [1000u128, 1000, 1000, 200, 200, 300, 300, 300];
    assert!(g.len() > want.len(), "{g:?}");
    for (i, w) in want.iter().enumerate() {
        assert!(near(g[i + 1], *w), "gap {}: want ~{w} ms, gaps {g:?}", i + 1);
    }
}

#[test]
fn without_fastinter_and_downinter_every_gap_is_inter() {
    let g = check_gaps("inter 300ms fall 3 rise 2", 4, Duration::from_millis(3200));
    assert!(g.len() >= 8, "{g:?}");
    assert!(g.iter().take(8).all(|x| near(*x, 300)), "{g:?}");
}
