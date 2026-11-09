// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T320: `show info` `ConnRate`, `SessRate`, `MaxConnRate`, `MaxSessRate`.
//!
//! Measured on `HAProxy` with two HTTP frontends and a stats socket:
//!
//! | moment                                         | ConnRate | MaxConnRate | SessRate | MaxSessRate |
//! |------------------------------------------------|----------|-------------|----------|-------------|
//! | start (nothing yet)                            | 0        | 0           | 0        | 0           |
//! | right after 50 client connections (both frontends together) | 50 | 50   | 50       | 50          |
//! | right after the CLI command `clear counters`   | 50       | 0           | 50       | 0           |
//! | 2.2 s later, no traffic                        | 0        | 0           | 0        | 0           |
//! | right after 5 more connections                 | 5        | 5           | 5        | 5           |
//! | right after `clear counters all`               | 5        | 0           | 5        | 0           |

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

struct Daemon(Child, std::path::PathBuf, std::path::PathBuf);

impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_file(&self.1);
        let _ = std::fs::remove_file(&self.2);
    }
}

fn get_status(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = Vec::<u8>::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).split(' ').nth(1).unwrap_or("").to_string()
}

fn cli(sock: &std::path::Path, cmd: &str) -> String {
    let mut c = UnixStream::connect(sock).expect("connect cli");
    c.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = String::new();
    c.read_to_string(&mut out).expect("read");
    out
}

fn show_info(sock: &std::path::Path) -> String {
    cli(sock, "show info")
}

fn get_rate(info: &str, name: &str) -> u64 {
    info.lines()
        .find(|l| l.starts_with(name))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

#[test]
fn show_info_rates_track_connections_and_clear_counters_resets_maxima() {
    let addr1 = common::reserve_addr();
    let addr2 = common::reserve_addr();
    let dir = std::env::temp_dir();
    let sock = dir.join(format!("alcyon_t320_rates_{}.sock", std::process::id()));
    let cfg = format!(
        "global\n  nbthread 4\n  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 10s\n  timeout server 10s\n\
         frontend f1\n  bind {addr1}\n  http-request return status 200\n\
         frontend f2\n  bind {addr2}\n  http-request return status 200\n",
        sock.display()
    );
    let path = dir.join(format!("alcyon_t320_rates_{}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    let _d = Daemon(child, path, sock.clone());

    // Wait for alcyon to be ready. The readiness loop opens client connections,
    // which are counted by the rate counters, exactly as HAProxy counts them.
    common::wait_listening(addr1);
    common::wait_listening(addr2);
    assert!(sock.exists(), "stats socket should exist");

    // Sleep 2.2s so the readiness-loop connections age out of the 1s window,
    // then send `clear counters` to zero the maxima. Now we should see all 0s.
    thread::sleep(Duration::from_secs(2));
    thread::sleep(Duration::from_millis(200));
    assert_eq!(cli(&sock, "clear counters"), "\n");
    let info = show_info(&sock);
    assert_eq!(get_rate(&info, "ConnRate"), 0, "ConnRate at start");
    assert_eq!(get_rate(&info, "MaxConnRate"), 0, "MaxConnRate at start");
    assert_eq!(get_rate(&info, "SessRate"), 0, "SessRate at start");
    assert_eq!(get_rate(&info, "MaxSessRate"), 0, "MaxSessRate at start");

    // 2. Send 50 connections across both frontends.
    for _ in 0..25 {
        assert_eq!(get_status(addr1.port(), "/"), "200");
        assert_eq!(get_status(addr2.port(), "/"), "200");
    }

    let info = show_info(&sock);
    assert_eq!(get_rate(&info, "ConnRate"), 50, "ConnRate after 50 connections");
    assert_eq!(get_rate(&info, "MaxConnRate"), 50, "MaxConnRate after 50 connections");
    assert_eq!(get_rate(&info, "SessRate"), 50, "SessRate after 50 connections");
    assert_eq!(get_rate(&info, "MaxSessRate"), 50, "MaxSessRate after 50 connections");

    // 3. `clear counters` resets maxima to 0, leaves rates.
    assert_eq!(cli(&sock, "clear counters"), "\n");
    let info = show_info(&sock);
    assert_eq!(get_rate(&info, "ConnRate"), 50, "ConnRate after clear counters");
    assert_eq!(get_rate(&info, "MaxConnRate"), 0, "MaxConnRate after clear counters");
    assert_eq!(get_rate(&info, "SessRate"), 50, "SessRate after clear counters");
    assert_eq!(get_rate(&info, "MaxSessRate"), 0, "MaxSessRate after clear counters");

    // 4. Wait 2.2s, no traffic: everything goes to 0.
    thread::sleep(Duration::from_secs(2));
    thread::sleep(Duration::from_millis(200));
    let info = show_info(&sock);
    assert_eq!(get_rate(&info, "ConnRate"), 0, "ConnRate after 2.2s idle");
    assert_eq!(get_rate(&info, "MaxConnRate"), 0, "MaxConnRate after 2.2s idle");
    assert_eq!(get_rate(&info, "SessRate"), 0, "SessRate after 2.2s idle");
    assert_eq!(get_rate(&info, "MaxSessRate"), 0, "MaxSessRate after 2.2s idle");

    // 5. Send 5 more connections.
    for _ in 0..5 {
        assert_eq!(get_status(addr1.port(), "/"), "200");
    }

    let info = show_info(&sock);
    assert_eq!(get_rate(&info, "ConnRate"), 5, "ConnRate after 5 connections");
    assert_eq!(get_rate(&info, "MaxConnRate"), 5, "MaxConnRate after 5 connections");
    assert_eq!(get_rate(&info, "SessRate"), 5, "SessRate after 5 connections");
    assert_eq!(get_rate(&info, "MaxSessRate"), 5, "MaxSessRate after 5 connections");

    // 6. `clear counters all` resets maxima to 0, leaves rates.
    assert_eq!(cli(&sock, "clear counters all"), "\n");
    let info = show_info(&sock);
    assert_eq!(get_rate(&info, "ConnRate"), 5, "ConnRate after clear counters all");
    assert_eq!(get_rate(&info, "MaxConnRate"), 0, "MaxConnRate after clear counters all");
    assert_eq!(get_rate(&info, "SessRate"), 5, "SessRate after clear counters all");
    assert_eq!(get_rate(&info, "MaxSessRate"), 0, "MaxSessRate after clear counters all");
}

/// Starts alcyon on `cfg`, waits for `tcp` to accept, then lets the probe connections age
/// out of the rate window and clears the maxima, so every counter starts at 0.
fn start_quiet(name: &str, cfg: &str, tcp: &[std::net::SocketAddr], sock: &std::path::Path) -> Daemon {
    let path = std::env::temp_dir().join(format!("alcyon_t320_{name}_{}_{}.cfg", common::h3_path_name(), std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let child = common::alcyon_command(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    let d = Daemon(child, path, sock.to_path_buf());
    for a in tcp {
        assert!(common::wait_listening(*a), "alcyon never listened on {a}");
    }
    thread::sleep(Duration::from_millis(2200));
    assert_eq!(cli(sock, "clear counters"), "\n");
    let info = show_info(sock);
    for k in ["ConnRate", "MaxConnRate", "SessRate", "MaxSessRate"] {
        assert_eq!(get_rate(&info, k), 0, "{k} at start");
    }
    d
}

/// Measured on `HAProxy` 3.5-dev8: 5 connections to a frontend with `tcp-request connection
/// reject` and 2 requests to an accepting one give `ConnRate: 7 MaxConnRate: 7 SessRate: 2
/// MaxSessRate: 2`, and reading `show info` again does not move them (the CLI listener is
/// unlimited and not counted). `listener_accept` ticks `conn_per_sec` before the rules run;
/// `sess_per_sec` only once `accept()` kept the connection.
#[test]
fn rejected_connections_count_in_conn_rate_not_sess_rate() {
    let rej = common::reserve_addr();
    let ok = common::reserve_addr();
    let sock = std::env::temp_dir().join(format!("alcyon_t320_rej_{}.sock", std::process::id()));
    let cfg = format!(
        "global\n  nbthread 2\n  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 10s\n  timeout server 10s\n\
         frontend rej\n  bind {rej}\n  tcp-request connection reject\n\
         frontend ok\n  bind {ok}\n  http-request return status 200\n",
        sock.display()
    );
    let _d = start_quiet("rej", &cfg, &[rej, ok], &sock);

    for _ in 0..5 {
        let mut s = TcpStream::connect(rej).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let _ = s.read_to_end(&mut Vec::new());
    }
    for _ in 0..2 {
        assert_eq!(get_status(ok.port(), "/"), "200");
    }
    for round in 0..2 {
        let info = show_info(&sock);
        assert_eq!(get_rate(&info, "ConnRate"), 7, "ConnRate (show info read {round})");
        assert_eq!(get_rate(&info, "MaxConnRate"), 7, "MaxConnRate (show info read {round})");
        assert_eq!(get_rate(&info, "SessRate"), 2, "SessRate (show info read {round})");
        assert_eq!(get_rate(&info, "MaxSessRate"), 2, "MaxSessRate (show info read {round})");
    }
}

/// Three HTTP/3 requests over one QUIC connection are one connection and one session.
/// Not measured: the reference binary is built without QUIC. From its source, a QUIC
/// connection reaches `listener_accept` once (`quic_accept_push_qc` -> `quic_accept_run`,
/// `src/quic_sock.c`), which ticks `conn_per_sec` and `sess_per_sec` once each; request
/// streams are not accepted connections.
crate::h3_both_paths! {
fn h3_requests_on_one_quic_connection_count_once() {
    let has_h3 = Command::new("curl")
        .arg("--version")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("HTTP3"));
    assert!(has_h3, "this test needs a curl with HTTP/3; it fails rather than skips");
    let tcp = common::reserve_addr();
    let quic = common::reserve_addr();
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let sock = std::env::temp_dir().join(format!("alcyon_t320_h3_{}_{}.sock", common::h3_path_name(), std::process::id()));
    let cfg = format!(
        "global\n  nbthread 2\n  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 10s\n  timeout server 10s\n\
         frontend fe\n  bind {tcp}\n  bind quic4@{quic} ssl crt {crt} alpn h3\n  http-request return status 200\n",
        sock.display()
    );
    let _d = start_quiet("h3", &cfg, &[tcp], &sock);

    let url = format!("https://localhost:{}/", quic.port());
    let out = Command::new("curl")
        .args(["-sS", "-o", "/dev/null", "-w", "%{http_code} ", "--http3-only", "-k", "--max-time", "8", "--resolve"])
        .arg(format!("localhost:{}:127.0.0.1", quic.port()))
        .args([&url, &url, &url])
        .output()
        .expect("curl");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "200 200 200 ", "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let info = show_info(&sock);
    assert_eq!(get_rate(&info, "ConnRate"), 1, "ConnRate");
    assert_eq!(get_rate(&info, "MaxConnRate"), 1, "MaxConnRate");
    assert_eq!(get_rate(&info, "SessRate"), 1, "SessRate");
    assert_eq!(get_rate(&info, "MaxSessRate"), 1, "MaxSessRate");
}
}

/// T499 part 2: the rates are per-thread counters summed on read. With `nbthread 4` and eight
/// clients connecting at once (so several threads accept), the sum is every connection and
/// `clear counters` zeroes the maxima of every thread, not only the one that served the CLI.
#[test]
fn rates_sum_over_threads_with_parallel_clients() {
    let addr = common::reserve_addr();
    let sock = std::env::temp_dir().join(format!("alcyon_t499_par_{}.sock", std::process::id()));
    let cfg = format!(
        "global\n  nbthread 4\n  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout client 10s\n\
         frontend f\n  bind {addr}\n  http-request return status 200\n",
        sock.display()
    );
    let _d = start_quiet("par", &cfg, &[addr], &sock);
    let workers: Vec<_> = (0..8)
        .map(|_| {
            thread::spawn(move || {
                for _ in 0..25 {
                    assert_eq!(get_status(addr.port(), "/"), "200");
                }
            })
        })
        .collect();
    for w in workers {
        w.join().expect("client");
    }
    let info = show_info(&sock);
    for k in ["ConnRate", "MaxConnRate", "SessRate", "MaxSessRate"] {
        assert_eq!(get_rate(&info, k), 200, "{k} after 8 x 25 parallel connections");
    }
    assert_eq!(cli(&sock, "clear counters"), "\n");
    let info = show_info(&sock);
    assert_eq!(get_rate(&info, "ConnRate"), 200, "ConnRate survives clear counters");
    assert_eq!(get_rate(&info, "MaxConnRate"), 0, "MaxConnRate zeroed on every thread");
    assert_eq!(get_rate(&info, "MaxSessRate"), 0, "MaxSessRate zeroed on every thread");
    // A new connection after the clear starts the maxima again from the current rate.
    assert_eq!(get_status(addr.port(), "/"), "200");
    let info = show_info(&sock);
    assert!(get_rate(&info, "MaxConnRate") >= 1, "MaxConnRate counts again after the clear");
}
