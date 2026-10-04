// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `show stat` after the same traffic as the reference `HAProxy` (3.5-dev8-885761-29), T165.
//!
//! The traffic, one request at a time against `frontend fe` (a `use_backend dead` for
//! `/dead`, a redirect for `/red`, a deny for `/deny`, otherwise `backend be` with one
//! origin that answers by path and takes a second over `/slow`, `timeout server 300ms`,
//! `retries 3`):
//! `/a` and `/b` kept alive then `/c`, `/404`, `/500`, `/301`, `/red`, `/deny`, a request
//! the client abandons after its head, `/slow` (504), `BAD` (400), `/dead` (503, three
//! retries on a closed port). The columns a monitoring tool reads, as `HAProxy` printed
//! them (`status=` and the like are the keys, in the order of the test below):
//!
//! ```text
//! fe FRONTEND  stot=10 bin=469 bout=433 dreq=1 ereq=1 hrsp_2xx=4 3xx=2 4xx=3 5xx=3 req_tot=12 mode=http
//! be s1        status="no check" stot=8 bin=344 bout=433 eresp=1 hrsp 2xx=4 3xx=1 4xx=1 5xx=1 req_tot=7 lbtot=8 cli_abrt=1 srv_abrt=0 chkfail="" lastchg=<secs>
//! be BACKEND   status=UP stot=8 bin=344 bout=433 eresp=1 hrsp 2xx=4 3xx=1 4xx=1 5xx=2 req_tot=8 lbtot=8 cli_abrt=1 downtime=0
//! dead d1      stot=4 bin=42 bout=0 econ=1 wretr=3 hrsp all 0 req_tot=0 lbtot=1
//! dead BACKEND stot=1 bin=42 econ=1 wretr=3 hrsp_5xx=1 req_tot=1 lbtot=1
//! ```
//!
//! `bin` counts the request as `HAProxy` parsed it, `bout` the response the server sent
//! (as `%U` and `%B` do in the log); a server row counts connection attempts in `stot`, a
//! backend the streams. Reaches the data path in `account_stream` (`engine.rs`), called
//! where the stream's log line is made, and printed by `stats.rs`.

mod common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Daemon(Child, std::path::PathBuf);

impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_file(&self.1);
    }
}

fn origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind origin");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for c in listener.incoming().flatten() {
            thread::spawn(move || serve(c));
        }
    });
    port
}

fn serve(mut c: TcpStream) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match c.read(&mut chunk) {
                Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                _ => return,
            }
        }
        let end = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("head") + 4;
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        buf.drain(..end);
        let path = head.split(' ').nth(1).unwrap_or("/").to_string();
        let reply: &[u8] = match path.as_str() {
            "/slow" => {
                thread::sleep(Duration::from_secs(1));
                return;
            }
            // Server failures (`server_failures_are_counted_as_haproxy_counts_them`).
            "/close" => return,
            "/cut" => {
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc");
                return;
            }
            "/stall" => {
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc");
                thread::sleep(Duration::from_secs(1));
                return;
            }
            "/garbage" => {
                let _ = c.write_all(b"NOT HTTP\r\n\r\n");
                thread::sleep(Duration::from_millis(200));
                return;
            }
            "/404" => b"HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnope",
            "/500" => b"HTTP/1.1 500 X\r\nContent-Length: 0\r\n\r\n",
            "/301" => b"HTTP/1.1 301 X\r\nLocation: /\r\nContent-Length: 0\r\n\r\n",
            _ => b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nSet-Cookie: a=b\r\n\r\nhello",
        };
        if c.write_all(reply).is_err() {
            return;
        }
    }
}

fn exchange(port: u16, data: &[u8]) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    s.write_all(data).expect("write");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n").into_bytes()
}

fn stat(sock: &std::path::Path) -> HashMap<(String, String), HashMap<String, String>> {
    let mut c = UnixStream::connect(sock).expect("connect cli");
    c.write_all(b"show stat\n").expect("write");
    let mut out = String::new();
    c.read_to_string(&mut out).expect("read");
    let mut lines = out.lines();
    let header: Vec<String> = lines.next().expect("header").trim_start_matches("# ").split(',').map(String::from).collect();
    lines
        .filter(|l| !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split(',').collect();
            let row: HashMap<String, String> = header.iter().cloned().zip(f.iter().map(|v| (*v).to_string())).collect();
            ((f[0].to_string(), f[1].to_string()), row)
        })
        .collect()
}

fn check(rows: &HashMap<(String, String), HashMap<String, String>>, px: &str, sv: &str, want: &[(&str, &str)]) {
    let row = rows.get(&(px.to_string(), sv.to_string())).unwrap_or_else(|| panic!("no row {px}/{sv}"));
    let bad: Vec<String> = want
        .iter()
        .filter(|(k, v)| row.get(*k).map(String::as_str) != Some(*v))
        .map(|(k, v)| format!("{k}: want {v:?}, got {:?}", row.get(*k)))
        .collect();
    assert!(bad.is_empty(), "{px}/{sv}: {bad:#?}");
}

#[test]
fn counters_after_the_reference_traffic() {
    let origin = origin();
    let dead = common::reserve_port();
    let port = common::reserve_port();
    let sock = std::env::temp_dir().join(format!("ibex_t165_stat_{}.sock", std::process::id()));
    let cfg = format!(
        "global\n  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout connect 300ms\n  timeout client 5s\n  timeout server 300ms\n\
         frontend fe\n  bind 127.0.0.1:{port}\n  use_backend dead if {{ path /dead }}\n  acl isred path /red\n  http-request redirect location /x if isred\n  acl isdeny path /deny\n  http-request deny if isdeny\n  default_backend be\n\
         backend be\n  server s1 127.0.0.1:{origin}\n\
         backend dead\n  server d1 127.0.0.1:{dead}\n",
        sock.display()
    );
    let path = std::env::temp_dir().join(format!("ibex_t165_stat_{}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let _d = Daemon(child, path);
    let deadline = Instant::now() + Duration::from_secs(5);
    // No probe connection to the frontend: `HAProxy` counts one that closes unspoken (a 400).
    while !sock.exists() {
        assert!(Instant::now() < deadline, "the daemon never listened");
        thread::sleep(Duration::from_millis(25));
    }
    thread::sleep(Duration::from_millis(300));

    let mut keepalive = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n".to_vec();
    keepalive.extend(get("/c"));
    exchange(port, &keepalive);
    for p in ["/404", "/500", "/301", "/red", "/deny"] {
        exchange(port, &get(p));
    }
    // A client that leaves with the body of its request unsent.
    {
        let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.write_all(b"GET /abort HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\nabc").expect("write");
        thread::sleep(Duration::from_millis(200));
    }
    exchange(port, &get("/slow"));
    exchange(port, b"BAD\r\n\r\n");
    exchange(port, &get("/dead"));
    thread::sleep(Duration::from_millis(300));

    let rows = stat(&sock);
    check(
        &rows,
        "fe",
        "FRONTEND",
        &[
            ("status", "OPEN"),
            ("stot", "10"),
            ("bin", "469"),
            ("bout", "433"),
            ("dreq", "1"),
            ("ereq", "1"),
            ("hrsp_1xx", "0"),
            ("hrsp_2xx", "4"),
            ("hrsp_3xx", "2"),
            ("hrsp_4xx", "3"),
            ("hrsp_5xx", "3"),
            ("hrsp_other", "0"),
            ("req_tot", "12"),
            ("mode", "http"),
            ("act", ""),
        ],
    );
    check(
        &rows,
        "be",
        "s1",
        &[
            ("status", "no check"),
            ("scur", "0"),
            ("stot", "8"),
            ("bin", "344"),
            ("bout", "433"),
            ("dresp", "0"),
            ("econ", "0"),
            ("eresp", "1"),
            ("weight", "1"),
            ("act", "1"),
            ("bck", "0"),
            ("chkfail", ""),
            ("chkdown", ""),
            ("hrsp_2xx", "4"),
            ("hrsp_3xx", "1"),
            ("hrsp_4xx", "1"),
            ("hrsp_5xx", "1"),
            ("req_tot", "7"),
            ("lbtot", "8"),
            ("cli_abrt", "1"),
            ("srv_abrt", "0"),
            ("mode", "http"),
        ],
    );
    check(
        &rows,
        "be",
        "BACKEND",
        &[
            ("status", "UP"),
            ("stot", "8"),
            ("bin", "344"),
            ("bout", "433"),
            ("econ", "0"),
            ("eresp", "1"),
            ("hrsp_2xx", "4"),
            ("hrsp_3xx", "1"),
            ("hrsp_4xx", "1"),
            ("hrsp_5xx", "2"),
            ("req_tot", "8"),
            ("lbtot", "8"),
            ("cli_abrt", "1"),
            ("downtime", "0"),
            ("mode", "http"),
        ],
    );
    check(
        &rows,
        "dead",
        "d1",
        &[
            ("stot", "4"),
            ("bin", "42"),
            ("bout", "0"),
            ("econ", "1"),
            ("eresp", "0"),
            ("wretr", "3"),
            ("hrsp_5xx", "0"),
            ("req_tot", "0"),
            ("lbtot", "1"),
        ],
    );
    check(
        &rows,
        "dead",
        "BACKEND",
        &[("stot", "1"), ("bin", "42"), ("econ", "1"), ("wretr", "3"), ("hrsp_5xx", "1"), ("req_tot", "1"), ("lbtot", "1")],
    );
    // `lastchg` is the seconds since the server last changed state, since the start here.
    let lastchg: u64 = rows[&("be".to_string(), "s1".to_string())]["lastchg"].parse().expect("lastchg is a number");
    assert!(lastchg <= 10, "lastchg {lastchg}");
}

/// Starts the daemon on `cfg_for(origin, port, sock)` and waits for its stats socket.
fn daemon(tag: &str, cfg_for: impl FnOnce(u16, u16, &std::path::Path) -> String) -> (Daemon, u16, std::path::PathBuf) {
    let origin = origin();
    let port = common::reserve_port();
    let sock = std::env::temp_dir().join(format!("ibex_t165_{tag}_{}.sock", std::process::id()));
    let path = std::env::temp_dir().join(format!("ibex_t165_{tag}_{}.cfg", std::process::id()));
    std::fs::write(&path, cfg_for(origin, port, &sock)).expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let d = Daemon(child, path);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sock.exists() {
        assert!(Instant::now() < deadline, "the daemon never listened");
        thread::sleep(Duration::from_millis(25));
    }
    thread::sleep(Duration::from_millis(300));
    (d, port, sock)
}

fn cli(sock: &std::path::Path, cmd: &str) {
    let mut c = UnixStream::connect(sock).expect("connect cli");
    c.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = String::new();
    c.read_to_string(&mut out).expect("read");
}

/// Measured on the reference, one request each on `be/s1` (`timeout server 300ms`): the
/// deltas of `stot eresp srv_abrt hrsp_2xx req_tot` the server row showed.
///
/// ```text
/// /ok       1 0 0 1 1     answered
/// /close    1 2 0 0 0     closed with no response (SH, 502): two failed responses
/// /cut      1 1 1 1 1     closed in the body (SD)
/// /stall    1 0 1 1 1     stopped in the body until timeout server (sD)
/// /garbage  1 2 0 0 0     not HTTP (PH, 502)
/// ```
#[test]
fn server_failures_are_counted_as_haproxy_counts_them() {
    let (_d, port, sock) = daemon("errs", |origin, port, sock| {
        format!(
            "global\n  stats socket {} level admin\n\
             defaults\n  mode http\n  timeout connect 300ms\n  timeout client 5s\n  timeout server 300ms\n\
             frontend fe\n  bind 127.0.0.1:{port}\n  default_backend be\n\
             backend be\n  server s1 127.0.0.1:{origin}\n",
            sock.display()
        )
    });
    let cols = ["stot", "eresp", "srv_abrt", "hrsp_2xx", "req_tot"];
    let read = || {
        let rows = stat(&sock);
        let row = &rows[&("be".to_string(), "s1".to_string())];
        cols.map(|c| row[c].parse::<u64>().unwrap_or(0))
    };
    let mut before = read();
    for (path, want) in [("/ok", [1, 0, 0, 1, 1]), ("/close", [1, 2, 0, 0, 0]), ("/cut", [1, 1, 1, 1, 1]), ("/stall", [1, 0, 1, 1, 1]), ("/garbage", [1, 2, 0, 0, 0])] {
        exchange(port, &get(path));
        thread::sleep(Duration::from_millis(300));
        let after = read();
        let delta: Vec<u64> = after.iter().zip(before).map(|(a, b)| a - b).collect();
        assert_eq!(delta, want, "{path}: {cols:?}");
        before = after;
    }
}

/// `disable server` on the only server, as measured: the server is `MAINT` with `lastchg`
/// reset, the backend `DOWN` with `chkdown` 1 and `downtime` running; `enable server` brings
/// the backend `UP` and `downtime` stays at what it was.
#[test]
fn a_server_state_change_moves_lastchg_and_takes_the_backend_down() {
    let (_d, _port, sock) = daemon("chg", |origin, port, sock| {
        format!(
            "global\n  stats socket {} level admin\n\
             defaults\n  mode http\n  timeout connect 300ms\n  timeout client 5s\n  timeout server 300ms\n\
             frontend fe\n  bind 127.0.0.1:{port}\n  default_backend be\n\
             backend be\n  server s1 127.0.0.1:{origin}\n",
            sock.display()
        )
    });
    thread::sleep(Duration::from_millis(2100));
    let rows = stat(&sock);
    let n = |rows: &HashMap<(String, String), HashMap<String, String>>, sv: &str, c: &str| rows[&("be".to_string(), sv.to_string())][c].clone();
    assert!(n(&rows, "s1", "lastchg").parse::<u64>().expect("number") >= 2, "since the start");
    assert_eq!(n(&rows, "BACKEND", "status"), "UP");
    cli(&sock, "disable server be/s1");
    thread::sleep(Duration::from_millis(1100));
    let rows = stat(&sock);
    assert_eq!(n(&rows, "s1", "status"), "MAINT");
    assert!(n(&rows, "s1", "lastchg").parse::<u64>().expect("number") <= 1);
    assert_eq!(n(&rows, "BACKEND", "status"), "DOWN");
    assert_eq!(n(&rows, "BACKEND", "chkdown"), "1");
    assert!(n(&rows, "BACKEND", "downtime").parse::<u64>().expect("number") >= 1);
    cli(&sock, "enable server be/s1");
    let rows = stat(&sock);
    assert_eq!(n(&rows, "s1", "status"), "no check");
    assert_eq!(n(&rows, "BACKEND", "status"), "UP");
    assert_eq!(n(&rows, "BACKEND", "chkdown"), "1");
}

/// A TCP-mode proxy, measured: `mode=tcp`, `bin`/`bout` the bytes through (20 and 60), no
/// `req_tot` on the server and backend rows (0 on the frontend), the server timing out in the
/// data (`sD`) counted in `srv_abrt` only.
#[test]
fn a_tcp_proxy_counts_bytes_and_a_server_timeout() {
    let (_d, port, sock) = daemon("tcp", |origin, port, sock| {
        format!(
            "global\n  stats socket {} level admin\n\
             defaults\n  mode tcp\n  timeout connect 300ms\n  timeout client 5s\n  timeout server 300ms\n\
             frontend fe\n  bind 127.0.0.1:{port}\n  default_backend be\n\
             backend be\n  server s1 127.0.0.1:{origin}\n",
            sock.display()
        )
    });
    exchange(port, b"GET /ok HTTP/1.0\r\n\r\n");
    thread::sleep(Duration::from_millis(300));
    let rows = stat(&sock);
    check(&rows, "fe", "FRONTEND", &[("stot", "1"), ("bin", "20"), ("bout", "60"), ("mode", "tcp"), ("req_tot", "0"), ("hrsp_2xx", "")]);
    check(
        &rows,
        "be",
        "s1",
        &[("stot", "1"), ("bin", "20"), ("bout", "60"), ("lbtot", "1"), ("srv_abrt", "1"), ("eresp", "0"), ("cli_abrt", "0"), ("mode", "tcp"), ("req_tot", "")],
    );
    check(&rows, "be", "BACKEND", &[("stot", "1"), ("lbtot", "1"), ("srv_abrt", "1"), ("eresp", "0"), ("mode", "tcp"), ("status", "UP")]);
}
