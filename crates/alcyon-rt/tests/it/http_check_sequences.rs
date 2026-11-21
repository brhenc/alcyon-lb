// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `http-check`: several `connect` / `send` / `expect` sequences in order,
//! `connect addr <ip>:<port>` and `connect addr <ip> port <port>`, and
//! `uri-lf` / `body-lf` / `hdr` log-format rendering.
//!
//! Set `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

struct Proxy {
    child: Child,
    sock: std::path::PathBuf,
    _cfg: tempfile::NamedTempFile,
    _dir: tempfile::TempDir,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_proxy(cfg_template: &str) -> Proxy {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("admin.sock");
    let cfg = tempfile::NamedTempFile::new_in(dir.path()).expect("tempfile");
    let cfg_txt = cfg_template.replace("{SOCK}", &sock.display().to_string());
    std::fs::write(cfg.path(), &cfg_txt).expect("write cfg");

    let bin = std::env::var("T281_ORACLE")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = common::alcyon_command(&bin)
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proxy");

    let started = Instant::now();
    let mut child = child;
    while !sock.exists() {
        if let Some(status) = child.try_wait().expect("try_wait") {
            let mut err = String::new();
            if let Some(mut stderr) = child.stderr.take() {
                let _ = stderr.read_to_string(&mut err);
            }
            panic!("proxy exited early with {status}: {err}");
        }
        assert!(started.elapsed() < Duration::from_secs(10), "admin socket never appeared");
        thread::sleep(Duration::from_millis(20));
    }
    // Wait until admin socket accepts connections.
    while UnixStream::connect(&sock).is_err() {
        assert!(started.elapsed() < Duration::from_secs(10), "admin socket never accepted");
        thread::sleep(Duration::from_millis(20));
    }

    Proxy { child, sock, _cfg: cfg, _dir: dir }
}

fn cli_cmd(sock: &std::path::Path, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect cli");
    s.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("write cli");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn server_status(sock: &std::path::Path, px: &str, sv: &str) -> Option<String> {
    let stat = cli_cmd(sock, "show stat");
    for line in stat.lines() {
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() > 17 && cols[0] == px && cols[1] == sv {
            return Some(cols[17].to_string());
        }
    }
    None
}

fn read_http_request(c: &mut TcpStream) -> Option<String> {
    let _ = c.set_read_timeout(Some(Duration::from_millis(500)));
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = c.read(&mut buf) {
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&data);
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let len = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            if body.len() >= len {
                break;
            }
        }
    }
    if data.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&data).into_owned())
    }
}

fn spawn_capture_server(responses: Vec<&'static str>) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let rec = Arc::clone(&seen);
    thread::spawn(move || {
        let mut idx = 0usize;
        for mut c in listener.incoming().flatten() {
            if let Some(req) = read_http_request(&mut c) {
                rec.lock().expect("lock").push(req);
            }
            let status = responses[idx % responses.len()];
            idx += 1;
            let _ = c.write_all(
                format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .as_bytes(),
            );
        }
    });
    (addr, seen)
}

#[test]
fn http_check_multi_connect_send_expect_sequence() {
    let (s4_addr, seen4) = spawn_capture_server(vec!["200 OK"]);
    let dead_addr = common::reserve_addr();

    let cfg = format!(
        r#"global
    stats socket {{SOCK}} mode 600 level admin
defaults
    mode http
    timeout client 5s
    timeout server 5s
    timeout connect 5s
backend be4
    mode tcp
    option httpchk
    http-check send-state
    http-check connect addr {ip}:{port}
    http-check set-var(check.server) "str(srv)"
    http-check set-var(check.path) "str(/req1)"
    http-check send meth GET uri-lf "%[var(check.path)]" ver HTTP/1.1 hdr x-test "server=%[var(check.server)]"
    http-check expect status 200
    http-check connect addr {ip} port {port}
    http-check unset-var(check.server)
    http-check set-var(check.path) "str(/req2)"
    http-check send meth GET uri-lf "%[var(check.path)]" ver HTTP/1.1 hdr x-test "server=%[var(check.server)]" body "health-check body"
    http-check expect rstatus "^2[0-9]{{2}}"
    http-check connect addr {ip} port {port}
    http-check set-var(check.path) "str(/req3)"
    http-check send meth GET uri-lf "%[var(check.path)]"
    http-check expect rstatus "^2[0-9]{{2}}"
    http-check connect addr {ip} port {port}
    http-check unset-var(check.path)
    http-check send meth GET uri-lf "%[var(check.path)]" body-lf "health-check on %[be_name]-%[srv_name]"
    server srv {dead_addr} check inter 200ms rise 1 fall 1
"#,
        ip = s4_addr.ip(),
        port = s4_addr.port(),
    );

    let proxy = spawn_proxy(&cfg);
    let started = Instant::now();
    loop {
        let count = seen4.lock().expect("lock").len();
        let st = server_status(&proxy.sock, "be4", "srv");
        if count >= 4 && st.as_deref() == Some("UP") {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timed out waiting for 4 requests and UP state; count={count}, status={st:?}"
        );
        thread::sleep(Duration::from_millis(20));
    }

    let reqs = seen4.lock().expect("lock").clone();
    assert!(reqs.len() >= 4, "expected at least 4 requests, got {}", reqs.len());

    // First 4 requests form one complete check sequence in order.
    assert!(reqs[0].starts_with("GET /req1 HTTP/1.1\r\n"), "req0: {:?}", reqs[0]);
    assert!(reqs[0].contains("x-test: server=srv\r\n"), "req0: {:?}", reqs[0]);
    assert!(reqs[0].contains("x-haproxy-server-state: "), "req0: {:?}", reqs[0]);

    assert!(reqs[1].starts_with("GET /req2 HTTP/1.1\r\n"), "req1: {:?}", reqs[1]);
    assert!(reqs[1].contains("x-test: server=\r\n"), "req1: {:?}", reqs[1]);
    assert!(reqs[1].contains("content-length: 17\r\n"), "req1: {:?}", reqs[1]);
    assert!(reqs[1].ends_with("\r\n\r\nhealth-check body"), "req1: {:?}", reqs[1]);

    assert!(reqs[2].starts_with("GET /req3 HTTP/1.0\r\n"), "req2: {:?}", reqs[2]);
    assert!(!reqs[2].contains("x-test:"), "req2: {:?}", reqs[2]);

    assert!(reqs[3].starts_with("GET / HTTP/1.0\r\n"), "req3: {:?}", reqs[3]);
    assert!(!reqs[3].contains("x-test:"), "req3: {:?}", reqs[3]);
    assert!(reqs[3].contains("content-length: 23\r\n"), "req3: {:?}", reqs[3]);
    assert!(reqs[3].ends_with("\r\n\r\nhealth-check on be4-srv"), "req3: {:?}", reqs[3]);
}

#[test]
fn http_check_sequence_stops_on_failed_expect() {
    let (s1_addr, seen1) = spawn_capture_server(vec!["200 OK"]);
    let (s2_addr, seen2) = spawn_capture_server(vec!["503 Service Unavailable"]);
    let (s3_addr, seen3) = spawn_capture_server(vec!["200 OK"]);
    let fe_addr = common::reserve_addr();

    let cfg = format!(
        r#"global
    stats socket {{SOCK}} mode 600 level admin
defaults
    mode http
    timeout client 5s
    timeout server 5s
    timeout connect 5s
backend be_fail
    option httpchk
    http-check connect addr {ip1}:{port1}
    http-check send meth GET uri /step1 ver HTTP/1.1
    http-check expect status 200
    http-check connect addr {ip2} port {port2}
    http-check send meth GET uri /step2 ver HTTP/1.1
    http-check expect status 200
    http-check connect addr {ip3}:{port3}
    http-check send meth GET uri /step3 ver HTTP/1.1
    http-check expect status 200
    server srv {fe_addr} check inter 200ms rise 1 fall 1
"#,
        ip1 = s1_addr.ip(),
        port1 = s1_addr.port(),
        ip2 = s2_addr.ip(),
        port2 = s2_addr.port(),
        ip3 = s3_addr.ip(),
        port3 = s3_addr.port(),
    );

    let proxy = spawn_proxy(&cfg);
    let started = Instant::now();
    loop {
        let c1 = seen1.lock().expect("lock").len();
        let c2 = seen2.lock().expect("lock").len();
        let st = server_status(&proxy.sock, "be_fail", "srv");
        if c1 >= 1 && c2 >= 1 && st.as_deref() == Some("DOWN") {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timed out waiting for failed check; c1={c1}, c2={c2}, status={st:?}"
        );
        thread::sleep(Duration::from_millis(20));
    }

    assert_eq!(seen3.lock().expect("lock").len(), 0, "step3 must not run after step2 failed expect");
}

#[test]
fn http_check_connect_send_proxy() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv_addr = listener.local_addr().expect("addr");
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let rec = Arc::clone(&seen);
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let _ = c.set_read_timeout(Some(Duration::from_millis(500)));
            let mut data = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n) = c.read(&mut buf) {
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
                if data.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            if !data.is_empty() {
                rec.lock().expect("lock").push(String::from_utf8_lossy(&data).into_owned());
            }
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        }
    });

    let cfg = format!(
        r#"global
    stats socket {{SOCK}} mode 600 level admin
defaults
    mode http
    timeout client 5s
    timeout server 5s
    timeout connect 5s
backend be_pp
    option httpchk
    http-check connect addr {ip}:{port} send-proxy
    http-check send meth GET uri /pp ver HTTP/1.1
    server srv {ip}:{port} check inter 200ms rise 1 fall 1
"#,
        ip = srv_addr.ip(),
        port = srv_addr.port(),
    );

    let proxy = spawn_proxy(&cfg);
    let started = Instant::now();
    loop {
        let count = seen.lock().expect("lock").len();
        let st = server_status(&proxy.sock, "be_pp", "srv");
        if count >= 1 && st.as_deref() == Some("UP") {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timed out waiting for PROXY check; count={count}, status={st:?}"
        );
        thread::sleep(Duration::from_millis(20));
    }

    let reqs = seen.lock().expect("lock").clone();
    assert!(reqs[0].starts_with("PROXY TCP4 "), "expected PROXY v1 header, got {:?}", reqs[0]);
    assert!(reqs[0].contains("\r\nGET /pp HTTP/1.1\r\n"), "got {:?}", reqs[0]);
}

#[test]
fn http_check_option_httpchk_with_host() {
    let (srv_addr, seen) = spawn_capture_server(vec!["200 OK"]);
    let cfg = format!(
        r#"global
    stats socket {{SOCK}} mode 600 level admin
defaults
    mode http
    timeout client 5s
    timeout server 5s
    timeout connect 5s
backend be_host
    option httpchk GET /status HTTP/1.1 www.haproxy.org
    server srv {ip}:{port} check inter 200ms rise 1 fall 1
"#,
        ip = srv_addr.ip(),
        port = srv_addr.port(),
    );

    let proxy = spawn_proxy(&cfg);
    let started = Instant::now();
    loop {
        let count = seen.lock().expect("lock").len();
        let st = server_status(&proxy.sock, "be_host", "srv");
        if count >= 1 && st.as_deref() == Some("UP") {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timed out waiting for httpchk host; count={count}, status={st:?}"
        );
        thread::sleep(Duration::from_millis(20));
    }

    let reqs = seen.lock().expect("lock").clone();
    assert!(reqs[0].starts_with("GET /status HTTP/1.1\r\n"), "got {:?}", reqs[0]);
    assert!(reqs[0].contains("host: www.haproxy.org\r\n"), "got {:?}", reqs[0]);
}
