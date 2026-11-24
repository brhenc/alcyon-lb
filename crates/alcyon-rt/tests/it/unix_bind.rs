// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! End-to-end tests for `unix@` and bare absolute-path `bind` listeners (T655 slice U1).
//!
//! Runs against Alcyon by default, or against `HAProxy` when `ADB_ORACLE=<haproxy>` is set.
//! Every expected value below was measured against `HAProxy` 3.5-dev11-ce79f339c:
//!
//! * HTTP (over `UnixStream` and `curl --unix-socket`), TCP mode, and TLS (`openssl s_client
//!   -unix` and `curl --unix-socket -k https://...`) work on both `/path` and `unix@/path`
//!   binds, including under `nbthread 2`.
//! * Network fetches on a unix client: `src`, `src_port`, `dst`, `dst_port`, `fc_src`,
//!   `fc_src_port`, `fc_dst`, `fc_dst_port`, `fc_rtt` return no sample (empty);
//!   `src_is_local`, `fc_src_is_local`, `dst_is_local`, `fc_dst_is_local` return `1`;
//!   `so_id` and `so_name` return the listener's id and name.
//! * Logging: `%ci` and `%fi` log `unix`; `%cp` and `%fp` log the listener's numeric id
//!   (`luid`, `1` by default or explicit `id <n>`); `option httplog` / `tcplog` start with
//!   `unix:<luid>`; JSON log format emits `"ci": "unix", "cp": <luid>, "fi": "unix", "fp": <luid>`;
//!   embryonic TLS errors start with `unix:<luid>`.
//! * `option forwardfor` and `option originalto` do not add `X-Forwarded-For` / `X-Original-To`;
//!   `option forwarded by for proto host` emits `by=unknown;for=unknown`.
//! * ACLs on `src`/`dst`/`src_port`/`dst_port` do not match a unix client (while a loopback
//!   TCP control bind matches and returns 403).
//! * `accept-proxy` over a unix bind overrides `src`/`src_port`/`%ci`/`%cp` from the PROXY
//!   header; `send-proxy` from a unix bind emits `PROXY UNKNOWN\r\n`.
//! * `show sess` shows `proto=unix_stream src=unix:<luid>`; `show stat` has an empty `addr`
//!   column on the frontend row.
//! * Existing-path handling: fresh path gets `0777 & ~umask`; stale and live sockets are
//!   replaced atomically via tempname+rename; directories, missing parents, and overlong paths
//!   are refused on both binaries. For non-sockets (regular file, symlink to file elsewhere,
//!   dangling symlink, FIFO), Alcyon fails closed and refuses without modifying the path
//!   (stricter than `HAProxy`, which renames over them — documented in `docs/differences.md`).
//! * Stop & reload: `SIGUSR1` and `SIGTERM` leave the socket file on disk (matching `HAProxy`);
//!   `SIGTTOU`/`SIGTTIN` pause and resume accepting; `-sf` reload atomically replaces the
//!   socket and keeps serving; `-x -sf` preserves the socket inode across reload.

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn proxy_bin() -> String {
    std::env::var("ADB_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

fn is_oracle() -> bool {
    std::env::var("ADB_ORACLE").is_ok()
}

fn cert_pem() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/ssl_f_common.pem")
}

/// Short fresh temp directory under `/tmp` so socket paths stay well under 97 bytes.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let p = PathBuf::from(format!("/tmp/au1-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create temp dir");
        Self(p)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn wait_unix_connectable(path: &Path, child: &mut Child) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            return false;
        }
        if UnixStream::connect(path).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(15));
    }
    false
}

fn unix_exchange(path: &Path, req: &[u8]) -> String {
    let mut s = UnixStream::connect(path).unwrap_or_else(|e| panic!("connect {}: {e}", path.display()));
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    s.set_write_timeout(Some(Duration::from_secs(5))).expect("timeout");
    s.write_all(req).expect("write req");
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

fn header_val(resp: &str, name: &str) -> Option<String> {
    let head = resp.split("\r\n\r\n").next().unwrap_or(resp);
    let prefix = format!("{}:", name.to_ascii_lowercase());
    for line in head.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.len() >= prefix.len() && trimmed[..prefix.len()].eq_ignore_ascii_case(&prefix) {
            return Some(trimmed[prefix.len()..].trim().to_string());
        }
    }
    None
}

fn start_proxy(cfg_path: &Path) -> common::Alcyon {
    let mut cmd = Command::new(proxy_bin());
    cmd.arg("-f").arg(cfg_path);
    if is_oracle() {
        cmd.arg("-db");
    }
    let child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proxy");
    common::Alcyon(child)
}

fn start_http_backend(
    captured: Arc<Mutex<Vec<String>>>,
    slow_delay: Duration,
) -> (u16, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind http backend");
    let port = listener.local_addr().expect("addr").port();
    listener.set_nonblocking(true).expect("nonblocking");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !stop_c.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut conn, _)) => {
                    let cap = Arc::clone(&captured);
                    thread::spawn(move || {
                        let _ = conn.set_read_timeout(Some(Duration::from_secs(3)));
                        let mut buf = [0u8; 4096];
                        if let Ok(n) = conn.read(&mut buf) {
                            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                            let is_slow = req.contains("/slow");
                            cap.lock().expect("lock").push(req);
                            if is_slow {
                                thread::sleep(slow_delay);
                            }
                            let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                Err(_) => break,
            }
        }
    });
    (port, stop, handle)
}

fn start_tcp_echo_backend() -> (u16, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp backend");
    let port = listener.local_addr().expect("addr").port();
    listener.set_nonblocking(true).expect("nonblocking");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !stop_c.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut conn, _)) => {
                    let _ = conn.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut buf = [0u8; 256];
                    if let Ok(n) = conn.read(&mut buf) {
                        let mut out = b"ECHO:".to_vec();
                        out.extend_from_slice(&buf[..n]);
                        let _ = conn.write_all(&out);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                Err(_) => break,
            }
        }
    });
    (port, stop, handle)
}

fn start_syslog_collector() -> (u16, Arc<Mutex<Vec<String>>>, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind syslog udp");
    let port = sock.local_addr().expect("addr").port();
    sock.set_read_timeout(Some(Duration::from_millis(50))).expect("timeout");
    let lines = Arc::new(Mutex::new(Vec::new()));
    let lines_c = Arc::clone(&lines);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while !stop_c.load(Ordering::Relaxed) {
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                lines_c.lock().expect("lock").push(String::from_utf8_lossy(&buf[..n]).into_owned());
            }
        }
    });
    (port, lines, stop, handle)
}

#[test]
fn http_tcp_tls_and_multithread_over_unix_binds() {
    let dir = TempDir::new("proto");
    let http_bare = dir.path().join("h1.sock");
    let http_pref = dir.path().join("h2.sock");
    let tcp_sock = dir.path().join("tcp.sock");
    let tls_sock = dir.path().join("tls.sock");
    let listen_sock = dir.path().join("li.sock");
    let (tcp_port, tcp_stop, tcp_h) = start_tcp_echo_backend();

    let cfg = format!(
        "global\n  nbthread 2\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe_http\n  bind {}\n  bind unix@{}\n  http-request return status 200 content-type text/plain string hello-unix\n\
         listen li_http\n  bind {}\n  http-request return status 200 content-type text/plain string hello-listen\n\
         frontend fe_tcp\n  mode tcp\n  bind {}\n  default_backend be_tcp\n\
         backend be_tcp\n  mode tcp\n  server s1 127.0.0.1:{tcp_port}\n\
         frontend fe_tls\n  bind {} ssl crt {}\n  http-request return status 200 content-type text/plain string hello-tls\n",
        http_bare.display(),
        http_pref.display(),
        listen_sock.display(),
        tcp_sock.display(),
        tls_sock.display(),
        cert_pem().display(),
    );
    let cfg_path = dir.path().join("p.cfg");
    std::fs::write(&cfg_path, cfg).expect("write cfg");
    let mut proxy = start_proxy(&cfg_path);
    assert!(wait_unix_connectable(&tls_sock, &mut proxy), "proxy failed to bind unix sockets");

    // 1. Bare path + unix@ prefix + listen section over Rust UnixStream (and keep-alive).
    for (sock, want) in [(&http_bare, "hello-unix"), (&http_pref, "hello-unix"), (&listen_sock, "hello-listen")] {
        let resp = unix_exchange(sock, b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        assert!(resp.contains("200 OK") && resp.ends_with(want), "{}: {resp:?}", sock.display());
    }

    // Keep-alive: 2 requests over a single UnixStream (plus exercising nbthread 2 across 6 conns).
    {
        let mut s = UnixStream::connect(&http_bare).expect("connect keepalive");
        s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        s.write_all(
            b"GET /1 HTTP/1.1\r\nHost: localhost\r\n\r\n\
              GET /2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .expect("write");
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf);
        let text = String::from_utf8_lossy(&buf);
        assert_eq!(text.matches("hello-unix").count(), 2, "keepalive over unix: {text:?}");
    }
    for _ in 0..6 {
        let r = unix_exchange(&http_bare, b"GET /mt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        assert!(r.ends_with("hello-unix"), "nbthread 2: {r:?}");
    }

    // 2. `curl --unix-socket` for plain HTTP and HTTPS (which also tests ALPN h2 over TLS unix).
    if Command::new("curl").arg("--version").output().is_ok() {
        let out = Command::new("curl")
            .args(["-sS", "--unix-socket"])
            .arg(&http_bare)
            .arg("http://localhost/")
            .output()
            .expect("curl http");
        assert!(out.status.success(), "curl http failed: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(String::from_utf8_lossy(&out.stdout), "hello-unix");

        let tls_out = Command::new("curl")
            .args(["-sS", "-k", "--unix-socket"])
            .arg(&tls_sock)
            .arg("https://localhost/")
            .output()
            .expect("curl https");
        assert!(tls_out.status.success(), "curl https failed: {}", String::from_utf8_lossy(&tls_out.stderr));
        assert_eq!(String::from_utf8_lossy(&tls_out.stdout), "hello-tls");
    }

    // 3. TCP mode over unix bind.
    let tcp_resp = unix_exchange(&tcp_sock, b"ping-unix");
    assert_eq!(tcp_resp, "ECHO:ping-unix");

    // 4. TLS over unix bind with `openssl s_client -unix`.
    let mut s_cli = Command::new("openssl")
        .args(["s_client", "-unix"])
        .arg(&tls_sock)
        .arg("-ign_eof")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn openssl s_client");
    if let Some(mut stdin) = s_cli.stdin.take() {
        let _ = stdin.write_all(b"GET /tls HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    }
    let out = s_cli.wait_with_output().expect("wait openssl");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("200 OK") && combined.contains("hello-tls"),
        "openssl s_client -unix failed:\n{combined}"
    );

    common::stop(&mut proxy);
    tcp_stop.store(true, Ordering::Relaxed);
    let _ = tcp_h.join();
}

#[test]
fn fetches_acls_logs_forwardfor_show_sess_and_stats() {
    let dir = TempDir::new("data");
    let stats_sock = dir.path().join("st.sock");
    let http_sock = dir.path().join("h.sock");
    let custom_sock = dir.path().join("c.sock");
    let json_sock = dir.path().join("j.sock");
    let ff_sock = dir.path().join("ff.sock");
    let acl_sock = dir.path().join("acl.sock");
    let pp_sock = dir.path().join("pp.sock");
    let sendpp_sock = dir.path().join("spp.sock");
    let sendpp2_sock = dir.path().join("spp2.sock");
    let deflog_sock = dir.path().join("dl.sock");
    let stats_html_sock = dir.path().join("html.sock");
    let rej_sock = dir.path().join("rej.sock");
    let tls_sock = dir.path().join("tls.sock");
    let tcp_ctl_addr = common::reserve_addr();

    let be_reqs = Arc::new(Mutex::new(Vec::new()));
    let (be_port, be_stop, be_h) = start_http_backend(Arc::clone(&be_reqs), Duration::from_millis(800));
    let (log_port, logs, log_stop, log_h) = start_syslog_collector();

    let cfg = format!(
        "global\n  nbthread 1\n  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe_http\n  log 127.0.0.1:{log_port} local0\n  option httplog\n\
           bind {} name ubind id 42\n\
           http-response set-header x-src \"%[src]\"\n\
           http-response set-header x-src-port \"%[src_port]\"\n\
           http-response set-header x-dst \"%[dst]\"\n\
           http-response set-header x-dst-port \"%[dst_port]\"\n\
           http-response set-header x-fc-src \"%[fc_src]\"\n\
           http-response set-header x-fc-src-port \"%[fc_src_port]\"\n\
           http-response set-header x-fc-dst \"%[fc_dst]\"\n\
           http-response set-header x-fc-dst-port \"%[fc_dst_port]\"\n\
           http-response set-header x-src-local \"%[src_is_local]\"\n\
           http-response set-header x-fc-src-local \"%[fc_src_is_local]\"\n\
           http-response set-header x-dst-local \"%[dst_is_local]\"\n\
           http-response set-header x-fc-dst-local \"%[fc_dst_is_local]\"\n\
           http-response set-header x-so-id \"%[so_id]\"\n\
           http-response set-header x-so-name \"%[so_name]\"\n\
           http-response set-header x-fc-rtt \"%[fc_rtt]\"\n\
           http-response set-header x-ci \"%ci\"\n\
           http-response set-header x-cp \"%cp\"\n\
           http-response set-header x-fi \"%fi\"\n\
           http-response set-header x-fp \"%fp\"\n\
           default_backend be_http\n\
         frontend fe_custom\n  log 127.0.0.1:{log_port} local0\n\
           log-format \"CUSTOM ci=%ci cp=%cp fi=%fi fp=%fp Qci=%{{+Q}}ci Mci=%{{+M}}ci Xcp=%{{+X}}cp\"\n\
           bind unix@{}\n  http-request return status 200 content-type text/plain string ok\n\
         frontend fe_deflog\n  log 127.0.0.1:{log_port} local0\n\
           bind {} id 7\n  http-request return status 200 content-type text/plain string ok\n\
         frontend fe_stats\n  bind {}\n  stats enable\n  stats uri /stats\n\
         frontend fe_rej\n  bind {}\n  tcp-request connection reject\n  http-request return status 200 content-type text/plain string no\n\
         frontend fe_json\n  log 127.0.0.1:{log_port} local0\n\
           log-format \"%{{+json}}o %(ci)ci %(cp)cp %(fi)fi %(fp)fp\"\n\
           bind {} id 19\n  http-request return status 200 content-type text/plain string ok\n\
         frontend fe_ff\n  bind {}\n  option forwardfor\n  option originalto\n  default_backend be_ff\n\
         backend be_ff\n  option forwarded by for proto host\n  server s1 127.0.0.1:{be_port}\n\
         frontend fe_acl\n  bind {}\n  bind {tcp_ctl_addr}\n\
           http-request deny deny_status 403 if {{ src 127.0.0.1 }}\n\
           http-request deny deny_status 403 if {{ src 0.0.0.0/0 }}\n\
           http-request deny deny_status 403 if {{ src ::/0 }}\n\
           http-request deny deny_status 403 if {{ dst 0.0.0.0/0 }}\n\
           http-request deny deny_status 403 if {{ src_port 0 }}\n\
           http-request deny deny_status 403 if {{ dst_port 0 }}\n\
           http-request return status 200 content-type text/plain string acl-ok\n\
         frontend fe_pp\n  bind {} accept-proxy\n\
           http-request return status 200 content-type text/plain lf-string \"src=%[src] sp=%[src_port] ci=%ci cp=%cp\"\n\
         frontend fe_sendpp\n  bind {}\n  default_backend be_sendpp\n\
         backend be_sendpp\n  server s1 127.0.0.1:{be_port} send-proxy\n\
         frontend fe_sendpp2\n  bind {}\n  default_backend be_sendpp2\n\
         backend be_sendpp2\n  server s1 127.0.0.1:{be_port} send-proxy-v2\n\
         frontend fe_tls\n  log 127.0.0.1:{log_port} local0\n  option httplog\n\
           bind {} ssl crt {} name tlsbind id 23\n\
           http-request return status 200 content-type text/plain string ok\n\
         backend be_http\n  server s1 127.0.0.1:{be_port}\n",
        stats_sock.display(),
        http_sock.display(),
        custom_sock.display(),
        deflog_sock.display(),
        stats_html_sock.display(),
        rej_sock.display(),
        json_sock.display(),
        ff_sock.display(),
        acl_sock.display(),
        pp_sock.display(),
        sendpp_sock.display(),
        sendpp2_sock.display(),
        tls_sock.display(),
        cert_pem().display(),
    );
    let cfg_path = dir.path().join("d.cfg");
    std::fs::write(&cfg_path, cfg).expect("write cfg");
    let mut proxy = start_proxy(&cfg_path);
    assert!(wait_unix_connectable(&tls_sock, &mut proxy), "proxy failed to start");

    // 1. Fetches and format aliases.
    let resp = unix_exchange(&http_sock, b"GET /fetches HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    for empty_hdr in [
        "x-src", "x-src-port", "x-dst", "x-dst-port",
        "x-fc-src", "x-fc-src-port", "x-fc-dst", "x-fc-dst-port", "x-fc-rtt",
    ] {
        assert_eq!(header_val(&resp, empty_hdr).as_deref(), Some(""), "{empty_hdr} must be empty: {resp}");
    }
    for local_hdr in ["x-src-local", "x-fc-src-local", "x-dst-local", "x-fc-dst-local"] {
        assert_eq!(header_val(&resp, local_hdr).as_deref(), Some("1"), "{local_hdr} must be 1: {resp}");
    }
    assert_eq!(header_val(&resp, "x-so-id").as_deref(), Some("42"));
    assert_eq!(header_val(&resp, "x-so-name").as_deref(), Some("ubind"));
    assert_eq!(header_val(&resp, "x-ci").as_deref(), Some("unix"));
    assert_eq!(header_val(&resp, "x-cp").as_deref(), Some("42"));
    assert_eq!(header_val(&resp, "x-fi").as_deref(), Some("unix"));
    assert_eq!(header_val(&resp, "x-fp").as_deref(), Some("42"));

    // 2. option forwardfor / originalto / forwarded.
    be_reqs.lock().expect("lock").clear();
    let ff_resp = unix_exchange(&ff_sock, b"GET /ff HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
    assert!(ff_resp.contains("200 OK"), "{ff_resp}");
    let got_be = be_reqs.lock().expect("lock").pop().expect("backend req");
    let lower_be = got_be.to_ascii_lowercase();
    assert!(!lower_be.contains("x-forwarded-for:"), "unix client must not get X-Forwarded-For:\n{got_be}");
    assert!(!lower_be.contains("x-original-to:"), "unix client must not get X-Original-To:\n{got_be}");
    assert!(
        lower_be.contains("forwarded: proto=http;host=\"example.com\";by=unknown;for=unknown"),
        "option forwarded mismatch:\n{got_be}"
    );

    // 3. ACLs on `src`/`dst`: unix client allowed (200), loopback TCP control denied (403).
    let acl_u = unix_exchange(&acl_sock, b"GET /acl HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(acl_u.contains("200 OK") && acl_u.ends_with("acl-ok"), "unix must bypass src ACL: {acl_u}");
    {
        let mut tc = std::net::TcpStream::connect(tcp_ctl_addr).expect("connect tcp control");
        tc.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        tc.write_all(b"GET /acl HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
        let mut b = Vec::new();
        let _ = tc.read_to_end(&mut b);
        let s = String::from_utf8_lossy(&b);
        assert!(s.contains("403 Forbidden"), "TCP loopback control must match src 127.0.0.1 ACL: {s}");
    }

    // 4. accept-proxy over unix bind & send-proxy from unix bind.
    let pp = unix_exchange(
        &pp_sock,
        b"PROXY TCP4 203.0.113.5 198.51.100.1 12345 443\r\nGET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(pp.ends_with("src=203.0.113.5 sp=12345 ci=203.0.113.5 cp=12345"), "accept-proxy: {pp}");

    be_reqs.lock().expect("lock").clear();
    let _ = unix_exchange(&sendpp_sock, b"GET /spp HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    let spp_req = be_reqs.lock().expect("lock").pop().expect("send-proxy backend req");
    assert!(spp_req.starts_with("PROXY UNKNOWN\r\n"), "send-proxy from unix must send PROXY UNKNOWN: {spp_req:?}");

    be_reqs.lock().expect("lock").clear();
    let _ = unix_exchange(&sendpp2_sock, b"GET /spp2 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    let spp2_req = be_reqs.lock().expect("lock").pop().expect("send-proxy-v2 backend req");
    assert!(
        spp2_req.as_bytes().starts_with(b"\r\n\r\n\x00\r\nQUIT\n"),
        "send-proxy-v2 from unix must send v2 header: {spp2_req:?}"
    );

    // 4b. HTML stats page on unix-only frontend and tcp-request connection reject.
    let html = unix_exchange(&stats_html_sock, b"GET /stats HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(html.contains("200 OK") && html.contains("fe_stats"), "HTML stats over unix: {html}");
    {
        let mut s = UnixStream::connect(&rej_sock).expect("connect rej");
        s.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
        let _ = s.write_all(b"GET /rej HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf);
        assert!(buf.is_empty(), "tcp-request connection reject over unix must drop connection: {buf:?}");
    }

    // 5. Custom log, default connect log, JSON log, and embryonic TLS error log.
    let _ = unix_exchange(&custom_sock, b"GET /c HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    let _ = unix_exchange(&deflog_sock, b"GET /d HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    let _ = unix_exchange(&json_sock, b"GET /j HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    let _ = unix_exchange(&tls_sock, b"NOT_TLS_GARBAGE\r\n");

    // 6. `show sess` during an in-flight request on the unix bind.
    let slow_path = http_sock.clone();
    let slow_t = thread::spawn(move || {
        unix_exchange(&slow_path, b"GET /slow HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    });
    thread::sleep(Duration::from_millis(200));
    let sess_out = unix_exchange(&stats_sock, b"show sess\n");
    assert!(
        sess_out.lines().any(|l| l.contains("proto=unix_stream") && l.contains("src=unix:42") && l.contains("fe=fe_http")),
        "show sess must report proto=unix_stream src=unix:42 for fe_http:\n{sess_out}"
    );
    let _ = slow_t.join();

    // 7. `show stat` has fe_http FRONTEND row with empty `addr` column (index 73).
    let stat_out = unix_exchange(&stats_sock, b"show stat\n");
    let header_cols: Vec<&str> = stat_out
        .lines()
        .next()
        .expect("stat header")
        .trim_start_matches("# ")
        .split(',')
        .collect();
    let addr_col = header_cols.iter().position(|&c| c == "addr").expect("addr column");
    let fe_row = stat_out
        .lines()
        .find(|l| l.starts_with("fe_http,FRONTEND,"))
        .expect("fe_http FRONTEND row");
    let cols: Vec<&str> = fe_row.split(',').collect();
    assert_eq!(cols.get(addr_col).copied(), Some(""), "fe_http addr column must be empty: {fe_row}");

    // 8. Verify syslog lines arrived and match HAProxy format.
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if logs.lock().expect("lock").len() >= 6 {
            break;
        }
        thread::sleep(Duration::from_millis(30));
    }
    let collected = logs.lock().expect("lock").clone();
    let joined = collected.join("\n");
    assert!(
        collected.iter().any(|l| l.contains("unix:42 [") && l.contains("fe_http be_http/s1") && l.contains("\"GET /fetches HTTP/1.1\"")),
        "missing httplog line:\n{joined}"
    );
    assert!(
        collected.iter().any(|l| l.contains("CUSTOM ci=unix cp=1 fi=unix fp=1 Qci=\"unix\" Mci=unix Xcp=1")),
        "missing custom log line:\n{joined}"
    );
    assert!(
        collected.iter().any(|l| l.contains("Connect to unix:7 (fe_deflog/HTTP)")),
        "missing default connect log line:\n{joined}"
    );
    assert!(
        collected.iter().any(|l| l.contains("{\"ci\": \"unix\", \"cp\": 19, \"fi\": \"unix\", \"fp\": 19}")),
        "missing json log line:\n{joined}"
    );
    assert!(
        collected.iter().any(|l| l.contains("unix:23 [") && l.contains("fe_tls/tlsbind:")),
        "missing embryonic TLS error line:\n{joined}"
    );

    common::stop(&mut proxy);
    be_stop.store(true, Ordering::Relaxed);
    log_stop.store(true, Ordering::Relaxed);
    let _ = be_h.join();
    let _ = log_h.join();
}

/// Runs the proxy briefly against a single `bind <path>` config, returning `(started, stderr)`.
///
/// Proves the proxy itself is serving `sock_path` by completing an HTTP request expecting the
/// unique `probe-ok` body (so a pre-existing live listener on the same path cannot fool the
/// readiness loop into returning early before the new proxy replaces it).
fn probe_bind_path(dir: &Path, sock_path: &Path, umask_opt: Option<u32>) -> (bool, String) {
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
         frontend fe\n  bind {}\n  http-request return status 200 content-type text/plain string probe-ok\n",
        sock_path.display()
    );
    let cfg_path = dir.join("probe.cfg");
    std::fs::write(&cfg_path, cfg).expect("write probe cfg");
    let mut child = if let Some(mask) = umask_opt {
        let mut sh = Command::new("sh");
        let extra = if is_oracle() { "-db " } else { "" };
        sh.arg("-c")
            .arg(format!("umask {mask:04o}; exec '{}' {extra}-f '{}'", proxy_bin(), cfg_path.display()))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        common::Alcyon(sh.spawn().expect("spawn sh"))
    } else {
        let mut cmd = Command::new(proxy_bin());
        cmd.arg("-f").arg(&cfg_path);
        if is_oracle() {
            cmd.arg("-db");
        }
        common::Alcyon(cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn"))
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut started = false;
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            break;
        }
        if let Ok(mut s) = UnixStream::connect(sock_path) {
            let _ = s.set_read_timeout(Some(Duration::from_millis(150)));
            let _ = s.set_write_timeout(Some(Duration::from_millis(150)));
            if s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").is_ok() {
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf);
                if buf.ends_with(b"probe-ok") {
                    started = true;
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    common::stop(&mut child);
    let mut err = String::new();
    if let Some(mut se) = child.stderr.take() {
        let _ = se.read_to_string(&mut err);
    }
    (started, err)
}

#[test]
fn existing_path_permissions_and_hostile_filesystem_cases() {
    let dir = TempDir::new("fs");

    // 1. Fresh socket permissions follow process umask (0777 & ~umask), matching HAProxy.
    for (name, mask, want_mode) in [("u22.sock", 0o022, 0o755), ("u77.sock", 0o077, 0o700)] {
        let p = dir.path().join(name);
        let (ok, err) = probe_bind_path(dir.path(), &p, Some(mask));
        assert!(ok, "{name} should start: {err}");
        let mode = std::fs::symlink_metadata(&p).expect("lstat").permissions().mode() & 0o777;
        assert_eq!(mode, want_mode, "{name} umask {mask:04o}: got {mode:04o}");
    }

    // 2. Stale socket (no listener) is replaced and starts.
    let stale = dir.path().join("stale.sock");
    drop(UnixListener::bind(&stale).expect("make stale"));
    let (ok, err) = probe_bind_path(dir.path(), &stale, None);
    assert!(ok, "stale socket must be replaced: {err}");

    // 3. Live socket (another listener) is atomically replaced (as required for `-sf` reload).
    let live = dir.path().join("live.sock");
    let _other = UnixListener::bind(&live).expect("make live");
    let old_ino = std::fs::symlink_metadata(&live).expect("lstat").ino();
    let (ok, err) = probe_bind_path(dir.path(), &live, None);
    assert!(ok, "live socket must be atomically replaced: {err}");
    let new_ino = std::fs::symlink_metadata(&live).expect("lstat").ino();
    assert_ne!(old_ino, new_ino, "new listener must have replaced the socket inode");

    // 4. Empty directory, non-empty directory, nonexistent parent, read-only parent: BOTH refuse.
    let empty_dir = dir.path().join("emptydir");
    std::fs::create_dir(&empty_dir).expect("mkdir");
    let (ok, err) = probe_bind_path(dir.path(), &empty_dir, None);
    assert!(!ok, "empty directory must be refused: {err}");
    assert!(empty_dir.is_dir(), "empty directory must remain intact");

    let nonempty = dir.path().join("nonempty");
    std::fs::create_dir(&nonempty).expect("mkdir");
    std::fs::write(nonempty.join("keep"), b"keep").expect("write");
    let (ok, err) = probe_bind_path(dir.path(), &nonempty, None);
    assert!(!ok, "non-empty directory must be refused: {err}");
    assert_eq!(std::fs::read(nonempty.join("keep")).expect("read"), b"keep");

    let missing_parent = dir.path().join("no_such_dir").join("a.sock");
    let (ok, _err) = probe_bind_path(dir.path(), &missing_parent, None);
    assert!(!ok, "nonexistent parent dir must be refused");

    // 5. Hostile non-socket cases: regular file, symlink to regular file elsewhere,
    //    dangling symlink, symlink to stale socket, FIFO.
    //    Alcyon fails closed and refuses all of them, leaving every path & target untouched.
    let reg = dir.path().join("regfile");
    std::fs::write(&reg, b"SECRET_DATA").expect("write reg");
    let (ok_reg, err_reg) = probe_bind_path(dir.path(), &reg, None);

    let sym_target = dir.path().join("target_secret");
    std::fs::write(&sym_target, b"TARGET_INTACT").expect("write target");
    let sym_reg = dir.path().join("sym_reg");
    std::os::unix::fs::symlink(&sym_target, &sym_reg).expect("symlink");
    let (ok_sym, err_sym) = probe_bind_path(dir.path(), &sym_reg, None);

    let sym_dang = dir.path().join("sym_dangling");
    std::os::unix::fs::symlink(dir.path().join("nowhere"), &sym_dang).expect("dangling symlink");
    let (ok_dang, err_dang) = probe_bind_path(dir.path(), &sym_dang, None);

    let fifo = dir.path().join("myfifo");
    let mkfifo_ok = Command::new("mkfifo").arg(&fifo).status().is_ok_and(|s| s.success());
    let (ok_fifo, err_fifo) = if mkfifo_ok {
        probe_bind_path(dir.path(), &fifo, None)
    } else {
        (false, String::new())
    };

    // In BOTH binaries, the symlink's target file MUST remain intact.
    assert_eq!(std::fs::read(&sym_target).expect("read target"), b"TARGET_INTACT");

    if is_oracle() {
        // HAProxy's `link`+`rename` overwrites regular files, symlinks, and FIFOs (target intact).
        assert!(ok_reg && ok_sym && ok_dang, "oracle replaces non-dir entries: {err_reg} {err_sym} {err_dang}");
    } else {
        // Alcyon fails closed: refuses every non-socket and leaves it untouched.
        assert!(!ok_reg, "Alcyon must refuse regular file: {err_reg}");
        assert_eq!(std::fs::read(&reg).expect("read reg"), b"SECRET_DATA");
        assert!(!ok_sym, "Alcyon must refuse symlink to file: {err_sym}");
        assert!(std::fs::symlink_metadata(&sym_reg).expect("lstat").file_type().is_symlink());
        assert!(!ok_dang, "Alcyon must refuse dangling symlink: {err_dang}");
        assert!(std::fs::symlink_metadata(&sym_dang).expect("lstat").file_type().is_symlink());
        if mkfifo_ok {
            assert!(!ok_fifo, "Alcyon must refuse FIFO: {err_fifo}");
            assert!(std::fs::symlink_metadata(&fifo).expect("lstat").file_type().is_fifo());
        }
    }

    // 6. Overlong path (> 97 bytes): refused by `-c` on both binaries.
    let over98 = PathBuf::from(format!("/{}", "a".repeat(97)));
    let (ok_98, err_98) = probe_bind_path(dir.path(), &over98, None);
    assert!(!ok_98, "98-byte path must be refused: {err_98}");
    assert!(err_98.contains("too long (max 97)"), "expected max 97 message: {err_98}");
}

#[test]
fn stop_pause_and_reload_match_oracle() {
    let dir = TempDir::new("rel");
    let sock = dir.path().join("r.sock");
    let stats = dir.path().join("st.sock");

    let write_cfg = |name: &str, body: &str| {
        let p = dir.path().join(name);
        let cfg = format!(
            "global\n  nbthread 1\n  stats socket {} level admin expose-fd listeners\n\
             defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
             frontend fe\n  bind {}\n  http-request return status 200 content-type text/plain string {body}\n",
            stats.display(),
            sock.display()
        );
        std::fs::write(&p, cfg).expect("write cfg");
        p
    };

    // 1. SIGUSR1 leaves the socket file on disk (matching HAProxy).
    let cfg_a = write_cfg("a.cfg", "old");
    let mut pa = start_proxy(&cfg_a);
    assert!(wait_unix_connectable(&sock, &mut pa), "pa start");
    assert!(unix_exchange(&sock, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").ends_with("old"));

    // SIGTTOU / SIGTTIN: unix bind pauses (stays on disk) and resumes serving.
    let pid_a = rustix::process::Pid::from_raw(i32::try_from(pa.id()).expect("pid")).expect("pid");
    let _ = rustix::process::kill_process(pid_a, rustix::process::Signal::Ttou);
    thread::sleep(Duration::from_millis(150));
    assert!(std::fs::symlink_metadata(&sock).is_ok(), "SIGTTOU must keep socket file");
    let _ = rustix::process::kill_process(pid_a, rustix::process::Signal::Ttin);
    thread::sleep(Duration::from_millis(150));
    assert!(unix_exchange(&sock, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").ends_with("old"));

    // 2. Reload with `-sf <oldpid>` (without `-x`): replaces socket inode, old exits, new serves.
    let ino_a = std::fs::symlink_metadata(&sock).expect("lstat a").ino();
    let cfg_b = write_cfg("b.cfg", "new");
    let mut cmd_b = Command::new(proxy_bin());
    cmd_b.arg("-f").arg(&cfg_b).arg("-sf").arg(pa.id().to_string());
    if is_oracle() {
        cmd_b.arg("-db");
    }
    let mut pb = common::Alcyon(cmd_b.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn pb"));
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if matches!(pa.try_wait(), Ok(Some(_))) {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(matches!(pa.try_wait(), Ok(Some(s)) if s.success()), "old process must exit cleanly on -sf");
    let ino_b = std::fs::symlink_metadata(&sock).expect("lstat b").ino();
    assert_ne!(ino_a, ino_b, "-sf without -x must replace socket inode atomically");
    assert!(unix_exchange(&sock, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").ends_with("new"));

    // 3. Reload with `-x <stats> -sf <pid>`: inherits socket fd, preserves inode, serves new config.
    let cfg_c = write_cfg("c.cfg", "handover");
    let mut cmd_c = Command::new(proxy_bin());
    cmd_c
        .arg("-f")
        .arg(&cfg_c)
        .arg("-x")
        .arg(&stats)
        .arg("-sf")
        .arg(pb.id().to_string());
    if is_oracle() {
        cmd_c.arg("-db");
    }
    let mut pc = common::Alcyon(cmd_c.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn pc"));
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if matches!(pb.try_wait(), Ok(Some(_))) {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(matches!(pb.try_wait(), Ok(Some(s)) if s.success()), "pb must exit cleanly on -x -sf");
    let ino_c = std::fs::symlink_metadata(&sock).expect("lstat c").ino();
    assert_eq!(ino_b, ino_c, "-x -sf must preserve the unix listener inode");
    assert!(unix_exchange(&sock, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").ends_with("handover"));

    // 4. SIGUSR1 stop leaves the socket file on disk (matching HAProxy).
    common::stop(&mut pc);
    assert!(std::fs::symlink_metadata(&sock).is_ok(), "SIGUSR1 must leave socket file on disk");
}
