// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Server `observe` (`layer4` / `layer7`), `error-limit`, `on-error`, and check `addr`
//! (OBSERVE). Set `T281_ORACLE=/path/to/haproxy` to run against the HAProxy oracle.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn bin() -> String {
    std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

fn query(sock: &std::path::Path, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect stats");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = String::new();
    s.read_to_string(&mut out).expect("read");
    out
}

fn wait_ready(sock: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if UnixStream::connect(sock).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("stats socket {} never became ready", sock.display());
}

fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect front");
    s.set_read_timeout(Some(Duration::from_secs(3))).ok();
    write!(s, "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write req");
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    let status = buf
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    (status, buf)
}

/// Returns `show stat <be> 4 1 typed` column value for `col`.
fn stat_col(sock: &std::path::Path, be: &str, col: &str) -> String {
    let out = query(sock, &format!("show stat {be} 4 1 typed"));
    for line in out.lines() {
        // Format: S.<iid>.<sid>.<pid>.<field>.<tid>:<metrics_type>:<value_type>:<value>
        let mut parts = line.splitn(4, ':');
        let Some(lhs) = parts.next() else { continue };
        let _metrics_type = parts.next();
        let _value_type = parts.next();
        let Some(val) = parts.next() else { continue };
        let field = lhs.rsplit('.').nth(1).unwrap_or("");
        if field == col {
            return val.to_string();
        }
    }
    panic!("column {col} not found in show stat {be} 4 1 typed:\n{out}");
}

/// Returns fields of `show servers state <be>` for server `srv`.
fn server_state_fields(sock: &std::path::Path, be: &str, srv: &str) -> Vec<String> {
    let out = query(sock, &format!("show servers state {be}"));
    for line in out.lines() {
        if line.starts_with('#') || line == "1" || line.is_empty() {
            continue;
        }
        let fields: Vec<String> = line.split_whitespace().map(str::to_string).collect();
        if fields.get(3).map(String::as_str) == Some(srv) {
            return fields;
        }
    }
    panic!("server {srv} not found in show servers state {be}:\n{out}");
}

/// A sink listener that accepts connections and holds them open without replying.
fn spawn_sink() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind sink");
    let addr = listener.local_addr().expect("sink addr");
    thread::spawn(move || {
        let mut held = Vec::new();
        for s in listener.incoming() {
            let Ok(s) = s else { break };
            held.push(s);
        }
    });
    addr
}

/// An HTTP server that responds with `status` (atomic) to every request.
fn spawn_http_server(status: Arc<AtomicU16>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind server");
    let addr = listener.local_addr().expect("server addr");
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { break };
            let status = status.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let code = status.load(Ordering::Relaxed);
                let resp = format!(
                    "HTTP/1.1 {code} MSG\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    addr
}

fn spawn_proxy(cfg: &str) -> (tempfile::TempDir, std::path::PathBuf, Proc) {
    let dir = tempfile::TempDir::new().expect("tmp");
    let sock = dir.path().join("stats.sock");
    let cfg_path = dir.path().join("haproxy.cfg");
    let full = cfg.replace("__SOCK__", &sock.display().to_string());
    std::fs::write(&cfg_path, full).expect("write cfg");
    let child = Command::new(bin())
        .arg("-f")
        .arg(&cfg_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    wait_ready(&sock);
    (dir, sock, Proc(child))
}

#[test]
fn observe_layer7_and_layer4_mark_down() {
    let sink = spawn_sink();
    let status = Arc::new(AtomicU16::new(404));
    let srv = spawn_http_server(status.clone());
    let closed_port = common::reserve_addr().port();
    let front = common::reserve_addr();

    let cfg = format!(
        "global\n\
         \tstats socket __SOCK__ level admin\n\
         defaults\n\
         \tmode http\n\
         \toption httpchk GET /\n\
         \tretries 0\n\
         \ttimeout connect 2s\n\
         \ttimeout client 2s\n\
         \ttimeout server 2s\n\
         \ttimeout check 1h\n\
         frontend fe\n\
         \tbind {front}\n\
         \tuse_backend be4 if {{ path -m beg /l4 }}\n\
         \tdefault_backend be7\n\
         backend be7\n\
         \tid 7\n\
         \tserver s1 {srv} id 1 check addr {sink_ip} port {sink_port} inter 100ms observe layer7 error-limit 2 on-error mark-down\n\
         backend be4\n\
         \tid 4\n\
         \tserver s1 127.0.0.1:{closed_port} id 1 check addr {sink_ip} port {sink_port} inter 100ms observe layer4 error-limit 1 on-error mark-down\n",
        sink_ip = sink.ip(),
        sink_port = sink.port(),
    );
    let (_dir, sock, _proc) = spawn_proxy(&cfg);

    assert!(stat_col(&sock, "be7", "status").starts_with("UP"));
    assert!(stat_col(&sock, "be4", "status").starts_with("UP"));

    // 404 is valid in layer7, does not count as an error.
    let (code, _) = http_get(front, "/ok");
    assert_eq!(code, 404);
    assert!(stat_col(&sock, "be7", "status").starts_with("UP"));

    // First 500 -> error 1 of 2, still UP.
    status.store(500, Ordering::Relaxed);
    let (code, _) = http_get(front, "/ko");
    assert_eq!(code, 500);
    assert!(stat_col(&sock, "be7", "status").starts_with("UP"));

    // A 200 resets the consecutive error counter.
    status.store(200, Ordering::Relaxed);
    let (code, _) = http_get(front, "/ok");
    assert_eq!(code, 200);
    assert!(stat_col(&sock, "be7", "status").starts_with("UP"));

    // Now two consecutive 500s mark s1 DOWN with check_status HANA.
    status.store(500, Ordering::Relaxed);
    let (code, _) = http_get(front, "/ko");
    assert_eq!(code, 500);
    assert!(stat_col(&sock, "be7", "status").starts_with("UP"));

    let (code, _) = http_get(front, "/ko");
    assert_eq!(code, 500);
    assert_eq!(stat_col(&sock, "be7", "status"), "DOWN");
    let cs = stat_col(&sock, "be7", "check_status");
    assert!(cs == "HANA" || cs == "* HANA", "expected HANA check_status, got {cs:?}");

    // show servers state matches oracle: op_state=0 (STOPPED), check_status=4 (HANA),
    // check_result=2 (FAILED), check_health=0, check_addr/port=sink.
    let f7 = server_state_fields(&sock, "be7", "s1");
    assert_eq!(f7[5], "0", "srv_op_state: {f7:?}");
    assert_eq!(f7[10], "4", "srv_check_status (HANA=4): {f7:?}");
    assert_eq!(f7[11], "2", "srv_check_result (FAILED=2): {f7:?}");
    assert_eq!(f7[12], "0", "srv_check_health: {f7:?}");
    assert_eq!(f7[21], sink.port().to_string(), "srv_check_port: {f7:?}");
    assert_eq!(f7[22], sink.ip().to_string(), "srv_check_addr: {f7:?}");

    // Next request to be7 gets 503.
    let (code, _) = http_get(front, "/ko");
    assert_eq!(code, 503);

    // Layer4 backend: 1 connection error marks it DOWN.
    let (code, _) = http_get(front, "/l4");
    assert_eq!(code, 503);
    assert_eq!(stat_col(&sock, "be4", "status"), "DOWN");
    let cs4 = stat_col(&sock, "be4", "check_status");
    assert!(cs4 == "HANA" || cs4 == "* HANA", "expected HANA check_status, got {cs4:?}");
    let f4 = server_state_fields(&sock, "be4", "s1");
    assert_eq!(f4[5], "0", "be4 srv_op_state: {f4:?}");
    assert_eq!(f4[10], "4", "be4 srv_check_status: {f4:?}");

    let (code, _) = http_get(front, "/l4");
    assert_eq!(code, 503);
}

#[test]
fn observe_on_error_fail_check_and_sudden_death() {
    let sink = spawn_sink();
    let status = Arc::new(AtomicU16::new(500));
    let srv = spawn_http_server(status);
    let front = common::reserve_addr();

    let cfg = format!(
        "global\n\
         \tstats socket __SOCK__ level admin\n\
         defaults\n\
         \tmode http\n\
         \toption httpchk GET /\n\
         \tretries 0\n\
         \ttimeout connect 2s\n\
         \ttimeout client 2s\n\
         \ttimeout server 2s\n\
         \ttimeout check 1h\n\
         frontend fe\n\
         \tbind {front}\n\
         \tuse_backend be_sd if {{ path -m beg /sd }}\n\
         \tdefault_backend be_fc\n\
         backend be_fc\n\
         \tid 10\n\
         \tserver s1 {srv} id 1 check addr {sink_ip} port {sink_port} inter 1h fall 2 observe layer7 error-limit 1 on-error fail-check\n\
         backend be_sd\n\
         \tid 11\n\
         \tserver s1 {srv} id 1 check addr {sink_ip} port {sink_port} inter 1h fall 5 observe layer7 error-limit 1 on-error sudden-death\n",
        sink_ip = sink.ip(),
        sink_port = sink.port(),
    );
    let (_dir, sock, _proc) = spawn_proxy(&cfg);

    // Raise health to full (rise + fall - 1) so fall=2 / fall=5 are exercised.
    let _ = query(&sock, "set server be_fc/s1 health up");
    let _ = query(&sock, "set server be_sd/s1 health up");

    // fail-check with fall 2: 1st error reduces health (3 -> 2), still UP; 2nd error marks DOWN.
    let (code, _) = http_get(front, "/fc");
    assert_eq!(code, 500);
    assert!(stat_col(&sock, "be_fc", "status").starts_with("UP"));
    let (code, _) = http_get(front, "/fc");
    assert_eq!(code, 500);
    assert_eq!(stat_col(&sock, "be_fc", "status"), "DOWN");

    // sudden-death with fall 5: 1st error sets health to rise+1 then fails check -> health=rise (UP),
    // 2nd error -> DOWN (2 errors instead of 5).
    let (code, _) = http_get(front, "/sd");
    assert_eq!(code, 500);
    assert!(stat_col(&sock, "be_sd", "status").starts_with("UP"));
    let (code, _) = http_get(front, "/sd");
    assert_eq!(code, 500);
    assert_eq!(stat_col(&sock, "be_sd", "status"), "DOWN");
}

#[test]
fn check_addr_uses_separate_check_target() {
    // Health check listener counts connections; traffic server is a closed port.
    let chk_hits = Arc::new(AtomicUsize::new(0));
    let chk_listener = TcpListener::bind("127.0.0.1:0").expect("bind chk");
    let chk_addr = chk_listener.local_addr().expect("chk addr");
    let chk_hits_bg = chk_hits.clone();
    thread::spawn(move || {
        for s in chk_listener.incoming() {
            let Ok(mut s) = s else { break };
            chk_hits_bg.fetch_add(1, Ordering::Relaxed);
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });

    let closed_port = common::reserve_addr().port();
    let cfg = format!(
        "global\n\
         \tstats socket __SOCK__ level admin\n\
         defaults\n\
         \tmode http\n\
         \toption httpchk GET /\n\
         \ttimeout connect 1s\n\
         \ttimeout client 1s\n\
         \ttimeout server 1s\n\
         \ttimeout check 1s\n\
         backend be\n\
         \tserver s1 127.0.0.1:{closed_port} check addr {chk_ip} port {chk_port} inter 100ms\n",
        chk_ip = chk_addr.ip(),
        chk_port = chk_addr.port(),
    );
    let (_dir, sock, _proc) = spawn_proxy(&cfg);

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if chk_hits.load(Ordering::Relaxed) >= 1 && stat_col(&sock, "be", "check_status") == "L7OK" {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(chk_hits.load(Ordering::Relaxed) >= 1, "check never hit addr target");
    assert!(stat_col(&sock, "be", "status").starts_with("UP"));
    assert_eq!(stat_col(&sock, "be", "check_status"), "L7OK");
    let f = server_state_fields(&sock, "be", "s1");
    assert_eq!(f[21], chk_addr.port().to_string());
    assert_eq!(f[22], chk_addr.ip().to_string());
}

#[test]
fn config_validation_rejects_invalid_observe_options() {
    let dir = tempfile::TempDir::new().expect("tmp");
    // layer7 in tcp mode: HAProxy emits an ALERT, Alcyon refuses at load.
    let p0 = dir.path().join("bad_tcp_l7.cfg");
    std::fs::write(
        &p0,
        "defaults\n\tmode tcp\nbackend b\n\tserver s1 127.0.0.1:80 check observe layer7\n",
    )
    .expect("write");
    let out0 = Command::new(bin()).args(["-c", "-f"]).arg(&p0).output().expect("run -c");
    let stderr0 = String::from_utf8_lossy(&out0.stderr);
    assert!(
        !out0.status.success() || stderr0.contains("http"),
        "expected layer7 in tcp mode to be rejected/alerted, stderr: {stderr0}"
    );

    let p1 = dir.path().join("bad_listen_l7.cfg");
    std::fs::write(
        &p1,
        "defaults\n\tmode tcp\nlisten l\n\tbind 127.0.0.1:0\n\tserver s1 127.0.0.1:80 check observe layer7\n",
    )
    .expect("write");
    let out1 = Command::new(bin()).args(["-c", "-f"]).arg(&p1).output().expect("run -c");
    let stderr1 = String::from_utf8_lossy(&out1.stderr);
    assert!(
        !out1.status.success() || stderr1.contains("http"),
        "expected layer7 in tcp listen to be rejected/alerted, stderr: {stderr1}"
    );

    let bad_configs = [
        // error-limit <= 0
        "defaults\n\tmode http\nbackend b\n\tserver s1 127.0.0.1:80 check observe layer4 error-limit 0\n",
        // invalid observe mode
        "defaults\n\tmode http\nbackend b\n\tserver s1 127.0.0.1:80 check observe bogus\n",
        // invalid on-error mode
        "defaults\n\tmode http\nbackend b\n\tserver s1 127.0.0.1:80 check observe layer4 on-error bogus\n",
        // invalid default-server on-error mode
        "defaults\n\tmode http\nbackend b\n\tdefault-server on-error bogus\n\tserver s1 127.0.0.1:80\n",
        // invalid addr
        "defaults\n\tmode http\nbackend b\n\tserver s1 127.0.0.1:80 check addr not_an_ip\n",
    ];
    for (idx, cfg) in bad_configs.iter().enumerate() {
        let p = dir.path().join(format!("bad_{idx}.cfg"));
        std::fs::write(&p, cfg).expect("write");
        let out = Command::new(bin()).args(["-c", "-f"]).arg(&p).output().expect("run -c");
        assert!(
            !out.status.success(),
            "expected config {idx} to fail validation:\n{cfg}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
}

#[test]
fn observe_tcp_mode_default_server_and_http_error_kinds() {
    let sink = spawn_sink();

    // TCP echo server for L4Ok in mode tcp.
    let tcp_listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
    let tcp_addr = tcp_listener.local_addr().expect("tcp addr");
    thread::spawn(move || {
        for s in tcp_listener.incoming() {
            let Ok(mut s) = s else { break };
            let _ = s.write_all(b"pong");
        }
    });

    // HTTP server that cycles through: garbage head, immediate close, silent (timeout).
    let mode = Arc::new(AtomicUsize::new(0));
    let http_listener = TcpListener::bind("127.0.0.1:0").expect("bind http");
    let http_addr = http_listener.local_addr().expect("http addr");
    let mode_bg = mode.clone();
    thread::spawn(move || {
        for s in http_listener.incoming() {
            let Ok(mut s) = s else { break };
            let m = mode_bg.load(Ordering::Relaxed);
            thread::spawn(move || {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                match m {
                    0 => {
                        let _ = s.write_all(b"NOT_HTTP\r\n\r\n");
                    }
                    1 => {}
                    2 => {
                        let _ = rustix::net::sockopt::set_socket_linger(&s, Some(Duration::ZERO));
                    }
                    _ => {
                        thread::sleep(Duration::from_millis(300));
                    }
                }
            });
        }
    });

    let tcp_front = common::reserve_addr();
    let tcp_err_front = common::reserve_addr();
    let closed_port = common::reserve_addr().port();
    let http_front = common::reserve_addr();
    let cfg = format!(
        "global\n\
         \tstats socket __SOCK__ level admin\n\
         defaults\n\
         \tretries 0\n\
         \ttimeout connect 1s\n\
         \ttimeout client 2s\n\
         \ttimeout server 120ms\n\
         \ttimeout check 1h\n\
         listen tcp_ok\n\
         \tmode tcp\n\
         \tbind {tcp_front}\n\
         \tdefault-server addr {sink_ip} port {sink_port} inter 1h observe layer4 error-limit 1 on-error fastinter\n\
         \tserver s1 {tcp_addr} check\n\
         listen tcp_err\n\
         \tmode tcp\n\
         \tbind {tcp_err_front}\n\
         \tdefault-server addr {sink_ip} port {sink_port} inter 1h observe layer4 error-limit 1 on-error fastinter\n\
         \tserver s1 127.0.0.1:{closed_port} check\n\
         frontend fe_http\n\
         \tmode http\n\
         \tbind {http_front}\n\
         \tuse_backend be_to if {{ path -m beg /to }}\n\
         \tuse_backend be_bp if {{ path -m beg /bp }}\n\
         \tuse_backend be_re if {{ path -m beg /re }}\n\
         \tdefault_backend be_hdr\n\
         backend be_hdr\n\
         \tmode http\n\
         \toption httpchk GET /\n\
         \tserver s1 {http_addr} check addr {sink_ip} port {sink_port} inter 1h observe layer7 error-limit 1 on-error mark-down\n\
         backend be_bp\n\
         \tmode http\n\
         \toption httpchk GET /\n\
         \tserver s1 {http_addr} check addr {sink_ip} port {sink_port} inter 1h observe layer7 error-limit 1 on-error mark-down\n\
         backend be_re\n\
         \tmode http\n\
         \toption httpchk GET /\n\
         \tserver s1 {http_addr} check addr {sink_ip} port {sink_port} inter 1h observe layer7 error-limit 1 on-error mark-down\n\
         backend be_to\n\
         \tmode http\n\
         \toption httpchk GET /\n\
         \tserver s1 {http_addr} check addr {sink_ip} port {sink_port} inter 1h observe layer7 error-limit 1 on-error mark-down\n",
        sink_ip = sink.ip(),
        sink_port = sink.port(),
    );
    let (_dir, sock, _proc) = spawn_proxy(&cfg);

    // TCP L4Ok succeeds and server stays UP.
    let mut ts = TcpStream::connect(tcp_front).expect("connect tcp front");
    let mut tbuf = [0u8; 8];
    let n = ts.read(&mut tbuf).unwrap_or(0);
    assert_eq!(&tbuf[..n], b"pong");
    assert!(stat_col(&sock, "tcp_ok", "status").starts_with("UP"));

    // TCP L4Err with on-error fastinter: server stays UP (fastinter only forces fastinter).
    if let Ok(mut te) = TcpStream::connect(tcp_err_front) {
        let mut ebuf = [0u8; 8];
        let _ = te.read(&mut ebuf);
    }
    assert!(stat_col(&sock, "tcp_err", "status").starts_with("UP"));

    // Invalid HTTP response headers -> 502, marks be_hdr/s1 DOWN.
    mode.store(0, Ordering::Relaxed);
    let (code, _) = http_get(http_front, "/hdr");
    assert_eq!(code, 502);
    assert_eq!(stat_col(&sock, "be_hdr", "status"), "DOWN");

    // Broken pipe (server closes without replying) -> 502, marks be_bp/s1 DOWN.
    mode.store(1, Ordering::Relaxed);
    let (code, _) = http_get(http_front, "/bp");
    assert_eq!(code, 502);
    assert_eq!(stat_col(&sock, "be_bp", "status"), "DOWN");

    // Read error (server resets with SO_LINGER 0) -> 502, marks be_re/s1 DOWN.
    mode.store(2, Ordering::Relaxed);
    let (code, _) = http_get(http_front, "/re");
    assert_eq!(code, 502);
    assert_eq!(stat_col(&sock, "be_re", "status"), "DOWN");

    // Read timeout -> 504, marks be_to/s1 DOWN.
    mode.store(3, Ordering::Relaxed);
    let (code, _) = http_get(http_front, "/to");
    assert_eq!(code, 504);
    assert_eq!(stat_col(&sock, "be_to", "status"), "DOWN");
}

#[test]
fn observe_l4_connection_reuse_and_non_observed_backend() {
    let sink = spawn_sink();
    let conn_count = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ka");
    let srv = listener.local_addr().expect("ka addr");
    let conn_bg = conn_count.clone();
    thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            conn_bg.fetch_add(1, Ordering::Relaxed);
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut chunk) {
                            Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                            _ => return,
                        }
                    }
                    let pos = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                    buf.drain(..pos);
                    if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                        return;
                    }
                }
            });
        }
    });

    let front = common::reserve_addr();
    let cfg = format!(
        "global\n\
         \tstats socket __SOCK__ level admin\n\
         defaults\n\
         \tmode http\n\
         \toption httpchk GET /\n\
         \tretries 0\n\
         \ttimeout connect 2s\n\
         \ttimeout client 2s\n\
         \ttimeout server 2s\n\
         \ttimeout check 1h\n\
         frontend fe\n\
         \tbind {front}\n\
         \tuse_backend be_kept if {{ path -m beg /kept }}\n\
         \tuse_backend be_pool if {{ path -m beg /pool }}\n\
         \tdefault_backend be_plain\n\
         backend be_kept\n\
         \thttp-reuse never\n\
         \tserver s1 {srv} check addr {sink_ip} port {sink_port} inter 1h observe layer4 error-limit 2 on-error mark-down\n\
         backend be_pool\n\
         \thttp-reuse always\n\
         \tserver s1 {srv} check addr {sink_ip} port {sink_port} inter 1h observe layer4 error-limit 2 on-error mark-down\n\
         backend be_plain\n\
         \tserver s1 {srv}\n",
        sink_ip = sink.ip(),
        sink_port = sink.port(),
    );
    let (_dir, sock, _proc) = spawn_proxy(&cfg);

    // 1. Session-kept server connection reuse (`http-reuse never`) with `observe layer4`.
    {
        let mut s = TcpStream::connect_timeout(&front, Duration::from_secs(2)).expect("connect kept");
        s.set_read_timeout(Some(Duration::from_secs(3))).ok();
        write!(s, "GET /kept/1 HTTP/1.1\r\nHost: localhost\r\n\r\n").expect("write kept 1");
        let mut raw = Vec::new();
        let mut tmp = [0u8; 1024];
        while !raw.windows(6).any(|w| w == b"\r\n\r\nok") {
            let n = s.read(&mut tmp).expect("read kept 1");
            assert!(n > 0, "eof before kept 1 body");
            raw.extend_from_slice(&tmp[..n]);
        }
        assert!(String::from_utf8_lossy(&raw).starts_with("HTTP/1.1 200"));

        write!(s, "GET /kept/2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write kept 2");
        let mut tail = String::new();
        let _ = s.read_to_string(&mut tail);
        assert!(tail.starts_with("HTTP/1.1 200") && tail.ends_with("ok"), "kept 2: {tail:?}");
    }
    assert!(stat_col(&sock, "be_kept", "status").starts_with("UP"));

    // 2. Idle-pool server connection reuse (`http-reuse always`) with `observe layer4`.
    let before_pool = conn_count.load(Ordering::Relaxed);
    let (c1, _) = http_get(front, "/pool/1");
    assert_eq!(c1, 200);
    let (c2, _) = http_get(front, "/pool/2");
    assert_eq!(c2, 200);
    let after_pool = conn_count.load(Ordering::Relaxed);
    assert_eq!(after_pool - before_pool, 1, "second /pool request should reuse the idle server connection");
    assert!(stat_col(&sock, "be_pool", "status").starts_with("UP"));

    // 3. Backend without `observe` when engine `has_observe` is true (`health_adjust` `!px.has_observe`).
    let (c3, _) = http_get(front, "/plain");
    assert_eq!(c3, 200);
}
