// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Server `agent-check` (`agent-addr`, `agent-port`, `agent-send`, `agent-inter`) and
//! `tcpcheck_agent_expect_reply` branch-by-branch parity against HAProxy.
//! Set `T281_ORACLE=/path/to/haproxy` to run against the HAProxy oracle.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
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

fn wait_until(desc: &str, timeout: Duration, mut pred: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if pred() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for: {desc}");
}

/// Returns fields of `show servers state <be>` for server `srv`.
/// Format (v1):
/// 0: be_id, 1: be_name, 2: srv_id, 3: srv_name, 4: srv_addr,
/// 5: srv_op_state, 6: srv_admin_state, 7: srv_uweight, 8: srv_iweight, ...
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

/// Returns `show stat <be> 4 1 typed` column value for `col`, if present.
fn try_stat_col(sock: &std::path::Path, be: &str, col: &str) -> Option<String> {
    let out = query(sock, &format!("show stat {be} 4 1 typed"));
    for line in out.lines() {
        let mut parts = line.splitn(4, ':');
        let Some(lhs) = parts.next() else { continue };
        let _metrics_type = parts.next();
        let _value_type = parts.next();
        let Some(val) = parts.next() else { continue };
        let field = lhs.rsplit('.').nth(1).unwrap_or("");
        if field == col {
            return Some(val.to_string());
        }
    }
    None
}

/// Returns `show stat <be> 4 1 typed` column value for `col`.
fn stat_col(sock: &std::path::Path, be: &str, col: &str) -> String {
    try_stat_col(sock, be, col)
        .unwrap_or_else(|| panic!("column {col} not found in show stat {be} 4 1 typed"))
}

fn spawn_proxy(cfg: &str) -> (Proc, tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("stats.sock");
    let cfg_path = dir.path().join("haproxy.cfg");
    let full_cfg = cfg.replace("@SOCK@", sock.to_str().unwrap());
    std::fs::write(&cfg_path, &full_cfg).expect("write cfg");

    let mut cmd = Command::new(bin());
    cmd.args(["-f", cfg_path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().expect("spawn proxy");
    let proc = Proc(child);
    wait_ready(&sock);
    (proc, dir, sock)
}

#[test]
fn agent_check_vtc_parity() {
    // Mirrors reg-tests/checks/agent-check.vtc:
    // agent-send "pouet", reply "75%,maxconn:30,maint,down\n",
    // verify show servers state and show stat.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind agent");
    let agent_addr: SocketAddr = listener.local_addr().unwrap();
    let seen_send = Arc::new(Mutex::new(Vec::<u8>::new()));
    let seen_send_bg = Arc::clone(&seen_send);

    let handle = thread::spawn(move || {
        // Handle first connection as in agent-check.vtc
        if let Ok((mut stream, _)) = listener.accept() {
            stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).unwrap_or(0);
            *seen_send_bg.lock().unwrap() = buf[..n].to_vec();
            let _ = stream.write_all(b"75%,maxconn:30,maint,down\n");
            let _ = stream.flush();
        }
        // Keep accepting silently in case another check fires before teardown
        for conn in listener.incoming().flatten() {
            drop(conn);
        }
    });

    // Dummy server port (not checked by regular `check`, only agent-check)
    let srv_listener = TcpListener::bind("127.0.0.1:0").expect("bind srv");
    let srv_addr = srv_listener.local_addr().unwrap();

    let cfg = format!(
        "global
    stats socket @SOCK@ level admin
defaults
    mode tcp
    timeout client 5s
    timeout server 5s
    timeout connect 5s
backend be1
    server srv 127.0.0.1:{srv_port} weight 100 agent-check agent-addr 127.0.0.1 agent-port {agent_port} agent-send \"pouet\" agent-inter 100ms
    server srv_plain 127.0.0.1:{srv_port}
",
        srv_port = srv_addr.port(),
        agent_port = agent_addr.port(),
    );

    let (_proc, _dir, sock) = spawn_proxy(&cfg);

    wait_until("agent-check vtc reply applied", Duration::from_secs(5), || {
        let fields = server_state_fields(&sock, "be1", "srv");
        fields.get(5).map(String::as_str) == Some("0")
            && fields.get(6).map(String::as_str) == Some("1")
            && fields.get(7).map(String::as_str) == Some("75")
            && fields.get(8).map(String::as_str) == Some("100")
    });

    assert_eq!(seen_send.lock().unwrap().as_slice(), b"pouet");
    assert_eq!(stat_col(&sock, "be1", "slim"), "30");
    assert_eq!(stat_col(&sock, "be1", "weight"), "75");
    assert_eq!(stat_col(&sock, "be1", "status"), "MAINT");
    assert_eq!(
        server_state_fields(&sock, "be1", "srv_plain").get(14).map(String::as_str),
        Some("0")
    );
    drop(handle);
    drop(srv_listener);
}

#[test]
fn agent_check_reply_branches() {
    // Port tcpcheck_agent_expect_reply branch by branch with one oracle row per branch:
    // 75%, drain, maint, ready, down, up, 50% ready, maxconn:10, unparsable reply.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind agent");
    let agent_addr: SocketAddr = listener.local_addr().unwrap();
    let current_reply = Arc::new(Mutex::new(String::from("75%\n")));
    let reply_bg = Arc::clone(&current_reply);

    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let reply = reply_bg.lock().unwrap().clone();
            let mut s = stream;
            let _ = s.write_all(reply.as_bytes());
            let _ = s.flush();
        }
    });

    // Server port unused (no regular `check`)
    let srv_listener = TcpListener::bind("127.0.0.1:0").expect("bind srv");
    let srv_addr = srv_listener.local_addr().unwrap();

    // Note: omit agent-addr to also test defaulting to the server's address (127.0.0.1).
    let cfg = format!(
        "global
    stats socket @SOCK@ level admin
defaults
    mode tcp
    timeout client 5s
    timeout server 5s
    timeout connect 5s
backend be1
    server srv 127.0.0.1:{srv_port} weight 100 agent-check agent-port {agent_port} agent-inter 50ms
",
        srv_port = srv_addr.port(),
        agent_port = agent_addr.port(),
    );

    let (_proc, _dir, sock) = spawn_proxy(&cfg);

    // Helper to set the current reply and wait until predicate on stats/state holds.
    let step = |reply: &str, desc: &str, pred: &dyn Fn() -> bool| {
        *current_reply.lock().unwrap() = reply.to_string();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if pred() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let st = query(&sock, "show servers state be1");
        let stat = query(&sock, "show stat be1 4 1 typed");
        panic!("timed out waiting for: {desc}\n--- show servers state ---\n{st}\n--- show stat ---\n{stat}");
    };

    // 1. "75%" -> uweight = 75
    step("75%\n", "75% weight", &|| {
        let f = server_state_fields(&sock, "be1", "srv");
        f.get(7).map(String::as_str) == Some("75")
    });

    // 2. "drain" -> admin_state = 8 (FDRAIN), status = DRAIN (agent)
    step("drain\n", "drain admin state", &|| {
        let f = server_state_fields(&sock, "be1", "srv");
        f.get(6).map(String::as_str) == Some("8")
            && stat_col(&sock, "be1", "status").starts_with("DRAIN")
    });

    // 3. "maint" -> admin_state = 1 (FMAINT), status = MAINT
    step("maint\n", "maint admin state", &|| {
        let f = server_state_fields(&sock, "be1", "srv");
        f.get(6).map(String::as_str) == Some("1") && stat_col(&sock, "be1", "status") == "MAINT"
    });

    // 4. "ready" -> admin_state = 0, status = "no check" (since regular `check` is not enabled)
    step("ready\n", "ready admin state", &|| {
        let f = server_state_fields(&sock, "be1", "srv");
        f.get(6).map(String::as_str) == Some("0") && stat_col(&sock, "be1", "status") == "no check"
    });

    // 5. "down" -> op_state = 0, status = DOWN (agent)
    step("down\n", "down op state", &|| {
        let f = server_state_fields(&sock, "be1", "srv");
        f.get(5).map(String::as_str) == Some("0")
            && stat_col(&sock, "be1", "status").starts_with("DOWN")
    });

    // 6. "up" -> op_state = 2, status = "no check"
    step("up\n", "up op state", &|| {
        let f = server_state_fields(&sock, "be1", "srv");
        f.get(5).map(String::as_str) == Some("2") && stat_col(&sock, "be1", "status") == "no check"
    });

    // 7. "50% ready" (first put into drain, then "50% ready" -> uweight=50, admin=0)
    step("drain\n", "drain before 50% ready", &|| {
        let f = server_state_fields(&sock, "be1", "srv");
        f.get(6).map(String::as_str) == Some("8")
    });
    step("50% ready\n", "50% ready", &|| {
        let f = server_state_fields(&sock, "be1", "srv");
        f.get(6).map(String::as_str) == Some("0") && f.get(7).map(String::as_str) == Some("50")
    });

    // 8. "maxconn:10" -> slim = 10
    step("maxconn:10\n", "maxconn:10", &|| {
        try_stat_col(&sock, "be1", "slim").as_deref() == Some("10")
    });

    // 9. unparsable reply -> state unchanged (still UP, admin=0, weight=50, maxconn=10)
    // and last_agt reports the error
    step("garbled_token\n", "unparsable reply", &|| {
        try_stat_col(&sock, "be1", "last_agt").is_some_and(|desc| desc.contains("garbled_token"))
    });
    let f = server_state_fields(&sock, "be1", "srv");
    assert_eq!(f.get(5).map(String::as_str), Some("2"));
    assert_eq!(f.get(6).map(String::as_str), Some("0"));
    assert_eq!(f.get(7).map(String::as_str), Some("50"));
    assert_eq!(stat_col(&sock, "be1", "slim"), "10");

    // 10. weight:60, fail, stopped, # comment
    step("weight:60\n", "weight:60", &|| {
        server_state_fields(&sock, "be1", "srv").get(7).map(String::as_str) == Some("60")
    });
    step("fail # disk full\n", "fail with comment", &|| {
        let f = server_state_fields(&sock, "be1", "srv");
        f.get(5).map(String::as_str) == Some("0")
            && try_stat_col(&sock, "be1", "last_agt")
                .is_some_and(|d| d.contains("fail") && d.contains("disk full"))
    });
    step("up\n", "up after fail", &|| {
        server_state_fields(&sock, "be1", "srv").get(5).map(String::as_str) == Some("2")
    });
    step("stopped\n", "stopped", &|| {
        server_state_fields(&sock, "be1", "srv").get(5).map(String::as_str) == Some("0")
    });

    drop(srv_listener);
}

#[test]
fn agent_check_error_and_timeout() {
    // 1. Closed agent port -> L4CON, server remains UP (op_state = 2).
    let closed_port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let srv_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();

    let cfg = format!(
        "global
    stats socket @SOCK@ level admin
defaults
    mode tcp
    timeout client 5s
    timeout server 5s
    timeout connect 5s
backend be1
    server srv 127.0.0.1:{srv_port} weight 100 agent-check agent-port {closed_port} agent-inter 50ms
"
    );
    let (_proc, _dir, sock) = spawn_proxy(&cfg);
    wait_until("L4CON recorded without marking server down", Duration::from_secs(5), || {
        try_stat_col(&sock, "be1", "agent_status").as_deref() == Some("L4CON")
    });
    assert_eq!(server_state_fields(&sock, "be1", "srv").get(5).map(String::as_str), Some("2"));

    // 2. Sink agent that accepts and never replies -> L7TOUT, server remains UP.
    let sink = TcpListener::bind("127.0.0.1:0").unwrap();
    let sink_port = sink.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut held = Vec::new();
        for conn in sink.incoming().flatten() {
            held.push(conn);
        }
    });
    let cfg2 = format!(
        "global
    stats socket @SOCK@ level admin
defaults
    mode tcp
    timeout client 5s
    timeout server 5s
    timeout connect 5s
backend be1
    server srv 127.0.0.1:{srv_port} weight 100 agent-check agent-port {sink_port} agent-inter 250ms
"
    );
    let (_proc2, _dir2, sock2) = spawn_proxy(&cfg2);
    wait_until("srv_agent_state reflects in_progress (23)", Duration::from_secs(5), || {
        server_state_fields(&sock2, "be1", "srv").get(14).map(String::as_str) == Some("23")
    });
    wait_until("L7TOUT recorded without marking server down", Duration::from_secs(5), || {
        try_stat_col(&sock2, "be1", "agent_status").as_deref() == Some("L7TOUT")
    });
    assert_eq!(server_state_fields(&sock2, "be1", "srv").get(5).map(String::as_str), Some("2"));
    drop(srv_listener);
}

/// An agent's "up" does not bring up a server whose regular health check is failing: the
/// server stays DOWN while `check` fails, and comes up once the check passes too
/// (`HAProxy`: the agent and the health check must both report up).
#[test]
fn agent_up_does_not_override_a_failing_health_check() {
    let agent = TcpListener::bind("127.0.0.1:0").expect("bind agent");
    let agent_port = agent.local_addr().unwrap().port();
    thread::spawn(move || {
        for mut s in agent.incoming().flatten() {
            let _ = s.write_all(b"up\n");
        }
    });
    // The server port is closed: the regular `check` fails (L4CON).
    let srv_port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let cfg = format!(
        "global
    stats socket @SOCK@ level admin
defaults
    mode tcp
    timeout client 5s
    timeout server 5s
    timeout connect 1s
backend be1
    server srv 127.0.0.1:{srv_port} check inter 50ms fall 1 rise 1 agent-check agent-port {agent_port} agent-inter 50ms
"
    );
    let (_proc, _dir, sock) = spawn_proxy(&cfg);
    wait_until("server DOWN from the failing check", Duration::from_secs(5), || {
        stat_col(&sock, "be1", "status").starts_with("DOWN")
    });
    // Many agent replies of "up" later, the server is still DOWN.
    thread::sleep(Duration::from_millis(500));
    let f = server_state_fields(&sock, "be1", "srv");
    assert_eq!(f.get(5).map(String::as_str), Some("0"), "op_state after agent up with a failing check: {f:?}");
    assert!(stat_col(&sock, "be1", "status").starts_with("DOWN"), "{}", stat_col(&sock, "be1", "status"));
}
