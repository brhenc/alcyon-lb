// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A server changing state is written on stderr and to the `log` targets whatever `option
//! log-health-checks` says (VV-24, T404). Expected lines measured on `HAProxy`
//! 3.5-dev8-885761-29 (2026-10-25):
//!
//! ```text
//! check fails:  Server b/s1 is DOWN, reason: Layer4 connection problem, info: "...", check duration: 0ms. 0 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.
//!               backend 'b' has no server available!      (stderr; the log has: backend b has ...)
//! disable:      Server b/s1 was DOWN and now enters maintenance.
//!               Server b/s1 is going DOWN for maintenance. 0 active and 1 backup servers left. Running on backup. 0 sessions active, 0 requeued, 0 remaining in queue.
//! enable:       Server b/s1 is UP/READY (leaving forced maintenance).
//! drain:        Server b/s1 enters drain state. 0 active and 1 backup servers online. Running on backup. 0 sessions requeued, 0 total in queue.
//! ready:        Server b/s1 is UP (leaving forced drain).
//! state file:   Server b/s1 is DOWN, changed from server-state after a reload. 0 active and 0 backup servers left. ... (stderr only)
//! ```

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Run {
    ibex: common::Ibex,
    syslog: UdpSocket,
    sock: String,
    err: String,
    front: std::net::SocketAddr,
    log: Vec<String>,
}

impl Run {
    fn start(dir: &Path, conf: &str, extra_global: &str, extra_be: &str, servers: &str) -> Run {
        let syslog = UdpSocket::bind("127.0.0.1:0").expect("udp");
        syslog.set_read_timeout(Some(Duration::from_millis(100))).ok();
        let front = common::reserve_addr();
        let sock = dir.join("cli.sock").to_string_lossy().into_owned();
        let cfg = format!(
            "global\n  stats socket {sock} level admin\n{extra_global}defaults\n  mode http\n  log 127.0.0.1:{} local0\n  \
             timeout connect 1s\n  timeout client 2s\n  timeout server 2s\nfrontend f\n  bind {front}\n  stats enable\n  stats uri /st\n  stats admin if TRUE\n  default_backend b\n\
             backend b\n{extra_be}{servers}",
            syslog.local_addr().unwrap().port()
        );
        let path = dir.join(conf);
        std::fs::write(&path, &cfg).expect("write cfg");
        let err = dir.join(format!("{conf}.err"));
        let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
            .arg("-f")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&err).expect("err file"))
            .spawn()
            .expect("spawn ibex");
        Run { ibex: common::Ibex(child), syslog, sock, err: err.to_string_lossy().into_owned(), front, log: Vec::new() }
    }

    /// Reads the log until `what` was seen (or 5 s), returns all lines so far.
    fn wait_log(&mut self, what: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut buf = [0u8; 4096];
        while Instant::now() < deadline {
            if self.log.iter().any(|l| l.contains(what)) {
                return true;
            }
            if let Ok((n, _)) = self.syslog.recv_from(&mut buf) {
                self.log.push(String::from_utf8_lossy(&buf[..n]).into_owned());
            }
        }
        self.log.iter().any(|l| l.contains(what))
    }

    fn cli(&self, cmd: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut c = loop {
            match UnixStream::connect(&self.sock) {
                Ok(c) => break c,
                Err(e) => assert!(Instant::now() < deadline, "cli connect: {e}"),
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        c.write_all(format!("{cmd}\n").as_bytes()).expect("cli write");
        let mut out = String::new();
        c.read_to_string(&mut out).expect("cli read");
        out
    }

    fn post(&self, body: &str) {
        let mut c = std::net::TcpStream::connect(self.front).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(3))).ok();
        let req = format!(
            "POST /st HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        c.write_all(req.as_bytes()).expect("post");
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
    }

    /// stderr so far (after ibex was stopped, so that nothing is missing).
    fn stderr(mut self) -> String {
        common::stop(&mut self.ibex.0);
        std::fs::read_to_string(&self.err).expect("stderr")
    }
}

/// A server that accepts and closes; checks against it pass at layer 4.
fn listener() -> (TcpListener, String) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let a = l.local_addr().unwrap().to_string();
    let l2 = l.try_clone().unwrap();
    std::thread::spawn(move || for _ in l2.incoming() {});
    (l, a)
}

fn closed_port() -> String {
    common::reserve_addr().to_string()
}

#[test]
fn a_check_taking_the_only_server_down_is_logged_without_log_health_checks() {
    let dir = tempfile::TempDir::new().unwrap();
    let srv = closed_port();
    let mut r = Run::start(dir.path(), "a.cfg", "", "", &format!("  server s1 {srv} check inter 200ms fall 1 rise 1\n"));
    assert!(r.wait_log("backend b has no server available!"), "log: {:?}", r.log);
    assert!(r.log.iter().any(|l| l.contains("Server b/s1 is DOWN, reason: Layer4 connection problem, info: \"")
        && l.contains("check duration: ")
        && l.contains(". 0 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.")),
        "log: {:?}", r.log);
    assert!(!r.log.iter().any(|l| l.contains("Health check for server")), "log: {:?}", r.log);
    let err = r.stderr();
    assert!(err.contains("[WARNING]  ("), "stderr: {err}");
    assert!(err.contains(") : Server b/s1 is DOWN, reason: Layer4 connection problem"), "stderr: {err}");
    assert!(err.contains(") : backend 'b' has no server available!\n"), "stderr: {err}");
    assert!(err.contains("[ALERT]    ("), "stderr: {err}");
}

#[test]
fn log_health_checks_adds_the_health_check_line_only() {
    let dir = tempfile::TempDir::new().unwrap();
    let srv = closed_port();
    let mut r = Run::start(dir.path(), "b.cfg", "", "  option log-health-checks\n", &format!("  server s1 {srv} check inter 200ms fall 1 rise 1\n"));
    assert!(r.wait_log("backend b has no server available!"), "log: {:?}", r.log);
    assert!(r.log.iter().any(|l| l.contains("Health check for server b/s1 failed, reason: Layer4 connection problem")), "log: {:?}", r.log);
    assert!(r.log.iter().any(|l| l.contains("Server b/s1 is DOWN, reason: Layer4 connection problem")), "log: {:?}", r.log);
}

#[test]
fn a_server_already_down_enters_maintenance() {
    let dir = tempfile::TempDir::new().unwrap();
    let srv = closed_port();
    let mut r = Run::start(dir.path(), "c.cfg", "", "", &format!("  server s1 {srv} check inter 200ms fall 1 rise 1\n"));
    assert!(r.wait_log("backend b has no server available!"), "log: {:?}", r.log);
    r.cli("disable server b/s1");
    assert!(r.wait_log("Server b/s1 was DOWN and now enters maintenance."), "log: {:?}", r.log);
    assert!(r.stderr().contains(") : Server b/s1 was DOWN and now enters maintenance.\n"));
}

#[test]
fn admin_changes_of_a_running_server() {
    let dir = tempfile::TempDir::new().unwrap();
    let (_l, srv) = listener();
    let mut r = Run::start(
        dir.path(),
        "d.cfg",
        "",
        "",
        &format!("  server s1 {srv} check inter 200ms fall 1 rise 1\n  server s2 {srv} backup\n"),
    );
    std::thread::sleep(Duration::from_millis(600));
    let steps: [(&str, &str); 5] = [
        (
            "disable server b/s1",
            "Server b/s1 is going DOWN for maintenance. 0 active and 1 backup servers left. Running on backup. 0 sessions active, 0 requeued, 0 remaining in queue.",
        ),
        ("enable server b/s1", "Server b/s1 is UP/READY (leaving forced maintenance)."),
        (
            "set server b/s1 state drain",
            "Server b/s1 enters drain state. 0 active and 1 backup servers online. Running on backup. 0 sessions requeued, 0 total in queue.",
        ),
        ("set server b/s1 state ready", "Server b/s1 is UP (leaving forced drain)."),
        ("disable server b/s2", "Backup Server b/s2 is going DOWN for maintenance. 1 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue."),
    ];
    for (cmd, line) in steps {
        r.cli(cmd);
        assert!(r.wait_log(line), "after `{cmd}` expected `{line}` in {:?}", r.log);
    }
    assert!(!r.log.iter().any(|l| l.contains("no server available")), "log: {:?}", r.log);
    let err = r.stderr();
    assert!(err.contains(") : Server b/s1 is UP (leaving forced drain).\n"), "stderr: {err}");
}

#[test]
fn the_server_state_file_down_is_on_stderr() {
    let dir = tempfile::TempDir::new().unwrap();
    let srv = closed_port();
    let servers = format!("  server s1 {srv} check inter 200ms fall 1 rise 1\n");
    let mut r = Run::start(dir.path(), "e.cfg", "", "", &servers);
    assert!(r.wait_log("backend b has no server available!"), "log: {:?}", r.log);
    let state = r.cli("show servers state b");
    let file = dir.path().join("state");
    std::fs::write(&file, state).unwrap();
    drop(r.stderr());
    let r2 = Run::start(
        dir.path(),
        "f.cfg",
        &format!("  server-state-file {}\n", file.display()),
        "  load-server-state-from-file global\n",
        &servers,
    );
    std::thread::sleep(Duration::from_millis(800));
    let err = r2.stderr();
    assert!(
        err.contains(") : Server b/s1 is DOWN, changed from server-state after a reload. 0 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.\n"),
        "stderr: {err}"
    );
}

#[test]
fn stats_page_and_cli_health_changes() {
    let dir = tempfile::TempDir::new().unwrap();
    let (_l, srv) = listener();
    let mut r = Run::start(
        dir.path(),
        "g.cfg",
        "",
        "",
        &format!("  server s1 {srv} check inter 200ms fall 1 rise 1\n  server s2 {srv} backup\n"),
    );
    std::thread::sleep(Duration::from_millis(600));
    let down = "Server b/s1 is going DOWN for maintenance ('disable' on stats page). 0 active and 1 backup servers left. Running on backup. 0 sessions active, 0 requeued, 0 remaining in queue.";
    r.post("s=s1&action=disable&b=b");
    assert!(r.wait_log(down), "log: {:?}", r.log);
    r.post("s=s1&action=ready&b=b");
    assert!(r.wait_log("Server b/s1 is UP/READY (leaving forced maintenance)."), "log: {:?}", r.log);
    r.post("s=s1&action=stop&b=b");
    assert!(
        r.wait_log("Server b/s1 enters drain state ('stop' on stats page). 0 active and 1 backup servers online. Running on backup."),
        "log: {:?}",
        r.log
    );
    r.post("s=s1&action=ready&b=b");
    assert!(r.wait_log("Server b/s1 is UP (leaving forced drain)."), "log: {:?}", r.log);
    r.post("s=s1&action=hdown&b=b");
    assert!(r.wait_log("Server b/s1 is DOWN, changed from Web interface. 0 active and 1 backup servers left."), "log: {:?}", r.log);
    r.post("s=s1&action=hrunn&b=b");
    assert!(r.wait_log("Server b/s1 is UP, changed from Web interface."), "log: {:?}", r.log);
    r.cli("set server b/s1 health down");
    assert!(r.wait_log("Server b/s1 is DOWN, changed from CLI. 0 active and 1 backup servers left."), "log: {:?}", r.log);
}
