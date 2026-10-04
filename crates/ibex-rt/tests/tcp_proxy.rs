// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! End-to-end `mode tcp` proxying, driven by the poller.
//!
//! These assert the behaviours `HAProxy` 1.0.2's `process_cli`/`process_srv` produce:
//! byte-exact forwarding in both directions, half-close preserving in-flight data,
//! shutdown propagation, and backpressure via buffer occupancy.

mod common;

use ibex_config::ast::{
    BackendSection, Config, FrontendSection, Mode, Server, StickTableConfigAst,
    TcpReqConnAction, TcpReqConnRule, TcpReqContentAction, TcpReqContentRule,
    TcpReqSessionAction, TcpReqSessionRule,
};
use ibex_rt::engine::Engine;
use ibex_rt::proxy::{Ending, TcpSession, Timeouts};
use ibex_rt::{FdState, FdTab, Interest, Listener, Poller};
use ibex_sched::Tick;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn loopback0() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

fn owned(s: TcpStream) -> OwnedFd {
    s.set_nonblocking(true).expect("nonblocking");
    // std provides a safe ownership transfer; no raw fd round-trip needed.
    OwnedFd::from(s)
}

/// Runs a session to completion, driving it from the poller like the real runtime does.
fn drive(sess: &mut TcpSession, budget_ms: u64) {
    let deadline = std::time::Instant::now() + Duration::from_millis(budget_ms);
    let mut now = Tick(1000);
    while !sess.is_done() && std::time::Instant::now() < deadline {
        sess.process(now).expect("process");
        now = now.add(1);
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// A backend that echoes whatever it receives, then optionally closes.
fn echo_backend() -> (SocketAddr, std::thread::JoinHandle<()>) {
    let l = TcpListener::bind(loopback0()).expect("backend bind");
    let addr = l.local_addr().expect("addr");
    let h = std::thread::spawn(move || {
        if let Ok((mut c, _)) = l.accept() {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match c.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if c.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = c.shutdown(std::net::Shutdown::Write);
        }
    });
    (addr, h)
}

#[test]
fn forwards_bytes_in_both_directions() {
    let (backend, bh) = echo_backend();
    let front = Listener::bind(loopback0(), 128, 0).expect("front bind");
    let faddr = {
        let a = rustix::net::getsockname(front.borrowed_fd()).expect("getsockname");
        match a {
            rustix::net::SocketAddrAny::V4(v4) => SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(v4.ip().octets()),
                v4.port(),
            )),
            _ => panic!("v4"),
        }
    };

    let client = std::thread::spawn(move || {
        let mut s = TcpStream::connect(faddr).expect("client connect");
        s.write_all(b"HELLO_IBEX").expect("write");
        s.shutdown(std::net::Shutdown::Write).expect("shutdown w");
        let mut got = Vec::new();
        s.read_to_end(&mut got).expect("read");
        got
    });

    // Accept the client.
    let cli_fd = loop {
        if let Some((fd, _)) = front.accept().expect("accept") {
            break fd;
        }
        std::thread::sleep(Duration::from_millis(2));
    };

    let mut sess = TcpSession::new(cli_fd, Timeouts::default(), 3, Tick(1000));

    // Connect to the backend and attach it.
    let srv = TcpStream::connect(backend).expect("backend connect");
    sess.attach_server(owned(srv), Tick(1000));
    sess.server_connected(Tick(1000));

    drive(&mut sess, 3000);

    assert_eq!(
        client.join().expect("client"),
        b"HELLO_IBEX".to_vec(),
        "payload must round-trip byte-exact through the proxy"
    );
    assert_eq!(sess.bytes_in, 10);
    assert_eq!(sess.bytes_out, 10);
    bh.join().ok();
}

#[test]
fn large_payload_survives_a_buffer_smaller_than_it() {
    // 1 MiB through a 16 KiB buffer: the whole point of the fill/drain loop. If
    // backpressure or compaction were wrong this loses or duplicates bytes.
    let (backend, bh) = echo_backend();
    let front = Listener::bind(loopback0(), 128, 0).expect("bind");
    let faddr = {
        let a = rustix::net::getsockname(front.borrowed_fd()).expect("getsockname");
        match a {
            rustix::net::SocketAddrAny::V4(v4) => SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(v4.ip().octets()),
                v4.port(),
            )),
            _ => panic!("v4"),
        }
    };

    let payload: Vec<u8> = (0u32..1024 * 1024).map(|i| (i % 251) as u8).collect();
    let expect = payload.clone();

    let client = std::thread::spawn(move || {
        let mut s = TcpStream::connect(faddr).expect("connect");
        let w = std::thread::spawn({
            let p = payload.clone();
            let mut s2 = s.try_clone().expect("clone");
            move || {
                s2.write_all(&p).expect("write");
                s2.shutdown(std::net::Shutdown::Write).expect("shutdown");
            }
        });
        let mut got = Vec::new();
        s.read_to_end(&mut got).expect("read");
        w.join().expect("writer");
        got
    });

    let cli_fd = loop {
        if let Some((fd, _)) = front.accept().expect("accept") {
            break fd;
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    let mut sess = TcpSession::new(cli_fd, Timeouts::default(), 3, Tick(1000));
    let srv = TcpStream::connect(backend).expect("backend connect");
    sess.attach_server(owned(srv), Tick(1000));
    sess.server_connected(Tick(1000));

    drive(&mut sess, 30_000);

    let got = client.join().expect("client");
    assert_eq!(got.len(), expect.len(), "1 MiB must arrive complete");
    assert_eq!(
        got, expect,
        "and byte-exact, with no reordering or duplication"
    );
    bh.join().ok();
}

#[test]
fn client_timeout_fires_and_is_reported() {
    let front = Listener::bind(loopback0(), 128, 0).expect("bind");
    let faddr = {
        let a = rustix::net::getsockname(front.borrowed_fd()).expect("getsockname");
        match a {
            rustix::net::SocketAddrAny::V4(v4) => SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(v4.ip().octets()),
                v4.port(),
            )),
            _ => panic!("v4"),
        }
    };
    let _client = std::thread::spawn(move || {
        let s = TcpStream::connect(faddr).expect("connect");
        std::thread::sleep(Duration::from_millis(400));
        drop(s);
    });
    let cli_fd = loop {
        if let Some((fd, _)) = front.accept().expect("accept") {
            break fd;
        }
        std::thread::sleep(Duration::from_millis(2));
    };

    let t = Timeouts {
        client: 100,
        server: 0,
        connect: 0,
    };
    let mut sess = TcpSession::new(cli_fd, t, 3, Tick(1000));
    assert!(!sess.check_timeouts(Tick(1050)), "must not fire early");
    assert!(sess.check_timeouts(Tick(1101)), "must fire at the deadline");
    assert_eq!(
        sess.ending,
        Some(Ending::Timeout(ibex_rt::proxy::Which::Client)),
        "the ending must say which timeout fired, for the log"
    );
}

#[test]
fn connect_retries_are_counted_then_exhausted() {
    let front = Listener::bind(loopback0(), 128, 0).expect("bind");
    let cli = TcpStream::connect({
        let a = rustix::net::getsockname(front.borrowed_fd()).expect("getsockname");
        match a {
            rustix::net::SocketAddrAny::V4(v4) => SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(v4.ip().octets()),
                v4.port(),
            )),
            _ => panic!("v4"),
        }
    });
    drop(cli);
    let cli_fd = loop {
        if let Some((fd, _)) = front.accept().expect("accept") {
            break fd;
        }
        std::thread::sleep(Duration::from_millis(2));
    };

    let mut sess = TcpSession::new(cli_fd, Timeouts::default(), 2, Tick(1000));
    assert!(sess.server_failed(), "retry 1 of 2 available");
    assert!(sess.server_failed(), "retry 2 of 2 available");
    assert!(!sess.server_failed(), "retries exhausted");
    assert_eq!(sess.ending, Some(Ending::ConnectFailed));
}

#[test]
fn interests_express_backpressure() {
    let front = Listener::bind(loopback0(), 128, 0).expect("bind");
    let faddr = {
        let a = rustix::net::getsockname(front.borrowed_fd()).expect("getsockname");
        match a {
            rustix::net::SocketAddrAny::V4(v4) => SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(v4.ip().octets()),
                v4.port(),
            )),
            _ => panic!("v4"),
        }
    };
    let _c = std::thread::spawn(move || {
        TcpStream::connect(faddr).map(|_s| std::thread::sleep(Duration::from_millis(200)))
    });
    let cli_fd = loop {
        if let Some((fd, _)) = front.accept().expect("accept") {
            break fd;
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    let mut sess = TcpSession::new(cli_fd, Timeouts::default(), 3, Tick(1000));

    let (cli, _srv) = sess.interests();
    assert!(cli.read, "an empty request buffer means we want to read");
    assert!(
        !cli.write,
        "an empty response buffer means nothing to write"
    );

    // Fill the request buffer: we must stop asking to read, so TCP slows the client.
    let cap = sess.req.capacity();
    let w = sess.req.writable();
    let n = w.len().min(cap);
    for b in &mut w[..n] {
        *b = 0;
    }
    sess.req.commit(n);
    let (cli, _srv) = sess.interests();
    assert!(
        !cli.read,
        "a full request buffer must stop client reads: backpressure"
    );
}

#[test]
fn poller_and_fdtab_integrate_with_a_session() {
    // The wiring the real accept path uses.
    let front = Listener::bind(loopback0(), 128, 0).expect("bind");
    let poller = Poller::new(64).expect("epoll");
    let mut fds = FdTab::with_capacity(256);
    let lfd = front.raw_fd();
    fds.insert(lfd, FdState::Listener { listener: 0 }, Interest::READ);
    poller
        .add(
            front.borrowed_fd(),
            u64::try_from(lfd).expect("fd"),
            true,
            false,
        )
        .expect("add");
    assert_eq!(fds.state(lfd), FdState::Listener { listener: 0 });
    assert_eq!(fds.live(), 1);
}


fn start_dummy_backend(
    running: Arc<AtomicBool>,
) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind(loopback0()).expect("bind dummy srv");
    let addr = listener.local_addr().expect("addr");
    listener.set_nonblocking(true).expect("nonblocking");
    let h = thread::spawn(move || {
        while running.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if req.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                let _ = stream.flush();
            }
            thread::sleep(Duration::from_millis(2));
        }
    });
    (addr, h)
}

fn run_and_show_table(mut frontend: FrontendSection, requests: usize) -> String {
    let running = Arc::new(AtomicBool::new(true));
    let (srv_addr, backend) = start_dummy_backend(Arc::clone(&running));

    frontend.bind = Some(loopback0());
    let config = Config {
        frontends: vec![frontend],
        backends: vec![BackendSection {
            name: "be_track".into(),
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            servers: vec![Server::new("s1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("Engine::new");
    let fe_addr = engine.listeners[0].addr();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let cli_sock_path = temp_dir.path().join("ibex.sock");
    engine
        .bind_cli_socket(&cli_sock_path)
        .expect("bind_cli_socket");

    for _ in 0..requests {
        let mut client = TcpStream::connect(fe_addr).expect("connect to frontend");
        client.set_nonblocking(true).expect("set_nonblocking");
        client
            .write_all(b"GET /api/test HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("write req");

        let start = Instant::now();
        let mut response = Vec::new();
        let mut buf = [0u8; 1024];
        while start.elapsed() < Duration::from_secs(2) {
            let _ = engine.run_once().expect("engine step");
            if let Ok(n) = client.read(&mut buf) {
                if n > 0 {
                    response.extend_from_slice(&buf[..n]);
                    if response.windows(4).any(|w| w == b"\r\n\r\n") && response.len() > 20 {
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    for _ in 0..10 {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(2));
    }

    let mut cli = UnixStream::connect(&cli_sock_path).expect("connect to cli socket");
    cli.set_nonblocking(true).expect("set_nonblocking cli");
    cli.write_all(b"show table\n").expect("write show table");

    let start = Instant::now();
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    while start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once().expect("engine step");
        if let Ok(n) = cli.read(&mut buf) {
            if n > 0 {
                out.extend_from_slice(&buf[..n]);
                break;
            }
        }
        thread::sleep(Duration::from_millis(2));
    }

    running.store(false, Ordering::Relaxed);
    let _ = backend.join();
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn sc_inc_gpc0_increments_counter_and_reports_via_show_table() {
    let fe_addr = common::reserve_addr();
    let frontend = FrontendSection {
        name: "fe_gpc0".into(),
        bind: Some(fe_addr),
        mode: Mode::Http,
        clitimeout: Some(Duration::from_secs(3)),
        default_backend: Some("be_track".into()),
        stick_table: Some(StickTableConfigAst {
            key_type: "ip".into(),
            size: 100,
            expire: Duration::from_secs(60),
            store_fields: vec!["gpc0".into()],
        }),
        tcp_req_session_rules: vec![TcpReqSessionRule {
            action: TcpReqSessionAction::TrackSc0 {
                expr: "src".into(),
                table: None,
            },
            cond: None,
        }],
        tcp_req_content_rules: vec![TcpReqContentRule {
            action: TcpReqContentAction::ScIncGpc0 { sc: 0 },
            cond: None,
            line: 0,
        }],
        ..Default::default()
    };

    let dump = run_and_show_table(frontend, 2);

    assert!(
        dump.contains("# table: fe_gpc0"),
        "table fe_gpc0 was not declared in show table output:\n{dump}"
    );
    assert!(
        dump.contains("gpc0=2"),
        "tracked entry must contain gpc0=2 after 2 requests with sc-inc-gpc0(0), got:\n{dump}"
    );
}

#[test]
fn without_sc_inc_gpc0_gpc0_remains_zero() {
    let frontend = FrontendSection {
        name: "fe_no_gpc0".into(),
        bind: None,
        mode: Mode::Http,
        clitimeout: Some(Duration::from_secs(3)),
        default_backend: Some("be_track".into()),
        stick_table: Some(StickTableConfigAst {
            key_type: "ip".into(),
            size: 100,
            expire: Duration::from_secs(60),
            store_fields: vec!["gpc0".into()],
        }),
        tcp_req_session_rules: vec![TcpReqSessionRule {
            action: TcpReqSessionAction::TrackSc0 {
                expr: "src".into(),
                table: None,
            },
            cond: None,
        }],
        tcp_req_content_rules: Vec::new(),
        ..Default::default()
    };

    let dump = run_and_show_table(frontend, 2);

    assert!(
        dump.contains("# table: fe_no_gpc0"),
        "table fe_no_gpc0 was not declared in show table output:\n{dump}"
    );
    assert!(
        !dump.contains("gpc0=2") && dump.contains("gpc0=0"),
        "without sc-inc-gpc0, gpc0 must remain 0 (HAProxy prints a stored type at zero), got:\n{dump}"
    );
}

#[test]
fn session_scope_tracking_populates_stick_table() {
    let frontend = FrontendSection {
        name: "fe_session_track".into(),
        bind: None,
        mode: Mode::Http,
        clitimeout: Some(Duration::from_secs(3)),
        default_backend: Some("be_track".into()),
        stick_table: Some(StickTableConfigAst {
            key_type: "ip".into(),
            size: 100,
            expire: Duration::from_secs(60),
            store_fields: vec!["conn_cnt".into()],
        }),
        tcp_req_session_rules: vec![TcpReqSessionRule {
            action: TcpReqSessionAction::TrackSc0 {
                expr: "src".into(),
                table: None,
            },
            cond: None,
        }],
        ..Default::default()
    };

    let dump = run_and_show_table(frontend, 3);

    assert!(
        dump.contains("# table: fe_session_track"),
        "table fe_session_track was not declared in show table output:\n{dump}"
    );
    assert!(
        dump.contains("conn_cnt=3"),
        "session-scope tracking must report conn_cnt=3 after 3 connections, got:\n{dump}"
    );
}

struct TestDaemon(std::process::Child);

impl Drop for TestDaemon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn ibex_test_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_ibex"))
}

fn spawn_test_daemon(cfg: &std::path::Path) -> TestDaemon {
    TestDaemon(
        std::process::Command::new(ibex_test_bin())
            .arg("-f")
            .arg(cfg)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn ibex daemon"),
    )
}

fn write_test_cfg(name: &str, body: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("ibex_proxy_t_{}_{}", std::process::id(), name));
    std::fs::write(&p, body).expect("write test config");
    p
}

fn wait_for_test_port(port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}

struct TestBackend {
    port: u16,
    seen: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

impl TestBackend {
    fn spawn(conns: usize) -> Self {
        let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .expect("bind backend");
        let port = listener.local_addr().expect("addr").port();
        let seen: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        thread::spawn(move || {
            for _ in 0..conns {
                let Ok((mut c, _)) = listener.accept() else {
                    return;
                };
                c.set_read_timeout(Some(Duration::from_millis(500))).ok();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    match c.read(&mut tmp) {
                        Ok(n) if n > 0 => {
                            buf.extend_from_slice(&tmp[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Ok(_) | Err(_) => break,
                    }
                }
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
                let _ = c.flush();
                sink.lock().expect("lock").push(buf);
            }
        });
        Self { port, seen }
    }

    fn spawn_echo(conns: usize) -> Self {
        let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .expect("bind echo backend");
        let port = listener.local_addr().expect("addr").port();
        let seen: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        thread::spawn(move || {
            for _ in 0..conns {
                let Ok((mut c, _)) = listener.accept() else {
                    return;
                };
                c.set_read_timeout(Some(Duration::from_secs(10))).ok();
                let mut tmp = [0u8; 4096];
                if let Ok(n) = c.read(&mut tmp) {
                    sink.lock().expect("lock").push(tmp[..n].to_vec());
                    let _ = c.write_all(b"OK");
                    let _ = c.flush();
                }
            }
        });
        Self { port, seen }
    }

    fn requests(&self) -> Vec<String> {
        self.seen
            .lock()
            .expect("lock")
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect()
    }
}

/// -m end: pattern at the end of stream, arriving after a first flush.
#[test]
fn test_unanchored_end_matcher_waits_for_payload() {
    let be = TestBackend::spawn(1);
    let port = common::reserve_addr().port();
    let cfg_body = format!(
        "defaults\n\tmode tcp\n\ttimeout connect 3s\n\ttimeout client 5s\n\ttimeout server 5s\n\n\
         frontend fe\n\tbind 127.0.0.1:{port}\n\t\
         tcp-request inspect-delay 1s\n\t\
         tcp-request content reject if {{ req.payload(0,0) -m end SECRET_SUFFIX }}\n\t\
         default_backend be\n\n\
         backend be\n\tserver s1 127.0.0.1:{}\n",
        be.port
    );
    let cfg = write_test_cfg("inspect_end.cfg", &cfg_body);
    let _d = spawn_test_daemon(&cfg);
    assert!(wait_for_test_port(port), "daemon did not listen on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(&[b'A'; 30]).expect("write padding");
    s.flush().ok();
    thread::sleep(Duration::from_millis(200));
    s.write_all(b"SECRET_SUFFIX").expect("write suffix");
    s.flush().ok();
    thread::sleep(Duration::from_millis(600));

    assert!(
        be.requests().is_empty(),
        "unanchored -m end matcher must wait for suffix; backend saw: {:?}",
        be.requests()
    );
    let _ = std::fs::remove_file(&cfg);
}

/// -m reg: unanchored regex pattern arriving after a first flush.
#[test]
fn test_unanchored_reg_matcher_waits_for_payload() {
    let be = TestBackend::spawn(1);
    let port = common::reserve_addr().port();
    let cfg_body = format!(
        "defaults\n\tmode tcp\n\ttimeout connect 3s\n\ttimeout client 5s\n\ttimeout server 5s\n\n\
         frontend fe\n\tbind 127.0.0.1:{port}\n\t\
         tcp-request inspect-delay 1s\n\t\
         tcp-request content reject if {{ req.payload(0,0) -m reg (ALPHA|BETA)_KEY }}\n\t\
         default_backend be\n\n\
         backend be\n\tserver s1 127.0.0.1:{}\n",
        be.port
    );
    let cfg = write_test_cfg("inspect_reg.cfg", &cfg_body);
    let _d = spawn_test_daemon(&cfg);
    assert!(wait_for_test_port(port), "daemon did not listen on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(&[b'B'; 25]).expect("write padding");
    s.flush().ok();
    thread::sleep(Duration::from_millis(200));
    s.write_all(b"ALPHA_KEY").expect("write regex match");
    s.flush().ok();
    thread::sleep(Duration::from_millis(600));

    assert!(
        be.requests().is_empty(),
        "unanchored -m reg matcher must wait for match; backend saw: {:?}",
        be.requests()
    );
    let _ = std::fs::remove_file(&cfg);
}

/// req.payload(0,4) -m str with bytes present: must NOT wait out the delay.
#[test]
fn test_anchored_str_matcher_decides_immediately_without_waiting() {
    let be = TestBackend::spawn_echo(1);
    let port = common::reserve_addr().port();
    let cfg_body = format!(
        "defaults\n\tmode tcp\n\ttimeout connect 3s\n\ttimeout client 20s\n\ttimeout server 20s\n\n\
         frontend fe\n\tbind 127.0.0.1:{port}\n\t\
         tcp-request inspect-delay 5s\n\t\
         tcp-request content reject if {{ req.payload(0,4) -m str POST }}\n\t\
         default_backend be\n\n\
         backend be\n\tserver s1 127.0.0.1:{}\n",
        be.port
    );
    let cfg = write_test_cfg("inspect_anchored_latency.cfg", &cfg_body);
    let _d = spawn_test_daemon(&cfg);
    assert!(wait_for_test_port(port), "daemon did not listen on {port}");

    let start = Instant::now();
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(15))).ok();
    s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").expect("write GET");
    s.flush().ok();
    let mut sink = [0u8; 64];
    let _ = s.read(&mut sink);
    let elapsed = start.elapsed();

    assert!(
        !be.requests().is_empty(),
        "anchored GET request must reach backend"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "anchored match on known bytes must decide immediately on pass 1, took: {elapsed:?}"
    );
    let _ = std::fs::remove_file(&cfg);
}

/// Threshold probing: below (8 bytes), at (9 bytes), and above (10 bytes) pattern length 9.
#[test]
fn test_threshold_padding_lengths_around_pattern_size() {
    let be = TestBackend::spawn(3);
    let port = common::reserve_addr().port();
    let cfg_body = format!(
        "defaults\n\tmode tcp\n\ttimeout connect 3s\n\ttimeout client 5s\n\ttimeout server 5s\n\n\
         frontend fe\n\tbind 127.0.0.1:{port}\n\t\
         tcp-request inspect-delay 1s\n\t\
         tcp-request content reject if {{ req.payload(0,0) -m sub FORBIDDEN }}\n\t\
         default_backend be\n\n\
         backend be\n\tserver s1 127.0.0.1:{}\n",
        be.port
    );
    let cfg = write_test_cfg("inspect_thresholds.cfg", &cfg_body);
    let _d = spawn_test_daemon(&cfg);
    assert!(wait_for_test_port(port), "daemon did not listen on {port}");

    // Pattern is "FORBIDDEN" (9 bytes)
    // Probe 1: below threshold (8 bytes padding)
    // Probe 2: at threshold (9 bytes padding)
    // Probe 3: above threshold (10 bytes padding)
    for padding_len in [8, 9, 10] {
        let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.write_all(&vec![b'X'; padding_len]).expect("write padding");
        s.flush().ok();
        thread::sleep(Duration::from_millis(200));
        s.write_all(b"FORBIDDEN-PAYLOAD").expect("write payload");
        s.flush().ok();
        thread::sleep(Duration::from_millis(500));
    }

    assert!(
        be.requests().is_empty(),
        "all threshold probes (below=8, at=9, above=10) must be rejected when payload arrives, got: {:?}",
        be.requests()
    );
    let _ = std::fs::remove_file(&cfg);
}

#[test]
fn test_tcp_request_connection_reject_and_silent_drop() {
    // 1. Connection reject
    let fe_addr1 = common::reserve_addr();
    let config_reject = Config {
        frontends: vec![FrontendSection {
            name: "fe_conn_reject".into(),
            bind: Some(fe_addr1),
            mode: Mode::Tcp,
            clitimeout: Some(Duration::from_secs(3)),
            tcp_req_conn_rules: vec![TcpReqConnRule {
                action: TcpReqConnAction::Reject,
                cond: None,
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut engine = Engine::new(&config_reject, 64).expect("Engine::new");
    let client = TcpStream::connect(fe_addr1).expect("connect");
    drop(client);
    common::drive_until(&mut engine, |e| e.proxies[0].stats[0].denied_conn.load(std::sync::atomic::Ordering::Relaxed) >= 1);
    assert_eq!(
        engine.proxies[0].stats[0].denied_conn.load(std::sync::atomic::Ordering::Relaxed), 1,
        "tcp-request connection reject must increment denied_conn"
    );

    // 2. Connection silent-drop
    let fe_addr2 = common::reserve_addr();
    let config_drop = Config {
        frontends: vec![FrontendSection {
            name: "fe_conn_drop".into(),
            bind: Some(fe_addr2),
            mode: Mode::Tcp,
            clitimeout: Some(Duration::from_secs(3)),
            tcp_req_conn_rules: vec![TcpReqConnRule {
                action: TcpReqConnAction::SilentDrop,
                cond: None,
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut engine2 = Engine::new(&config_drop, 64).expect("Engine::new");
    let client2 = TcpStream::connect(fe_addr2).expect("connect");
    drop(client2);
    common::drive_until(&mut engine2, |e| e.proxies[0].stats[0].denied_conn.load(std::sync::atomic::Ordering::Relaxed) >= 1);
    assert_eq!(
        engine2.proxies[0].stats[0].denied_conn.load(std::sync::atomic::Ordering::Relaxed), 1,
        "tcp-request connection silent-drop must increment denied_conn"
    );
}

#[test]
fn test_tcp_request_session_reject_and_silent_drop() {
    // 1. Session reject
    let fe_addr1 = common::reserve_addr();
    let config_reject = Config {
        frontends: vec![FrontendSection {
            name: "fe_sess_reject".into(),
            bind: Some(fe_addr1),
            mode: Mode::Tcp,
            clitimeout: Some(Duration::from_secs(3)),
            tcp_req_session_rules: vec![TcpReqSessionRule {
                action: TcpReqSessionAction::Reject,
                cond: None,
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut engine = Engine::new(&config_reject, 64).expect("Engine::new");
    let client = TcpStream::connect(fe_addr1).expect("connect");
    drop(client);
    common::drive_until(&mut engine, |e| e.proxies[0].stats[0].denied_req.load(std::sync::atomic::Ordering::Relaxed) >= 1);
    assert_eq!(
        engine.proxies[0].stats[0].denied_req.load(std::sync::atomic::Ordering::Relaxed), 1,
        "tcp-request session reject must increment denied_req"
    );

    // 2. Session silent-drop
    let fe_addr2 = common::reserve_addr();
    let config_drop = Config {
        frontends: vec![FrontendSection {
            name: "fe_sess_drop".into(),
            bind: Some(fe_addr2),
            mode: Mode::Tcp,
            clitimeout: Some(Duration::from_secs(3)),
            tcp_req_session_rules: vec![TcpReqSessionRule {
                action: TcpReqSessionAction::SilentDrop,
                cond: None,
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut engine2 = Engine::new(&config_drop, 64).expect("Engine::new");
    let client2 = TcpStream::connect(fe_addr2).expect("connect");
    drop(client2);
    common::drive_until(&mut engine2, |e| e.proxies[0].stats[0].denied_req.load(std::sync::atomic::Ordering::Relaxed) >= 1);
    assert_eq!(
        engine2.proxies[0].stats[0].denied_req.load(std::sync::atomic::Ordering::Relaxed), 1,
        "tcp-request session silent-drop must increment denied_req"
    );
}

#[test]
fn test_tcp_request_content_reject_and_silent_drop() {
    // 1. Content reject
    let fe_addr1 = common::reserve_addr();
    let config_reject = Config {
        frontends: vec![FrontendSection {
            name: "fe_cnt_reject".into(),
            bind: Some(fe_addr1),
            mode: Mode::Tcp,
            clitimeout: Some(Duration::from_secs(3)),
            tcp_req_inspect_delay: Some(Duration::from_millis(500)),
            tcp_req_content_rules: vec![TcpReqContentRule {
                action: TcpReqContentAction::Reject,
                cond: None,
                line: 0,
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut engine = Engine::new(&config_reject, 64).expect("Engine::new");
    let mut client = TcpStream::connect(fe_addr1).expect("connect");
    let _ = client.write_all(b"HELLO");
    common::drive_until(&mut engine, |e| e.proxies[0].stats[0].denied_req.load(std::sync::atomic::Ordering::Relaxed) >= 1);
    assert_eq!(
        engine.proxies[0].stats[0].denied_req.load(std::sync::atomic::Ordering::Relaxed), 1,
        "tcp-request content reject must increment denied_req"
    );

    // 2. Content silent-drop
    let fe_addr2 = common::reserve_addr();
    let config_drop = Config {
        frontends: vec![FrontendSection {
            name: "fe_cnt_drop".into(),
            bind: Some(fe_addr2),
            mode: Mode::Tcp,
            clitimeout: Some(Duration::from_secs(3)),
            tcp_req_inspect_delay: Some(Duration::from_millis(500)),
            tcp_req_content_rules: vec![TcpReqContentRule {
                action: TcpReqContentAction::SilentDrop,
                cond: None,
                line: 0,
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut engine2 = Engine::new(&config_drop, 64).expect("Engine::new");
    let mut client2 = TcpStream::connect(fe_addr2).expect("connect");
    let _ = client2.write_all(b"HELLO");
    common::drive_until(&mut engine2, |e| e.proxies[0].stats[0].denied_req.load(std::sync::atomic::Ordering::Relaxed) >= 1);
    assert_eq!(
        engine2.proxies[0].stats[0].denied_req.load(std::sync::atomic::Ordering::Relaxed), 1,
        "tcp-request content silent-drop must increment denied_req"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_header_size_boundary_against_bufsize_minus_maxrewrite() {
    let (srv_listener, srv_addr) = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let a = l.local_addr().expect("local_addr");
        (l, a)
    };
    let fe_addr = common::reserve_addr();

    let backend_seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let backend_seen_clone = Arc::clone(&backend_seen);
    let response_mode = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let response_mode_clone = Arc::clone(&response_mode);
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let running_clone = Arc::clone(&running);

    let _srv_thread = thread::spawn(move || {
        srv_listener.set_nonblocking(true).ok();
        while running_clone.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok((mut stream, _)) = srv_listener.accept() {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                while let Ok(n) = stream.read(&mut tmp) {
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                backend_seen_clone.lock().unwrap().push(buf);

                let mode = response_mode_clone.load(std::sync::atomic::Ordering::Relaxed);
                let resp_body = match mode {
                    1 => {
                        // Response below threshold: 3071 bytes header
                        // HTTP/1.1 200 OK\r\n (17) + X-Padding:  (11) + \r\n\r\n (4) = 32 bytes
                        let pad_len = 3071 - 32;
                        let pad = "X".repeat(pad_len);
                        format!("HTTP/1.1 200 OK\r\nX-Padding: {pad}\r\n\r\nOK").into_bytes()
                    }
                    2 => {
                        // Response at threshold: 3072 bytes header
                        let pad_len = 3072 - 32;
                        let pad = "X".repeat(pad_len);
                        format!("HTTP/1.1 200 OK\r\nX-Padding: {pad}\r\n\r\nOK").into_bytes()
                    }
                    3 => {
                        // Response above threshold: 3073 bytes header
                        let pad_len = 3073 - 32;
                        let pad = "X".repeat(pad_len);
                        format!("HTTP/1.1 200 OK\r\nX-Padding: {pad}\r\n\r\nOK").into_bytes()
                    }
                    _ => b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_vec(),
                };
                let _ = stream.write_all(&resp_body);
                let _ = stream.flush();
            }
            thread::sleep(Duration::from_millis(1));
        }
    });

    let config = Config {
        global: Some(ibex_config::ast::GlobalSection {
            bufsize: Some(4096),
            maxrewrite: Some(1024),
            ..Default::default()
        }),
        frontends: vec![FrontendSection {
            name: "fe_thresh".into(),
            bind: Some(fe_addr),
            mode: Mode::Http,
            default_backend: Some("be_thresh".into()),
            clitimeout: Some(Duration::from_secs(5)),
            ..Default::default()
        }],
        backends: vec![BackendSection {
            name: "be_thresh".into(),
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(5)),
            srvtimeout: Some(Duration::from_secs(5)),
            servers: vec![Server::new("s1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("Engine::new");

    let drive_req = |eng: &mut Engine, req: &[u8]| -> String {
        let mut client = TcpStream::connect(fe_addr).expect("connect to fe");
        client.set_nonblocking(true).expect("set_nonblocking");
        client.write_all(req).expect("write req");

        let start = Instant::now();
        let mut response = Vec::new();
        let mut tmp = [0u8; 1024];
        while start.elapsed() < Duration::from_secs(2) {
            let _ = eng.run_once();
            if let Ok(n) = client.read(&mut tmp) {
                if n > 0 {
                    response.extend_from_slice(&tmp[..n]);
                    if response.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
        for _ in 0..5 {
            let _ = eng.run_once();
            thread::sleep(Duration::from_millis(1));
        }
        String::from_utf8_lossy(&response).into_owned()
    };

    // 1. Request below threshold: 3071 bytes
    // Fixed: GET / HTTP/1.1\r\n (16) + X-Padding:  (11) + \r\n\r\n (4) = 31 bytes
    let pad_below = "A".repeat(3071 - 31);
    let req_below = format!("GET / HTTP/1.1\r\nX-Padding: {pad_below}\r\n\r\n").into_bytes();
    assert_eq!(req_below.len(), 3071);
    let resp1 = drive_req(&mut engine, &req_below);
    assert!(
        resp1.starts_with("HTTP/1.1 200 OK"),
        "below threshold must succeed with 200 OK, got: {resp1}"
    );
    assert_eq!(
        backend_seen.lock().unwrap().len(),
        1,
        "backend must have received below-threshold request"
    );

    // 2. Request at threshold: 3072 bytes
    let pad_at = "B".repeat(3072 - 31);
    let req_at = format!("GET / HTTP/1.1\r\nX-Padding: {pad_at}\r\n\r\n").into_bytes();
    assert_eq!(req_at.len(), 3072);
    let resp2 = drive_req(&mut engine, &req_at);
    assert!(
        resp2.starts_with("HTTP/1.1 200 OK"),
        "at threshold must succeed with 200 OK, got: {resp2}"
    );
    assert_eq!(
        backend_seen.lock().unwrap().len(),
        2,
        "backend must have received at-threshold request"
    );

    // 3. Request above threshold: 3073 bytes
    let pad_above = "C".repeat(3073 - 31);
    let req_above = format!("GET / HTTP/1.1\r\nX-Padding: {pad_above}\r\n\r\n").into_bytes();
    assert_eq!(req_above.len(), 3073);
    let resp3 = drive_req(&mut engine, &req_above);
    // The status, not the reason: the page is HAProxy's built-in one now, which says
    // "Bad request". (HAProxy 3.5 itself answers 431 here, and already at 3071 bytes:
    // tasks/T87.)
    assert!(
        resp3.starts_with("HTTP/1.1 400 "),
        "above threshold must produce 400 Bad Request, got: {resp3}"
    );
    assert_eq!(
        backend_seen.lock().unwrap().len(),
        2,
        "backend must NOT receive above-threshold request"
    );

    // 4. Response below threshold (3071 bytes header)
    response_mode.store(1, std::sync::atomic::Ordering::Relaxed);
    let resp4 = drive_req(&mut engine, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(
        resp4.starts_with("HTTP/1.1 200 OK"),
        "response below threshold must succeed, got: {resp4}"
    );

    // 5. Response at threshold (3072 bytes header)
    response_mode.store(2, std::sync::atomic::Ordering::Relaxed);
    let resp5 = drive_req(&mut engine, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(
        resp5.starts_with("HTTP/1.1 200 OK"),
        "response at threshold must succeed, got: {resp5}"
    );

    // 6. Response above threshold (3073 bytes header) -> 502 Bad Gateway
    response_mode.store(3, std::sync::atomic::Ordering::Relaxed);
    let resp6 = drive_req(&mut engine, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(
        resp6.starts_with("HTTP/1.1 502 Bad Gateway"),
        "response above threshold must produce 502 Bad Gateway, got: {resp6}"
    );

    running.store(false, std::sync::atomic::Ordering::Relaxed);
}

