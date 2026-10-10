// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! End-to-end parity test: curl against `HAProxy` 1.0.2 vs Ibex proxy runtime.
//!
//! Verifies that real HTTP traffic via `curl` through Ibex returns byte-identical
//! responses to `HAProxy` 1.0.2 in `mode tcp`.

use crate::common;

use ibex_rt::proxy::{TcpSession, Timeouts};
use ibex_rt::{Listener, Poller};
use ibex_sched::Tick;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn loopback0() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

fn owned(s: TcpStream) -> OwnedFd {
    s.set_nonblocking(true).expect("nonblocking");
    OwnedFd::from(s)
}

fn bound_addr(l: &Listener) -> SocketAddr {
    let any = rustix::net::getsockname(l.borrowed_fd()).expect("getsockname");
    match any {
        rustix::net::SocketAddrAny::V4(v4) => SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(v4.ip().octets()),
            v4.port(),
        )),
        _ => panic!("expected v4"),
    }
}

/// A versatile HTTP backend server.
fn start_http_backend() -> (SocketAddr, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind(loopback0()).expect("bind backend");
    let addr = listener.local_addr().expect("local addr");
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    listener.set_nonblocking(true).expect("nonblocking");

    let handle = std::thread::spawn(move || {
        while r.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).ok();
                    let mut buf = vec![0u8; 512 * 1024];
                    if let Ok(n) = stream.read(&mut buf) {
                        if n > 0 {
                            let req = String::from_utf8_lossy(&buf[..n]);
                            let (status, body) = if req.starts_with("GET /large") {
                                ("200 OK", "X".repeat(256 * 1024))
                            } else if req.starts_with("GET /404") {
                                ("404 Not Found", "RESOURCE_NOT_FOUND".to_string())
                            } else {
                                ("200 OK", format!("HTTP_ECHO:\n{req}"))
                            };

                            let response = format!(
                                "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len(),
                            );
                            let _ = stream.write_all(response.as_bytes());
                            let _ = stream.shutdown(std::net::Shutdown::Write);
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    (addr, running, handle)
}

/// Spawns `HAProxy` 1.0.2 pointing to backend.
fn spawn_haproxy102(backend_addr: SocketAddr) -> Option<(SocketAddr, std::process::Child, String)> {
    let haproxy_bin = "/home/bhenc/reference/haproxy-1.0.2/haproxy102";
    if !std::path::Path::new(haproxy_bin).exists() {
        return None;
    }

    let front_port = common::reserve_port();

    let front_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, front_port));

    let cfg_path = format!(
        "/tmp/haproxy102_test_{}_{}.cfg",
        std::process::id(),
        front_port
    );
    let cfg = format!(
        "listen tcptest 127.0.0.1:{}\n\tmode\ttcp\n\tdispatch 127.0.0.1:{}\n\tcontimeout\t3000\n\tclitimeout\t15000\n\tsrvtimeout\t15000\n\tmaxconn\t100\n\tretries\t2\n",
        front_port,
        backend_addr.port()
    );
    std::fs::write(&cfg_path, cfg).expect("write cfg");

    let child = Command::new(haproxy_bin)
        .arg("-f")
        .arg(&cfg_path)
        .arg("-d") // foreground mode
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn haproxy102");

    // Wait for haproxy to bind
    for _ in 0..50 {
        if TcpStream::connect(front_addr).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    Some((front_addr, child, cfg_path))
}

/// Runs the Ibex proxy event loop in a background thread.
#[allow(clippy::too_many_lines)]
fn spawn_ibex_proxy(
    backend_addr: SocketAddr,
) -> (SocketAddr, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let front = Listener::bind(loopback0(), 128, 0).expect("bind front");
    let front_addr = bound_addr(&front);
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    let handle = std::thread::spawn(move || {
        let mut poller = Poller::new(256).expect("poller new");
        let lfd = front.raw_fd();
        poller
            .add(
                front.borrowed_fd(),
                u64::try_from(lfd).expect("fd fits"),
                true,
                false,
            )
            .expect("add listener");

        let mut sessions: Vec<Option<TcpSession>> = Vec::new();
        let mut fd_to_sess: HashMap<RawFd, usize> = HashMap::new();
        let mut now = Tick(1000);

        while r.load(Ordering::Relaxed) {
            let mut events = Vec::new();
            poller
                .poll(Some(Duration::from_millis(5)), |ev| events.push(ev))
                .expect("poll");
            now = now.add(5);

            for ev in events {
                if ev.fd == lfd {
                    // Accept loop
                    while let Ok(Some((cli_fd, _))) = front.accept() {
                        if let Ok(srv) = TcpStream::connect(backend_addr) {
                            let mut sess = TcpSession::new(cli_fd, Timeouts::default(), 3, now);
                            let srv_owned = owned(srv);
                            let cli_raw = sess.cli.as_raw_fd();
                            let srv_raw = srv_owned.as_raw_fd();

                            sess.attach_server(srv_owned, now);
                            sess.server_connected(now);
                            let _ = sess.process(now);

                            // Find or allocate slot
                            let slot = if let Some(i) = sessions.iter().position(Option::is_none) {
                                sessions[i] = Some(sess);
                                i
                            } else {
                                sessions.push(Some(sess));
                                sessions.len() - 1
                            };

                            fd_to_sess.insert(cli_raw, slot);
                            fd_to_sess.insert(srv_raw, slot);

                            if let Some(s) = &sessions[slot] {
                                let (cli_w, srv_w) = s.interests();
                                let _ = poller.add(
                                    s.cli.as_fd(),
                                    u64::try_from(cli_raw).expect("u64"),
                                    cli_w.read,
                                    cli_w.write,
                                );
                                if let Some(srv_fd) = &s.srv {
                                    let _ = poller.add(
                                        srv_fd.as_fd(),
                                        u64::try_from(srv_raw).expect("u64"),
                                        srv_w.read,
                                        srv_w.write,
                                    );
                                }
                            }
                        }
                    }
                } else if let Some(&slot) = fd_to_sess.get(&ev.fd) {
                    if let Some(sess) = &mut sessions[slot] {
                        let _ = sess.process(now);
                    }
                }
            }

            // Cleanup & interest update
            for slot_opt in &mut sessions {
                if let Some(sess) = slot_opt {
                    let _ = sess.process(now);
                    let cli_raw = sess.cli.as_raw_fd();
                    let srv_raw = sess.srv.as_ref().map(AsRawFd::as_raw_fd);

                    if sess.is_done() {
                        let _ = poller.delete(sess.cli.as_fd());
                        fd_to_sess.remove(&cli_raw);
                        if let Some(sfd) = &sess.srv {
                            let _ = poller.delete(sfd.as_fd());
                        }
                        if let Some(sr) = srv_raw {
                            fd_to_sess.remove(&sr);
                        }
                        *slot_opt = None;
                    } else {
                        let (cli_w, srv_w) = sess.interests();
                        let _ = poller.modify(
                            sess.cli.as_fd(),
                            u64::try_from(cli_raw).expect("u64"),
                            cli_w.read,
                            cli_w.write,
                        );
                        if let Some(sfd) = &sess.srv {
                            if let Some(sr) = srv_raw {
                                let _ = poller.modify(
                                    sfd.as_fd(),
                                    u64::try_from(sr).expect("u64"),
                                    srv_w.read,
                                    srv_w.write,
                                );
                            }
                        }
                    }
                }
            }
        }
    });

    (front_addr, running, handle)
}

struct TestContext {
    haproxy_addr: SocketAddr,
    ibex_addr: SocketAddr,
    haproxy_child: std::process::Child,
    cfg_path: String,
    b_run: Arc<AtomicBool>,
    i_run: Arc<AtomicBool>,
    b_handle: Option<std::thread::JoinHandle<()>>,
    i_handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for TestContext {
    fn drop(&mut self) {
        let _ = self.haproxy_child.kill();
        let _ = self.haproxy_child.wait();
        let _ = std::fs::remove_file(&self.cfg_path);
        self.b_run.store(false, Ordering::Relaxed);
        self.i_run.store(false, Ordering::Relaxed);
        if let Some(h) = self.b_handle.take() {
            let _ = h.join();
        }
        if let Some(h) = self.i_handle.take() {
            let _ = h.join();
        }
    }
}

fn setup_test_proxies() -> TestContext {
    let (backend_addr, b_run, b_handle) = start_http_backend();
    let (ibex_addr, i_run, i_handle) = spawn_ibex_proxy(backend_addr);

    let (haproxy_addr, haproxy_child, cfg_path) =
        spawn_haproxy102(backend_addr).expect("HAProxy 1.0.2 binary must exist and run");

    TestContext {
        haproxy_addr,
        ibex_addr,
        haproxy_child,
        cfg_path,
        b_run,
        i_run,
        b_handle: Some(b_handle),
        i_handle: Some(i_handle),
    }
}

#[test]
fn curl_parity_get_and_post() {
    let ctx = setup_test_proxies();

    // 1. GET request via curl
    let get_path = "/test/get/path";
    let h_get = Command::new("curl")
        .arg("-s")
        .arg("-H")
        .arg("Host: localhost")
        .arg(format!("http://{}{get_path}", ctx.haproxy_addr))
        .output()
        .expect("curl haproxy get");
    let i_get = Command::new("curl")
        .arg("-s")
        .arg("-H")
        .arg("Host: localhost")
        .arg(format!("http://{}{get_path}", ctx.ibex_addr))
        .output()
        .expect("curl ibex get");

    assert_eq!(h_get.status, i_get.status, "HTTP status must match");
    assert_eq!(
        String::from_utf8_lossy(&h_get.stdout),
        String::from_utf8_lossy(&i_get.stdout),
        "GET response body must match byte-for-byte between HAProxy 1.0 and Ibex"
    );

    // 2. POST request with payload via curl
    let post_body = "HELLO_IBEX_POST_PAYLOAD_123456789";
    let h_post = Command::new("curl")
        .arg("-s")
        .arg("-H")
        .arg("Host: localhost")
        .arg("-d")
        .arg(post_body)
        .arg(format!("http://{}/test/post", ctx.haproxy_addr))
        .output()
        .expect("curl haproxy post");
    let i_post = Command::new("curl")
        .arg("-s")
        .arg("-H")
        .arg("Host: localhost")
        .arg("-d")
        .arg(post_body)
        .arg(format!("http://{}/test/post", ctx.ibex_addr))
        .output()
        .expect("curl ibex post");

    assert_eq!(h_post.status, i_post.status);
    assert_eq!(
        String::from_utf8_lossy(&h_post.stdout),
        String::from_utf8_lossy(&i_post.stdout),
        "POST response body must match byte-for-byte between HAProxy 1.0 and Ibex"
    );
}

#[test]
fn curl_parity_headers_and_large_payload() {
    let ctx = setup_test_proxies();

    // 1. Custom Headers via curl
    let h_hdr = Command::new("curl")
        .arg("-s")
        .arg("-H")
        .arg("Host: localhost")
        .arg("-H")
        .arg("X-Ibex-Custom: TestHeaderValue42")
        .arg(format!("http://{}/headers", ctx.haproxy_addr))
        .output()
        .expect("curl haproxy hdr");
    let i_hdr = Command::new("curl")
        .arg("-s")
        .arg("-H")
        .arg("Host: localhost")
        .arg("-H")
        .arg("X-Ibex-Custom: TestHeaderValue42")
        .arg(format!("http://{}/headers", ctx.ibex_addr))
        .output()
        .expect("curl ibex hdr");

    assert_eq!(
        String::from_utf8_lossy(&h_hdr.stdout),
        String::from_utf8_lossy(&i_hdr.stdout),
        "Custom header request must match between HAProxy 1.0 and Ibex"
    );

    // 2. Large response payload (256 KB) via curl
    let h_large = Command::new("curl")
        .arg("-s")
        .arg("-H")
        .arg("Host: localhost")
        .arg(format!("http://{}/large", ctx.haproxy_addr))
        .output()
        .expect("curl haproxy large");
    let i_large = Command::new("curl")
        .arg("-s")
        .arg("-H")
        .arg("Host: localhost")
        .arg(format!("http://{}/large", ctx.ibex_addr))
        .output()
        .expect("curl ibex large");

    assert_eq!(h_large.stdout.len(), i_large.stdout.len());
    assert_eq!(
        h_large.stdout, i_large.stdout,
        "Large payload must match byte-for-byte"
    );
}
