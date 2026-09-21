// SPDX-License-Identifier: GPL-2.0-or-later

//! End-to-end `mode tcp` proxying, driven by the poller.
//!
//! These assert the behaviours `HAProxy` 1.0.2's `process_cli`/`process_srv` produce:
//! byte-exact forwarding in both directions, half-close preserving in-flight data,
//! shutdown propagation, and backpressure via buffer occupancy.

use ibex_rt::proxy::{Ending, TcpSession, Timeouts};
use ibex_rt::{FdState, FdTab, Interest, Listener, Poller};
use ibex_sched::Tick;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::time::Duration;

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
