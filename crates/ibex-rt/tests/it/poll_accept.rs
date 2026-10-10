// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! End-to-end: epoll reports a pending connection, the listener accepts it, and bytes
//! move. This is the smallest thing that proves the runtime's foundation works rather
//! than merely compiles.

use ibex_rt::{FdState, FdTab, Interest, Listener, Poller};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::os::fd::AsFd;
use std::time::Duration;

fn loopback0() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
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

#[test]
fn epoll_reports_a_pending_connection_and_bytes_flow() {
    let listener = Listener::bind(loopback0(), 128, 0).expect("bind");
    let addr = bound_addr(&listener);

    let mut poller = Poller::new(64).expect("epoll_create");
    let mut fds = FdTab::with_capacity(1024);

    let lfd = listener.raw_fd();
    fds.insert(lfd, FdState::Listener { listener: 0 }, Interest::READ);
    poller
        .add(
            listener.borrowed_fd(),
            u64::try_from(lfd).expect("fd fits"),
            true,
            false,
        )
        .expect("epoll_ctl add");

    // Nothing pending yet: a zero timeout must return immediately with no events.
    let n = poller
        .poll(Some(Duration::ZERO), |_| panic!("no event expected"))
        .expect("poll");
    assert_eq!(n, 0, "an idle listener must report no readiness");

    // Connect from a client thread.
    let client = std::thread::spawn(move || {
        let mut s = TcpStream::connect(addr).expect("connect");
        s.write_all(b"PING").expect("write");
        let mut buf = [0u8; 16];
        let n = s.read(&mut buf).expect("read");
        buf[..n].to_vec()
    });

    // The listener must now become readable.
    let mut ready_fd = None;
    for _ in 0..50 {
        let n = poller
            .poll(Some(Duration::from_millis(100)), |ev| {
                assert!(ev.readable, "listener readiness must be readable");
                ready_fd = Some(ev.fd);
            })
            .expect("poll");
        if n > 0 {
            break;
        }
    }
    assert_eq!(ready_fd, Some(lfd), "epoll must name the listening fd");
    assert_eq!(
        fds.state(lfd),
        FdState::Listener { listener: 0 },
        "the fd table must identify what became ready"
    );

    // Accept, echo, close.
    let (conn, peer) = listener
        .accept()
        .expect("accept must not fail")
        .expect("a connection must be pending");
    assert_eq!(peer.ip(), Ipv4Addr::LOCALHOST, "peer address is recorded");

    let mut buf = [0u8; 64];
    let mut got = 0;
    for _ in 0..100 {
        match rustix::io::read(conn.as_fd(), &mut buf) {
            Ok(n) if n > 0 => {
                got = n;
                break;
            }
            Ok(_) => break,
            Err(rustix::io::Errno::WOULDBLOCK) => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("read: {e}"),
        }
    }
    assert_eq!(&buf[..got], b"PING");
    rustix::io::write(conn.as_fd(), b"PONG").expect("write");
    drop(conn);

    assert_eq!(client.join().expect("client thread"), b"PONG".to_vec());

    // Queue drained: a further accept reports None rather than erroring.
    assert!(listener.accept().expect("accept").is_none());
}

#[test]
fn poller_timeout_actually_waits() {
    let mut poller = Poller::new(8).expect("epoll_create");
    let start = std::time::Instant::now();
    let n = poller
        .poll(Some(Duration::from_millis(120)), |_| {})
        .expect("poll");
    let waited = start.elapsed();
    assert_eq!(n, 0);
    assert!(
        waited >= Duration::from_millis(100),
        "poll returned after {waited:?}; the scheduler sizes its sleep from this, so \
         a short return would spin the thread"
    );
}
