// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The destination address of a received datagram, for both families.
//!
//! A server bound to a wildcard must reply from the address the client aimed at, which means
//! knowing which local address a datagram arrived on. That comes from a control message, and
//! the constant that enables it is not the constant the kernel tags it with:
//! `setsockopt` takes `IPV6_RECVPKTINFO` (49), the cmsg arrives as `IPV6_PKTINFO` (50).
//! Checking for the former meant `dst_addr` was always `None` on IPv6.

use alcyon_mmsg::{recvmmsg, set_ip_pktinfo, set_ipv6_recvpktinfo, RecvMsg};
use std::net::{IpAddr, UdpSocket};
use std::os::fd::AsFd;

fn recv_one(server: &UdpSocket) -> (usize, Option<IpAddr>) {
    let mut buf = [0u8; 64];
    let mut cmsg = [0u8; 256];
    let mut msgs = vec![RecvMsg {
        buf: &mut buf,
        cmsg_buf: &mut cmsg,
        len: 0,
        wire_len: 0,
        src_addr: None,
        dst_addr: None,
        truncated: false,
    }];
    let n = recvmmsg(server.as_fd(), &mut msgs).expect("recvmmsg");
    (n, msgs[0].dst_addr)
}

#[test]
#[cfg_attr(miri, ignore = "UDP socket and sendmmsg/recvmmsg syscalls")]
fn ipv4_reports_the_destination_the_client_aimed_at() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind v4");
    set_ip_pktinfo(server.as_fd(), true).expect("IP_PKTINFO");
    let addr = server.local_addr().expect("addr");

    UdpSocket::bind("127.0.0.1:0")
        .expect("client")
        .send_to(b"probe", addr)
        .expect("send");

    let (n, dst) = recv_one(&server);
    assert_eq!(n, 1);
    assert_eq!(dst, Some(addr.ip()), "IP_PKTINFO must yield the local address");
}

#[test]
#[cfg_attr(miri, ignore = "UDP socket and sendmmsg/recvmmsg syscalls")]
fn ipv6_reports_the_destination_the_client_aimed_at() {
    let Ok(server) = UdpSocket::bind("[::1]:0") else {
        eprintln!("no IPv6 loopback on this host; skipping");
        return;
    };
    set_ipv6_recvpktinfo(server.as_fd(), true).expect("IPV6_RECVPKTINFO");
    let addr = server.local_addr().expect("addr");

    UdpSocket::bind("[::1]:0")
        .expect("client")
        .send_to(b"probe", addr)
        .expect("send");

    let (n, dst) = recv_one(&server);
    assert_eq!(n, 1);
    assert_eq!(
        dst,
        Some(addr.ip()),
        "the cmsg arrives tagged IPV6_PKTINFO, not IPV6_RECVPKTINFO; \
         checking the wrong constant leaves dst_addr None forever"
    );
}

/// A control buffer too small for the whole pktinfo (T611 / #1): the kernel cuts the message
/// short (`MSG_CTRUNC`, `cmsg_len` below `CMSG_LEN(size_of::<in_pktinfo>())`), and the
/// reader must not take the missing bytes as an address. The 8 bytes past the slice are 0xAA
/// so that reading them shows.
#[test]
#[cfg_attr(miri, ignore = "UDP socket and sendmmsg/recvmmsg syscalls")]
fn a_truncated_pktinfo_control_message_gives_no_destination() {
    #[repr(align(8))]
    struct Aligned([u8; 40]);
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind v4");
    set_ip_pktinfo(server.as_fd(), true).expect("IP_PKTINFO");
    let addr = server.local_addr().expect("addr");
    UdpSocket::bind("127.0.0.1:0").expect("client").send_to(b"probe", addr).expect("send");

    let mut buf = [0u8; 64];
    let mut ctl = Aligned([0xAA; 40]);
    let mut msgs = vec![RecvMsg::new(&mut buf, &mut ctl.0[..24])];
    let n = recvmmsg(server.as_fd(), &mut msgs).expect("recvmmsg");
    assert_eq!(n, 1);
    assert_eq!(msgs[0].dst_addr, None);
}
