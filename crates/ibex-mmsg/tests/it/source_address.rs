// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T552 (VV-27): `SendMsg::src_addr` reaches the wire. A socket bound to the wildcard address
//! sends each datagram from the source address it was given, as `HAProxy`'s `cmsg_set_saddr`
//! (`quic_sock.c`) does with `IP_PKTINFO` / `IPV6_PKTINFO`; without it the kernel picks the
//! route's source, which a client that connected to another local address drops.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::os::fd::AsFd;
use ibex_mmsg::{sendmmsg, SendMsg};

/// Sends one datagram from `sender` to `to` with `src_addr = src`; the source the receiver saw.
fn source_seen(sender: &UdpSocket, to: &UdpSocket, src: Option<IpAddr>) -> std::net::SocketAddr {
    to.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
    let mut msg = SendMsg::new(b"x");
    msg.dst_addr = Some(to.local_addr().unwrap());
    msg.src_addr = src;
    assert_eq!(sendmmsg(sender.as_fd(), &[msg]).unwrap(), 1);
    let mut buf = [0u8; 8];
    to.recv_from(&mut buf).unwrap().1
}

#[test]
fn wildcard_v4_sends_from_the_given_source() {
    let sender = UdpSocket::bind("0.0.0.0:0").unwrap();
    let to = UdpSocket::bind("127.0.0.1:0").unwrap();
    // Without a source the kernel picks the route's, 127.0.0.1.
    assert_eq!(source_seen(&sender, &to, None).ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    let want = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    let got = source_seen(&sender, &to, Some(want));
    assert_eq!(got.ip(), want, "the datagram left from {got}, not from the source it was given");
    assert_eq!(got.port(), sender.local_addr().unwrap().port());
}

#[test]
fn a_batch_carries_one_source_per_datagram() {
    let sender = UdpSocket::bind("0.0.0.0:0").unwrap();
    let to = UdpSocket::bind("127.0.0.1:0").unwrap();
    to.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
    let srcs = [Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 3), Ipv4Addr::LOCALHOST];
    let msgs: Vec<SendMsg> = srcs
        .iter()
        .map(|s| {
            let mut m = SendMsg::new(b"y");
            m.dst_addr = Some(to.local_addr().unwrap());
            m.src_addr = Some(IpAddr::V4(*s));
            m
        })
        .collect();
    assert_eq!(sendmmsg(sender.as_fd(), &msgs).unwrap(), 3);
    let mut buf = [0u8; 8];
    for s in srcs {
        assert_eq!(to.recv_from(&mut buf).unwrap().1.ip(), IpAddr::V4(s));
    }
}

/// The host has `::1` only, so the IPv6 cmsg is checked with the one address it has: it must be
/// accepted by the kernel (a malformed `IPV6_PKTINFO` is `EINVAL`) and honoured.
#[test]
fn wildcard_v6_accepts_a_source() {
    let Ok(sender) = UdpSocket::bind("[::]:0") else { return };
    let Ok(to) = UdpSocket::bind("[::1]:0") else { return };
    let got = source_seen(&sender, &to, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert_eq!(got.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
}

/// A dual-stack IPv6 socket reaching an IPv4 client through its mapped address: an IPv4 source
/// goes as its mapped form, which the kernel takes as the IPv4 source.
#[test]
fn mapped_destination_takes_an_ipv4_source() {
    let Ok(sender) = UdpSocket::bind("[::]:0") else { return };
    let to = UdpSocket::bind("127.0.0.1:0").unwrap();
    to.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
    let mut msg = SendMsg::new(b"m");
    msg.dst_addr = Some(std::net::SocketAddr::new(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), to.local_addr().unwrap().port()));
    msg.src_addr = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
    assert_eq!(sendmmsg(sender.as_fd(), &[msg]).unwrap(), 1);
    let mut buf = [0u8; 8];
    assert_eq!(to.recv_from(&mut buf).unwrap().1.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
}

/// An IPv4 destination with a mapped IPv6 source sends it as IPv4; a source that has no IPv4
/// form is left to the kernel rather than sent as a control message the kernel refuses.
#[test]
fn ipv4_destination_with_an_ipv6_source() {
    let sender = UdpSocket::bind("0.0.0.0:0").unwrap();
    let to = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mapped = IpAddr::V6(Ipv4Addr::new(127, 0, 0, 2).to_ipv6_mapped());
    assert_eq!(source_seen(&sender, &to, Some(mapped)).ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
    assert_eq!(source_seen(&sender, &to, Some(IpAddr::V6(Ipv6Addr::LOCALHOST))).ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
}
