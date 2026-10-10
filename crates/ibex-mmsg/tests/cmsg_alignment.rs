// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The control-message buffer handed to the kernel is aligned for `cmsghdr`, whatever
//! address the caller's `&mut [u8]` starts at (T241 item 5).

use ibex_mmsg::{align_cmsg, recvmmsg, set_ip_pktinfo, RecvMsg};
use std::net::UdpSocket;
use std::os::fd::AsFd;

#[test]
fn every_start_address_gets_an_aligned_buffer_inside_the_original() {
    let mut raw = [0u8; 300];
    let align = std::mem::align_of::<libc::cmsghdr>();
    for skip in 0..align {
        let (start, len) = (raw[skip..].as_ptr() as usize, raw.len() - skip);
        let got = align_cmsg(&mut raw[skip..]);
        let at = got.as_ptr() as usize;
        assert_eq!(at % align, 0, "skip {skip}");
        assert!(at >= start && at + got.len() == start + len, "skip {skip}: the buffer must stay inside the original, to its end");
    }
    assert!(align_cmsg(&mut raw[..0]).is_empty());
    let mut tiny = [0u8; 2];
    assert!(align_cmsg(&mut tiny[1..]).len() < 2);
}

#[test]
fn a_datagram_is_received_with_an_unaligned_cmsg_buffer() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
    set_ip_pktinfo(server.as_fd(), true).expect("IP_PKTINFO");
    UdpSocket::bind("127.0.0.1:0").expect("client").send_to(b"probe", server.local_addr().expect("addr")).expect("send");
    let mut buf = [0u8; 64];
    let mut cmsg = [0u8; 257];
    let mut msgs = vec![RecvMsg { buf: &mut buf, cmsg_buf: &mut cmsg[1..], len: 0, wire_len: 0, src_addr: None, dst_addr: None, truncated: false }];
    assert_eq!(recvmmsg(server.as_fd(), &mut msgs).expect("recvmmsg"), 1);
    assert_eq!(msgs[0].dst_addr, Some("127.0.0.1".parse().expect("ip")));
}
