// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use std::net::UdpSocket;
use std::os::fd::AsFd;
use alcyon_mmsg::{sendmmsg, SendMsg, recvmmsg, RecvMsg};

#[test]
#[cfg_attr(miri, ignore = "UDP socket and sendmmsg/recvmmsg syscalls")]
fn test_sendmmsg_basic() {
    let server4 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let server6 = UdpSocket::bind("[::1]:0").unwrap();
    let client = UdpSocket::bind("0.0.0.0:0").unwrap();

    let addr4 = server4.local_addr().unwrap();
    let addr6 = server6.local_addr().unwrap();

    // one message IPv4
    let mut msg1 = SendMsg::new(b"hello");
    msg1.dst_addr = Some(addr4);
    let msgs = [msg1];
    let sent = sendmmsg(client.as_fd(), &msgs).unwrap();
    assert_eq!(sent, 1);

    // a batch mixing both
    let mut msg4 = SendMsg::new(b"msg4");
    msg4.dst_addr = Some(addr4);
    let mut msg6 = SendMsg::new(b"msg6");
    msg6.dst_addr = Some(addr6);
    
    let batch = [msg4, msg6];
    let client6 = UdpSocket::bind("[::]:0").unwrap(); // Can send both IPv4 and IPv6 on dual-stack OS
    let sent = sendmmsg(client6.as_fd(), &batch).unwrap();
    assert_eq!(sent, 2);
}

#[test]
#[cfg_attr(miri, ignore = "UDP socket and sendmmsg/recvmmsg syscalls")]
fn test_sendmmsg_connected() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.connect(server.local_addr().unwrap()).unwrap();

    let msg = SendMsg::new(b"connected");
    let sent = sendmmsg(client.as_fd(), &[msg]).unwrap();
    assert_eq!(sent, 1);
}

#[test]
#[cfg_attr(miri, ignore = "UDP socket and sendmmsg/recvmmsg syscalls")]
fn test_eagain_returns_ok_zero() {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_nonblocking(true).unwrap();

    let mut buf = [0u8; 10];
    let mut cmsg = [0u8; 10];
    let mut msgs = [RecvMsg::new(&mut buf, &mut cmsg)];

    let res = recvmmsg(sock.as_fd(), &mut msgs).unwrap();
    assert_eq!(res, 0);
}

#[test]
#[cfg_attr(miri, ignore = "UDP socket and sendmmsg/recvmmsg syscalls")]
fn test_zero_length_datagram() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();

    let mut send_msg = SendMsg::new(b"");
    send_msg.dst_addr = Some(server.local_addr().unwrap());
    
    let sent = sendmmsg(client.as_fd(), &[send_msg]).unwrap();
    assert_eq!(sent, 1);

    let mut buf = [0u8; 10];
    let mut cmsg = [0u8; 10];
    let mut recvs = [RecvMsg::new(&mut buf, &mut cmsg)];
    
    let n = recvmmsg(server.as_fd(), &mut recvs).unwrap();
    assert_eq!(n, 1);
    assert_eq!(recvs[0].len, 0);
    assert_eq!(recvs[0].wire_len, 0);
}

#[test]
#[cfg_attr(miri, ignore = "UDP socket and sendmmsg/recvmmsg syscalls")]
fn test_batch_larger_than_max() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    
    let mut send_msg = SendMsg::new(b"x");
    send_msg.dst_addr = Some(server.local_addr().unwrap());
    
    let mut sends = Vec::new();
    for _ in 0..100 {
        sends.push(SendMsg { buf: send_msg.buf, dst_addr: send_msg.dst_addr, src_addr: send_msg.src_addr });
    }
    
    let sent = sendmmsg(client.as_fd(), &sends).unwrap();
    assert_eq!(sent, 64); // BATCH_MAX is 64
}

#[test]
#[cfg_attr(miri, ignore = "UDP socket and sendmmsg/recvmmsg syscalls")]
fn test_empty_slices() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();

    let sent = sendmmsg(client.as_fd(), &[]).unwrap();
    assert_eq!(sent, 0);
    
    let n = recvmmsg(server.as_fd(), &mut []).unwrap();
    assert_eq!(n, 0);

    let mut empty_buf = [];
    let mut empty_cmsg = [];
    let mut recvs = [RecvMsg::new(&mut empty_buf, &mut empty_cmsg)];
    
    client.send_to(b"hello", server.local_addr().unwrap()).unwrap();
    
    let n = recvmmsg(server.as_fd(), &mut recvs).unwrap();
    assert_eq!(n, 1);
    assert_eq!(recvs[0].len, 0);
    assert_eq!(recvs[0].wire_len, 5); // TRUNCATED!
    assert!(recvs[0].truncated);
}

#[test]
#[cfg_attr(miri, ignore = "UDP socket and sendmmsg/recvmmsg syscalls")]
fn test_src_addr_correctness_two_senders() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client1 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client2 = UdpSocket::bind("127.0.0.1:0").unwrap();

    let c1_addr = client1.local_addr().unwrap();
    let c2_addr = client2.local_addr().unwrap();

    client1.send_to(b"1", server.local_addr().unwrap()).unwrap();
    client2.send_to(b"2", server.local_addr().unwrap()).unwrap();

    let mut buf1 = [0u8; 10];
    let mut cmsg1 = [0u8; 128];
    let mut buf2 = [0u8; 10];
    let mut cmsg2 = [0u8; 128];
    
    let mut recvs = [
        RecvMsg::new(&mut buf1, &mut cmsg1),
        RecvMsg::new(&mut buf2, &mut cmsg2),
    ];
    
    let n = recvmmsg(server.as_fd(), &mut recvs).unwrap();
    assert_eq!(n, 2);
    
    assert_eq!(&recvs[0].buf[..1], b"1");
    assert_eq!(recvs[0].src_addr, Some(c1_addr));
    
    assert_eq!(&recvs[1].buf[..1], b"2");
    assert_eq!(recvs[1].src_addr, Some(c2_addr));
}
