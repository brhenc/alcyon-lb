// SPDX-License-Identifier: GPL-2.0-or-later

use ibex_rt::dgram::{DgramSocket, DgramBuf};
use serde::Deserialize;
use std::net::{UdpSocket, SocketAddr, IpAddr, Ipv4Addr};

#[derive(Deserialize)]
struct Packet {
    dir: String,
    len: usize,
    hex: String,
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn test_dgram_path_c2s_batch() {
    let json = std::fs::read_to_string("../../data/quic_handshake_capture.json").unwrap();
    let packets: Vec<Packet> = serde_json::from_str(&json).unwrap();
    let c2s_packets: Vec<_> = packets.into_iter().filter(|p| p.dir == "c2s").collect();

    assert_eq!(c2s_packets.len(), 9);

    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    let socket = DgramSocket::bind(server_addr).unwrap();
    let bound_addr = socket.local_addr().unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client_addr = client.local_addr().unwrap();

    // Send all c2s packets
    for p in &c2s_packets {
        let mut data = vec![0u8; p.len];
        let prefix = hex_to_bytes(&p.hex);
        data[..prefix.len()].copy_from_slice(&prefix);
        client.send_to(&data, bound_addr).unwrap();
    }

    // Now recv batch
    let mut bufs_data = vec![vec![0u8; 1500]; 10];
    let mut cmsgs = vec![vec![0u8; 128]; 10];
    let mut dgram_bufs: Vec<DgramBuf> = bufs_data.iter_mut().zip(cmsgs.iter_mut()).map(|(buf, cmsg_buf)| DgramBuf {
        buf,
        cmsg_buf,
        len: 0,
        wire_len: 0,
        src_addr: None,
        dst_addr: None,
        truncated: false,
    }).collect();

    let n = socket.recv_batch(&mut dgram_bufs).unwrap();
    assert_eq!(n, 9);

    for i in 0..9 {
        let p = &c2s_packets[i];
        assert_eq!(dgram_bufs[i].len, p.len);
        assert_eq!(dgram_bufs[i].src_addr, Some(client_addr));
        assert_eq!(dgram_bufs[i].dst_addr, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert_eq!(dgram_bufs[i].truncated, false);
        
        let prefix = hex_to_bytes(&p.hex);
        assert_eq!(&dgram_bufs[i].buf[..prefix.len()], prefix.as_slice());
    }

    // Test truncation
    let p = &c2s_packets[0];
    let mut data = vec![0u8; 1200];
    let prefix = hex_to_bytes(&p.hex);
    data[..prefix.len()].copy_from_slice(&prefix);
    client.send_to(&data, bound_addr).unwrap();

    let mut small_buf = vec![0u8; 1199];
    let mut small_cmsg = vec![0u8; 128];
    let mut small_dgrams = vec![DgramBuf {
        buf: &mut small_buf,
        cmsg_buf: &mut small_cmsg,
        len: 0,
        wire_len: 0,
        src_addr: None,
        dst_addr: None,
        truncated: false,
    }];

    let n = socket.recv_batch(&mut small_dgrams).unwrap();
    assert_eq!(n, 1);
    assert_eq!(small_dgrams[0].truncated, true);
    
    // Check EAGAIN behavior
    let n = socket.recv_batch(&mut dgram_bufs).unwrap();
    assert_eq!(n, 0);
}
