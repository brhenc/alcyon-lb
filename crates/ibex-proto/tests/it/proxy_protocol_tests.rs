// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Integration and Property-based Tests for Ibex PROXY Protocol Implementation.

use ibex_proto::proxy_protocol::{
    ssl_client_flags, tlv_types, update_crc32c_in_buffer, ProxyAddress, ProxyCommand, ProxyHeader,
    ProxyParseError, ProxyTransport, ProxyVersion, TlvBuilder, PP2_SIGNATURE,
};
use proptest::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn test_haproxy_v1_ipv4_differential_vector() {
    let wire = b"PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n";
    let (hdr, consumed) = ProxyHeader::parse(wire).unwrap().unwrap();
    assert_eq!(consumed, wire.len());
    assert_eq!(hdr.version, ProxyVersion::V1);
    assert_eq!(hdr.command, ProxyCommand::Proxy);
    assert_eq!(hdr.transport, ProxyTransport::Stream);
    assert_eq!(
        hdr.address,
        ProxyAddress::Ipv4 {
            src_addr: Ipv4Addr::new(192, 168, 0, 1),
            dst_addr: Ipv4Addr::new(192, 168, 0, 11),
            src_port: 56324,
            dst_port: 443,
        }
    );

    let mut out = [0u8; 128];
    let written = hdr.encode(&mut out).unwrap();
    assert_eq!(&out[..written], wire);
}

#[test]
fn test_haproxy_v1_ipv6_differential_vector() {
    let wire =
        b"PROXY TCP6 2001:db8:85a3::8a2e:370:7334 2001:db8:85a3::8a2e:370:7335 56324 443\r\n";
    let (hdr, consumed) = ProxyHeader::parse(wire).unwrap().unwrap();
    assert_eq!(consumed, wire.len());
    assert_eq!(hdr.version, ProxyVersion::V1);
    assert_eq!(hdr.command, ProxyCommand::Proxy);

    let mut out = [0u8; 128];
    let written = hdr.encode(&mut out).unwrap();
    let (hdr2, consumed2) = ProxyHeader::parse(&out[..written]).unwrap().unwrap();
    assert_eq!(consumed2, written);
    assert_eq!(hdr2.address, hdr.address);
}

#[test]
fn test_haproxy_v1_unknown_differential_vectors() {
    let cases: &[&[u8]] = &[
        b"PROXY UNKNOWN\r\n",
        b"PROXY UNKNOWN 1.2.3.4 5.6.7.8 80 80\r\n",
        b"PROXY UNKNOWN arbitrary health check data\r\n",
    ];

    for &wire in cases {
        let (hdr, consumed) = ProxyHeader::parse(wire).unwrap().unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(hdr.version, ProxyVersion::V1);
        assert_eq!(hdr.command, ProxyCommand::Local);
        assert_eq!(hdr.address, ProxyAddress::Unspec);
    }
}

#[test]
fn test_haproxy_v2_binary_spec_example() {
    // 12-byte sig + ver_cmd(0x21 PROXY) + fam(0x11 TCP4) + len(12 bytes) + 12 addr bytes
    let mut wire = Vec::new();
    wire.extend_from_slice(PP2_SIGNATURE);
    wire.push(0x21); // Version 2, Command PROXY
    wire.push(0x11); // AF_INET, STREAM
    wire.extend_from_slice(&12u16.to_be_bytes());
    wire.extend_from_slice(&[192, 168, 0, 1]); // src IP
    wire.extend_from_slice(&[192, 168, 0, 11]); // dst IP
    wire.extend_from_slice(&56324u16.to_be_bytes()); // src port
    wire.extend_from_slice(&443u16.to_be_bytes()); // dst port

    let (hdr, consumed) = ProxyHeader::parse(&wire).unwrap().unwrap();
    assert_eq!(consumed, 16 + 12);
    assert_eq!(hdr.version, ProxyVersion::V2);
    assert_eq!(hdr.command, ProxyCommand::Proxy);
    assert_eq!(hdr.transport, ProxyTransport::Stream);
    assert_eq!(
        hdr.address,
        ProxyAddress::Ipv4 {
            src_addr: Ipv4Addr::new(192, 168, 0, 1),
            dst_addr: Ipv4Addr::new(192, 168, 0, 11),
            src_port: 56324,
            dst_port: 443,
        }
    );
}

#[test]
fn test_v2_comprehensive_tlv_pipeline() {
    let mut sub_buf = [0u8; 512];
    let mut sub_builder = TlvBuilder::new(&mut sub_buf);
    sub_builder
        .append_tlv(tlv_types::PP2_SUBTYPE_SSL_VERSION, b"TLSv1.3")
        .unwrap();
    sub_builder
        .append_tlv(tlv_types::PP2_SUBTYPE_SSL_CN, b"edge.ibex.internal")
        .unwrap();
    sub_builder
        .append_tlv(tlv_types::PP2_SUBTYPE_SSL_CIPHER, b"TLS_AES_128_GCM_SHA256")
        .unwrap();
    sub_builder
        .append_tlv(tlv_types::PP2_SUBTYPE_SSL_SIG_ALG, b"ECDSA-SHA256")
        .unwrap();
    sub_builder
        .append_tlv(tlv_types::PP2_SUBTYPE_SSL_KEY_ALG, b"prime256v1")
        .unwrap();
    sub_builder
        .append_tlv(tlv_types::PP2_SUBTYPE_SSL_GROUP, b"secp256r1")
        .unwrap();
    sub_builder
        .append_tlv(
            tlv_types::PP2_SUBTYPE_SSL_SIG_SCHEME,
            b"ecdsa_secp256r1_sha256",
        )
        .unwrap();
    let sub_tlvs = sub_builder.into_slice();

    let mut tlv_buf = [0u8; 1024];
    let mut builder = TlvBuilder::new(&mut tlv_buf);
    builder.append_alpn(b"h2").unwrap();
    builder.append_authority("gateway.ibex.io").unwrap();
    builder.append_unique_id(b"REQ-TRACE-9999").unwrap();
    builder.append_netns("vrf_customer_10").unwrap();
    builder.append_noop(8).unwrap();
    builder
        .append_ssl(
            ssl_client_flags::PP2_CLIENT_SSL
                | ssl_client_flags::PP2_CLIENT_CERT_CONN
                | ssl_client_flags::PP2_CLIENT_CERT_SESS,
            0,
            sub_tlvs,
        )
        .unwrap();
    builder.append_crc32c_placeholder().unwrap();
    let tlv_slice = builder.into_slice();

    let hdr = ProxyHeader::new_v2_ipv6(
        ProxyCommand::Proxy,
        ProxyTransport::Stream,
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 20),
        60000,
        443,
        tlv_slice,
    );

    let mut out = [0u8; 2048];
    let written = hdr.encode(&mut out).unwrap();

    // Finalize CRC32C
    update_crc32c_in_buffer(&mut out[..written]).unwrap();

    // Parse and verify all fields
    let (parsed, consumed) = ProxyHeader::parse(&out[..written]).unwrap().unwrap();
    assert_eq!(consumed, written);
    assert_eq!(parsed.alpn().unwrap().unwrap(), b"h2");
    assert_eq!(parsed.authority().unwrap().unwrap(), "gateway.ibex.io");
    assert_eq!(parsed.unique_id().unwrap().unwrap(), b"REQ-TRACE-9999");
    assert_eq!(parsed.netns().unwrap().unwrap(), "vrf_customer_10");

    let ssl = parsed.ssl().unwrap().unwrap();
    assert!(ssl.is_ssl());
    assert!(ssl.has_cert_conn());
    assert!(ssl.has_cert_sess());
    assert!(ssl.is_verified());
    assert_eq!(ssl.version().unwrap().unwrap(), "TLSv1.3");
    assert_eq!(ssl.common_name().unwrap().unwrap(), "edge.ibex.internal");
    assert_eq!(ssl.cipher().unwrap().unwrap(), "TLS_AES_128_GCM_SHA256");
    assert_eq!(ssl.sig_alg().unwrap().unwrap(), "ECDSA-SHA256");
    assert_eq!(ssl.key_alg().unwrap().unwrap(), "prime256v1");
    assert_eq!(ssl.group().unwrap().unwrap(), "secp256r1");
    assert_eq!(ssl.sig_scheme().unwrap().unwrap(), "ecdsa_secp256r1_sha256");
}

#[test]
fn test_corrupt_non_proxy_signatures() {
    let invalid_inputs: &[&[u8]] = &[
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"POST /api/v1/submit HTTP/1.1\r\n",
        b"SSH-2.0-OpenSSH_8.9\r\n",
        b"CONNECT 10.0.0.1:443 HTTP/1.1\r\n",
        b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03", // TLS ClientHello
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    ];

    for &input in invalid_inputs {
        let res = ProxyHeader::parse(input);
        assert_eq!(res, Err(ProxyParseError::InvalidSignature));
    }
}

// ---------------------------------------------------------------------------
// Property-Based Tests (Proptest)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_v1_ipv4_roundtrip(
        src_ip in any::<[u8; 4]>().prop_map(Ipv4Addr::from),
        dst_ip in any::<[u8; 4]>().prop_map(Ipv4Addr::from),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
    ) {
        let hdr = ProxyHeader::new_v1_ipv4(src_ip, dst_ip, src_port, dst_port);
        let mut out = [0u8; 128];
        let written = hdr.encode(&mut out).expect("encode v1 failed");

        let res = ProxyHeader::parse(&out[..written]).expect("parse v1 failed");
        let (parsed, consumed) = res.expect("need more data");

        prop_assert_eq!(consumed, written);
        prop_assert_eq!(parsed.version, ProxyVersion::V1);
        prop_assert_eq!(parsed.command, ProxyCommand::Proxy);
        prop_assert_eq!(parsed.address, ProxyAddress::Ipv4 {
            src_addr: src_ip,
            dst_addr: dst_ip,
            src_port,
            dst_port,
        });
    }

    #[test]
    fn prop_v1_ipv6_roundtrip(
        src_ip in any::<[u8; 16]>().prop_map(Ipv6Addr::from),
        dst_ip in any::<[u8; 16]>().prop_map(Ipv6Addr::from),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
    ) {
        let hdr = ProxyHeader::new_v1_ipv6(src_ip, dst_ip, src_port, dst_port);
        let mut out = [0u8; 256];
        let written = hdr.encode(&mut out).expect("encode v1 ipv6 failed");

        let res = ProxyHeader::parse(&out[..written]).expect("parse v1 ipv6 failed");
        let (parsed, consumed) = res.expect("need more data");

        prop_assert_eq!(consumed, written);
        prop_assert_eq!(parsed.version, ProxyVersion::V1);
        prop_assert_eq!(parsed.command, ProxyCommand::Proxy);
        prop_assert_eq!(parsed.address, ProxyAddress::Ipv6 {
            src_addr: src_ip,
            dst_addr: dst_ip,
            src_port,
            dst_port,
        });
    }

    #[test]
    fn prop_v2_ipv4_roundtrip(
        is_local in any::<bool>(),
        is_dgram in any::<bool>(),
        src_ip in any::<[u8; 4]>().prop_map(Ipv4Addr::from),
        dst_ip in any::<[u8; 4]>().prop_map(Ipv4Addr::from),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
        alpn in prop::collection::vec(any::<u8>(), 0..16),
        authority in "[a-z0-9-]{1,20}\\.example\\.com",
    ) {
        let cmd = if is_local { ProxyCommand::Local } else { ProxyCommand::Proxy };
        let trans = if is_dgram { ProxyTransport::Datagram } else { ProxyTransport::Stream };

        let mut tlv_buf = [0u8; 256];
        let mut builder = TlvBuilder::new(&mut tlv_buf);
        if !alpn.is_empty() {
            builder.append_alpn(&alpn).unwrap();
        }
        builder.append_authority(&authority).unwrap();
        let tlv_slice = builder.into_slice();

        let hdr = ProxyHeader::new_v2_ipv4(cmd, trans, src_ip, dst_ip, src_port, dst_port, tlv_slice);
        let mut out = [0u8; 512];
        let written = hdr.encode(&mut out).expect("encode v2 failed");

        let (parsed, consumed) = ProxyHeader::parse(&out[..written]).unwrap().unwrap();
        prop_assert_eq!(consumed, written);
        prop_assert_eq!(parsed.version, ProxyVersion::V2);
        prop_assert_eq!(parsed.command, cmd);
        prop_assert_eq!(parsed.transport, trans);
        prop_assert_eq!(parsed.address, ProxyAddress::Ipv4 {
            src_addr: src_ip,
            dst_addr: dst_ip,
            src_port,
            dst_port,
        });

        if !alpn.is_empty() {
            prop_assert_eq!(parsed.alpn().unwrap().unwrap(), alpn.as_slice());
        }
        prop_assert_eq!(parsed.authority().unwrap().unwrap(), authority.as_str());
    }

    #[test]
    fn prop_v2_crc32c_fuzz(
        src_ip in any::<[u8; 4]>().prop_map(Ipv4Addr::from),
        dst_ip in any::<[u8; 4]>().prop_map(Ipv4Addr::from),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
        unique_id in prop::collection::vec(any::<u8>(), 1..32),
    ) {
        let mut tlv_buf = [0u8; 256];
        let mut builder = TlvBuilder::new(&mut tlv_buf);
        builder.append_unique_id(&unique_id).unwrap();
        builder.append_crc32c_placeholder().unwrap();
        let tlv_slice = builder.into_slice();

        let hdr = ProxyHeader::new_v2_ipv4(
            ProxyCommand::Proxy,
            ProxyTransport::Stream,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            tlv_slice,
        );

        let mut out = [0u8; 512];
        let written = hdr.encode(&mut out).unwrap();
        update_crc32c_in_buffer(&mut out[..written]).unwrap();

        let (parsed, consumed) = ProxyHeader::parse(&out[..written]).unwrap().unwrap();
        prop_assert_eq!(consumed, written);
        prop_assert_eq!(parsed.unique_id().unwrap().unwrap(), unique_id.as_slice());
        prop_assert!(parsed.crc32c().is_some());
    }

    #[test]
    fn prop_fuzz_parser_never_panics(
        data in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        // Must never panic on arbitrary random byte sequences
        let _ = ProxyHeader::parse(&data);
    }

    #[test]
    fn prop_streaming_chunk_resilience(
        src_ip in any::<[u8; 4]>().prop_map(Ipv4Addr::from),
        dst_ip in any::<[u8; 4]>().prop_map(Ipv4Addr::from),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
    ) {
        let hdr = ProxyHeader::new_v1_ipv4(src_ip, dst_ip, src_port, dst_port);
        let mut out = [0u8; 128];
        let written = hdr.encode(&mut out).unwrap();
        let wire = &out[..written];

        for i in 0..wire.len() {
            let chunk = &wire[..i];
            let res = ProxyHeader::parse(chunk);
            if i < wire.len() {
                prop_assert!(res.is_ok() && res.unwrap().is_none(), "expected None for incomplete slice of length {}", i);
            }
        }

        let full_res = ProxyHeader::parse(wire).unwrap();
        prop_assert!(full_res.is_some());
    }
}
