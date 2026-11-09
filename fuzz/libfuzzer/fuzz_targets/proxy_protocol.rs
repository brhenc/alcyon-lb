// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![no_main]
use libfuzzer_sys::fuzz_target;
use alcyon_proto::proxy_protocol::ProxyHeader;

fuzz_target!(|data: &[u8]| {
    if let Ok(Some((h, _n))) = ProxyHeader::parse(data) {
        let _ = h.src_sockaddr();
        let _ = h.dst_sockaddr();
        let _ = h.alpn();
        let _ = h.authority();
        let _ = h.crc32c();
        let _ = h.unique_id();
        let _ = h.netns();
        let _ = h.ssl();
        let _ = h.find_tlv(0x20);
    }
});
