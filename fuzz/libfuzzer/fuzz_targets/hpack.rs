// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![no_main]
use libfuzzer_sys::fuzz_target;
use ibex_proto::hpack::HpackDecoder;

fuzz_target!(|data: &[u8]| {
    // one decoder across two blocks, so the dynamic table state is exercised
    let mut d = HpackDecoder::new();
    let _ = d.decode(data);
    let _ = d.decode(data);
    let _ = ibex_proto::hpack::decode_huffman(data);
});
