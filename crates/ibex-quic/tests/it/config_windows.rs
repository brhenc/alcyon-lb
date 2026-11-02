// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A flow-control window or stream limit above `u32::MAX` is still applied (T611 / #4): it
//! used to skip the setter and leave quinn's default, which for the windows is unbounded.

use ibex_quic::QuicConfig;

#[test]
fn a_window_above_u32_max_is_not_left_at_quinns_unbounded_default() {
    // 100 streams of a 100 MB buffer: a 10 GB connection window.
    let tc = QuicConfig::new().with_flow_windows(100_000_000, 100, 90).build_transport_config();
    let dbg = format!("{tc:?}");
    assert!(dbg.contains("receive_window: 9999999600"), "{dbg}");
    assert!(dbg.contains("stream_receive_window: 8999999640"), "{dbg}");
}

#[test]
fn a_stream_limit_above_u32_max_is_clamped_not_dropped() {
    let tc = QuicConfig::new().with_max_bidi_streams(u64::MAX).with_max_uni_streams(1 << 40).build_transport_config();
    let dbg = format!("{tc:?}");
    // u64::MAX does not fit a varint: it becomes the largest one. 1 << 40 is kept as asked.
    assert!(dbg.contains("max_concurrent_bidi_streams: 4611686018427387903"), "{dbg}");
    assert!(dbg.contains("max_concurrent_uni_streams: 1099511627776"), "{dbg}");
}
