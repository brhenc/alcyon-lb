// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `tcp.src`, `tcp.dst`, `tcp.seq`, `tcp.win` and `tcp.flags` converters answer nothing for a sample
//! that is not binary. A configuration cannot reach this (their input type is `bin`, so the expression
//! compiler casts any other sample to `bin` first), hence what HAProxy does here is moot; the test calls
//! the converter functions directly to pin that they do not panic and answer `None`.

use alcyon_sample::{Registry, Sample};

#[test]
fn tcp_converters_refuse_non_binary_samples() {
    let reg = Registry::new();
    for name in ["tcp.src", "tcp.dst", "tcp.seq", "tcp.win", "tcp.flags"] {
        let f = reg.get_converter(name).unwrap_or_else(|| panic!("no converter {name}")).func;
        assert!(f(Sample::Str("x".repeat(40)), &[]).is_none(), "{name} on Str");
        assert!(f(Sample::Sint(7), &[]).is_none(), "{name} on Sint");
        assert!(f(Sample::Bin(vec![0; 19]), &[]).is_none(), "{name} on 19 bytes");
        assert!(f(Sample::Bin(vec![0; 20]), &[]).is_some(), "{name} on 20 bytes");
    }
}
