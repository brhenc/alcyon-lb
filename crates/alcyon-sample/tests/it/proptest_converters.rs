// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Property-based tests for sample converters.

use alcyon_sample::{Registry, Sample, SampleContext};
use proptest::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// `lower` converter is idempotent: lower(lower(s)) == lower(s).
    #[test]
    fn prop_conv_lower_idempotent(s in "\\PC*") {
        let reg = Registry::new();
        let convs = vec![("lower", vec![])];
        let ctx = SampleContext { phase: &alcyon_sample::PhaseCtx {
            req_uri: Some(&s),
            ..Default::default()
        }, live: None };
        let first = reg.eval("url", &[], &convs, &ctx).expect("first lower");
        if let Sample::Str(res1) = first {
            let ctx2 = SampleContext { phase: &alcyon_sample::PhaseCtx {
                req_uri: Some(&res1),
                ..Default::default()
            }, live: None };
            let second = reg.eval("url", &[], &convs, &ctx2).expect("second lower");
            prop_assert_eq!(second, Sample::Str(res1));
        } else {
            prop_assert!(false, "Expected Sample::Str");
        }
    }

    /// `upper` converter is idempotent: upper(upper(s)) == upper(s).
    #[test]
    fn prop_conv_upper_idempotent(s in "\\PC*") {
        let reg = Registry::new();
        let convs = vec![("upper", vec![])];
        let ctx = SampleContext { phase: &alcyon_sample::PhaseCtx {
            req_uri: Some(&s),
            ..Default::default()
        }, live: None };
        let first = reg.eval("url", &[], &convs, &ctx).expect("first upper");
        if let Sample::Str(res1) = first {
            let ctx2 = SampleContext { phase: &alcyon_sample::PhaseCtx {
                req_uri: Some(&res1),
                ..Default::default()
            }, live: None };
            let second = reg.eval("url", &[], &convs, &ctx2).expect("second upper");
            prop_assert_eq!(second, Sample::Str(res1));
        } else {
            prop_assert!(false, "Expected Sample::Str");
        }
    }

    /// `len` converter matches UTF-8 byte length.
    #[test]
    fn prop_conv_len(s in "\\PC*") {
        let reg = Registry::new();
        let convs = vec![("len", vec![])];
        let ctx = SampleContext { phase: &alcyon_sample::PhaseCtx {
            req_uri: Some(&s),
            ..Default::default()
        }, live: None };
        let result = reg.eval("url", &[], &convs, &ctx).expect("eval len");
        let expected_len = i64::try_from(s.len()).unwrap_or(i64::MAX);
        prop_assert_eq!(result, Sample::Sint(expected_len));
    }

    /// `add` and `sub` are inverses when not overflowing.
    #[test]
    fn prop_conv_add_sub_inverse(val in -1_000_000i64..1_000_000, delta in -1_000_000i64..1_000_000) {
        let reg = Registry::new();
        let conv_add = reg.get_converter("add").unwrap();
        let conv_sub = reg.get_converter("sub").unwrap();

        let after_add = (conv_add.func)(Sample::Sint(val), &[delta.to_string()]).unwrap();
        let after_sub = (conv_sub.func)(after_add, &[delta.to_string()]).unwrap();
        prop_assert_eq!(after_sub, Sample::Sint(val));
    }

    /// `add` converter never panics on boundary values.
    #[test]
    fn prop_conv_add_saturation(val in any::<i64>(), delta in any::<i64>()) {
        let reg = Registry::new();
        let conv_add = reg.get_converter("add").unwrap();
        let result = (conv_add.func)(Sample::Sint(val), &[delta.to_string()]);
        prop_assert_eq!(result, Some(Sample::Sint(val.saturating_add(delta))));
    }

    /// `sub` converter never panics on boundary values.
    #[test]
    fn prop_conv_sub_saturation(val in any::<i64>(), delta in any::<i64>()) {
        let reg = Registry::new();
        let conv_sub = reg.get_converter("sub").unwrap();
        let result = (conv_sub.func)(Sample::Sint(val), &[delta.to_string()]);
        prop_assert_eq!(result, Some(Sample::Sint(val.saturating_sub(delta))));
    }

    /// `hex` -> `hex2bin` round-trip for arbitrary binary buffers.
    #[test]
    fn prop_conv_hex_roundtrip(data in prop::collection::vec(any::<u8>(), 0..256)) {
        let reg = Registry::new();
        let conv_hex = reg.get_converter("hex").unwrap();
        let conv_hex2bin = reg.get_converter("hex2bin").unwrap();

        let as_hex = (conv_hex.func)(Sample::Bin(data.clone()), &[]).expect("hex encode");
        if let Sample::Str(hex_str) = &as_hex {
            prop_assert_eq!(hex_str.len(), data.len() * 2);
        }
        let back_bin = (conv_hex2bin.func)(as_hex, &[]).expect("hex decode");
        prop_assert_eq!(back_bin, Sample::Bin(data));
    }

    /// `base64` -> `b64dec` round-trip for arbitrary binary buffers.
    #[test]
    fn prop_conv_base64_roundtrip(data in prop::collection::vec(any::<u8>(), 0..256)) {
        let reg = Registry::new();
        let conv_b64 = reg.get_converter("base64").unwrap();
        let conv_b64dec = reg.get_converter("b64dec").unwrap();

        let as_b64 = (conv_b64.func)(Sample::Bin(data.clone()), &[]).expect("b64 encode");
        let back_bin = (conv_b64dec.func)(as_b64, &[]).expect("b64 decode");
        prop_assert_eq!(back_bin, Sample::Bin(data));
    }

    /// `concat` converter appends prefix and suffix arguments.
    #[test]
    fn prop_conv_concat(base in "\\PC*", prefix in "\\PC*", suffix in "\\PC*") {
        let reg = Registry::new();
        let conv_concat = reg.get_converter("concat").unwrap();

        let result = (conv_concat.func)(
            Sample::Str(base.clone()),
            &[prefix.clone(), String::new(), suffix.clone()],
        ).expect("concat");
        let expected = format!("{base}{prefix}{suffix}");
        prop_assert_eq!(result, Sample::Str(expected));
    }

    /// `bytes` converter extracts subslice correctly.
    #[test]
    fn prop_conv_bytes(
        data in prop::collection::vec(any::<u8>(), 0..64),
        offset in 0usize..80,
        len in 0usize..80
    ) {
        let reg = Registry::new();
        let conv_bytes = reg.get_converter("bytes").unwrap();

        let result = (conv_bytes.func)(
            Sample::Bin(data.clone()),
            &[offset.to_string(), len.to_string()]
        ).expect("bytes slice");

        let expected_slice = if offset >= data.len() {
            Vec::new()
        } else {
            let end = (offset + len).min(data.len());
            data[offset..end].to_vec()
        };
        prop_assert_eq!(result, Sample::Bin(expected_slice));
    }

    /// `ipmask` converter for IPv4 correctly masks host bits.
    #[test]
    fn prop_conv_ipmask_v4(octets in any::<[u8; 4]>(), prefix in 0u32..=32) {
        let ip = Ipv4Addr::from(octets);
        let reg = Registry::new();
        let conv_ipmask = reg.get_converter("ipmask").unwrap();

        let result = (conv_ipmask.func)(Sample::Ipv4(ip), &[prefix.to_string()]).expect("ipmask v4");
        let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
        let expected_ip = Ipv4Addr::from(u32::from(ip) & mask);
        prop_assert_eq!(result, Sample::Ipv4(expected_ip));
    }

    /// `ipmask` converter for IPv6 correctly masks host bits.
    #[test]
    fn prop_conv_ipmask_v6(octets in any::<[u8; 16]>(), prefix in 0u32..=128) {
        let ip = Ipv6Addr::from(octets);
        let reg = Registry::new();
        let conv_ipmask = reg.get_converter("ipmask").unwrap();

        let result = (conv_ipmask.func)(
            Sample::Ipv6(ip),
            &["32".to_string(), prefix.to_string()],
        ).expect("ipmask v6");
        let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
        let expected_ip = Ipv6Addr::from(u128::from(ip) & mask);
        prop_assert_eq!(result, Sample::Ipv6(expected_ip));
    }

    /// `crc32` converter is deterministic and produces consistent results.
    #[test]
    fn prop_conv_crc32_deterministic(data in prop::collection::vec(any::<u8>(), 0..128)) {
        let reg = Registry::new();
        let conv_crc = reg.get_converter("crc32").unwrap();

        let res1 = (conv_crc.func)(Sample::Bin(data.clone()), &[]).expect("crc32 first");
        let res2 = (conv_crc.func)(Sample::Bin(data), &[]).expect("crc32 second");
        prop_assert_eq!(res1, res2);
    }
}
