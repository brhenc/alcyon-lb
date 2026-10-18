// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Property-based tests for the 7x7 sample cast engine.

use ibex_proto::htx::HttpMethod;
use ibex_sample::{can_cast, cast, Sample, SampleType};
use proptest::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn arb_http_method() -> impl Strategy<Value = HttpMethod> {
    prop_oneof![
        Just(HttpMethod::Get),
        Just(HttpMethod::Post),
        Just(HttpMethod::Put),
        Just(HttpMethod::Delete),
        Just(HttpMethod::Head),
        Just(HttpMethod::Options),
        Just(HttpMethod::Trace),
        Just(HttpMethod::Connect),
        Just(HttpMethod::Patch),
        // `Other` is a method the parser does not know: `Other("PUT")` cannot come from a
        // request (it parses as `Put`), and a round trip rightly gives `Put` back.
        "[A-Z]{3,8}"
            .prop_filter("a known method is not `Other`", |m| {
                !matches!(HttpMethod::from_bytes(m.as_bytes()), HttpMethod::Get
                    | HttpMethod::Head
                    | HttpMethod::Post
                    | HttpMethod::Put
                    | HttpMethod::Delete
                    | HttpMethod::Connect
                    | HttpMethod::Options
                    | HttpMethod::Trace
                    | HttpMethod::Patch)
            })
            .prop_map(HttpMethod::Other),
    ]
}

fn arb_sample_type() -> impl Strategy<Value = SampleType> {
    prop_oneof![
        Just(SampleType::Bool),
        Just(SampleType::Sint),
        Just(SampleType::Ipv4),
        Just(SampleType::Ipv6),
        Just(SampleType::Str),
        Just(SampleType::Bin),
        Just(SampleType::Meth),
    ]
}

fn arb_sample() -> impl Strategy<Value = Sample> {
    prop_oneof![
        any::<bool>().prop_map(Sample::Bool),
        any::<i64>().prop_map(Sample::Sint),
        any::<[u8; 4]>().prop_map(|b| Sample::Ipv4(Ipv4Addr::from(b))),
        any::<[u8; 16]>().prop_map(|b| Sample::Ipv6(Ipv6Addr::from(b))),
        "\\PC*".prop_map(Sample::Str),
        prop::collection::vec(any::<u8>(), 0..128).prop_map(Sample::Bin),
        arb_http_method().prop_map(Sample::Meth),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Casting to the same type tag must be the identity operation.
    #[test]
    fn prop_cast_identity(sample in arb_sample()) {
        let ty = sample.sample_type();
        let result = cast(sample.clone(), ty);
        prop_assert_eq!(result, Some(sample));
    }

    /// If can_cast returns false, cast must return None.
    #[test]
    fn prop_can_cast_agreement(sample in arb_sample(), target_ty in arb_sample_type()) {
        let src_ty = sample.sample_type();
        if !can_cast(src_ty, target_ty) {
            let res = cast(sample, target_ty);
            prop_assert!(res.is_none(), "Expected cast({:?}, {:?}) to be None", src_ty, target_ty);
        }
    }

    /// Bool -> Sint -> Bool round-trip.
    #[test]
    fn prop_cast_bool_roundtrip(b in any::<bool>()) {
        let smp = Sample::Bool(b);
        let as_sint = cast(smp, SampleType::Sint).expect("Bool -> Sint cast");
        prop_assert_eq!(&as_sint, &Sample::Sint(i64::from(b)));
        let back_bool = cast(as_sint, SampleType::Bool).expect("Sint -> Bool cast");
        prop_assert_eq!(back_bool, Sample::Bool(b));
    }

    /// Bool -> Str -> Bool round-trip.
    #[test]
    fn prop_cast_bool_str_roundtrip(b in any::<bool>()) {
        let smp = Sample::Bool(b);
        let as_str = cast(smp, SampleType::Str).expect("Bool -> Str cast");
        let back_bool = cast(as_str, SampleType::Bool).expect("Str -> Bool cast");
        prop_assert_eq!(back_bool, Sample::Bool(b));
    }

    /// Bool -> Bin produces 8 big-endian bytes (c_bool2bin).
    #[test]
    fn prop_cast_bool_bin(b in any::<bool>()) {
        let smp = Sample::Bool(b);
        let as_bin = cast(smp, SampleType::Bin).expect("Bool -> Bin cast");
        prop_assert_eq!(as_bin, Sample::Bin(i64::from(b).to_be_bytes().to_vec()));
    }

    /// Sint -> Str -> Sint round-trip for arbitrary 64-bit signed integers.
    #[test]
    fn prop_cast_sint_str_roundtrip(n in any::<i64>()) {
        let smp = Sample::Sint(n);
        let as_str = cast(smp, SampleType::Str).expect("Sint -> Str cast");
        let back_sint = cast(as_str, SampleType::Sint).expect("Str -> Sint cast");
        prop_assert_eq!(back_sint, Sample::Sint(n));
    }

    /// Sint -> Bin produces 8 big-endian bytes.
    #[test]
    fn prop_cast_sint_bin(n in any::<i64>()) {
        let smp = Sample::Sint(n);
        let as_bin = cast(smp, SampleType::Bin).expect("Sint -> Bin cast");
        if let Sample::Bin(bytes) = as_bin {
            prop_assert_eq!(bytes.len(), 8);
            let reconstructed = i64::from_be_bytes(bytes.try_into().unwrap());
            prop_assert_eq!(reconstructed, n);
        } else {
            prop_assert!(false, "Expected Sample::Bin");
        }
    }

    /// Sint -> Bool: 0 is false, any non-zero is true.
    #[test]
    fn prop_cast_sint_bool(n in any::<i64>()) {
        let smp = Sample::Sint(n);
        let as_bool = cast(smp, SampleType::Bool).expect("Sint -> Bool cast");
        prop_assert_eq!(as_bool, Sample::Bool(n != 0));
    }

    /// Ipv4 -> Str -> Ipv4 round-trip.
    #[test]
    fn prop_cast_ipv4_str_roundtrip(octets in any::<[u8; 4]>()) {
        let ip = Ipv4Addr::from(octets);
        let smp = Sample::Ipv4(ip);
        let as_str = cast(smp, SampleType::Str).expect("Ipv4 -> Str cast");
        let back_ip = cast(as_str, SampleType::Ipv4).expect("Str -> Ipv4 cast");
        prop_assert_eq!(back_ip, Sample::Ipv4(ip));
    }

    /// Ipv4 -> Bin produces 4 bytes matching octets.
    #[test]
    fn prop_cast_ipv4_bin(octets in any::<[u8; 4]>()) {
        let ip = Ipv4Addr::from(octets);
        let smp = Sample::Ipv4(ip);
        let as_bin = cast(smp, SampleType::Bin).expect("Ipv4 -> Bin cast");
        prop_assert_eq!(as_bin, Sample::Bin(octets.to_vec()));
    }

    /// Ipv4 -> Ipv6 mapped -> Ipv4 round-trip.
    #[test]
    fn prop_cast_ipv4_ipv6_mapped_roundtrip(octets in any::<[u8; 4]>()) {
        let ip = Ipv4Addr::from(octets);
        let smp = Sample::Ipv4(ip);
        let as_ipv6 = cast(smp, SampleType::Ipv6).expect("Ipv4 -> Ipv6 mapped cast");
        prop_assert_eq!(&as_ipv6, &Sample::Ipv6(ip.to_ipv6_mapped()));
        let back_ipv4 = cast(as_ipv6, SampleType::Ipv4).expect("Ipv6 -> Ipv4 cast");
        prop_assert_eq!(back_ipv4, Sample::Ipv4(ip));
    }

    /// Ipv4 -> Sint -> Ipv4 round-trip.
    #[test]
    fn prop_cast_ipv4_sint_roundtrip(octets in any::<[u8; 4]>()) {
        let ip = Ipv4Addr::from(octets);
        let smp = Sample::Ipv4(ip);
        let as_sint = cast(smp, SampleType::Sint).expect("Ipv4 -> Sint cast");
        let back_ip = cast(as_sint, SampleType::Ipv4).expect("Sint -> Ipv4 cast");
        prop_assert_eq!(back_ip, Sample::Ipv4(ip));
    }

    /// Ipv6 -> Str -> Ipv6 round-trip.
    #[test]
    fn prop_cast_ipv6_str_roundtrip(octets in any::<[u8; 16]>()) {
        let ip = Ipv6Addr::from(octets);
        let smp = Sample::Ipv6(ip);
        let as_str = cast(smp, SampleType::Str).expect("Ipv6 -> Str cast");
        let back_ip = cast(as_str, SampleType::Ipv6).expect("Str -> Ipv6 cast");
        prop_assert_eq!(back_ip, Sample::Ipv6(ip));
    }

    /// Ipv6 -> Bin produces 16 bytes matching octets.
    #[test]
    fn prop_cast_ipv6_bin(octets in any::<[u8; 16]>()) {
        let ip = Ipv6Addr::from(octets);
        let smp = Sample::Ipv6(ip);
        let as_bin = cast(smp, SampleType::Bin).expect("Ipv6 -> Bin cast");
        prop_assert_eq!(as_bin, Sample::Bin(octets.to_vec()));
    }

    /// Str -> Bin -> Str UTF-8 round-trip.
    #[test]
    fn prop_cast_str_bin_roundtrip(s in "\\PC*") {
        let smp = Sample::Str(s.clone());
        let as_bin = cast(smp, SampleType::Bin).expect("Str -> Bin cast");
        let back_str = cast(as_bin, SampleType::Str).expect("Bin -> Str cast");
        prop_assert_eq!(back_str, Sample::Str(s));
    }

    /// HttpMethod -> Str -> HttpMethod round-trip.
    #[test]
    fn prop_cast_method_str_roundtrip(m in arb_http_method()) {
        let smp = Sample::Meth(m.clone());
        let as_str = cast(smp, SampleType::Str).expect("Meth -> Str cast");
        let back_meth = cast(as_str, SampleType::Meth).expect("Str -> Meth cast");
        prop_assert_eq!(back_meth, Sample::Meth(m));
    }

    /// HttpMethod -> Bin -> HttpMethod round-trip.
    #[test]
    fn prop_cast_method_bin_roundtrip(m in arb_http_method()) {
        let smp = Sample::Meth(m.clone());
        let as_bin = cast(smp, SampleType::Bin).expect("Meth -> Bin cast");
        let back_meth = cast(as_bin, SampleType::Meth).expect("Bin -> Meth cast");
        prop_assert_eq!(back_meth, Sample::Meth(m));
    }

    /// A NUL byte ends the string: what follows it, valid UTF-8 or not, is not part of it.
    #[test]
    fn prop_cast_bin_to_str_stops_at_nul(
        head in "[a-z]{0,8}",
        tail in prop::collection::vec(any::<u8>(), 0..10)
    ) {
        let mut bytes = head.clone().into_bytes();
        bytes.push(0);
        bytes.extend(tail);
        prop_assert_eq!(cast(Sample::Bin(bytes), SampleType::Str), Some(Sample::Str(head)));
    }

    /// Invalid UTF-8 bytes in Bin -> Str are kept (`c_bin2str` casts any bytes): held as text,
    /// they come back as the same bytes (T286). The prefix has no NUL: the cast stops at the
    /// first NUL byte, so a NUL before the bad bytes drops them.
    #[test]
    fn prop_cast_invalid_utf8_fails(
        prefix in prop::collection::vec(1u8..=255, 0..10),
        suffix in prop::collection::vec(any::<u8>(), 0..10)
    ) {
        // Construct invalid UTF-8 sequence [0xFF, 0xFF]
        let mut bytes = prefix;
        bytes.extend_from_slice(&[0xFF, 0xFF]);
        bytes.extend(suffix);
        let bytes: Vec<u8> = bytes.into_iter().take_while(|&b| b != 0).collect();
        let smp = Sample::Bin(bytes.clone());
        let text = cast(smp, SampleType::Str);
        prop_assert!(matches!(text, Some(Sample::Str(_))));
        prop_assert_eq!(cast(text.unwrap(), SampleType::Bin), Some(Sample::Bin(bytes)));
    }
}
