// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Property-based tests for IPv4 and IPv6 CIDR matching in `Matcher`.

use alcyon_sample::{Matcher, Sample};
use proptest::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// 0.0.0.0/0 matches every IPv4 address.
    #[test]
    fn prop_cidr_v4_zero_matches_all(octets in any::<[u8; 4]>()) {
        let ip = Ipv4Addr::from(octets);
        let matcher = Matcher::compile("ip", "0.0.0.0/0").expect("compile 0.0.0.0/0");
        prop_assert!(matcher.matches(&Sample::Ipv4(ip)));
    }

    /// An IPv4 address always matches its own /32 and /prefix for any prefix in 0..=32.
    #[test]
    fn prop_cidr_v4_contains_self(octets in any::<[u8; 4]>(), prefix in 0u32..=32) {
        let ip = Ipv4Addr::from(octets);
        let pattern = format!("{ip}/{prefix}");
        let matcher = Matcher::compile("ip", &pattern).expect("compile cidr");
        prop_assert!(matcher.matches(&Sample::Ipv4(ip)));
    }

    /// IPv4 CIDR matching matches exact bitwise model.
    #[test]
    fn prop_cidr_v4_bitwise_model(
        a_octets in any::<[u8; 4]>(),
        b_octets in any::<[u8; 4]>(),
        prefix in 0u32..=32
    ) {
        let ip_a = Ipv4Addr::from(a_octets);
        let ip_b = Ipv4Addr::from(b_octets);
        let pattern = format!("{ip_b}/{prefix}");
        let matcher = Matcher::compile("ip", &pattern).expect("compile cidr");

        let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
        let expected = (u32::from(ip_a) & mask) == (u32::from(ip_b) & mask);

        prop_assert_eq!(matcher.matches(&Sample::Ipv4(ip_a)), expected);
    }

    /// IPv4 CIDR prefix monotonicity: if ip matches net/p2, it matches net/p1 for p1 <= p2.
    #[test]
    fn prop_cidr_v4_prefix_monotonicity(
        ip_octets in any::<[u8; 4]>(),
        net_octets in any::<[u8; 4]>(),
        p1 in 0u32..=32,
        p2 in 0u32..=32
    ) {
        let ip = Ipv4Addr::from(ip_octets);
        let net = Ipv4Addr::from(net_octets);
        let (p_lo, p_hi) = if p1 <= p2 { (p1, p2) } else { (p2, p1) };

        let m_hi = Matcher::compile("ip", &format!("{net}/{p_hi}")).unwrap();
        let m_lo = Matcher::compile("ip", &format!("{net}/{p_lo}")).unwrap();

        if m_hi.matches(&Sample::Ipv4(ip)) {
            prop_assert!(m_lo.matches(&Sample::Ipv4(ip)));
        }
    }

    /// ::/0 matches every IPv6 address.
    #[test]
    fn prop_cidr_v6_zero_matches_all(octets in any::<[u8; 16]>()) {
        let ip = Ipv6Addr::from(octets);
        let matcher = Matcher::compile("ip", "::/0").expect("compile ::/0");
        prop_assert!(matcher.matches(&Sample::Ipv6(ip)));
    }

    /// An IPv6 address always matches its own /128 and /prefix for any prefix in 0..=128.
    #[test]
    fn prop_cidr_v6_contains_self(octets in any::<[u8; 16]>(), prefix in 0u32..=128) {
        let ip = Ipv6Addr::from(octets);
        let pattern = format!("{ip}/{prefix}");
        let matcher = Matcher::compile("ip", &pattern).expect("compile cidr");
        prop_assert!(matcher.matches(&Sample::Ipv6(ip)));
    }

    /// IPv6 CIDR matching matches exact bitwise model.
    #[test]
    fn prop_cidr_v6_bitwise_model(
        a_octets in any::<[u8; 16]>(),
        b_octets in any::<[u8; 16]>(),
        prefix in 0u32..=128
    ) {
        let ip_a = Ipv6Addr::from(a_octets);
        let ip_b = Ipv6Addr::from(b_octets);
        let pattern = format!("{ip_b}/{prefix}");
        let matcher = Matcher::compile("ip", &pattern).expect("compile cidr");

        let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
        let expected = (u128::from(ip_a) & mask) == (u128::from(ip_b) & mask);

        prop_assert_eq!(matcher.matches(&Sample::Ipv6(ip_a)), expected);
    }

    /// IPv6 CIDR prefix monotonicity: if ip matches net/p2, it matches net/p1 for p1 <= p2.
    #[test]
    fn prop_cidr_v6_prefix_monotonicity(
        ip_octets in any::<[u8; 16]>(),
        net_octets in any::<[u8; 16]>(),
        p1 in 0u32..=128,
        p2 in 0u32..=128
    ) {
        let ip = Ipv6Addr::from(ip_octets);
        let net = Ipv6Addr::from(net_octets);
        let (p_lo, p_hi) = if p1 <= p2 { (p1, p2) } else { (p2, p1) };

        let m_hi = Matcher::compile("ip", &format!("{net}/{p_hi}")).unwrap();
        let m_lo = Matcher::compile("ip", &format!("{net}/{p_lo}")).unwrap();

        if m_hi.matches(&Sample::Ipv6(ip)) {
            prop_assert!(m_lo.matches(&Sample::Ipv6(ip)));
        }
    }

    /// String-represented IP addresses are cast and matched against CIDR patterns.
    #[test]
    fn prop_cidr_str_sample_matching(octets in any::<[u8; 4]>(), prefix in 0u32..=32) {
        let ip = Ipv4Addr::from(octets);
        let pattern = format!("{ip}/{prefix}");
        let matcher = Matcher::compile("ip", &pattern).expect("compile cidr");
        let str_sample = Sample::Str(ip.to_string());
        prop_assert!(matcher.matches(&str_sample));
    }

    /// Disjoint IPv4 subnets have empty intersection.
    #[test]
    fn prop_cidr_v4_disjoint_subnets(
        prefix in 1u32..=32,
        ip_octets in any::<[u8; 4]>(),
    ) {
        let ip = Ipv4Addr::from(ip_octets);
        let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
        let net_a = u32::from(ip) & mask;
        // Flip one prefix bit to produce a guaranteed disjoint subnet
        let bit = 1u32 << (32 - prefix);
        let net_b = net_a ^ bit;

        let m_a = Matcher::compile("ip", &format!("{}/{prefix}", Ipv4Addr::from(net_a))).unwrap();
        let m_b = Matcher::compile("ip", &format!("{}/{prefix}", Ipv4Addr::from(net_b))).unwrap();

        let smp = Sample::Ipv4(ip);
        let in_a = m_a.matches(&smp);
        let in_b = m_b.matches(&smp);

        prop_assert!(!(in_a && in_b), "Sample matched two disjoint subnets");
    }

    /// Invalid CIDR patterns must fail compilation.
    #[test]
    fn prop_cidr_invalid_prefixes(invalid_prefix in 33u32..=1000) {
        let pattern_v4 = format!("192.168.1.1/{invalid_prefix}");
        prop_assert!(Matcher::compile("ip", &pattern_v4).is_err());
    }

    /// Invalid IPv6 prefixes must fail compilation.
    #[test]
    fn prop_cidr_v6_invalid_prefixes(invalid_prefix in 129u32..=1000) {
        let pattern_v6 = format!("2001:db8::1/{invalid_prefix}");
        prop_assert!(Matcher::compile("ip", &pattern_v6).is_err());
    }
}
