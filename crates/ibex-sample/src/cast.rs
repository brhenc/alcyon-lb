// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/sample.c (sample_casts table).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The fallible 7×7 implicit sample cast matrix.
//!
//! See `design/007-sample-lattice.md` §3.

#![allow(clippy::needless_pass_by_value)]

use crate::sample::{Sample, SampleType, SAMPLE_TYPES_COUNT};
use ibex_proto::htx::HttpMethod;
use std::net::{Ipv4Addr, Ipv6Addr};

type CastFn = fn(Sample) -> Option<Sample>;

/// Performs an implicit cast from `smp` to `target_type`.
#[must_use]
pub fn cast(smp: Sample, target_type: SampleType) -> Option<Sample> {
    let src_idx = smp.sample_type() as usize;
    let dst_idx = target_type as usize;

    if src_idx == dst_idx {
        return Some(smp);
    }

    let f = CAST_MATRIX[src_idx][dst_idx]?;
    f(smp)
}

/// Checks whether an implicit cast from `src` to `dst` is available.
#[must_use]
pub const fn can_cast(src: SampleType, dst: SampleType) -> bool {
    let src_idx = src as usize;
    let dst_idx = dst as usize;
    if src_idx == dst_idx {
        true
    } else {
        CAST_MATRIX[src_idx][dst_idx].is_some()
    }
}

const CAST_MATRIX: [[Option<CastFn>; SAMPLE_TYPES_COUNT]; SAMPLE_TYPES_COUNT] = [
    // BOOL (0)
    [
        Some(c_none),      // -> BOOL
        Some(c_bool2sint), // -> SINT
        None,              // -> IPV4
        None,              // -> IPV6
        Some(c_bool2str),  // -> STR
        Some(c_bool2bin),  // -> BIN
        None,              // -> METH
    ],
    // SINT (1)
    [
        Some(c_sint2bool), // -> BOOL
        Some(c_none),      // -> SINT
        Some(c_sint2ip),   // -> IPV4
        Some(c_sint2ipv6), // -> IPV6
        Some(c_sint2str),  // -> STR
        Some(c_sint2bin),  // -> BIN
        None,              // -> METH
    ],
    // IPV4 (2)
    [
        None,            // -> BOOL
        Some(c_ip2int),  // -> SINT
        Some(c_none),    // -> IPV4
        Some(c_ip2ipv6), // -> IPV6
        Some(c_ip2str),  // -> STR
        Some(c_ip2bin),  // -> BIN
        None,            // -> METH
    ],
    // IPV6 (3)
    [
        None,             // -> BOOL
        None,             // -> SINT
        Some(c_ipv62ip),  // -> IPV4
        Some(c_none),     // -> IPV6
        Some(c_ipv62str), // -> STR
        Some(c_ipv62bin), // -> BIN
        None,             // -> METH
    ],
    // STR (4)
    [
        Some(c_str2bool), // -> BOOL
        Some(c_str2sint), // -> SINT
        Some(c_str2ip),   // -> IPV4
        Some(c_str2ipv6), // -> IPV6
        Some(c_none),     // -> STR
        Some(c_str2bin),  // -> BIN
        Some(c_str2meth), // -> METH
    ],
    // BIN (5)
    [
        None,             // -> BOOL
        None,             // -> SINT
        None,             // -> IPV4
        None,             // -> IPV6
        Some(c_bin2str),  // -> STR
        Some(c_none),     // -> BIN
        Some(c_bin2meth), // -> METH
    ],
    // METH (6)
    [
        None,             // -> BOOL
        None,             // -> SINT
        None,             // -> IPV4
        None,             // -> IPV6
        Some(c_meth2str), // -> STR
        Some(c_meth2bin), // -> BIN
        Some(c_none),     // -> METH
    ],
];

#[allow(clippy::unnecessary_wraps)]
fn c_none(smp: Sample) -> Option<Sample> {
    Some(smp)
}

fn c_bool2sint(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Bool(b) => Some(Sample::Sint(i64::from(b))),
        _ => None,
    }
}

fn c_bool2str(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Bool(b) => Some(Sample::Str(if b { "1".into() } else { "0".into() })),
        _ => None,
    }
}

fn c_bool2bin(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Bool(b) => Some(Sample::Bin(vec![u8::from(b)])),
        _ => None,
    }
}

fn c_sint2bool(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Sint(i) => Some(Sample::Bool(i != 0)),
        _ => None,
    }
}

fn c_sint2ip(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Sint(i) => {
            let bytes = i.to_be_bytes();
            let u = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            Some(Sample::Ipv4(Ipv4Addr::from(u)))
        }
        _ => None,
    }
}

fn c_sint2ipv6(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Sint(i) => {
            let bytes = i.to_be_bytes();
            let u = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            Some(Sample::Ipv6(Ipv4Addr::from(u).to_ipv6_mapped()))
        }
        _ => None,
    }
}

fn c_sint2str(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Sint(i) => Some(Sample::Str(i.to_string())),
        _ => None,
    }
}

fn c_sint2bin(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Sint(i) => Some(Sample::Bin(i.to_be_bytes().to_vec())),
        _ => None,
    }
}

fn c_ip2int(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Ipv4(ip) => Some(Sample::Sint(i64::from(u32::from(ip)))),
        _ => None,
    }
}

fn c_ip2ipv6(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Ipv4(ip) => Some(Sample::Ipv6(ip.to_ipv6_mapped())),
        _ => None,
    }
}

fn c_ip2str(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Ipv4(ip) => Some(Sample::Str(ip.to_string())),
        _ => None,
    }
}

fn c_ip2bin(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Ipv4(ip) => Some(Sample::Bin(ip.octets().to_vec())),
        _ => None,
    }
}

fn c_ipv62ip(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Ipv6(ip) => ip.to_ipv4_mapped().map(Sample::Ipv4),
        _ => None,
    }
}

fn c_ipv62str(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Ipv6(ip) => Some(Sample::Str(ip.to_string())),
        _ => None,
    }
}

fn c_ipv62bin(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Ipv6(ip) => Some(Sample::Bin(ip.octets().to_vec())),
        _ => None,
    }
}

fn c_str2bool(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Str(s) => match s.trim() {
            "1" | "true" | "TRUE" | "yes" | "YES" => Some(Sample::Bool(true)),
            "0" | "false" | "FALSE" | "no" | "NO" => Some(Sample::Bool(false)),
            _ => None,
        },
        _ => None,
    }
}

fn c_str2sint(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Str(s) => s.trim().parse::<i64>().ok().map(Sample::Sint),
        _ => None,
    }
}

fn c_str2ip(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Str(s) => s.trim().parse::<Ipv4Addr>().ok().map(Sample::Ipv4),
        _ => None,
    }
}

fn c_str2ipv6(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Str(s) => s.trim().parse::<Ipv6Addr>().ok().map(Sample::Ipv6),
        _ => None,
    }
}

fn c_str2bin(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Str(s) => Some(Sample::Bin(s.into_bytes())),
        _ => None,
    }
}

fn c_str2meth(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Str(s) => Some(Sample::Meth(HttpMethod::from_bytes(s.as_bytes()))),
        _ => None,
    }
}

fn c_bin2str(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Bin(b) => String::from_utf8(b).ok().map(Sample::Str),
        _ => None,
    }
}

fn c_bin2meth(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Bin(b) => Some(Sample::Meth(HttpMethod::from_bytes(&b))),
        _ => None,
    }
}

fn c_meth2str(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Meth(m) => Some(Sample::Str(m.as_str().to_string())),
        _ => None,
    }
}

fn c_meth2bin(smp: Sample) -> Option<Sample> {
    match smp {
        Sample::Meth(m) => Some(Sample::Bin(m.as_str().as_bytes().to_vec())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_casts() {
        assert_eq!(
            cast(Sample::Bool(true), SampleType::Sint),
            Some(Sample::Sint(1))
        );
        assert_eq!(
            cast(Sample::Sint(42), SampleType::Str),
            Some(Sample::Str("42".into()))
        );
        assert_eq!(
            cast(Sample::Str("127.0.0.1".into()), SampleType::Ipv4),
            Some(Sample::Ipv4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(cast(Sample::Str("invalid".into()), SampleType::Ipv4), None);
    }
}
