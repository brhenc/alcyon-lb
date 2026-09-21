// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/sample-t.h and src/sample.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Sample types and value representations.
//!
//! See `design/007-sample-lattice.md`.

use ibex_proto::htx::HttpMethod;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The runtime value of a sample. Seven inhabitable variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sample {
    Bool(bool),
    Sint(i64),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Str(String),
    Bin(Vec<u8>),
    Meth(HttpMethod),
}

impl Sample {
    /// Returns the discriminator type of this sample value.
    #[must_use]
    pub const fn sample_type(&self) -> SampleType {
        match self {
            Sample::Bool(_) => SampleType::Bool,
            Sample::Sint(_) => SampleType::Sint,
            Sample::Ipv4(_) => SampleType::Ipv4,
            Sample::Ipv6(_) => SampleType::Ipv6,
            Sample::Str(_) => SampleType::Str,
            Sample::Bin(_) => SampleType::Bin,
            Sample::Meth(_) => SampleType::Meth,
        }
    }
}

/// The concrete type tag of a sample value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SampleType {
    Bool = 0,
    Sint = 1,
    Ipv4 = 2,
    Ipv6 = 3,
    Str = 4,
    Bin = 5,
    Meth = 6,
}

/// Total count of concrete sample types.
pub const SAMPLE_TYPES_COUNT: usize = 7;

impl SampleType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            SampleType::Bool => "bool",
            SampleType::Sint => "sint",
            SampleType::Ipv4 => "ipv4",
            SampleType::Ipv6 => "ipv6",
            SampleType::Str => "str",
            SampleType::Bin => "bin",
            SampleType::Meth => "meth",
        }
    }
}

/// A signature slot specification for fetches, converters, and matchers.
///
/// Notice `ANY`, `SAME`, and `ADDR` describe signatures, never runtime values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeSpec {
    Exact(SampleType),
    /// Accepts any input type.
    Any,
    /// Preserves input type as output type.
    Same,
    /// Accepts either IPv4 or IPv6 address.
    Addr,
}

impl TypeSpec {
    #[must_use]
    pub fn matches(self, ty: SampleType) -> bool {
        match self {
            TypeSpec::Exact(t) => t == ty,
            TypeSpec::Any | TypeSpec::Same => true,
            TypeSpec::Addr => matches!(ty, SampleType::Ipv4 | SampleType::Ipv6),
        }
    }
}
