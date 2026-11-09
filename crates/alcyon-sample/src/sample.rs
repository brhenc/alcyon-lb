// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/sample-t.h and src/sample.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Sample types and value representations.
//!
//! See `design/007-sample-lattice.md`.

use alcyon_proto::htx::HttpMethod;
use std::borrow::Cow;
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

/// A sample as the data path holds it (R2): a text or binary sample is bytes, as
/// `HAProxy`'s `smp->data.u.str` is, borrowed from the request or the configuration it comes
/// from (`SMP_F_CONST`) and owned only once a converter has made new bytes. No byte of it is
/// read as UTF-8.
///
/// [`Sample`] is the same value in the text form the by-name entry points (the CLI, the
/// tests, the converters not yet ported) take and give: its `Str` is the bytes as
/// [`alcyon_regex::bytetext`] text, so the two convert into each other losslessly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Smp<'a> {
    Bool(bool),
    Sint(i64),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Str(Cow<'a, [u8]>),
    Bin(Cow<'a, [u8]>),
    Meth(HttpMethod),
}

impl<'a> Smp<'a> {
    /// A text sample of the bytes `b`, borrowed.
    #[must_use]
    pub const fn str(b: &'a [u8]) -> Self {
        Smp::Str(Cow::Borrowed(b))
    }

    /// Returns the discriminator type of this sample value.
    #[must_use]
    pub const fn sample_type(&self) -> SampleType {
        match self {
            Smp::Bool(_) => SampleType::Bool,
            Smp::Sint(_) => SampleType::Sint,
            Smp::Ipv4(_) => SampleType::Ipv4,
            Smp::Ipv6(_) => SampleType::Ipv6,
            Smp::Str(_) => SampleType::Str,
            Smp::Bin(_) => SampleType::Bin,
            Smp::Meth(_) => SampleType::Meth,
        }
    }

    /// The text form ([`Sample`]): a text sample's bytes as [`alcyon_regex::bytetext`] text in a
    /// [`crate::spare`] string.
    #[must_use]
    pub fn into_sample(self) -> Sample {
        match self {
            Smp::Bool(b) => Sample::Bool(b),
            Smp::Sint(i) => Sample::Sint(i),
            Smp::Ipv4(a) => Sample::Ipv4(a),
            Smp::Ipv6(a) => Sample::Ipv6(a),
            // Owned bytes keep their buffer (a spare string's, often): no copy, no allocation.
            Smp::Str(Cow::Owned(v)) => Sample::Str(match String::from_utf8(v) {
                Ok(t) if !alcyon_regex::bytetext::has_escapes(&t) => t,
                Ok(t) => alcyon_regex::bytetext::bytes_to_text(t.as_bytes()),
                Err(e) => alcyon_regex::bytetext::bytes_to_text(e.as_bytes()),
            }),
            Smp::Str(Cow::Borrowed(b)) => Sample::Str(text_of(b)),
            Smp::Bin(b) => Sample::Bin(b.into_owned()),
            Smp::Meth(m) => Sample::Meth(m),
        }
    }

    /// The bytes form of the text form ([`Smp::into_sample`] undone): the string's bytes
    /// moved, not copied, unless it holds a [`alcyon_regex::bytetext`] escape.
    #[must_use]
    pub fn from_sample(smp: Sample) -> Smp<'static> {
        match smp {
            Sample::Bool(b) => Smp::Bool(b),
            Sample::Sint(i) => Smp::Sint(i),
            Sample::Ipv4(a) => Smp::Ipv4(a),
            Sample::Ipv6(a) => Smp::Ipv6(a),
            Sample::Str(s) => Smp::Str(Cow::Owned(bytes_of(s))),
            Sample::Bin(b) => Smp::Bin(Cow::Owned(b)),
            Sample::Meth(m) => Smp::Meth(m),
        }
    }

    /// [`Smp::from_sample`] of a borrowed sample: its bytes borrowed when it holds no
    /// escape.
    #[must_use]
    pub fn of_sample(smp: &'a Sample) -> Self {
        match smp {
            Sample::Bool(b) => Smp::Bool(*b),
            Sample::Sint(i) => Smp::Sint(*i),
            Sample::Ipv4(a) => Smp::Ipv4(*a),
            Sample::Ipv6(a) => Smp::Ipv6(*a),
            Sample::Str(s) => Smp::Str(alcyon_regex::bytetext::text_to_bytes(s)),
            Sample::Bin(b) => Smp::Bin(Cow::Borrowed(b)),
            Sample::Meth(m) => Smp::Meth(m.clone()),
        }
    }
}

/// The bytes a text holds ([`alcyon_regex::bytetext`]), the string's own buffer when it holds
/// no escape.
#[must_use]
pub fn bytes_of(s: String) -> Vec<u8> {
    if alcyon_regex::bytetext::has_escapes(&s) {
        alcyon_regex::bytetext::text_to_bytes(&s).into_owned()
    } else {
        s.into_bytes()
    }
}

/// The text of bytes ([`alcyon_regex::bytetext`]) in a [`crate::spare`] string.
#[must_use]
pub fn text_of(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(t) if !alcyon_regex::bytetext::has_escapes(t) => crate::spare::string_from(t),
        _ => alcyon_regex::bytetext::bytes_to_text(b),
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
