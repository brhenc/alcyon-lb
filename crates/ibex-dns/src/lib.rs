// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

pub mod resolver;

pub use resolver::{Resolver, ResolverConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKind {
    A,
    Aaaa,
    Srv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueryId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    A(std::net::Ipv4Addr),
    Aaaa(std::net::Ipv6Addr),
    Srv {
        target: String,
        port: u16,
        priority: u16,
        weight: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    NxDomain,
    Refused,
    ServFail,
    Timeout,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Udp,
    Tcp,
}
