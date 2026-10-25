// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A sans-IO DNS resolver modelled on `HAProxy`'s `src/resolvers.c`
//! (design: `docs/design/dns-2026-10-25.md`). The caller owns the sockets and the clock:
//! [`Resolver::query`], [`Resolver::poll_transmit`], [`Resolver::handle_response`],
//! [`Resolver::poll_timeout`], [`Resolver::poll_result`].

pub mod resolver;

pub use resolver::{Resolver, ResolverConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKind {
    A,
    Aaaa,
    Srv,
}

/// An address family, for `resolve-prefer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    Ipv4,
    Ipv6,
}

/// The families the resolver may ask for (`dns-accept-family`). Both accepted enables
/// `HAProxy`'s A <-> AAAA fallback (`resolvers.c:2496-2508`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Families {
    pub ipv4: bool,
    pub ipv6: bool,
}

impl Families {
    pub const IPV4: Self = Self { ipv4: true, ipv6: false };
    pub const IPV6: Self = Self { ipv4: false, ipv6: true };
    pub const BOTH: Self = Self { ipv4: true, ipv6: true };

    #[must_use]
    pub fn accepts(self, f: Family) -> bool {
        match f {
            Family::Ipv4 => self.ipv4,
            Family::Ipv6 => self.ipv6,
        }
    }
}

/// What a resolution asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Question {
    /// A or AAAA: the first query is of the preferred type if it is accepted, else of the
    /// other one.
    Addr { accept: Families, prefer: Family },
    Srv,
}

impl Question {
    /// A question for one family only, no fallback.
    #[must_use]
    pub fn v4() -> Self {
        Self::Addr { accept: Families::IPV4, prefer: Family::Ipv4 }
    }

    #[must_use]
    pub fn v6() -> Self {
        Self::Addr { accept: Families::IPV6, prefer: Family::Ipv6 }
    }
}

/// Who asks. A `DoResolve` query may be answered from the `hold valid` cache; a `Server`
/// query never is (`HAProxy` re-resolves a server every `timeout resolve` whatever the TTL,
/// design A.t2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Requester {
    Server,
    DoResolve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueryId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rdata {
    A(std::net::Ipv4Addr),
    Aaaa(std::net::Ipv6Addr),
    Srv {
        target: String,
        port: u16,
        priority: u16,
        weight: u16,
    },
}

/// One answer record. `ttl` is the record's TTL, kept for the `do-resolve` cache's users
/// (T489) only: nothing here re-resolves on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub rdata: Rdata,
    pub ttl: u32,
}

/// The status a resolution ends with: `HAProxy`'s `RSLV_STATUS_*`. SERVFAIL, NODATA, a CNAME
/// chain without an address and a truncated TCP answer are all `Other` (design A.t6b, A.t6c,
/// A.t20b). `Invalid` is the status left by an invalid reply in the last try (`HAProxy`'s
/// `RSLV_STATUS_INVALID`, which a server treats as `hold other`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    NxDomain,
    Refused,
    Timeout,
    Other,
    Invalid,
}

/// How [`Resolver::handle_response`] classified one datagram: the name of the per-nameserver
/// counter `HAProxy` increments for it (`resolvers.c:2398-2486`, `show resolvers`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Received {
    Valid,
    Nx,
    Refused,
    /// NOERROR with no answer (NODATA).
    AnyErr,
    CnameError,
    /// TC set: over UDP the query is re-sent over TCP to the same nameserver.
    Truncated,
    Other,
    /// Malformed, wrong question, wrong name/type/class, too many answers announced, or not
    /// from a configured nameserver. Never ends a resolution by itself.
    Invalid,
    /// Longer than `accepted_payload_size` over UDP; dropped before decoding.
    TooBig,
    /// No resolution in progress has this id.
    Outdated,
}

/// Why [`Resolver::query`] refused to start a resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryError {
    /// `resolv_hostname_validation` / `resolv_str_to_dn_label`; the text is `HAProxy`'s.
    InvalidName(&'static str),
    /// `Question::Addr` with no family accepted.
    NoFamily,
    /// 100 random ids in a row were all in use (`resolvers.c:543-553`).
    NoFreeId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Udp,
    Tcp,
}
