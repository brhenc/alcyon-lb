// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `resolvers` sections (`cfg_parse_resolvers`, `src/resolvers.c`).
//!
//! Parsed and checked as `HAProxy` checks them; a section a server names runs at run time
//! (`ibex_rt::resolvers`, T484). A section no server uses does nothing observable in
//! `HAProxy` either, except in `show resolvers` (T485).

use std::net::SocketAddr;
use std::time::Duration;

/// The transport a `nameserver` address asks for (`str2sa_range` with `PA_O_DEFAULT_DGRAM`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NsTransport {
    /// No explicit type (`ip:port`, `ipv4@`, `ipv6@`, `ip@`): UDP, and a truncated answer is
    /// asked again over TCP.
    #[default]
    Default,
    /// `udp@`, `udp4@`, `udp6@`, `dgram+`: UDP only, no TCP fallback.
    Udp,
    /// `tcp@`, `tcp4@`, `tcp6@`, `stream+`: every query goes over TCP.
    Tcp,
}

/// A `nameserver <name> <addr>:<port>` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nameserver {
    pub name: String,
    /// How it is reached (the address prefix).
    pub transport: NsTransport,
    /// The address, a name in it resolved by libc while the configuration loads.
    pub addr: SocketAddr,
    /// The line it is on, for the duplicate-name alert: of `/etc/resolv.conf` for one
    /// `parse-resolv-conf` added.
    pub line: usize,
    /// Added by `parse-resolv-conf` (named after its address, port 53).
    pub from_resolv_conf: bool,
}

/// `hold <status> <period>`: how long the last valid answer is kept after each status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolverHolds {
    pub valid: Duration,
    pub nx: Duration,
    pub other: Duration,
    pub refused: Duration,
    pub timeout: Duration,
    pub obsolete: Duration,
}

/// A `resolvers <name>` section, with `HAProxy`'s defaults (`resolvers_new`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolversSection {
    pub name: String,
    /// The line of the `resolvers` line.
    pub line: usize,
    pub nameservers: Vec<Nameserver>,
    /// `resolve_retries` (default 3), as `atoi` reads it.
    pub resolve_retries: i32,
    /// `timeout resolve` (default 1 s).
    pub timeout_resolve: Duration,
    /// `timeout retry` (default 1 s).
    pub timeout_retry: Duration,
    pub hold: ResolverHolds,
    /// `accepted_payload_size` (default 512, 12 to 65535).
    pub accepted_payload_size: u16,
}

impl ResolversSection {
    /// A section named `name`, on `line`, with nothing set.
    #[must_use]
    pub fn new(name: String, line: usize) -> Self {
        let s = Duration::from_secs;
        Self {
            name,
            line,
            nameservers: Vec::new(),
            resolve_retries: 3,
            timeout_resolve: s(1),
            timeout_retry: s(1),
            hold: ResolverHolds { valid: s(10), nx: s(30), other: s(30), refused: s(30), timeout: s(30), obsolete: Duration::ZERO },
            accepted_payload_size: 512,
        }
    }
}
