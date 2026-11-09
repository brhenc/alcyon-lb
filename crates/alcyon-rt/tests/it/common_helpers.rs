// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The test helpers themselves (`tests/common`): the port reservation. (The daemon guard,
//! `common::Alcyon`, has its own test: `spawned_alcyon_stopped_on_panic.rs`.)
//!
//! 2026-11-09: 24 alcyon daemons left behind by `h3_track_sc` tests that had failed (their
//! `common::stop` came after an assertion that panicked) held 24 UDP ports with
//! `SO_REUSEPORT`. `reserve_addr` probed a port with a TCP bind only, so it handed those ports
//! out again; a QUIC test's alcyon then joined the orphan's reuseport group and the kernel sent
//! it part of the test's datagrams. One QUIC test or another failed in the parallel run of
//! every gate that day.

use crate::common;

use std::net::SocketAddr;

/// A UDP socket bound the way alcyon binds a QUIC listener (`SO_REUSEPORT`), on a port from
/// [`common::reserve_addr`]: below the ephemeral range and locked for this process. A port from
/// `bind(:0)` is ephemeral, and in the parallel run any other test's `connect()` could take it
/// between the drop and the check (`a_free_port_is_bindable` failed so, 2026-11-09).
fn hold_udp_reuseport() -> (rustix::fd::OwnedFd, SocketAddr) {
    use rustix::net::{AddressFamily, SocketFlags, SocketType};
    let addr = common::reserve_addr();
    let fd = rustix::net::socket_with(AddressFamily::INET, SocketType::DGRAM, SocketFlags::CLOEXEC, None).unwrap();
    rustix::net::sockopt::set_socket_reuseport(&fd, true).unwrap();
    rustix::net::bind(&fd, &addr).unwrap();
    (fd, addr)
}

#[test]
fn a_port_a_quic_listener_holds_is_not_bindable() {
    let (_held, addr) = hold_udp_reuseport();
    assert!(!common::bindable(addr), "{addr} is held by a UDP SO_REUSEPORT socket, yet reported bindable");
}

#[test]
fn a_free_port_is_bindable() {
    let (held, addr) = hold_udp_reuseport();
    drop(held);
    assert!(common::bindable(addr), "{addr} is free, yet reported not bindable");
}
