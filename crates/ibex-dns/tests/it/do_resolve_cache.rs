// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The `do-resolve` cache is bounded (T611 / #6): its names come from a sample expression a
//! client controls (a `Host` header), and an entry used to leave only when the same name was
//! asked again after `hold valid`.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use ibex_dns::{Protocol, Question, Requester, Resolver, ResolverConfig};

use crate::resolver_behavior::{a_rec, response};

const NS1: &str = "192.0.2.1:53";

/// A `do-resolve` of `name` answered at once.
fn resolve(r: &mut Resolver, now: Instant, name: &str) {
    let ns: SocketAddr = NS1.parse().unwrap();
    r.query(now, name, Question::v4(), Requester::DoResolve).unwrap();
    let (_, _, buf) = r.poll_transmit(now).expect("a query is sent");
    let id = Message::from_vec(&buf).unwrap().id();
    r.handle_response(
        now,
        ns,
        Protocol::Udp,
        &response(id, name, RecordType::A, ResponseCode::NoError, vec![a_rec(name, Ipv4Addr::new(1, 2, 3, 4), 60)]),
    );
    assert!(r.poll_result().unwrap().1.is_ok());
}

#[test]
fn distinct_do_resolve_names_do_not_grow_the_cache_without_bound() {
    let ns: SocketAddr = NS1.parse().unwrap();
    let mut r = Resolver::new(ResolverConfig {
        nameservers: vec![ns],
        hold_valid: Duration::from_secs(1),
        ..ResolverConfig::default()
    });
    let t0 = Instant::now();
    for i in 0..Resolver::CACHE_MAX + 500 {
        resolve(&mut r, t0, &format!("h{i}.test"));
    }
    assert_eq!(r.cached_names(), Resolver::CACHE_MAX);
    // The names expire: the next answer sweeps them out and is kept.
    resolve(&mut r, t0 + Duration::from_secs(2), "late.test");
    assert_eq!(r.cached_names(), 1);
    // A kept name is still served from the cache.
    r.query(t0 + Duration::from_secs(2), "late.test", Question::v4(), Requester::DoResolve).unwrap();
    assert!(r.poll_transmit(t0 + Duration::from_secs(2)).is_none());
}

#[test]
fn hold_valid_zero_keeps_nothing() {
    let ns: SocketAddr = NS1.parse().unwrap();
    let mut r = Resolver::new(ResolverConfig { nameservers: vec![ns], hold_valid: Duration::ZERO, ..ResolverConfig::default() });
    resolve(&mut r, Instant::now(), "z.test");
    assert_eq!(r.cached_names(), 0);
}
