// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

#![allow(clippy::field_reassign_with_default)]
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{Name, Record, RData};
use hickory_proto::rr::rdata::{AAAA, SRV};

use ibex_dns::{Answer, Protocol, RecordKind, Resolver, ResolverConfig};

fn build_a_response(id: u16, name: &str, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Response);
    msg.set_response_code(ResponseCode::NoError);

    let record = Record::from_rdata(Name::from_str(name).unwrap(), ttl, RData::A(ip.into()));
    msg.add_answer(record);

    msg.to_vec().unwrap()
}

fn build_aaaa_response(id: u16, name: &str, ip: Ipv6Addr, ttl: u32) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Response);
    msg.set_response_code(ResponseCode::NoError);

    let record = Record::from_rdata(Name::from_str(name).unwrap(), ttl, RData::AAAA(AAAA(ip.into())));
    msg.add_answer(record);

    msg.to_vec().unwrap()
}

fn build_srv_response(id: u16, name: &str, srvs: &[(u16, u16, u16, &str)], ttl: u32) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Response);
    msg.set_response_code(ResponseCode::NoError);

    for (priority, weight, port, target) in srvs {
        let record = Record::from_rdata(
            Name::from_str(name).unwrap(),
            ttl,
            RData::SRV(SRV::new(*priority, *weight, *port, Name::from_str(target).unwrap())),
        );
        msg.add_answer(record);
    }

    msg.to_vec().unwrap()
}

fn build_truncated_response(id: u16) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Response);
    msg.set_response_code(ResponseCode::NoError);
    msg.set_truncated(true);

    msg.to_vec().unwrap()
}

fn build_error_response(id: u16, rcode: ResponseCode) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Response);
    msg.set_response_code(rcode);
    msg.to_vec().unwrap()
}

#[test]
fn test_happy_path() {
    let ns: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let mut cfg = ResolverConfig::default();
    cfg.nameservers = vec![ns];
    cfg.timeout_resolve = Duration::from_secs(10);
    let mut resolver = Resolver::new(cfg);

    let now = Instant::now();
    let qid = resolver.query(now, "example.com", RecordKind::A);

    let tx = resolver.poll_transmit(now).unwrap();
    assert_eq!(tx.0, ns);
    assert_eq!(tx.1, Protocol::Udp);

    let q_msg = Message::from_vec(&tx.2).unwrap();
    let id = q_msg.id();

    let resp = build_a_response(id, "example.com", Ipv4Addr::new(1, 2, 3, 4), 60);
    resolver.handle_response(now, ns, &resp);

    let res = resolver.poll_result().unwrap();
    assert_eq!(res.0, qid);
    assert_eq!(res.1.unwrap(), vec![Answer::A(Ipv4Addr::new(1, 2, 3, 4))]);
}

#[test]
fn test_aaaa_and_srv() {
    let ns: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let mut cfg = ResolverConfig::default();
    cfg.nameservers = vec![ns];
    cfg.timeout_resolve = Duration::from_secs(10);
    let mut resolver = Resolver::new(cfg);

    let now = Instant::now();
    let qid_aaaa = resolver.query(now, "example.com", RecordKind::Aaaa);

    let tx = resolver.poll_transmit(now).unwrap();
    let id_aaaa = Message::from_vec(&tx.2).unwrap().id();

    let resp_aaaa = build_aaaa_response(id_aaaa, "example.com", Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 60);
    resolver.handle_response(now, ns, &resp_aaaa);

    let res = resolver.poll_result().unwrap();
    assert_eq!(res.0, qid_aaaa);
    assert_eq!(res.1.unwrap(), vec![Answer::Aaaa(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))]);

    let qid_srv = resolver.query(now, "_http._tcp.example.com", RecordKind::Srv);
    let tx = resolver.poll_transmit(now).unwrap();
    let id_srv = Message::from_vec(&tx.2).unwrap().id();

    let srvs = vec![
        (10, 20, 8080, "target1.example.com."),
        (20, 10, 8081, "target2.example.com."),
    ];
    let resp_srv = build_srv_response(id_srv, "_http._tcp.example.com", &srvs, 60);
    resolver.handle_response(now, ns, &resp_srv);

    let res = resolver.poll_result().unwrap();
    assert_eq!(res.0, qid_srv);
    
    let srv_ans = res.1.unwrap();
    let exp1 = Answer::Srv { target: "target1.example.com.".into(), port: 8080, priority: 10, weight: 20 };
    let exp2 = Answer::Srv { target: "target2.example.com.".into(), port: 8081, priority: 20, weight: 10 };
    assert!(srv_ans.contains(&exp1));
    assert!(srv_ans.contains(&exp2));
    assert_eq!(srv_ans.len(), 2);
}

#[test]
fn test_truncation_fallback_to_tcp() {
    let ns: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let mut cfg = ResolverConfig::default();
    cfg.nameservers = vec![ns];
    cfg.timeout_resolve = Duration::from_secs(10);
    let mut resolver = Resolver::new(cfg);

    let now = Instant::now();
    resolver.query(now, "example.com", RecordKind::A);

    let tx1 = resolver.poll_transmit(now).unwrap();
    assert_eq!(tx1.1, Protocol::Udp);
    let id1 = Message::from_vec(&tx1.2).unwrap().id();

    let resp_tc = build_truncated_response(id1);
    resolver.handle_response(now, ns, &resp_tc);

    let tx2 = resolver.poll_transmit(now).unwrap();
    assert_eq!(tx2.1, Protocol::Tcp);
    assert_eq!(tx2.0, ns);
    let id2 = Message::from_vec(&tx2.2).unwrap().id();

    let resp = build_a_response(id2, "example.com", Ipv4Addr::new(1, 2, 3, 4), 60);
    resolver.handle_response(now, ns, &resp);

    let res = resolver.poll_result().unwrap();
    assert_eq!(res.1.unwrap(), vec![Answer::A(Ipv4Addr::new(1, 2, 3, 4))]);
}

// Measured on HAProxy 3.5-dev8 (two silent nameservers, resolve_retries 2, timeout retry 500ms):
// every try goes to every nameserver at the same instant (ns1 then ns2), and the initial send
// counts as a try, so 2 tries = sends at t=0 and t=0.5s, then the resolution times out.
#[test]
fn test_retry_and_failover() {
    let ns1: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let ns2: SocketAddr = "127.0.0.1:54".parse().unwrap();
    let mut cfg = ResolverConfig::default();
    cfg.nameservers = vec![ns1, ns2];
    cfg.resolve_retries = 2;
    cfg.timeout_retry = Duration::from_millis(500);
    cfg.timeout_resolve = Duration::from_secs(10);
    let mut resolver = Resolver::new(cfg);

    let mut now = Instant::now();
    resolver.query(now, "example.com", RecordKind::A);

    // Try 1: ns1 then ns2, nothing else yet.
    assert_eq!(resolver.poll_transmit(now).unwrap().0, ns1);
    assert_eq!(resolver.poll_transmit(now).unwrap().0, ns2);
    assert!(resolver.poll_transmit(now).is_none());

    // Not yet time to retry.
    now += Duration::from_millis(499);
    assert!(resolver.poll_transmit(now).is_none());

    // Try 2 (the one retry): again both, in order.
    now += Duration::from_millis(1);
    assert_eq!(resolver.poll_transmit(now).unwrap().0, ns1);
    assert_eq!(resolver.poll_transmit(now).unwrap().0, ns2);
    assert!(resolver.poll_transmit(now).is_none());

    // Tries exhausted: no third send, the query times out.
    now += Duration::from_millis(500);
    assert!(resolver.poll_transmit(now).is_none());
    let res = resolver.poll_result().unwrap();
    assert!(res.1.is_err());
}

fn assert_hold_timer(
    rcode_opt: Option<ResponseCode>, 
    is_timeout: bool,
    hold_duration: Duration, 
    test_name: &str
) {
    let ns: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let mut cfg = ResolverConfig::default();
    cfg.nameservers = vec![ns];
    cfg.timeout_resolve = Duration::from_secs(10);
    cfg.hold_valid = Duration::from_secs(10);
    cfg.hold_nx = Duration::from_secs(11);
    cfg.hold_other = Duration::from_secs(12);
    cfg.hold_refused = Duration::from_secs(13);
    cfg.hold_timeout = Duration::from_secs(14);
    
    let test_hold = hold_duration;

    let mut resolver = Resolver::new(cfg);
    let mut now = Instant::now();

    resolver.query(now, test_name, RecordKind::A);
    let tx = resolver.poll_transmit(now).unwrap();
    let id = Message::from_vec(&tx.2).unwrap().id();

    if is_timeout {
        now += Duration::from_secs(10);
        assert!(resolver.poll_transmit(now).is_none());
        assert!(resolver.poll_result().is_some());
    } else {
        let resp = build_error_response(id, rcode_opt.unwrap());
        resolver.handle_response(now, ns, &resp);
        assert!(resolver.poll_result().is_some());
    }

    now += test_hold.checked_sub(Duration::from_secs(1)).unwrap();
    resolver.query(now, test_name, RecordKind::A);
    assert!(resolver.poll_transmit(now).is_none(), "transmitted inside hold timer for {test_name:?}");
    let r2 = resolver.poll_result();
    assert!(r2.is_some(), "cached result missing inside hold for {test_name:?}");

    now += Duration::from_secs(2);
    resolver.query(now, test_name, RecordKind::A);
    let tx3 = resolver.poll_transmit(now);
    assert!(tx3.is_some(), "did not transmit after hold timer expired for {test_name:?}");
}

#[test]
fn test_hold_timers_independent() {
    assert_hold_timer(Some(ResponseCode::NXDomain), false, Duration::from_secs(11), "nx.com");
    assert_hold_timer(Some(ResponseCode::Refused), false, Duration::from_secs(13), "refused.com");
    assert_hold_timer(Some(ResponseCode::ServFail), false, Duration::from_secs(12), "servfail.com");
    assert_hold_timer(None, true, Duration::from_secs(14), "timeout.com");

    let ns: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let mut cfg = ResolverConfig::default();
    cfg.nameservers = vec![ns];
    cfg.timeout_resolve = Duration::from_secs(10);
    cfg.hold_valid = Duration::from_secs(10);
    
    let mut resolver = Resolver::new(cfg);
    let mut now = Instant::now();
    resolver.query(now, "valid.com", RecordKind::A);
    let tx = resolver.poll_transmit(now).unwrap();
    let id = Message::from_vec(&tx.2).unwrap().id();

    let resp = build_a_response(id, "valid.com", Ipv4Addr::new(1,2,3,4), 100);
    resolver.handle_response(now, ns, &resp);
    resolver.poll_result();

    now += Duration::from_secs(9);
    resolver.query(now, "valid.com", RecordKind::A);
    assert!(resolver.poll_transmit(now).is_none(), "transmitted inside valid hold");
    assert!(resolver.poll_result().is_some());

    now += Duration::from_secs(2);
    resolver.query(now, "valid.com", RecordKind::A);
    assert!(resolver.poll_transmit(now).is_some(), "did not transmit after valid hold");
}

#[test]
fn test_ttl_drives_reresolution() {
    let ns: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let mut cfg = ResolverConfig::default();
    cfg.nameservers = vec![ns];
    cfg.hold_valid = Duration::from_secs(300);
    let mut resolver = Resolver::new(cfg);

    let mut now = Instant::now();
    resolver.query(now, "ttl.example.com", RecordKind::A);

    let tx = resolver.poll_transmit(now).unwrap();
    let id = Message::from_vec(&tx.2).unwrap().id();

    let resp = build_a_response(id, "ttl.example.com", Ipv4Addr::new(1, 2, 3, 4), 60);
    resolver.handle_response(now, ns, &resp);
    resolver.poll_result();

    now += Duration::from_secs(59);
    resolver.query(now, "ttl.example.com", RecordKind::A);
    assert!(resolver.poll_transmit(now).is_none(), "transmitted at 59s when TTL is 60s");
    assert!(resolver.poll_result().is_some());

    now += Duration::from_secs(2);
    resolver.query(now, "ttl.example.com", RecordKind::A);
    assert!(resolver.poll_transmit(now).is_some(), "did not transmit at 61s when TTL is 60s");
}

#[test]
fn test_poll_timeout_honest() {
    let ns: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let mut cfg = ResolverConfig::default();
    cfg.nameservers = vec![ns];
    cfg.timeout_retry = Duration::from_secs(2);
    cfg.timeout_resolve = Duration::from_secs(10);
    let mut resolver = Resolver::new(cfg);

    assert!(resolver.poll_timeout().is_none(), "poll_timeout must be None when idle");

    let now = Instant::now();
    resolver.query(now, "example.com", RecordKind::A);

    assert_eq!(resolver.poll_timeout(), Some(now), "before transmit, must be ready now");

    resolver.poll_transmit(now);

    let expected_timeout = now + Duration::from_secs(2);
    assert_eq!(resolver.poll_timeout(), Some(expected_timeout), "after transmit, must wait for retry");

    let now2 = now + Duration::from_secs(1);
    resolver.query(now2, "example2.com", RecordKind::A);
    resolver.poll_transmit(now2);

    assert_eq!(resolver.poll_timeout(), Some(expected_timeout), "must return earliest deadline");
}
