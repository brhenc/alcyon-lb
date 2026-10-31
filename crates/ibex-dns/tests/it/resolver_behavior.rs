// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The resolver against the oracle. Rows `A.tN` are runs of the oracle (3.5-dev8) and `B.Pn` the
//! probes of the crate, both in `docs/design/dns-2026-10-25.md` (appendices A and B).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::rdata::{AAAA, CNAME, SRV};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use ibex_dns::{NsTransport, 
    Answer, DnsError, Families, Family, Protocol, QueryError, QueryId, Question, Rdata, Received,
    Requester, Resolver, ResolverConfig,
};

const NS1: &str = "127.0.0.1:53";
const NS2: &str = "127.0.0.1:54";

fn ns(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn cfg(nameservers: &[&str]) -> ResolverConfig {
    ResolverConfig { nameservers: nameservers.iter().map(|s| ns(s)).collect(), ..ResolverConfig::default() }
}

fn ms(t0: Instant, ms: u64) -> Instant {
    t0 + Duration::from_millis(ms)
}

/// A response carrying the question `(qname, qtype)` and `answers`.
pub fn response(id: u16, qname: &str, qtype: RecordType, rcode: ResponseCode, answers: Vec<Record>) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Response);
    msg.set_response_code(rcode);
    msg.add_query(Query::query(Name::from_str(qname).unwrap(), qtype));
    for a in answers {
        msg.add_answer(a);
    }
    msg.to_vec().unwrap()
}

pub fn a_rec(name: &str, ip: Ipv4Addr, ttl: u32) -> Record {
    Record::from_rdata(Name::from_str(name).unwrap(), ttl, RData::A(ip.into()))
}

fn aaaa_rec(name: &str, ip: Ipv6Addr, ttl: u32) -> Record {
    Record::from_rdata(Name::from_str(name).unwrap(), ttl, RData::AAAA(AAAA(ip)))
}

fn cname_rec(name: &str, target: &str) -> Record {
    Record::from_rdata(Name::from_str(name).unwrap(), 60, RData::CNAME(CNAME(Name::from_str(target).unwrap())))
}

pub fn a_response(id: u16, name: &str, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    response(id, name, RecordType::A, ResponseCode::NoError, vec![a_rec(name, ip, ttl)])
}

fn error_response(id: u16, name: &str, qtype: RecordType, rcode: ResponseCode) -> Vec<u8> {
    response(id, name, qtype, rcode, vec![])
}

fn a(ip: Ipv4Addr, ttl: u32) -> Answer {
    Answer { rdata: Rdata::A(ip), ttl }
}

/// Drains every pending transmit at `now`: (nameserver, protocol, message id, query type).
fn sends(r: &mut Resolver, now: Instant) -> Vec<(SocketAddr, Protocol, u16, RecordType)> {
    let mut v = Vec::new();
    while let Some((to, proto, buf)) = r.poll_transmit(now) {
        let m = Message::from_vec(&buf).unwrap();
        v.push((to, proto, m.id(), m.queries()[0].query_type()));
    }
    v
}

fn q4(r: &mut Resolver, now: Instant, name: &str) -> QueryId {
    r.query(now, name, Question::v4(), Requester::Server).unwrap()
}

#[test]
fn test_happy_path() {
    let mut r = Resolver::new(cfg(&[NS1]));
    let now = Instant::now();
    let qid = q4(&mut r, now, "example.com");

    let tx = r.poll_transmit(now).unwrap();
    assert_eq!(tx.0, ns(NS1));
    assert_eq!(tx.1, Protocol::Udp);
    let id = Message::from_vec(&tx.2).unwrap().id();

    let resp = a_response(id, "example.com", Ipv4Addr::new(1, 2, 3, 4), 60);
    assert_eq!(r.handle_response(now, ns(NS1), Protocol::Udp, &resp), Received::Valid);

    let res = r.poll_result().unwrap();
    assert_eq!(res.0, qid);
    assert_eq!(res.1.unwrap(), vec![a(Ipv4Addr::new(1, 2, 3, 4), 60)]);
}

#[test]
fn test_aaaa_and_srv() {
    let mut r = Resolver::new(cfg(&[NS1]));
    let now = Instant::now();
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let qid_aaaa = r.query(now, "example.com", Question::v6(), Requester::Server).unwrap();
    let id = Message::from_vec(&r.poll_transmit(now).unwrap().2).unwrap().id();
    let resp = response(id, "example.com", RecordType::AAAA, ResponseCode::NoError, vec![aaaa_rec("example.com", v6, 60)]);
    r.handle_response(now, ns(NS1), Protocol::Udp, &resp);
    let res = r.poll_result().unwrap();
    assert_eq!(res.0, qid_aaaa);
    assert_eq!(res.1.unwrap(), vec![Answer { rdata: Rdata::Aaaa(v6), ttl: 60 }]);

    let qid_srv = r.query(now, "_http._tcp.example.com", Question::Srv, Requester::Server).unwrap();
    let id = Message::from_vec(&r.poll_transmit(now).unwrap().2).unwrap().id();
    let srv = |p, w, port, t: &str| {
        Record::from_rdata(
            Name::from_str("_http._tcp.example.com").unwrap(),
            60,
            RData::SRV(SRV::new(p, w, port, Name::from_str(t).unwrap())),
        )
    };
    let resp = response(
        id,
        "_http._tcp.example.com",
        RecordType::SRV,
        ResponseCode::NoError,
        vec![srv(10, 20, 8080, "target1.example.com."), srv(20, 10, 8081, "target2.example.com.")],
    );
    r.handle_response(now, ns(NS1), Protocol::Udp, &resp);
    let res = r.poll_result().unwrap();
    assert_eq!(res.0, qid_srv);
    let got = res.1.unwrap();
    let exp1 = Rdata::Srv { target: "target1.example.com.".into(), port: 8080, priority: 10, weight: 20 };
    let exp2 = Rdata::Srv { target: "target2.example.com.".into(), port: 8081, priority: 20, weight: 10 };
    assert_eq!(got.iter().map(|a| a.rdata.clone()).collect::<Vec<_>>(), vec![exp1, exp2]);
}

#[test]
fn test_truncation_fallback_to_tcp() {
    let mut r = Resolver::new(cfg(&[NS1]));
    let now = Instant::now();
    q4(&mut r, now, "example.com");
    let tx1 = sends(&mut r, now);
    assert_eq!(tx1.len(), 1);
    let id = tx1[0].2;

    let mut tc = Message::from_vec(&error_response(id, "example.com", RecordType::A, ResponseCode::NoError)).unwrap();
    tc.set_truncated(true);
    assert_eq!(r.handle_response(now, ns(NS1), Protocol::Udp, &tc.to_vec().unwrap()), Received::Truncated);

    // A.t9: retried over TCP to the same nameserver at once, same question.
    assert_eq!(sends(&mut r, now), vec![(ns(NS1), Protocol::Tcp, id, RecordType::A)]);
    let resp = a_response(id, "example.com", Ipv4Addr::new(1, 2, 3, 4), 60);
    assert_eq!(r.handle_response(now, ns(NS1), Protocol::Tcp, &resp), Received::Valid);
    assert_eq!(r.poll_result().unwrap().1.unwrap(), vec![a(Ipv4Addr::new(1, 2, 3, 4), 60)]);
}

// Measured on HAProxy 3.5-dev8 (two silent nameservers, resolve_retries 2, timeout retry 500ms):
// every try goes to every nameserver at the same instant (ns1 then ns2), and the initial send
// counts as a try, so 2 tries = sends at t=0 and t=0.5s, then the resolution times out.
#[test]
fn test_retry_and_failover() {
    let mut c = cfg(&[NS1, NS2]);
    c.resolve_retries = 2;
    c.timeout_retry = Duration::from_millis(500);
    c.timeout_resolve = Duration::from_secs(10);
    let mut r = Resolver::new(c);

    let mut now = Instant::now();
    q4(&mut r, now, "example.com");

    // Try 1: ns1 then ns2, nothing else yet.
    assert_eq!(r.poll_transmit(now).unwrap().0, ns(NS1));
    assert_eq!(r.poll_transmit(now).unwrap().0, ns(NS2));
    assert!(r.poll_transmit(now).is_none());

    // Not yet time to retry.
    now += Duration::from_millis(499);
    assert!(r.poll_transmit(now).is_none());

    // Try 2 (the one retry): again both, in order.
    now += Duration::from_millis(1);
    assert_eq!(r.poll_transmit(now).unwrap().0, ns(NS1));
    assert_eq!(r.poll_transmit(now).unwrap().0, ns(NS2));
    assert!(r.poll_transmit(now).is_none());

    // Tries exhausted: no third send, the query times out.
    now += Duration::from_millis(500);
    assert!(r.poll_transmit(now).is_none());
    let res = r.poll_result().unwrap();
    assert_eq!(res.1, Err(DnsError::Timeout));
}

// Item 1. A.t4: `231.59 id=52136 / 232.59 id=52136 / 233.59 id=52136 / 235.59 id=61365`: one
// random id per resolution (`ha_random32()`, resolvers.c:543), the same id for its retries,
// a fresh one for the next resolution. B.P1: the crate numbered them 1, 2, 3.
#[test]
fn ids_are_random_per_resolution_and_kept_across_its_retries() {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    fn ids() -> u16 {
        [52136, 61365][NEXT.fetch_add(1, Ordering::Relaxed) % 2]
    }
    let mut c = cfg(&[NS1]);
    c.random_id = ids;
    let mut r = Resolver::new(c);
    let t0 = Instant::now();

    q4(&mut r, t0, "a1.test");
    let mut seen = Vec::new();
    for t in [0, 1000, 2000] {
        seen.extend(sends(&mut r, ms(t0, t)).into_iter().map(|s| s.2));
    }
    assert_eq!(seen, vec![52136, 52136, 52136], "the retries of one resolution keep its id");
    assert_eq!(sends(&mut r, ms(t0, 3000)), vec![]);
    assert_eq!(r.poll_result().unwrap().1, Err(DnsError::Timeout));

    q4(&mut r, ms(t0, 4000), "a1.test");
    assert_eq!(sends(&mut r, ms(t0, 4000))[0].2, 61365, "a new resolution draws a new id");
}

// Item 1, the default generator: ids are not sequential (B.P1: 1, 2, 3).
#[test]
fn default_ids_are_not_sequential() {
    let mut r = Resolver::new(cfg(&[NS1]));
    let t0 = Instant::now();
    let mut ids = Vec::new();
    for i in 0..8 {
        let id = q4(&mut r, t0, &format!("h{i}.test"));
        let _ = id;
        ids.push(sends(&mut r, t0)[0].2);
    }
    let sequential = ids.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
    assert!(!sequential, "message ids must be random, got {ids:?}");
    let mut uniq = ids.clone();
    uniq.sort_unstable();
    uniq.dedup();
    assert_eq!(uniq.len(), ids.len(), "two resolutions in flight never share an id: {ids:?}");
}

// Item 2. A.t5 (resolve_retries 3, timeout retry 1s, silent nameserver): sends at 2.6, 3.6,
// 4.6 with one id, timeout reported at ~5.6. `timeout resolve` (1 s by default) is the period
// between resolutions, not a deadline. B.P5: the crate sent once and timed out at 1 s.
#[test]
fn a_silent_nameserver_gets_every_retry_then_timeout() {
    let mut r = Resolver::new(cfg(&[NS1])); // defaults: retries 3, retry 1s, resolve 1s
    let t0 = Instant::now();
    q4(&mut r, t0, "a1.test");
    let mut at = Vec::new();
    for t in (0..=3000).step_by(250) {
        for _ in sends(&mut r, ms(t0, t)) {
            at.push(t);
        }
        if t < 3000 {
            assert!(r.poll_result().is_none(), "reported before the last retry ran out (t={t} ms)");
        }
    }
    assert_eq!(at, vec![0, 1000, 2000]);
    assert_eq!(r.poll_result().unwrap().1, Err(DnsError::Timeout));
    assert_eq!(r.poll_timeout(), None);
}

// Item 3. A.t10: ns1 answers NX at once, ns2 answers 10.0.0.9 0.3 s later: the address comes
// from ns2 (`IP changed ... by 'r/ns2'`). An error ends a try only when every nameserver has
// answered (resolvers.c:2488). B.P6: the crate returned NxDomain and dropped ns2's answer.
#[test]
fn an_error_waits_for_every_nameserver_and_the_first_valid_answer_wins() {
    let mut r = Resolver::new(cfg(&[NS1, NS2]));
    let t0 = Instant::now();
    q4(&mut r, t0, "mix.test");
    let id = sends(&mut r, t0)[0].2;

    let nx = error_response(id, "mix.test", RecordType::A, ResponseCode::NXDomain);
    assert_eq!(r.handle_response(t0, ns(NS1), Protocol::Udp, &nx), Received::Nx);
    assert!(r.poll_result().is_none(), "one nameserver's error must not end the resolution");

    let ok = a_response(id, "mix.test", Ipv4Addr::new(10, 0, 0, 9), 60);
    assert_eq!(r.handle_response(ms(t0, 300), ns(NS2), Protocol::Udp, &ok), Received::Valid);
    assert_eq!(r.poll_result().unwrap().1.unwrap(), vec![a(Ipv4Addr::new(10, 0, 0, 9), 60)]);
}

// Item 3, all errors. A.t4 (`hold nx`, one nameserver answering NX): the same id is re-sent
// every `timeout retry` and the status is set after the last try's `timeout retry`; a valid
// answer for that id afterwards is `outdated` (resolvers.c:2420).
#[test]
fn errors_from_every_nameserver_are_retried_then_reported() {
    let mut r = Resolver::new(cfg(&[NS1, NS2]));
    let t0 = Instant::now();
    q4(&mut r, t0, "nx.test");
    let mut id = 0;
    for t in [0, 1000, 2000] {
        let s = sends(&mut r, ms(t0, t));
        assert_eq!(s.len(), 2, "try at {t} ms goes to both nameservers");
        id = s[0].2;
        let nx = error_response(id, "nx.test", RecordType::A, ResponseCode::NXDomain);
        r.handle_response(ms(t0, t), ns(NS1), Protocol::Udp, &nx);
        r.handle_response(ms(t0, t), ns(NS2), Protocol::Udp, &nx);
        assert!(r.poll_result().is_none(), "reported inside try at {t} ms");
    }
    assert_eq!(sends(&mut r, ms(t0, 2999)), vec![]);
    assert!(r.poll_result().is_none());
    assert_eq!(sends(&mut r, ms(t0, 3000)), vec![]);
    assert_eq!(r.poll_result().unwrap().1, Err(DnsError::NxDomain));

    let late = a_response(id, "nx.test", Ipv4Addr::new(10, 0, 0, 1), 60);
    assert_eq!(r.handle_response(ms(t0, 3100), ns(NS1), Protocol::Udp, &late), Received::Outdated);
    assert!(r.poll_result().is_none());
}

// Item 4. A.t8b: both families accepted, resolve-prefer ipv4, A gets NODATA: AAAA is sent in
// the same millisecond with the same id, without using a try, and its answer is taken.
#[test]
fn an_error_on_the_preferred_type_falls_back_to_the_other_at_once() {
    let mut r = Resolver::new(cfg(&[NS1]));
    let t0 = Instant::now();
    let q = Question::Addr { accept: Families::BOTH, prefer: Family::Ipv4 };
    r.query(t0, "v6only.test", q, Requester::Server).unwrap();
    let s = sends(&mut r, t0);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].3, RecordType::A);
    let id = s[0].2;

    let nodata = error_response(id, "v6only.test", RecordType::A, ResponseCode::NoError);
    assert_eq!(r.handle_response(t0, ns(NS1), Protocol::Udp, &nodata), Received::AnyErr);
    assert_eq!(sends(&mut r, t0), vec![(ns(NS1), Protocol::Udp, id, RecordType::AAAA)]);

    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 6);
    let ok = response(id, "v6only.test", RecordType::AAAA, ResponseCode::NoError, vec![aaaa_rec("v6only.test", v6, 60)]);
    assert_eq!(r.handle_response(t0, ns(NS1), Protocol::Udp, &ok), Received::Valid);
    assert_eq!(r.poll_result().unwrap().1.unwrap(), vec![Answer { rdata: Rdata::Aaaa(v6), ttl: 60 }]);
}

// Item 4. A.t8c: NX on both types: `290.16 A / 290.16 AAAA / 291.16 A / 291.16 AAAA / 292.16 A /
// 292.16 AAAA`, then the error (the next resolution, a new id, at 293.16 = report + timeout
// resolve, so the report is at the third AAAA error, resolvers.c:2496-2500).
#[test]
fn errors_on_both_types_send_three_pairs_then_report() {
    let mut r = Resolver::new(cfg(&[NS1]));
    let t0 = Instant::now();
    let q = Question::Addr { accept: Families::BOTH, prefer: Family::Ipv4 };
    r.query(t0, "nx.test", q, Requester::Server).unwrap();
    let mut seen = Vec::new();
    for t in [0, 1000, 2000] {
        let now = ms(t0, t);
        for _ in 0..2 {
            for (_, _, id, ty) in sends(&mut r, now) {
                seen.push((t, ty));
                let nx = error_response(id, "nx.test", ty, ResponseCode::NXDomain);
                r.handle_response(now, ns(NS1), Protocol::Udp, &nx);
            }
        }
        if t < 2000 {
            assert!(r.poll_result().is_none(), "reported early at {t} ms");
        }
    }
    assert_eq!(seen, {
        use RecordType::{A, AAAA};
        vec![(0, A), (0, AAAA), (1000, A), (1000, AAAA), (2000, A), (2000, AAAA)]
    });
    assert_eq!(r.poll_result().unwrap().1, Err(DnsError::NxDomain));
}

// Item 4: a timeout does not flip the type (resolvers.c:2622-2630: no response -> back to
// the preferred type, try--). A.t18b: both families, prefer ipv6: AAAA x3.
#[test]
fn a_timeout_does_not_flip_the_query_type() {
    let mut r = Resolver::new(cfg(&[NS1]));
    let t0 = Instant::now();
    let q = Question::Addr { accept: Families::BOTH, prefer: Family::Ipv6 };
    r.query(t0, "both.test", q, Requester::Server).unwrap();
    let mut types = Vec::new();
    for t in [0, 1000, 2000, 3000] {
        types.extend(sends(&mut r, ms(t0, t)).into_iter().map(|s| s.3));
    }
    assert_eq!(types, vec![RecordType::AAAA; 3]);
    assert_eq!(r.poll_result().unwrap().1, Err(DnsError::Timeout));
}

// Item 4: a preferred family that is not accepted is not asked for (A.t18: accept-family auto
// on a host without IPv6, prefer defaults to ipv6: only A is sent); no family is refused.
#[test]
fn the_preferred_type_is_asked_only_when_accepted() {
    let mut r = Resolver::new(cfg(&[NS1]));
    let t0 = Instant::now();
    let q = Question::Addr { accept: Families::IPV4, prefer: Family::Ipv6 };
    r.query(t0, "both.test", q, Requester::Server).unwrap();
    assert_eq!(sends(&mut r, t0)[0].3, RecordType::A);
    let none = Families { ipv4: false, ipv6: false };
    let q = Question::Addr { accept: none, prefer: Family::Ipv4 };
    assert_eq!(r.query(t0, "both.test", q, Requester::Server), Err(QueryError::NoFamily));
}

// Item 5. resolv_validate_dns_response (resolvers.c:1052-1195): qdcount 1, the question's name
// (lower-cased by resolv_read_name, so compared case-insensitively), class IN, type equal or
// A <-> AAAA. A failing reply is `invalid`, counted, and the resolution goes on. B.P2: a reply
// for another name was accepted.
#[test]
fn a_reply_with_the_wrong_question_is_invalid_and_does_not_end_the_resolution() {
    let mut r = Resolver::new(cfg(&[NS1]));
    let t0 = Instant::now();
    q4(&mut r, t0, "a1.test");
    let id = sends(&mut r, t0)[0].2;
    let evil = Ipv4Addr::new(6, 6, 6, 6);

    let wrong_name = response(id, "evil.test", RecordType::A, ResponseCode::NoError, vec![a_rec("evil.test", evil, 60)]);
    let wrong_type = response(id, "a1.test", RecordType::TXT, ResponseCode::NoError, vec![a_rec("a1.test", evil, 60)]);
    let mut m = Message::from_vec(&a_response(id, "a1.test", evil, 60)).unwrap();
    m.take_queries();
    m.add_query(Query::query(Name::from_str("a1.test").unwrap(), RecordType::A).set_query_class(DNSClass::CH).clone());
    let wrong_class = m.to_vec().unwrap();
    let mut m = Message::from_vec(&a_response(id, "a1.test", evil, 60)).unwrap();
    m.add_query(Query::query(Name::from_str("a1.test").unwrap(), RecordType::A));
    let two_questions = m.to_vec().unwrap();
    let wrong_owner = response(id, "a1.test", RecordType::A, ResponseCode::NoError, vec![a_rec("other.test", evil, 60)]);

    for (what, buf) in [
        ("wrong name", &wrong_name),
        ("wrong type", &wrong_type),
        ("wrong class", &wrong_class),
        ("two questions", &two_questions),
        ("answer for another name", &wrong_owner),
    ] {
        assert_eq!(r.handle_response(t0, ns(NS1), Protocol::Udp, buf), Received::Invalid, "{what}");
        assert!(r.poll_result().is_none(), "{what} ended the resolution");
    }
    // From an address that is not a nameserver: invalid, whatever it says.
    let good = a_response(id, "A1.TEST", Ipv4Addr::new(10, 0, 0, 1), 60);
    assert_eq!(r.handle_response(t0, ns("127.0.0.9:53"), Protocol::Udp, &good), Received::Invalid);
    // The real answer, its name upper-cased, is still taken.
    assert_eq!(r.handle_response(t0, ns(NS1), Protocol::Udp, &good), Received::Valid);
    assert_eq!(r.poll_result().unwrap().1.unwrap(), vec![a(Ipv4Addr::new(10, 0, 0, 1), 60)]);
}

// Item 5: A <-> AAAA replies are accepted for an address query (resolvers.c:1187: "A and AAAA
// responses may arrive after the query type switched").
#[test]
fn an_aaaa_reply_is_accepted_for_an_a_query() {
    let mut r = Resolver::new(cfg(&[NS1]));
    let t0 = Instant::now();
    let q = Question::Addr { accept: Families::BOTH, prefer: Family::Ipv4 };
    r.query(t0, "both.test", q, Requester::Server).unwrap();
    let id = sends(&mut r, t0)[0].2;
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let ok = response(id, "both.test", RecordType::AAAA, ResponseCode::NoError, vec![aaaa_rec("both.test", v6, 60)]);
    assert_eq!(r.handle_response(t0, ns(NS1), Protocol::Udp, &ok), Received::Valid);
}

// Item 5 and 9: `ancount <= (payload - 12) / 6` (resolvers.c:2433, 1136) and a UDP datagram
// longer than `accepted_payload_size` is `too_big` (resolvers.c:2401). B.P8: 4000 answers in
// 64,020 bytes were decoded and kept.
#[test]
fn answers_are_bounded_by_the_payload_size() {
    let mut r = Resolver::new(cfg(&[NS1])); // accepted_payload_size 512: 83 answers at most
    let t0 = Instant::now();
    q4(&mut r, t0, "many.test");
    let id = sends(&mut r, t0)[0].2;
    let recs = |n: u8| (0..n).map(|i| a_rec("many.test", Ipv4Addr::new(10, 0, 0, i), 60)).collect::<Vec<_>>();

    let big = response(id, "many.test", RecordType::A, ResponseCode::NoError, recs(200));
    assert!(big.len() > 512);
    assert_eq!(r.handle_response(t0, ns(NS1), Protocol::Udp, &big), Received::TooBig);
    let over_count = {
        // 84 answers announced in a datagram under 512 bytes: a header that lies.
        let mut b = response(id, "many.test", RecordType::A, ResponseCode::NoError, recs(1));
        b[6] = 0;
        b[7] = 84;
        b
    };
    assert!(over_count.len() <= 512);
    assert_eq!(r.handle_response(t0, ns(NS1), Protocol::Udp, &over_count), Received::Invalid);
    assert!(r.poll_result().is_none());

    let ok = response(id, "many.test", RecordType::A, ResponseCode::NoError, recs(20));
    assert_eq!(r.handle_response(t0, ns(NS1), Protocol::Udp, &ok), Received::Valid);
    assert_eq!(r.poll_result().unwrap().1.unwrap().len(), 20);

    // Over TCP the limit is 65,535 bytes, (65535 - 12) / 6 = 10920 answers: 200 are fine.
    q4(&mut r, t0, "many.test");
    let id = sends(&mut r, t0)[0].2;
    let big = response(id, "many.test", RecordType::A, ResponseCode::NoError, recs(200));
    assert_eq!(r.handle_response(t0, ns(NS1), Protocol::Tcp, &big), Received::Valid);
    assert_eq!(r.poll_result().unwrap().1.unwrap().len(), 200);
}

// Item 6. A.t6c: NODATA (NOERROR, no answer) is `any_err`, status OTHER ("unspecified DNS
// error"), B.P4: NxDomain. A.t20b: a CNAME with no address is `cname_error`, OTHER; B.P3:
// Ok([]) and cached. A.t6b: SERVFAIL is `other`, OTHER.
#[test]
fn nodata_cname_only_and_servfail_are_other() {
    type Build = Box<dyn Fn(u16) -> Vec<u8>>;
    let cases: Vec<(&str, Build, Received)> = vec![
        ("nodata", Box::new(|id| error_response(id, "a1.test", RecordType::A, ResponseCode::NoError)), Received::AnyErr),
        (
            "cname only",
            Box::new(|id| response(id, "a1.test", RecordType::A, ResponseCode::NoError, vec![cname_rec("a1.test", "dangling.test")])),
            Received::CnameError,
        ),
        ("servfail", Box::new(|id| error_response(id, "a1.test", RecordType::A, ResponseCode::ServFail)), Received::Other),
    ];
    for (what, build, class) in cases {
        let mut r = Resolver::new(cfg(&[NS1]));
        let t0 = Instant::now();
        q4(&mut r, t0, "a1.test");
        for t in [0, 1000, 2000] {
            let now = ms(t0, t);
            let id = sends(&mut r, now)[0].2;
            assert_eq!(r.handle_response(now, ns(NS1), Protocol::Udp, &build(id)), class, "{what}");
        }
        sends(&mut r, ms(t0, 3000));
        assert_eq!(r.poll_result().unwrap().1, Err(DnsError::Other), "{what}");
    }
}

// Item 6, the positive case: A.t20 cname.test -> CNAME a1.test -> 10.0.0.1.
#[test]
fn a_cname_chain_to_an_address_is_followed() {
    let mut r = Resolver::new(cfg(&[NS1]));
    let t0 = Instant::now();
    q4(&mut r, t0, "cname.test");
    let id = sends(&mut r, t0)[0].2;
    let ip = Ipv4Addr::new(10, 0, 0, 1);
    let resp = response(id, "cname.test", RecordType::A, ResponseCode::NoError, vec![cname_rec("cname.test", "a1.test"), a_rec("a1.test", ip, 30)]);
    assert_eq!(r.handle_response(t0, ns(NS1), Protocol::Udp, &resp), Received::Valid);
    assert_eq!(r.poll_result().unwrap().1.unwrap(), vec![a(ip, 30)]);
}

// Item 7. resolv_build_query (resolvers.c:406-453): `arcount 1`, an OPT record announcing
// `accepted_payload_size`. A.t1a `edns=512`, A.t15 `edns=4096`. B.P7: arcount 0, no OPT.
#[test]
fn every_query_announces_the_accepted_payload_size() {
    for size in [512u16, 4096] {
        let mut c = cfg(&[NS1]);
        c.accepted_payload_size = size;
        let mut r = Resolver::new(c);
        let t0 = Instant::now();
        q4(&mut r, t0, "a1.test");
        let (_, _, buf) = r.poll_transmit(t0).unwrap();
        assert_eq!(&buf[2..4], &[0x01, 0x00], "flags: rd only");
        assert_eq!(&buf[4..12], &[0, 1, 0, 0, 0, 0, 0, 1], "qdcount 1, arcount 1");
        let m = Message::from_vec(&buf).unwrap();
        let edns = m.extensions().as_ref().expect("an OPT record");
        assert_eq!(edns.max_payload(), size);
        assert_eq!(buf.len(), 12 + 9 + 4 + 11, "header + a1.test + type/class + OPT");
    }
}

// Item 8. resolv_hostname_validation and resolv_str_to_dn_label (resolvers.c:1925-2000): at
// most 255 bytes, 63 per label, [-_a-zA-Z0-9], no empty label. B.P9: `query("bad..name")`
// sent a message with no question.
#[test]
fn an_invalid_name_is_refused_at_query() {
    let mut r = Resolver::new(cfg(&[NS1]));
    let t0 = Instant::now();
    let long_label = format!("{}.test", "a".repeat(64));
    let long_name = format!("{}.test", ["abcdefghi"; 26].join("."));
    assert!(long_name.len() > 255);
    for (name, why) in [
        ("bad..name", "invalid"),
        ("", "invalid"),
        (".", "invalid"),
        ("a b.test", "found an invalid character"),
        (long_label.as_str(), "one label too long"),
        (long_name.as_str(), "hostname too long"),
    ] {
        let got = r.query(t0, name, Question::v4(), Requester::DoResolve);
        match got {
            Err(QueryError::InvalidName(msg)) => {
                if why != "invalid" {
                    assert_eq!(msg, why, "{name:?}");
                }
            }
            other => panic!("{name:?} accepted: {other:?}"),
        }
    }
    assert!(r.poll_transmit(t0).is_none(), "nothing is sent for a refused name");
    assert!(r.poll_result().is_none());
    // A trailing dot and 63-byte labels are fine.
    assert!(r.query(t0, &format!("{}.test.", "a".repeat(63)), Question::v4(), Requester::DoResolve).is_ok());
}

/// A server's name is only cut into labels (`resolv_str_to_dn_label`, measured on `HAProxy`
/// 3.5-dev8: `server s1 a!b.test:80 resolvers r` is asked and resolves): an empty label is
/// refused, any character and any length go out as written.
#[test]
fn a_server_name_is_asked_as_written() {
    let mut r = Resolver::new(cfg(&[NS1]));
    let t0 = Instant::now();
    for name in ["bad..name", "", ".", ".a.test"] {
        assert!(matches!(r.query(t0, name, Question::v4(), Requester::Server), Err(QueryError::InvalidName(_))), "{name:?}");
    }
    let long_label = format!("{}.test", "a".repeat(64));
    for name in ["a!b.test", "a b.test", long_label.as_str()] {
        assert!(r.query(t0, name, Question::v4(), Requester::Server).is_ok(), "{name:?}");
    }
    let mut sent = Vec::new();
    while let Some((_, _, buf)) = r.poll_transmit(t0) {
        sent.push(buf);
    }
    assert_eq!(sent.len(), 3);
    // The question of the first: 3 "a!b", 4 "test", 0.
    assert_eq!(&sent[0][12..22], b"\x03a!b\x04test\x00");
    assert_eq!(sent[2][12], 64);
}

// Item 9 (rewrites test_ttl_drives_reresolution). HAProxy ignores the TTL: a server is
// re-resolved every `timeout resolve` whatever the TTL (A.t2: TTL 300, queries every 2 s), and
// `hold valid` is the `do-resolve` cache's lifetime (A.t14: a second request 2.3 s later sends
// no query). B.P10: the crate cached min(TTL, hold valid) and served servers from it.
#[test]
fn the_ttl_does_not_drive_reresolution() {
    let mut c = cfg(&[NS1]);
    c.hold_valid = Duration::from_secs(10);
    let mut r = Resolver::new(c);
    let t0 = Instant::now();
    q4(&mut r, t0, "ttl.test");
    let id = sends(&mut r, t0)[0].2;
    r.handle_response(t0, ns(NS1), Protocol::Udp, &a_response(id, "ttl.test", Ipv4Addr::new(1, 2, 3, 4), 5));
    assert_eq!(r.poll_result().unwrap().1.unwrap(), vec![a(Ipv4Addr::new(1, 2, 3, 4), 5)]);

    // A server asks again 1 s later: a query is sent, the cache is not consulted.
    q4(&mut r, ms(t0, 1000), "ttl.test");
    assert_eq!(sends(&mut r, ms(t0, 1000)).len(), 1, "a server query must not be served from the cache");
    assert!(r.poll_result().is_none());

    // do-resolve 6 s later, past the TTL of 5 s but inside hold valid: from the cache.
    let mut r = Resolver::new(ResolverConfig { hold_valid: Duration::from_secs(10), ..cfg(&[NS1]) });
    r.query(t0, "ttl.test", Question::v4(), Requester::DoResolve).unwrap();
    let id = sends(&mut r, t0)[0].2;
    r.handle_response(t0, ns(NS1), Protocol::Udp, &a_response(id, "ttl.test", Ipv4Addr::new(1, 2, 3, 4), 5));
    assert!(r.poll_result().unwrap().1.is_ok());
    r.query(ms(t0, 6000), "ttl.test", Question::v4(), Requester::DoResolve).unwrap();
    assert!(sends(&mut r, ms(t0, 6000)).is_empty(), "do-resolve inside hold valid must use the cache");
    assert!(r.poll_result().unwrap().1.is_ok());
    // And past hold valid: a query.
    r.query(ms(t0, 10_001), "ttl.test", Question::v4(), Requester::DoResolve).unwrap();
    assert_eq!(sends(&mut r, ms(t0, 10_001)).len(), 1);
}

// Item 9 (rewrites test_hold_timers_independent). A hold is how long a *server* keeps its last
// address once errors start (snr_set_srv_down, server.c:5135), decided by the engine (T484);
// the resolver keeps querying meanwhile (A.t4: NX from 2.6, retried at 3.6 and 4.6, the next
// resolution at 7.6). So an error is never cached: the next query of any requester is sent.
#[test]
fn errors_are_not_cached() {
    for (rcode, what) in [
        (Some(ResponseCode::NXDomain), "nx"),
        (Some(ResponseCode::Refused), "refused"),
        (Some(ResponseCode::ServFail), "servfail"),
        (None, "timeout"),
    ] {
        let mut c = cfg(&[NS1]);
        c.resolve_retries = 1;
        c.hold_nx = Duration::from_secs(30);
        c.hold_other = Duration::from_secs(30);
        c.hold_refused = Duration::from_secs(30);
        c.hold_timeout = Duration::from_secs(30);
        let mut r = Resolver::new(c);
        let t0 = Instant::now();
        for requester in [Requester::Server, Requester::DoResolve] {
            r.query(t0, "e.test", Question::v4(), requester).unwrap();
            let id = sends(&mut r, t0)[0].2;
            if let Some(rc) = rcode {
                r.handle_response(t0, ns(NS1), Protocol::Udp, &error_response(id, "e.test", RecordType::A, rc));
            }
            sends(&mut r, ms(t0, 1000));
            assert!(r.poll_result().unwrap().1.is_err(), "{what}");

            r.query(ms(t0, 1500), "e.test", Question::v4(), requester).unwrap();
            assert_eq!(sends(&mut r, ms(t0, 1500)).len(), 1, "{what}/{requester:?}: an error must not be cached");
            assert!(r.poll_result().is_none());
            sends(&mut r, ms(t0, 2500));
            r.poll_result();
        }
    }
}

#[test]
fn test_poll_timeout_honest() {
    let mut c = cfg(&[NS1]);
    c.timeout_retry = Duration::from_secs(2);
    c.timeout_resolve = Duration::from_secs(10);
    let mut r = Resolver::new(c);

    assert!(r.poll_timeout().is_none(), "poll_timeout must be None when idle");

    let now = Instant::now();
    q4(&mut r, now, "example.com");
    assert_eq!(r.poll_timeout(), Some(now), "before transmit, must be ready now");

    r.poll_transmit(now);
    let expected = now + Duration::from_secs(2);
    assert_eq!(r.poll_timeout(), Some(expected), "after transmit, must wait for retry");

    let now2 = now + Duration::from_secs(1);
    q4(&mut r, now2, "example2.com");
    r.poll_transmit(now2);
    assert_eq!(r.poll_timeout(), Some(expected), "must return earliest deadline");
}

// Item 1: resolv_run_resolution draws at most 100 ids for one no resolution in flight uses.
#[test]
fn no_free_message_id_is_refused() {
    let mut c = cfg(&[NS1]);
    c.random_id = || 7;
    let mut r = Resolver::new(c);
    let t0 = Instant::now();
    q4(&mut r, t0, "a.test");
    assert_eq!(r.query(t0, "b.test", Question::v4(), Requester::Server), Err(QueryError::NoFreeId));
}

#[test]
fn no_nameserver_is_an_error_result() {
    let mut r = Resolver::new(ResolverConfig::default());
    let t0 = Instant::now();
    let id = q4(&mut r, t0, "a.test");
    assert!(r.poll_transmit(t0).is_none());
    assert_eq!(r.poll_result(), Some((id, Err(DnsError::Other))));
}

// F9: a truncated answer over TCP is an error (`truncated`, status OTHER), not another fallback.
#[test]
fn a_truncated_tcp_answer_is_other() {
    let mut c = cfg(&[NS1]);
    c.resolve_retries = 1;
    let mut r = Resolver::new(c);
    let t0 = Instant::now();
    q4(&mut r, t0, "tc.test");
    let id = sends(&mut r, t0)[0].2;
    let mut tc = Message::from_vec(&a_response(id, "tc.test", Ipv4Addr::new(10, 0, 0, 7), 60)).unwrap();
    tc.set_truncated(true);
    let tc = tc.to_vec().unwrap();
    assert_eq!(r.handle_response(t0, ns(NS1), Protocol::Udp, &tc), Received::Truncated);
    assert_eq!(sends(&mut r, t0), vec![(ns(NS1), Protocol::Tcp, id, RecordType::A)]);
    assert_eq!(r.handle_response(t0, ns(NS1), Protocol::Tcp, &tc), Received::Truncated);
    assert!(sends(&mut r, t0).is_empty(), "no second fallback");
    sends(&mut r, ms(t0, 1000));
    assert_eq!(r.poll_result().unwrap().1, Err(DnsError::Other));
}

// T484: with `tcp_fallback` off, a truncated UDP answer is an error like a
// truncated TCP one: counted `truncated`, no TCP query, the resolution ends `Other`.
#[test]
fn without_tcp_fallback_a_truncated_udp_answer_is_other() {
    let mut c = cfg(&[NS1]);
    c.resolve_retries = 1;
    c.tcp_fallback = false;
    let mut r = Resolver::new(c);
    let t0 = Instant::now();
    q4(&mut r, t0, "tc.test");
    let id = sends(&mut r, t0)[0].2;
    let mut tc = Message::from_vec(&a_response(id, "tc.test", Ipv4Addr::new(10, 0, 0, 7), 60)).unwrap();
    tc.set_truncated(true);
    assert_eq!(r.handle_response(t0, ns(NS1), Protocol::Udp, &tc.to_vec().unwrap()), Received::Truncated);
    assert!(sends(&mut r, t0).is_empty(), "no TCP query");
    sends(&mut r, ms(t0, 1000));
    assert_eq!(r.poll_result().unwrap().1, Err(DnsError::Other));
}

// T488: `tcp@` sends the query over TCP (to that nameserver only), and a nameserver with
// `udp@` has no fallback although `tcp_fallback` is on.
#[test]
fn transports_choose_the_protocol_and_the_fallback() {
    let mut c = cfg(&[NS1, NS2]);
    c.resolve_retries = 1;
    c.transports = vec![NsTransport::Tcp, NsTransport::Udp];
    let mut r = Resolver::new(c);
    let t0 = Instant::now();
    q4(&mut r, t0, "tc.test");
    let s = sends(&mut r, t0);
    assert_eq!(s.iter().map(|x| (x.0, x.1)).collect::<Vec<_>>(), vec![(ns(NS1), Protocol::Tcp), (ns(NS2), Protocol::Udp)]);
    let mut tc = Message::from_vec(&a_response(s[1].2, "tc.test", Ipv4Addr::new(10, 0, 0, 7), 60)).unwrap();
    tc.set_truncated(true);
    assert_eq!(r.handle_response(t0, ns(NS2), Protocol::Udp, &tc.to_vec().unwrap()), Received::Truncated);
    assert!(sends(&mut r, t0).is_empty(), "no fallback on udp@");
}

// Item 4, at the retry timer (resolvers.c:2631-2640): both families, an error from one of two
// nameservers and silence from the other: the next try is of the other type, no try used.
#[test]
fn the_retry_timer_flips_the_type_after_a_partial_error() {
    let mut r = Resolver::new(cfg(&[NS1, NS2]));
    let t0 = Instant::now();
    let q = Question::Addr { accept: Families::BOTH, prefer: Family::Ipv4 };
    r.query(t0, "half.test", q, Requester::Server).unwrap();
    let id = sends(&mut r, t0)[0].2;
    let nx = error_response(id, "half.test", RecordType::A, ResponseCode::NXDomain);
    assert_eq!(r.handle_response(t0, ns(NS1), Protocol::Udp, &nx), Received::Nx);
    assert_eq!(sends(&mut r, t0), vec![]);
    let types: Vec<_> = sends(&mut r, ms(t0, 1000)).into_iter().map(|s| s.3).collect();
    assert_eq!(types, vec![RecordType::AAAA, RecordType::AAAA]);
    // Then back to A for the remaining two tries (silence: no flip), then the timeout.
    for t in [2000, 3000] {
        let types: Vec<_> = sends(&mut r, ms(t0, t)).into_iter().map(|s| s.3).collect();
        assert_eq!(types, vec![RecordType::A, RecordType::A], "at {t} ms");
    }
    sends(&mut r, ms(t0, 4000));
    assert_eq!(r.poll_result().unwrap().1, Err(DnsError::Timeout));
}

// T513 (defect E of T484): `tcp@A` and `A` are two nameservers on one address. The
// transmits and the replies are keyed by index: each gets the question over its own
// transport, and an NX from one waits for the other (A.t10 on `HAProxy` 3.5-dev8: both asked).
#[test]
fn two_nameservers_on_one_address_are_told_apart_by_index() {
    let mut c = cfg(&[NS1, NS1]);
    c.transports = vec![NsTransport::Tcp, NsTransport::Udp];
    let mut r = Resolver::new(c);
    let t0 = Instant::now();
    q4(&mut r, t0, "two.test");
    let mut tx = Vec::new();
    while let Some((i, proto, buf)) = r.poll_transmit_ns(t0) {
        tx.push((i, proto, Message::from_vec(&buf).unwrap().id()));
    }
    assert_eq!(tx.iter().map(|t| (t.0, t.1)).collect::<Vec<_>>(), [(0, Protocol::Tcp), (1, Protocol::Udp)]);
    let id = tx[0].2;
    let nx = error_response(id, "two.test", RecordType::A, ResponseCode::NXDomain);
    assert_eq!(r.handle_response_ns(t0, 0, Protocol::Tcp, &nx), Received::Nx);
    assert!(r.poll_result().is_none(), "the second nameserver has not answered");
    let ok = a_response(id, "two.test", Ipv4Addr::new(10, 0, 0, 9), 60);
    assert_eq!(r.handle_response_ns(t0, 1, Protocol::Udp, &ok), Received::Valid);
    assert_eq!(r.poll_result().unwrap().1.unwrap(), vec![a(Ipv4Addr::new(10, 0, 0, 9), 60)]);
    // An index the section does not have is not a nameserver.
    assert_eq!(r.handle_response_ns(t0, 2, Protocol::Udp, &ok), Received::Invalid);
}
