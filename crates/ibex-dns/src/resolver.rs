// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! One `resolvers` section's resolutions, as `HAProxy`'s `src/resolvers.c` runs them
//! (`resolv_run_resolution`, `resolv_send_query`, `resolv_process_responses`,
//! `process_resolvers`). Design and measurements: `docs/design/dns-2026-10-25.md`.
//!
//! A resolution: a random message id (kept for all its tries), `resolve_retries` tries
//! `timeout_retry` apart, each sent to every nameserver. A valid answer from any nameserver
//! ends it at once; an error ends a try only once every nameserver has answered, and the
//! resolution only when the tries are used up. Scheduling resolutions every
//! `timeout_resolve`, and the `hold` timers, belong to the caller (T484).

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasher;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use hickory_proto::rr::{DNSClass, Name, RData};

use crate::{
    Answer, DnsError, Family, Protocol, QueryError, QueryId, Question, Rdata, Received, Requester,
};

/// `HAProxy`'s `DNS_MAX_NAME_SIZE`, `DNS_MAX_LABEL_SIZE`, `DNS_HEADER_SIZE`,
/// `DNS_MIN_RECORD_SIZE`, and the largest message over TCP.
const MAX_NAME: usize = 255;
const MAX_LABEL: usize = 63;
const HEADER: usize = 12;
const MIN_RECORD: usize = 6;
const MAX_MSG: usize = 65_535;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;

pub struct ResolverConfig {
    pub nameservers: Vec<SocketAddr>,
    /// Tries per resolution, the first send included.
    pub resolve_retries: usize,
    /// The period between two resolutions of a name. Not read here: the caller schedules
    /// resolutions with it (T484).
    pub timeout_resolve: Duration,
    /// The time between two tries; the last try's `timeout_retry` ends a resolution that got
    /// no valid answer.
    pub timeout_retry: Duration,
    /// The lifetime of a valid answer in the `do-resolve` cache (T489). Server queries never
    /// read the cache.
    pub hold_valid: Duration,
    /// The `hold` timers decide what a *server* does on an error status (T484,
    /// `snr_set_srv_down`). Not read here.
    pub hold_nx: Duration,
    pub hold_other: Duration,
    pub hold_refused: Duration,
    pub hold_timeout: Duration,
    /// SRV records' obsolescence (T487). Not read here.
    pub hold_obsolete: Duration,
    /// Announced in every query's OPT record; a longer UDP reply is `too_big`, and
    /// `(size - 12) / 6` bounds the answers a UDP reply may announce.
    pub accepted_payload_size: u16,
    /// The message id generator. T484 passes `ibex_rt`'s RNG; the default is `SipHash` under
    /// the standard library's random keys.
    pub random_id: fn() -> u16,
    /// A truncated UDP answer is asked again over TCP (`HAProxy`'s behaviour, A.t9). Off, it
    /// is an error like a truncated TCP answer (`Other`).
    pub tcp_fallback: bool,
    /// How each nameserver (by index) is reached; missing entries are [`NsTransport::Auto`].
    pub transports: Vec<NsTransport>,
}

/// How a nameserver is reached (the address prefix of `nameserver`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum NsTransport {
    /// UDP, and a truncated answer is asked again over TCP (`tcp_fallback`).
    #[default]
    Auto,
    /// UDP only (`udp@`): a truncated answer is `Other`.
    Udp,
    /// Every query over TCP (`tcp@`).
    Tcp,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            nameservers: vec![],
            resolve_retries: 3,
            timeout_resolve: Duration::from_secs(1),
            timeout_retry: Duration::from_secs(1),
            hold_valid: Duration::from_secs(10),
            hold_nx: Duration::from_secs(30),
            hold_other: Duration::from_secs(30),
            hold_refused: Duration::from_secs(30),
            hold_timeout: Duration::from_secs(30),
            hold_obsolete: Duration::from_secs(0),
            accepted_payload_size: 512,
            random_id: default_random_id,
            tcp_fallback: true,
            transports: vec![],
        }
    }
}

fn default_random_id() -> u16 {
    static KEYS: OnceLock<RandomState> = OnceLock::new();
    static N: AtomicU64 = AtomicU64::new(0);
    let h = KEYS.get_or_init(RandomState::new).hash_one(N.fetch_add(1, Ordering::Relaxed));
    h.to_be_bytes()[3..5].iter().fold(0u16, |acc, b| acc << 8 | u16::from(*b))
}

type Cached = Option<(Vec<Answer>, Instant)>;

/// The `do-resolve` cache: one valid result per name and question kind, kept `hold valid`.
#[derive(Default)]
struct CacheSlot {
    addr: Cached,
    srv: Cached,
}

impl CacheSlot {
    fn get(&mut self, srv: bool) -> &mut Cached {
        if srv { &mut self.srv } else { &mut self.addr }
    }
}

struct InFlight {
    id: QueryId,
    name: Box<str>,
    /// The name in wire form, lower-cased (`resolv_str_to_dn_label`).
    dn: Vec<u8>,
    question: Question,
    prefer_type: u16,
    query_type: u16,
    /// Tries left after the current one (`HAProxy`'s `try`).
    tries: usize,
    /// The next `poll_transmit` sends this resolution to every nameserver.
    send_now: bool,
    last_query: Instant,
    nb_queries: usize,
    nb_responses: usize,
    nb_tcp_fallback: usize,
    /// The status the last reply left (`HAProxy`'s `res->status`).
    status: Option<DnsError>,
    message_id: u16,
}

impl InFlight {
    fn both_families(&self) -> bool {
        matches!(self.question, Question::Addr { accept, .. } if accept.ipv4 && accept.ipv6)
    }
}

pub struct Resolver {
    cfg: ResolverConfig,
    next_query_id: u64,
    cache: HashMap<Box<str>, CacheSlot>,
    in_flight: Vec<InFlight>,
    transmits: VecDeque<(SocketAddr, Protocol, Vec<u8>)>,
    results: VecDeque<(QueryId, Result<Vec<Answer>, DnsError>)>,
}

/// `resolv_hostname_validation` + `resolv_str_to_dn_label`: the wire form, lower-cased.
fn to_dn(name: &str) -> Result<Vec<u8>, QueryError> {
    if name.len() > MAX_NAME {
        return Err(QueryError::InvalidName("hostname too long"));
    }
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() {
        return Err(QueryError::InvalidName("empty hostname"));
    }
    let mut dn = Vec::with_capacity(trimmed.len() + 2);
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(QueryError::InvalidName("empty label"));
        }
        if !label.bytes().all(|b| b == b'-' || b == b'_' || b.is_ascii_alphanumeric()) {
            return Err(QueryError::InvalidName("found an invalid character"));
        }
        let len = u8::try_from(label.len())
            .ok()
            .filter(|l| usize::from(*l) <= MAX_LABEL)
            .ok_or(QueryError::InvalidName("one label too long"))?;
        dn.push(len);
        dn.extend(label.bytes().map(|b| b.to_ascii_lowercase()));
    }
    dn.push(0);
    Ok(dn)
}

/// `resolv_build_query`: header (rd), one question, one OPT record.
fn build_query(id: u16, dn: &[u8], qtype: u16, payload: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(HEADER + dn.len() + 4 + 11);
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]);
    b.extend_from_slice(dn);
    b.extend_from_slice(&qtype.to_be_bytes());
    b.extend_from_slice(&CLASS_IN.to_be_bytes());
    b.push(0); // root name
    b.extend_from_slice(&TYPE_OPT.to_be_bytes());
    b.extend_from_slice(&payload.to_be_bytes());
    b.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // extended rcode, version, flags, rdlength
    b
}

/// The other address type, for the A <-> AAAA fallback.
fn flip(t: u16) -> u16 {
    if t == TYPE_A { TYPE_AAAA } else { TYPE_A }
}

/// A decoded name against a wire-form `dn`, case-insensitively.
fn name_is(name: &Name, dn: &[u8]) -> bool {
    let mut rest = dn;
    for label in name {
        let Some((&len, tail)) = rest.split_first() else { return false };
        let len = usize::from(len);
        if len == 0 || len != label.len() || !tail[..len].eq_ignore_ascii_case(label) {
            return false;
        }
        rest = &tail[len..];
    }
    rest == [0]
}

fn names_eq(a: &Name, b: &Name) -> bool {
    a.num_labels() == b.num_labels() && a.iter().zip(b.iter()).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// What a matched reply says (`resolv_validate_dns_response`).
enum Verdict {
    Valid(Vec<Answer>),
    Error(Received, DnsError),
    Truncated,
    Invalid,
}

impl Resolver {
    #[must_use]
    pub fn new(cfg: ResolverConfig) -> Self {
        Self {
            cfg,
            next_query_id: 1,
            cache: HashMap::new(),
            in_flight: Vec::new(),
            transmits: VecDeque::new(),
            results: VecDeque::new(),
        }
    }

    /// Starts a resolution of `name`. A `DoResolve` query inside `hold valid` of a valid
    /// answer is answered from the cache. The query is sent by the next [`Self::poll_transmit`].
    ///
    /// # Errors
    /// An invalid name (nothing is sent), no family accepted, or no free message id.
    pub fn query(
        &mut self,
        now: Instant,
        name: &str,
        question: Question,
        requester: Requester,
    ) -> Result<QueryId, QueryError> {
        let dn = to_dn(name)?;
        let prefer_type = match question {
            Question::Srv => TYPE_SRV,
            // The preferred family if accepted, else the other one (A.t18).
            Question::Addr { accept, prefer } => match (prefer, accept.ipv4, accept.ipv6) {
                (Family::Ipv4, true, _) | (Family::Ipv6, true, false) => TYPE_A,
                (_, _, true) => TYPE_AAAA,
                (_, false, false) => return Err(QueryError::NoFamily),
            },
        };
        let qid = QueryId(self.next_query_id);
        self.next_query_id += 1;

        if let Some(slot) = self.cache.get_mut(name).filter(|_| requester == Requester::DoResolve) {
            let entry = slot.get(question == Question::Srv);
            if let Some((answers, exp)) = entry {
                if *exp > now {
                    self.results.push_back((qid, Ok(answers.clone())));
                    return Ok(qid);
                }
                *entry = None;
            }
        }

        if self.cfg.nameservers.is_empty() {
            self.results.push_back((qid, Err(DnsError::Other)));
            return Ok(qid);
        }

        // resolv_run_resolution: at most 100 draws for an id no resolution uses.
        let message_id = (0..100)
            .map(|_| (self.cfg.random_id)())
            .find(|id| self.in_flight.iter().all(|f| f.message_id != *id))
            .ok_or(QueryError::NoFreeId)?;

        self.in_flight.push(InFlight {
            id: qid,
            name: name.into(),
            dn,
            question,
            prefer_type,
            query_type: prefer_type,
            tries: self.cfg.resolve_retries.saturating_sub(1),
            send_now: true,
            last_query: now,
            nb_queries: 0,
            nb_responses: 0,
            nb_tcp_fallback: 0,
            status: None,
            message_id,
        });
        Ok(qid)
    }

    fn transport_of(&self, ns: SocketAddr) -> NsTransport {
        self.cfg.nameservers.iter().position(|a| *a == ns).and_then(|i| self.cfg.transports.get(i)).copied().unwrap_or_default()
    }

    /// The next datagram to send. Each try goes to every nameserver, in configuration order.
    /// Also runs the retry timer: call it at [`Self::poll_timeout`].
    pub fn poll_transmit(&mut self, now: Instant) -> Option<(SocketAddr, Protocol, Vec<u8>)> {
        if let Some(tx) = self.transmits.pop_front() {
            return Some(tx);
        }

        // process_resolvers (resolvers.c:2588-2640): a try whose `timeout retry` ran out.
        let mut i = 0;
        while i < self.in_flight.len() {
            let f = &mut self.in_flight[i];
            if f.send_now || now < f.last_query + self.cfg.timeout_retry {
                i += 1;
                continue;
            }
            if f.tries == 0 {
                let f = self.in_flight.remove(i);
                let status = match f.status {
                    Some(s) if f.nb_responses > 0 => s,
                    _ => DnsError::Timeout,
                };
                self.results.push_back((f.id, Err(status)));
                continue;
            }
            if f.nb_responses == 0
                || f.nb_tcp_fallback > 0
                || f.prefer_type != f.query_type
                || !f.both_families()
            {
                f.query_type = f.prefer_type;
                f.tries -= 1;
            } else {
                f.query_type = flip(f.prefer_type);
            }
            f.send_now = true;
            i += 1;
        }

        let f = self.in_flight.iter_mut().find(|f| f.send_now)?;
        f.send_now = false;
        f.last_query = now;
        f.nb_queries = self.cfg.nameservers.len();
        f.nb_responses = 0;
        f.nb_tcp_fallback = 0;
        let buf = build_query(f.message_id, &f.dn, f.query_type, self.cfg.accepted_payload_size);
        let proto = |i: usize| if self.cfg.transports.get(i) == Some(&NsTransport::Tcp) { Protocol::Tcp } else { Protocol::Udp };
        for (i, &other) in self.cfg.nameservers.iter().enumerate().skip(1) {
            self.transmits.push_back((other, proto(i), buf.clone()));
        }
        Some((self.cfg.nameservers[0], proto(0), buf))
    }

    /// Feeds one reply received from `from` over `proto`. The returned class is the
    /// nameserver counter `HAProxy` increments for it; only a valid answer, or an error once
    /// every nameserver has answered, moves the resolution on.
    pub fn handle_response(&mut self, now: Instant, from: SocketAddr, proto: Protocol, buf: &[u8]) -> Received {
        let max_payload = match proto {
            Protocol::Udp => usize::from(self.cfg.accepted_payload_size),
            Protocol::Tcp => MAX_MSG,
        };
        if buf.len() > max_payload {
            return Received::TooBig;
        }
        if buf.len() < 2 || !self.cfg.nameservers.contains(&from) {
            return Received::Invalid;
        }
        let msg_id = u16::from_be_bytes([buf[0], buf[1]]);
        let Some(idx) = self.in_flight.iter().position(|f| f.message_id == msg_id) else {
            return Received::Outdated;
        };
        let transport = self.transport_of(from);
        let f = &mut self.in_flight[idx];
        if proto == Protocol::Tcp && transport == NsTransport::Auto && f.nb_tcp_fallback > 0 {
            f.nb_tcp_fallback -= 1;
        }
        f.nb_responses += 1;

        let (verdict, qtype) = validate(buf, f, max_payload);
        let (rx, status) = match verdict {
            Verdict::Valid(answers) => {
                let f = self.in_flight.remove(idx);
                if !self.cfg.hold_valid.is_zero() {
                    let slot = self.cache.entry(f.name).or_default();
                    *slot.get(f.question == Question::Srv) = Some((answers.clone(), now + self.cfg.hold_valid));
                }
                self.results.push_back((f.id, Ok(answers)));
                return Received::Valid;
            }
            Verdict::Truncated if proto == Protocol::Udp && transport == NsTransport::Auto && self.cfg.tcp_fallback => {
                // resolv_send_tcp_fallback: the same question over TCP to this nameserver,
                // without using a try.
                f.nb_queries += 1;
                f.nb_tcp_fallback += 1;
                f.last_query = now;
                let q = build_query(f.message_id, &f.dn, qtype, self.cfg.accepted_payload_size);
                self.transmits.push_back((from, Protocol::Tcp, q));
                return Received::Truncated;
            }
            Verdict::Truncated => (Received::Truncated, DnsError::Other),
            Verdict::Invalid => (Received::Invalid, DnsError::Invalid),
            Verdict::Error(rx, e) => (rx, e),
        };
        f.status = Some(status);

        // Wait for every nameserver before treating an error (resolvers.c:2488).
        if f.nb_responses < f.nb_queries {
            return rx;
        }
        if f.prefer_type != f.query_type {
            // The type fallback already ran: report if no try is left, else wait for the timer.
            if f.tries == 0 {
                let f = self.in_flight.remove(idx);
                self.results.push_back((f.id, Err(f.status.unwrap_or(DnsError::Other))));
            }
        } else if f.both_families() {
            // A <-> AAAA at once, same id, the try not used.
            f.query_type = flip(f.prefer_type);
            f.send_now = true;
        }
        rx
    }

    /// When [`Self::poll_transmit`] next has something to do.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.in_flight
            .iter()
            .map(|f| if f.send_now { f.last_query } else { f.last_query + self.cfg.timeout_retry })
            .min()
    }

    pub fn poll_result(&mut self) -> Option<(QueryId, Result<Vec<Answer>, DnsError>)> {
        self.results.pop_front()
    }
}

/// `resolv_validate_dns_response` (resolvers.c:1052-1660) on a reply whose id matched `f`.
/// Returns the verdict and the reply's question type (for the TCP fallback).
fn validate(buf: &[u8], f: &InFlight, max_payload: usize) -> (Verdict, u16) {
    if buf.len() < HEADER {
        return (Verdict::Invalid, f.query_type);
    }
    let word = |i: usize| u16::from_be_bytes([buf[i], buf[i + 1]]);
    // The rcode is read before anything else, as HAProxy does.
    match word(2) & 0x000f {
        0 => {}
        3 => return (Verdict::Error(Received::Nx, DnsError::NxDomain), f.query_type),
        5 => return (Verdict::Error(Received::Refused, DnsError::Refused), f.query_type),
        _ => return (Verdict::Error(Received::Other, DnsError::Other), f.query_type),
    }
    // One question; no more answers announced than the payload can carry (before decoding,
    // so a lying count drives no allocation).
    if word(4) != 1 || usize::from(word(6)) > max_payload.saturating_sub(HEADER) / MIN_RECORD {
        return (Verdict::Invalid, f.query_type);
    }
    let Ok(msg) = Message::from_vec(buf) else {
        return (Verdict::Invalid, f.query_type);
    };
    let q = &msg.queries()[0];
    let qtype = u16::from(q.query_type());
    let addr = |t: u16| t == TYPE_A || t == TYPE_AAAA;
    if !name_is(q.name(), &f.dn)
        || q.query_class() != DNSClass::IN
        || (qtype != f.query_type && !(addr(qtype) && addr(f.query_type)))
    {
        return (Verdict::Invalid, qtype);
    }
    if msg.truncated() {
        return (Verdict::Truncated, qtype);
    }
    let n = msg.answers().len();
    if n == 0 {
        return (Verdict::Error(Received::AnyErr, DnsError::Other), qtype);
    }

    // Each owner is the name asked or the last CNAME's target (not checked for SRV); a CNAME
    // as the last record is a chain with no address.
    let srv = qtype == TYPE_SRV;
    let mut target: Option<&Name> = None;
    let mut answers: Vec<Answer> = Vec::with_capacity(n);
    for (i, rec) in msg.answers().iter().enumerate() {
        let owner_ok = srv
            || match target {
                None => name_is(rec.name(), &f.dn),
                Some(t) => names_eq(rec.name(), t),
            };
        if !owner_ok {
            let v = if i == 0 { Verdict::Invalid } else { Verdict::Error(Received::CnameError, DnsError::Other) };
            return (v, qtype);
        }
        let rdata = match rec.data() {
            RData::A(ip) => Rdata::A(ip.0),
            RData::AAAA(ip) => Rdata::Aaaa(ip.0),
            RData::SRV(s) => Rdata::Srv {
                target: s.target().to_string(),
                port: s.port(),
                priority: s.priority(),
                weight: s.weight(),
            },
            RData::CNAME(c) => {
                if i + 1 == n {
                    return (Verdict::Error(Received::CnameError, DnsError::Other), qtype);
                }
                target = Some(&c.0);
                continue;
            }
            _ => continue,
        };
        // A record seen twice is kept once (resolvers.c:1400-1450).
        if !answers.iter().any(|a| a.rdata == rdata) {
            answers.push(Answer { rdata, ttl: rec.ttl() });
        }
    }
    (Verdict::Valid(answers), qtype)
}
