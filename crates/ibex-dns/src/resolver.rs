// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query as ProtoQuery, ResponseCode};
use hickory_proto::rr::{Name, RecordType, RData};

use crate::{Answer, DnsError, Protocol, QueryId, RecordKind};

pub struct ResolverConfig {
    pub nameservers: Vec<SocketAddr>,
    pub resolve_retries: usize,
    pub timeout_resolve: Duration,
    pub timeout_retry: Duration,
    pub hold_valid: Duration,
    pub hold_nx: Duration,
    pub hold_other: Duration,
    pub hold_refused: Duration,
    pub hold_timeout: Duration,
    pub hold_obsolete: Duration,
    pub accepted_payload_size: u16,
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
        }
    }
}

#[derive(Clone)]
struct CacheEntry {
    result: Result<Vec<Answer>, DnsError>,
    expires_at: Instant,
}

struct InFlight {
    id: QueryId,
    name: String,
    kind: RecordKind,
    proto: Protocol,
    nameserver_idx: usize,
    retries_left: usize,
    next_transmit: Instant,
    deadline: Instant,
    message_id: u16,
}

pub struct Resolver {
    cfg: ResolverConfig,
    next_query_id: u64,
    next_message_id: u16,
    cache: HashMap<(String, RecordKind), CacheEntry>,
    in_flight: Vec<InFlight>,
    transmits: VecDeque<(SocketAddr, Protocol, Vec<u8>)>,
    results: VecDeque<(QueryId, Result<Vec<Answer>, DnsError>)>,
}

impl Resolver {
    #[must_use]
    pub fn new(cfg: ResolverConfig) -> Self {
        Self {
            cfg,
            next_query_id: 1,
            next_message_id: 1,
            cache: HashMap::new(),
            in_flight: Vec::new(),
            transmits: VecDeque::new(),
            results: VecDeque::new(),
        }
    }

    pub fn query(&mut self, now: Instant, name: &str, kind: RecordKind) -> QueryId {
        let qid = QueryId(self.next_query_id);
        self.next_query_id += 1;

        // Check cache
        let cache_key = (name.to_string(), kind);
        if let Some(entry) = self.cache.get(&cache_key) {
            if entry.expires_at > now {
                self.results.push_back((qid, entry.result.clone()));
                return qid;
            }
            self.cache.remove(&cache_key);
        }

        if self.cfg.nameservers.is_empty() {
            self.results.push_back((qid, Err(DnsError::Other)));
            return qid;
        }

        let message_id = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);

        let inflight = InFlight {
            id: qid,
            name: name.to_string(),
            kind,
            proto: Protocol::Udp,
            nameserver_idx: 0,
            retries_left: self.cfg.resolve_retries,
            next_transmit: now,
            deadline: now + self.cfg.timeout_resolve,
            message_id,
        };

        self.in_flight.push(inflight);
        // Will be transmitted on next poll_transmit
        qid
    }

    pub fn poll_transmit(&mut self, now: Instant) -> Option<(SocketAddr, Protocol, Vec<u8>)> {
        if let Some(tx) = self.transmits.pop_front() {
            return Some(tx);
        }

        let mut i = 0;
        while i < self.in_flight.len() {
            if now >= self.in_flight[i].deadline || self.in_flight[i].retries_left == 0 && now >= self.in_flight[i].next_transmit {
                let inflight = self.in_flight.remove(i);
                self.cache.insert((inflight.name, inflight.kind), CacheEntry {
                    result: Err(DnsError::Timeout),
                    expires_at: now + self.cfg.hold_timeout,
                });
                self.results.push_back((inflight.id, Err(DnsError::Timeout)));
                continue;
            }
            i += 1;
        }

        for inflight in &mut self.in_flight {
            if now >= inflight.next_transmit {
                inflight.next_transmit = now + self.cfg.timeout_retry;
                
                let mut msg = Message::new();
                msg.set_id(inflight.message_id)
                   .set_message_type(MessageType::Query)
                   .set_op_code(OpCode::Query)
                   .set_recursion_desired(true); // Usually true for forwarders

                let rtype = match inflight.kind {
                    RecordKind::A => RecordType::A,
                    RecordKind::Aaaa => RecordType::AAAA,
                    RecordKind::Srv => RecordType::SRV,
                };

                if let Ok(n) = Name::from_str(&inflight.name) {
                    let proto_query = ProtoQuery::query(n, rtype);
                    msg.add_query(proto_query);
                }

                if let Ok(buf) = msg.to_vec() {
                    let ns = self.cfg.nameservers[inflight.nameserver_idx];
                    inflight.nameserver_idx = (inflight.nameserver_idx + 1) % self.cfg.nameservers.len();
                    if inflight.retries_left > 0 {
                        inflight.retries_left -= 1;
                    }
                    return Some((ns, inflight.proto, buf));
                }
            }
        }

        None
    }

    pub fn handle_response(&mut self, now: Instant, _from: SocketAddr, buf: &[u8]) {
        let Ok(msg) = Message::from_vec(buf) else {
            return;
        };

        if msg.message_type() != MessageType::Response {
            return;
        }

        let mut matched_idx = None;
        for (i, inflight) in self.in_flight.iter().enumerate() {
            if inflight.message_id == msg.id() {
                matched_idx = Some(i);
                break;
            }
        }

        let Some(idx) = matched_idx else {
            return;
        };

        let inflight = &self.in_flight[idx];

        // Truncation check
        if msg.truncated() && inflight.proto == Protocol::Udp {
            let mut inflight_copy = self.in_flight.remove(idx);
            inflight_copy.proto = Protocol::Tcp;
            inflight_copy.next_transmit = now; // Retry immediately
            self.in_flight.push(inflight_copy);
            return;
        }

        let qid = inflight.id;
        let cache_key = (inflight.name.clone(), inflight.kind);

        let (result, cache_ttl) = match msg.response_code() {
            ResponseCode::NoError => {
                let mut answers = Vec::new();
                let mut min_ttl = u32::try_from(self.cfg.hold_valid.as_secs()).unwrap_or(u32::MAX);

                let mut has_records = false;
                for record in msg.answers() {
                    has_records = true;
                    let ttl = record.ttl();
                    if ttl < min_ttl {
                        min_ttl = ttl;
                    }

                    match record.data() {
                        RData::A(ip) => answers.push(Answer::A(ip.0)),
                        RData::AAAA(ip) => answers.push(Answer::Aaaa(ip.0)),
                        RData::SRV(srv) => {
                            answers.push(Answer::Srv {
                                target: srv.target().to_string(),
                                port: srv.port(),
                                priority: srv.priority(),
                                weight: srv.weight(),
                            });
                        }
                        _ => {}
                    }
                }

                if !has_records && answers.is_empty() {
                    // NODATA is often treated like NXDOMAIN or just empty answers
                    (Err(DnsError::NxDomain), self.cfg.hold_nx)
                } else {
                    (Ok(answers), Duration::from_secs(u64::from(min_ttl)))
                }
            }
            ResponseCode::NXDomain => (Err(DnsError::NxDomain), self.cfg.hold_nx),
            ResponseCode::Refused => (Err(DnsError::Refused), self.cfg.hold_refused),
            ResponseCode::ServFail => (Err(DnsError::ServFail), self.cfg.hold_other),
            _ => (Err(DnsError::Other), self.cfg.hold_other),
        };

        self.cache.insert(cache_key, CacheEntry {
            result: result.clone(),
            expires_at: now + cache_ttl,
        });

        self.results.push_back((qid, result));
        self.in_flight.remove(idx);
    }

    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        let mut min_t = None;
        for inflight in &self.in_flight {
            let t = inflight.next_transmit.min(inflight.deadline);
            min_t = Some(min_t.map_or(t, |m: Instant| m.min(t)));
        }
        min_t
    }

    pub fn poll_result(&mut self) -> Option<(QueryId, Result<Vec<Answer>, DnsError>)> {
        // We also need to check for timeouts in in_flight
        // Wait, if an inflight query runs out of retries, it should time out.
        // We should do that in poll_transmit or a separate method.
        self.results.pop_front()
    }
}
