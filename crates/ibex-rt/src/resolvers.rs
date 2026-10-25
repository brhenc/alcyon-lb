// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Run-time resolution of the servers whose address is a name and that name a `resolvers`
//! section (T484, `docs/design/dns-2026-10-25.md` §2.1-2.6): `HAProxy`'s `process_resolvers`,
//! `resolv_process_responses`, `snr_resolution_cb`, `snr_resolution_error_cb`,
//! `snr_set_srv_down` and `resolv_get_ip_from_response` (`src/resolvers.c`, `src/server.c`).
//!
//! One [`Section`] per `resolvers` section that a server uses, a `Kind::Resolver` task on worker
//! 0, the worker that runs the health checks it changes (`HAProxy` spreads the sections over its
//! threads; Ibex's checks all live on worker 0, and a section on another worker would have to
//! ask worker 0 for every state change). One connected UDP socket per nameserver: the kernel
//! picks the source port and drops datagrams from any other source (`dns.c:62-130`). The
//! sans-IO `ibex_dns::Resolver` owns the ids, retries and validation; this module owns the
//! schedule (`timeout resolve`), the `hold` timers and what an answer does to a server.
//!
//! Nothing here runs on the request path. What other workers read: the server's address in
//! `Proxy::servers` (the seqlock `set server addr` writes), its state in
//! `Proxy::server_statuses`, and `SRV_ADMF_RMAINT` in `Proxy::server_rmaint`.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use ibex_config::ast::ResolveOpts;
use ibex_config::LogLevel;
use ibex_dns::{Answer, DnsError, Families, Family, Protocol, QueryId, Question, Rdata, Requester};

use crate::check::{ServerCheckState, ServerStatus, DRAIN_DOWN};
use crate::engine::Proxy;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

ibex_alloc::declare_pool!(
    /// `show pools` `resolution`: one per name and query type a `resolvers` section resolves
    /// (`HAProxy`'s `resolv_resolution_pool`). Taken while the configuration starts, never
    /// given back: their number is the configuration's.
    static RESOLUTION_POOL: Pool<Box<Resolution>> = ibex_alloc::PoolSpec::new("resolution");
);

impl ibex_alloc::Poolable for Box<Resolution> {
    fn footprint(&self) -> usize {
        std::mem::size_of::<Resolution>()
            + self.items.capacity() * std::mem::size_of::<AnswerItem>()
            + self.reqs.capacity() * std::mem::size_of::<Req>()
    }

    fn reset(&mut self, _wipe: bool) {
        self.items.clear();
        self.reqs.clear();
    }

    fn try_new() -> Option<Self> {
        None
    }
}

thread_local! {
    /// A check on this thread ended in a layer-4 timeout since the last look.
    static L4_TIMEOUT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A check ended in a layer-4 timeout (`crate::check`): its server's resolution may be due.
pub fn note_l4_timeout() {
    L4_TIMEOUT.set(true);
}

/// Whether a check ended in a layer-4 timeout since the last call.
pub fn take_l4_timeout() -> bool {
    L4_TIMEOUT.replace(false)
}

/// Lists the pool in `show pools` from the start.
pub fn register_pools() {
    RESOLUTION_POOL.register();
}

/// Why a server went into `SRV_ADMF_RMAINT` (`srv_adm_st_chg_cause`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cause {
    NoIp,
    Nx,
    Timeout,
    Refused,
    Unspec,
}

impl Cause {
    fn text(self) -> &'static str {
        match self {
            // HAProxy's string, with its trailing space (A.t12).
            Cause::NoIp => "No IP for server ",
            Cause::Nx => "DNS NX status",
            Cause::Timeout => "DNS timeout status",
            Cause::Refused => "DNS refused status",
            Cause::Unspec => "unspecified DNS error",
        }
    }
}

/// A resolution's last status (`RSLV_STATUS_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    None,
    Valid,
    Error(Cause),
}

/// One address of the last answers (`struct resolv_answer_item`).
#[derive(Debug, Clone, Copy)]
struct AnswerItem {
    /// `XXH32(rdata, type)`: `HAProxy` keeps the items in a tree on it, which is the order
    /// [`pick`] reads them in.
    key: u32,
    ip: IpAddr,
    last_seen: Instant,
}

/// The tree key of an answer item (`resolv_validate_dns_response`).
fn item_key(ip: IpAddr) -> u32 {
    match ip {
        IpAddr::V4(a) => ibex_sample::hash::hash_xxh32(&a.octets(), u32::from(TYPE_A)),
        IpAddr::V6(a) => ibex_sample::hash::hash_xxh32(&a.octets(), u32::from(TYPE_AAAA)),
    }
}

/// A server that asks for a resolution (`struct resolv_requester`).
#[derive(Debug)]
struct Req {
    proxy: u32,
    server: u32,
    opts: ResolveOpts,
    /// The answer item the server took its address from (`srv->ip_rec_item`).
    attached: Option<IpAddr>,
    /// The admin state to give back when the server leaves `SRV_ADMF_RMAINT`: what the
    /// operator or the configuration set (`Maint` for `disabled`, `Drain`), else `Up`.
    saved: ServerStatus,
}

/// One name and query type (`struct resolv_resolution`).
#[derive(Debug)]
pub struct Resolution {
    /// The name as written on the first server line that asked for it.
    name: Box<str>,
    /// The type the resolution prefers (`prefered_query_type`), fixed when it is made.
    prefer: u16,
    reqs: Vec<Req>,
    items: Vec<AnswerItem>,
    /// Where the next pick starts among the items (`r_res->next`), so that servers sharing a
    /// name spread over its addresses.
    cursor: usize,
    in_flight: Option<QueryId>,
    /// When the next resolution starts (`last_resolution + timeout resolve`).
    next_at: Instant,
    last_valid: Option<Instant>,
    /// When the last resolution ended (`last_resolution`).
    last_resolution: Option<Instant>,
    status: Status,
}

struct Nameserver {
    name: Box<str>,
    addr: SocketAddr,
    sock: UdpSocket,
}

/// The holds and timers of a section that this module reads (the crate reads the rest).
struct Holds {
    timeout_resolve: Duration,
    valid: Duration,
    nx: Duration,
    other: Duration,
    refused: Duration,
    timeout: Duration,
    obsolete: Duration,
}

/// One `resolvers` section at run time.
pub struct Section {
    name: Box<str>,
    pub task: ibex_sched::task::TaskRef,
    nameservers: Vec<Nameserver>,
    dns: ibex_dns::Resolver,
    holds: Holds,
    resolutions: Vec<Box<Resolution>>,
    /// The read buffer, the task's own (64 KiB: a datagram never needs more).
    buf: Box<[u8]>,
}

/// What a step reports to the engine: a line to log on the server's proxy, at a level, also
/// printed on stderr as `HAProxy`'s `ha_warning` does.
pub type LogFn<'a> = dyn FnMut(usize, LogLevel, &str) + 'a;

thread_local! {
    /// `is_inet6_reachable`: the result and when it was taken, kept 30 s
    /// (`INET6_CONNECTIVITY_CACHE_TIME`).
    static INET6: std::cell::Cell<Option<(Instant, bool)>> = const { std::cell::Cell::new(None) };
}

/// Whether the host has a route to IPv6 (`is_inet6_reachable`, `sock_inet.c:498`): a UDP
/// `connect` to `[2001::]:53`, which sends nothing, re-done every 30 s.
fn inet6_reachable(now: Instant) -> bool {
    if let Some((at, v)) = INET6.get() {
        if now.duration_since(at) < Duration::from_secs(30) {
            return v;
        }
    }
    let v = UdpSocket::bind("[::]:0").and_then(|s| s.connect("[2001::]:53")).is_ok();
    INET6.set(Some((now, v)));
    v
}

/// The families resolvers accept: `dns-accept-family auto`, `HAProxy`'s default
/// (`resolv_active_families`): IPv4, and IPv6 while the host has a route to it.
fn active_families(now: Instant) -> Families {
    Families { ipv4: true, ipv6: inet6_reachable(now) }
}

/// Builds the sections the servers of `proxies` name, in `config` order, each with a task and
/// its sockets registered. Only worker 0 calls this.
///
/// # Errors
/// A nameserver socket that cannot be made.
pub fn build(
    config: &ibex_config::Config,
    proxies: &[Proxy],
    scheduler: &mut ibex_sched::Scheduler,
    fdtab: &mut crate::fdtab::FdTab,
    poller: &crate::poller::Poller,
    now: ibex_sched::Tick,
) -> io::Result<Vec<Section>> {
    let t0 = Instant::now();
    let families = active_families(t0);
    let mut out: Vec<Section> = Vec::new();
    // `config.listens` then `config.backends`, enabled ones, are `proxies` in order
    // (`build_shared_state`); the frontends have no servers.
    let sections = config
        .listens
        .iter()
        .filter(|l| !l.disabled)
        .map(|l| (&l.servers, &l.server_extras))
        .chain(config.backends.iter().filter(|b| !b.disabled).map(|b| (&b.servers, &b.server_extras)));
    let mut by_key: HashMap<(usize, Box<str>, u16), (usize, usize)> = HashMap::new();
    for (p_idx, (servers, extras)) in sections.enumerate() {
        let Some(px) = proxies.get(p_idx) else { continue };
        for n in &extras.names {
            let Some(sec_name) = n.resolvers.as_deref() else { continue };
            let Some(cfg) = config.resolvers.iter().find(|r| r.name == sec_name) else { continue };
            let s_idx = n.index as usize;
            if servers.get(s_idx).is_none() {
                continue;
            }
            let sec_idx = match out.iter().position(|s| *s.name == *sec_name) {
                Some(i) => i,
                None => {
                    out.push(Section::new(cfg, usize_to_u32(out.len()), scheduler, fdtab, poller, now)?);
                    out.len() - 1
                }
            };
            // `resolv_link_resolution`: the type asked first, fixed now (A.t18).
            let prefer = if !families.ipv6 || n.resolve.prefer_ipv4 { TYPE_A } else { TYPE_AAAA };
            let key = (sec_idx, n.fqdn.to_ascii_lowercase().into_boxed_str(), prefer);
            let saved = if px.server_cmaint(s_idx) { ServerStatus::Maint } else { ServerStatus::Up };
            let req = Req { proxy: usize_to_u32(p_idx), server: n.index, opts: n.resolve.clone(), attached: None, saved };
            let sec = &mut out[sec_idx];
            if let Some(&(_, r)) = by_key.get(&key) {
                sec.resolutions[r].reqs.push(req);
            } else {
                let mut res = RESOLUTION_POOL
                    .take_counted(|| {
                        Some(Box::new(Resolution {
                            name: Box::from(""),
                            prefer,
                            reqs: Vec::new(),
                            items: Vec::new(),
                            cursor: 0,
                            in_flight: None,
                            next_at: t0,
                            last_valid: None,
                            last_resolution: None,
                            status: Status::None,
                        }))
                    })
                    .expect("a resolution");
                res.name = n.fqdn.clone();
                res.prefer = prefer;
                res.reqs.push(req);
                by_key.insert(key, (sec_idx, sec.resolutions.len()));
                sec.resolutions.push(res);
            }
        }
    }
    Ok(out)
}

fn usize_to_u32(v: usize) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

impl Section {
    fn new(
        cfg: &ibex_config::ast::ResolversSection,
        idx: u32,
        scheduler: &mut ibex_sched::Scheduler,
        fdtab: &mut crate::fdtab::FdTab,
        poller: &crate::poller::Poller,
        now: ibex_sched::Tick,
    ) -> io::Result<Self> {
        let mut nameservers = Vec::with_capacity(cfg.nameservers.len());
        for ns in &cfg.nameservers {
            let local: SocketAddr = if ns.addr.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { "[::]:0".parse().expect("addr") };
            let sock = UdpSocket::bind(local)?;
            sock.connect(ns.addr)?;
            sock.set_nonblocking(true)?;
            let fd = sock.as_raw_fd();
            fdtab.insert(fd, crate::fdtab::FdState::Resolver { section: idx }, crate::fdtab::Interest::READ);
            poller.add(std::os::fd::AsFd::as_fd(&sock), u64::try_from(fd).unwrap_or(0), true, false)?;
            nameservers.push(Nameserver { name: ns.name.as_str().into(), addr: ns.addr, sock });
        }
        let h = &cfg.hold;
        let dns = ibex_dns::Resolver::new(ibex_dns::ResolverConfig {
            nameservers: nameservers.iter().map(|n| n.addr).collect(),
            resolve_retries: usize::try_from(cfg.resolve_retries.max(1)).unwrap_or(1),
            timeout_resolve: cfg.timeout_resolve,
            timeout_retry: cfg.timeout_retry,
            hold_valid: h.valid,
            hold_nx: h.nx,
            hold_other: h.other,
            hold_refused: h.refused,
            hold_timeout: h.timeout,
            hold_obsolete: h.obsolete,
            accepted_payload_size: cfg.accepted_payload_size,
            // The crate's ids: SipHash under the OS-seeded keys of the standard library, not
            // the load balancer's xorshift, whose seed is the clock.
            // No TCP until T488: a truncated answer is an error (`Other`).
            tcp_fallback: false,
            ..ibex_dns::ResolverConfig::default()
        });
        let task = scheduler.create(ibex_sched::task::WorkKind::new(ibex_sched::task::Kind::Resolver, idx)).ok_or_else(|| io::Error::other("no task for a resolvers section"))?;
        scheduler.queue_timer(task, now.add(1));
        Ok(Self {
            name: cfg.name.as_str().into(),
            task,
            nameservers,
            dns,
            holds: Holds {
                timeout_resolve: cfg.timeout_resolve,
                valid: h.valid,
                nx: h.nx,
                other: h.other,
                refused: h.refused,
                timeout: h.timeout,
                obsolete: h.obsolete,
            },
            resolutions: Vec::new(),
            buf: vec![0u8; 65_536].into_boxed_slice(),
        })
    }

    /// Runs the section: reads every datagram, starts the resolutions that are due, sends,
    /// and applies every result to its servers. Returns when it wants to run again.
    pub fn step(&mut self, proxies: &[Proxy], checks: &mut [ServerCheckState], log: &mut LogFn<'_>) -> Duration {
        let now = Instant::now();
        // Replies: every nameserver's socket until it is empty.
        for ns_idx in 0..self.nameservers.len() {
            loop {
                let n = match self.nameservers[ns_idx].sock.recv(&mut self.buf) {
                    Ok(n) => n,
                    // An ICMP unreachable is reported on the next read: the nameserver is
                    // silent, which the retry timer turns into a timeout (A.t7).
                    Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => continue,
                    Err(_) => break,
                };
                let from = self.nameservers[ns_idx].addr;
                let _counter = self.dns.handle_response(now, from, Protocol::Udp, &self.buf[..n]);
                self.drain_results(now, Some(ns_idx), proxies, checks, log);
            }
        }
        // Resolutions due: one query each, to every nameserver (A.t2).
        let families = active_families(now);
        for r in &mut self.resolutions {
            if r.in_flight.is_none() && now >= r.next_at {
                let prefer = if r.prefer == TYPE_A { Family::Ipv4 } else { Family::Ipv6 };
                let accept = Families { ipv4: families.ipv4 || prefer == Family::Ipv4, ipv6: families.ipv6 || prefer == Family::Ipv6 };
                match self.dns.query(now, &r.name, Question::Addr { accept, prefer }, Requester::Server) {
                    Ok(q) => r.in_flight = Some(q),
                    // A name the parser let through and the crate refuses, or no id free:
                    // tried again at the next period.
                    Err(_) => r.next_at = now + self.holds.timeout_resolve,
                }
            }
        }
        self.drain_results(now, None, proxies, checks, log);
        // Sends, and the retry timer (which may end resolutions in a timeout).
        while let Some((to, proto, bytes)) = self.dns.poll_transmit(now) {
            if proto == Protocol::Udp {
                if let Some(ns) = self.nameservers.iter().find(|n| n.addr == to) {
                    // A failed send is `snd_error` (T485); the retry timer sends again.
                    let _ = ns.sock.send(&bytes);
                }
            }
        }
        self.drain_results(now, None, proxies, checks, log);
        let next = self
            .resolutions
            .iter()
            .filter(|r| r.in_flight.is_none())
            .map(|r| r.next_at)
            .chain(self.dns.poll_timeout())
            .min()
            .unwrap_or(now + self.holds.timeout_resolve);
        next.saturating_duration_since(Instant::now())
    }

    /// `resolv_trigger_resolution` for server `s` of proxy `p`, whose check ended in a layer-4
    /// timeout (`check.c:950`): its resolution starts now unless one runs or the last valid
    /// one is younger than `hold valid` (A.t16). Whether the section must run.
    pub fn trigger(&mut self, p: usize, s: usize) -> bool {
        let now = Instant::now();
        let mut due = false;
        for r in &mut self.resolutions {
            if r.in_flight.is_some() || !r.reqs.iter().any(|q| q.proxy as usize == p && q.server as usize == s) {
                continue;
            }
            if r.status != Status::Valid || r.last_resolution.is_none_or(|t| now >= t + self.holds.valid) {
                r.next_at = now;
                due = true;
            }
        }
        due
    }

    /// Applies the results the crate has. A valid answer read from `ns` names it in the log.
    fn drain_results(&mut self, now: Instant, ns: Option<usize>, proxies: &[Proxy], checks: &mut [ServerCheckState], log: &mut LogFn<'_>) {
        while let Some((qid, res)) = self.dns.poll_result() {
            let Some(r) = self.resolutions.iter_mut().find(|r| r.in_flight == Some(qid)) else { continue };
            r.in_flight = None;
            r.next_at = now + self.holds.timeout_resolve;
            r.last_resolution = Some(now);
            match res {
                Ok(answers) => {
                    let by = ns.map(|i| format!("{}/{}", self.name, self.nameservers[i].name));
                    on_valid(r, &answers, by.as_deref(), &self.holds, now, proxies, checks, log);
                }
                Err(e) => on_error(r, &e, &self.holds, now, proxies, checks, log),
            }
        }
    }
}

/// `resolv_process_responses`, valid: the items are refreshed and every requester runs
/// `snr_resolution_cb`, the first one naming the nameserver, the others `DNS cache`.
#[allow(clippy::too_many_arguments)]
fn on_valid(
    r: &mut Resolution,
    answers: &[Answer],
    by: Option<&str>,
    holds: &Holds,
    now: Instant,
    proxies: &[Proxy],
    checks: &mut [ServerCheckState],
    log: &mut LogFn<'_>,
) {
    r.status = Status::Valid;
    r.last_valid = Some(now);
    refresh_items(r, answers, active_families(now), holds.obsolete, now);
    let mut by = by;
    for k in 0..r.reqs.len() {
        server_answer(r, k, by.take().unwrap_or("DNS cache"), holds, now, proxies, checks, log);
    }
}

/// The answer's addresses into the items (in key order, kept when already there), then the
/// items not seen for `hold obsolete` go, and the servers on them lose them.
fn refresh_items(r: &mut Resolution, answers: &[Answer], fam: Families, obsolete: Duration, now: Instant) {
    for a in answers {
        let ip: IpAddr = match a.rdata {
            Rdata::A(v4) if fam.ipv4 => v4.into(),
            Rdata::Aaaa(v6) if fam.ipv6 => v6.into(),
            _ => continue,
        };
        match r.items.iter_mut().find(|i| i.ip == ip) {
            Some(i) => i.last_seen = now,
            None => {
                let key = item_key(ip);
                let at = r.items.partition_point(|i| i.key <= key);
                r.items.insert(at, AnswerItem { key, ip, last_seen: now });
            }
        }
    }
    r.items.retain(|i| i.last_seen + obsolete >= now);
    let items = &r.items;
    for req in &mut r.reqs {
        if req.attached.is_some_and(|ip| !items.iter().any(|i| i.ip == ip)) {
            req.attached = None;
        }
    }
}

/// What [`pick`] found (`RSLV_UPD_*`).
#[derive(Debug, PartialEq, Eq)]
enum Pick {
    /// The server keeps its address.
    No,
    /// The server takes this one.
    New(IpAddr),
    NoIp,
}

/// `snr_resolution_cb` for requester `k`.
#[allow(clippy::too_many_arguments)]
fn server_answer(r: &mut Resolution, k: usize, by: &str, holds: &Holds, now: Instant, proxies: &[Proxy], checks: &mut [ServerCheckState], log: &mut LogFn<'_>) {
    let (p, s) = (r.reqs[k].proxy as usize, r.reqs[k].server as usize);
    let Some(px) = proxies.get(p) else { return };
    let cur = px.servers.get(s).map(|a| a.ip()).filter(|ip| !ip.is_unspecified());
    match pick(r, k, cur, active_families(now)) {
        Pick::No => {}
        Pick::New(ip) => {
            // `srv_update_addr` (the line where an answer becomes the server's address).
            let old = px.servers.get(s).unwrap_or_else(|| SocketAddr::new(ip, 0));
            px.servers.set(s, SocketAddr::new(ip, old.port()));
            let from = cur.map_or_else(|| "(none)".to_string(), |c| c.to_string());
            let srv = &px.server_ids[s];
            log(p, LogLevel::Notice, &format!("{}/{srv}: IP changed from '{from}' to '{ip}' by '{by}'.", px.name));
            if px.server_rmaint(s) {
                leave_rmaint(&r.reqs[k], &r.name, proxies, checks, log);
            }
        }
        Pick::NoIp => {
            if set_srv_down(r, k, holds, now, proxies, checks, log) {
                clear_addr(px, s);
            }
        }
    }
}

/// `resolv_get_ip_from_response`: the score of each item for requester `k` (8 the preferred
/// family, 4 a `resolve-net` network, 2 no other server of the proxy on it, 1 the current
/// address) picks its address (design F7).
fn pick(r: &mut Resolution, k: usize, cur: Option<IpAddr>, fam: Families) -> Pick {
    let req = &r.reqs[k];
    // The server is on an item still in the answer.
    if req.attached.is_some_and(|ip| r.items.iter().any(|i| i.ip == ip)) {
        return Pick::No;
    }
    let n = r.items.len();
    if n == 0 {
        return Pick::NoIp;
    }
    let prefer_v4 = req.opts.prefer_ipv4;
    let (mut best4, mut best6, mut found) = (None, None, None);
    let mut cur_found = false;
    let mut max = -1i32;
    let start = r.cursor % n;
    'items: for step in 0..n {
        let idx = (start + step) % n;
        let ip = r.items[idx].ip;
        if (ip.is_ipv4() && !fam.ipv4) || (ip.is_ipv6() && !fam.ipv6) {
            continue;
        }
        let mut score = 0;
        if ip.is_ipv4() == prefer_v4 {
            score += 8;
        }
        for &(net, bits) in &req.opts.nets {
            // `HAProxy` skips the item when a network of the other family comes first.
            if net.is_ipv4() != ip.is_ipv4() {
                continue 'items;
            }
            if in_net(ip, net, bits) {
                score += 4;
                break;
            }
        }
        let used = r.reqs.iter().enumerate().any(|(j, o)| j != k && o.proxy == req.proxy && o.attached == Some(ip));
        if used {
            if !req.opts.allow_dup_ip {
                continue;
            }
        } else {
            score += 2;
        }
        let sel = cur == Some(ip);
        if sel {
            score += 1;
        }
        if score > max {
            r.cursor = (idx + 1) % n;
            if ip.is_ipv4() { best4 = Some(ip) } else { best6 = Some(ip) }
            found = Some(ip);
            cur_found = sel;
            if score == 15 {
                r.reqs[k].attached = Some(ip);
                return Pick::No;
            }
            max = score;
        }
    }
    let chosen = if prefer_v4 { best4.or(best6) } else { best6.or(best4) };
    let Some(chosen) = chosen else { return Pick::NoIp };
    r.reqs[k].attached = found;
    if cur_found { Pick::No } else { Pick::New(chosen) }
}

fn in_net(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let m = if bits == 0 { 0 } else { u32::MAX << (32 - u32::from(bits.min(32))) };
            u32::from(a) & m == u32::from(b) & m
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let m = if bits == 0 { 0 } else { u128::MAX << (128 - u32::from(bits.min(128))) };
            u128::from(a) & m == u128::from(b) & m
        }
        _ => false,
    }
}

/// `resolv_process_responses` / `process_resolvers`, an error: each requester runs
/// `snr_resolution_error_cb`; the items go unless a server keeps its address within its hold.
#[allow(clippy::too_many_arguments)]
fn on_error(r: &mut Resolution, e: &DnsError, holds: &Holds, now: Instant, proxies: &[Proxy], checks: &mut [ServerCheckState], log: &mut LogFn<'_>) {
    r.status = Status::Error(match e {
        DnsError::NxDomain => Cause::Nx,
        DnsError::Refused => Cause::Refused,
        DnsError::Timeout => Cause::Timeout,
        DnsError::Other | DnsError::Invalid => Cause::Unspec,
    });
    let mut keep = false;
    for k in 0..r.reqs.len() {
        if set_srv_down(r, k, holds, now, proxies, checks, log) {
            let (p, s) = (r.reqs[k].proxy as usize, r.reqs[k].server as usize);
            if let Some(px) = proxies.get(p) {
                clear_addr(px, s);
            }
            r.reqs[k].attached = None;
        } else {
            keep = true;
        }
    }
    if !keep {
        r.items.clear();
        for req in &mut r.reqs {
            req.attached = None;
        }
    }
}

/// `snr_set_srv_down`: whether requester `k`'s server went into `SRV_ADMF_RMAINT` now (the
/// hold of the status ran out since the last valid answer, or there never was one, F5).
fn set_srv_down(r: &Resolution, k: usize, holds: &Holds, now: Instant, proxies: &[Proxy], checks: &mut [ServerCheckState], log: &mut LogFn<'_>) -> bool {
    let req = &r.reqs[k];
    let (p, s) = (req.proxy as usize, req.server as usize);
    if proxies.get(p).is_none_or(|px| px.server_rmaint(s)) {
        return false;
    }
    let cause = match r.status {
        Status::None => return false,
        Status::Valid => Cause::NoIp,
        Status::Error(c) => {
            let hold = match c {
                Cause::Nx => holds.nx,
                Cause::Timeout => holds.timeout,
                Cause::Refused => holds.refused,
                Cause::NoIp | Cause::Unspec => holds.other,
            };
            if r.last_valid.is_some_and(|lv| now < lv + hold) {
                return false;
            }
            c
        }
    };
    enter_rmaint(req, cause, proxies, checks, log);
    true
}

/// The server's address is gone (`AF_UNSPEC`, `-` in `show servers state`); its port stays.
fn clear_addr(px: &Proxy, s: usize) {
    if let Some(a) = px.servers.get(s) {
        px.servers.set(s, SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), a.port()));
    }
}

fn status_of(px: &Proxy, s: usize) -> u8 {
    px.server_statuses.get(s).map_or(ServerStatus::Up as u8, |a| a.load(std::sync::atomic::Ordering::Relaxed))
}

/// `srv_set_admin_flag(SRV_ADMF_RMAINT)` and its log line (`_srv_update_status_adm`).
fn enter_rmaint(req: &Req, cause: Cause, proxies: &[Proxy], checks: &mut [ServerCheckState], log: &mut LogFn<'_>) {
    let (p, s) = (req.proxy as usize, req.server as usize);
    let px = &proxies[p];
    let before = status_of(px, s);
    px.set_server_rmaint(s, true);
    crate::track::set_admin(proxies, checks, p, s, ServerStatus::Maint);
    let srv = &px.server_ids[s];
    let backup = if px.server_backups.get(s).copied().unwrap_or(false) { "Backup " } else { "" };
    let msg = match ServerStatus::from(before) {
        // Already in maintenance: one more reason, no line.
        ServerStatus::Maint => return,
        ServerStatus::Down => format!("{backup}Server {}/{srv} was DOWN and now enters maintenance ({}).", px.name, cause.text()),
        _ if before == DRAIN_DOWN => format!("{backup}Server {}/{srv} was DOWN and now enters maintenance ({}).", px.name, cause.text()),
        _ => {
            let (act, bck) = usable_servers(px);
            let sess = px.server_actconn.get(s).map_or(0, |a| a.load(std::sync::atomic::Ordering::Relaxed));
            let on_backup = if bck > 0 && act == 0 { " Running on backup." } else { "" };
            format!(
                "{backup}Server {}/{srv} is going DOWN for maintenance ({}). {act} active and {bck} backup servers left.{on_backup} {sess} sessions active, 0 requeued, 0 remaining in queue.",
                px.name,
                cause.text()
            )
        }
    };
    log(p, if before == ServerStatus::Up as u8 || before == ServerStatus::Drain as u8 { LogLevel::Alert } else { LogLevel::Notice }, &msg);
}

/// `srv_act` and `srv_bck`: the servers of `px` that take traffic.
fn usable_servers(px: &Proxy) -> (usize, usize) {
    let mut n = (0, 0);
    for s in 0..px.server_ids.len() {
        if status_of(px, s) == ServerStatus::Up as u8 {
            if px.server_backups.get(s).copied().unwrap_or(false) {
                n.1 += 1;
            } else {
                n.0 += 1;
            }
        }
    }
    n
}

/// `srv_clr_admin_flag(SRV_ADMF_RMAINT)` on a valid answer, and its two lines.
fn leave_rmaint(req: &Req, fqdn: &str, proxies: &[Proxy], checks: &mut [ServerCheckState], log: &mut LogFn<'_>) {
    let (p, s) = (req.proxy as usize, req.server as usize);
    let px = &proxies[p];
    px.set_server_rmaint(s, false);
    crate::track::set_admin(proxies, checks, p, s, req.saved);
    let srv = &px.server_ids[s];
    let backup = if px.server_backups.get(s).copied().unwrap_or(false) { "Backup " } else { "" };
    let after = status_of(px, s);
    let msg = if req.saved == ServerStatus::Maint {
        format!("{backup}Server {}/{srv} ('{fqdn}') resolves again but remains in maintenance.", px.name)
    } else {
        let op = if after == ServerStatus::Down as u8 || after == DRAIN_DOWN { "DOWN" } else { "UP" };
        let adm = if req.saved == ServerStatus::Drain { "DRAIN" } else { "READY" };
        format!("{backup}Server {}/{srv} ('{fqdn}') is {op}/{adm} (resolves again).", px.name)
    };
    log(p, LogLevel::Notice, &msg);
    log(p, LogLevel::Notice, &format!("Server {}/{srv} administratively READY thanks to valid DNS answer.", px.name));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(ips: &[&str], reqs: Vec<Req>) -> Resolution {
        let now = Instant::now();
        Resolution {
            name: "x.test".into(),
            prefer: TYPE_A,
            reqs,
            items: ips.iter().map(|i| AnswerItem { key: 0, ip: i.parse().expect("ip"), last_seen: now }).collect(),
            cursor: 0,
            in_flight: None,
            next_at: now,
            last_valid: None,
            last_resolution: None,
            status: Status::None,
        }
    }

    fn req(proxy: u32, server: u32, opts: ResolveOpts) -> Req {
        Req { proxy, server, opts, attached: None, saved: ServerStatus::Up }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    /// A.t18b, A.t8b: with both families accepted the default preference (IPv6) wins; with
    /// `resolve-prefer ipv4`, IPv4. (`dns-accept-family ipv4,ipv6` is T489's keyword.)
    #[test]
    fn both_families_follow_resolve_prefer() {
        let mut r = res(&["10.0.0.1", "2001:db8::1"], vec![req(0, 0, ResolveOpts::default())]);
        assert_eq!(pick(&mut r, 0, None, Families::BOTH), Pick::New(ip("2001:db8::1")));
        let v4 = ResolveOpts { prefer_ipv4: true, ..ResolveOpts::default() };
        let mut r = res(&["2001:db8::1", "10.0.0.1"], vec![req(0, 0, v4)]);
        assert_eq!(pick(&mut r, 0, None, Families::BOTH), Pick::New(ip("10.0.0.1")));
        // IPv6 not accepted (auto, no route): the AAAA item is not a candidate.
        let mut r = res(&["2001:db8::6"], vec![req(0, 0, ResolveOpts::default())]);
        assert_eq!(pick(&mut r, 0, None, Families::IPV4), Pick::NoIp);
    }

    /// F7: a network of the other family listed first makes `HAProxy` skip the item; a
    /// dotted or short prefix matches as `in_net_ipv4` does.
    #[test]
    fn resolve_net_scores() {
        let nets = |n: &[(&str, u8)]| ResolveOpts { nets: n.iter().map(|(a, b)| (ip(a), *b)).collect(), prefer_ipv4: true, ..ResolveOpts::default() };
        let mut r = res(&["10.0.0.1", "10.0.1.2"], vec![req(0, 0, nets(&[("10.0.1.0", 24)]))]);
        assert_eq!(pick(&mut r, 0, None, Families::BOTH), Pick::New(ip("10.0.1.2")));
        let mut r = res(&["10.0.0.1"], vec![req(0, 0, nets(&[("2001:db8::", 32), ("10.0.0.0", 8)]))]);
        assert_eq!(pick(&mut r, 0, None, Families::BOTH), Pick::NoIp);
        assert!(in_net(ip("2001:db8::5"), ip("2001:db8::"), 32));
        assert!(!in_net(ip("2001:db9::5"), ip("2001:db8::"), 32));
        assert!(in_net(ip("1.2.3.4"), ip("9.9.9.9"), 0));
        assert!(in_net(ip("::1"), ip("::2"), 0));
        assert!(!in_net(ip("::1"), ip("1.2.3.4"), 0));
    }

    /// The battery's `oversize-4000` (4000 A records 10.77.x.y): `HAProxy` reads the items in
    /// `XXH32` order and gives the server 10.77.8.138, not the first record.
    #[test]
    fn items_are_read_in_haproxys_tree_order() {
        let answers: Vec<Answer> = (0..4000u32)
            .map(|i| Answer { rdata: Rdata::A(Ipv4Addr::new(10, 77, u8::try_from(i / 250).unwrap(), u8::try_from(i % 250 + 1).unwrap())), ttl: 1 })
            .collect();
        let mut r = res(&[], vec![req(0, 0, ResolveOpts::default())]);
        let now = Instant::now();
        refresh_items(&mut r, &answers, Families::IPV4, Duration::ZERO, now);
        assert_eq!(r.items.len(), 4000);
        assert_eq!(pick(&mut r, 0, None, Families::IPV4), Pick::New(ip("10.77.8.138")));
        // Seen again: kept; gone from the next answer: dropped, and the server with it.
        refresh_items(&mut r, &answers[..1], Families::IPV4, Duration::ZERO, now + Duration::from_millis(1));
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.reqs[0].attached, None);
        // An AAAA record while IPv6 is not accepted is not an item.
        let v6 = [Answer { rdata: Rdata::Aaaa("2001:db8::1".parse().unwrap()), ttl: 1 }];
        refresh_items(&mut r, &v6, Families::IPV4, Duration::from_secs(9), now);
        assert_eq!(r.items.len(), 1);
        refresh_items(&mut r, &v6, Families::BOTH, Duration::from_secs(9), now);
        assert_eq!(r.items.len(), 2);
    }

    /// A server already on an item still in the answer keeps it; a second server of the
    /// proxy takes another one (the cursor spreads them).
    #[test]
    fn servers_spread_over_the_items() {
        let o = ResolveOpts { prefer_ipv4: true, ..ResolveOpts::default() };
        let mut r = res(&["10.0.0.1", "10.0.0.2"], vec![req(0, 0, o.clone()), req(0, 1, o)]);
        assert_eq!(pick(&mut r, 0, None, Families::IPV4), Pick::New(ip("10.0.0.1")));
        assert_eq!(pick(&mut r, 1, None, Families::IPV4), Pick::New(ip("10.0.0.2")));
        assert_eq!(pick(&mut r, 0, Some(ip("10.0.0.1")), Families::IPV4), Pick::No);
    }
}
