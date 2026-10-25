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
#[must_use]
pub fn take_l4_timeout() -> bool {
    L4_TIMEOUT.replace(false)
}

/// Lists the pool in `show pools` from the start.
pub fn register_pools() {
    RESOLUTION_POOL.register();
}

/// The per-nameserver counters of `show resolvers`, in its order, with the name and description
/// `haproxy_resolver_*` gives each (`resolv_stats`, `resolvers.c:104`).
pub const COUNTERS: [(&str, &str, &str); 16] = [
    ("sent", "sent", "Sent"),
    ("snd_error", "send_error", "Send error"),
    ("valid", "valid", "Valid"),
    ("update", "update", "Update"),
    ("cname", "cname", "CNAME"),
    ("cname_error", "cname_error", "CNAME error"),
    ("any_err", "any_err", "Any errors"),
    ("nx", "nx", "NX"),
    ("timeout", "timeout", "Timeout"),
    ("refused", "refused", "Refused"),
    ("other", "other", "Other"),
    ("invalid", "invalid", "Invalid"),
    ("too_big", "too_big", "Too big"),
    ("truncated", "truncated", "Truncated"),
    ("tcp_fallback", "tcp_fallback", "TCP fallback"),
    ("outdated", "outdated", "Outdated"),
];
const C_SENT: usize = 0;
const C_SND_ERROR: usize = 1;
const C_VALID: usize = 2;
const C_UPDATE: usize = 3;
const C_CNAME_ERROR: usize = 5;
const C_ANY_ERR: usize = 6;
const C_NX: usize = 7;
const C_REFUSED: usize = 9;
const C_OTHER: usize = 10;
const C_INVALID: usize = 11;
const C_TOO_BIG: usize = 12;
const C_TRUNCATED: usize = 13;
const C_OUTDATED: usize = 15;
// `cname` and `timeout` are never counted by HAProxy either (A.t5: `timeout 0` after a timeout);
// `tcp_fallback` waits for T488.

/// One `resolvers` section's nameservers and their counters, as `show resolvers` and the
/// exporter read them.
pub struct SectionStats {
    pub name: Box<str>,
    pub nameservers: Vec<(Box<str>, [u64; 16])>,
}

/// Every configured section (also one no server uses), in configuration order. Written only by
/// the worker that owns a section, when its counters changed (never on the request path); read
/// by the CLI and the exporter on any worker.
static STATS: std::sync::Mutex<Vec<SectionStats>> = std::sync::Mutex::new(Vec::new());

/// Runs `f` on the sections' counters.
pub fn with_stats<R>(f: impl FnOnce(&[SectionStats]) -> R) -> R {
    f(&STATS.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
}

/// `show resolvers [<id>]` (`cli_io_handler_dump_resolvers_to_buffer`): the text, one
/// `Resolvers section` block each, or the error `HAProxy` gives for an unknown id. `HAProxy`
/// always has a `default` section; Ibex does not (design §2.8), so with no section it says what
/// `HAProxy` says for an empty list.
#[must_use]
pub fn show(id: Option<&str>) -> String {
    use std::fmt::Write as _;
    with_stats(|all| {
        if let Some(id) = id {
            if !all.iter().any(|s| &*s.name == id) {
                return "Can't find that resolvers section\n".to_string();
            }
        }
        if all.is_empty() {
            return "No resolvers found\n".to_string();
        }
        let mut out = String::new();
        for s in all.iter().filter(|s| id.is_none_or(|i| i == &*s.name)) {
            let _ = writeln!(out, "Resolvers section {}", s.name);
            for (ns, c) in &s.nameservers {
                let _ = writeln!(out, " nameserver {ns}:");
                for ((name, _, _), v) in COUNTERS.iter().zip(c) {
                    let _ = writeln!(out, "  {:<13} {v}", format!("{name}:"));
                }
            }
        }
        out
    })
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
#[derive(Debug, Clone)]
struct AnswerItem {
    /// `XXH32(rdata, type)`: `HAProxy` keeps the items in a tree on it, which is the order
    /// [`pick`] reads them in.
    key: u32,
    ip: IpAddr,
    last_seen: Instant,
    /// How many servers of each proxy took their address from it (`attached_servers`), as
    /// (proxy, count): what makes the "+2 not used by another server" of [`pick`] one look.
    users: Vec<(u32, u32)>,
}

impl AnswerItem {
    fn users_in(&self, proxy: u32) -> u32 {
        self.users.iter().find(|u| u.0 == proxy).map_or(0, |u| u.1)
    }
}

/// The index of the item for `ip`: they are sorted by key.
fn find_item(items: &[AnswerItem], ip: IpAddr) -> Option<usize> {
    let key = item_key(ip);
    let from = items.partition_point(|i| i.key < key);
    items[from..].iter().take_while(|i| i.key == key).position(|i| i.ip == ip).map(|j| from + j)
}

/// Moves requester `k` onto the item for `to` (`LIST_DEL_INIT` / `LIST_APPEND` on
/// `ip_rec_item`), keeping the items' counts.
fn set_attached(r: &mut Resolution, k: usize, to: Option<IpAddr>) {
    let (old, px) = (r.reqs[k].attached, r.reqs[k].proxy);
    if old == to {
        return;
    }
    if let Some(i) = old.and_then(|ip| find_item(&r.items, ip)) {
        if let Some(u) = r.items[i].users.iter_mut().find(|u| u.0 == px) {
            u.1 = u.1.saturating_sub(1);
        }
    }
    if let Some(i) = to.and_then(|ip| find_item(&r.items, ip)) {
        match r.items[i].users.iter_mut().find(|u| u.0 == px) {
            Some(u) => u.1 += 1,
            None => r.items[i].users.push((px, 1)),
        }
    }
    r.reqs[k].attached = to;
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
    /// When the next resolution starts (`ended_at + timeout resolve`).
    next_at: Instant,
    last_valid: Option<Instant>,
    /// When the last resolution ended (`last_resolution`).
    ended_at: Option<Instant>,
    status: Status,
}

struct Nameserver {
    name: Box<str>,
    addr: SocketAddr,
    sock: UdpSocket,
    /// `ns->counters`, in the order of [`COUNTERS`]; this worker alone writes them.
    counts: [u64; 16],
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
    // Boxed: the pool's objects (`RESOLUTION_POOL`).
    #[allow(clippy::vec_box)]
    resolutions: Vec<Box<Resolution>>,
    /// The read buffer, the task's own (64 KiB: a datagram never needs more).
    buf: Box<[u8]>,
    /// Where this section's counters are in [`STATS`] (the configuration order).
    stats_idx: usize,
    /// A counter changed since the last [`Section::publish`].
    dirty: bool,
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
///
/// # Panics
/// Never: a resolution is made by its pool's `init`, which always gives one.
pub fn build(
    config: &ibex_config::Config,
    proxies: &[Proxy],
    scheduler: &mut ibex_sched::Scheduler,
    fdtab: &mut crate::fdtab::FdTab,
    poller: &crate::poller::Poller,
    now: ibex_sched::Tick,
) -> io::Result<Vec<Section>> {
    let t0 = Instant::now();
    // `show resolvers` and the exporter list every configured section, used or not.
    *STATS.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = config
        .resolvers
        .iter()
        .map(|r| SectionStats { name: r.name.as_str().into(), nameservers: r.nameservers.iter().map(|n| (n.name.as_str().into(), [0; 16])).collect() })
        .collect();
    if config.resolvers.is_empty() {
        return Ok(Vec::new());
    }
    // In `show pools` once a configuration has resolvers.
    register_pools();
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
            let sec_idx = if let Some(i) = out.iter().position(|s| *s.name == *sec_name) {
                i
            } else {
                let mut sec = Section::new(cfg, usize_to_u32(out.len()), scheduler, fdtab, poller, now)?;
                sec.stats_idx = config.resolvers.iter().position(|r| r.name == sec_name).unwrap_or(0);
                out.push(sec);
                out.len() - 1
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
                            ended_at: None,
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
            nameservers.push(Nameserver { name: ns.name.as_str().into(), addr: ns.addr, sock, counts: [0; 16] });
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
            stats_idx: 0,
            dirty: false,
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
                let got = self.dns.handle_response(now, from, Protocol::Udp, &self.buf[..n]);
                self.count(ns_idx, received_counter(got));
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
                if let Some(i) = self.nameservers.iter().position(|n| n.addr == to) {
                    // A failed send is `snd_error`; the retry timer sends again. A full socket
                    // buffer is neither (`dns.c:165`: HAProxy queues the datagram).
                    match self.nameservers[i].sock.send(&bytes) {
                        Ok(_) => self.count(i, C_SENT),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(_) => self.count(i, C_SND_ERROR),
                    }
                }
            }
        }
        self.drain_results(now, None, proxies, checks, log);
        self.publish();
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
            if r.status != Status::Valid || r.ended_at.is_none_or(|t| now >= t + self.holds.valid) {
                r.next_at = now;
                due = true;
            }
        }
        due
    }

    /// Applies the results the crate has. A valid answer read from `ns` names it in the log.
    fn count(&mut self, ns: usize, counter: usize) {
        self.nameservers[ns].counts[counter] += 1;
        self.dirty = true;
    }

    /// Copies the counters to [`STATS`] when one changed.
    fn publish(&mut self) {
        if !std::mem::take(&mut self.dirty) {
            return;
        }
        let mut all = STATS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(s) = all.get_mut(self.stats_idx) {
            for (dst, src) in s.nameservers.iter_mut().zip(&self.nameservers) {
                dst.1 = src.counts;
            }
        }
    }

    fn drain_results(&mut self, now: Instant, ns: Option<usize>, proxies: &[Proxy], checks: &mut [ServerCheckState], log: &mut LogFn<'_>) {
        while let Some((qid, res)) = self.dns.poll_result() {
            let Some(r) = self.resolutions.iter_mut().find(|r| r.in_flight == Some(qid)) else { continue };
            r.in_flight = None;
            r.next_at = now + self.holds.timeout_resolve;
            r.ended_at = Some(now);
            match res {
                Ok(answers) => {
                    let by = ns.map(|i| format!("{}/{}", self.name, self.nameservers[i].name));
                    if on_valid(r, &answers, by.as_deref(), &self.holds, now, proxies, checks, log) {
                        if let Some(i) = ns {
                            self.nameservers[i].counts[C_UPDATE] += 1;
                            self.dirty = true;
                        }
                    }
                }
                Err(e) => on_error(r, &e, &self.holds, now, proxies, checks, log),
            }
        }
    }
}

/// The counter `resolv_process_responses` bumps for a datagram (`resolvers.c:2398-2486`).
fn received_counter(r: ibex_dns::Received) -> usize {
    use ibex_dns::Received as R;
    match r {
        R::Valid => C_VALID,
        R::Nx => C_NX,
        R::Refused => C_REFUSED,
        R::AnyErr => C_ANY_ERR,
        R::CnameError => C_CNAME_ERROR,
        R::Truncated => C_TRUNCATED,
        R::Other => C_OTHER,
        R::Invalid => C_INVALID,
        R::TooBig => C_TOO_BIG,
        R::Outdated => C_OUTDATED,
    }
}

/// `resolv_process_responses`, valid: the items are refreshed and every requester runs
/// `snr_resolution_cb`, the first one naming the nameserver, the others `DNS cache`. Whether
/// the first one moved its server (`counters->app.resolver.update++`).
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
) -> bool {
    r.status = Status::Valid;
    r.last_valid = Some(now);
    refresh_items(r, answers, active_families(now), holds.obsolete, now);
    let mut updated = false;
    for k in 0..r.reqs.len() {
        let first = k == 0 && by.is_some();
        let moved = server_answer(r, k, by.filter(|_| k == 0).unwrap_or("DNS cache"), holds, now, proxies, checks, log);
        updated |= first && moved;
    }
    updated
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
        if let Some(i) = find_item(&r.items, ip) {
            r.items[i].last_seen = now;
        } else {
            let key = item_key(ip);
            let at = r.items.partition_point(|i| i.key <= key);
            r.items.insert(at, AnswerItem { key, ip, last_seen: now, users: Vec::new() });
        }
    }
    let before = r.items.len();
    r.items.retain(|i| i.last_seen + obsolete >= now);
    if r.items.len() != before {
        let items = &r.items;
        for req in &mut r.reqs {
            if req.attached.is_some_and(|ip| find_item(items, ip).is_none()) {
                req.attached = None;
            }
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
fn server_answer(r: &mut Resolution, k: usize, by: &str, holds: &Holds, now: Instant, proxies: &[Proxy], checks: &mut [ServerCheckState], log: &mut LogFn<'_>) -> bool {
    let (p, s) = (r.reqs[k].proxy as usize, r.reqs[k].server as usize);
    let Some(px) = proxies.get(p) else { return false };
    let cur = px.servers.get(s).map(|a| a.ip()).filter(|ip| !ip.is_unspecified());
    match pick(r, k, cur, active_families(now)) {
        Pick::No => false,
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
            true
        }
        Pick::NoIp => {
            if set_srv_down(r, k, holds, now, proxies, checks, log) {
                clear_addr(px, s);
            }
            false
        }
    }
}

/// `resolv_get_ip_from_response`: the score of each item for requester `k` (8 the preferred
/// family, 4 a `resolve-net` network, 2 no other server of the proxy on it, 1 the current
/// address) picks its address (design F7).
fn pick(r: &mut Resolution, k: usize, cur: Option<IpAddr>, fam: Families) -> Pick {
    let req = &r.reqs[k];
    // The server is on an item still in the answer.
    if req.attached.is_some_and(|ip| find_item(&r.items, ip).is_some()) {
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
        // The owner is on no live item (checked above), so every user is another server.
        let used = r.items[idx].users_in(req.proxy) > 0;
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
                set_attached(r, k, Some(ip));
                return Pick::No;
            }
            max = score;
        }
    }
    let chosen = if prefer_v4 { best4.or(best6) } else { best6.or(best4) };
    let Some(chosen) = chosen else { return Pick::NoIp };
    set_attached(r, k, found);
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
            set_attached(r, k, None);
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
#[allow(clippy::many_single_char_names)] // HAProxy's names: r(esolution), k, p(roxy), s(erver)
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
    crate::track::set_admin(proxies, checks, p, s, ServerStatus::Maint, crate::srvlog::Cause::Dns);
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
    crate::track::set_admin(proxies, checks, p, s, req.saved, crate::srvlog::Cause::Dns);
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

    /// Every `Received` bumps the counter of its name (`resolvers.c:2398-2486`).
    #[test]
    fn a_received_class_names_its_counter() {
        use ibex_dns::Received as R;
        for (r, name) in [
            (R::Valid, "valid"),
            (R::Nx, "nx"),
            (R::Refused, "refused"),
            (R::AnyErr, "any_err"),
            (R::CnameError, "cname_error"),
            (R::Truncated, "truncated"),
            (R::Other, "other"),
            (R::Invalid, "invalid"),
            (R::TooBig, "too_big"),
            (R::Outdated, "outdated"),
        ] {
            assert_eq!(COUNTERS[received_counter(r)].0, name);
        }
        assert_eq!(COUNTERS[C_SENT].0, "sent");
        assert_eq!(COUNTERS[C_SND_ERROR].0, "snd_error");
        assert_eq!(COUNTERS[C_UPDATE].0, "update");
    }

    /// `show resolvers` with no section, an unknown id, and one section (the only test that
    /// writes `STATS` in this binary).
    #[test]
    fn show_resolvers_without_sections_and_with_an_unknown_id() {
        *STATS.lock().unwrap() = Vec::new();
        assert_eq!(show(None), "No resolvers found\n");
        let mut c = [0u64; 16];
        c[C_NX] = 7;
        *STATS.lock().unwrap() = vec![SectionStats { name: "r".into(), nameservers: vec![("ns1".into(), c)] }];
        assert_eq!(show(Some("zz")), "Can't find that resolvers section\n");
        let text = show(Some("r"));
        assert!(text.starts_with("Resolvers section r\n nameserver ns1:\n  sent:         0\n"), "{text}");
        assert!(text.contains("\n  nx:           7\n"), "{text}");
        *STATS.lock().unwrap() = Vec::new();
    }

    /// The pool never gets a resolution back, so only this reaches the `Poolable` impl.
    #[test]
    fn a_resolution_is_a_poolable_object() {
        use ibex_alloc::Poolable;
        let mut r = Box::new(res(&["192.0.2.1", "192.0.2.2"], Vec::new()));
        let with_items = r.footprint();
        assert!(with_items >= std::mem::size_of::<Resolution>() + 2 * std::mem::size_of::<AnswerItem>());
        r.reset(false);
        assert!(r.items.is_empty() && r.reqs.is_empty());
        assert!(<Box<Resolution> as Poolable>::try_new().is_none());
    }

    fn res(ips: &[&str], reqs: Vec<Req>) -> Resolution {
        let now = Instant::now();
        Resolution {
            name: "x.test".into(),
            prefer: TYPE_A,
            reqs,
            items: {
                let mut v: Vec<AnswerItem> = ips.iter().map(|i| {
                    let ip: IpAddr = i.parse().expect("ip");
                    AnswerItem { key: item_key(ip), ip, last_seen: now, users: Vec::new() }
                }).collect();
                v.sort_by_key(|i| i.key);
                v
            },
            cursor: 0,
            in_flight: None,
            next_at: now,
            last_valid: None,
            ended_at: None,
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
        let Pick::New(a) = pick(&mut r, 0, None, Families::IPV4) else { panic!("no address") };
        let Pick::New(b) = pick(&mut r, 1, None, Families::IPV4) else { panic!("no address") };
        assert_ne!(a, b);
        assert_eq!(pick(&mut r, 0, Some(a), Families::IPV4), Pick::No);
        // Without allow-dup-ip a third server finds both taken.
        r.reqs.push(req(0, 2, ResolveOpts::default()));
        assert_eq!(pick(&mut r, 2, None, Families::IPV4), Pick::NoIp);
        // Another proxy's server may share one.
        r.reqs.push(req(1, 0, ResolveOpts::default()));
        assert!(matches!(pick(&mut r, 3, None, Families::IPV4), Pick::New(_)));
        // The first leaves its item: the third can have it.
        set_attached(&mut r, 0, None);
        assert_eq!(pick(&mut r, 2, None, Families::IPV4), Pick::New(a));
    }
}
