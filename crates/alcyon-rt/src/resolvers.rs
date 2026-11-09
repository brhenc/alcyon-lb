// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Run-time resolution of the servers whose address is a name and that name a `resolvers`
//! section (T484, `docs/design/dns-2026-10-25.md` §2.1-2.6): `HAProxy`'s `process_resolvers`,
//! `resolv_process_responses`, `snr_resolution_cb`, `snr_resolution_error_cb`,
//! `snr_set_srv_down` and `resolv_get_ip_from_response` (`src/resolvers.c`, `src/server.c`).
//!
//! One [`Section`] per `resolvers` section that a server uses, a `Kind::Resolver` task on worker
//! 0, the worker that runs the health checks it changes (`HAProxy` spreads the sections over its
//! threads; Alcyon's checks all live on worker 0, and a section on another worker would have to
//! ask worker 0 for every state change). One connected UDP socket per nameserver: the kernel
//! picks the source port and drops datagrams from any other source (`dns.c:62-130`). The
//! sans-IO `alcyon_dns::Resolver` owns the ids, retries and validation; this module owns the
//! schedule (`timeout resolve`), the `hold` timers and what an answer does to a server.
//!
//! An SRV name (`_...`, T487) is a resolution of its own whose records fill the slots of the
//! servers that name it (`resolv_check_response`): target, port, weight, and the address of an
//! additional record, or else an A/AAAA resolution per target made at run time.
//!
//! Nothing here runs on the request path. What other workers read: the server's address in
//! `Proxy::servers` (the seqlock `set server addr` writes), its state in
//! `Proxy::server_statuses`, and `SRV_ADMF_RMAINT` in `Proxy::server_rmaint`.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use alcyon_config::ast::ResolveOpts;
use alcyon_config::LogLevel;
use alcyon_dns::{Answer, DnsError, Families, Family, NsTransport, Protocol, QueryId, Question, Rdata, Requester};

use crate::check::{ServerCheckState, ServerStatus, DRAIN_DOWN};
use crate::engine::Proxy;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;

alcyon_alloc::declare_pool!(
    /// `show pools` `resolution`: one per name and query type a `resolvers` section resolves
    /// (`HAProxy`'s `resolv_resolution_pool`). Taken while the configuration starts, never
    /// given back: their number is the configuration's.
    static RESOLUTION_POOL: Pool<Box<Resolution>> = alcyon_alloc::PoolSpec::new("resolution");
);

impl alcyon_alloc::Poolable for Box<Resolution> {
    fn footprint(&self) -> usize {
        std::mem::size_of::<Resolution>()
            + self.items.capacity() * std::mem::size_of::<AnswerItem>()
            + self.reqs.capacity() * std::mem::size_of::<Req>()
    }

    fn reset(&mut self, _wipe: bool) {
        self.items.clear();
        self.reqs.clear();
        self.srv = None;
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
const C_TCP_FALLBACK: usize = 14;
const C_OUTDATED: usize = 15;
// `cname` and `timeout` are never counted by HAProxy either (A.t5: `timeout 0` after a timeout).

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
/// always has a `default` section; Alcyon does not (design §2.8), so with no section it says what
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
    /// `SRV_ADM_STCHGC_DNS_NOENT`: the slot's SRV record is gone.
    NoEnt,
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
            Cause::NoEnt => "entry removed from SRV record",
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
        IpAddr::V4(a) => alcyon_sample::hash::hash_xxh32(&a.octets(), u32::from(TYPE_A)),
        IpAddr::V6(a) => alcyon_sample::hash::hash_xxh32(&a.octets(), u32::from(TYPE_AAAA)),
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
    /// An SRV resolution's slots and records (`prefer` is then [`TYPE_SRV`]; `reqs` and
    /// `items` stay empty).
    srv: Option<Box<SrvState>>,
}

/// The slots of the servers whose name is an SRV record, shared by every worker (T487): the
/// target each took (`srv->hostname`, `srv_fqdn`) and whether it ever took one
/// (`SRV_ADMF_FQDN_CHANGED`). Written by the section's worker when an answer changes a slot,
/// read by `show servers state`.
#[derive(Debug)]
pub struct SrvSlots {
    /// Each server's SRV name (`srvrecord`), `None` for the others.
    pub record: Vec<Option<Box<str>>>,
    /// The `resolvers` section each server names (`srv->resolvers`), if any (T489).
    pub section: Vec<Option<Box<str>>>,
    pub fqdn: std::sync::Mutex<Vec<Option<Box<str>>>>,
    pub changed: Vec<std::sync::atomic::AtomicBool>,
}

impl SrvSlots {
    /// The slots of a section's servers, `None` when no server's name is an SRV record.
    #[must_use]
    pub fn new(count: usize, extras: &alcyon_config::ast::ServerExtras) -> Option<std::sync::Arc<Self>> {
        if !extras.names.iter().any(|n| n.fqdn.starts_with('_')) && extras.resolvers_refs.is_empty() {
            return None;
        }
        let mut section = vec![None; count];
        for (i, _, sec) in &extras.resolvers_refs {
            if let Some(v) = section.get_mut(*i as usize) {
                *v = Some(sec.clone());
            }
        }
        let mut record = vec![None; count];
        for n in extras.names.iter().filter(|n| n.fqdn.starts_with('_')) {
            if let Some(r) = record.get_mut(n.index as usize) {
                *r = Some(n.fqdn.clone());
            }
        }
        Some(std::sync::Arc::new(Self {
            record,
            section,
            fqdn: std::sync::Mutex::new(vec![None; count]),
            changed: (0..count).map(|_| std::sync::atomic::AtomicBool::new(false)).collect(),
        }))
    }

    /// The target of slot `idx`.
    #[must_use]
    pub fn fqdn(&self, idx: usize) -> Option<Box<str>> {
        self.fqdn.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(idx).cloned().flatten()
    }

    pub(crate) fn set_fqdn(&self, idx: usize, v: Option<&str>) {
        self.set_name(idx, v);
        if v.is_some() {
            if let Some(c) = self.changed.get(idx) {
                c.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

impl SrvSlots {
    /// Sets the name `srv_fqdn` shows for server `idx` (`srv->hostname`), no flag raised.
    pub(crate) fn set_name(&self, idx: usize, v: Option<&str>) {
        if let Some(f) = self.fqdn.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get_mut(idx) {
            *f = v.map(Box::from);
        }
    }
}

/// `set server <b>/<s> fqdn` requests (T489) the CLI made on any worker, for the section
/// worker to apply: `(proxy, server, name)`. Operator-rate, never on the request path.
static FQDN_SETS: std::sync::Mutex<Vec<(u32, u32, Box<str>)>> = std::sync::Mutex::new(Vec::new());
static FQDN_PENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Asks the section of server `s` of proxy `p` to resolve `name` from now on (`srv_set_fqdn`):
/// applied at the section's next step.
pub fn request_fqdn(p: usize, s: usize, name: &str) {
    FQDN_SETS.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push((usize_to_u32(p), usize_to_u32(s), name.into()));
    FQDN_PENDING.store(true, std::sync::atomic::Ordering::Release);
}

/// An SRV resolution (`struct resolv_srvrq` per proxy, and the SRV items of the answers).
#[derive(Debug, Default)]
struct SrvState {
    rqs: Vec<SrvRq>,
    /// In key order, as `HAProxy`'s answer tree: the order the records fill the slots in.
    items: Vec<SrvItem>,
}

/// The servers of one proxy that name the SRV record.
#[derive(Debug)]
struct SrvRq {
    proxy: u32,
    /// The slots with no record, in order (`srvrq->attached_servers`): a slot whose record goes
    /// comes back at the end.
    free: Vec<u32>,
    /// The first slot's `resolve-*` options, its per-target resolutions' too.
    opts: ResolveOpts,
}

/// One SRV record of the answers (`struct resolv_answer_item` of type SRV).
#[derive(Debug)]
struct SrvItem {
    /// `XXH32` of the target in label form, seed 33.
    key: u32,
    /// Lower case, no final dot.
    target: Box<str>,
    port: u16,
    weight: u16,
    last_seen: Instant,
    /// The additional record for the target (`ar_item`) and when it was last seen.
    ar: Option<(IpAddr, Instant)>,
    /// The slots on this record, as (proxy, server) (`attached_servers`).
    slots: Vec<(u32, u32)>,
}

/// What an SRV answer asks of the section's other resolutions.
#[derive(Debug)]
enum SrvAct {
    /// Slot (proxy, server) resolves its target on its own (`resolv_link_resolution`).
    Link(u32, u32, Box<str>, ResolveOpts),
    /// Slot (proxy, server) leaves its target's resolution (`_resolv_unlink_resolution`).
    Unlink(u32, u32),
}

/// The tree key of an SRV item: `XXH32` of the target as labels (`\x02t1\x04test`).
fn srv_key(target: &str) -> u32 {
    let mut dn = Vec::with_capacity(target.len() + 1);
    for l in target.split('.').filter(|l| !l.is_empty()) {
        dn.push(u8::try_from(l.len()).unwrap_or(u8::MAX));
        dn.extend_from_slice(l.as_bytes());
    }
    alcyon_sample::hash::hash_xxh32(&dn, u32::from(TYPE_SRV))
}

/// A name of an answer as the slots keep it: lower case (the crate's), no final dot.
fn srv_name(name: &str) -> &str {
    name.strip_suffix('.').unwrap_or(name)
}

/// A new resolution of `name` (`resolv_pick_resolution`), from the pool.
fn new_resolution(name: &str, prefer: u16, at: Instant) -> Box<Resolution> {
    let mut res = RESOLUTION_POOL
        .take_counted(|| {
            Some(Box::new(Resolution {
                name: Box::from(""),
                prefer,
                reqs: Vec::new(),
                items: Vec::new(),
                cursor: 0,
                in_flight: None,
                next_at: at,
                last_valid: Some(at),
                ended_at: None,
                status: Status::None,
                srv: None,
            }))
        })
        .expect("a resolution");
    res.name = name.into();
    res.prefer = prefer;
    res.cursor = 0;
    res.in_flight = None;
    res.next_at = at;
    res.last_valid = Some(at);
    res.ended_at = None;
    res.status = Status::None;
    res
}

/// A nameserver's TCP connection (`dns_stream_*`, `dns.c`): opened by the first query that
/// needs it, closed after [`TCP_IDLE`] without one or at the first error.
struct TcpConn {
    stream: TcpStream,
    /// The connect finished.
    up: bool,
    /// Framed queries not written yet.
    out: Vec<u8>,
    /// Bytes read, a partial reply at the end.
    inb: Vec<u8>,
    /// Queries sent and not answered (`DNS_STREAM_MAX_PIPELINED_REQ` at most).
    pending: usize,
    /// The last query sent or reply read.
    last_use: Instant,
    /// The id the next query takes on this connection: `HAProxy` numbers a stream's queries
    /// 1, 2, ... (`dns_session_io_handler`, `ds->query_counter`; A.t9, A.t15c).
    next_id: u16,
    /// `(id on the wire, the resolution's id)` of the queries written and not answered.
    ids: Vec<(u16, u16)>,
}

/// `DNS_STREAM_MAX_PIPELINED_REQ`.
const TCP_PIPELINED: usize = 4;
/// `tcp_idle` of the stream server (doc §5.3.2): the connection is closed after this.
const TCP_IDLE: Duration = Duration::from_secs(5);

struct Nameserver {
    name: Box<str>,
    addr: SocketAddr,
    transport: NsTransport,
    /// None for `tcp@`: nothing is sent or read over UDP.
    sock: Option<UdpSocket>,
    tcp: Option<TcpConn>,
    /// Queries waiting for the connection or for a free slot among the pipelined ones.
    queue: VecDeque<Vec<u8>>,
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
    pub task: alcyon_sched::task::TaskRef,
    /// The index in the engine's list: the `FdState::Resolver` of its descriptors.
    idx: u32,
    nameservers: Vec<Nameserver>,
    dns: alcyon_dns::Resolver,
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
    /// `do-resolve` questions asked of the nameservers, and the answered messages to send back.
    dr_pending: Vec<DrPending>,
    // Pooled messages (`DR_MSG_POOL`).
    #[allow(clippy::vec_box)]
    dr_done: Vec<alcyon_alloc::PoolBox<Box<DrMsg>>>,
}

/// What a step reports to the engine: a line to log on the server's proxy, at a level, also
/// printed on stderr as `HAProxy`'s `ha_warning` does.
/// The last argument is false for a line `HAProxy` only logs (`send_log` alone).
pub type LogFn<'a> = dyn FnMut(usize, LogLevel, &str, bool) + 'a;

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

/// `dns-accept-family` (`resolv_accept_families`, process-wide as in `HAProxy`): bit 0 IPv4,
/// bit 1 IPv6, bit 2 `auto`. Written once by [`build`], before any section runs.
static ACCEPT_FAMILY: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(4);

/// The families resolvers accept (`resolv_active_families`): with `auto`, `HAProxy`'s
/// default, IPv4, and IPv6 while the host has a route to it; else the configured ones.
fn active_families(now: Instant) -> Families {
    let f = ACCEPT_FAMILY.load(std::sync::atomic::Ordering::Relaxed);
    if f & 4 != 0 {
        return Families { ipv4: true, ipv6: inet6_reachable(now) };
    }
    Families { ipv4: f & 1 != 0, ipv6: f & 2 != 0 }
}

/// The type a server's resolution asks first (`resolvers.c:2179`): the only accepted family,
/// else `resolve-prefer`'s (IPv6 by default).
fn first_type(fam: Families, prefer_ipv4: bool) -> u16 {
    if !fam.ipv6 || (fam.ipv4 && prefer_ipv4) {
        TYPE_A
    } else {
        TYPE_AAAA
    }
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
    config: &alcyon_config::Config,
    proxies: &[Proxy],
    scheduler: &mut alcyon_sched::Scheduler,
    fdtab: &mut crate::fdtab::FdTab,
    poller: &crate::poller::Poller,
    now: alcyon_sched::Tick,
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
    let f = config.global.as_ref().map(|g| g.dns_accept_family).unwrap_or_default();
    ACCEPT_FAMILY.store(u8::from(f.ipv4) | u8::from(f.ipv6) << 1 | u8::from(f.auto) << 2, std::sync::atomic::Ordering::Relaxed);
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
    // The sections a `do-resolve` names run even when no server uses them (T489).
    let dr_names = config
        .listens
        .iter()
        .map(|l| (&l.tcp_req_content_rules, &l.http_req_rules))
        .chain(config.frontends.iter().map(|f| (&f.tcp_req_content_rules, &f.http_req_rules)))
        .chain(config.backends.iter().map(|b| (&b.tcp_req_content_rules, &b.http_req_rules)))
        .flat_map(|(t, h)| {
            t.iter()
                .filter_map(|r| if let alcyon_config::ast::TcpReqContentAction::DoResolve(d) = &r.action { Some(d.resolvers.as_str()) } else { None })
                .chain(h.iter().filter_map(|r| if let alcyon_config::HttpReqAction::DoResolve(d) = &r.action { Some(d.resolvers.as_str()) } else { None }))
        });
    for sec_name in dr_names {
        if out.iter().any(|s| *s.name == *sec_name) {
            continue;
        }
        let Some((i, cfg)) = config.resolvers.iter().enumerate().find(|(_, r)| r.name == sec_name) else { continue };
        let mut sec = Section::new(cfg, usize_to_u32(out.len()), scheduler, fdtab, poller, now)?;
        sec.stats_idx = i;
        out.push(sec);
    }
    if let Some(n) = config.global.as_ref().and_then(|g| g.resolvers_cache_size) {
        DR_CACHE_SIZE.store(n, std::sync::atomic::Ordering::Relaxed);
    }
    for (p_idx, (servers, extras)) in sections.enumerate() {
        let Some(px) = proxies.get(p_idx) else { continue };
        // A server written as an address with `resolvers` resolves nothing until `set server
        // fqdn` names it one (T489): its section must run.
        for (_, _, sec_name) in &extras.resolvers_refs {
            if out.iter().any(|s| s.name == *sec_name) {
                continue;
            }
            let Some(cfg) = config.resolvers.iter().find(|r| *r.name == **sec_name) else { continue };
            let mut sec = Section::new(cfg, usize_to_u32(out.len()), scheduler, fdtab, poller, now)?;
            sec.stats_idx = config.resolvers.iter().position(|r| *r.name == **sec_name).unwrap_or(0);
            out.push(sec);
        }
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
            let srv = n.fqdn.starts_with('_');
            let prefer = if srv { TYPE_SRV } else { first_type(families, n.resolve.prefer_ipv4) };
            let key = (sec_idx, n.fqdn.to_ascii_lowercase().into_boxed_str(), prefer);
            if srv {
                // The slots join the record's resolution (`find_srvrq_by_name`, one per proxy).
                let sec = &mut out[sec_idx];
                let p = usize_to_u32(p_idx);
                let r = if let Some(&(_, r)) = by_key.get(&key) {
                    r
                } else {
                    let mut res = new_resolution(&n.fqdn, TYPE_SRV, t0);
                    res.srv = Some(Box::default());
                    by_key.insert(key, (sec_idx, sec.resolutions.len()));
                    sec.resolutions.push(res);
                    sec.resolutions.len() - 1
                };
                let st = sec.resolutions[r].srv.get_or_insert_with(Box::default);
                if let Some(rq) = st.rqs.iter_mut().find(|q| q.proxy == p) {
                    rq.free.push(n.index);
                } else {
                    st.rqs.push(SrvRq { proxy: p, free: vec![n.index], opts: n.resolve.clone() });
                }
                continue;
            }
            let req = Req { proxy: usize_to_u32(p_idx), server: n.index, opts: n.resolve.clone(), attached: None };
            let sec = &mut out[sec_idx];
            if let Some(&(_, r)) = by_key.get(&key) {
                sec.resolutions[r].reqs.push(req);
            } else {
                let mut res = new_resolution(&n.fqdn, prefer, t0);
                res.reqs.push(req);
                by_key.insert(key, (sec_idx, sec.resolutions.len()));
                sec.resolutions.push(res);
            }
        }
    }
    Ok(out)
}

/// A non-blocking connect to a nameserver: the result is known when the socket is writable.
fn tcp_open(addr: SocketAddr) -> io::Result<TcpStream> {
    use rustix::net::{AddressFamily, SocketFlags, SocketType};
    let family = if addr.is_ipv4() { AddressFamily::INET } else { AddressFamily::INET6 };
    let fd = rustix::net::socket_with(family, SocketType::STREAM, SocketFlags::NONBLOCK | SocketFlags::CLOEXEC, None)?;
    match rustix::net::connect(&fd, &addr) {
        Ok(()) | Err(rustix::io::Errno::INPROGRESS) => {}
        Err(e) => return Err(e.into()),
    }
    Ok(TcpStream::from(fd))
}

fn usize_to_u32(v: usize) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

impl Section {
    fn new(
        cfg: &alcyon_config::ast::ResolversSection,
        idx: u32,
        scheduler: &mut alcyon_sched::Scheduler,
        fdtab: &mut crate::fdtab::FdTab,
        poller: &crate::poller::Poller,
        now: alcyon_sched::Tick,
    ) -> io::Result<Self> {
        let mut nameservers = Vec::with_capacity(cfg.nameservers.len());
        for ns in &cfg.nameservers {
            let transport = match ns.transport {
                alcyon_config::ast::NsTransport::Default => NsTransport::Auto,
                alcyon_config::ast::NsTransport::Udp => NsTransport::Udp,
                alcyon_config::ast::NsTransport::Tcp => NsTransport::Tcp,
            };
            let sock = if transport == NsTransport::Tcp {
                None
            } else {
                let local: SocketAddr = if ns.addr.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { "[::]:0".parse().expect("addr") };
                let sock = UdpSocket::bind(local)?;
                sock.connect(ns.addr)?;
                sock.set_nonblocking(true)?;
                let fd = sock.as_raw_fd();
                fdtab.insert(fd, crate::fdtab::FdState::Resolver { section: idx }, crate::fdtab::Interest::READ);
                poller.add(std::os::fd::AsFd::as_fd(&sock), u64::try_from(fd).unwrap_or(0), true, false)?;
                Some(sock)
            };
            nameservers.push(Nameserver { name: ns.name.as_str().into(), addr: ns.addr, transport, sock, tcp: None, queue: VecDeque::new(), counts: [0; 16] });
        }
        let h = &cfg.hold;
        let dns = alcyon_dns::Resolver::new(alcyon_dns::ResolverConfig {
            nameservers: nameservers.iter().map(|n| n.addr).collect(),
            resolve_retries: usize::try_from(cfg.resolve_retries.max(1)).unwrap_or(1),
            timeout_resolve: cfg.timeout_resolve,
            timeout_retry: cfg.timeout_retry,
            // The engine keeps the `do-resolve` answers (bounded, [`DrCache`]); the crate's own
            // cache, keyed by any name a request gives, stays off.
            hold_valid: Duration::ZERO,
            hold_nx: h.nx,
            hold_other: h.other,
            hold_refused: h.refused,
            hold_timeout: h.timeout,
            hold_obsolete: h.obsolete,
            accepted_payload_size: cfg.accepted_payload_size,
            // The crate's ids: SipHash under the OS-seeded keys of the standard library, not
            // the load balancer's xorshift, whose seed is the clock.
            tcp_fallback: true,
            transports: nameservers.iter().map(|n| n.transport).collect(),
            ..alcyon_dns::ResolverConfig::default()
        });
        let task = scheduler.create(alcyon_sched::task::WorkKind::new(alcyon_sched::task::Kind::Resolver, idx)).ok_or_else(|| io::Error::other("no task for a resolvers section"))?;
        scheduler.queue_timer(task, now.add(1));
        Ok(Self {
            name: cfg.name.as_str().into(),
            task,
            idx,
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
            dr_pending: Vec::new(),
            dr_done: Vec::new(),
        })
    }

    /// Runs the section: reads every datagram, starts the resolutions that are due, sends,
    /// and applies every result to its servers. Returns when it wants to run again.
    pub fn step(
        &mut self,
        proxies: &[Proxy],
        checks: &mut [ServerCheckState],
        log: &mut LogFn<'_>,
        fdtab: &mut crate::fdtab::FdTab,
        poller: &crate::poller::Poller,
    ) -> Duration {
        let now = Instant::now();
        // Replies: every nameserver's socket until it is empty.
        for ns_idx in 0..self.nameservers.len() {
            while let Some(sock) = &self.nameservers[ns_idx].sock {
                let n = match sock.recv(&mut self.buf) {
                    Ok(n) => n,
                    // An ICMP unreachable is reported on the next read: the nameserver is
                    // silent, which the retry timer turns into a timeout (A.t7).
                    Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => continue,
                    Err(_) => break,
                };
                let got = self.dns.handle_response_ns(now, ns_idx, Protocol::Udp, &self.buf[..n]);
                self.count(ns_idx, received_counter(got));
                self.drain_results(now, Some(ns_idx), proxies, checks, log);
            }
            self.tcp_service(ns_idx, now, proxies, checks, log, fdtab, poller);
        }
        if FQDN_PENDING.load(std::sync::atomic::Ordering::Acquire) {
            self.take_fqdn_requests(proxies, now);
        }
        // Resolutions due: one query each, to every nameserver (A.t2).
        let families = active_families(now);
        for r in &mut self.resolutions {
            if r.in_flight.is_none() && now >= r.next_at {
                let prefer = if r.prefer == TYPE_A { Family::Ipv4 } else { Family::Ipv6 };
                let accept = Families { ipv4: families.ipv4 || prefer == Family::Ipv4, ipv6: families.ipv6 || prefer == Family::Ipv6 };
                let question = if r.prefer == TYPE_SRV { Question::Srv } else { Question::Addr { accept, prefer } };
                match self.dns.query(now, &r.name, question, Requester::Server) {
                    Ok(q) => r.in_flight = Some(q),
                    // A name the parser let through and the crate refuses, or no id free:
                    // tried again at the next period.
                    Err(_) => r.next_at = now + self.holds.timeout_resolve,
                }
            }
        }
        self.drain_results(now, None, proxies, checks, log);
        // Sends, and the retry timer (which may end resolutions in a timeout).
        // By index: `tcp@A` and `A` are two nameservers (T513).
        while let Some((i, proto, bytes)) = self.dns.poll_transmit_ns(now) {
            if proto == Protocol::Tcp {
                // A.t9: on a nameserver that also speaks UDP, a TCP query is the fallback
                // (`resolv_send_tcp_fallback`).
                if self.nameservers[i].transport == NsTransport::Auto {
                    self.count(i, C_TCP_FALLBACK);
                }
                // `sent` when it is queued for a connection, up or not (`dns_session_io_handler`
                // hands it to a session: a connect that never completes still counts).
                self.count(i, C_SENT);
                self.nameservers[i].queue.push_back(bytes);
            } else if let Some(sock) = &self.nameservers[i].sock {
                // A failed send is `snd_error`; the retry timer sends again. A full socket
                // buffer is neither (`dns.c:165`: HAProxy queues the datagram).
                // An ICMP unreachable an earlier datagram drew fails the next send on a
                // connected socket, and this datagram is not sent: `HAProxy`'s socket is not
                // connected, so it never sees that error (a dead nameserver: every query
                // `sent`, no `snd_error`). The failed send took the error: again.
                let sent = match sock.send(&bytes) {
                    Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => sock.send(&bytes),
                    r => r,
                };
                match sent {
                    Ok(_) => self.count(i, C_SENT),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => self.count(i, C_SND_ERROR),
                }
            }
        }
        for i in 0..self.nameservers.len() {
            self.tcp_service(i, now, proxies, checks, log, fdtab, poller);
        }
        self.drain_results(now, None, proxies, checks, log);
        self.publish();
        let next = self
            .resolutions
            .iter()
            .filter(|r| r.in_flight.is_none())
            .map(|r| r.next_at)
            .chain(self.dns.poll_timeout())
            .chain(self.nameservers.iter().filter_map(|n| n.tcp.as_ref().filter(|c| c.up && c.pending == 0).map(|c| c.last_use + TCP_IDLE)))
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

    /// Closes nameserver `i`'s TCP connection; the queries it carried are left to the retry
    /// timer, as a silent nameserver's are.
    fn tcp_close(&mut self, i: usize, fdtab: &mut crate::fdtab::FdTab, poller: &crate::poller::Poller) {
        let ns = &mut self.nameservers[i];
        if let Some(c) = ns.tcp.take() {
            let _ = poller.delete(std::os::fd::AsFd::as_fd(&c.stream));
            fdtab.remove(c.stream.as_raw_fd());
        }
    }

    /// One nameserver's TCP connection: opens it for a queued query, frames and writes the
    /// queries (four in flight at most), reads and applies the replies, closes it when idle
    /// or broken. A query that cannot be sent is not an error: `HAProxy` counts it `sent`
    /// and the resolution times out (measured with the port closed).
    #[allow(clippy::too_many_arguments)]
    fn tcp_service(
        &mut self,
        i: usize,
        now: Instant,
        proxies: &[Proxy],
        checks: &mut [ServerCheckState],
        log: &mut LogFn<'_>,
        fdtab: &mut crate::fdtab::FdTab,
        poller: &crate::poller::Poller,
    ) {
        if self.nameservers[i].tcp.is_none() {
            if self.nameservers[i].queue.is_empty() {
                return;
            }
            let Ok(stream) = tcp_open(self.nameservers[i].addr) else {
                self.drop_queued(i);
                return;
            };
            let fd = stream.as_raw_fd();
            fdtab.insert(fd, crate::fdtab::FdState::Resolver { section: self.idx }, crate::fdtab::Interest::READ);
            if poller.add(std::os::fd::AsFd::as_fd(&stream), u64::try_from(fd).unwrap_or(0), true, true).is_err() {
                fdtab.remove(fd);
                self.drop_queued(i);
                return;
            }
            self.nameservers[i].tcp = Some(TcpConn { stream, up: false, out: Vec::new(), inb: Vec::new(), pending: 0, last_use: now, next_id: 1, ids: Vec::with_capacity(TCP_PIPELINED) });
        }
        let ns = &mut self.nameservers[i];
        let Some(c) = ns.tcp.as_mut() else { return };
        let mut broken = false;
        if !c.up {
            match c.stream.take_error() {
                Ok(None) if c.stream.peer_addr().is_ok() => c.up = true,
                Ok(None) => return,
                _ => broken = true,
            }
        }
        if !broken && c.up && c.pending == 0 && ns.queue.is_empty() && now >= c.last_use + TCP_IDLE {
            broken = true;
        }
        let mut frames: Vec<Vec<u8>> = Vec::new();
        if !broken && c.up {
            while c.pending < TCP_PIPELINED {
                let Some(mut q) = ns.queue.pop_front() else { break };
                if q.len() >= 2 {
                    let wire = c.next_id;
                    c.next_id = c.next_id.wrapping_add(1);
                    c.ids.push((wire, u16::from_be_bytes([q[0], q[1]])));
                    q[..2].copy_from_slice(&wire.to_be_bytes());
                }
                c.out.extend_from_slice(&u16::try_from(q.len()).unwrap_or(u16::MAX).to_be_bytes());
                c.out.extend_from_slice(&q);
                c.pending += 1;
                c.last_use = now;
            }
            while !c.out.is_empty() {
                match c.stream.write(&c.out) {
                    Ok(0) => break,
                    Ok(n) => {
                        c.out.drain(..n);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        broken = true;
                        break;
                    }
                }
            }
            while !broken {
                match c.stream.read(&mut self.buf) {
                    Ok(0) => broken = true,
                    Ok(n) => c.inb.extend_from_slice(&self.buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => broken = true,
                }
            }
            // Whole replies (2-byte length, then the message) in the bytes read.
            while c.inb.len() >= 2 {
                let len = usize::from(u16::from_be_bytes([c.inb[0], c.inb[1]]));
                if c.inb.len() < 2 + len {
                    break;
                }
                let mut frame = c.inb[2..2 + len].to_vec();
                c.inb.drain(..2 + len);
                c.last_use = now;
                // The reply carries the connection's id: back to the resolution's. A frame
                // with no id of ours (or no room for one) is dropped, counted nowhere
                // (`dns_session_io_handler`, `dns.c:794`).
                let wire = frame.first_chunk::<2>().map(|b| u16::from_be_bytes(*b));
                let Some(k) = wire.and_then(|w| c.ids.iter().position(|&(id, _)| id == w)) else { continue };
                frame[..2].copy_from_slice(&c.ids.swap_remove(k).1.to_be_bytes());
                frames.push(frame);
                c.pending = c.pending.saturating_sub(1);
            }
        }
        let more = !ns.queue.is_empty() && !broken;
        for f in &frames {
            let got = self.dns.handle_response_ns(now, i, Protocol::Tcp, f);
            self.count(i, received_counter(got));
            self.drain_results(now, Some(i), proxies, checks, log);
        }
        if broken {
            self.tcp_close(i, fdtab, poller);
            // Queries that waited for a slot go with the connection (retry timer).
            self.drop_queued(i);
        } else if more && !frames.is_empty() {
            // Replies freed slots: send what waited.
            self.tcp_service(i, now, proxies, checks, log, fdtab, poller);
        }
    }

    /// The queries waiting for a connection that is not coming are dropped; the retry timer
    /// sends them again.
    /// (They were counted `sent` when queued.)
    fn drop_queued(&mut self, i: usize) {
        self.nameservers[i].queue.clear();
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
            if !self.dr_pending.is_empty() && self.dr_result(qid, &res, now) {
                continue;
            }
            let Some(r) = self.resolutions.iter_mut().find(|r| r.in_flight == Some(qid)) else { continue };
            r.in_flight = None;
            r.next_at = now + self.holds.timeout_resolve;
            r.ended_at = Some(now);
            if r.srv.is_some() {
                let mut acts = Vec::new();
                match res {
                    Ok(answers) => srv_answer(r, &answers, &self.holds, now, proxies, checks, log, &mut acts),
                    Err(e) => srv_error(r, &e, &self.holds, now, proxies, checks, log, &mut acts),
                }
                for a in acts {
                    match a {
                        SrvAct::Link(p, s, target, opts) => self.link(p, s, &target, opts, now),
                        SrvAct::Unlink(p, s) => {
                            self.unlink(p, s);
                        }
                    }
                }
                continue;
            }
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

    /// Slot `s` of proxy `p` resolves `target` (`resolv_link_resolution`): it joins the
    /// resolution of that name, else a new one, first asked one `timeout resolve` from now
    /// (A.t11b: the A queries go out with the next SRV query).
    fn link(&mut self, p: u32, s: u32, target: &str, opts: ResolveOpts, now: Instant) {
        if self.resolutions.iter().any(|r| r.reqs.iter().any(|q| q.proxy == p && q.server == s)) {
            return;
        }
        let prefer = first_type(active_families(now), opts.prefer_ipv4);
        let req = Req { proxy: p, server: s, opts, attached: None };
        if let Some(r) = self.resolutions.iter_mut().find(|r| r.srv.is_none() && r.prefer == prefer && r.name.eq_ignore_ascii_case(target)) {
            r.reqs.push(req);
            return;
        }
        let mut res = new_resolution(target, prefer, now);
        res.next_at = now + self.holds.timeout_resolve;
        res.reqs.push(req);
        self.resolutions.push(res);
    }

    /// Slot `s` of proxy `p` leaves its target's resolution, which goes back to the pool once
    /// no server is on it (`_resolv_unlink_resolution`, `resolv_free_resolution`).
    fn unlink(&mut self, p: u32, s: u32) -> Option<ResolveOpts> {
        let i = self.resolutions.iter().position(|r| r.srv.is_none() && r.reqs.iter().any(|q| q.proxy == p && q.server == s))?;
        let r = &mut self.resolutions[i];
        let k = r.reqs.iter().position(|q| q.proxy == p && q.server == s)?;
        set_attached(r, k, None);
        let opts = r.reqs.remove(k).opts;
        if r.reqs.is_empty() {
            RESOLUTION_POOL.give_counted(self.resolutions.remove(i));
        }
        Some(opts)
    }

    /// Applies the `set server fqdn` requests for this section's servers (`srv_set_fqdn`):
    /// the server leaves its resolution and joins the new name's, asked at once. A server
    /// written as an address had no resolution: it takes the default `resolve-*` options.
    fn take_fqdn_requests(&mut self, proxies: &[Proxy], now: Instant) {
        let mine: Vec<(u32, u32, Box<str>)> = {
            let mut all = FQDN_SETS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let (mine, rest): (Vec<_>, Vec<_>) = all.drain(..).partition(|(p, s, _)| {
                proxies.get(*p as usize).and_then(|px| px.server_resolvers(*s as usize)).is_some_and(|n| *n == *self.name)
            });
            *all = rest;
            if all.is_empty() {
                FQDN_PENDING.store(false, std::sync::atomic::Ordering::Release);
            }
            mine
        };
        for (p, s, name) in mine {
            let opts = self.unlink(p, s).unwrap_or_default();
            self.link(p, s, &name, opts, now);
            // `link` left the server on a resolution of the name: asked at once unless a query
            // is in flight (`resolv_trigger_resolution`).
            let joined = self.resolutions.iter_mut().find(|r| r.srv.is_none() && r.reqs.iter().any(|q| q.proxy == p && q.server == s));
            if let Some(r) = joined.filter(|r| r.in_flight.is_none()) {
                r.next_at = r.next_at.min(now);
            }
            if let Some(px) = proxies.get(p as usize) {
                px.mark_server_fqdn_changed(s as usize);
            }
        }
    }
}

/// `resolv_validate_dns_response` and `resolv_check_response` for an SRV resolution: the
/// records into the items (in key order, kept when already there, the weight refreshed), the
/// additional records onto the first record of their name without one, then in key order the
/// obsolete records go (their slots with them) and each record fills a slot of each proxy.
#[allow(clippy::too_many_arguments)]
fn srv_answer(r: &mut Resolution, answers: &[Answer], holds: &Holds, now: Instant, proxies: &[Proxy], checks: &mut [ServerCheckState], log: &mut LogFn<'_>, acts: &mut Vec<SrvAct>) {
    r.status = Status::Valid;
    r.last_valid = Some(now);
    let fam = active_families(now);
    let Some(st) = r.srv.as_deref_mut() else { return };
    for a in answers {
        if let Rdata::Srv { target, port, weight, .. } = &a.rdata {
            let target = srv_name(target);
            let key = srv_key(target);
            if let Some(it) = st.items.iter_mut().find(|i| i.key == key && i.port == *port && *i.target == *target) {
                it.weight = *weight;
                it.last_seen = now;
            } else {
                let at = st.items.partition_point(|i| i.key <= key);
                st.items.insert(at, SrvItem { key, target: target.into(), port: *port, weight: *weight, last_seen: now, ar: None, slots: Vec::new() });
            }
        }
    }
    for a in answers {
        let Rdata::Additional { name, ip } = &a.rdata else { continue };
        if (ip.is_ipv4() && !fam.ipv4) || (ip.is_ipv6() && !fam.ipv6) {
            continue;
        }
        let name = srv_name(name);
        // Seen again (not twice in one answer), else onto the first record of the name without one.
        if let Some(it) = st.items.iter_mut().find(|i| *i.target == *name && i.ar.is_some_and(|(v, seen)| v == *ip && seen != now)) {
            it.ar = Some((*ip, now));
        } else if let Some(it) = st.items.iter_mut().find(|i| *i.target == *name && i.ar.is_none()) {
            it.ar = Some((*ip, now));
        }
    }
    let mut leave: Vec<(u32, u32)> = Vec::new();
    let mut i = 0;
    while i < st.items.len() {
        if st.items[i].ar.is_some_and(|(_, seen)| seen + holds.obsolete < now) {
            st.items[i].ar = None;
        }
        if st.items[i].last_seen + holds.obsolete < now {
            let it = st.items.remove(i);
            for (p, s) in it.slots {
                srv_cleanup(&mut st.rqs, p, s, proxies, checks, log, acts);
            }
            continue;
        }
        for q in 0..st.rqs.len() {
            let p = st.rqs[q].proxy;
            let it = &mut st.items[i];
            let s = if let Some(&(_, s)) = it.slots.iter().find(|x| x.0 == p) {
                s
            } else if st.rqs[q].free.is_empty() {
                continue;
            } else {
                let s = st.rqs[q].free.remove(0);
                it.slots.push((p, s));
                s
            };
            srv_fill(it, p, s, &st.rqs[q].opts, proxies, log, acts, &mut leave);
        }
        i += 1;
    }
    for (p, s) in leave {
        let req = Req { proxy: p, server: s, opts: ResolveOpts::default(), attached: None };
        // The slot's own name (`srv->hostname`), `(null)` when its target was refused.
        let name = proxies.get(p as usize).and_then(|px| px.server_srv_fqdn(s as usize));
        leave_rmaint(&req, name.as_deref().unwrap_or("(null)"), proxies, checks, log);
    }
}

/// `srv_found` in `resolv_check_response`: slot `s` of proxy `p` takes record `it`'s port,
/// target and weight, and the address of its additional record if it has one (its own
/// resolution is then dropped), else resolves the target.
#[allow(clippy::too_many_arguments)]
fn srv_fill(it: &SrvItem, p: u32, s: u32, opts: &ResolveOpts, proxies: &[Proxy], log: &mut LogFn<'_>, acts: &mut Vec<SrvAct>, leave: &mut Vec<(u32, u32)>) {
    let (pi, si) = (p as usize, s as usize);
    let Some(px) = proxies.get(pi) else { return };
    let Some(old) = px.servers.get(si) else { return };
    let srv = &px.server_ids[si];
    if let Some((ip, _)) = it.ar {
        acts.push(SrvAct::Unlink(p, s));
        // `server_set_inetaddr_warn`: a port 0 is a mapped port (`+0`).
        let ip_change = old.ip() != ip;
        let port_change = old.port() != it.port || old.port() == 0;
        if ip_change || port_change {
            px.servers.set(si, SocketAddr::new(ip, it.port));
            let mut msg = format!("{}/{srv}: ", px.name);
            if ip_change {
                let from = if old.ip().is_unspecified() { "(none)".to_string() } else { old.ip().to_string() };
                let _ = write!(msg, "IP changed from '{from}' to '{ip}'");
            }
            if port_change {
                let sep = if ip_change { ", " } else { "" };
                let plus = if old.port() == 0 { "+" } else { "" };
                let _ = write!(msg, "{sep}port changed from '{plus}{}' to '{}'", old.port(), it.port);
            }
            msg.push_str(" by 'DNS additional record'.");
            log(pi, LogLevel::Notice, &msg, true);
        }
        if px.server_rmaint(si) {
            leave.push((p, s));
        }
    } else if old.port() != it.port {
        px.servers.set(si, SocketAddr::new(old.ip(), it.port));
    }
    if px.server_srv_fqdn(si).is_none() {
        if it.target.is_empty() || it.target.len() > 255 || it.target.bytes().any(|b| !(b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')) {
            // `srv_update_fqdn`: logged at every answer; the slot keeps no target (nothing to
            // resolve) but takes the weight (A.tinv).
            log(pi, LogLevel::Notice, &format!("invalid fqdn '{}' by 'SRV record'", it.target), false);
        } else {
            px.set_server_srv_fqdn(si, Some(&it.target));
            log(pi, LogLevel::Notice, &format!("{}/{srv} changed its FQDN from (null) to {} by 'SRV record'", px.name, it.target), false);
        }
    }
    if it.ar.is_none() && px.server_srv_fqdn(si).is_some() {
        acts.push(SrvAct::Link(p, s, it.target.clone(), opts.clone()));
    }
    if !opts.ignore_weight {
        // A DNS weight is 0-65535, a server's 0-256 (`resolv_check_response`).
        px.set_weight(si, u32::from(it.weight).div_ceil(256));
    }
}

/// `resolv_srvrq_cleanup_srv`: the slot's record is gone. It enters maintenance ("entry
/// removed from SRV record"), loses its target, address and port, leaves its target's
/// resolution, and is free again (at the end of the list).
#[allow(clippy::too_many_arguments)]
fn srv_cleanup(rqs: &mut [SrvRq], p: u32, s: u32, proxies: &[Proxy], checks: &mut [ServerCheckState], log: &mut LogFn<'_>, acts: &mut Vec<SrvAct>) {
    acts.push(SrvAct::Unlink(p, s));
    let Some(px) = proxies.get(p as usize) else { return };
    if !px.server_rmaint(s as usize) {
        let req = Req { proxy: p, server: s, opts: ResolveOpts::default(), attached: None };
        enter_rmaint(&req, Cause::NoEnt, proxies, checks, log);
    }
    px.set_server_srv_fqdn(s as usize, None);
    px.servers.set(s as usize, SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0));
    if let Some(rq) = rqs.iter_mut().find(|q| q.proxy == p) {
        rq.free.push(s);
    }
}

/// `srvrq_resolution_error_cb`: an SRV resolution that failed for longer than the hold of its
/// status since the last valid answer drops every record and its slots.
#[allow(clippy::too_many_arguments)]
fn srv_error(r: &mut Resolution, e: &DnsError, holds: &Holds, now: Instant, proxies: &[Proxy], checks: &mut [ServerCheckState], log: &mut LogFn<'_>, acts: &mut Vec<SrvAct>) {
    let (cause, hold) = match e {
        DnsError::NxDomain => (Cause::Nx, holds.nx),
        DnsError::Refused => (Cause::Refused, holds.refused),
        DnsError::Timeout => (Cause::Timeout, holds.timeout),
        DnsError::Other | DnsError::Invalid => (Cause::Unspec, holds.other),
    };
    r.status = Status::Error(cause);
    if r.last_valid.is_some_and(|lv| now < lv + hold) {
        return;
    }
    let Some(st) = r.srv.as_deref_mut() else { return };
    for it in std::mem::take(&mut st.items) {
        for (p, s) in it.slots {
            srv_cleanup(&mut st.rqs, p, s, proxies, checks, log, acts);
        }
    }
}

/// The counter `resolv_process_responses` bumps for a datagram (`resolvers.c:2398-2486`).
fn received_counter(r: alcyon_dns::Received) -> usize {
    use alcyon_dns::Received as R;
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
            log(p, LogLevel::Notice, &format!("{}/{srv}: IP changed from '{from}' to '{ip}' by '{by}'.", px.name), true);
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
/// hold of the status ran out since `last_valid`, which starts at the resolution's creation, T510).
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
                Cause::NoIp | Cause::Unspec | Cause::NoEnt => holds.other,
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
    // The operator's maintenance or drain (not one inherited from a tracked server) is kept
    // under `RMAINT` and taken back when the name resolves again.
    let own = !crate::track::inherited(px, s);
    let kept = match ServerStatus::from(before) {
        ServerStatus::Maint if own => ServerStatus::Maint,
        ServerStatus::Drain if own => ServerStatus::Drain,
        _ if before == DRAIN_DOWN && own => ServerStatus::Drain,
        _ => ServerStatus::Up,
    };
    px.set_server_rmaint(s, Some(kept));
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
    log(p, if before == ServerStatus::Up as u8 || before == ServerStatus::Drain as u8 { LogLevel::Alert } else { LogLevel::Notice }, &msg, true);
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
    let saved = px.server_rmaint_kept(s);
    px.set_server_rmaint(s, None);
    crate::track::set_admin(proxies, checks, p, s, saved, crate::srvlog::Cause::Dns);
    let srv = &px.server_ids[s];
    let backup = if px.server_backups.get(s).copied().unwrap_or(false) { "Backup " } else { "" };
    let after = status_of(px, s);
    let msg = if saved == ServerStatus::Maint {
        format!("{backup}Server {}/{srv} ('{fqdn}') resolves again but remains in maintenance.", px.name)
    } else {
        let op = if after == ServerStatus::Down as u8 || after == DRAIN_DOWN { "DOWN" } else { "UP" };
        let adm = if saved == ServerStatus::Drain { "DRAIN" } else { "READY" };
        format!("{backup}Server {}/{srv} ('{fqdn}') is {op}/{adm} (resolves again).", px.name)
    };
    log(p, LogLevel::Notice, &msg, true);
    if saved == ServerStatus::Drain {
        log(p, LogLevel::Notice, &format!("{backup}Server {}/{srv} remains in forced drain mode.", px.name), true);
    }
    log(p, LogLevel::Notice, &format!("Server {}/{srv} administratively READY thanks to valid DNS answer.", px.name), true);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T489: what `do-resolve` asks (`resolv_hostname_validation`) and the bounded cache.
    #[test]
    fn do_resolve_names_and_cache() {
        let mut out = [0u8; DR_NAME_MAX];
        assert_eq!(dr_name(b"A1.Test.", &mut out), Some(7));
        assert_eq!(&out[..7], b"a1.test");
        for bad in [&b""[..], b".", b"a..b", b"a b", &[b'a'; 64][..], &[b'a'; 255][..]] {
            assert_eq!(dr_name(bad, &mut out), None, "{bad:?}");
        }
        let long: Vec<u8> = std::iter::repeat_n(&b"abcdefghi."[..], 25).flatten().copied().chain(*b"abcd").collect();
        assert_eq!(dr_name(&long, &mut out), Some(254));
        // One bucket of DR_WAYS: a fifth key evicts the oldest.
        let mut c = Box::new(DrCache { buckets: vec![[None; DR_WAYS]; 1], seq: 0 });
        let t0 = Instant::now();
        let mut m = DrMsg::try_new_inner();
        for i in 0..=DR_WAYS {
            m.len = dr_name(format!("n{i}.test").as_bytes(), &mut m.name).expect("name");
            m.hold = Duration::from_secs(10);
            c.insert(&m, t0 + Duration::from_millis(u64::try_from(i).expect("i")));
        }
        assert!(c.find(0, false, b"n0.test").is_none());
        assert!(c.find(0, false, b"n4.test").is_some());
        // The same key again takes its own slot.
        c.insert(&m, t0 + Duration::from_secs(1));
        assert_eq!(c.buckets[0].iter().flatten().count(), DR_WAYS);
        assert!(alcyon_alloc::Poolable::footprint(&c) >= DR_WAYS * std::mem::size_of::<DrEntry>());
        alcyon_alloc::Poolable::reset(&mut c, false);
        assert!(c.find(0, false, b"n4.test").is_none());
        assert_eq!(dr_pick([ip("10.0.0.1"), ip("2001:db8::1")].into_iter(), false, Families::BOTH), Some(ip("2001:db8::1")));
        assert_eq!(dr_wait_unpack(0), None);
        assert_eq!(dr_wait_pack(300, 5), 0);
        let m = dr_mark();
        assert_eq!(dr_wait_unpack(dr_wait_pack(3, m)), Some((3, m)));
        assert_eq!(dr_pick([ip("2001:db8::1")].into_iter(), true, Families::IPV4), None);
    }

    /// Every `Received` bumps the counter of its name (`resolvers.c:2398-2486`).
    #[test]
    fn a_received_class_names_its_counter() {
        use alcyon_dns::Received as R;
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
        use alcyon_alloc::Poolable;
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
            srv: None,
        }
    }

    fn req(proxy: u32, server: u32, opts: ResolveOpts) -> Req {
        Req { proxy, server, opts, attached: None }
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

    /// T527: a `do-resolve` question that gets no message id (100 draws all taken by a
    /// resolution in flight) is answered with nothing now, like one the nameservers fail.
    #[test]
    fn do_resolve_without_a_free_message_id_is_answered_empty() {
        let cfg = alcyon_config::ast::ResolversSection::new("r".into(), 1);
        let mut sched = alcyon_sched::Scheduler::with_capacity(8);
        let mut fdtab = crate::fdtab::FdTab::with_capacity(8);
        let poller = crate::poller::Poller::new(4).expect("poller");
        let mut sec = Section::new(&cfg, 0, &mut sched, &mut fdtab, &poller, alcyon_sched::Tick(1)).expect("section");
        // A nameserver nobody listens on, and ids that always collide.
        sec.dns = alcyon_dns::Resolver::new(alcyon_dns::ResolverConfig { nameservers: vec!["127.0.0.1:9".parse().expect("addr")], random_id: || 7, ..alcyon_dns::ResolverConfig::default() });
        let ask = |sec: &mut Section, name: &[u8]| {
            let mut m = DR_MSG_POOL.take().expect("message");
            m.len = dr_name(name, &mut m.name).expect("name");
            sec.do_resolve(m)
        };
        assert!(ask(&mut sec, b"a.test").is_none(), "the first waits for the nameserver");
        let m = ask(&mut sec, b"b.test").expect("answered at once");
        assert_eq!((m.answer, m.hold), (None, Duration::ZERO));
    }
}

// ---------------------------------------------------------------------------------------------
// `do-resolve` (T489): `resolv_action_do_resolve`, `resolvers.c:3257`.
//
// A rule asks its worker's cache first (no lock, no allocation: a hit sets the variable and
// the rule goes on). A miss posts one pooled message to worker 0, which owns the sections:
// worker 0 answers from its own cache, from a server resolution of the same name whose last
// valid answer is younger than `hold valid` (`HAProxy` shares the resolution), or asks the
// nameservers; the reply comes back in the same message, goes into the asking worker's cache
// and wakes the stream, which reads it there. The caches are bounded
// (`tune.resolvers.cache-size`, Alcyon-only), since their keys come from requests.

/// The longest name `do-resolve` asks (`DNS_MAX_NAME_SIZE`).
pub const DR_NAME_MAX: usize = 255;

/// One `do-resolve` question and, on its way back, its answer.
pub struct DrMsg {
    /// The worker that asked, and the stream task to wake there.
    pub wid: usize,
    pub task: alcyon_sched::task::TaskRef,
    /// The section, as its index in the configuration's `resolvers`.
    pub section: u32,
    pub prefer_ipv4: bool,
    name: [u8; DR_NAME_MAX],
    len: u8,
    /// The answer: `Some(ip)` for a valid one with an address of an accepted family.
    pub answer: Option<IpAddr>,
    /// How long a valid answer stays fresh (`hold valid`); zero for an error.
    pub hold: Duration,
}

impl DrMsg {
    #[cfg(test)]
    fn try_new_inner() -> Box<Self> {
        <Box<Self> as alcyon_alloc::Poolable>::try_new().expect("message")
    }

    /// The name, lower case as it was stored.
    #[must_use]
    pub fn name(&self) -> &str {
        std::str::from_utf8(&self.name[..usize::from(self.len)]).unwrap_or("")
    }
}

alcyon_alloc::declare_pool!(
    /// `show pools` `do_resolve`: the messages of the `do-resolve` cache misses between a worker
    /// and worker 0 (one in flight per waiting stream).
    static DR_MSG_POOL: Pool<Box<DrMsg>> = alcyon_alloc::PoolSpec::new("do_resolve");
);

impl alcyon_alloc::Poolable for Box<DrMsg> {
    fn footprint(&self) -> usize {
        std::mem::size_of::<DrMsg>()
    }

    fn reset(&mut self, _wipe: bool) {
        self.len = 0;
        self.answer = None;
    }

    fn try_new() -> Option<Self> {
        Some(Box::new(DrMsg {
            wid: 0,
            task: alcyon_sched::task::TaskRef(0),
            section: 0,
            prefer_ipv4: false,
            name: [0; DR_NAME_MAX],
            len: 0,
            answer: None,
            hold: Duration::ZERO,
        }))
    }
}

/// One cached answer.
#[derive(Clone, Copy)]
struct DrEntry {
    hash: u64,
    section: u32,
    prefer_ipv4: bool,
    len: u8,
    name: [u8; DR_NAME_MAX],
    answer: Option<IpAddr>,
    /// When the answer came; fresh until `exp` (a failure is never fresh, but the streams that
    /// waited for it read it by `at`).
    at: Instant,
    exp: Instant,
    /// The cache's insert count when it came in: a waiting stream takes what came after it asked.
    seq: u32,
}

/// Entries per bucket: a bucket is searched whole, and its oldest entry is replaced.
const DR_WAYS: usize = 4;

/// A worker's `do-resolve` cache: buckets of [`DR_WAYS`] entries, sized once.
pub struct DrCache {
    buckets: Vec<[Option<DrEntry>; DR_WAYS]>,
    /// Answers inserted so far (wrapping).
    seq: u32,
}

alcyon_alloc::declare_pool!(
    /// `show pools` `do_resolve_cache`: one per worker that ran a `do-resolve` rule.
    static DR_CACHE_POOL: Pool<Box<DrCache>> = alcyon_alloc::PoolSpec::new("do_resolve_cache");
);

impl alcyon_alloc::Poolable for Box<DrCache> {
    fn footprint(&self) -> usize {
        std::mem::size_of::<DrCache>() + self.buckets.capacity() * std::mem::size_of::<[Option<DrEntry>; DR_WAYS]>()
    }

    fn reset(&mut self, _wipe: bool) {
        self.buckets.iter_mut().for_each(|b| *b = [None; DR_WAYS]);
    }

    fn try_new() -> Option<Self> {
        let n = (DR_CACHE_SIZE.load(std::sync::atomic::Ordering::Relaxed).max(1)).div_ceil(DR_WAYS).next_power_of_two();
        Some(Box::new(DrCache { buckets: vec![[None; DR_WAYS]; n], seq: 0 }))
    }
}

/// `tune.resolvers.cache-size` (entries per worker), set by [`build`].
static DR_CACHE_SIZE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1024);

/// FNV-1a of the key (no allocation, no seed: the key is bounded and lands in one bucket of
/// four, so a flood of colliding names only evicts within that bucket).
fn dr_hash(section: u32, prefer_ipv4: bool, name: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in section.to_le_bytes().into_iter().chain([u8::from(prefer_ipv4)]).chain(name.iter().copied()) {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

impl DrCache {
    fn find(&self, section: u32, prefer_ipv4: bool, name: &[u8]) -> Option<&DrEntry> {
        let h = dr_hash(section, prefer_ipv4, name);
        let b = &self.buckets[usize::try_from(h).unwrap_or(0) & (self.buckets.len() - 1)];
        b.iter().flatten().find(|e| e.hash == h && e.section == section && e.prefer_ipv4 == prefer_ipv4 && &e.name[..usize::from(e.len)] == name)
    }

    fn insert(&mut self, m: &DrMsg, now: Instant) {
        let name = &m.name[..usize::from(m.len)];
        let h = dr_hash(m.section, m.prefer_ipv4, name);
        let mask = self.buckets.len() - 1;
        let b = &mut self.buckets[usize::try_from(h).unwrap_or(0) & mask];
        let same = |e: &DrEntry| e.hash == h && e.section == m.section && e.prefer_ipv4 == m.prefer_ipv4 && &e.name[..usize::from(e.len)] == name;
        let slot = b
            .iter()
            .position(|e| e.as_ref().is_some_and(same))
            .or_else(|| b.iter().position(Option::is_none))
            .unwrap_or_else(|| (0..DR_WAYS).min_by_key(|&i| b[i].map(|e| e.at)).unwrap_or(0));
        self.seq = self.seq.wrapping_add(1);
        b[slot] = Some(DrEntry { hash: h, section: m.section, prefer_ipv4: m.prefer_ipv4, len: m.len, name: m.name, answer: m.answer, at: now, exp: now + m.hold, seq: self.seq });
    }
}

thread_local! {
    /// This worker's cache and the mailboxes to reach worker 0 (set by the engine).
    static DR_LOCAL: std::cell::RefCell<Option<alcyon_alloc::PoolBox<Box<DrCache>>>> = const { std::cell::RefCell::new(None) };
    static DR_MAILBOXES: std::cell::RefCell<Option<std::sync::Arc<crate::mailbox::Mailboxes>>> = const { std::cell::RefCell::new(None) };
}

thread_local! {
    /// The stream task whose `tcp-request content` rules run now (a `do-resolve` wakes it).
    static DR_TASK: std::cell::Cell<alcyon_sched::task::TaskRef> = const { std::cell::Cell::new(alcyon_sched::task::TaskRef(0)) };
}

/// Names the stream task the next `tcp-request content` rules run for.
pub fn dr_set_task(t: alcyon_sched::task::TaskRef) {
    DR_TASK.set(t);
}

/// The stream task [`dr_set_task`] named.
#[must_use]
pub fn dr_task() -> alcyon_sched::task::TaskRef {
    DR_TASK.get()
}

/// The engine of this worker reaches the others through `boxes`.
pub fn dr_set_mailboxes(boxes: &std::sync::Arc<crate::mailbox::Mailboxes>) {
    DR_MAILBOXES.with(|m| *m.borrow_mut() = Some(std::sync::Arc::clone(boxes)));
}

fn with_cache<R>(f: impl FnOnce(&mut DrCache) -> R) -> Option<R> {
    DR_LOCAL.with(|c| {
        let mut c = c.borrow_mut();
        if c.is_none() {
            DR_CACHE_POOL.register();
            *c = DR_CACHE_POOL.take();
        }
        c.as_mut().map(|b| f(b))
    })
}

/// What a `do-resolve` rule does now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrStep {
    /// Done: store this address in the variable (`None`: nothing to store) and go on.
    Done(Option<IpAddr>),
    /// Asked: wait for the answer.
    Wait,
}

/// A `do-resolve` question in the form `HAProxy` asks it (`resolv_str_to_dn_label` +
/// `resolv_hostname_validation`): lower case, no final dot, labels of 1 to 63 letters, digits,
/// `-` or `_`, 255 bytes at most. `None`: the action is ignored.
fn dr_name(name: &[u8], out: &mut [u8; DR_NAME_MAX]) -> Option<u8> {
    let name = name.strip_suffix(b".").unwrap_or(name);
    if name.is_empty() || name.len() > DR_NAME_MAX - 1 {
        return None;
    }
    for l in name.split(|b| *b == b'.') {
        if l.is_empty() || l.len() > 63 || !l.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_') {
            return None;
        }
    }
    for (o, b) in out.iter_mut().zip(name) {
        *o = b.to_ascii_lowercase();
    }
    u8::try_from(name.len()).ok()
}

/// The first visit of a `do-resolve` rule on `name` (section `section`): a fresh answer in this
/// worker's cache, or a question posted to worker 0 for the stream task `task` (`Wait`).
pub fn dr_start(section: u32, prefer_ipv4: bool, name: &[u8], task: alcyon_sched::task::TaskRef, now: Instant) -> DrStep {
    let mut key = [0u8; DR_NAME_MAX];
    let Some(len) = dr_name(name, &mut key) else { return DrStep::Done(None) };
    let k = &key[..usize::from(len)];
    if let Some(Some(ip)) = with_cache(|c| c.find(section, prefer_ipv4, k).filter(|e| now < e.exp).map(|e| e.answer)) {
        return DrStep::Done(ip);
    }
    let Some(boxes) = DR_MAILBOXES.with(|m| m.borrow().clone()) else { return DrStep::Done(None) };
    let Some(mut m) = DR_MSG_POOL.take() else { return DrStep::Done(None) };
    m.wid = crate::engine::worker_id();
    m.task = task;
    m.section = section;
    m.prefer_ipv4 = prefer_ipv4;
    m.name = key;
    m.len = len;
    m.answer = None;
    m.hold = Duration::ZERO;
    boxes.post(0, crate::mailbox::Msg::DoResolve(m));
    DrStep::Wait
}

/// The mark a stream keeps when [`dr_start`] asked: [`dr_poll`] takes the answers after it.
#[must_use]
pub fn dr_mark() -> u32 {
    with_cache(|c| c.seq).unwrap_or(0)
}

/// `TcpSession::dr_wait` for rule `rule` waiting since mark `mark`; 0 (nothing) when the rule
/// index does not fit (a 255th rule waits no more than it would without the mark: it asks again).
#[must_use]
pub fn dr_wait_pack(rule: usize, mark: u32) -> u32 {
    u32::try_from(rule + 1).ok().filter(|r| *r < 256).map_or(0, |r| r << 24 | (mark & 0x00ff_ffff))
}

/// The rule and mark of [`dr_wait_pack`], `None` for 0. The mark comes back as the full
/// counter value nearest below the current one with the same low 24 bits.
#[must_use]
pub fn dr_wait_unpack(w: u32) -> Option<(usize, u32)> {
    let rule = usize::try_from(w >> 24).ok().filter(|r| *r > 0)? - 1;
    let low = w & 0x00ff_ffff;
    let now = dr_mark();
    Some((rule, now.wrapping_sub(now.wrapping_sub(low) & 0x00ff_ffff)))
}

/// A `do-resolve` rule woken after [`dr_start`] asked at mark `asked`: the answer if it came.
pub fn dr_poll(section: u32, prefer_ipv4: bool, name: &[u8], asked: u32) -> Option<Option<IpAddr>> {
    let mut key = [0u8; DR_NAME_MAX];
    let len = dr_name(name, &mut key)?;
    // Inserted after the mark, modulo the wrap (half the range is "after").
    let after = |e: &&DrEntry| e.seq.wrapping_sub(asked).wrapping_sub(1) < u32::MAX / 2;
    with_cache(|c| c.find(section, prefer_ipv4, &key[..usize::from(len)]).filter(after).map(|e| e.answer)).flatten()
}

/// The answer to a question this worker asked: into the cache, and the stream woken.
pub fn dr_answered(m: &DrMsg) -> alcyon_sched::task::TaskRef {
    let now = Instant::now();
    with_cache(|c| c.insert(m, now));
    m.task
}

/// The address `do-resolve` takes from an answer (`resolv_get_ip_from_response` with the
/// rule's family preference): the first of the preferred family, else the first accepted.
fn dr_pick(ips: impl Iterator<Item = IpAddr> + Clone, prefer_ipv4: bool, fam: Families) -> Option<IpAddr> {
    let ok = |ip: &IpAddr| if ip.is_ipv4() { fam.ipv4 } else { fam.ipv6 };
    ips.clone().filter(ok).find(|ip| ip.is_ipv4() == prefer_ipv4).or_else(|| ips.filter(ok).next())
}

/// A `do-resolve` question waiting for the nameservers on worker 0.
pub(crate) struct DrPending {
    qid: QueryId,
    // Pooled messages (`DR_MSG_POOL`), held until the answer.
    #[allow(clippy::vec_box)]
    waiters: Vec<alcyon_alloc::PoolBox<Box<DrMsg>>>,
}

impl Section {
    /// The configuration index of this section (its [`DrMsg::section`]).
    #[must_use]
    pub fn config_index(&self) -> u32 {
        usize_to_u32(self.stats_idx)
    }

    /// Worker 0's side of a `do-resolve` miss: the answer now (from this worker's cache or a
    /// server resolution younger than `hold valid`), or the message kept until the
    /// nameservers answer. Returns the message when it is answered.
    pub fn do_resolve(&mut self, mut m: alcyon_alloc::PoolBox<Box<DrMsg>>) -> Option<alcyon_alloc::PoolBox<Box<DrMsg>>> {
        let now = Instant::now();
        let name_buf = m.name;
        let name = &name_buf[..usize::from(m.len)];
        if let Some(Some(e)) = with_cache(|c| c.find(m.section, m.prefer_ipv4, name).filter(|e| now < e.exp).copied()) {
            m.answer = e.answer;
            m.hold = e.exp - now;
            return Some(m);
        }
        let fam = active_families(now);
        let ty = first_type(fam, m.prefer_ipv4);
        let fresh = |r: &&Box<Resolution>| {
            r.srv.is_none() && r.prefer == ty && r.status == Status::Valid && r.last_valid.is_some_and(|t| now.duration_since(t) < self.holds.valid) && r.name.as_bytes().eq_ignore_ascii_case(name)
        };
        if let Some(r) = self.resolutions.iter().find(fresh) {
            m.answer = dr_pick(r.items.iter().map(|i| i.ip), m.prefer_ipv4, fam);
            m.hold = self.holds.valid.saturating_sub(r.last_valid.map_or(Duration::ZERO, |t| now.duration_since(t)));
            return Some(m);
        }
        if let Some(p) = self.dr_pending.iter_mut().find(|p| p.waiters.first().is_some_and(|w| w.section == m.section && w.prefer_ipv4 == m.prefer_ipv4 && w.name == m.name)) {
            p.waiters.push(m);
            return None;
        }
        let prefer = if ty == TYPE_A { Family::Ipv4 } else { Family::Ipv6 };
        let accept = Families { ipv4: fam.ipv4 || prefer == Family::Ipv4, ipv6: fam.ipv6 || prefer == Family::Ipv6 };
        match self.dns.query(now, m.name(), Question::Addr { accept, prefer }, Requester::DoResolve) {
            Ok(qid) => {
                let mut waiters = Vec::with_capacity(1);
                waiters.push(m);
                self.dr_pending.push(DrPending { qid, waiters });
                None
            }
            Err(_) => {
                m.answer = None;
                m.hold = Duration::ZERO;
                Some(m)
            }
        }
    }

    /// The answered `do-resolve` messages, for the engine to send back.
    pub fn take_dr_answers(&mut self) -> Vec<alcyon_alloc::PoolBox<Box<DrMsg>>> {
        std::mem::take(&mut self.dr_done)
    }

    /// A result of the crate for a `do-resolve` question: every waiter gets it.
    fn dr_result(&mut self, qid: QueryId, res: &Result<Vec<Answer>, DnsError>, now: Instant) -> bool {
        let Some(i) = self.dr_pending.iter().position(|p| p.qid == qid) else { return false };
        let p = self.dr_pending.swap_remove(i);
        let fam = active_families(now);
        for mut m in p.waiters {
            match res {
                Ok(answers) => {
                    let ips = answers.iter().filter_map(|a| match a.rdata {
                        Rdata::A(v4) => Some(IpAddr::from(v4)),
                        Rdata::Aaaa(v6) => Some(IpAddr::from(v6)),
                        _ => None,
                    });
                    m.answer = dr_pick(ips, m.prefer_ipv4, fam);
                    m.hold = self.holds.valid;
                }
                Err(_) => {
                    m.answer = None;
                    m.hold = Duration::ZERO;
                }
            }
            with_cache(|c| c.insert(&m, now));
            self.dr_done.push(m);
        }
        true
    }
}
