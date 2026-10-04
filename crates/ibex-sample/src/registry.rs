// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/sample.c, src/http_fetch.c, src/http_conv.c,
// src/payload.c, src/ssl_sample.c and include/haproxy/sample.h.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Registries for Sample Fetches and Sample Converters.

#![forbid(unsafe_code)]

use crate::cast::cast;
use crate::hash::{
    full_hash, hash_crc32, hash_crc32c, hash_djb2, hash_sdbm, hash_wt6, hash_xxh3, hash_xxh32,
    hash_xxh64, md5_digest, sha1_digest, sha224_digest, sha256_digest, sha384_digest,
    sha512_digest,
};
use crate::sample::{Sample, SampleType, TypeSpec};
use ibex_proto::htx::{Htx, HtxSliceRef};

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, LazyLock, RwLock};

thread_local! {
    pub static CURRENT_VARS: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
    /// The timeouts of the stream running on the thread, for the `*_timeout` fetches; set
    /// by the engine for the length of one run of a stream, `None` outside one.
    pub static CURRENT_TIMEOUTS: Cell<Option<StreamTimeouts>> = const { Cell::new(None) };
    pub static CURRENT_RES_HEADERS: RefCell<Vec<(String, String)>> = const { RefCell::new(Vec::new()) };
    pub static CURRENT_RES_STATUS: Cell<u16> = const { Cell::new(0) };
}

/// The timeouts a `set-timeout` names, as indexes into [`StreamTimeouts`]' arrays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutKind {
    Client = 0,
    Server = 1,
    Connect = 2,
    Queue = 3,
    Tunnel = 4,
    Tarpit = 5,
}

impl TimeoutKind {
    /// The kind `set-timeout <name>` names.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "client" => Self::Client,
            "server" => Self::Server,
            "connect" => Self::Connect,
            "queue" => Self::Queue,
            "tunnel" => Self::Tunnel,
            "tarpit" => Self::Tarpit,
            _ => return None,
        })
    }
}

/// One stream's timeouts, in ms (0: none), indexed by [`TimeoutKind`]: its frontend's
/// (`fe_*_timeout`), its backend's (`be_*_timeout`, the frontend's until one is chosen) and
/// the ones it runs on (`cur_*_timeout`: the backend's, or what `set-timeout` set). `Copy`:
/// the engine computes it for each run of a stream, from the stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamTimeouts {
    pub fe: [u32; 6],
    pub be: [u32; 6],
    pub cur: [u32; 6],
}

pub static GLOBAL_PROC_VARS:LazyLock<RwLock<HashMap<String, String>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

pub static SAMPLE_REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

#[must_use]
pub fn sample_registry() -> &'static Registry {
    &SAMPLE_REGISTRY
}

#[must_use]
pub fn get_proc_var(name: &str) -> Option<String> {
    GLOBAL_PROC_VARS.read().ok()?.get(name).cloned()
}

/// The conditions of `set-var(<name>,<cond>...)` against what is known of the variable and the
/// sample (`var_set`, src/vars.c): `exists`/`is_set` describe the variable, `empty` the new
/// sample. `ifgt` and `iflt` are refused when the configuration loads.
#[must_use]
pub fn var_conds_hold(spec: &str, exists: bool, is_set: bool, empty: bool) -> bool {
    spec.split(',').skip(1).all(|c| {
        (c != "ifexists" || exists)
            && (c != "ifnotexists" || !exists)
            && (c != "ifset" || is_set)
            && (c != "ifnotset" || !is_set)
            && (c != "ifempty" || empty)
            && (c != "ifnotempty" || !empty)
    })
}

/// `unset-var` of a process variable: it stays declared but has no value.
pub fn unset_proc_var(name: &str) {
    if let Ok(mut lock) = GLOBAL_PROC_VARS.write() {
        lock.remove(name);
    }
}

/// Where `debug()` writes a line: the runtime's event sinks, given the sink's name.
pub type DebugSinkFn = fn(&str, &[u8]);

static DEBUG_SINK: std::sync::OnceLock<DebugSinkFn> = std::sync::OnceLock::new();

/// Sets the writer `debug()` sends its lines to.
pub fn set_debug_sink(f: DebugSinkFn) {
    let _ = DEBUG_SINK.set(f);
}

thread_local! {
    /// The destinations named by the `debug()` converters checked on this thread since the
    /// last `take_debug_destinations`, for the runtime to check against its sinks.
    static DEBUG_DESTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// The destinations `debug()` converters named while their arguments were checked.
pub fn take_debug_destinations() -> Vec<String> {
    DEBUG_DESTS.with(|d| std::mem::take(&mut *d.borrow_mut()))
}

pub fn set_proc_var(name: &str, val: String) {
    if let Ok(mut lock) = GLOBAL_PROC_VARS.write() {
        lock.insert(name.to_string(), val);
    }
}


// Not generalised over the hasher: these write straight into a thread-local declared as
// `HashMap<String, String>` with the default hasher, so a generic `S` could not be stored
// without converting the map anyway.
#[allow(clippy::implicit_hasher)]
pub fn set_current_vars(vars: HashMap<String, String>) {
    CURRENT_VARS.with(|v| *v.borrow_mut() = vars);
}

pub fn set_current_res_headers(headers: Vec<(String, String)>) {
    CURRENT_RES_HEADERS.with(|h| *h.borrow_mut() = headers);
}

pub fn set_current_res_status(status: u16) {
    CURRENT_RES_STATUS.set(status);
}

#[inline]
fn u64_to_sint(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

#[inline]
fn len_to_sint(len: usize) -> i64 {
    i64::try_from(len).unwrap_or(i64::MAX)
}

/// Set once the process is stopping (`when(stopping)`).
pub static STOPPING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The stream state `when()` conditions read (`sample_conv_when`, src/sample.c).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamFacts {
    /// An error was met: a 5xx status, or a failed connection (the `dontlog-normal` rule).
    pub error: bool,
    /// A connection to a server was attempted for the request.
    pub forwarded: bool,
    /// An applet is serving the request.
    pub toapplet: bool,
}

/// Runtime context passed into sample fetch functions during evaluation.
#[derive(Debug, Clone, Default)]
pub struct SampleContext<'a> {
    /// Evaluated for the access log, after the request buffer is gone: `method` reads
    /// only the transaction's method enum then, so a method outside it has no value.
    pub at_log: bool,
    pub client_addr: Option<SocketAddr>,
    pub server_addr: Option<SocketAddr>,
    pub fc_src: Option<SocketAddr>,
    pub fc_dst: Option<SocketAddr>,
    pub proxy_tlvs: Option<&'a [u8]>,
    pub htx: Option<&'a Htx>,
    pub htx_slice: Option<HtxSliceRef<'a>>,
    pub req_uri: Option<&'a str>,
    pub req_method: Option<&'a str>,
    pub req_headers: Option<&'a [(String, String)]>,
    pub req_version: Option<&'a str>,
    pub req_body: Option<&'a [u8]>,
    /// The raw buffer of a TCP stream, for the fetches that parse it (`req.ssl_*`,
    /// `req.rdp_cookie`, `payload_lv`): the request's and the response's. `None` for an HTTP
    /// stream, where `HAProxy` has no raw buffer to read.
    pub raw_req: Option<&'a [u8]>,
    pub raw_res: Option<&'a [u8]>,
    pub res_version: Option<&'a str>,
    pub res_headers: Option<&'a [(String, String)]>,
    pub res_status: Option<u16>,
    pub res_body: Option<&'a [u8]>,
    pub fe_id: Option<u32>,
    pub fe_name: Option<&'a str>,
    pub be_id: Option<u32>,
    pub be_name: Option<&'a str>,
    pub srv_id: Option<u32>,
    pub srv_name: Option<&'a str>,
    pub so_id: Option<u32>,
    pub so_name: Option<&'a str>,
    pub fc_rtt: Option<u32>,
    pub fc_rttvar: Option<u32>,
    pub bc_rtt: Option<u32>,
    pub bc_rttvar: Option<u32>,
    /// Capture slots: `None` where nothing was captured (a header that was absent).
    pub captures_req_hdr: Option<&'a [Option<Vec<u8>>]>,
    pub captures_res_hdr: Option<&'a [Option<Vec<u8>>]>,
    /// The stream's unique ID (`unique-id-format`), for the `unique-id` fetch.
    pub unique_id: Option<&'a str>,
    /// The file and line of the last rule that ended a rule set for the request
    /// (`last_rule_file`, `last_rule_line`); `None` where no rule did.
    pub last_rule: Option<(&'a str, u32)>,
    /// The stream's priority class and offset (`prio_class`, `prio_offset`).
    pub prio: (i32, i32),
    /// When the stream was accepted, as unix seconds and milliseconds: `accept_date`.
    pub accept_date: Option<(i64, u32)>,
    /// What `when()` reads of the stream; `None` is a stream that has done nothing yet.
    pub stream: Option<StreamFacts>,
    /// The proxy's ACLs, for `when(acl,<name>)`; `None` where the caller has none, and the
    /// condition then gives no sample.
    pub acls: Option<&'a HashMap<String, crate::expr::Expr>>,
    pub is_first_req: bool,
    pub vars: Option<&'a HashMap<String, String>>,
    pub timeouts: Option<&'a HashMap<String, u32>>,
    /// The backend's `retries`, for `be_max_retries`.
    pub be_max_retries: Option<u16>,
    /// The stream's retry budget, for `cur_max_retries`: what `set-retries` changes.
    pub cur_max_retries: Option<u16>,
    pub act_conn: u32,
    /// The client connection's TLS session, for `ssl_fc*` and `ssl_c_used`; the default
    /// (`used` false, nothing else) for a plaintext one.
    pub ssl_fc: SslFacts<'a>,
    /// The server connection's TLS session, for `ssl_bc*`; `None` where there is no TLS
    /// server connection (a plaintext one, or none yet).
    pub ssl_bc: Option<SslFacts<'a>>,
    /// The proxies' live state, for the fetches and converters that read it (`nbsrv`,
    /// `srv_is_up`, `srv_conn`, `fe_exists`, `in_table`, ...). `None` where the caller
    /// has none to give, and those fetches then return no sample -- never a guess.
    pub proxies: Option<&'a dyn ProxyState>,
    /// The stream's tracked stick-table entries, for the `sc_*` and `src_*` fetches. `None`
    /// where the caller has none, and those fetches then give no sample.
    pub stick: Option<&'a dyn StickState>,
}

/// What a TLS session tells the `ssl_*` fetches, as the transport knows it once the
/// handshake is done (`TlsInfo`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SslFacts<'a> {
    /// The connection is TLS (`ssl_fc`; for the server side, it is the `Some` of the field).
    pub used: bool,
    /// The server name the client sent (`ssl_fc_sni`).
    pub sni: Option<&'a str>,
    /// The negotiated cipher suite, in OpenSSL's name for it (`ssl_fc_cipher`).
    pub cipher: Option<&'a str>,
    /// The negotiated protocol, `TLSv1.3` (`ssl_fc_protocol`).
    pub protocol: Option<&'a str>,
    /// The peer sent a certificate (`ssl_c_used`).
    pub has_crt: bool,
}

/// One server's live state, as the server fetches read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerState {
    /// `smp_fetch_srv_is_up`: not in maintenance, and not DOWN by its health check (a
    /// server without a check, or with weight 0, is up).
    pub is_up: bool,
    /// The streams currently on the server (`srv->cur_sess`).
    pub cur_sess: u32,
    /// `maxconn`; `None` for unlimited.
    pub maxconn: Option<u32>,
    /// The streams assigned to the server over the last second (`srv_sess_rate`).
    pub sess_rate: i64,
}

/// A frontend counter, for [`ProxyState::frontend_counter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontendCounter {
    /// The connections open on the frontend now (`fe_conn`, `feconn`).
    Conn,
    /// The sessions it accepted over the last second (`fe_sess_rate`).
    SessRate,
    /// The HTTP requests it received over the last second (`fe_req_rate`).
    ReqRate,
}

/// A data type of a stick-table entry, as the `sc_*` and `src_*` fetches read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StickData {
    ConnCnt,
    ConnCur,
    ConnRate,
    SessCnt,
    HttpReqCnt,
    HttpReqRate,
    HttpErrCnt,
    HttpErrRate,
    /// `bytes_in_cnt`, in kilobytes (`bytes >> 10`).
    KbytesIn,
    KbytesOut,
    Gpc0,
    Gpc1,
    Gpt0,
    /// `gpc0_rate` and `gpc1_rate`.
    Gpc0Rate,
    Gpc1Rate,
    /// An element of the array of `gpc(<n>)`, of `gpc_rate(<n>,<period>)`, of `gpt(<n>)`.
    GpcIdx(usize),
    GpcRateIdx(usize),
    GptIdx(usize),
    SessRate,
    BytesInRate,
    BytesOutRate,
    HttpFailCnt,
    HttpFailRate,
    GlitchCnt,
    GlitchRate,
    /// The streams that track the entry (`sc_trackers`, `table_trackers`).
    Trackers,
    /// `table_server_id`: the server the entry sticks to, 0 for none.
    ServerId,
    /// `table_expire`: the milliseconds before the entry expires.
    Expire,
    /// `table_idle`: the milliseconds since the entry was last used.
    Idle,
}

/// The general purpose counter a write names: `gpc0`, `gpc1`, or an element of `gpc(<n>)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StickGpc {
    Zero,
    One,
    Idx(usize),
}

/// What a fetch writes to a stick-table entry (`inc_gpc`, `clr_gpc`, `src_updt_conn_cnt`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StickOp {
    /// `src_updt_conn_cnt`: one more connection counted; gives the new count.
    UpdtConnCnt,
    /// `*_inc_gpc*`: one more; gives the new value.
    IncGpc(StickGpc),
    /// `*_clr_gpc*`: back to 0; gives the previous value.
    ClrGpc(StickGpc),
}

/// The stick-table entries a stream tracks, which the `sc_*`, `sc[0-9]_*` and `src_*`
/// fetches read, provided through [`SampleContext::stick`].
///
/// Both answer as `HAProxy` does: `None` where there is no sample (nothing is tracked in
/// the slot; the entry is there and its table does not store `data`; a table argument whose
/// key type is not the tracked table's), 0 where the entry is missing from the table the
/// fetch looks in.
pub trait StickState: std::fmt::Debug {
    /// The entry tracked in slot `slot`, or the entry of the same key in `table`.
    fn tracked(&self, slot: usize, table: Option<&str>, data: StickData) -> Option<i64>;
    /// The entry whose key is the client's address `addr` in the first of `tables` that
    /// exists (the one the fetch names, or else the current proxies' own); it is looked up,
    /// never created.
    fn source(&self, addr: IpAddr, tables: &[&str], data: StickData) -> Option<i64>;
    /// Writes `op` to the entry tracked in `slot` (or the one of the same key in `table`,
    /// which is looked up and not created); the value the fetch gives. No sample where nothing
    /// is tracked or the table does not store what is written.
    fn write_tracked(&self, slot: usize, table: Option<&str>, op: StickOp) -> Option<i64>;
    /// Writes `op` to the entry of `addr` in the first of `tables` that exists, which is
    /// created if need be (`src_updt_conn_cnt`, `src_inc_gpc0`).
    fn write_source(&self, addr: IpAddr, tables: &[&str], op: StickOp) -> Option<i64>;
    /// The key of the entry tracked in `slot` (`sc_key`), as a sample of the table's key
    /// type, or of the entry of the same key in `table`; `None` where nothing is tracked
    /// (`sc_tracked` is whether there is one).
    fn tracked_key(&self, slot: usize, table: Option<&str>) -> Option<Sample>;
}

/// The live state of the configured proxies, which the runtime provides through
/// [`SampleContext::proxies`].
///
/// Backend and server names are resolved against the configuration when it loads, so a
/// `None` from these at run time means the name was not checked (a converter's input is
/// only known per request).
pub trait ProxyState: std::fmt::Debug {
    /// `be_usable_srv` (`include/haproxy/backend.h`): the usable active servers -- UP, not
    /// in maintenance, weight above 0 -- or, when there are none, 1 if a backup is usable;
    /// `None` if no proxy with a backend named `backend` exists.
    fn usable_servers(&self, backend: &str) -> Option<i64>;
    /// `smp_fetch_be_conn_free`: the free connection slots over the servers that would take
    /// traffic, `-1` if one of them has no `maxconn`.
    fn backend_conn_free(&self, backend: &str) -> Option<i64>;
    /// The server `server` of backend `backend`.
    fn server(&self, backend: &str, server: &str) -> Option<ServerState>;
    /// Whether a proxy with a frontend (a `frontend` or a `listen`) is named `name`.
    fn frontend_exists(&self, name: &str) -> bool;
    /// A counter of the frontend `frontend`; `None` if there is none of that name.
    fn frontend_counter(&self, frontend: &str, counter: FrontendCounter) -> Option<i64>;
    /// The streams assigned to backend `backend` over the last second (`be_sess_rate`).
    fn backend_sess_rate(&self, backend: &str) -> Option<i64>;
    /// The `default_backend` of frontend `frontend`, if it has one.
    fn default_backend(&self, frontend: &str) -> Option<String>;
    /// The connections open on all the frontends (`actconn`).
    fn active_connections(&self) -> i64;
    /// Whether `key` is an entry of the stick table `table`; `None` if there is no such
    /// table or the key cannot be one of its keys.
    fn table_has_key(&self, table: &str, key: &Sample) -> Option<bool>;
    /// `data` of the entry `key` of the stick table `table` (the `table_*` converters): 0 if
    /// the table has no such entry, `None` if there is no such table or it does not store
    /// `data`.
    fn table_value(&self, table: &str, key: &Sample, data: StickData) -> Option<i64>;
    /// `table_cnt` and `table_avl`: the entries of the stick table `table` and the ones it
    /// can still take; `None` if there is no such table.
    fn table_usage(&self, table: &str) -> Option<(i64, i64)>;
    /// `table_inc_gpc*` and `table_clr_gpc*`: writes `op` to the entry of `key` in `table`,
    /// which is created; `None` if there is no such table or it does not store what is written.
    fn table_write(&self, table: &str, key: &Sample, op: StickOp) -> Option<i64>;
}

/// A sample fetch implementation.
pub type FetchFn = fn(&SampleContext, &[String]) -> Option<Sample>;

/// A sample converter implementation.
pub type ConvFn = fn(Sample, &[String]) -> Option<Sample>;

/// A converter that reads the runtime state ([`SampleContext::proxies`]) as well as its
/// input: `nbsrv`, `srv_is_up`, `fe_exists`, `in_table`.
pub type CtxConvFn = fn(&SampleContext, Sample, &[String]) -> Option<Sample>;

/// Registered definition of a converter that reads the runtime state.
#[derive(Clone)]
pub struct CtxConvDesc {
    pub name: &'static str,
    pub in_type: TypeSpec,
    pub out_type: TypeSpec,
    pub func: CtxConvFn,
}

/// The fetches and converters `HAProxy` has and Ibex does not implement, with what is
/// missing. They are not registered, and the configuration is refused where they appear
/// (`ibex-rt`'s load-time checks), rather than evaluated to a constant: each of these used
/// to load and return 0 or 1, which an ACL then compared as if it were the state.
pub const NOT_IMPLEMENTED: &[(&str, &str)] = &[
    ("fc_unacked", "Ibex does not read TCP_INFO"),
    ("fc_sacked", "Ibex does not read TCP_INFO"),
    ("fc_lost", "Ibex does not read TCP_INFO"),
    ("fc_retrans", "Ibex does not read TCP_INFO"),
    ("fc_fackets", "Ibex does not read TCP_INFO"),
    ("fc_reordering", "Ibex does not read TCP_INFO"),
    ("queue", "Ibex has no server queues"),
    ("avg_queue", "Ibex has no server queues"),
    ("srv_queue", "Ibex has no server queues"),
    ("be_conn", "Ibex does not count the streams on a backend"),
];

/// Why `name` -- a fetch or a converter -- is in [`NOT_IMPLEMENTED`].
#[must_use]
pub fn not_implemented(name: &str) -> Option<&'static str> {
    NOT_IMPLEMENTED.iter().find(|(n, _)| *n == name).map(|&(_, why)| why)
}

/// The refusal for a name in [`NOT_IMPLEMENTED`]: "'<name>' : not implemented in Ibex
/// (<why>)".
#[must_use]
pub fn not_implemented_message(name: &str) -> Option<String> {
    not_implemented(name).map(|why| format!("'{name}' : not implemented in Ibex ({why})"))
}

/// `smp_fetch_srv_*`'s server argument, `[<backend>/]<server>`, with the backend defaulting
/// to the current one (`ctx.be_name`).
fn server_arg<'a>(ctx: &'a SampleContext, arg: &'a str) -> Option<(&'a str, &'a str)> {
    match arg.split_once('/') {
        Some((be, srv)) => Some((be, srv)),
        None => Some((ctx.be_name?, arg)),
    }
}

/// A server fetch: the named server's [`ServerState`] through `f`.
fn server_fetch(ctx: &SampleContext, args: &[String], f: fn(ServerState) -> Sample) -> Option<Sample> {
    let (be, srv) = server_arg(ctx, args.first()?)?;
    ctx.proxies?.server(be, srv).map(f)
}

/// A frontend fetch: `[<frontend>]`, defaulting to the current frontend.
fn frontend_arg<'a>(ctx: &'a SampleContext, args: &'a [String]) -> Option<&'a str> {
    args.first().map(String::as_str).filter(|a| !a.is_empty()).or(ctx.fe_name)
}

/// The tables a `src_*` fetch looks in: the one it names, or else the current proxy's own,
/// which is the backend's if the rule runs once a backend is chosen and has a table, and the
/// frontend's otherwise (the same guess `in_table` makes).
fn source_tables<'a>(ctx: &'a SampleContext, args: &'a [String]) -> Vec<&'a str> {
    match table_arg(args) {
        Some(t) => vec![t],
        None => ctx.be_name.into_iter().chain(ctx.fe_name).collect(),
    }
}

/// What a stick-counter fetch does to the entry it names.
#[derive(Clone, Copy)]
enum Act {
    Read(StickData),
    Write(StickOp),
}

/// The entry a stick-counter fetch names: what a stream tracks in a slot (and the table
/// to look the same key up in), or the client's address in the first of some tables.
enum Target<'a> {
    Slot(usize, Option<&'a str>),
    Source(&'a [&'a str]),
}

fn stick_act(ctx: &SampleContext, target: Target, act: Act) -> Option<Sample> {
    let stick = ctx.stick?;
    match (target, act) {
        (Target::Slot(slot, table), Act::Read(d)) => stick.tracked(slot, table, d),
        (Target::Slot(slot, table), Act::Write(op)) => stick.write_tracked(slot, table, op),
        (Target::Source(tables), Act::Read(d)) => stick.source(ctx.client_addr?.ip(), tables, d),
        (Target::Source(tables), Act::Write(op)) => stick.write_source(ctx.client_addr?.ip(), tables, op),
    }
    .map(Sample::Sint)
}

/// A `sc[0-9]_*` or `src_*` fetch's optional `[<table>]` argument.
fn table_arg(args: &[String]) -> Option<&str> {
    args.first().map(String::as_str).filter(|a| !a.is_empty())
}

/// A backend fetch: `[<backend>]`, defaulting to the current backend.
fn backend_arg<'a>(ctx: &'a SampleContext, args: &'a [String]) -> Option<&'a str> {
    args.first().map(String::as_str).filter(|a| !a.is_empty()).or(ctx.be_name)
}

/// A string converter's input, which the registry has cast to a string already.
fn input_str(smp: Sample) -> Option<String> {
    if let Sample::Str(s) = smp { Some(s) } else { None }
}

/// `smp_fetch_srv_conn_free`: `-1` without `maxconn`, else the slots left, never below 0.
fn conn_free(s: ServerState) -> Sample {
    Sample::Sint(match s.maxconn {
        None | Some(0) => -1,
        Some(mc) => i64::from(mc.saturating_sub(s.cur_sess)),
    })
}

/// Registered sample fetch definition.
#[derive(Clone)]
pub struct FetchDesc {
    pub name: &'static str,
    pub out_type: SampleType,
    pub func: FetchFn,
}

/// Registered converter definition.
#[derive(Clone)]
pub struct ConvDesc {
    pub name: &'static str,
    pub in_type: TypeSpec,
    pub out_type: TypeSpec,
    pub func: ConvFn,
}

pub type MultiFetchFn = fn(&SampleContext, &[String]) -> Vec<Sample>;

/// Central registry of sample fetches and converters.
pub struct Registry {
    fetches: HashMap<&'static str, FetchDesc>,
    converters: HashMap<&'static str, ConvDesc>,
    ctx_converters: HashMap<&'static str, CtxConvDesc>,
    multi_fetches: HashMap<&'static str, MultiFetchFn>,
}

fn resolve_int_arg(arg: &str) -> Option<i64> {
    let trimmed = arg.trim().trim_matches('"').trim_matches('\'');
    if let Ok(n) = trimmed.parse::<i64>() {
        return Some(n);
    }
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        if let Ok(n) = i64::from_str_radix(hex, 16) {
            return Some(n);
        }
    }
    let var_name = if trimmed.starts_with("var(") && trimmed.ends_with(')') {
        &trimmed[4..trimmed.len() - 1]
    } else {
        trimmed
    };
    if var_name.starts_with("proc.") {
        get_proc_var(var_name).and_then(|s| s.parse::<i64>().ok())
    } else if var_name.starts_with("sess.")
        || var_name.starts_with("req.")
        || var_name.starts_with("txn.")
        || var_name.starts_with("res.")
    {
        CURRENT_VARS.with(|v| {
            v.borrow().get(var_name).and_then(|s| s.parse::<i64>().ok())
        })
    } else {
        None
    }
}

fn resolve_var_str(arg: &str) -> String {
    let trimmed = arg.trim().trim_matches('"').trim_matches('\'');
    let var_name = if trimmed.starts_with("var(") && trimmed.ends_with(')') {
        &trimmed[4..trimmed.len() - 1]
    } else {
        trimmed
    };
    if var_name.starts_with("proc.") {
        get_proc_var(var_name).unwrap_or_default()
    } else {
        CURRENT_VARS.with(|v| v.borrow().get(var_name).cloned().unwrap_or_default())
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    #[must_use]
    pub fn new() -> Self {
        let mut r = Registry {
            fetches: HashMap::new(),
            converters: HashMap::new(),
            ctx_converters: HashMap::new(),
            multi_fetches: HashMap::new(),
        };
        r.register_builtin_fetches();
        r.register_builtin_converters();
        r
    }

    pub fn register_multi_fetch(&mut self, name: &'static str, func: MultiFetchFn) {
        self.multi_fetches.insert(name, func);
    }

    /// Registers a sample fetch. Panics if `desc.name` is already registered.
    ///
    /// This used to be a bare `HashMap::insert`, so a second registration of the same
    /// name silently replaced the first and the loser became unreachable -- code that
    /// still compiled, still had passing tests, and never ran. It happened twice: once
    /// across crates, where `ibex-rt` shadowed 29 of these, and once inside this file,
    /// where four `None` stubs were appended after the working `map_beg`/`map_sub`/
    /// `map_dir`/`map_dom` and silently won.
    ///
    /// Neither was detectable by building, testing or linting, which is why this is a
    /// panic and not a lint: the registry is built by every test that evaluates a
    /// sample, so a duplicate now fails loudly the first time anything touches it.
    ///
    /// # Panics
    ///
    /// If a fetch with this name is already registered. Registration happens once at
    /// startup from a fixed table, so this fires during development, never on a request.
    pub fn register_fetch(&mut self, desc: FetchDesc) {
        assert!(
            !self.fetches.contains_key(desc.name),
            "sample fetch '{}' registered twice; the later registration would silently \
             shadow the earlier one",
            desc.name
        );
        self.fetches.insert(desc.name, desc);
    }

    /// Registers a converter. Panics if `desc.name` is already registered.
    ///
    /// See [`Registry::register_fetch`] for why this is a panic.
    ///
    /// # Panics
    ///
    /// If a converter with this name is already registered.
    pub fn register_converter(&mut self, desc: ConvDesc) {
        assert!(
            !self.converters.contains_key(desc.name),
            "converter '{}' registered twice; the later registration would silently \
             shadow the earlier one",
            desc.name
        );
        self.converters.insert(desc.name, desc);
    }

    /// Registers a converter that reads the runtime state. Panics if a converter of
    /// either kind already has this name, as [`Registry::register_converter`] does.
    ///
    /// # Panics
    ///
    /// If a converter with this name is already registered.
    pub fn register_ctx_converter(&mut self, desc: CtxConvDesc) {
        assert!(
            !self.converters.contains_key(desc.name) && !self.ctx_converters.contains_key(desc.name),
            "converter '{}' registered twice; the later registration would silently \
             shadow the earlier one",
            desc.name
        );
        self.ctx_converters.insert(desc.name, desc);
    }

    /// Whether a fetch, of either kind, is registered under `name`.
    #[must_use]
    pub fn has_fetch(&self, name: &str) -> bool {
        self.fetches.contains_key(name) || self.multi_fetches.contains_key(name)
    }

    #[must_use]
    pub fn get_fetch(&self, name: &str) -> Option<&FetchDesc> {
        self.fetches.get(name)
    }

    /// A converter that needs no runtime state. [`Registry::has_converter`] also sees the
    /// ones that do.
    #[must_use]
    pub fn get_converter(&self, name: &str) -> Option<&ConvDesc> {
        self.converters.get(name)
    }

    /// A converter that reads the runtime state (`nbsrv`, `srv_is_up`, ...).
    #[must_use]
    pub fn get_ctx_converter(&self, name: &str) -> Option<&CtxConvDesc> {
        self.ctx_converters.get(name)
    }

    /// Whether a converter of either kind is named `name`.
    #[must_use]
    pub fn has_converter(&self, name: &str) -> bool {
        self.converters.contains_key(name) || self.ctx_converters.contains_key(name)
    }

    #[must_use]
    pub fn fetch_count(&self) -> usize {
        self.fetches.len()
    }

    #[must_use]
    pub fn converter_count(&self) -> usize {
        self.converters.len() + self.ctx_converters.len()
    }

    #[must_use]
    pub fn fetch_names(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self.fetches.keys().copied().collect();
        names.sort_unstable();
        names
    }

    #[must_use]
    pub fn converter_names(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> =
            self.converters.keys().chain(self.ctx_converters.keys()).copied().collect();
        names.sort_unstable();
        names
    }

    #[allow(clippy::too_many_lines)]
    fn register_builtin_fetches(&mut self) {
        // --- 1. Client & Destination Network Fetches ---
        let src_fetch: FetchFn = |ctx, _args| match ctx.client_addr?.ip() {
            IpAddr::V4(v4) => Some(Sample::Ipv4(v4)),
            IpAddr::V6(v6) => Some(Sample::Ipv6(v6)),
        };
        let fc_src_fetch: FetchFn = |ctx, _args| match ctx.fc_src.or(ctx.client_addr)?.ip() {
            IpAddr::V4(v4) => Some(Sample::Ipv4(v4)),
            IpAddr::V6(v6) => Some(Sample::Ipv6(v6)),
        };
        self.register_fetch(FetchDesc {
            name: "src",
            out_type: SampleType::Ipv4,
            func: src_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "fc_src",
            out_type: SampleType::Ipv4,
            func: fc_src_fetch,
        });

        let http_first_req_fetch: FetchFn =
            |ctx, _args| Some(Sample::Bool(ctx.is_first_req));
        self.register_fetch(FetchDesc {
            name: "http_first_req",
            out_type: SampleType::Bool,
            func: http_first_req_fetch,
        });

        let src_port_fetch: FetchFn =
            |ctx, _args| ctx.client_addr.map(|sa| Sample::Sint(i64::from(sa.port())));
        let fc_src_port_fetch: FetchFn =
            |ctx, _args| ctx.fc_src.or(ctx.client_addr).map(|sa| Sample::Sint(i64::from(sa.port())));
        self.register_fetch(FetchDesc {
            name: "src_port",
            out_type: SampleType::Sint,
            func: src_port_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "fc_src_port",
            out_type: SampleType::Sint,
            func: fc_src_port_fetch,
        });

        let dst_fetch: FetchFn = |ctx, _args| match ctx.server_addr?.ip() {
            IpAddr::V4(v4) => Some(Sample::Ipv4(v4)),
            IpAddr::V6(v6) => Some(Sample::Ipv6(v6)),
        };
        let fc_dst_fetch: FetchFn = |ctx, _args| match ctx.fc_dst.or(ctx.server_addr)?.ip() {
            IpAddr::V4(v4) => Some(Sample::Ipv4(v4)),
            IpAddr::V6(v6) => Some(Sample::Ipv6(v6)),
        };
        self.register_fetch(FetchDesc {
            name: "dst",
            out_type: SampleType::Ipv4,
            func: dst_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "fc_dst",
            out_type: SampleType::Ipv4,
            func: fc_dst_fetch,
        });

        // `smp_fetch_dport` (src/tcp_sample.c) fails on port 0: `set-dst-port` can put it
        // there, and HAProxy then prints nothing for `%[dst_port]`.
        let dst_port_fetch: FetchFn = |ctx, _args| {
            ctx.server_addr.filter(|sa| sa.port() != 0).map(|sa| Sample::Sint(i64::from(sa.port())))
        };
        let fc_dst_port_fetch: FetchFn = |ctx, _args| {
            ctx.fc_dst
                .or(ctx.server_addr)
                .filter(|sa| sa.port() != 0)
                .map(|sa| Sample::Sint(i64::from(sa.port())))
        };
        self.register_fetch(FetchDesc {
            name: "dst_port",
            out_type: SampleType::Sint,
            func: dst_port_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "fc_dst_port",
            out_type: SampleType::Sint,
            func: fc_dst_port_fetch,
        });

        self.register_fetch(FetchDesc {
            name: "fc_rtt",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(i64::from(ctx.fc_rtt.unwrap_or(0)))),
        });
        self.register_fetch(FetchDesc {
            name: "fc_rttvar",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(i64::from(ctx.fc_rttvar.unwrap_or(0)))),
        });
        self.register_fetch(FetchDesc {
            name: "bc_rtt",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(i64::from(ctx.bc_rtt.unwrap_or(0)))),
        });
        self.register_fetch(FetchDesc {
            name: "bc_rttvar",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(i64::from(ctx.bc_rttvar.unwrap_or(0)))),
        });

        // --- 2. HTTP Request Line & URL Fetches ---
        self.register_fetch(FetchDesc {
            name: "path",
            out_type: SampleType::Str,
            func: |ctx, _args| {
                let uri = get_context_uri(ctx)?;
                let (_, path, _) = split_uri(uri);
                Some(Sample::Str(path.to_string()))
            },
        });

        self.register_fetch(FetchDesc {
            name: "pathq",
            out_type: SampleType::Str,
            func: |ctx, _args| {
                let uri = get_context_uri(ctx)?;
                let (_, path, query) = split_uri(uri);
                if query.is_empty() {
                    Some(Sample::Str(path.to_string()))
                } else {
                    Some(Sample::Str(format!("{path}?{query}")))
                }
            },
        });

        let url_fetch: FetchFn = |ctx, _args| {
            let uri = get_context_uri(ctx)?;
            Some(Sample::Str(uri.to_string()))
        };
        self.register_fetch(FetchDesc {
            name: "url",
            out_type: SampleType::Str,
            func: url_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "req.uri",
            out_type: SampleType::Str,
            func: url_fetch,
        });

        self.register_fetch(FetchDesc {
            name: "query",
            out_type: SampleType::Str,
            func: |ctx, _args| {
                let uri = get_context_uri(ctx)?;
                let (_, _, query) = split_uri(uri);
                Some(Sample::Str(query.to_string()))
            },
        });

        let url_param_fetch: FetchFn = |ctx, args| {
            let param = args.first()?;
            let uri = get_context_uri(ctx)?;
            let (_, _, query) = split_uri(uri);
            extract_url_param(query, param).map(Sample::Str)
        };
        self.register_fetch(FetchDesc {
            name: "url_param",
            out_type: SampleType::Str,
            func: url_param_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "urlp",
            out_type: SampleType::Str,
            func: url_param_fetch,
        });

        self.register_fetch(FetchDesc {
            name: "urlp_val",
            out_type: SampleType::Sint,
            func: |ctx, args| {
                let param = args.first()?;
                let uri = get_context_uri(ctx)?;
                let (_, _, query) = split_uri(uri);
                let val_str = extract_url_param(query, param)?;
                val_str.parse::<i64>().ok().map(Sample::Sint)
            },
        });

        // `meth(<name>)`: the constant method `<name>` (`smp_fetch_meth` is `method`; this one
        // is the constant `meth` of src/sample.c). A name outside the known methods is kept as
        // it was written.
        self.register_fetch(FetchDesc {
            name: "meth",
            out_type: SampleType::Meth,
            func: |_ctx, args| {
                let name = args.first()?;
                Some(Sample::Meth(ibex_proto::htx::HttpMethod::from_bytes(name.as_bytes())))
            },
        });

        self.register_fetch(FetchDesc {
            name: "method",
            out_type: SampleType::Meth,
            func: |ctx, _args| {
                if let Some(m_str) = get_context_method(ctx) {
                    let m = ibex_proto::htx::HttpMethod::from_bytes(m_str.as_bytes());
                    // `smp_fetch_meth` (src/http_fetch.c): `HTTP_METH_OTHER` is read from the
                    // request buffer, which is gone when the log line is built. HAProxy
                    // 3.5-dev8 logs `-` for `PATCH` and any other method outside its enum.
                    if ctx.at_log
                        && matches!(m, ibex_proto::htx::HttpMethod::Patch | ibex_proto::htx::HttpMethod::Other(_))
                    {
                        return None;
                    }
                    return Some(Sample::Meth(m));
                }
                ctx.htx?
                    .req_line()
                    .map(|req| Sample::Meth(req.method.clone()))
            },
        });

        // `smp_fetch_rqver` / `smp_fetch_stver` (src/http_fetch.c): the version without
        // its "HTTP/" ("1.1"), and nothing when there is no message to read it from.
        let request_version_fetch: FetchFn = |ctx, _args| {
            let v = get_context_req_version(ctx).map(str::to_string)
                .or_else(|| ctx.htx.and_then(|h| h.req_line()).map(|l| l.version.as_str().to_string()))?;
            Some(Sample::Str(v.strip_prefix("HTTP/").unwrap_or(&v).to_string()))
        };
        self.register_fetch(FetchDesc {
            name: "req.ver",
            out_type: SampleType::Str,
            func: request_version_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "req_ver",
            out_type: SampleType::Str,
            func: request_version_fetch,
        });

        // `smp_fetch_rqver` / `smp_fetch_stver` (src/http_fetch.c): the version without
        // its "HTTP/" ("1.1"), and nothing when there is no message to read it from.
        let response_version_fetch: FetchFn = |ctx, _args| {
            let v = get_context_res_version(ctx).map(str::to_string)
                .or_else(|| ctx.htx.and_then(|h| h.res_line()).map(|l| l.version.as_str().to_string()))?;
            Some(Sample::Str(v.strip_prefix("HTTP/").unwrap_or(&v).to_string()))
        };
        self.register_fetch(FetchDesc {
            name: "res.ver",
            out_type: SampleType::Str,
            func: response_version_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "res_ver",
            out_type: SampleType::Str,
            func: response_version_fetch,
        });

        let status_fetch: FetchFn = |ctx, _args| {
            if let Some(h) = ctx.htx_slice {
                if let Some(res) = h.res_line() {
                    return Some(Sample::Sint(i64::from(res.status)));
                }
            }
            if let Some(st) = ctx.res_status {
                return Some(Sample::Sint(i64::from(st)));
            }
            if let Some(htx) = ctx.htx {
                if let Some(res) = htx.res_line() {
                    return Some(Sample::Sint(i64::from(res.status)));
                }
            }
            let st = CURRENT_RES_STATUS.get();
            if st > 0 {
                Some(Sample::Sint(i64::from(st)))
            } else {
                None
            }
        };
        self.register_fetch(FetchDesc {
            name: "status",
            out_type: SampleType::Sint,
            func: status_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "res.status",
            out_type: SampleType::Sint,
            func: status_fetch,
        });

        self.register_fetch(FetchDesc {
            name: "req.proto_http",
            out_type: SampleType::Bool,
            func: |ctx, _args| {
                Some(Sample::Bool(
                    ctx.htx_slice.is_some() || ctx.htx.is_some() || ctx.req_uri.is_some(),
                ))
            },
        });
        self.register_fetch(FetchDesc {
            name: "res.proto_http",
            out_type: SampleType::Bool,
            func: |ctx, _args| {
                Some(Sample::Bool(
                    ctx.htx_slice.is_some()
                        || ctx.htx.is_some()
                        || ctx.res_status.is_some()
                        || CURRENT_RES_STATUS.get() > 0,
                ))
            },
        });

        // --- 3. Base Fetches ---
        self.register_fetch(FetchDesc {
            name: "base",
            out_type: SampleType::Str,
            func: fetch_base,
        });

        self.register_fetch(FetchDesc {
            name: "base32",
            out_type: SampleType::Sint,
            func: |ctx, args| {
                let base_smp = fetch_base(ctx, args)?;
                let Sample::Str(s) = base_smp else { return None };
                let h = full_hash(hash_djb2(s.as_bytes()));
                Some(Sample::Sint(i64::from(h)))
            },
        });

        self.register_fetch(FetchDesc {
            name: "base32+src",
            out_type: SampleType::Bin,
            func: |ctx, args| {
                let base_smp = fetch_base(ctx, args)?;
                let Sample::Str(s) = base_smp else { return None };
                let h = full_hash(hash_djb2(s.as_bytes()));
                let mut out = Vec::with_capacity(20);
                out.extend_from_slice(&h.to_be_bytes());
                if let Some(sa) = ctx.client_addr {
                    match sa.ip() {
                        IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
                        IpAddr::V6(v6) => out.extend_from_slice(&v6.octets()),
                    }
                }
                Some(Sample::Bin(out))
            },
        });

        self.register_fetch(FetchDesc {
            name: "baseq",
            out_type: SampleType::Str,
            func: |ctx, args| {
                let base_smp = fetch_base(ctx, args)?;
                let Sample::Str(b) = base_smp else { return None };
                let uri = get_context_uri(ctx)?;
                let (_, _, query) = split_uri(uri);
                if query.is_empty() {
                    Some(Sample::Str(b))
                } else {
                    Some(Sample::Str(format!("{b}?{query}")))
                }
            },
        });

        // --- 4. HTTP Headers Fetches ---
        let request_header_fetch: FetchFn = |ctx, args| {
            let name = args.first()?;
            let occ: Option<i64> = args.get(1).and_then(|s| s.parse().ok());
            let hdrs = get_all_req_headers(ctx, name);
            if hdrs.is_empty() {
                return None;
            }
            if let Some(idx) = occ {
                // HAProxy counts occurrences from 1, and from the end when negative, so
                // -1 is the last header. Both conversions are fallible rather than `as`:
                // the index comes from the config as an i64, and a truncating cast would
                // turn an out-of-range occurrence into a valid index for a *different*
                // header instead of no match at all.
                if idx > 0 {
                    let uidx = usize::try_from(idx - 1).ok()?;
                    return hdrs.get(uidx).map(|s| Sample::Str((*s).clone()));
                } else if idx < 0 {
                    let back = usize::try_from(idx.unsigned_abs()).ok()?;
                    let uidx = hdrs.len().checked_sub(back)?;
                    return hdrs.get(uidx).map(|s| Sample::Str((*s).clone()));
                }
                return None;
            }
            Some(Sample::Str(hdrs.join(", ")))
        };
        self.register_fetch(FetchDesc {
            name: "req.hdr",
            out_type: SampleType::Str,
            func: request_header_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "hdr",
            out_type: SampleType::Str,
            func: request_header_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "req.fhdr",
            out_type: SampleType::Str,
            func: request_header_fetch,
        });

        // `http_auth_bearer([<header>])` (`smp_fetch_http_auth_bearer`): the token of a
        // `Bearer` credential in the first `<header>` (default `Authorization`). The scheme is
        // matched without regard to case and needs at least one space before the token, which
        // is the rest of the value; no token, another scheme or no header is no sample.
        self.register_fetch(FetchDesc {
            name: "http_auth_bearer",
            out_type: SampleType::Str,
            func: |ctx, args| {
                let name = args.first().map_or("authorization", String::as_str);
                let name = if name.is_empty() { "authorization" } else { name };
                let hdrs = get_all_req_headers(ctx, name);
                let value = hdrs.first()?;
                let (scheme, rest) = value.split_at_checked(6)?;
                if !scheme.eq_ignore_ascii_case("bearer") || !rest.starts_with(' ') {
                    return None;
                }
                let token = rest.trim_start_matches(' ');
                (!token.is_empty()).then(|| Sample::Str(token.to_string()))
            },
        });

        let response_header_fetch: FetchFn = |ctx, args| {
            let name = args.first()?;
            let occ: Option<i64> = args.get(1).and_then(|s| s.parse().ok());
            let hdrs = get_all_res_headers(ctx, name);
            if hdrs.is_empty() {
                return None;
            }
            if let Some(idx) = occ {
                // HAProxy counts occurrences from 1, and from the end when negative, so
                // -1 is the last header. Both conversions are fallible rather than `as`:
                // the index comes from the config as an i64, and a truncating cast would
                // turn an out-of-range occurrence into a valid index for a *different*
                // header instead of no match at all.
                if idx > 0 {
                    let uidx = usize::try_from(idx - 1).ok()?;
                    return hdrs.get(uidx).map(|s| Sample::Str((*s).clone()));
                } else if idx < 0 {
                    let back = usize::try_from(idx.unsigned_abs()).ok()?;
                    let uidx = hdrs.len().checked_sub(back)?;
                    return hdrs.get(uidx).map(|s| Sample::Str((*s).clone()));
                }
                return None;
            }
            Some(Sample::Str(hdrs.join(", ")))
        };
        self.register_fetch(FetchDesc {
            name: "res.hdr",
            out_type: SampleType::Str,
            func: response_header_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "res.fhdr",
            out_type: SampleType::Str,
            func: response_header_fetch,
        });

        let req_hdr_cnt_fetch: FetchFn = |ctx, args| {
            let name = args.first()?;
            let count = get_all_req_headers(ctx, name).len();
            Some(Sample::Sint(len_to_sint(count)))
        };
        self.register_fetch(FetchDesc {
            name: "req.hdr_cnt",
            out_type: SampleType::Sint,
            func: req_hdr_cnt_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "hdr_cnt",
            out_type: SampleType::Sint,
            func: req_hdr_cnt_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "req.fhdr_cnt",
            out_type: SampleType::Sint,
            func: req_hdr_cnt_fetch,
        });

        self.register_fetch(FetchDesc {
            name: "res.hdr_cnt",
            out_type: SampleType::Sint,
            func: |ctx, args| {
                let name = args.first()?;
                let count = get_all_res_headers(ctx, name).len();
                Some(Sample::Sint(len_to_sint(count)))
            },
        });

        let req_hdr_val_fetch: FetchFn = |ctx, args| {
            let name = args.first()?;
            let val = get_req_header(ctx, name)?;
            val.trim().parse::<i64>().ok().map(Sample::Sint)
        };
        self.register_fetch(FetchDesc {
            name: "req.hdr_val",
            out_type: SampleType::Sint,
            func: req_hdr_val_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "hdr_val",
            out_type: SampleType::Sint,
            func: req_hdr_val_fetch,
        });

        self.register_fetch(FetchDesc {
            name: "res.hdr_val",
            out_type: SampleType::Sint,
            func: |ctx, args| {
                let name = args.first()?;
                let val = get_res_header(ctx, name)?;
                val.trim().parse::<i64>().ok().map(Sample::Sint)
            },
        });

        let hdr_ip_fetch: FetchFn = |ctx, args| {
            let name = args.first()?;
            let val = get_req_header(ctx, name)?;
            parse_ip_str(&val)
        };
        self.register_fetch(FetchDesc {
            name: "req.hdr_ip",
            out_type: SampleType::Ipv4,
            func: hdr_ip_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "hdr_ip",
            out_type: SampleType::Ipv4,
            func: hdr_ip_fetch,
        });

        self.register_fetch(FetchDesc {
            name: "res.hdr_ip",
            out_type: SampleType::Ipv4,
            func: |ctx, args| {
                let name = args.first()?;
                let val = get_res_header(ctx, name)?;
                parse_ip_str(&val)
            },
        });

        self.register_fetch(FetchDesc {
            name: "req.cook",
            out_type: SampleType::Str,
            func: fetch_req_cook,
        });
        self.register_fetch(FetchDesc {
            name: "cook",
            out_type: SampleType::Str,
            func: fetch_req_cook,
        });
        self.register_fetch(FetchDesc {
            name: "cookie",
            out_type: SampleType::Str,
            func: fetch_req_cook,
        });

        self.register_fetch(FetchDesc {
            name: "res.cook",
            out_type: SampleType::Str,
            func: |ctx, args| {
                let name = args.first()?;
                let set_cookies = get_all_res_headers(ctx, "set-cookie");
                for hdr in set_cookies {
                    for (k, v) in extract_cookies(&hdr) {
                        if k == name {
                            return Some(Sample::Str(v.to_string()));
                        }
                    }
                }
                None
            },
        });

        let cook_cnt_fetch: FetchFn = |ctx, args| {
            let name = args.first();
            let cookie_hdrs = get_all_req_headers(ctx, "cookie");
            let mut count = 0;
            for hdr in cookie_hdrs {
                for (k, _) in extract_cookies(&hdr) {
                    if let Some(target) = name {
                        if k == target {
                            count += 1;
                        }
                    } else {
                        count += 1;
                    }
                }
            }
            Some(Sample::Sint(count))
        };
        self.register_fetch(FetchDesc {
            name: "req.cook_cnt",
            out_type: SampleType::Sint,
            func: cook_cnt_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "cook_cnt",
            out_type: SampleType::Sint,
            func: cook_cnt_fetch,
        });

        self.register_fetch(FetchDesc {
            name: "res.cook_cnt",
            out_type: SampleType::Sint,
            func: |ctx, args| {
                let name = args.first();
                let set_cookies = get_all_res_headers(ctx, "set-cookie");
                let mut count = 0;
                for hdr in set_cookies {
                    for (k, _) in extract_cookies(&hdr) {
                        if let Some(target) = name {
                            if k == target {
                                count += 1;
                            }
                        } else {
                            count += 1;
                        }
                    }
                }
                Some(Sample::Sint(count))
            },
        });

        let cook_val_fetch: FetchFn = |ctx, args| {
            let smp = fetch_req_cook(ctx, args)?;
            let Sample::Str(s) = smp else { return None };
            s.parse::<i64>().ok().map(Sample::Sint)
        };
        self.register_fetch(FetchDesc {
            name: "req.cook_val",
            out_type: SampleType::Sint,
            func: cook_val_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "cook_val",
            out_type: SampleType::Sint,
            func: cook_val_fetch,
        });

        self.register_fetch(FetchDesc {
            name: "res.cook_val",
            out_type: SampleType::Sint,
            func: |ctx, args| {
                let name = args.first()?;
                let set_cookies = get_all_res_headers(ctx, "set-cookie");
                for hdr in set_cookies {
                    for (k, v) in extract_cookies(&hdr) {
                        if k == name {
                            return v.parse::<i64>().ok().map(Sample::Sint);
                        }
                    }
                }
                None
            },
        });

        // --- 6. Body & Length Fetches ---
        self.register_fetch(FetchDesc {
            name: "req.body",
            out_type: SampleType::Bin,
            func: |ctx, _args| {
                if let Some(b) = ctx.req_body {
                    return Some(Sample::Bin(b.to_vec()));
                }
                ctx.htx_slice.map(|h| Sample::Bin(h.body_bytes()))
            },
        });

        self.register_fetch(FetchDesc {
            name: "res.body",
            out_type: SampleType::Bin,
            func: |ctx, _args| {
                if let Some(b) = ctx.res_body {
                    return Some(Sample::Bin(b.to_vec()));
                }
                ctx.htx_slice.map(|h| Sample::Bin(h.body_bytes()))
            },
        });

        let request_body_len_fetch: FetchFn = |ctx, _args| {
            if let Some(h) = ctx.htx_slice {
                let bl = h.body_len();
                if bl > 0 {
                    return Some(Sample::Sint(len_to_sint(bl)));
                }
            }
            if let Some(b) = ctx.req_body {
                return Some(Sample::Sint(len_to_sint(b.len())));
            }
            if let Some(cl) = get_req_header(ctx, "content-length") {
                return cl.trim().parse::<i64>().ok().map(Sample::Sint);
            }
            None
        };
        self.register_fetch(FetchDesc {
            name: "req.len",
            out_type: SampleType::Sint,
            func: request_body_len_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "req_len",
            out_type: SampleType::Sint,
            func: request_body_len_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "req.body_len",
            out_type: SampleType::Sint,
            func: request_body_len_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "req.body_size",
            out_type: SampleType::Sint,
            func: request_body_len_fetch,
        });

        let response_body_len_fetch: FetchFn = |ctx, _args| {
            if let Some(h) = ctx.htx_slice {
                let bl = h.body_len();
                if bl > 0 {
                    return Some(Sample::Sint(len_to_sint(bl)));
                }
            }
            if let Some(b) = ctx.res_body {
                return Some(Sample::Sint(len_to_sint(b.len())));
            }
            if let Some(cl) = get_res_header(ctx, "content-length") {
                return cl.trim().parse::<i64>().ok().map(Sample::Sint);
            }
            None
        };
        self.register_fetch(FetchDesc {
            name: "res.len",
            out_type: SampleType::Sint,
            func: response_body_len_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "res.body_size",
            out_type: SampleType::Sint,
            func: response_body_len_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "res.body_len",
            out_type: SampleType::Sint,
            func: response_body_len_fetch,
        });

        crate::rawpayload::register(self);

        fn request_payload_fetch(ctx: &SampleContext, args: &[String]) -> Option<Sample> {
            let offset = args.first().and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
            let len = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);

            if let Some(body) = ctx.req_body {
                if offset >= body.len() {
                    return None;
                }
                let slice = if len == 0 || offset.saturating_add(len) > body.len() {
                    &body[offset..]
                } else {
                    &body[offset..offset + len]
                };
                return Some(Sample::Bin(slice.to_vec()));
            }

            if let Some(h) = ctx.htx_slice {
                let body = h.body_bytes();
                if offset >= body.len() {
                    return None;
                }
                let slice = if len == 0 || offset.saturating_add(len) > body.len() {
                    &body[offset..]
                } else {
                    &body[offset..offset + len]
                };
                return Some(Sample::Bin(slice.to_vec()));
            }

            None
        }
        self.register_fetch(FetchDesc {
            name: "req.payload",
            out_type: SampleType::Bin,
            func: request_payload_fetch,
        });
        let response_payload_fetch_early: FetchFn = |ctx, args| {
            // `payload` takes the direction of the rule set that runs it.
            if ctx.raw_res.is_some() && ctx.raw_req.is_none() {
                let body = ctx.res_body?;
                let offset = args.first().and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
                let len = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
                if offset >= body.len() {
                    return None;
                }
                let end = if len == 0 || offset.saturating_add(len) > body.len() { body.len() } else { offset + len };
                return Some(Sample::Bin(body[offset..end].to_vec()));
            }
            request_payload_fetch(ctx, args)
        };
        self.register_fetch(FetchDesc {
            name: "payload",
            out_type: SampleType::Bin,
            func: response_payload_fetch_early,
        });

        let response_payload_fetch: FetchFn = |ctx, args| {
            let body = ctx.res_body?;
            let offset = args.first().and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
            if offset >= body.len() {
                return None;
            }
            let len = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
            let slice = if len == 0 || offset.saturating_add(len) > body.len() {
                &body[offset..]
            } else {
                &body[offset..offset + len]
            };
            Some(Sample::Bin(slice.to_vec()))
        };
        self.register_fetch(FetchDesc {
            name: "res.payload",
            out_type: SampleType::Bin,
            func: response_payload_fetch,
        });

        // `unique-id` (src/http_fetch.c): the stream's `unique-id-format` value; nothing
        // when the proxy has no format.
        self.register_fetch(FetchDesc {
            name: "unique-id",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.unique_id.map(|u| Sample::Str(u.to_string())),
        });
        // `smp_fetch_wait_end` (src/payload.c): true once the rules may no longer wait. The
        // tcp-request and tcp-response content rules hold a condition on it while they can
        // wait (`inspect-delay` not over, the buffer not full, the peer not closed), so a
        // sample is only ever asked for when they cannot.
        self.register_fetch(FetchDesc {
            name: "wait_end",
            out_type: SampleType::Bool,
            func: |_ctx, _args| Some(Sample::Bool(true)),
        });
        // `smp_fetch_last_rule_file` / `smp_fetch_last_rule_line` (src/stream.c).
        self.register_fetch(FetchDesc {
            name: "last_rule_file",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.last_rule.map(|(file, _)| Sample::Str(file.to_string())),
        });
        self.register_fetch(FetchDesc {
            name: "prio_class",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(i64::from(ctx.prio.0))),
        });
        self.register_fetch(FetchDesc {
            name: "prio_offset",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(i64::from(ctx.prio.1))),
        });
        self.register_fetch(FetchDesc {
            name: "last_rule_line",
            out_type: SampleType::Sint,
            func: |ctx, _args| ctx.last_rule.map(|(_, line)| Sample::Sint(i64::from(line))),
        });

        // --- 7. Captures ---
        self.register_fetch(FetchDesc {
            name: "capture.req.hdr",
            out_type: SampleType::Str,
            func: |ctx, args| {
                let idx_str = args.first()?;
                let idx: usize = idx_str.parse().ok()?;
                let caps = ctx.captures_req_hdr?;
                caps.get(idx)?.clone().map(capture_sample)
            },
        });

        self.register_fetch(FetchDesc {
            name: "capture.res.hdr",
            out_type: SampleType::Str,
            func: |ctx, args| {
                let idx_str = args.first()?;
                let idx: usize = idx_str.parse().ok()?;
                let caps = ctx.captures_res_hdr?;
                caps.get(idx)?.clone().map(capture_sample)
            },
        });

        self.register_fetch(FetchDesc {
            name: "capture.req.method",
            out_type: SampleType::Str,
            func: |ctx, _args| {
                let m = get_context_method(ctx)?;
                Some(Sample::Str(m.to_string()))
            },
        });

        self.register_fetch(FetchDesc {
            name: "capture.req.uri",
            out_type: SampleType::Str,
            func: |ctx, _args| {
                let uri = get_context_uri(ctx)?;
                Some(Sample::Str(uri.to_string()))
            },
        });

        self.register_fetch(FetchDesc {
            name: "capture.req.ver",
            out_type: SampleType::Str,
            func: request_version_fetch,
        });

        self.register_fetch(FetchDesc {
            name: "capture.res.ver",
            out_type: SampleType::Str,
            func: response_version_fetch,
        });

        // --- 8. Frontend / Backend / Server Fetches ---
        self.register_fetch(FetchDesc {
            name: "fe_id",
            out_type: SampleType::Sint,
            func: |ctx, _args| ctx.fe_id.map(|id| Sample::Sint(i64::from(id))),
        });
        self.register_fetch(FetchDesc {
            name: "fe_name",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.fe_name.map(|n| Sample::Str(n.to_string())),
        });
        self.register_fetch(FetchDesc {
            name: "fe_defbe",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.proxies?.default_backend(ctx.fe_name?).map(Sample::Str),
        });

        self.register_fetch(FetchDesc {
            name: "be_id",
            out_type: SampleType::Sint,
            func: |ctx, _args| ctx.be_id.map(|id| Sample::Sint(i64::from(id))),
        });
        self.register_fetch(FetchDesc {
            name: "be_name",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.be_name.map(|n| Sample::Str(n.to_string())),
        });

        self.register_fetch(FetchDesc {
            name: "srv_id",
            out_type: SampleType::Sint,
            func: |ctx, _args| ctx.srv_id.map(|id| Sample::Sint(i64::from(id))),
        });
        self.register_fetch(FetchDesc {
            name: "srv_name",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.srv_name.map(|n| Sample::Str(n.to_string())),
        });
        // `acl(<name>[,<name>...])`: true when every named ACL matches, each one optionally
        // negated by a leading `!` (`smp_fetch_acl`, src/acl.c). An ACL that does not exist
        // gives no sample.
        self.register_fetch(FetchDesc {
            name: "acl",
            out_type: SampleType::Bool,
            func: |ctx, args| {
                let acls = ctx.acls?;
                let reg = sample_registry();
                for a in args {
                    let (neg, name) = a.strip_prefix('!').map_or((false, a.as_str()), |n| (true, n));
                    if acls.get(name)?.eval(reg, ctx) == neg {
                        return Some(Sample::Bool(false));
                    }
                }
                Some(Sample::Bool(true))
            },
        });
        // The server and backend state fetches (`src/backend.c`). Their arguments are
        // resolved when the configuration loads; `queue`, `avg_queue`, `srv_queue` and
        // `be_conn` are refused there instead (see [`NOT_IMPLEMENTED`]).
        self.register_fetch(FetchDesc {
            name: "srv_is_up",
            out_type: SampleType::Bool,
            func: |ctx, args| server_fetch(ctx, args, |s| Sample::Bool(s.is_up)),
        });
        self.register_fetch(FetchDesc {
            name: "nbsrv",
            out_type: SampleType::Sint,
            func: |ctx, args| ctx.proxies?.usable_servers(backend_arg(ctx, args)?).map(Sample::Sint),
        });
        self.register_fetch(FetchDesc {
            name: "srv_conn",
            out_type: SampleType::Sint,
            func: |ctx, args| server_fetch(ctx, args, |s| Sample::Sint(i64::from(s.cur_sess))),
        });
        self.register_fetch(FetchDesc {
            name: "srv_conn_free",
            out_type: SampleType::Sint,
            func: |ctx, args| server_fetch(ctx, args, conn_free),
        });
        self.register_fetch(FetchDesc {
            name: "be_conn_free",
            out_type: SampleType::Sint,
            func: |ctx, args| ctx.proxies?.backend_conn_free(backend_arg(ctx, args)?).map(Sample::Sint),
        });
        self.register_fetch(FetchDesc {
            name: "fe_conn",
            out_type: SampleType::Sint,
            func: |ctx, args| ctx.proxies?.frontend_counter(frontend_arg(ctx, args)?, FrontendCounter::Conn).map(Sample::Sint),
        });

        self.register_fetch(FetchDesc {
            name: "so_id",
            out_type: SampleType::Sint,
            func: |ctx, _args| ctx.so_id.map(|id| Sample::Sint(i64::from(id))),
        });
        self.register_fetch(FetchDesc {
            name: "so_name",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.so_name.map(|n| Sample::Str(n.to_string())),
        });

        // --- 9. Connection & Rate Fetches ---
        self.register_fetch(FetchDesc {
            name: "act_conn",
            out_type: SampleType::Sint,
            // `smp_fetch_actconn`: the connections open on every frontend, not the current one's.
            func: |ctx, _args| ctx.proxies.map(|p| Sample::Sint(p.active_connections())),
        });
        self.register_fetch(FetchDesc {
            name: "dst_conn",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(i64::from(ctx.act_conn))),
        });
        self.register_fetch(FetchDesc {
            name: "fe_sess_rate",
            out_type: SampleType::Sint,
            func: |ctx, args| ctx.proxies?.frontend_counter(frontend_arg(ctx, args)?, FrontendCounter::SessRate).map(Sample::Sint),
        });
        self.register_fetch(FetchDesc {
            name: "be_sess_rate",
            out_type: SampleType::Sint,
            func: |ctx, args| ctx.proxies?.backend_sess_rate(backend_arg(ctx, args)?).map(Sample::Sint),
        });
        self.register_fetch(FetchDesc {
            name: "srv_sess_rate",
            out_type: SampleType::Sint,
            func: |ctx, args| server_fetch(ctx, args, |s| Sample::Sint(s.sess_rate)),
        });
        self.register_fetch(FetchDesc {
            name: "fe_req_rate",
            out_type: SampleType::Sint,
            func: |ctx, args| ctx.proxies?.frontend_counter(frontend_arg(ctx, args)?, FrontendCounter::ReqRate).map(Sample::Sint),
        });

        // --- 10. Stick-table counters: sc_*, sc[0-9]_*, src_* ---
        //
        // `smp_fetch_sc_conn_cnt` and its siblings (`src/stick_table.c`): the entry of the
        // table tracked in the stream's slot, or the client's address looked up in the table
        // the argument names. Nothing tracked, or a data type the table does not store, is no
        // sample -- these used to fall back to unrelated per-connection fields. Where the
        // entry itself is missing the value is 0. The rest is [`StickState`].
        macro_rules! reg_stick {
            ($suffix:literal, $data:expr) => {
                self.register_fetch(FetchDesc {
                    name: concat!("sc_", $suffix),
                    out_type: SampleType::Sint,
                    func: |ctx, args| {
                        let slot = args.first()?.parse::<usize>().ok()?;
                        let table = args.get(1).map(String::as_str).filter(|a| !a.is_empty());
                        ctx.stick?.tracked(slot, table, $data).map(Sample::Sint)
                    },
                });
                self.register_fetch(FetchDesc {
                    name: concat!("sc0_", $suffix),
                    out_type: SampleType::Sint,
                    func: |ctx, args| ctx.stick?.tracked(0, table_arg(args), $data).map(Sample::Sint),
                });
                self.register_fetch(FetchDesc {
                    name: concat!("sc1_", $suffix),
                    out_type: SampleType::Sint,
                    func: |ctx, args| ctx.stick?.tracked(1, table_arg(args), $data).map(Sample::Sint),
                });
                self.register_fetch(FetchDesc {
                    name: concat!("sc2_", $suffix),
                    out_type: SampleType::Sint,
                    func: |ctx, args| ctx.stick?.tracked(2, table_arg(args), $data).map(Sample::Sint),
                });
                self.register_fetch(FetchDesc {
                    name: concat!("src_", $suffix),
                    out_type: SampleType::Sint,
                    func: |ctx, args| ctx.stick?.source(ctx.client_addr?.ip(), &source_tables(ctx, args), $data).map(Sample::Sint),
                });
            };
        }
        reg_stick!("conn_cnt", StickData::ConnCnt);
        reg_stick!("conn_cur", StickData::ConnCur);
        reg_stick!("conn_rate", StickData::ConnRate);
        reg_stick!("sess_cnt", StickData::SessCnt);
        reg_stick!("http_req_cnt", StickData::HttpReqCnt);
        reg_stick!("http_req_rate", StickData::HttpReqRate);
        reg_stick!("http_err_cnt", StickData::HttpErrCnt);
        reg_stick!("http_err_rate", StickData::HttpErrRate);
        reg_stick!("kbytes_in", StickData::KbytesIn);
        reg_stick!("kbytes_out", StickData::KbytesOut);
        reg_stick!("sess_rate", StickData::SessRate);
        reg_stick!("http_fail_cnt", StickData::HttpFailCnt);
        reg_stick!("http_fail_rate", StickData::HttpFailRate);
        reg_stick!("bytes_in_rate", StickData::BytesInRate);
        reg_stick!("bytes_out_rate", StickData::BytesOutRate);
        reg_stick!("glitch_cnt", StickData::GlitchCnt);
        reg_stick!("glitch_rate", StickData::GlitchRate);

        // The general purpose counters and tags. `sc_get_gpc0(<ctr>[,<table>])`,
        // `sc[0-2]_get_gpc0([<table>])` and `src_get_gpc0(<table>)` read, `*_inc_gpc0` and
        // `*_clr_gpc0` (and `1`) write, `gpc0_rate` reads the rate; the array forms take the
        // element first: `sc_get_gpc(<idx>,<ctr>[,<table>])`, `src_get_gpc(<idx>,<table>)`.
        // `sc1_clr_gpc` is the only `sc[0-2]_` shorthand of an array form `HAProxy` registers.
        macro_rules! reg_legacy {
            ($suffix:literal, $read:expr) => {
                self.register_fetch(FetchDesc {
                    name: concat!("sc_", $suffix),
                    out_type: SampleType::Sint,
                    func: |ctx, args| {
                        let slot = args.first()?.parse::<usize>().ok()?;
                        let table = args.get(1).map(String::as_str).filter(|a| !a.is_empty());
                        stick_act(ctx, Target::Slot(slot, table), $read)
                    },
                });
                self.register_fetch(FetchDesc {
                    name: concat!("sc0_", $suffix),
                    out_type: SampleType::Sint,
                    func: |ctx, args| stick_act(ctx, Target::Slot(0, table_arg(args)), $read),
                });
                self.register_fetch(FetchDesc {
                    name: concat!("sc1_", $suffix),
                    out_type: SampleType::Sint,
                    func: |ctx, args| stick_act(ctx, Target::Slot(1, table_arg(args)), $read),
                });
                self.register_fetch(FetchDesc {
                    name: concat!("sc2_", $suffix),
                    out_type: SampleType::Sint,
                    func: |ctx, args| stick_act(ctx, Target::Slot(2, table_arg(args)), $read),
                });
                self.register_fetch(FetchDesc {
                    name: concat!("src_", $suffix),
                    out_type: SampleType::Sint,
                    func: |ctx, args| stick_act(ctx, Target::Source(&source_tables(ctx, args)), $read),
                });
            };
        }
        reg_legacy!("get_gpc0", Act::Read(StickData::Gpc0));
        reg_legacy!("get_gpc1", Act::Read(StickData::Gpc1));
        reg_legacy!("get_gpt0", Act::Read(StickData::Gpt0));
        reg_legacy!("gpc0_rate", Act::Read(StickData::Gpc0Rate));
        reg_legacy!("gpc1_rate", Act::Read(StickData::Gpc1Rate));
        reg_legacy!("inc_gpc0", Act::Write(StickOp::IncGpc(StickGpc::Zero)));
        reg_legacy!("inc_gpc1", Act::Write(StickOp::IncGpc(StickGpc::One)));
        reg_legacy!("clr_gpc0", Act::Write(StickOp::ClrGpc(StickGpc::Zero)));
        reg_legacy!("clr_gpc1", Act::Write(StickOp::ClrGpc(StickGpc::One)));
        macro_rules! reg_array {
            ($suffix:literal, $idx:ident => $act:expr) => {
                self.register_fetch(FetchDesc {
                    name: concat!("sc_", $suffix),
                    out_type: SampleType::Sint,
                    func: |ctx, args| {
                        let $idx = args.first()?.parse::<usize>().ok()?;
                        let slot = args.get(1)?.parse::<usize>().ok()?;
                        let table = args.get(2).map(String::as_str).filter(|a| !a.is_empty());
                        stick_act(ctx, Target::Slot(slot, table), $act)
                    },
                });
                self.register_fetch(FetchDesc {
                    name: concat!("src_", $suffix),
                    out_type: SampleType::Sint,
                    func: |ctx, args| {
                        let $idx = args.first()?.parse::<usize>().ok()?;
                        let tables: Vec<&str> = match args.get(1).map(String::as_str).filter(|a| !a.is_empty()) {
                            Some(t) => vec![t],
                            None => ctx.be_name.into_iter().chain(ctx.fe_name).collect(),
                        };
                        stick_act(ctx, Target::Source(&tables), $act)
                    },
                });
            };
        }
        reg_array!("get_gpc", i => Act::Read(StickData::GpcIdx(i)));
        reg_array!("get_gpt", i => Act::Read(StickData::GptIdx(i)));
        reg_array!("gpc_rate", i => Act::Read(StickData::GpcRateIdx(i)));
        reg_array!("inc_gpc", i => Act::Write(StickOp::IncGpc(StickGpc::Idx(i))));
        reg_array!("clr_gpc", i => Act::Write(StickOp::ClrGpc(StickGpc::Idx(i))));
        self.register_fetch(FetchDesc {
            name: "sc1_clr_gpc",
            out_type: SampleType::Sint,
            func: |ctx, args| {
                let i = args.first()?.parse::<usize>().ok()?;
                let table = args.get(1).map(String::as_str).filter(|a| !a.is_empty());
                stick_act(ctx, Target::Slot(1, table), Act::Write(StickOp::ClrGpc(StickGpc::Idx(i))))
            },
        });
        // `sc_trackers` has no `src_` form in `HAProxy` (it is a stream's tracker count).
        self.register_fetch(FetchDesc {
            name: "sc_trackers",
            out_type: SampleType::Sint,
            func: |ctx, args| {
                let slot = args.first()?.parse::<usize>().ok()?;
                let table = args.get(1).map(String::as_str).filter(|a| !a.is_empty());
                ctx.stick?.tracked(slot, table, StickData::Trackers).map(Sample::Sint)
            },
        });
        self.register_fetch(FetchDesc {
            name: "sc0_trackers",
            out_type: SampleType::Sint,
            func: |ctx, args| ctx.stick?.tracked(0, table_arg(args), StickData::Trackers).map(Sample::Sint),
        });
        self.register_fetch(FetchDesc {
            name: "sc1_trackers",
            out_type: SampleType::Sint,
            func: |ctx, args| ctx.stick?.tracked(1, table_arg(args), StickData::Trackers).map(Sample::Sint),
        });
        self.register_fetch(FetchDesc {
            name: "sc2_trackers",
            out_type: SampleType::Sint,
            func: |ctx, args| ctx.stick?.tracked(2, table_arg(args), StickData::Trackers).map(Sample::Sint),
        });
        // `smp_fetch_sc_key` and `smp_fetch_sc_tracked`.
        self.register_fetch(FetchDesc {
            name: "sc_key",
            out_type: SampleType::Str,
            func: |ctx, args| ctx.stick?.tracked_key(args.first()?.parse().ok()?, None),
        });
        self.register_fetch(FetchDesc {
            name: "sc_tracked",
            out_type: SampleType::Bool,
            func: |ctx, args| {
                let table = args.get(1).map(String::as_str).filter(|a| !a.is_empty());
                Some(Sample::Bool(ctx.stick?.tracked_key(args.first()?.parse().ok()?, table).is_some()))
            },
        });
        self.register_fetch(FetchDesc {
            name: "sc0_key",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.stick?.tracked_key(0, None),
        });
        self.register_fetch(FetchDesc {
            name: "sc1_key",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.stick?.tracked_key(1, None),
        });
        self.register_fetch(FetchDesc {
            name: "sc2_key",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.stick?.tracked_key(2, None),
        });
        self.register_fetch(FetchDesc {
            name: "sc0_tracked",
            out_type: SampleType::Bool,
            func: |ctx, args| Some(Sample::Bool(ctx.stick?.tracked_key(0, table_arg(args)).is_some())),
        });
        self.register_fetch(FetchDesc {
            name: "sc1_tracked",
            out_type: SampleType::Bool,
            func: |ctx, args| Some(Sample::Bool(ctx.stick?.tracked_key(1, table_arg(args)).is_some())),
        });
        self.register_fetch(FetchDesc {
            name: "sc2_tracked",
            out_type: SampleType::Bool,
            func: |ctx, args| Some(Sample::Bool(ctx.stick?.tracked_key(2, table_arg(args)).is_some())),
        });
        // `smp_fetch_src_updt_conn_cnt`: creates or updates the client's entry.
        self.register_fetch(FetchDesc {
            name: "src_updt_conn_cnt",
            out_type: SampleType::Sint,
            func: |ctx, args| ctx.stick?.write_source(ctx.client_addr?.ip(), &source_tables(ctx, args), StickOp::UpdtConnCnt).map(Sample::Sint),
        });
        // `smp_fetch_table_cnt` and `smp_fetch_table_avl`.
        self.register_fetch(FetchDesc {
            name: "table_cnt",
            out_type: SampleType::Sint,
            func: |ctx, args| ctx.proxies?.table_usage(source_tables(ctx, args).first()?).map(|(used, _)| Sample::Sint(used)),
        });
        self.register_fetch(FetchDesc {
            name: "table_avl",
            out_type: SampleType::Sint,
            func: |ctx, args| ctx.proxies?.table_usage(source_tables(ctx, args).first()?).map(|(_, avl)| Sample::Sint(avl)),
        });

        crate::auth::register(self);
        crate::rfc7239::register(self);

        // --- 11. Timeout Fetches ---
        macro_rules! reg_timeout_fetch {
            ($name:literal, $set:ident, $kind:expr) => {
                self.register_fetch(FetchDesc {
                    name: $name,
                    out_type: SampleType::Sint,
                    func: |ctx, _args| {
                        if let Some(t_map) = ctx.timeouts {
                            if let Some(&v) = t_map.get($name) {
                                return Some(Sample::Sint(i64::from(v)));
                            }
                        }
                        CURRENT_TIMEOUTS.get().map(|t| Sample::Sint(i64::from(t.$set[$kind as usize])))
                    },
                });
            };
        }

        use TimeoutKind::{Client, Connect, Queue, Server, Tarpit, Tunnel};
        reg_timeout_fetch!("fe_client_timeout", fe, Client);
        reg_timeout_fetch!("cur_client_timeout", cur, Client);
        reg_timeout_fetch!("be_server_timeout", be, Server);
        reg_timeout_fetch!("cur_server_timeout", cur, Server);
        reg_timeout_fetch!("be_connect_timeout", be, Connect);
        reg_timeout_fetch!("cur_connect_timeout", cur, Connect);
        reg_timeout_fetch!("be_queue_timeout", be, Queue);
        reg_timeout_fetch!("cur_queue_timeout", cur, Queue);
        reg_timeout_fetch!("be_tunnel_timeout", be, Tunnel);
        reg_timeout_fetch!("cur_tunnel_timeout", cur, Tunnel);
        reg_timeout_fetch!("be_tarpit_timeout", be, Tarpit);
        reg_timeout_fetch!("cur_tarpit_timeout", cur, Tarpit);
        reg_timeout_fetch!("fe_connect_timeout", fe, Connect);
        reg_timeout_fetch!("fe_server_timeout", fe, Server);
        reg_timeout_fetch!("fe_queue_timeout", fe, Queue);
        reg_timeout_fetch!("fe_tunnel_timeout", fe, Tunnel);
        reg_timeout_fetch!("fe_tarpit_timeout", fe, Tarpit);
        reg_timeout_fetch!("be_client_timeout", be, Client);

        self.register_fetch(FetchDesc {
            name: "be_max_retries",
            out_type: SampleType::Sint,
            func: |ctx, _args| ctx.be_max_retries.map(|v| Sample::Sint(i64::from(v))),
        });
        self.register_fetch(FetchDesc {
            name: "cur_max_retries",
            out_type: SampleType::Sint,
            func: |ctx, _args| ctx.cur_max_retries.map(|v| Sample::Sint(i64::from(v))),
        });

        // --- 12. SSL Fetches ---
        // From the TLS session of the client connection (`ctx.ssl_fc`) or of the server
        // connection (`ctx.ssl_bc`); a plaintext connection has none, and `ssl_fc` is then 0.
        // `ssl_fc_version` is not a `HAProxy` fetch (`ssl_fc_protocol` is) and is not here.
        self.register_fetch(FetchDesc {
            name: "ssl_fc",
            out_type: SampleType::Bool,
            func: |ctx, _args| Some(Sample::Bool(ctx.ssl_fc.used)),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_sni",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.ssl_fc.sni.map(|v| Sample::Str(v.to_string())),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_cipher",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.ssl_fc.cipher.map(|v| Sample::Str(v.to_string())),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_protocol",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.ssl_fc.protocol.map(|v| Sample::Str(v.to_string())),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_c_used",
            out_type: SampleType::Bool,
            func: |ctx, _args| Some(Sample::Bool(ctx.ssl_fc.has_crt)),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_bc",
            out_type: SampleType::Bool,
            func: |ctx, _args| Some(Sample::Bool(ctx.ssl_bc.is_some())),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_bc_cipher",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.ssl_bc.and_then(|f| f.cipher).map(|v| Sample::Str(v.to_string())),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_bc_protocol",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.ssl_bc.and_then(|f| f.protocol).map(|v| Sample::Str(v.to_string())),
        });

        // --- 13. System, Primitive & Time Fetches ---
        self.register_fetch(FetchDesc {
            name: "always_true",
            out_type: SampleType::Bool,
            func: |_ctx, _args| Some(Sample::Bool(true)),
        });
        self.register_fetch(FetchDesc {
            name: "always_false",
            out_type: SampleType::Bool,
            func: |_ctx, _args| Some(Sample::Bool(false)),
        });
        self.register_fetch(FetchDesc {
            name: "bool",
            out_type: SampleType::Bool,
            func: |_ctx, args| {
                let s = args.first()?;
                match s.as_str() {
                    "1" | "true" | "TRUE" | "yes" | "YES" => Some(Sample::Bool(true)),
                    "0" | "false" | "FALSE" | "no" | "NO" => Some(Sample::Bool(false)),
                    _ => None,
                }
            },
        });
        self.register_fetch(FetchDesc {
            name: "str",
            out_type: SampleType::Str,
            func: |_ctx, args| {
                let s = args.first().map_or("", |s| s.as_str());
                let mut bytes = Vec::new();
                let mut chars = s.chars().peekable();
                while let Some(c) = chars.next() {
                    if c == '\\' {
                        if let Some(&'x') = chars.peek() {
                            chars.next();
                            let hex1 = chars.next();
                            let hex2 = chars.next();
                            if let (Some(h1), Some(h2)) = (hex1, hex2) {
                                if let (Some(d1), Some(d2)) = (h1.to_digit(16), h2.to_digit(16)) {
                                    bytes.push((d1 << 4 | d2) as u8);
                                    continue;
                                }
                                bytes.push(b'\\');
                                bytes.push(b'x');
                                bytes.push(h1 as u8);
                                bytes.push(h2 as u8);
                                continue;
                            }
                            bytes.push(b'\\');
                            bytes.push(b'x');
                            if let Some(h1) = hex1 { bytes.push(h1 as u8); }
                            continue;
                        }
                    }
                    let mut buf = [0; 4];
                    bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                let decoded = String::from_utf8_lossy(&bytes).into_owned();
                Some(Sample::Str(decoded))
            },
        });
        self.register_fetch(FetchDesc {
            name: "int",
            out_type: SampleType::Sint,
            func: |_ctx, args| {
                let n = args.first()?.parse::<i64>().ok()?;
                Some(Sample::Sint(n))
            },
        });
        self.register_fetch(FetchDesc {
            name: "ipv4",
            out_type: SampleType::Ipv4,
            func: |_ctx, args| {
                let s = args.first()?;
                let ip = s.parse::<std::net::Ipv4Addr>().ok()?;
                Some(Sample::Ipv4(ip))
            },
        });
        self.register_fetch(FetchDesc {
            name: "ipv6",
            out_type: SampleType::Ipv6,
            func: |_ctx, args| {
                let s = args.first()?;
                let ip = s.parse::<std::net::Ipv6Addr>().ok()?;
                Some(Sample::Ipv6(ip))
            },
        });
        self.register_fetch(FetchDesc {
            name: "bin",
            out_type: SampleType::Bin,
            func: |_ctx, args| {
                let s = args.first()?;
                if let Some(b) = hex_decode(s) {
                    Some(Sample::Bin(b))
                } else {
                    Some(Sample::Bin(s.as_bytes().to_vec()))
                }
            },
        });
        self.register_fetch(FetchDesc {
            name: "uuid",
            out_type: SampleType::Str,
            func: |_ctx, _args| {
                let mut b = [0u8; 16];
                let _ = getrandom::getrandom(&mut b);
                b[6] = (b[6] & 0x0f) | 0x40; // version 4
                b[8] = (b[8] & 0x3f) | 0x80; // variant 1
                let s = format!(
                    "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
                );
                Some(Sample::Str(s))
            },
        });
        // `smp_fetch_fc_pp_unique_id`: `fc_pp_tlv(PP2_TYPE_UNIQUE_ID)`, first occurrence only.
        self.register_fetch(FetchDesc {
            name: "fc_pp_unique_id",
            out_type: SampleType::Str,
            func: |ctx, _args| {
                let mut t = ctx.proxy_tlvs?;
                while t.len() >= 3 {
                    let len = usize::from(u16::from_be_bytes([t[1], t[2]]));
                    let value = t.get(3..3 + len)?;
                    if t[0] == 0x05 {
                        return Some(Sample::Str(String::from_utf8_lossy(value).into_owned()));
                    }
                    t = &t[3 + len..];
                }
                None
            },
        });
        self.register_fetch(FetchDesc {
            name: "fc_pp_tlv",
            out_type: SampleType::Bin,
            func: |ctx, args| {
                let target_type_str = args.first()?;
                let target_type = if let Some(hex) = target_type_str.strip_prefix("0x").or_else(|| target_type_str.strip_prefix("0X")) {
                    u8::from_str_radix(hex, 16).ok()?
                } else {
                    target_type_str.parse::<u8>().ok()?
                };
                let tlvs_data = ctx.proxy_tlvs?;
                let mut matches = Vec::new();
                let mut idx = 0;
                while idx + 3 <= tlvs_data.len() {
                    let tlv_type = tlvs_data[idx];
                    let tlv_len = usize::from(u16::from_be_bytes([tlvs_data[idx + 1], tlvs_data[idx + 2]]));
                    let val_start = idx + 3;
                    let val_end = val_start + tlv_len;
                    if val_end > tlvs_data.len() {
                        break;
                    }
                    if tlv_type == target_type {
                        matches.push(&tlvs_data[val_start..val_end]);
                    }
                    idx = val_end;
                }
                if matches.is_empty() {
                    return None;
                }
                if let Some(occ) = args.get(1).and_then(|s| s.parse::<i64>().ok()) {
                    if occ > 0 {
                        let uidx = usize::try_from(occ - 1).ok()?;
                        return matches.get(uidx).map(|s| Sample::Bin((*s).to_vec()));
                    } else if occ < 0 {
                        let back = usize::try_from(occ.unsigned_abs()).ok()?;
                        let uidx = matches.len().checked_sub(back)?;
                        return matches.get(uidx).map(|s| Sample::Bin((*s).to_vec()));
                    }
                }
                matches.first().map(|s| Sample::Bin((*s).to_vec()))
            },
        });
        self.register_multi_fetch("fc_pp_tlv", |ctx, args| {
            let Some(target_type_str) = args.first() else {
                return Vec::new();
            };
            let Some(target_type) = (if let Some(hex) = target_type_str.strip_prefix("0x").or_else(|| target_type_str.strip_prefix("0X")) {
                u8::from_str_radix(hex, 16).ok()
            } else {
                target_type_str.parse::<u8>().ok()
            }) else {
                return Vec::new();
            };
            let Some(tlvs_data) = ctx.proxy_tlvs else {
                return Vec::new();
            };
            let mut matches = Vec::new();
            let mut idx = 0;
            while idx + 3 <= tlvs_data.len() {
                let tlv_type = tlvs_data[idx];
                let tlv_len = usize::from(u16::from_be_bytes([tlvs_data[idx + 1], tlvs_data[idx + 2]]));
                let val_start = idx + 3;
                let val_end = val_start + tlv_len;
                if val_end > tlvs_data.len() {
                    break;
                }
                if tlv_type == target_type {
                    matches.push(&tlvs_data[val_start..val_end]);
                }
                idx = val_end;
            }
            if matches.is_empty() {
                return Vec::new();
            }
            if let Some(occ) = args.get(1).and_then(|s| s.parse::<i64>().ok()) {
                if occ > 0 {
                    if let Ok(uidx) = usize::try_from(occ - 1) {
                        return matches.get(uidx).map(|s| Sample::Bin((*s).to_vec())).into_iter().collect();
                    }
                } else if occ < 0 {
                    if let Ok(back) = usize::try_from(occ.unsigned_abs()) {
                        if let Some(uidx) = matches.len().checked_sub(back) {
                            return matches.get(uidx).map(|s| Sample::Bin((*s).to_vec())).into_iter().collect();
                        }
                    }
                }
            }
            matches.into_iter().map(|m| Sample::Bin(m.to_vec())).collect()
        });
        self.register_fetch(FetchDesc {
            name: "var",
            out_type: SampleType::Str,
            func: |ctx, args| {
                let var_name = args.first()?;
                if var_name.starts_with("proc.") {
                    return get_proc_var(var_name).map(Sample::Str)
                        .or_else(|| args.get(1).cloned().map(Sample::Str));
                }
                if let Some(v_map) = ctx.vars {
                    if let Some(val) = v_map.get(var_name) {
                        return Some(Sample::Str(val.clone()));
                    }
                }
                CURRENT_VARS.with(|v| v.borrow().get(var_name).cloned().map(Sample::Str))
                    .or_else(|| args.get(1).cloned().map(Sample::Str))
            },
        });
        self.register_fetch(FetchDesc {
            name: "env",
            out_type: SampleType::Str,
            func: |_ctx, args| {
                let var_name = args.first()?;
                std::env::var(var_name).ok().map(Sample::Str)
            },
        });
        // `date([<offset>],[<unit>])`: now, in seconds, `ms` or `us`; the offset is in that
        // unit (measured on HAProxy 3.5-dev8: `date(3600,ms)` is 3.6 seconds ahead).
        let date_fetch: FetchFn = |_ctx, args| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let offset = args.first().filter(|a| !a.is_empty()).map_or(Some(0), |a| a.parse::<i64>().ok())?;
            let v = match args.get(1).map_or("s", String::as_str) {
                "s" | "" => u64_to_sint(now.as_secs()),
                "ms" => i64::try_from(now.as_millis()).ok()?,
                "us" => i64::try_from(now.as_micros()).ok()?,
                _ => return None,
            };
            Some(Sample::Sint(v.checked_add(offset)?))
        };
        // `accept_date[(<unit>)]`: when the stream was accepted (milliseconds resolution).
        self.register_fetch(FetchDesc {
            name: "accept_date",
            out_type: SampleType::Sint,
            func: |ctx, args| {
                let (secs, ms) = ctx.accept_date?;
                match args.first().map_or("s", String::as_str) {
                    "s" | "" => Some(Sample::Sint(secs)),
                    "ms" => Some(Sample::Sint(secs * 1000 + i64::from(ms))),
                    "us" => Some(Sample::Sint((secs * 1000 + i64::from(ms)) * 1000)),
                    _ => None,
                }
            },
        });
        self.register_fetch(FetchDesc {
            name: "date",
            out_type: SampleType::Sint,
            func: date_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "date_us",
            out_type: SampleType::Sint,
            func: |_ctx, _args| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                // Saturating rather than wrapping: microseconds since the epoch exceed
                // i64 only past the year 294247, so this is unreachable, but a wrap
                // would hand out a negative timestamp instead of an obviously clamped one.
                Some(Sample::Sint(
                    i64::try_from(now.as_micros()).unwrap_or(i64::MAX),
                ))
            },
        });
        self.register_fetch(FetchDesc {
            name: "rand",
            out_type: SampleType::Sint,
            func: |_ctx, args| {
                let max = args
                    .first()
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(u32::MAX);
                let seed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                let seed_u32 = u32::from_ne_bytes(seed.to_ne_bytes()[..4].try_into().unwrap());
                let r = i64::from(full_hash(seed_u32) % max.max(1));
                Some(Sample::Sint(r))
            },
        });
    }

    #[allow(clippy::too_many_lines)]
    fn register_builtin_converters(&mut self) {
                
        // --- 1. String Transforms ---
        self.register_converter(ConvDesc {
            name: "lower",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Str(s) => Some(Sample::Str(s.to_lowercase())),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "upper",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Str(s) => Some(Sample::Str(s.to_uppercase())),
                _ => None,
            },
        });

        // A sample longer than i64::MAX bytes cannot exist, so the conversion never
        // fails; it is fallible here so that a length can never arrive as a negative.
        let len_conv: ConvFn = |smp, _args| match smp {
            Sample::Str(s) => Some(Sample::Sint(i64::try_from(s.len()).unwrap_or(i64::MAX))),
            Sample::Bin(b) => Some(Sample::Sint(i64::try_from(b.len()).unwrap_or(i64::MAX))),
            _ => None,
        };
        self.register_converter(ConvDesc {
            name: "len",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: len_conv,
        });
        // `length` takes a string: a binary is cast first, and the cast stops at the first NUL
        // byte (`c_bin2str`), so the length of `\x00\x01...` is 0. The bytes are counted here,
        // before they would have to be valid UTF-8 to become a `String`.
        self.register_converter(ConvDesc {
            name: "length",
            in_type: TypeSpec::Any,
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| {
                let n = match &smp {
                    Sample::Str(s) => s.len(),
                    Sample::Bin(b) => b.iter().position(|&c| c == 0).unwrap_or(b.len()),
                    other => sample_to_string(other).len(),
                };
                Some(Sample::Sint(i64::try_from(n).unwrap_or(i64::MAX)))
            },
        });

        self.register_converter(ConvDesc {
            name: "concat",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| match smp {
                Sample::Str(mut s) => {
                    let start = args.first().map_or("", String::as_str);
                    let var_name = args.get(1).map_or("", String::as_str);
                    let end = args.get(2).map_or("", String::as_str);

                    let var_val = if var_name.is_empty() {
                        String::new()
                    } else {
                        resolve_var_str(var_name)
                    };

                    s.push_str(start);
                    s.push_str(&var_val);
                    s.push_str(end);
                    Some(Sample::Str(s))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "strcmp",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| {
                let target_arg = args.first()?;
                let target_val = CURRENT_VARS
                    .with(|v| v.borrow().get(target_arg).cloned())
                    .unwrap_or_else(|| target_arg.clone());
                let Sample::Str(s) = smp else { return None };
                let cmp = s.cmp(&target_val);
                let res = match cmp {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                };
                Some(Sample::Sint(res))
            },
        });

        self.register_converter(ConvDesc {
            name: "field",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                let idx_str = args.first()?;
                let delim_char = args.get(1).and_then(|d| d.chars().next()).unwrap_or(' ');
                let count_str = args.get(2);

                let idx: i64 = idx_str.parse().ok()?;
                let count: usize = count_str.and_then(|c| c.parse().ok()).unwrap_or(1);

                let Sample::Str(s) = smp else { return None };
                let fields: Vec<&str> = s.split(delim_char).collect();
                let len = fields.len();
                // A field past either end is "no sample", not an empty one.
                let start_idx = match idx.cmp(&0) {
                    std::cmp::Ordering::Greater => {
                        usize::try_from(idx).unwrap_or(usize::MAX).saturating_sub(1)
                    }
                    std::cmp::Ordering::Less => {
                        let neg_idx = usize::try_from(idx.saturating_neg()).unwrap_or(usize::MAX);
                        if neg_idx > len {
                            return None;
                        }
                        len - neg_idx
                    }
                    std::cmp::Ordering::Equal => return None,
                };
                if start_idx >= len {
                    return None;
                }
                let end_idx = if count == 0 {
                    len
                } else {
                    (start_idx + count).min(len)
                };
                let joined = fields[start_idx..end_idx].join(&delim_char.to_string());
                Some(Sample::Str(joined))
            },
        });

        self.register_converter(ConvDesc {
            name: "word",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                let idx_str = args.first()?;
                let delims = args.get(1).map_or(" ", String::as_str);
                let count_str = args.get(2);

                let idx: i64 = idx_str.parse().ok()?;
                if idx == 0 {
                    return None;
                }
                let count: usize = count_str.and_then(|c| c.parse().ok()).unwrap_or(1);

                let Sample::Str(s) = smp else { return None };
                let mut words: Vec<(usize, usize)> = Vec::new();
                let mut in_word = false;
                let mut word_start = 0;
                for (char_idx, ch) in s.char_indices() {
                    let is_delim = delims.contains(ch);
                    if in_word {
                        if is_delim {
                            words.push((word_start, char_idx));
                            in_word = false;
                        }
                    } else if !is_delim {
                        word_start = char_idx;
                        in_word = true;
                    }
                }
                if in_word {
                    words.push((word_start, s.len()));
                }

                let len = words.len();
                if len == 0 {
                    return None;
                }

                let start_idx = match idx.cmp(&0) {
                    std::cmp::Ordering::Greater => {
                        usize::try_from(idx).unwrap_or(usize::MAX).saturating_sub(1)
                    }
                    std::cmp::Ordering::Less => {
                        let neg_idx = usize::try_from(idx.saturating_neg()).unwrap_or(usize::MAX);
                        if neg_idx > len {
                            return None;
                        }
                        len - neg_idx
                    }
                    std::cmp::Ordering::Equal => return None,
                };

                if start_idx >= len {
                    return None;
                }

                let end_word_idx = if count == 0 {
                    len - 1
                } else {
                    (start_idx + count - 1).min(len - 1)
                };

                let slice = &s[words[start_idx].0..words[end_word_idx].1];
                Some(Sample::Str(slice.to_string()))
            },
        });

        self.register_converter(ConvDesc {
            name: "param",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                let param_name = args.first()?;
                // The separator is one character, written as itself or as `0x<hex>`.
                let delim = args.get(1).map_or("&".to_string(), |d| {
                    d.strip_prefix("0x")
                        .or_else(|| d.strip_prefix("0X"))
                        .and_then(|h| u8::from_str_radix(h, 16).ok())
                        .map_or_else(|| d.clone(), |b| char::from(b).to_string())
                });
                let Sample::Str(s) = smp else { return None };
                for pair in s.split(delim.as_str()) {
                    if let Some((k, v)) = pair.split_once('=') {
                        if k == param_name {
                            return Some(Sample::Str(v.to_string()));
                        }
                    } else if pair == param_name {
                        return Some(Sample::Str(String::new()));
                    }
                }
                None
            },
        });

        self.register_converter(ConvDesc {
            name: "add_item",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                let delim = args.first().map_or(",", String::as_str);
                let var_name = args.get(1).map_or("", String::as_str);
                let suff = args.get(2).map_or("", String::as_str);

                let var_val = if var_name.is_empty() {
                    String::new()
                } else {
                    resolve_var_str(var_name)
                };

                let item = format!("{var_val}{suff}");
                let Sample::Str(s) = smp else { return None };
                if item.is_empty() {
                    Some(Sample::Str(s))
                } else if s.is_empty() {
                    Some(Sample::Str(item))
                } else {
                    Some(Sample::Str(format!("{s}{delim}{item}")))
                }
            },
        });

        self.register_converter(ConvDesc {
            name: "cut_crlf",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Str(mut s) => {
                    if let Some(pos) = s.find(['\r', '\n']) {
                        s.truncate(pos);
                    }
                    Some(Sample::Str(s))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "ltrim",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                let chars: &[char] = &[' ', '\t', '\r', '\n'];
                let pat: Vec<char> = args
                    .first()
                    .map_or_else(|| chars.to_vec(), |s| s.chars().collect());
                match smp {
                    Sample::Str(s) => Some(Sample::Str(s.trim_start_matches(&pat[..]).to_string())),
                    _ => None,
                }
            },
        });

        self.register_converter(ConvDesc {
            name: "rtrim",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                let chars: &[char] = &[' ', '\t', '\r', '\n'];
                let pat: Vec<char> = args
                    .first()
                    .map_or_else(|| chars.to_vec(), |s| s.chars().collect());
                match smp {
                    Sample::Str(s) => Some(Sample::Str(s.trim_end_matches(&pat[..]).to_string())),
                    _ => None,
                }
            },
        });

        self.register_converter(ConvDesc {
            name: "reverse",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Str(s) => Some(Sample::Str(s.chars().rev().collect())),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "reverse_dom",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Str(mut s) => {
                    if s.ends_with('.') {
                        s.pop();
                    }
                    if s.is_empty() || s.starts_with('.') || s.contains("..") {
                        return None;
                    }
                    let parts: Vec<&str> = s.split('.').collect();
                    let reversed = parts.into_iter().rev().collect::<Vec<_>>().join(".");
                    Some(Sample::Str(reversed))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "host_only",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Str(s) => Some(Sample::Str(split_host_port(&s).0.to_lowercase())),
                _ => None,
            },
        });

        // `port_only`: what follows the last colon, every byte of it taken as a digit (`abc`
        // is 5451, a `-` wraps), in an unsigned 32-bit number; 0 when there is no port.
        self.register_converter(ConvDesc {
            name: "port_only",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Str(s) => {
                    let port = split_host_port(&s).1.unwrap_or("").bytes().fold(0u32, |acc, c| {
                        acc.wrapping_mul(10).wrapping_add(u32::from(c).wrapping_sub(u32::from(b'0')))
                    });
                    Some(Sample::Sint(i64::from(port)))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "regsub",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                let pattern = args.first()?;
                let repl = args.get(1)?;
                let flags = args.get(2).map_or("", String::as_str);
                let Sample::Str(s) = smp else { return None };
                regsub_eval(&s, pattern, repl, flags).map(Sample::Str)
            },
        });

        self.register_converter(ConvDesc {
            name: "url_dec",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| match smp {
                Sample::Str(s) => {
                    let in_form = args.first().and_then(|a| a.parse::<i64>().ok()).unwrap_or(0) != 0;
                    // A '%' not followed by two hex digits makes the conversion fail.
                    let bytes = s.as_bytes();
                    let bad = bytes.iter().enumerate().any(|(i, &b)| {
                        b == b'%'
                            && !(bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                                && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
                    });
                    if bad {
                        return None;
                    }
                    Some(Sample::Str(url_decode(&s, in_form)))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "url_enc",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Str(s) => Some(Sample::Str(url_encode(&s))),
                _ => None,
            },
        });

        // --- 2. Arithmetic & Bitwise Logic ---

        self.register_converter(ConvDesc {
            name: "add",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| {
                let n = resolve_int_arg(args.first()?)?;
                match smp {
                    Sample::Sint(val) => Some(Sample::Sint(val.saturating_add(n))),
                    _ => None,
                }
            },
        });

        self.register_converter(ConvDesc {
            name: "sub",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| {
                let n = resolve_int_arg(args.first()?)?;
                match smp {
                    Sample::Sint(val) => Some(Sample::Sint(val.saturating_sub(n))),
                    _ => None,
                }
            },
        });

        self.register_converter(ConvDesc {
            name: "mul",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| {
                let factor = resolve_int_arg(args.first()?)?;
                match smp {
                    Sample::Sint(n) => Some(Sample::Sint(n.saturating_mul(factor))),
                    _ => None,
                }
            },
        });

        self.register_converter(ConvDesc {
            name: "div",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| {
                let divisor = resolve_int_arg(args.first()?)?;
                if divisor == 0 {
                    return Some(Sample::Sint(i64::MAX));
                }
                match smp {
                    Sample::Sint(n) => Some(Sample::Sint(n.checked_div(divisor).unwrap_or(i64::MAX))),
                    _ => None,
                }
            },
        });

        self.register_converter(ConvDesc {
            name: "mod",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| {
                let divisor = resolve_int_arg(args.first()?)?;
                if divisor == 0 {
                    return Some(Sample::Sint(0));
                }
                match smp {
                    Sample::Sint(n) => Some(Sample::Sint(n.checked_rem(divisor).unwrap_or(0))),
                    _ => None,
                }
            },
        });

        self.register_converter(ConvDesc {
            name: "neg",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Sint(n) => Some(Sample::Sint(n.saturating_neg())),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "and",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| {
                let mask = resolve_int_arg(args.first()?)?;
                match smp {
                    Sample::Sint(n) => Some(Sample::Sint(n & mask)),
                    _ => None,
                }
            },
        });

        self.register_converter(ConvDesc {
            name: "or",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| {
                let mask = resolve_int_arg(args.first()?)?;
                match smp {
                    Sample::Sint(n) => Some(Sample::Sint(n | mask)),
                    _ => None,
                }
            },
        });

        self.register_converter(ConvDesc {
            name: "xor",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| {
                let mask = resolve_int_arg(args.first()?)?;
                match smp {
                    Sample::Sint(n) => Some(Sample::Sint(n ^ mask)),
                    _ => None,
                }
            },
        });

        self.register_converter(ConvDesc {
            name: "cpl",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Sint(n) => Some(Sample::Sint(!n)),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "bool",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Bool),
            func: |smp, _args| match smp {
                Sample::Sint(n) => Some(Sample::Bool(n != 0)),
                Sample::Bool(b) => Some(Sample::Bool(b)),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "not",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Bool),
            func: |smp, _args| match smp {
                Sample::Sint(n) => Some(Sample::Bool(n == 0)),
                Sample::Bool(b) => Some(Sample::Bool(!b)),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "odd",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Bool),
            func: |smp, _args| match smp {
                Sample::Sint(n) => Some(Sample::Bool((n & 1) != 0)),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "even",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Bool),
            func: |smp, _args| match smp {
                Sample::Sint(n) => Some(Sample::Bool((n & 1) == 0)),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "iif",
            in_type: TypeSpec::Exact(SampleType::Bool),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                let true_val = args.first().cloned().unwrap_or_default();
                let false_val = args.get(1).cloned().unwrap_or_default();
                match smp {
                    Sample::Bool(true) => Some(Sample::Str(true_val)),
                    Sample::Bool(false) => Some(Sample::Str(false_val)),
                    _ => None,
                }
            },
        });

        // `when(<condition>[,<args>])`: the input sample, or nothing, by a condition on the
        // stream (`sample_conv_when`).
        self.register_ctx_converter(CtxConvDesc {
            name: "when",
            in_type: TypeSpec::Any,
            out_type: TypeSpec::Same,
            func: |ctx, smp, args| {
                let (neg, cond) = parse_when_cond(args)?;
                let facts = ctx.stream.unwrap_or_default();
                let (mut neg, ret) = match cond {
                    WhenCond::Stopping => (neg, STOPPING.load(std::sync::atomic::Ordering::Relaxed)),
                    WhenCond::Normal => (!neg, facts.error),
                    WhenCond::Error => (neg, facts.error),
                    WhenCond::Forwarded => (neg, facts.forwarded),
                    WhenCond::ToApplet => (neg, facts.toapplet),
                    WhenCond::Processed => (neg, facts.forwarded || facts.toapplet),
                    WhenCond::Acl(name) => {
                        let expr = ctx.acls?.get(name)?;
                        (neg, expr.eval(&sample_registry(), ctx))
                    }
                };
                neg ^= ret;
                neg.then_some(smp)
            },
        });

        // --- 3. Encoding & Binary Converters ---
        // FIX (src/fix.c). A message that needs more data yields nothing; the
        // response rules ask `fix` directly whether to wait (`SMP_F_MAY_CHANGE`).
        self.register_converter(ConvDesc {
            name: "fix_is_valid",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bool),
            func: |smp, _args| {
                // The input is cast to binary first (`in_type`).
                let Sample::Bin(b) = smp else { return None };
                match crate::fix::validate_message(&b) {
                    crate::fix::Validity::Valid => Some(Sample::Bool(true)),
                    crate::fix::Validity::Invalid => Some(Sample::Bool(false)),
                    crate::fix::Validity::NeedMoreData => None,
                }
            },
        });
        self.register_converter(ConvDesc {
            name: "fix_tag_value",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, args| {
                let Sample::Bin(b) = smp else { return None };
                let id = crate::fix::tag_id(args.first()?.trim())?;
                let crate::fix::TagValue::Found(v) = crate::fix::tag_value(&b, id) else { return None };
                Some(Sample::Bin(v.to_vec()))
            },
        });
        self.register_converter(ConvDesc {
            name: "hex",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Str(hex_encode(&b))),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "hex2bin",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, _args| match smp {
                Sample::Str(s) => hex_decode(&s).map(Sample::Bin),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "hex2i",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Str(s) => {
                    let clean = s.trim();
                    if clean.is_empty() {
                        return Some(Sample::Sint(0));
                    }
                    if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
                        return None;
                    }
                    i64::from_str_radix(clean, 16).ok().map(Sample::Sint)
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "base64",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Str(base64_encode(&b, false))),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "b64dec",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, _args| match smp {
                Sample::Str(s) => base64_decode(&s, false, true).map(Sample::Bin),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "ub64enc",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Str(base64_encode(&b, true))),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "ub64dec",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, _args| match smp {
                Sample::Str(s) => base64_decode(&s, true, false).map(Sample::Bin),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "base2",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    let mut s = String::with_capacity(b.len() * 8);
                    for byte in b {
                        use std::fmt::Write;
                        let _ = write!(s, "{byte:08b}");
                    }
                    Some(Sample::Str(s))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "be2dec",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| match smp {
                Sample::Bin(b) => {
                    let sep = args.first().map_or("", String::as_str);
                    let chunk_size = match args.get(1) {
                        Some(s) => match s.parse::<usize>() {
                            Ok(n) if (1..=8).contains(&n) => n,
                            _ => return None,
                        },
                        None => {
                            if b.is_empty() {
                                1
                            } else {
                                b.len().min(8)
                            }
                        }
                    };
                    let truncate = args.get(2).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0) == 1;
                    if b.is_empty() {
                        return Some(Sample::Str(String::new()));
                    }
                    let mut parts = Vec::new();
                    for chunk in b.chunks(chunk_size) {
                        if chunk.len() < chunk_size && truncate {
                            continue;
                        }
                        let mut n: u64 = 0;
                        for byte in chunk {
                            n = (n << 8) | u64::from(*byte);
                        }
                        parts.push(n.to_string());
                    }
                    Some(Sample::Str(parts.join(sep)))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "le2dec",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| match smp {
                Sample::Bin(b) => {
                    let sep = args.first().map_or("", String::as_str);
                    let chunk_size = match args.get(1) {
                        Some(s) => match s.parse::<usize>() {
                            Ok(n) if (1..=8).contains(&n) => n,
                            _ => return None,
                        },
                        None => {
                            if b.is_empty() {
                                1
                            } else {
                                b.len().min(8)
                            }
                        }
                    };
                    let truncate = args.get(2).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0) == 1;
                    if b.is_empty() {
                        return Some(Sample::Str(String::new()));
                    }
                    let mut parts = Vec::new();
                    for chunk in b.chunks(chunk_size) {
                        if chunk.len() < chunk_size && truncate {
                            continue;
                        }
                        let mut n: u64 = 0;
                        for (i, byte) in chunk.iter().enumerate() {
                            n |= u64::from(*byte) << (i * 8);
                        }
                        parts.push(n.to_string());
                    }
                    Some(Sample::Str(parts.join(sep)))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "be2hex",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| match smp {
                Sample::Bin(b) => {
                    let sep = args.first().map_or("", String::as_str);
                    let chunk_size = match args.get(1) {
                        Some(s) => {
                            let n = s.parse::<usize>().ok()?;
                            if n == 0 {
                                return None;
                            }
                            n
                        }
                        None => {
                            if b.is_empty() {
                                1
                            } else {
                                b.len()
                            }
                        }
                    };
                    let truncate = args.get(2).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0) == 1;
                    if b.is_empty() {
                        return Some(Sample::Str(String::new()));
                    }
                    let mut parts = Vec::new();
                    for chunk in b.chunks(chunk_size) {
                        if chunk.len() < chunk_size && truncate {
                            continue;
                        }
                        parts.push(hex_encode(chunk));
                    }
                    Some(Sample::Str(parts.join(sep)))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "be_sort",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, args| {
                let size = args.first().and_then(|s| s.parse::<usize>().ok()).unwrap_or(1);
                match smp {
                    Sample::Bin(b) => {
                        if size == 0 || b.len() % size != 0 {
                            return None;
                        }
                        let mut chunks: Vec<Vec<u8>> = b.chunks_exact(size).map(|c| c.to_vec()).collect();
                        chunks.sort_unstable();
                        Some(Sample::Bin(chunks.into_iter().flatten().collect()))
                    }
                    _ => None,
                }
            },
        });

        self.register_converter(ConvDesc {
            name: "has_ctl",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bool),
            func: |smp, args| match smp {
                Sample::Bin(b) => {
                    let mask = has_ctl_mask(args.first().map_or("", String::as_str))?;
                    let has = b.iter().any(|&c| match c {
                        0..=31 => mask >> c & 1 != 0,
                        127 => mask >> 32 & 1 != 0,
                        _ => false,
                    });
                    Some(Sample::Bool(has))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "bytes",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, args| match smp {
                Sample::Bin(b) => {
                    let offset_arg: i64 = match args.first() {
                        Some(s) => resolve_int_arg(s)?,
                        None => 0,
                    };
                    if offset_arg < 0 {
                        return None;
                    }
                    let len_arg: Option<i64> = match args.get(1) {
                        Some(s) => {
                            let l = resolve_int_arg(s)?;
                            if l < 0 {
                                return None;
                            }
                            Some(l)
                        }
                        None => None,
                    };
                    let offset = usize::try_from(offset_arg).unwrap_or(usize::MAX);
                    if offset >= b.len() {
                        Some(Sample::Bin(Vec::new()))
                    } else {
                        let len = len_arg.map_or(usize::MAX, |l| usize::try_from(l).unwrap_or(usize::MAX));
                        let end = b.len().min(offset.saturating_add(len));
                        Some(Sample::Bin(b[offset..end].to_vec()))
                    }
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "htonl",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, _args| match smp {
                Sample::Sint(n) => Some(Sample::Bin(n.to_be_bytes()[4..8].to_vec())),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "ipmask",
            in_type: TypeSpec::Addr,
            out_type: TypeSpec::Same,
            func: |smp, args| {
                let mask1_str = args.first()?;
                let mask2_str = args.get(1);
                match smp {
                    Sample::Ipv4(ip) => {
                        let mask = if let Ok(prefix) = mask1_str.parse::<u32>() {
                            if prefix == 0 {
                                0
                            } else if prefix >= 32 {
                                u32::MAX
                            } else {
                                !((1u32 << (32 - prefix)) - 1)
                            }
                        } else if let Ok(m_ip) = mask1_str.parse::<Ipv4Addr>() {
                            u32::from(m_ip)
                        } else {
                            return None;
                        };
                        Some(Sample::Ipv4(Ipv4Addr::from(u32::from(ip) & mask)))
                    }
                    Sample::Ipv6(ip) => {
                        let mask6_str = mask2_str?;
                        let mask = if let Ok(prefix) = mask6_str.parse::<u32>() {
                            if prefix == 0 {
                                0
                            } else if prefix >= 128 {
                                u128::MAX
                            } else {
                                !((1u128 << (128 - prefix)) - 1)
                            }
                        } else if let Ok(m_ip) = mask6_str.parse::<Ipv6Addr>() {
                            u128::from(m_ip)
                        } else {
                            return None;
                        };
                        Some(Sample::Ipv6(Ipv6Addr::from(u128::from(ip) & mask)))
                    }
                    _ => None,
                }
            },
        });

        // --- 4. Hash Algorithms ---
        self.register_converter(ConvDesc {
            name: "crc32",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| match smp {
                Sample::Bin(b) => {
                    let mut h = hash_crc32(&b);
                    if args.first().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0) != 0 {
                        h = full_hash(h);
                    }
                    Some(Sample::Sint(i64::from(h)))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "crc32c",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| match smp {
                Sample::Bin(b) => {
                    let mut h = hash_crc32c(&b);
                    if args.first().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0) != 0 {
                        h = full_hash(h);
                    }
                    Some(Sample::Sint(i64::from(h)))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "djb2",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| match smp {
                Sample::Bin(b) => {
                    let mut h = hash_djb2(&b);
                    if args.first().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0) != 0 {
                        h = full_hash(h);
                    }
                    Some(Sample::Sint(i64::from(h)))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "sdbm",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| match smp {
                Sample::Bin(b) => {
                    let mut h = hash_sdbm(&b);
                    if args.first().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0) != 0 {
                        h = full_hash(h);
                    }
                    Some(Sample::Sint(i64::from(h)))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "wt6",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| match smp {
                Sample::Bin(b) => {
                    let mut h = hash_wt6(&b);
                    if args.first().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0) != 0 {
                        h = full_hash(h);
                    }
                    Some(Sample::Sint(i64::from(h)))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "xxh32",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| {
                let seed = args.first().and_then(|s| s.parse().ok()).unwrap_or(0);
                match smp {
                    Sample::Bin(b) => Some(Sample::Sint(i64::from(hash_xxh32(&b, seed)))),
                    _ => None,
                }
            },
        });

        self.register_converter(ConvDesc {
            name: "xxh64",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| {
                let seed = args.first().and_then(|s| s.parse().ok()).unwrap_or(0);
                match smp {
                    Sample::Bin(b) => {
                        let h = hash_xxh64(&b, seed);
                        Some(Sample::Sint(i64::from_ne_bytes(h.to_ne_bytes())))
                    }
                    _ => None,
                }
            },
        });

        self.register_converter(ConvDesc {
            name: "xxh3",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| {
                let seed = args.first().and_then(|s| s.parse().ok()).unwrap_or(0);
                match smp {
                    Sample::Bin(b) => {
                        let h = hash_xxh3(&b, seed);
                        Some(Sample::Sint(i64::from_ne_bytes(h.to_ne_bytes())))
                    }
                    _ => None,
                }
            },
        });

        self.register_converter(ConvDesc {
            name: "sha1",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Bin(sha1_digest(&b).to_vec())),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "sha2",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, args| {
                let bits = args.first().map_or("256", String::as_str);
                let Sample::Bin(b) = smp else { return None };
                let out = match bits {
                    "224" => sha224_digest(&b).to_vec(),
                    "384" => sha384_digest(&b).to_vec(),
                    "512" => sha512_digest(&b).to_vec(),
                    _ => sha256_digest(&b).to_vec(),
                };
                Some(Sample::Bin(out))
            },
        });

        self.register_converter(ConvDesc {
            name: "digest",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, args| {
                let algo = args.first().map_or("sha256", String::as_str);
                let Sample::Bin(b) = smp else { return None };
                let out = match algo.to_lowercase().as_str() {
                    "sha1" => sha1_digest(&b).to_vec(),
                    "sha224" => sha224_digest(&b).to_vec(),
                    "sha384" => sha384_digest(&b).to_vec(),
                    "sha512" => sha512_digest(&b).to_vec(),
                    "md5" => md5_digest(&b).to_vec(),
                    "crc32" => hash_crc32(&b).to_be_bytes().to_vec(),
                    "crc32c" => hash_crc32c(&b).to_be_bytes().to_vec(),
                    "djb2" => hash_djb2(&b).to_be_bytes().to_vec(),
                    "sdbm" => hash_sdbm(&b).to_be_bytes().to_vec(),
                    "wt6" => hash_wt6(&b).to_be_bytes().to_vec(),
                    _ => sha256_digest(&b).to_vec(),
                };
                Some(Sample::Bin(out))
            },
        });

        // --- 5. Map Converters ---
        // HAProxy names these `map_<match>` and `map_<match>_<output>`, where the
        // match method decides how the key is compared and the output type decides how
        // the value is returned (src/map.c). Two of them take no output variants:
        // `map` is a bare alias for `map_str`, and `map_regm` always returns the
        // substituted string. Generating variants for those two is not merely extra --
        // `map` + `_int` produces `map_int`, which is a *different, real* converter
        // (integer key matching), and the collision silently replaced one with the
        // other. Hence the two arms: `base` alone, or `base + variants`.
        //
        // The full set is 38 names, checked against data/converters.json in
        // `map_converter_names_match_haproxy` below.
        macro_rules! reg_map_base {
            ($base:literal, $mt:expr, $in_spec:expr) => {
                self.register_converter(ConvDesc {
                    name: $base,
                    in_type: $in_spec,
                    out_type: TypeSpec::Exact(SampleType::Str),
                    func: |smp, args| {
                        let path = args.first()?;
                        let default_val = args.get(1).map(|s| s.trim_matches('"').to_string());
                        let in_str = sample_to_string(&smp);
                        match_map(path, &in_str, $mt)
                            .map(|(v, _k)| Sample::Str(v))
                            .or_else(|| default_val.map(Sample::Str))
                    },
                });
            };
        }

        macro_rules! reg_map {
            ($base:literal, $mt:expr, $in_spec:expr) => {
                reg_map_base!($base, $mt, $in_spec);

                self.register_converter(ConvDesc {
                    name: concat!($base, "_int"),
                    in_type: $in_spec,
                    out_type: TypeSpec::Exact(SampleType::Sint),
                    func: |smp, args| {
                        let path = args.first()?;
                        let default_val: Option<i64> =
                            args.get(1).and_then(|s| s.trim_matches('"').parse().ok());
                        let in_str = sample_to_string(&smp);
                        if let Some((v, _)) = match_map(path, &in_str, $mt) {
                            if let Ok(n) = v.parse::<i64>() {
                                return Some(Sample::Sint(n));
                            }
                        }
                        default_val.map(Sample::Sint)
                    },
                });

                self.register_converter(ConvDesc {
                    name: concat!($base, "_ip"),
                    in_type: $in_spec,
                    out_type: TypeSpec::Addr,
                    func: |smp, args| {
                        let path = args.first()?;
                        let default_val = args.get(1).and_then(|s| parse_ip_str(s.trim_matches('"')));
                        let in_str = sample_to_string(&smp);
                        if let Some((v, _)) = match_map(path, &in_str, $mt) {
                            if let Some(ip) = parse_ip_str(&v) {
                                return Some(ip);
                            }
                        }
                        default_val
                    },
                });

                self.register_converter(ConvDesc {
                    name: concat!($base, "_key"),
                    in_type: $in_spec,
                    out_type: TypeSpec::Exact(SampleType::Str),
                    func: |smp, args| {
                        let path = args.first()?;
                        let default_val = args.get(1).map(|s| s.trim_matches('"').to_string());
                        let in_str = sample_to_string(&smp);
                        match_map(path, &in_str, $mt)
                            .map(|(_v, k)| Sample::Str(k))
                            .or_else(|| default_val.map(Sample::Str))
                    },
                });
            };
        }

        // `map` is an alias for `map_str` and `map_regm` returns a substitution, so
        // neither takes `_int`/`_ip`/`_key` variants -- see the comment on reg_map!.
        reg_map_base!("map", MapMatchType::Str, TypeSpec::Exact(SampleType::Str));
        reg_map_base!("map_regm", MapMatchType::Regm, TypeSpec::Exact(SampleType::Str));

        reg_map!("map_str", MapMatchType::Str, TypeSpec::Exact(SampleType::Str));
        reg_map!("map_beg", MapMatchType::Beg, TypeSpec::Exact(SampleType::Str));
        reg_map!("map_sub", MapMatchType::Sub, TypeSpec::Exact(SampleType::Str));
        reg_map!("map_dir", MapMatchType::Dir, TypeSpec::Exact(SampleType::Str));
        reg_map!("map_dom", MapMatchType::Dom, TypeSpec::Exact(SampleType::Str));
        reg_map!("map_end", MapMatchType::End, TypeSpec::Exact(SampleType::Str));
        reg_map!("map_reg", MapMatchType::Reg, TypeSpec::Exact(SampleType::Str));
        reg_map!("map_int", MapMatchType::Int, TypeSpec::Exact(SampleType::Sint));
        reg_map!("map_ip", MapMatchType::Ip, TypeSpec::Addr);

        // --- 6. JSON Converters ---
        fn json_escape(s: &str) -> String {
            let mut out = String::with_capacity(s.len());
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '/' => out.push_str("\\/"),
                    '\x08' => out.push_str("\\b"),
                    '\x0c' => out.push_str("\\f"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    _ if c.is_control() => {
                        use std::fmt::Write;
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    _ => out.push(c),
                }
            }
            out
        }

        self.register_converter(ConvDesc {
            name: "json",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| match smp {
                Sample::Str(s) => {
                    let mode = args.first().map(|x| x.as_str()).unwrap_or("");
                    if mode == "utf8" && s.contains('\u{FFFD}') {
                        return Some(Sample::Str(String::new()));
                    }
                    let s = if mode == "utf8s" {
                        s.replace('\u{FFFD}', "")
                    } else {
                        s
                    };
                    Some(Sample::Str(json_escape(&s)))
                }
                _ => None,
            },
        });
        
        let json_query_conv: ConvFn = |smp, args| {
            let path = args.first()?;
            let Sample::Str(s) = smp else { return None };
            json_extract(&s, path).map(Sample::Str)
        };

        self.register_converter(ConvDesc {
            name: "json_query",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Any,
            func: json_query_conv,
        });

        // --- 7. Time & Date Converters ---
        self.register_converter(ConvDesc {
            name: "http_date",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                // `http_date([<offset>[,<unit>]])`: the unit (s, ms or us) is the input's and
                // the offset's; ms and us add a fractional part.
                let offset = args.first().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
                let (per_sec, digits) = match args.get(1).map(String::as_str) {
                    None | Some("s") => (1, 0),
                    Some("ms") => (1000, 3),
                    Some("us") => (1_000_000, 6),
                    Some(_) => return None,
                };
                let Sample::Sint(v) = smp else { return None };
                let v = v.checked_add(offset)?;
                let date = format_http_date(v.div_euclid(per_sec));
                if digits == 0 {
                    return Some(Sample::Str(date));
                }
                let frac = v.rem_euclid(per_sec);
                let (head, _) = date.rsplit_once(" GMT")?;
                Some(Sample::Str(format!("{head}.{frac:0digits$} GMT")))
            },
        });

        self.register_converter(ConvDesc {
            name: "date",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Str(s) => parse_http_date(&s).map(Sample::Sint),
                _ => None,
            },
        });

        // `utime`, `ltime` (seconds) and their `ms_`/`us_` variants: `<fmt>[,<offset>]`, the
        // offset in the unit of the input (`sample_conv_ltime`/`sample_conv_ms_ltime` ...).
        fn time_conv(smp: Sample, args: &[String], per_sec: i64, local: bool) -> Option<Sample> {
            let fmt = args.first().map_or("%d/%b/%Y:%H:%M:%S", String::as_str);
            let offset = args.get(1).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
            let Sample::Sint(v) = smp else { return None };
            let v = v.checked_add(offset)?;
            let frac = u32::try_from(v.rem_euclid(per_sec) * (1_000_000_000 / per_sec)).ok()?;
            Some(Sample::Str(format_time_ns(v.div_euclid(per_sec), frac, fmt, local)))
        }
        for (name, per_sec, local) in [
            ("ltime", 1, true),
            ("utime", 1, false),
            ("ms_ltime", 1000, true),
            ("ms_utime", 1000, false),
            ("us_ltime", 1_000_000, true),
            ("us_utime", 1_000_000, false),
        ] {
            let func: ConvFn = match (per_sec, local) {
                (1, true) => |smp, args| time_conv(smp, args, 1, true),
                (1, false) => |smp, args| time_conv(smp, args, 1, false),
                (1000, true) => |smp, args| time_conv(smp, args, 1000, true),
                (1000, false) => |smp, args| time_conv(smp, args, 1000, false),
                (_, true) => |smp, args| time_conv(smp, args, 1_000_000, true),
                (_, false) => |smp, args| time_conv(smp, args, 1_000_000, false),
            };
            self.register_converter(ConvDesc {
                name,
                in_type: TypeSpec::Exact(SampleType::Sint),
                out_type: TypeSpec::Exact(SampleType::Str),
                func,
            });
        }

        // --- 8. Stick table, server and frontend converters ---
        //
        // These read the runtime state, so they are context converters. The `table_*`
        // family and `srv_queue` are not implemented and are refused at load
        // ([`NOT_IMPLEMENTED`]); they used to be registered here returning 0.
        self.register_ctx_converter(CtxConvDesc {
            name: "in_table",
            in_type: TypeSpec::Any,
            out_type: TypeSpec::Exact(SampleType::Bool),
            // `sample_conv_in_table`. Without an argument the table is the current
            // proxy's, which the load-time check has made sure exists.
            func: |ctx, smp, args| {
                let proxies = ctx.proxies?;
                let table = args.first().map(String::as_str).filter(|a| !a.is_empty());
                let found = match table {
                    Some(t) => proxies.table_has_key(t, &smp),
                    None => ctx
                        .be_name
                        .and_then(|t| proxies.table_has_key(t, &smp))
                        .or_else(|| proxies.table_has_key(ctx.fe_name?, &smp)),
                };
                found.map(Sample::Bool)
            },
        });

        // `sample_conv_table_conn_cnt` and its siblings (`src/stick_table.c`): the input cast to
        // the table's key type is looked up in the table; 0 where it has no entry, no sample
        // where the table does not store the data type. Those that write (`table_inc_gpc0`,
        // `table_clr_gpc0`), or read what Ibex does not keep (`table_expire`, `table_idle`,
        // `table_trackers`, `table_server_id`, rates, `glitch` and `http_fail` counters, the
        // indexed `table_gpc(<idx>)`), are refused ([`NOT_IMPLEMENTED`]).
        macro_rules! reg_table_conv {
            ($name:literal, $data:expr) => {
                self.register_ctx_converter(CtxConvDesc {
                    name: $name,
                    in_type: TypeSpec::Any,
                    out_type: TypeSpec::Exact(SampleType::Sint),
                    func: |ctx, smp, args| {
                        let proxies = ctx.proxies?;
                        match table_arg(args) {
                            Some(t) => proxies.table_value(t, &smp, $data),
                            None => ctx
                                .be_name
                                .and_then(|t| proxies.table_value(t, &smp, $data))
                                .or_else(|| proxies.table_value(ctx.fe_name?, &smp, $data)),
                        }
                        .map(Sample::Sint)
                    },
                });
            };
        }
        reg_table_conv!("table_conn_cnt", StickData::ConnCnt);
        reg_table_conv!("table_conn_cur", StickData::ConnCur);
        reg_table_conv!("table_conn_rate", StickData::ConnRate);
        reg_table_conv!("table_sess_cnt", StickData::SessCnt);
        reg_table_conv!("table_http_req_cnt", StickData::HttpReqCnt);
        reg_table_conv!("table_http_req_rate", StickData::HttpReqRate);
        reg_table_conv!("table_http_err_cnt", StickData::HttpErrCnt);
        reg_table_conv!("table_http_err_rate", StickData::HttpErrRate);
        reg_table_conv!("table_kbytes_in", StickData::KbytesIn);
        reg_table_conv!("table_kbytes_out", StickData::KbytesOut);
        reg_table_conv!("table_sess_rate", StickData::SessRate);
        reg_table_conv!("table_http_fail_cnt", StickData::HttpFailCnt);
        reg_table_conv!("table_http_fail_rate", StickData::HttpFailRate);
        reg_table_conv!("table_bytes_in_rate", StickData::BytesInRate);
        reg_table_conv!("table_bytes_out_rate", StickData::BytesOutRate);
        reg_table_conv!("table_glitch_cnt", StickData::GlitchCnt);
        reg_table_conv!("table_glitch_rate", StickData::GlitchRate);
        reg_table_conv!("table_trackers", StickData::Trackers);
        reg_table_conv!("table_server_id", StickData::ServerId);
        // `table_expire(<table>[,<default>])` and `table_idle`: the time of an entry, in
        // milliseconds; the default (none: no sample) where the entry is not in the table.
        macro_rules! reg_table_time {
            ($name:literal, $data:expr) => {
                self.register_ctx_converter(CtxConvDesc {
                    name: $name,
                    in_type: TypeSpec::Any,
                    out_type: TypeSpec::Exact(SampleType::Sint),
                    func: |ctx, smp, args| {
                        let proxies = ctx.proxies?;
                        let found = match table_arg(args) {
                            Some(t) => proxies.table_value(t, &smp, $data),
                            None => ctx
                                .be_name
                                .and_then(|t| proxies.table_value(t, &smp, $data))
                                .or_else(|| proxies.table_value(ctx.fe_name?, &smp, $data)),
                        };
                        let default = args.get(1).and_then(|d| d.trim().parse::<i64>().ok());
                        found.or(default).map(Sample::Sint)
                    },
                });
            };
        }
        reg_table_time!("table_expire", StickData::Expire);
        reg_table_time!("table_idle", StickData::Idle);
        // The counters and tags that take an element (`table_gpc(<idx>,<table>)`), the rates of
        // the legacy ones, and the converters that write (`table_inc_gpc0`, `table_clr_gpc`).
        macro_rules! reg_table_conv_at {
            ($name:literal, $pos:literal, $idx:ident => $data:expr) => {
                self.register_ctx_converter(CtxConvDesc {
                    name: $name,
                    in_type: TypeSpec::Any,
                    out_type: TypeSpec::Exact(SampleType::Sint),
                    func: |ctx, smp, args| {
                        let proxies = ctx.proxies?;
                        let $idx = if $pos == 1 { args.first()?.trim().parse::<usize>().ok()? } else { 0 };
                        let table = args.get($pos).map(String::as_str).filter(|a| !a.is_empty());
                        match table {
                            Some(t) => proxies.table_value(t, &smp, $data),
                            None => ctx
                                .be_name
                                .and_then(|t| proxies.table_value(t, &smp, $data))
                                .or_else(|| proxies.table_value(ctx.fe_name?, &smp, $data)),
                        }
                        .map(Sample::Sint)
                    },
                });
            };
        }
        reg_table_conv_at!("table_gpc", 1, i => StickData::GpcIdx(i));
        reg_table_conv_at!("table_gpt", 1, i => StickData::GptIdx(i));
        reg_table_conv_at!("table_gpc_rate", 1, i => StickData::GpcRateIdx(i));
        reg_table_conv_at!("table_gpc0_rate", 0, _i => StickData::Gpc0Rate);
        reg_table_conv_at!("table_gpc1_rate", 0, _i => StickData::Gpc1Rate);
        macro_rules! reg_table_write {
            ($name:literal, $pos:literal, $idx:ident => $op:expr) => {
                self.register_ctx_converter(CtxConvDesc {
                    name: $name,
                    in_type: TypeSpec::Any,
                    out_type: TypeSpec::Exact(SampleType::Sint),
                    func: |ctx, smp, args| {
                        let proxies = ctx.proxies?;
                        let $idx = if $pos == 1 { args.first()?.trim().parse::<usize>().ok()? } else { 0 };
                        let table = args.get($pos).map(String::as_str).filter(|a| !a.is_empty());
                        match table {
                            Some(t) => proxies.table_write(t, &smp, $op),
                            None => ctx
                                .be_name
                                .and_then(|t| proxies.table_write(t, &smp, $op))
                                .or_else(|| proxies.table_write(ctx.fe_name?, &smp, $op)),
                        }
                        .map(Sample::Sint)
                    },
                });
            };
        }
        reg_table_write!("table_inc_gpc", 1, i => StickOp::IncGpc(StickGpc::Idx(i)));
        reg_table_write!("table_clr_gpc", 1, i => StickOp::ClrGpc(StickGpc::Idx(i)));
        reg_table_write!("table_inc_gpc0", 0, _i => StickOp::IncGpc(StickGpc::Zero));
        reg_table_write!("table_inc_gpc1", 0, _i => StickOp::IncGpc(StickGpc::One));
        reg_table_write!("table_clr_gpc0", 0, _i => StickOp::ClrGpc(StickGpc::Zero));
        reg_table_write!("table_clr_gpc1", 0, _i => StickOp::ClrGpc(StickGpc::One));
        reg_table_conv!("table_gpc0", StickData::Gpc0);
        reg_table_conv!("table_gpc1", StickData::Gpc1);
        reg_table_conv!("table_gpt0", StickData::Gpt0);

        // `sample_conv_nbsrv`: the input names a backend; none of that name, no sample.
        self.register_ctx_converter(CtxConvDesc {
            name: "nbsrv",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |ctx, smp, _args| ctx.proxies?.usable_servers(&input_str(smp)?).map(Sample::Sint),
        });

        // `sample_conv_srv_is_up`: `<backend>/<server>`, or `<server>` in the current
        // backend; a name that resolves to nothing gives no sample.
        self.register_ctx_converter(CtxConvDesc {
            name: "srv_is_up",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Bool),
            func: |ctx, smp, _args| {
                let name = input_str(smp)?;
                let (be, srv) = server_arg(ctx, &name)?;
                ctx.proxies?.server(be, srv).map(|s| Sample::Bool(s.is_up))
            },
        });

        // `sample_conv_fe_exists`: a proxy with a frontend (`frontend` or `listen`).
        self.register_ctx_converter(CtxConvDesc {
            name: "fe_exists",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Bool),
            func: |ctx, smp, _args| Some(Sample::Bool(ctx.proxies?.frontend_exists(&input_str(smp)?))),
        });

        self.register_converter(ConvDesc {
            name: "debug",
            in_type: TypeSpec::Any,
            out_type: TypeSpec::Same,
            func: |smp, args| {
                // `sample_conv_debug`: `[debug] <prefix>: type=<type> <printable text>`, to the
                // destination (`buf0` when none is named).
                let prefix = args.first().map_or("", String::as_str);
                let sink = args.get(1).map_or("buf0", String::as_str);
                let sink = if sink.is_empty() { "buf0" } else { sink };
                let kind = match &smp {
                    Sample::Bool(_) => "bool",
                    Sample::Sint(_) => "sint",
                    Sample::Ipv4(_) => "ipv4",
                    Sample::Ipv6(_) => "ipv6",
                    Sample::Str(_) => "str",
                    Sample::Bin(_) => "bin",
                    Sample::Meth(_) => "meth",
                };
                let text = match &smp {
                    Sample::Bin(b) => b.clone(),
                    other => sample_to_string(other).into_bytes(),
                };
                let mut line = format!("[debug] {prefix}: type={kind} <").into_bytes();
                line.extend(text.iter().map(|&c| if (0x20..0x7f).contains(&c) { c } else { b'.' }));
                line.push(b'>');
                if let Some(write) = DEBUG_SINK.get() {
                    write(sink, &line);
                }
                Some(smp)
            },
        });

        self.register_converter(ConvDesc {
            name: "set-var",
            in_type: TypeSpec::Any,
            out_type: TypeSpec::Same,
            func: |smp, args| {
                { // `set-var` always has its variable name: the load refuses `set-var()`
                    let spec = args.join(",");
                    let spec = spec.as_str();
                    let name = spec.split(',').next().unwrap_or("");
                    let is_proc = name.starts_with("proc.");
                    let is_set = if is_proc {
                        get_proc_var(name).is_some()
                    } else {
                        CURRENT_VARS.with(|v| v.borrow().contains_key(name))
                    };
                    let empty = matches!(&smp, Sample::Str(s) if s.is_empty())
                        || matches!(&smp, Sample::Bin(b) if b.is_empty());
                    if var_conds_hold(spec, is_proc || is_set, is_set, empty) {
                        let val_str = sample_to_string(&smp);
                        if is_proc {
                            set_proc_var(name, val_str);
                        } else {
                            CURRENT_VARS.with(|v| {
                                v.borrow_mut().insert(name.to_string(), val_str);
                            });
                        }
                    }
                }
                Some(smp)
            },
        });

        self.register_converter(ConvDesc {
            name: "unset-var",
            in_type: TypeSpec::Any,
            out_type: TypeSpec::Same,
            func: |smp, args| {
                // A `proc.` variable is the process's, not the stream's (T156).
                if let Some(var_name) = args.first() {
                    if var_name.starts_with("proc.") {
                        unset_proc_var(var_name);
                    } else {
                        CURRENT_VARS.with(|v| {
                            v.borrow_mut().remove(var_name);
                        });
                    }
                }
                Some(smp)
            },
        });

        self.register_converter(ConvDesc {
            name: "ip.ver",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    let first = b.first()?;
                    Some(Sample::Sint(i64::from(first >> 4)))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "ip.ttl",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    let ver = b.first()? >> 4;
                    match ver {
                        4 => {
                            if b.len() < 20 {
                                return None;
                            }
                            Some(Sample::Sint(i64::from(*b.get(8)?)))
                        }
                        6 => {
                            if b.len() < 40 {
                                return None;
                            }
                            Some(Sample::Sint(i64::from(*b.get(7)?)))
                        }
                        _ => None,
                    }
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "ip.proto",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    let ver = b.first()? >> 4;
                    match ver {
                        4 => {
                            if b.len() < 10 {
                                return None;
                            }
                            Some(Sample::Sint(i64::from(*b.get(9)?)))
                        }
                        6 => {
                            if b.len() < 40 {
                                return None;
                            }
                            let mut next = *b.get(6)?;
                            let mut len = 40usize;
                            while next != 6 && next != 17 {
                                if b.len() < len + 2 {
                                    return None;
                                }
                                let ext_len = usize::from(*b.get(len + 1)?) * 8 + 8;
                                next = *b.get(len)?;
                                len += ext_len;
                            }
                            if b.len() < len {
                                return None;
                            }
                            Some(Sample::Sint(i64::from(next)))
                        }
                        _ => None,
                    }
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "ip.tos",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    if b.len() < 2 {
                        return None;
                    }
                    let ver = b[0] >> 4;
                    match ver {
                        4 => Some(Sample::Sint(i64::from(b[1]))),
                        6 => {
                            let tc = ((b[0] & 0x0f) << 4) | (b[1] >> 4);
                            Some(Sample::Sint(i64::from(tc)))
                        }
                        _ => None,
                    }
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "ip.df",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    let ver = b.first()? >> 4;
                    match ver {
                        4 => {
                            if b.len() < 6 {
                                return None;
                            }
                            let df = i64::from((b[6] & 0x40) != 0);
                            Some(Sample::Sint(df))
                        }
                        6 => Some(Sample::Sint(1)),
                        _ => None,
                    }
                }
                _ => None,
            },
        });

        // `hmac(<alg>,<key>)`: `sample_conv_hmac` (src/sample.c). The key is a variable
        // (scope-prefixed name) or, otherwise, a base64 string; a variable that is not
        // set, a bad base64 key or an unknown algorithm yields no sample.
        self.register_converter(ConvDesc {
            name: "hmac",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, args| {
                let Sample::Bin(msg) = smp else { return None };
                let (digest, block) = hmac_digest(args.first()?)?;
                let key_arg = args.get(1)?.trim();
                let is_var = hmac_key_is_var(key_arg);
                let key = if is_var {
                    let v = if key_arg.starts_with("proc.") {
                        get_proc_var(key_arg)
                    } else {
                        CURRENT_VARS.with(|v| v.borrow().get(key_arg).cloned())
                    };
                    v?
                } else {
                    key_arg.to_string()
                };
                // Either way the key is base64 text.
                let mut key = base64_decode(&key, false, true)?;
                if key.len() > block {
                    key = digest(&key);
                }
                key.resize(block, 0);
                let mut inner: Vec<u8> = key.iter().map(|b| b ^ 0x36).collect();
                inner.extend_from_slice(&msg);
                let mut outer: Vec<u8> = key.iter().map(|b| b ^ 0x5c).collect();
                outer.extend_from_slice(&digest(&inner));
                Some(Sample::Bin(digest(&outer)))
            },
        });

        // `aes_cbc_enc(<bits>,<nonce>,<key>[,<aad>])`, `aes_cbc_dec` (same arguments),
        // `aes_gcm_enc(<bits>,<nonce>,<key>,<tag var>[,<aad>])` and
        // `aes_gcm_dec(<bits>,<nonce>,<key>,<tag>[,<aad>])`: `sample_conv_aes_cbc`
        // and `sample_conv_aes_gcm` (src/sample.c). Nonce, key, aad and the decryption's
        // tag are base64, as a variable's text or as a literal; the encryption's tag is
        // written to its variable, base64 too. Anything that does not work (a variable
        // that is not set, a key shorter than `bits`, a bad padding or tag) yields no sample.
        self.register_converter(ConvDesc {
            name: "aes_cbc_enc",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, args| aes_cbc(smp, args, true),
        });
        self.register_converter(ConvDesc {
            name: "aes_cbc_dec",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, args| aes_cbc(smp, args, false),
        });
        self.register_converter(ConvDesc {
            name: "aes_gcm_enc",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, args| aes_gcm(smp, args, true),
        });
        self.register_converter(ConvDesc {
            name: "aes_gcm_dec",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, args| aes_gcm(smp, args, false),
        });

        // `language(<value>[;<value>...][,<default>])`: `sample_conv_q_prefered`. The
        // input is an `Accept-Language` style header; the output is the listed value the
        // header prefers.
        self.register_converter(ConvDesc {
            name: "language",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                let header = sample_to_string(&smp);
                match language_pick(&header, args.first()?) {
                    Some(v) => Some(Sample::Str(v)),
                    None => args.get(1).map(|d| Sample::Str(d.clone())),
                }
            },
        });

        self.register_converter(ConvDesc {
            name: "secure_memcmp",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bool),
            func: |smp, args| match smp {
                Sample::Bin(b) => {
                    let arg = args.first()?;
                    let target_bytes = CURRENT_VARS.with(|v| v.borrow().get(arg).cloned())
                        .or_else(|| get_proc_var(arg))
                        .map_or_else(|| arg.as_bytes().to_vec(), String::into_bytes);

                    if b.len() != target_bytes.len() {
                        return Some(Sample::Bool(false));
                    }
                    let mut diff = 0u8;
                    for (x, y) in b.iter().zip(target_bytes.iter()) {
                        diff |= x ^ y;
                    }
                    Some(Sample::Bool(diff == 0))
                }
                _ => None,
            },
        });
    }

    /// Applies a chain of converters to a sample value, with the runtime state the context
    /// converters read.
    #[must_use]
    pub fn apply_converters_in(
        &self,
        ctx: &SampleContext,
        mut smp: Sample,
        converters: &[(&str, Vec<String>)],
    ) -> Option<Sample> {
        /// A converter, and whether it reads the context.
        enum Conv {
            Plain(ConvFn),
            WithCtx(CtxConvFn),
        }
        for (c_name, c_args) in converters {
            let (in_type, func) = if let Some(d) = self.get_converter(c_name) {
                (d.in_type, Conv::Plain(d.func))
            } else {
                let d = self.get_ctx_converter(c_name)?;
                (d.in_type, Conv::WithCtx(d.func))
            };

            // Apply implicit cast if input type doesn't match
            if !in_type.matches(smp.sample_type()) {
                if let TypeSpec::Exact(target_ty) = in_type {
                    smp = cast(smp, target_ty)?;
                } else if in_type == TypeSpec::Addr {
                    if let Some(v4) = cast(smp.clone(), SampleType::Ipv4) {
                        smp = v4;
                    } else {
                        smp = cast(smp, SampleType::Ipv6)?;
                    }
                } else {
                    return None;
                }
            }

            smp = match func {
                Conv::Plain(f) => f(smp, c_args)?,
                Conv::WithCtx(f) => f(ctx, smp, c_args)?,
            };
        }

        Some(smp)
    }

    /// Evaluates a fetch and a chain of converters against the given context, returning all matching sample values.
    #[must_use]
    pub fn eval_all(
        &self,
        fetch_name: &str,
        fetch_args: &[String],
        converters: &[(&str, Vec<String>)],
        ctx: &SampleContext,
    ) -> Vec<Sample> {
        let initial_samples = if let Some(mf) = self.multi_fetches.get(fetch_name) {
            mf(ctx, fetch_args)
        } else if let Some(f_desc) = self.get_fetch(fetch_name) {
            (f_desc.func)(ctx, fetch_args).into_iter().collect()
        } else {
            return Vec::new();
        };

        let mut out = Vec::with_capacity(initial_samples.len());
        for smp in initial_samples {
            if let Some(res) = self.apply_converters_in(ctx, smp, converters) {
                out.push(res);
            }
        }
        out
    }

    /// Evaluates a fetch and a chain of converters against the given context.
    #[must_use]
    pub fn eval(
        &self,
        fetch_name: &str,
        fetch_args: &[String],
        converters: &[(&str, Vec<String>)],
        ctx: &SampleContext,
    ) -> Option<Sample> {
        self.eval_all(fetch_name, fetch_args, converters, ctx).into_iter().next()
    }
}

fn get_context_uri<'a>(ctx: &'a SampleContext) -> Option<&'a str> {
    ctx.htx_slice
        .and_then(|h| h.req_line().map(|r| r.uri))
        .or(ctx.req_uri)
        .or_else(|| ctx.htx.and_then(|h| h.req_line().map(|r| r.uri.as_str())))
}

fn get_context_method<'a>(ctx: &'a SampleContext) -> Option<&'a str> {
    ctx.htx_slice
        .and_then(|h| h.req_line().map(|r| r.method))
        .or(ctx.req_method)
        .or_else(|| ctx.htx.and_then(|h| h.req_line().map(|r| r.method.as_str())))
}

fn get_context_req_version<'a>(ctx: &'a SampleContext) -> Option<&'a str> {
    ctx.htx_slice
        .and_then(|h| h.req_line().map(|r| r.version))
        .or(ctx.req_version)
        .or_else(|| ctx.htx.and_then(|h| h.req_line().map(|r| r.version.as_str())))
}

fn get_context_res_version<'a>(ctx: &'a SampleContext) -> Option<&'a str> {
    ctx.htx_slice
        .and_then(|h| h.res_line().map(|r| r.version))
        .or(ctx.res_version)
        .or_else(|| ctx.htx.and_then(|h| h.res_line().map(|r| r.version.as_str())))
}

fn fetch_base(ctx: &SampleContext, _args: &[String]) -> Option<Sample> {
    let uri = get_context_uri(ctx)?;
    let (prefix, path, _) = split_uri(uri);
    // One arm borrows from `uri`, the other returns an owned String from the header
    // lookup, so both are normalised to String rather than fighting the lifetimes.
    let host: String = if prefix.is_empty() {
        get_req_header(ctx, "host").unwrap_or_default().clone()
    } else {
        prefix
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .to_string()
    };
    Some(Sample::Str(format!("{host}{path}")))
}

fn fetch_req_cook(ctx: &SampleContext, args: &[String]) -> Option<Sample> {
    let name = args.first()?;
    let cookie_hdrs = get_all_req_headers(ctx, "cookie");
    for hdr in cookie_hdrs {
        for (k, v) in extract_cookies(&hdr) {
            if k == name {
                return Some(Sample::Str(v.to_string()));
            }
        }
    }
    None
}

// --- Map Matching Internals ---

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MapMatchType {
    Str,
    Beg,
    Sub,
    Dir,
    Dom,
    End,
    Reg,
    Regm,
    Int,
    Ip,
}

#[derive(Debug, Clone)]
pub struct CachedMapEntry {
    pub key: String,
    pub val: String,
    pub regex: Option<ibex_regex::UserRegex>,
    pub int_val: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct CachedMapTable {
    pub entries: Vec<CachedMapEntry>,
    pub exact_str: HashMap<String, String>,
    pub exact_int: HashMap<i64, (String, String)>,
}

impl CachedMapTable {
    #[must_use]
    pub fn parse(content: &str) -> Self {
        let mut entries = Vec::new();
        let mut exact_str = HashMap::new();
        let mut exact_int = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            let key = parts[0].to_string();
            let val = if parts.len() > 1 {
                parts[1..].join(" ")
            } else {
                String::new()
            };

            let int_val = key.parse::<i64>().ok();
            let regex = ibex_regex::UserRegex::new(&key).ok();

            if let Some(n) = int_val {
                exact_int.entry(n).or_insert_with(|| (val.clone(), key.clone()));
            }
            exact_str.entry(key.clone()).or_insert_with(|| val.clone());

            entries.push(CachedMapEntry {
                key,
                val,
                regex,
                int_val,
            });
        }

        Self {
            entries,
            exact_str,
            exact_int,
        }
    }
}

static MAP_CACHE: RwLock<Option<HashMap<String, Arc<CachedMapTable>>>> = RwLock::new(None);

#[must_use]
pub fn get_or_load_map_table(path: &str) -> Option<Arc<CachedMapTable>> {
    // Fast path: read lock
    if let Ok(guard) = MAP_CACHE.read() {
        if let Some(ref map) = *guard {
            if let Some(table) = map.get(path) {
                return Some(Arc::clone(table));
            }
        }
    }

    // Disk read performed once
    let content = std::fs::read_to_string(path).ok()?;
    let table = Arc::new(CachedMapTable::parse(&content));

    // Slow path: insert into cache
    if let Ok(mut guard) = MAP_CACHE.write() {
        let map = guard.get_or_insert_with(HashMap::new);
        map.insert(path.to_string(), Arc::clone(&table));
    }

    Some(table)
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn match_map(path: &str, input: &str, match_type: MapMatchType) -> Option<(String, String)> {
    let table = get_or_load_map_table(path)?;

    match match_type {
        MapMatchType::Str => {
            if let Some(val) = table.exact_str.get(input) {
                return Some((val.clone(), input.to_string()));
            }
            None
        }
        MapMatchType::Int => {
            let n = input.parse::<i64>().ok()?;
            if let Some(res) = table.exact_int.get(&n) {
                return Some(res.clone());
            }
            // `<low>-<high>` keys, bounds included.
            table.entries.iter().find_map(|e| {
                let (lo, hi) = e.key.split_once('-')?;
                let (lo, hi) = (lo.parse::<i64>().ok()?, hi.parse::<i64>().ok()?);
                (lo <= n && n <= hi).then(|| (e.val.clone(), e.key.clone()))
            })
        }
        MapMatchType::Beg => {
            let mut best_match: Option<(String, String)> = None;
            for entry in &table.entries {
                if input.starts_with(&entry.key) {
                    if let Some((_, ref best_key)) = best_match {
                        if entry.key.len() > best_key.len() {
                            best_match = Some((entry.val.clone(), entry.key.clone()));
                        }
                    } else {
                        best_match = Some((entry.val.clone(), entry.key.clone()));
                    }
                }
            }
            best_match
        }
        MapMatchType::End => {
            let mut best_match: Option<(String, String)> = None;
            for entry in &table.entries {
                if input.ends_with(&entry.key) {
                    if let Some((_, ref best_key)) = best_match {
                        if entry.key.len() > best_key.len() {
                            best_match = Some((entry.val.clone(), entry.key.clone()));
                        }
                    } else {
                        best_match = Some((entry.val.clone(), entry.key.clone()));
                    }
                }
            }
            best_match
        }
        MapMatchType::Sub => {
            for entry in &table.entries {
                if input.contains(&entry.key) {
                    return Some((entry.val.clone(), entry.key.clone()));
                }
            }
            None
        }
        MapMatchType::Dir => {
            for entry in &table.entries {
                let key = &entry.key;
                if input == key
                    || (input.starts_with(key)
                        && (key.ends_with('/')
                            || input
                                .get(key.len()..)
                                .is_some_and(|rest| rest.starts_with('/'))))
                {
                    return Some((entry.val.clone(), key.clone()));
                }
            }
            None
        }
        MapMatchType::Dom => {
            for entry in &table.entries {
                let key = &entry.key;
                if input == key
                    || (key.starts_with('.') && input.ends_with(key))
                    || input.ends_with(&format!(".{key}"))
                {
                    return Some((entry.val.clone(), key.clone()));
                }
            }
            None
        }
        MapMatchType::Reg => {
            for entry in &table.entries {
                if let Some(re) = &entry.regex {
                    if re.is_match(input) {
                        return Some((entry.val.clone(), entry.key.clone()));
                    }
                }
            }
            None
        }
        MapMatchType::Regm => {
            for entry in &table.entries {
                if let Some(re) = &entry.regex {
                    if let Some(caps) = re.captures(input) {
                        let mut result = entry.val.clone();
                        for i in 1..caps.len() {
                            let backref = format!("\\{i}");
                            let captured = caps.get(i).unwrap_or("");
                            result = result.replace(&backref, captured);
                        }
                        return Some((result, entry.key.clone()));
                    }
                }
            }
            None
        }
        MapMatchType::Ip => {
            for entry in &table.entries {
                if check_ip_cidr(input, &entry.key) {
                    return Some((entry.val.clone(), entry.key.clone()));
                }
            }
            None
        }
    }
}

fn check_ip_cidr(ip_str: &str, cidr_str: &str) -> bool {
    let Ok(target_ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    if let Some((net_str, prefix_str)) = cidr_str.split_once('/') {
        let Ok(prefix) = prefix_str.parse::<u32>() else {
            return false;
        };
        match (target_ip, net_str.parse::<IpAddr>()) {
            (IpAddr::V4(target_v4), Ok(IpAddr::V4(net_v4))) => {
                if prefix > 32 {
                    return false;
                }
                let mask = if prefix == 0 {
                    0
                } else if prefix >= 32 {
                    u32::MAX
                } else {
                    !((1u32 << (32 - prefix)) - 1)
                };
                (u32::from(target_v4) & mask) == (u32::from(net_v4) & mask)
            }
            (IpAddr::V6(target_v6), Ok(IpAddr::V6(net_v6))) => {
                if prefix > 128 {
                    return false;
                }
                let mask = if prefix == 0 {
                    0
                } else if prefix >= 128 {
                    u128::MAX
                } else {
                    !((1u128 << (128 - prefix)) - 1)
                };
                (u128::from(target_v6) & mask) == (u128::from(net_v6) & mask)
            }
            _ => false,
        }
    } else if let Ok(exact_ip) = cidr_str.parse::<IpAddr>() {
        target_ip == exact_ip
    } else {
        false
    }
}

// --- JSON & Regex Helpers ---

fn json_extract(json_str: &str, path: &str) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(json_str).ok()?;
    let path = path.trim_start_matches("$.");
    let path = path.trim_start_matches('/');
    
    let mut parts = Vec::new();
    let mut current_part = String::new();
    let mut chars = path.chars().peekable();
    let is_slash_delim = path.starts_with('/');
    
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next_c) = chars.peek() {
                if next_c == '.' || next_c == '\\' {
                    current_part.push(next_c);
                    chars.next();
                    continue;
                }
            }
            current_part.push(c);
        } else if (is_slash_delim && c == '/') || (!is_slash_delim && c == '.') {
            parts.push(current_part);
            current_part = String::new();
        } else {
            current_part.push(c);
        }
    }
    parts.push(current_part);

    let mut current = &val;
    for part in parts {
        if part.is_empty() {
            continue;
        }
        if let Ok(idx) = part.parse::<usize>() {
            if let Some(elem) = current.get(idx) {
                current = elem;
                continue;
            }
        }
        current = current.get(&part)?;
    }

    match current {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Null => Some("null".to_string()),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            serde_json::to_string(current).ok()
        }
    }
}

fn regsub_eval(input: &str, pattern: &str, repl: &str, flags: &str) -> Option<String> {
    let case_insensitive = flags.contains('i');
    let global = flags.contains('g');

    let re = ibex_regex::UserRegex::with_case(pattern, case_insensitive).ok()?;

    // Translate \1, \2 to ${1}, ${2} for Rust regex replacement
    let mut rust_repl = String::with_capacity(repl.len() + 4);
    let chars: Vec<char> = repl.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit() {
            rust_repl.push_str("${");
            let mut j = i + 1;
            while j < chars.len() && chars[j].is_ascii_digit() {
                rust_repl.push(chars[j]);
                j += 1;
            }
            rust_repl.push('}');
            i = j;
        } else if chars[i] == '&' {
            rust_repl.push_str("${0}");
            i += 1;
        } else {
            rust_repl.push(chars[i]);
            i += 1;
        }
    }

    if global {
        Some(re.replace_all(input, rust_repl.as_str()).into_owned())
    } else {
        Some(re.replace(input, rust_repl.as_str()).into_owned())
    }
}

// --- HTTP and String Parsing Helpers ---

#[must_use]
pub fn sample_to_string(smp: &Sample) -> String {
    match smp {
        Sample::Str(s) => s.clone(),
        Sample::Sint(n) => n.to_string(),
        Sample::Bool(b) => {
            if *b {
                "1".to_string()
            } else {
                "0".to_string()
            }
        }
        Sample::Ipv4(ip) => ip.to_string(),
        Sample::Ipv6(ip) => ip.to_string(),
        Sample::Bin(b) => String::from_utf8_lossy(b).to_string(),
        Sample::Meth(m) => m.as_str().to_string(),
    }
}

/// The first `name` header of the request.
pub(crate) fn request_header(ctx: &SampleContext, name: &str) -> Option<String> {
    get_req_header(ctx, name)
}

fn get_req_header(ctx: &SampleContext, name: &str) -> Option<String> {
    if let Some(htx) = ctx.htx_slice {
        if let Some(v) = htx.get_header(name) {
            return Some(v.to_string());
        }
    }
    if let Some(htx) = ctx.htx {
        if let Some(v) = htx.get_header(name) {
            return Some(v.to_string());
        }
    }
    if let Some(headers) = ctx.req_headers {
        for (k, v) in headers {
            if k.eq_ignore_ascii_case(name) {
                return Some(v.clone());
            }
        }
    }
    None
}

fn get_all_req_headers(ctx: &SampleContext, name: &str) -> Vec<String> {
    let mut matches = Vec::new();
    if let Some(htx) = ctx.htx_slice {
        for (hn, hv) in htx.headers() {
            if hn.eq_ignore_ascii_case(name) {
                matches.push(hv.to_string());
            }
        }
        if !matches.is_empty() {
            return matches;
        }
    }
    if let Some(htx) = ctx.htx {
        for hf in htx.headers() {
            if hf.name.eq_ignore_ascii_case(name) {
                matches.push(hf.value.clone());
            }
        }
    }
    if let Some(headers) = ctx.req_headers {
        for (k, v) in headers {
            if k.eq_ignore_ascii_case(name) {
                matches.push(v.clone());
            }
        }
    }
    matches
}

/// The response's header `name`. Only the response is read: `ctx.htx_slice` holds the
/// *request* while a response rule runs, so a `shdr(x-n)` that fell back to it answered
/// with the request's `X-N` (T132).
fn get_res_header(ctx: &SampleContext, name: &str) -> Option<String> {
    get_all_res_headers(ctx, name).into_iter().next()
}

fn get_all_res_headers(ctx: &SampleContext, name: &str) -> Vec<String> {
    let mut matches = Vec::new();
    if let Some(headers) = ctx.res_headers {
        for (k, v) in headers {
            if k.eq_ignore_ascii_case(name) {
                matches.push(v.clone());
            }
        }
    }
    if matches.is_empty() {
        CURRENT_RES_HEADERS.with(|hdrs| {
            for (k, v) in hdrs.borrow().iter() {
                if k.eq_ignore_ascii_case(name) {
                    matches.push(v.clone());
                }
            }
        });
    }
    matches
}

fn extract_cookies(cookie_header: &str) -> Vec<(&str, &str)> {
    let mut list = Vec::new();
    for part in cookie_header.split(';') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            list.push((k.trim(), v.trim().trim_matches('"')));
        }
    }
    list
}

fn extract_url_param(query: &str, param: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == param {
                return Some(url_decode(v, true));
            }
        } else if pair == param {
            return Some(String::new());
        }
    }
    None
}

fn split_uri(uri: &str) -> (&str, &str, &str) {
    let (prefix, rest) = if let Some(stripped) = uri.strip_prefix("http://") {
        if let Some(idx) = stripped.find('/') {
            let p = &uri[..7 + idx];
            let r = &stripped[idx..];
            (p, r)
        } else {
            (uri, "/")
        }
    } else if let Some(stripped) = uri.strip_prefix("https://") {
        if let Some(idx) = stripped.find('/') {
            let p = &uri[..8 + idx];
            let r = &stripped[idx..];
            (p, r)
        } else {
            (uri, "/")
        }
    } else {
        ("", uri)
    };

    let (path, query) = if let Some((p, q)) = rest.split_once('?') {
        (p, q)
    } else {
        (rest, "")
    };

    (prefix, path, query)
}

fn parse_ip_str(s: &str) -> Option<Sample> {
    let clean = s.trim().trim_start_matches('[').trim_end_matches(']');
    let ip_str = if let Some((h, _)) = clean.split_once(':') {
        if clean.contains("::") || clean.chars().filter(|&c| c == ':').count() > 1 {
            clean
        } else {
            h
        }
    } else {
        clean
    };
    if let Ok(v4) = ip_str.parse::<Ipv4Addr>() {
        Some(Sample::Ipv4(v4))
    } else if let Ok(v6) = ip_str.parse::<Ipv6Addr>() {
        Some(Sample::Ipv6(v6))
    } else {
        None
    }
}

// --- Date & Time Calculation Internals ---

/// Splits a Unix epoch into whole days and the seconds within that day.
///
/// `div_euclid`/`rem_euclid` floor towards negative infinity, so a pre-1970 epoch yields
/// a seconds-of-day in `0..86400` like any other rather than a negative remainder.
fn split_epoch(epoch: i64) -> (i64, i64) {
    (epoch.div_euclid(86_400), epoch.rem_euclid(86_400))
}

/// Civil date from a day count relative to 1970-01-01, after Howard Hinnant's
/// `civil_from_days`. Returns `(year, month 1..=12, day 1..=31)`.
///
/// This was previously computed in `u32` with `doe - doe / 1020 + doe / 1460 -
/// doe / 36524`, two terms of which are wrong: the published algorithm is
/// `doe - doe / 1460 + doe / 36524 - doe / 146_096`. It agreed with the correct
/// result on most dates, which is why it survived, and disagreed on leap days:
/// 2000-02-29 came back as 2000-03-01, and 2024-02-29 made the `u32` subtraction for
/// `doy` underflow, producing 2024-28071672-3435973857 in release and a panic in debug.
/// Since the epoch can come from a `Date` header by way of the `date` converter, that
/// panic was reachable from a request.
///
/// All of it is `i64` now. The intermediate values are small and every subtraction here
/// is only non-negative because of the algorithm's invariants, which is exactly the
/// property an unsigned type turns into a wrap instead of a visible negative.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // 0..=146_096
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // 0..=399
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // 0..=365
    let mp = (5 * doy + 2) / 153; // 0..=11
    let d = doy - (153 * mp + 2) / 5 + 1; // 1..=31
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // 1..=12
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Index into a 7-element weekday table, where day 0 (1970-01-01) is a Thursday.
fn weekday_index(days: i64) -> usize {
    // `rem_euclid` keeps this in 0..=6 for negative day counts too, so the conversion
    // cannot fail; `unwrap_or(0)` is unreachable rather than a fallback.
    usize::try_from(days.rem_euclid(7)).unwrap_or(0)
}

/// Index into a 12-element month table from a 1..=12 month number.
fn month_index(month: i64) -> usize {
    usize::try_from(month.clamp(1, 12) - 1).unwrap_or(0)
}

fn format_http_date(epoch: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let (days, secs) = split_epoch(epoch);

    let (y, m, d) = civil_from_days(days);
    let wday = DAYS[weekday_index(days)];
    let month = MONTHS[month_index(m)];

    let hour = secs / 3600;
    let min = (secs % 3600) / 60;
    let sec = secs % 60;

    format!("{wday}, {d:02} {month} {y:04} {hour:02}:{min:02}:{sec:02} GMT")
}

fn parse_http_date(s: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let trimmed = s.trim();
    if let Ok(n) = trimmed.parse::<i64>() {
        return Some(n);
    }

    // Attempt RFC 1123: "Sun, 06 Nov 1994 08:49:37 GMT"
    let parts: Vec<&str> = trimmed
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|p| !p.is_empty())
        .collect();
    if parts.len() >= 5 {
        let (day_str, month_str, year_str, time_str) =
            if parts[0].len() == 3 && !parts[0].chars().all(|c| c.is_ascii_digit()) {
                (parts[1], parts[2], parts[3], parts[4])
            } else {
                (parts[0], parts[1], parts[2], parts[3])
            };

        // Every component is range-checked before it is used. RFC 9110 5.6.7 fixes these
        // ranges, so anything outside them is not an HTTP-date and returning None is
        // both correct and what keeps the arithmetic below in bounds.
        //
        // This used to parse into `u32` and compute `hour * 3600 + min * 60 + sec`
        // unchecked. The string comes from a header -- `req.hdr(Date),date` reaches
        // here -- so `Date: Sun, 06 Nov 1994 9999999:00:00 GMT` overflowed the
        // multiply: a panic in a debug build, and in release a wrapped value that
        // silently became a plausible-looking timestamp.
        let day: i64 = day_str.parse().ok()?;
        if !(1..=31).contains(&day) {
            return None;
        }
        let month = i64::try_from(
            MONTHS
                .iter()
                .position(|&m| m.eq_ignore_ascii_case(month_str))?,
        )
        .ok()?
            + 1;
        let year: i64 = year_str.parse().ok()?;
        // Bounded so `days_from_civil` cannot overflow; far wider than any real date.
        if !(-9999..=9999).contains(&year) {
            return None;
        }

        let mut time_parts = time_str.split(':');
        let hour: i64 = time_parts.next()?.parse().ok()?;
        let min: i64 = time_parts.next()?.parse().ok()?;
        let sec: i64 = time_parts.next()?.parse().ok()?;
        // 60 is allowed for a leap second, as RFC 9110 5.6.7 permits.
        if !(0..=23).contains(&hour) || !(0..=59).contains(&min) || !(0..=60).contains(&sec) {
            return None;
        }

        let days = days_from_civil(year, month, day);
        return Some(days * 86400 + hour * 3600 + min * 60 + sec);
    }

    None
}

/// Inverse of [`civil_from_days`]. Expects a month in `1..=12` and a day in `1..=31`;
/// `parse_http_date` is the only caller and rejects anything else first.
///
/// `i64` throughout for the same reason: `yoe` and `doy` are non-negative only by the
/// algorithm's construction, and the previous `u32` version turned a violation of that
/// into a wrapped value rather than an obviously wrong one.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // 0..=399
    let mp = if m > 2 { m - 3 } else { m + 9 }; // 0..=11
    let doy = (153 * mp + 2) / 5 + d - 1; // 0..=365
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `epoch` seconds and `nanos` nanoseconds; `%N` prints the nanoseconds on 9 digits and
/// `%<n>N` the first `n` of them, as the date converters in `HAProxy` do.
fn format_time_ns(epoch: i64, nanos: u32, format: &str, local: bool) -> String {
    use std::fmt::Write;

    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    const MONTHS_FULL: [&str; 12] = [
        "January", "February", "March", "April", "May", "June", "July", "August", "September",
        "October", "November", "December",
    ];
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const DAYS_FULL: [&str; 7] = [
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
    ];

    let zone = crate::localtime::zone();
    let offset = if local { zone.offset_at(epoch) } else { 0 };
    let (days, secs) = split_epoch(epoch + i64::from(offset));

    let (y, m, d) = civil_from_days(days);
    let wday_idx = weekday_index(days);
    let month_idx = month_index(m);

    let hour = secs / 3600;
    let min = (secs % 3600) / 60;
    let sec = secs % 60;

    let mut out = String::new();
    let mut chars = format.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            if let Some(spec) = chars.next() {
                match spec {
                    // `write!` into the buffer rather than `push_str(&format!(..))`:
                    // the latter allocates a String per conversion specifier and throws
                    // it away. Writing to a String cannot fail, so the Result is dropped.
                    'Y' => { let _ = write!(out, "{y:04}"); }
                    'y' => { let _ = write!(out, "{:02}", y % 100); }
                    'm' => { let _ = write!(out, "{m:02}"); }
                    'd' => { let _ = write!(out, "{d:02}"); }
                    'H' => { let _ = write!(out, "{hour:02}"); }
                    'M' => { let _ = write!(out, "{min:02}"); }
                    'S' => { let _ = write!(out, "{sec:02}"); }
                    'b' | 'h' => out.push_str(MONTHS[month_idx]),
                    'B' => out.push_str(MONTHS_FULL[month_idx]),
                    'a' => out.push_str(DAYS[wday_idx]),
                    'A' => out.push_str(DAYS_FULL[wday_idx]),
                    'T' => { let _ = write!(out, "{hour:02}:{min:02}:{sec:02}"); }
                    'F' => { let _ = write!(out, "{y:04}-{m:02}-{d:02}"); }
                    's' => out.push_str(&epoch.to_string()),
                    'N' => { let _ = write!(out, "{nanos:09}"); }
                    '1'..='9' if chars.peek() == Some(&'N') => {
                        chars.next();
                        let digits = usize::from(spec as u8 - b'0');
                        let _ = write!(out, "{}", &format!("{nanos:09}")[..digits]);
                    }
                    'z' => {
                        let sign = if offset < 0 { '-' } else { '+' };
                        let mins = offset.unsigned_abs() / 60;
                        let _ = write!(out, "{sign}{:02}{:02}", mins / 60, mins % 60);
                    }
                    'Z' => out.push_str(if local { zone.abbr_at(epoch) } else { "GMT" }),
                    '%' => out.push('%'),
                    other => {
                        out.push('%');
                        out.push(other);
                    }
                }
            } else {
                out.push('%');
            }
        } else {
            out.push(c);
        }
    }
    out
}

// --- Encoding Internals ---

fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        use std::fmt::Write;
        let _ = write!(s, "{b:02X}");
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

fn base64_encode(data: &[u8], url_safe: bool) -> String {
    let table: &[u8; 64] = if url_safe {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        out.push(table[usize::from(b0 >> 2)] as char);
        out.push(table[usize::from(((b0 & 0x03) << 4) | (b1 >> 4))] as char);
        if chunk.len() > 1 {
            out.push(table[usize::from(((b1 & 0x0F) << 2) | (b2 >> 6))] as char);
        } else if !url_safe {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(table[usize::from(b2 & 0x3F)] as char);
        } else if !url_safe {
            out.push('=');
        }
    }
    out
}

#[allow(clippy::naive_bytecount)]
pub(crate) fn base64_decode(input: &str, url_safe: bool, strict_padding: bool) -> Option<Vec<u8>> {
    fn decode_char(c: u8, url_safe: bool) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' if !url_safe => Some(62),
            b'-' if url_safe => Some(62),
            b'/' if !url_safe => Some(63),
            b'_' if url_safe => Some(63),
            _ => None,
        }
    }

    let clean: Vec<u8> = input
        .bytes()
        .filter(|&b| !b.is_ascii_whitespace())
        .collect();
    if clean.is_empty() {
        return Some(Vec::new());
    }
    if strict_padding && !clean.len().is_multiple_of(4) {
        return None;
    }
    let mut padded = clean;
    while !padded.len().is_multiple_of(4) {
        padded.push(b'=');
    }

    let chunks = padded.as_chunks::<4>().0;
    let num_chunks = chunks.len();
    let mut out = Vec::with_capacity(num_chunks * 3);

    for (chunk_idx, chunk) in chunks.iter().enumerate() {
        let is_last = chunk_idx + 1 == num_chunks;
        let pad_count = chunk.iter().filter(|&&b| b == b'=').count();
        if pad_count > 0 {
            if !is_last || pad_count > 2 {
                return None;
            }
            if pad_count == 1 && chunk[3] != b'=' {
                return None;
            }
        }
        let c0 = decode_char(chunk[0], url_safe)?;
        let c1 = decode_char(chunk[1], url_safe)?;
        out.push((c0 << 2) | (c1 >> 4));

        if chunk[2] != b'=' {
            let c2 = decode_char(chunk[2], url_safe)?;
            out.push(((c1 & 0x0F) << 4) | (c2 >> 2));
            if chunk[3] != b'=' {
                let c3 = decode_char(chunk[3], url_safe)?;
                out.push(((c2 & 0x03) << 6) | c3);
            }
        }
    }
    Some(out)
}

/// Percent-decodes a string, also mapping `+` to a space.
///
/// Infallible: invalid escapes are left as written and invalid UTF-8 is replaced, so the
/// return type is a `String` rather than an `Option` that was always `Some`.
fn url_decode(s: &str, mut in_form: bool) -> String {
    let mut res = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                res.push(b);
                i += 3;
                continue;
            }
        } else if in_form && bytes[i] == b'+' {
            res.push(b' ');
            i += 1;
            continue;
        } else if bytes[i] == b'?' {
            in_form = true;
        }
        res.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&res).to_string()
}

/// A `when()` condition.
enum WhenCond<'a> {
    Stopping,
    Normal,
    Error,
    Forwarded,
    ToApplet,
    Processed,
    Acl(&'a str),
}

/// `check_when_cond`: an optional `!`, a keyword, and the ACL name `acl` takes.
fn parse_when_cond(args: &[String]) -> Option<(bool, WhenCond<'_>)> {
    let first = args.first()?;
    let (neg, kw) = first.strip_prefix('!').map_or((false, first.as_str()), |k| (true, k));
    let cond = match kw {
        "stopping" => WhenCond::Stopping,
        "normal" => WhenCond::Normal,
        "error" => WhenCond::Error,
        "forwarded" => WhenCond::Forwarded,
        "toapplet" => WhenCond::ToApplet,
        "processed" => WhenCond::Processed,
        "acl" => WhenCond::Acl(args.get(1).filter(|a| !a.is_empty())?),
        _ => return None,
    };
    Some((neg, cond))
}

/// The characters `has_ctl` looks for, as a mask: bit `n` is the character `n` (0-31), bit 32 is
/// DEL. No argument or an empty one is every control character but tab; `any` is all of them,
/// `http` only NUL, LF and CR; otherwise a number of at most 33 bits (`sample_conv_has_ctl`).
pub fn has_ctl_mask(arg: &str) -> Option<u64> {
    const ALL: u64 = 0x1_FFFF_FFFF;
    match arg {
        "" => Some(ALL & !(1 << 9)),
        "any" => Some(ALL),
        "http" => Some(1 | 1 << 10 | 1 << 13),
        n => {
            let v = match n.strip_prefix("0x").or_else(|| n.strip_prefix("0X")) {
                Some(h) => u64::from_str_radix(h, 16).ok()?,
                None => n.parse::<u64>().ok()?,
            };
            (v <= ALL).then_some(v)
        }
    }
}

/// The digest and block size `hmac` computes for an `OpenSSL` message digest name
/// (`EVP_get_digestbyname`: case-insensitive, with the `SHA-256` and `SHA2-256` aliases).
fn hmac_digest(alg: &str) -> Option<(fn(&[u8]) -> Vec<u8>, usize)> {
    Some(match alg.to_ascii_lowercase().as_str() {
        "md5" => (|d| md5_digest(d).to_vec(), 64),
        "sha1" | "sha-1" => (|d| sha1_digest(d).to_vec(), 64),
        "sha224" | "sha-224" | "sha2-224" => (|d| sha224_digest(d).to_vec(), 64),
        "sha256" | "sha-256" | "sha2-256" => (|d| sha256_digest(d).to_vec(), 64),
        "sha384" | "sha-384" | "sha2-384" => (|d| sha384_digest(d).to_vec(), 128),
        "sha512" | "sha-512" | "sha2-512" => (|d| sha512_digest(d).to_vec(), 128),
        _ => return None,
    })
}

/// Digests `OpenSSL` has that `hmac` does not compute here; `HAProxy` loads them, so
/// refusing is the honest answer to a name that is valid but would never give a sample.
const HMAC_UNIMPLEMENTED: &[&str] = &[
    "sha3-224", "sha3-256", "sha3-384", "sha3-512", "sha512-224", "sha512-256", "sha512-224",
    "blake2b512", "blake2s256", "ripemd160", "rmd160", "ripemd", "sm3", "md4", "md5-sha1",
    "whirlpool", "shake128", "shake256", "mdc2",
];

/// A key written as a variable name (scope prefix) rather than as base64 text.
/// Splits `host[:port]` at its last colon, unless a `]` follows it (the colon is inside the
/// brackets of an IPv6 address): `sample_conv_host_only` and `sample_conv_port_only`.
fn split_host_port(s: &str) -> (&str, Option<&str>) {
    match s.rfind(':') {
        Some(i) if !s[i + 1..].contains(']') => (&s[..i], Some(&s[i + 1..])),
        _ => (s, None),
    }
}

/// The text a variable named `name` holds, in the scope its prefix names.
fn read_var(name: &str) -> Option<String> {
    if name.starts_with("proc.") {
        get_proc_var(name)
    } else {
        CURRENT_VARS.with(|v| v.borrow().get(name).cloned())
    }
}

/// Sets a variable from a converter: in the stream's map, which the engine hands back to
/// the session when the step ends.
fn write_var(name: &str, value: String) {
    if name.starts_with("proc.") {
        set_proc_var(name, value);
        return;
    }
    CURRENT_VARS.with(|v| v.borrow_mut().insert(name.to_string(), value));
}

/// A base64 argument: the text of the variable it names, or the literal, decoded.
fn b64_arg(arg: &str) -> Option<Vec<u8>> {
    let arg = arg.trim();
    let text = if hmac_key_is_var(arg) { read_var(arg)? } else { arg.to_string() };
    base64_decode(&text, false, true)
}

fn aes_bits(arg: &str) -> Option<usize> {
    arg.trim().parse::<i64>().ok().filter(|b| matches!(b, 128 | 192 | 256)).and_then(|b| usize::try_from(b / 8).ok())
}

fn aes_for(args: &[String], key_len: usize) -> Option<crate::aes::Aes> {
    let key = b64_arg(args.get(2)?)?;
    // A longer key is cut to the size asked for, a shorter one is no key.
    crate::aes::Aes::new(key.get(..key_len)?)
}

fn aes_cbc(smp: Sample, args: &[String], encrypt: bool) -> Option<Sample> {
    let Sample::Bin(msg) = smp else { return None };
    let key_len = aes_bits(args.first()?)?;
    let nonce = b64_arg(args.get(1)?)?;
    let aes = aes_for(args, key_len)?;
    // The aad has no use in CBC; HAProxy still reads it.
    if let Some(aad) = args.get(3) {
        b64_arg(aad)?;
    }
    // The nonce is the IV: zero padded when short, cut when long.
    let mut iv = [0u8; 16];
    let n = nonce.len().min(16);
    iv[..n].copy_from_slice(&nonce[..n]);
    if encrypt {
        Some(Sample::Bin(crate::aes::cbc_encrypt(&aes, &iv, &msg)))
    } else {
        crate::aes::cbc_decrypt(&aes, &iv, &msg).map(Sample::Bin)
    }
}

fn aes_gcm(smp: Sample, args: &[String], encrypt: bool) -> Option<Sample> {
    let Sample::Bin(msg) = smp else { return None };
    let key_len = aes_bits(args.first()?)?;
    let nonce = b64_arg(args.get(1)?)?;
    let aes = aes_for(args, key_len)?;
    let tag_arg = args.get(3)?.trim();
    let aad = match args.get(4) {
        Some(a) => b64_arg(a)?,
        None => Vec::new(),
    };
    if encrypt {
        let (cipher, tag) = crate::aes::gcm_encrypt(&aes, &nonce, &aad, &msg)?;
        write_var(tag_arg, base64_encode(&tag, false));
        Some(Sample::Bin(cipher))
    } else {
        let tag = b64_arg(tag_arg)?;
        crate::aes::gcm_decrypt(&aes, &nonce, &aad, &msg, &tag).map(Sample::Bin)
    }
}

/// A q-value as `Accept-Language` writes it, in thousandths: what follows a leading `0`
/// and a dot (three digits at most) is the fraction, a `0` followed by anything else is
/// 0, and what does not start with `0` counts as 1.
fn parse_qvalue(s: &str) -> u32 {
    let b = s.as_bytes();
    if b.first() != Some(&b'0') {
        return 1000;
    }
    if b.get(1) != Some(&b'.') {
        return 0;
    }
    let mut q = 0;
    let mut scale = 100;
    for d in b[2..].iter().take(3).take_while(|d| d.is_ascii_digit()) {
        q += u32::from(d - b'0') * scale;
        scale /= 10;
    }
    q
}

/// `language(<list>)` on the header `header`: the first entry of `list` (`;` separated)
/// matching the language with the highest q-value, ties going to the first in the header.
fn language_pick(header: &str, list: &str) -> Option<String> {
    let entries: Vec<&str> = list.split(';').filter(|e| !e.is_empty()).collect();
    let mut best: Option<(u32, &str)> = None;
    for item in header.split(',') {
        let item = item.trim_start();
        let tok_end = item.find(|c: char| c.is_whitespace() || c == ';').unwrap_or(item.len());
        let (token, rest) = item.split_at(tok_end);
        if token.is_empty() {
            continue;
        }
        let rest = rest.trim_start();
        let q = if rest.is_empty() {
            1000
        } else if let Some(params) = rest.strip_prefix(';') {
            let qv = params.trim_start().strip_prefix('q').and_then(|r| r.trim_start().strip_prefix('='));
            qv.map_or(1000, |v| parse_qvalue(v.trim_start()))
        } else {
            // something other than ';' after the language: not a language
            continue;
        };
        if q == 0 {
            continue;
        }
        let hit = entries
            .iter()
            .find(|e| token == **e || token.strip_prefix(**e).is_some_and(|r| r.starts_with('-')));
        if let Some(e) = hit {
            if best.is_none_or(|(bq, _)| q > bq) {
                best = Some((q, e));
            }
        }
    }
    best.map(|(_, e)| e.to_string())
}

/// What `check_converter_args` says about the `aes_*` converters: `bits` first, then the
/// base64 arguments in the order HAProxy checks them.
fn check_aes_args(name: &str, args: &[String]) -> Option<String> {
    let gcm = name.starts_with("aes_gcm");
    let (min, max) = if gcm { (4, 5) } else { (3, 4) };
    let first = args.first().map_or("", |a| a.trim());
    if first.is_empty() {
        return Some(format!("invalid arg 1 in converter '{name}' : expected type 'integer' at position 1, but got nothing."));
    }
    let Ok(bits) = first.parse::<i64>() else {
        return Some(format!("invalid arg 1 in converter '{name}' : failed to parse '{first}' as type 'integer' at position 1."));
    };
    if args.len() < min {
        return Some(format!(
            "invalid arg {} in converter '{name}' : missing arguments (got {}/{min}), type 'string' expected.",
            args.len() + 1,
            args.len()
        ));
    }
    if args.len() > max {
        return Some(format!("invalid arg {max} in converter '{name}' : expected ')' before ',{})'.", args[max..].join(",")));
    }
    if !matches!(bits, 128 | 192 | 256) {
        return Some(format!("invalid args in converter '{name}' : key size must be 128, 192 or 256 (bits).."));
    }
    let b64_ok = |a: &str| hmac_key_is_var(a.trim()) || base64_decode(a.trim(), false, true).is_some();
    let bad = |what: &str| {
        format!(
            "invalid args in converter '{name}' : failed to parse {what} : argument needs to be base64 encoded, and can either be a string or a variable."
        )
    };
    if !b64_ok(&args[1]) {
        return Some(bad("nonce"));
    }
    if !b64_ok(&args[2]) {
        return Some(bad("key"));
    }
    let tag = args.get(3).map_or("", |t| t.trim());
    if name == "aes_gcm_enc" {
        // the tag is where the encryption leaves its result: a variable
        if tag.is_empty() {
            return Some(format!("invalid args in converter '{name}' : failed to parse aead_tag : Empty variable name cannot be accepted."));
        }
        if !hmac_key_is_var(tag) {
            return Some(format!("invalid args in converter '{name}' : failed to parse aead_tag : (null)."));
        }
    } else if name == "aes_gcm_dec" && !b64_ok(tag) {
        return Some(bad("aead_tag"));
    }
    let aad = if gcm { args.get(4) } else { args.get(3) };
    if let Some(aad) = aad {
        if !b64_ok(aad) {
            return Some(bad("aad"));
        }
    }
    None
}

fn hmac_key_is_var(key: &str) -> bool {
    ["txn.", "sess.", "req.", "res.", "proc."].iter().any(|p| key.starts_with(p))
}

/// Load-time check of a converter's arguments, where `HAProxy` refuses some
/// (`invalid args in converter '<name>'`). `None` when they are acceptable.
#[must_use]
pub fn check_converter_args(name: &str, args: &[String]) -> Option<String> {
    match name {
        "has_ctl" if has_ctl_mask(args.first().map_or("", String::as_str)).is_none() => {
            Some("invalid args in converter 'has_ctl' : expects 'any', 'http' or a mask of at most 33 bits".to_string())
        }
        "hmac" => {
            if args.len() < 2 {
                return Some("invalid arg 2 in converter 'hmac' : missing arguments (got 1/2), type 'string' expected.".to_string());
            }
            if args.len() > 2 {
                return Some(format!("invalid arg 2 in converter 'hmac' : expected ')' before ',{})'.", args[2..].join(",")));
            }
            if hmac_digest(&args[0]).is_none() {
                return Some(if HMAC_UNIMPLEMENTED.contains(&args[0].to_ascii_lowercase().as_str()) {
                    format!("converter 'hmac' with digest '{}' is not implemented by Ibex", args[0])
                } else {
                    "invalid args in converter 'hmac' : algorithm must be a valid OpenSSL message digest name..".to_string()
                });
            }
            let key = args[1].trim();
            if !hmac_key_is_var(key) && base64_decode(key, false, true).is_none() {
                return Some("invalid args in converter 'hmac' : failed to parse key : argument needs to be base64 encoded, and can either be a string or a variable.".to_string());
            }
            None
        }
        "set-var" if args.first().is_none_or(String::is_empty) => {
            Some("invalid args in converter 'set-var' : Empty variable name cannot be accepted.".to_string())
        }
        "set-var" => args.iter().skip(1).filter(|c| !c.is_empty()).find_map(|c| match c.as_str() {
            "ifexists" | "ifnotexists" | "ifempty" | "ifnotempty" | "ifset" | "ifnotset" => None,
            "ifgt" | "iflt" => Some(format!(
                "invalid args in converter 'set-var' : condition \"{c}\" needs typed variables, which Ibex does not implement"
            )),
            _ => Some(format!("invalid args in converter 'set-var' : unknown condition \"{c}\".")),
        }),
        "aes_cbc_enc" | "aes_cbc_dec" | "aes_gcm_enc" | "aes_gcm_dec" => check_aes_args(name, args),
        "url_enc" => match args {
            [] => None,
            [a] if a.is_empty() || a == "query" => None,
            [_, rest @ ..] if !rest.is_empty() => Some(format!("invalid arg 2 in converter 'url_enc' : expected ')' before ',{})'.", rest.join(","))),
            _ => Some("invalid args in converter 'url_enc' : Unexpected encode type. Allowed value is 'query'.".to_string()),
        },
        "debug" => {
            if let Some(dest) = args.get(1).filter(|d| !d.is_empty()) {
                DEBUG_DESTS.with(|d| d.borrow_mut().push(dest.clone()));
            }
            None
        }
        "when" if parse_when_cond(args).is_none() => Some(
            "invalid args in converter 'when' : expects [!]error, forwarded, normal, processed, stopping, toapplet or acl,<name>".to_string(),
        ),
        _ => None,
    }
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_fetches_and_converters_count() {
        let reg = Registry::new();
        assert!(reg.fetch_count() >= 50);
        assert!(reg.converter_count() >= 50);
    }

    /// `unset-var` removes a stream variable from the running stream's map, and only
    /// from it; a `proc.` name is the process's (T156).
    #[test]
    fn unset_var_removes_a_stream_variable_from_the_running_stream() {
        let reg = Registry::new();
        let conv = reg.get_converter("unset-var").expect("unset-var is registered");
        CURRENT_VARS.with(|v| v.borrow_mut().insert("txn.t156".to_string(), "v".to_string()));
        set_proc_var("proc.t156", "p".to_string());
        assert_eq!((conv.func)(Sample::Sint(1), &["txn.t156".to_string()]), Some(Sample::Sint(1)));
        assert!(CURRENT_VARS.with(|v| !v.borrow().contains_key("txn.t156")));
        assert_eq!(get_proc_var("proc.t156").as_deref(), Some("p"));
        (conv.func)(Sample::Sint(1), &["proc.t156".to_string()]);
        assert_eq!(get_proc_var("proc.t156"), None);
        // Without a name (the load refuses it) the sample goes through untouched.
        assert_eq!((conv.func)(Sample::Sint(2), &[]), Some(Sample::Sint(2)));
    }

    /// The names `set-timeout` takes; the parser refuses any other.
    #[test]
    fn timeout_kinds_by_name() {
        assert_eq!(TimeoutKind::from_name("tarpit"), Some(TimeoutKind::Tarpit));
        assert_eq!(TimeoutKind::from_name("http-request"), None);
    }

    #[test]
    fn ip_ver_reads_the_high_nibble_of_the_first_byte() {
        let reg = Registry::new();
        let conv = reg.get_converter("ip.ver").expect("ip.ver is registered");

        // IPv4: starts with 0x45 (version 4)
        let v4 = Sample::Bin(vec![0x45, 0x00, 0x00, 0x3c]);
        assert_eq!((conv.func)(v4, &[]), Some(Sample::Sint(4)));

        // IPv6: starts with 0x60 (version 6)
        let v6 = Sample::Bin(vec![0x60, 0x00, 0x00, 0x00]);
        assert_eq!((conv.func)(v6, &[]), Some(Sample::Sint(6)));

        // Empty input fails
        assert_eq!((conv.func)(Sample::Bin(vec![]), &[]), None);
    }

    #[test]
    fn ip_ttl_reads_ttl_from_ipv4_and_ipv6_headers() {
        let reg = Registry::new();
        let conv = reg.get_converter("ip.ttl").expect("ip.ttl is registered");

        // IPv4 header (20 bytes), byte 8 is TTL (e.g. 64)
        let mut v4 = vec![0u8; 20];
        v4[0] = 0x45;
        v4[8] = 64;
        assert_eq!((conv.func)(Sample::Bin(v4), &[]), Some(Sample::Sint(64)));

        // Truncated IPv4 header (<20 bytes) fails
        let v4_trunc = vec![0x45, 0, 0, 0, 0];
        assert_eq!((conv.func)(Sample::Bin(v4_trunc), &[]), None);

        // IPv6 header (40 bytes), byte 7 is Hop Limit (e.g. 128)
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        v6[7] = 128;
        assert_eq!((conv.func)(Sample::Bin(v6), &[]), Some(Sample::Sint(128)));
    }

    #[test]
    fn ip_proto_reads_protocol_number_from_headers() {
        let reg = Registry::new();
        let conv = reg.get_converter("ip.proto").expect("ip.proto is registered");

        // IPv4 header (20 bytes), byte 9 is proto: TCP = 6
        let mut v4 = vec![0u8; 20];
        v4[0] = 0x45;
        v4[9] = 6;
        assert_eq!((conv.func)(Sample::Bin(v4), &[]), Some(Sample::Sint(6)));

        // IPv6 header (40 bytes), byte 6 is Next Header: UDP = 17
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        v6[6] = 17;
        assert_eq!((conv.func)(Sample::Bin(v6), &[]), Some(Sample::Sint(17)));
    }

    #[test]
    fn ip_tos_reads_tos_or_traffic_class() {
        let reg = Registry::new();
        let conv = reg.get_converter("ip.tos").expect("ip.tos is registered");

        // IPv4 header: byte 1 is TOS
        let mut v4 = vec![0u8; 20];
        v4[0] = 0x45;
        v4[1] = 0x10;
        assert_eq!((conv.func)(Sample::Bin(v4), &[]), Some(Sample::Sint(0x10)));

        // IPv6 header: traffic class in first 2 bytes
        // 0x60 0xa0 -> version 6, traffic class 0x0a
        let v6 = vec![0x60, 0xa0, 0x00, 0x00];
        assert_eq!((conv.func)(Sample::Bin(v6), &[]), Some(Sample::Sint(0x0a)));
    }

    #[test]
    fn ip_df_reads_dont_fragment_flag() {
        let reg = Registry::new();
        let conv = reg.get_converter("ip.df").expect("ip.df is registered");

        // IPv4 with DF set: byte 6 has 0x40
        let mut v4_df = vec![0u8; 20];
        v4_df[0] = 0x45;
        v4_df[6] = 0x40;
        assert_eq!((conv.func)(Sample::Bin(v4_df), &[]), Some(Sample::Sint(1)));

        // IPv4 without DF
        let mut v4_nodf = vec![0u8; 20];
        v4_nodf[0] = 0x45;
        assert_eq!((conv.func)(Sample::Bin(v4_nodf), &[]), Some(Sample::Sint(0)));

        // IPv6 always returns 1
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        assert_eq!((conv.func)(Sample::Bin(v6), &[]), Some(Sample::Sint(1)));
    }

    #[test]
    fn secure_memcmp_performs_constant_time_comparison() {
        let reg = Registry::new();
        let conv = reg.get_converter("secure_memcmp").expect("secure_memcmp is registered");

        let secret = b"my_secret_token";
        let target = Sample::Bin(secret.to_vec());

        // Equal match
        assert_eq!(
            (conv.func)(target.clone(), &["my_secret_token".to_string()]),
            Some(Sample::Bool(true))
        );

        // Same length, differing byte
        assert_eq!(
            (conv.func)(target.clone(), &["my_secret_tokeX".to_string()]),
            Some(Sample::Bool(false))
        );

        // Different length
        assert_eq!(
            (conv.func)(target, &["short".to_string()]),
            Some(Sample::Bool(false))
        );
    }

    #[test]
    fn test_basic_eval() {
        let reg = Registry::new();
        let ctx = SampleContext {
            req_uri: Some("/api/v1/users?id=123&name=alice"),
            client_addr: Some("192.168.1.50:8080".parse().unwrap()),
            ..Default::default()
        };

        let res = reg.eval("path", &[], &[("upper", vec![])], &ctx);
        assert_eq!(res, Some(Sample::Str("/API/V1/USERS".to_string())));

        let res_param = reg.eval("urlp", &["id".to_string()], &[], &ctx);
        assert_eq!(res_param, Some(Sample::Str("123".to_string())));

        let res_src = reg.eval("src", &[], &[("ipmask", vec!["24".to_string()])], &ctx);
        assert_eq!(
            res_src,
            Some(Sample::Ipv4("192.168.1.0".parse::<Ipv4Addr>().unwrap()))
        );
    }

    #[test]
    fn test_converters_eval() {
        let reg = Registry::new();
        let ctx = SampleContext::default();

        // Arithmetic
        let res = reg.eval(
            "int",
            &["10".to_string()],
            &[("add", vec!["5".to_string()]), ("mul", vec!["2".to_string()])],
            &ctx,
        );
        assert_eq!(res, Some(Sample::Sint(30)));

        // Hashing
        let res_sha1 = reg.eval(
            "str",
            &["abc".to_string()],
            &[("sha1", vec![]), ("hex", vec![])],
            &ctx,
        );
        assert_eq!(
            res_sha1,
            Some(Sample::Str(
                "A9993E364706816ABA3E25717850C26C9CD0D89D".to_string()
            ))
        );

        // Regsub
        let res_regsub = reg.eval(
            "str",
            &["foo123bar".to_string()],
            &[("regsub", vec![r"\d+".to_string(), "NUM".to_string()])],
            &ctx,
        );
        assert_eq!(res_regsub, Some(Sample::Str("fooNUMbar".to_string())));

        // JSON
        let json_input = r#"{"user":{"name":"bob","age":42}}"#;
        let res_json = reg.eval(
            "str",
            &[json_input.to_string()],
            &[("json_query", vec!["user.name".to_string()])],
            &ctx,
        );
        assert_eq!(res_json, Some(Sample::Str("bob".to_string())));
    }
}

#[cfg(test)]
mod map_name_tests {
    use super::Registry;

    /// The map converter names must be exactly `HAProxy`'s, no more and no fewer.
    ///
    /// Extracted from `HAProxy` 3.5 into `data/converters.json`. The generated names came
    /// from one macro applied to every match method, which invented `map_key` and
    /// `map_regm_int`/`_ip`/`_key`, and produced `map_int` and `map_ip` twice -- once as
    /// the output variants of the bare `map` alias and once as the real integer- and
    /// address-matching converters. Registration was a `HashMap` insert, so one silently
    /// replaced the other and which one survived depended on declaration order.
    ///
    /// A missing name makes a valid config fail; an invented one makes a config Ibex
    /// accepts and `HAProxy` rejects, which is the direction that actually hurts, since it
    /// means a config that cannot be migrated back.
    #[test]
    fn map_converter_names_match_haproxy() {
        let reg = Registry::new();
        let mut got: Vec<&str> = reg
            .converter_names()
            .into_iter()
            .filter(|n| n.starts_with("map"))
            .collect();
        got.sort_unstable();

        let want: [&str; 38] = [
            "map",
            "map_beg",
            "map_beg_int",
            "map_beg_ip",
            "map_beg_key",
            "map_dir",
            "map_dir_int",
            "map_dir_ip",
            "map_dir_key",
            "map_dom",
            "map_dom_int",
            "map_dom_ip",
            "map_dom_key",
            "map_end",
            "map_end_int",
            "map_end_ip",
            "map_end_key",
            "map_int",
            "map_int_int",
            "map_int_ip",
            "map_int_key",
            "map_ip",
            "map_ip_int",
            "map_ip_ip",
            "map_ip_key",
            "map_reg",
            "map_reg_int",
            "map_reg_ip",
            "map_reg_key",
            "map_regm",
            "map_str",
            "map_str_int",
            "map_str_ip",
            "map_str_key",
            "map_sub",
            "map_sub_int",
            "map_sub_ip",
            "map_sub_key",
        ];

        let missing: Vec<&&str> = want.iter().filter(|n| !got.contains(n)).collect();
        let extra: Vec<&&str> = got.iter().filter(|n| !want.contains(n)).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "map converter names drifted from HAProxy 3.5\n  missing: {missing:?}\n  \
             invented: {extra:?}"
        );
    }
}

#[cfg(test)]
mod oracle_tests {
    use super::Registry;
    use std::collections::HashSet;

    fn oracle(file: &str) -> HashSet<String> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/").to_string() + file;
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read the oracle at {path}: {e}"));
        let v: serde_json::Value = serde_json::from_str(&raw).expect("oracle is not JSON");
        v.as_array()
            .expect("oracle is not an array")
            .iter()
            .filter_map(|e| e.get("keyword")?.as_str().map(str::to_owned))
            .collect()
    }

    /// Names Ibex registers that `HAProxy` 3.5 does not have. This list may only shrink.
    ///
    /// A name we are missing makes a valid config fail, which is visible immediately. A
    /// name we invent is worse and quieter: the config loads on Ibex and is rejected by
    /// `HAProxy`, so it cannot be migrated back, and an operator who writes `res.status`
    /// or `hex2bin` gets no warning that they have written something only Ibex
    /// understands. Several here are near-misses for a real fetch -- `res_ver` for
    /// `res.ver`, `sc0_bytes_in_cnt` for
    /// `sc0_bytes_in_rate` -- which is exactly the kind of typo that looks like it works.
    ///
    /// Verified absent two ways: against `data/sample_fetches.json` (extracted from 3.5
    /// with `file:line` citations) and by grepping the `smp_fetch` registration tables in
    /// the reference tree directly.
    const NOT_IN_HAPROXY_FETCHES: &[&str] = &[
        "be_client_timeout", "fe_connect_timeout", "fe_queue_timeout",
        "fe_server_timeout", "fe_tunnel_timeout", "req.uri", "res.proto_http", "res.status",
        "res_ver",
    ];

    const NOT_IN_HAPROXY_CONVERTERS: &[&str] = &[
        "hex2bin", "len",
    ];

    /// The registry must not grow names `HAProxy` does not have.
    ///
    /// This is a ratchet, not a clean bill of health: the allowlists above record what
    /// was already wrong when the check was added. Adding to them is the thing this test
    /// exists to make someone argue for.
    #[test]
    fn registers_no_new_names_haproxy_lacks() {
        let reg = Registry::new();

        let fetches = oracle("sample_fetches.json");
        let new_f: Vec<&str> = reg
            .fetch_names()
            .into_iter()
            .filter(|n| !fetches.contains(*n) && !NOT_IN_HAPROXY_FETCHES.contains(n))
            .collect();

        let convs = oracle("converters.json");
        let new_c: Vec<&str> = reg
            .converter_names()
            .into_iter()
            .filter(|n| !convs.contains(*n) && !NOT_IN_HAPROXY_CONVERTERS.contains(n))
            .collect();

        assert!(
            new_f.is_empty() && new_c.is_empty(),
            "registered names HAProxy 3.5 does not have\n  fetches: {new_f:?}\n  \
             converters: {new_c:?}\nIf one of these is real, the oracle in data/ is \
             missing it and should be re-extracted; if it is a guess, it will silently \
             accept configs HAProxy rejects."
        );
    }

    /// The allowlists must not outlive what they describe.
    ///
    /// Without this, deleting an invented name leaves a stale entry behind and the next
    /// person cannot tell which of them are still real.
    #[test]
    fn the_allowlists_have_no_stale_entries() {
        let reg = Registry::new();
        let f = reg.fetch_names();
        let c = reg.converter_names();

        let stale_f: Vec<&&str> =
            NOT_IN_HAPROXY_FETCHES.iter().filter(|n| !f.contains(n)).collect();
        let stale_c: Vec<&&str> =
            NOT_IN_HAPROXY_CONVERTERS.iter().filter(|n| !c.contains(n)).collect();

        assert!(
            stale_f.is_empty() && stale_c.is_empty(),
            "allowlist entries no longer registered -- remove them\n  fetches: \
             {stale_f:?}\n  converters: {stale_c:?}"
        );
    }
}

#[cfg(test)]
mod date_tests {
    use super::{civil_from_days, days_from_civil, format_http_date, parse_http_date, split_epoch};

    /// Leap days, which is where the previous `civil_from_days` was wrong.
    ///
    /// It used `doe - doe / 1020 + doe / 1460 - doe / 36524` where the published
    /// algorithm uses `doe - doe / 1460 + doe / 36524 - doe / 146_096`. That agrees on
    /// most dates, so ordinary spot checks passed; it disagreed on 29 February.
    #[test]
    fn civil_from_days_is_right_on_leap_days() {
        let cases: &[(i64, (i64, i64, i64))] = &[
            (0, (1970, 1, 1)),
            (784_111_777, (1994, 11, 6)),
            (1_000_000_000, (2001, 9, 9)),
            (2_147_483_647, (2038, 1, 19)),
            // 2000 is a leap year (divisible by 400); the old code returned 2000-03-01.
            (951_782_400, (2000, 2, 29)),
            // The old code underflowed its u32 here and produced 2024-28071672-3435973857.
            (1_709_164_800, (2024, 2, 29)),
            // 1900 is not a leap year (divisible by 100, not 400).
            (-2_203_977_600, (1900, 2, 28)),
            (-1, (1969, 12, 31)),
            (4_102_444_800, (2100, 1, 1)),
        ];
        for &(epoch, want) in cases {
            let (days, _) = split_epoch(epoch);
            assert_eq!(civil_from_days(days), want, "epoch {epoch}");
        }
    }

    /// `days_from_civil` must invert `civil_from_days` across every day for 30 years,
    /// including all the leap days in that span.
    #[test]
    fn days_from_civil_inverts_civil_from_days() {
        for days in -20_000..20_000 {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "round trip at day {days}");
        }
    }

    /// Seconds-of-day stays in `0..86400` on both sides of the epoch.
    ///
    /// The previous code special-cased negative epochs by hand; `rem_euclid` makes the
    /// two branches one expression.
    #[test]
    fn split_epoch_handles_dates_before_1970() {
        assert_eq!(split_epoch(0), (0, 0));
        assert_eq!(split_epoch(86_399), (0, 86_399));
        assert_eq!(split_epoch(86_400), (1, 0));
        assert_eq!(split_epoch(-1), (-1, 86_399));
        assert_eq!(split_epoch(-86_400), (-1, 0));
        assert_eq!(split_epoch(-86_401), (-2, 86_399));
    }

    /// A `Date` header reaches this through the `date` converter, so it is untrusted.
    ///
    /// The out-of-range hour is the one that mattered: parsed as `u32`, `hour * 3600`
    /// overflowed, which panics in a debug build and silently wraps to a plausible
    /// timestamp in release. Every one of these must return `None`, not a number.
    #[test]
    fn parse_http_date_rejects_out_of_range_components() {
        let bad = [
            "Sun, 06 Nov 1994 9999999:00:00 GMT",
            "Sun, 06 Nov 1994 4294967296:00:00 GMT",
            "Sun, 06 Nov 1994 24:00:00 GMT",
            "Sun, 06 Nov 1994 08:60:00 GMT",
            "Sun, 06 Nov 1994 08:49:61 GMT",
            "Sun, 32 Nov 1994 08:49:37 GMT",
            "Sun, 00 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 999999999 08:49:37 GMT",
            "Sun, 06 Xxx 1994 08:49:37 GMT",
        ];
        for s in bad {
            assert_eq!(parse_http_date(s), None, "should have been rejected: {s}");
        }
    }

    #[test]
    fn parse_http_date_accepts_the_rfc_example() {
        // RFC 9110 5.6.7's own example, and its leap second allowance.
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:60 GMT"), Some(784_111_800));
        // A bare epoch stays accepted; the `date` converter relies on it.
        assert_eq!(parse_http_date("784111777"), Some(784_111_777));
    }

    #[test]
    fn format_http_date_round_trips_through_parse() {
        for epoch in [0, 784_111_777, 951_782_400, 1_709_164_800, 2_147_483_647] {
            let formatted = format_http_date(epoch);
            assert_eq!(parse_http_date(&formatted), Some(epoch), "{formatted}");
        }
        assert_eq!(format_http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(format_http_date(1_709_164_800), "Thu, 29 Feb 2024 00:00:00 GMT");
    }
}

/// A header capture as a sample: a string, or the bytes when a capture length cut a
/// multi-byte character (captures are bytes, as in `HAProxy`).
fn capture_sample(bytes: Vec<u8>) -> Sample {
    String::from_utf8(bytes).map_or_else(|e| Sample::Bin(e.into_bytes()), Sample::Str)
}
