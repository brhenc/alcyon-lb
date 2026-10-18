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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, LazyLock, RwLock};

thread_local! {
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

pub use crate::vars::{
    get_proc_var, set_current_vars, set_proc_var, unset_proc_var, VarMap, CURRENT_VARS, GLOBAL_PROC_VARS,
};
pub use crate::vars::conds_hold as var_conds_hold;

pub static SAMPLE_REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

#[must_use]
pub fn sample_registry() -> &'static Registry {
    &SAMPLE_REGISTRY
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

/// T329: Whether `ip` is an address of this host (`addr_is_local`, src/tools.c): a UDP
/// socket binds to it and then connects to it. A broadcast address binds but does not
/// connect: not local. `EADDRNOTAVAIL` on the bind: not local. Any other failure: `None`,
/// no sample.
fn addr_is_local(ip: IpAddr) -> Option<bool> {
    match UdpSocket::bind((ip, 0)) {
        Ok(s) => Some(s.connect((ip, 0)).is_ok()),
        Err(e) if e.kind() == std::io::ErrorKind::AddrNotAvailable => Some(false),
        Err(_) => None,
    }
}

/// A `*_is_local` sample of `addr`: none without an address, or when the test fails.
fn is_local_sample(addr: Option<SocketAddr>) -> Option<Sample> {
    addr.and_then(|a| addr_is_local(a.ip())).map(Sample::Bool)
}

/// Set once the process is stopping (`when(stopping)`).
pub static STOPPING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// T386: the process CPU usage in percent (`cpu_usage_proc`, `_thr`, `_grp`), read through a
/// function `ibex-rt` installs (`/proc/self/stat`, re-read at most every 500 ms, as
/// `HAProxy` refreshes `idle_pct` about once a second). Without one the usage is 0.
pub static CPU_USAGE_SOURCE: std::sync::OnceLock<fn() -> u8> = std::sync::OnceLock::new();

/// A stream is being processed (`smp->strm` is set).
fn has_stream(ctx: &SampleContext<'_>) -> bool {
    ctx.stream.is_some() || ctx.fe_id.is_some()
}

fn cpu_usage_pct() -> i64 {
    CPU_USAGE_SOURCE.get().map_or(0, |f| i64::from(f()))
}

thread_local! {
    /// T326: the engine thread this code runs on (0..nbthread-1), for `thread`; set by
    /// `Engine::new_worker`, so every sample context on that thread reads the same value.
    pub static THREAD_ID: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// T326: the host name, read once (`HAProxy` reads it at startup), for `hostname`.
static HOSTNAME: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

/// The stream state `when()` conditions read (`sample_conv_when`, src/sample.c).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamFacts {
    /// An error was met: a 5xx status, or a failed connection (the `dontlog-normal` rule).
    pub error: bool,
    /// A connection to a server was attempted for the request.
    pub forwarded: bool,
    /// An applet is serving the request.
    pub toapplet: bool,
    /// Connection retries spent on the stream (`txn.conn_retries`).
    pub retries: u32,
    /// The stream was redispatched (`txn.redispatched`).
    pub redispatched: bool,
}

/// Why a client connection failed before a session began (`conn->err_code`): what
/// `fc_err`, `fc_err_str`, `fc_err_name` and `ssl_fc_err[_str]` read in an
/// `error-log-format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnErr<'a> {
    /// `CO_ER_*`.
    pub code: i64,
    /// `conn_err_code_str`.
    pub text: &'a str,
    /// `conn_err_code_name`.
    pub name: &'a str,
    /// The failure was a TLS handshake's: `ssl_fc_err` has a value (0 without OpenSSL's error).
    pub tls: bool,
    /// OpenSSL's error code, when it gave one (`ssl_fc_err`).
    pub ssl_code: i64,
    /// OpenSSL's error text (`ssl_fc_err_str`).
    pub ssl_text: Option<&'a str>,
}

/// Runtime context passed into sample fetch functions during evaluation.
#[derive(Debug, Clone, Default)]
pub struct SampleContext<'a> {
    /// The client connection's error, when it failed before a session (`error-log-format`).
    pub conn_err: Option<ConnErr<'a>>,
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
    /// The backend connection's error (`conn->err_code` of the stream's `scb`): `CO_ER_NONE`
    /// once it is connected, the code of a connect that failed, `None` while there is no
    /// connection or it is still connecting. What `bc_err` and `bc_err_str` read.
    pub bc_err: Option<ConnErr<'a>>,
    /// The stream's server connection was taken over from an earlier one (`SF_SRV_REUSED`);
    /// `None` where there is no stream. What `bc_reused` reads.
    pub bc_reused: Option<bool>,
    /// The address the backend connection was made to (`conn_dst` of the stream's `scb`),
    /// `None` without one. What `bc_dst` and `bc_dst_port` read; `server_addr` is the
    /// frontend's.
    pub bc_dst: Option<SocketAddr>,
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
    /// When the first byte of the request was received, as unix seconds and milliseconds: `request_date`.
    pub request_date: Option<(i64, u32)>,
    /// What `when()` reads of the stream; `None` is a stream that has done nothing yet.
    pub stream: Option<StreamFacts>,
    /// The proxy's ACLs, for `when(acl,<name>)`; `None` where the caller has none, and the
    /// condition then gives no sample.
    pub acls: Option<&'a crate::acls::Acls>,
    pub is_first_req: bool,
    pub vars: Option<&'a VarMap>,
    pub timeouts: Option<&'a HashMap<String, u32>>,
    /// The backend's `retries`, for `be_max_retries`.
    pub be_max_retries: Option<u16>,
    /// The stream's retry budget, for `cur_max_retries`: what `set-retries` changes.
    pub cur_max_retries: Option<u16>,
    pub act_conn: u32,
    /// T326: the major HTTP version of the client connection's mux (`fc_http_major`): 2 for
    /// HTTP/2, 1 for HTTP/1; `None` where it has no HTTP mux (TCP mode, not set up yet).
    pub fc_http_major: Option<u8>,
    /// T326: the same for the server connection (`bc_http_major`); `None` where there is none
    /// yet or it is not HTTP.
    pub bc_http_major: Option<u8>,
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
    /// The negotiated application protocol, `h2` (`ssl_fc_alpn`); none when not negotiated.
    pub alpn: Option<&'a [u8]>,
    /// The peer sent a certificate (`ssl_c_used`).
    pub has_crt: bool,
    /// The handshake resumed an earlier session (`ssl_fc_is_resumed`).
    pub resumed: bool,
    /// The client's `ClientHello` as `tune.ssl.capture-buffer-size` kept it; `None` when the
    /// size is 0 (`ssl_fc_cipherlist_bin`, `ssl_fc_protocol_hello_id`: no sample).
    pub capture: Option<&'a ibex_tls::SslCapture>,
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
    /// T331: `srv_weight`: the effective weight (`srv->cur_eweight` scaled by `wmult`/`wdiv`).
    /// The user weight while Ibex has no `slowstart` or other effective-weight scaling.
    pub weight: u32,
    /// T331: `srv_iweight`: the configured weight (`srv->iweight`).
    pub iweight: u32,
    /// T331: `srv_uweight`: the user weight as `set server weight` leaves it (`srv->uweight`).
    pub uweight: u32,
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
    // T351: registered, and always 0.
    ("fc_rtt", "Ibex does not read TCP_INFO"),
    ("fc_rttvar", "Ibex does not read TCP_INFO"),
    ("bc_rtt", "Ibex does not read TCP_INFO"),
    ("bc_rttvar", "Ibex does not read TCP_INFO"),
    ("queue", "Ibex has no server queues"),
    ("avg_queue", "Ibex has no server queues"),
    ("srv_queue", "Ibex has no server queues"),
    ("be_conn", "Ibex does not count the streams on a backend"),
    // T331: `HAProxy` asks the front mux; an HTTP/2 stream's entry does not see its connection's.
    ("fc_nb_streams", "a stream does not see its HTTP/2 connection's stream count"),
    ("fc_settings_streams_limit", "a stream does not see its HTTP/2 connection's advertised SETTINGS_MAX_CONCURRENT_STREAMS"),
    ("fc_glitches", "Ibex counts no HTTP/1 glitches, and a stream does not see its HTTP/2 connection's count"),
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
    // T343: what `check_operator` made of it at load: an integer `read_int64` takes whole (an
    // empty argument, a lone sign: 0), or a variable.
    if let Some(n) = crate::argspec::read_int64_whole(arg) {
        return Some(n);
    }
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
    // `sample_conv_var2smp_sint`: the variable cast to `sint` from its own type (T364).
    if ["proc.", "sess.", "req.", "txn.", "res."].iter().any(|p| var_name.starts_with(p)) {
        crate::vars::var_arg_int(var_name)
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
    // The variable cast to `str` from its own type; none, or no cast, is an empty piece.
    crate::vars::var_arg_str(var_name).unwrap_or_default()
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// T330: the `mqtt_is_valid` and `mqtt_field_value` converters, ported from
/// `HAProxy`'s `src/mqtt.c` (`mqtt_validate_message`, `mqtt_field_value`) and
/// `include/haproxy/mqtt.h` (`mqtt_typeid`, `mqtt_check_type_fieldname`). Only CONNECT and
/// CONNACK are parsed, as in `HAProxy`; every read is bounds-checked.
mod mqtt {
    const CPT_CONNECT: u8 = 1;
    const CPT_CONNACK: u8 = 2;
    const CPT_ENTRIES: u32 = 16;
    const VERSION_3_1: u8 = 3;
    const VERSION_3_1_1: u8 = 4;
    const VERSION_5_0: u8 = 5;
    const FL_RESERVED: u8 = 0x01;
    const FL_WILL: u8 = 0x04;
    const FL_WILL_QOS: u8 = 0x18;
    const FL_WILL_RETAIN: u8 = 0x20;
    const FL_PASSWORD: u8 = 0x40;
    const FL_USERNAME: u8 = 0x80;

    /// The field names (`mqtt_fields_string`); the numeric ones are MQTT 5.0 property ids.
    const FIELDS: &[&str] = &[
        "flags", "reason_code", "protocol_name", "protocol_version", "client_identifier", "will_topic",
        "will_payload", "username", "password", "keepalive", "1", "2", "3", "8", "9", "11", "17", "18", "19",
        "21", "22", "23", "24", "25", "26", "28", "31", "33", "34", "35", "36", "37", "38", "39", "40", "41",
        "42",
    ];

    /// The property ids each packet type may be asked for (`mqtt_fields_per_packet`), the
    /// named fields apart. Indexed by packet type; only CONNECT and CONNACK are parsed.
    const CONNECT_FIELDS: &[&str] = &[
        "flags", "protocol_name", "protocol_version", "client_identifier", "will_topic", "will_payload",
        "username", "password", "keepalive", "1", "2", "3", "8", "9", "17", "21", "22", "23", "24",
        "25", "33", "34", "38", "39",
    ];
    const CONNACK_FIELDS: &[&str] = &[
        "flags", "protocol_version", "reason_code", "17", "18", "19", "21", "22", "26", "28", "31", "33",
        "34", "36", "37", "38", "39", "40", "41", "42",
    ];
    const PUBLISH_FIELDS: &[&str] = &["1", "2", "3", "8", "9", "11", "35", "38"];
    const ACK_FIELDS: &[&str] = &["reason_code", "31", "38"];
    const NO_FIELDS: &[&str] = &[];
    const TYPE_NAMES: [&str; 15] = [
        "CONNECT", "CONNACK", "PUBLISH", "PUBACK", "PUBREC", "PUBREL", "PUBCOMP", "SUBSCRIBE", "SUBACK",
        "UNSUBSCRIBE", "UNSUBACK", "PINGREQ", "PINGRESP", "DISCONNECT", "AUTH",
    ];

    /// `mqtt_typeid`: a packet type from its number or name. The number is `HAProxy`'s
    /// unchecked `strl2ui` (each byte adds its value minus `'0'`, wrapping), so a stray
    /// character still maps to a type exactly as it does there.
    #[must_use]
    pub(super) fn type_id(s: &str) -> Option<u8> {
        let n = s.bytes().fold(0u32, |i, b| i.wrapping_mul(10).wrapping_sub(u32::from(b'0')).wrapping_add(u32::from(b)));
        if (u32::from(CPT_CONNECT)..CPT_ENTRIES).contains(&n) {
            return u8::try_from(n).ok();
        }
        let pos = TYPE_NAMES.iter().position(|n| n.eq_ignore_ascii_case(s))?;
        u8::try_from(pos + 1).ok()
    }

    /// `mqtt_check_type_fieldname`: the field `name` when packet type `ty` has it.
    #[must_use]
    pub(super) fn field_id(ty: u8, name: &str) -> Option<&'static str> {
        let known = FIELDS.iter().copied().find(|f| f.eq_ignore_ascii_case(name))?;
        let allowed = match ty {
            CPT_CONNECT => CONNECT_FIELDS,
            CPT_CONNACK => CONNACK_FIELDS,
            3 => PUBLISH_FIELDS,
            4..=7 => ACK_FIELDS,
            8 => &["11", "38"],
            9 | 11 => &["31", "38"],
            10 => &["38"],
            14 => &["reason_code", "17", "28", "31", "38"],
            15 => &["21", "22", "31", "38"],
            _ => NO_FIELDS,
        };
        allowed.contains(&known).then_some(known)
    }

    /// A read cursor over the bytes not yet consumed (an `ist` in `HAProxy`).
    #[derive(Clone, Copy)]
    struct Cur<'a>(&'a [u8]);

    impl<'a> Cur<'a> {
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            let head = self.0.get(..n)?;
            self.0 = self.0.get(n..)?;
            Some(head)
        }

        fn u8(&mut self) -> Option<u8> {
            self.take(1)?.first().copied()
        }

        fn u16(&mut self) -> Option<u16> {
            let b = self.take(2)?;
            Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
        }

        fn u32(&mut self) -> Option<u32> {
            let b = self.take(4)?;
            Some(u32::from_be_bytes([*b.first()?, *b.get(1)?, *b.get(2)?, *b.get(3)?]))
        }

        /// A string prefixed by its 16-bit length.
        fn string(&mut self) -> Option<&'a [u8]> {
            let len = usize::from(self.u16()?);
            self.take(len)
        }

        /// `mqtt_read_varint`: up to four bytes; running out of bytes is not an error here
        /// (the caller compares lengths), a fourth continuation byte is.
        fn varint(&mut self) -> Option<u32> {
            let (mut value, mut shift, mut off) = (0u32, 0u32, 0u8);
            while off < 4 {
                let Some(b) = self.u8() else { break };
                value = value.checked_add(u32::from(b & 0x7f) << shift)?;
                shift += 7;
                if b <= 0x7f {
                    break;
                }
                off += 1;
            }
            (off < 4).then_some(value)
        }
    }

    /// Which property set a block is parsed against.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Ctx {
        Connect,
        Will,
        Connack,
    }

    /// The MQTT 5.0 properties of a block; absent ones stay 0 / empty, as in `HAProxy`.
    #[derive(Default)]
    struct Props<'a> {
        session_expiry_interval: u32,
        receive_maximum: u16,
        maximum_packet_size: u32,
        topic_alias_maximum: u16,
        request_response_information: u8,
        request_problem_information: u8,
        maximum_qos: u8,
        retain_available: u8,
        wildcard_subscription_available: u8,
        subscription_identifiers_available: u8,
        shared_subscription_available: u8,
        server_keepalive: u16,
        delay_interval: u32,
        payload_format_indicator: u8,
        message_expiry_interval: u32,
        authentication_method: &'a [u8],
        authentication_data: &'a [u8],
        assigned_client_identifier: &'a [u8],
        reason_string: &'a [u8],
        response_information: &'a [u8],
        server_reference: &'a [u8],
        content_type: &'a [u8],
        response_topic: &'a [u8],
        correlation_data: &'a [u8],
    }

    /// Reads a property block (its length, then the properties) from `cur`.
    fn props<'a>(cur: &mut Cur<'a>, ctx: Ctx) -> Option<Props<'a>> {
        let plen = usize::try_from(cur.varint()?).ok()?;
        let mut block = Cur(cur.take(plen)?);
        let mut p = Props::default();
        let mut seen = 0u64;
        while let Some(id) = block.u8() {
            if id != 0x26 {
                // a property may appear once (only user properties repeat)
                let bit = 1u64.checked_shl(u32::from(id))?;
                if seen & bit != 0 {
                    return None;
                }
                seen |= bit;
            }
            let flag = |v: u8| (v <= 1).then_some(v);
            match (ctx, id) {
                (Ctx::Connect | Ctx::Connack, 0x11) => p.session_expiry_interval = block.u32()?,
                (Ctx::Connect | Ctx::Connack, 0x21) => {
                    p.receive_maximum = block.u16().filter(|v| *v != 0)?;
                }
                (Ctx::Connect | Ctx::Connack, 0x27) => {
                    p.maximum_packet_size = block.u32().filter(|v| *v != 0)?;
                }
                (Ctx::Connect | Ctx::Connack, 0x22) => p.topic_alias_maximum = block.u16()?,
                (Ctx::Connect, 0x19) => p.request_response_information = block.u8().and_then(flag)?,
                (Ctx::Connect, 0x17) => p.request_problem_information = block.u8().and_then(flag)?,
                (Ctx::Connect | Ctx::Connack, 0x15) => p.authentication_method = block.string()?,
                (Ctx::Connect | Ctx::Connack, 0x16) => p.authentication_data = block.string()?,
                (Ctx::Will, 0x18) => p.delay_interval = block.u32()?,
                (Ctx::Will, 0x01) => p.payload_format_indicator = block.u8().and_then(flag)?,
                (Ctx::Will, 0x02) => p.message_expiry_interval = block.u32()?,
                (Ctx::Will, 0x03) => p.content_type = block.string()?,
                (Ctx::Will, 0x08) => p.response_topic = block.string()?,
                (Ctx::Will, 0x09) => p.correlation_data = block.string()?,
                (Ctx::Connack, 0x24) => p.maximum_qos = block.u8().and_then(flag)?,
                (Ctx::Connack, 0x25) => p.retain_available = block.u8().and_then(flag)?,
                (Ctx::Connack, 0x12) => {
                    p.assigned_client_identifier = block.string().filter(|s| !s.is_empty())?;
                }
                (Ctx::Connack, 0x1f) => p.reason_string = block.string()?,
                (Ctx::Connack, 0x28) => p.wildcard_subscription_available = block.u8().and_then(flag)?,
                (Ctx::Connack, 0x29) => p.subscription_identifiers_available = block.u8().and_then(flag)?,
                (Ctx::Connack, 0x2a) => p.shared_subscription_available = block.u8().and_then(flag)?,
                (Ctx::Connack, 0x13) => p.server_keepalive = block.u16()?,
                (Ctx::Connack, 0x1a) => p.response_information = block.string()?,
                (Ctx::Connack, 0x1c) => p.server_reference = block.string()?,
                (_, 0x26) => {
                    block.string()?;
                    block.string()?;
                }
                _ => return None,
            }
        }
        Some(p)
    }

    #[derive(Default)]
    pub(super) struct Connect<'a> {
        protocol_name: &'a [u8],
        protocol_version: u8,
        flags: u8,
        keepalive: u16,
        props: Props<'a>,
        client_identifier: &'a [u8],
        will_props: Props<'a>,
        will_topic: &'a [u8],
        will_payload: &'a [u8],
        username: &'a [u8],
        password: &'a [u8],
    }

    /// `mqtt_parse_connect`; `cur` follows the fixed header. `None` is an invalid message.
    fn parse_connect<'a>(cur: &mut Cur<'a>) -> Option<Connect<'a>> {
        let mut c = Connect { protocol_name: cur.string()?, ..Connect::default() };
        if !(c.protocol_name.eq_ignore_ascii_case(b"MQTT") || c.protocol_name.eq_ignore_ascii_case(b"MQIsdp")) {
            return None;
        }
        c.protocol_version = cur.u8()?;
        if ![VERSION_3_1, VERSION_3_1_1, VERSION_5_0].contains(&c.protocol_version) {
            return None;
        }
        c.flags = cur.u8()?;
        if c.flags & FL_RESERVED != 0 {
            return None;
        }
        // as in HAProxy: refused only when both QoS bits are set without will nor retain
        if c.flags & (FL_WILL | FL_WILL_QOS | FL_WILL_RETAIN) == FL_WILL_QOS {
            return None;
        }
        c.keepalive = cur.u16()?;
        let v5 = c.protocol_version == VERSION_5_0;
        if v5 {
            c.props = props(cur, Ctx::Connect)?;
        }
        if c.props.authentication_method.is_empty() && !c.props.authentication_data.is_empty() {
            return None;
        }
        c.client_identifier = cur.string()?;
        if v5 && c.flags & FL_WILL != 0 {
            c.will_props = props(cur, Ctx::Will)?;
        }
        if c.flags & FL_WILL != 0 {
            c.will_topic = cur.string()?;
            c.will_payload = cur.string()?;
        }
        if c.flags & FL_USERNAME != 0 {
            c.username = cur.string()?;
        }
        if c.flags & FL_PASSWORD != 0 {
            c.password = cur.string()?;
        }
        Some(c)
    }

    #[derive(Default)]
    pub(super) struct Connack<'a> {
        protocol_version: u8,
        flags: u8,
        reason_code: u8,
        props: Props<'a>,
    }

    /// `mqtt_parse_connack`; `cur` follows the fixed header. As in `HAProxy`, the version
    /// is told from everything that follows the header, not from the remaining length.
    fn parse_connack<'a>(cur: &mut Cur<'a>) -> Option<Connack<'a>> {
        let mut c = Connack::default();
        match cur.0.len() {
            0 | 1 => return None,
            2 => c.protocol_version = VERSION_3_1_1,
            _ => c.protocol_version = VERSION_5_0,
        }
        c.flags = cur.u8()?;
        if c.flags & 0xfe != 0 {
            return None;
        }
        c.reason_code = cur.u8()?;
        if c.protocol_version == VERSION_5_0 {
            c.props = props(cur, Ctx::Connack)?;
        }
        Some(c)
    }

    /// A message that passed `mqtt_validate_message`.
    pub(super) enum Packet<'a> {
        Connect(Box<Connect<'a>>),
        Connack(Box<Connack<'a>>),
    }

    /// The outcome of `mqtt_validate_message`.
    pub(super) enum Parsed<'a> {
        Invalid,
        NeedMoreData,
        Valid(Packet<'a>),
    }

    /// `mqtt_validate_message`: the fixed header, the remaining length, then the packet.
    #[must_use]
    pub(super) fn validate(msg: &[u8]) -> Parsed<'_> {
        let mut cur = Cur(msg);
        if msg.len() < 2 {
            return Parsed::NeedMoreData;
        }
        let Some(first) = cur.u8() else { return Parsed::Invalid };
        let (ty, flags) = (first >> 4, first & 0x0f);
        let wanted_flags = match ty {
            0 => return Parsed::Invalid,
            3 => flags,
            6 | 8 | 10 => 0x02,
            _ => 0,
        };
        if flags != wanted_flags {
            return Parsed::Invalid;
        }
        let Some(remaining) = cur.varint().and_then(|r| usize::try_from(r).ok()) else {
            return Parsed::Invalid;
        };
        if cur.0.len() < remaining {
            return Parsed::NeedMoreData;
        }
        let before = cur.0.len();
        let packet = match ty {
            CPT_CONNECT => parse_connect(&mut cur).map(|c| Packet::Connect(Box::new(c))),
            CPT_CONNACK => parse_connack(&mut cur).map(|c| Packet::Connack(Box::new(c))),
            _ => None,
        };
        match packet {
            Some(p) if before - cur.0.len() == remaining => Parsed::Valid(p),
            _ => Parsed::Invalid,
        }
    }

    /// A field value: a number (printed in decimal) or bytes.
    pub(super) enum Value<'a> {
        Num(u32),
        Bytes(&'a [u8]),
    }

    fn bytes(b: &[u8]) -> Option<Value<'_>> {
        (!b.is_empty()).then_some(Value::Bytes(b))
    }

    /// `mqtt_field_value` for a CONNECT: `field` comes from [`field_id`].
    fn connect_field<'a>(c: &Connect<'a>, field: &str) -> Option<Value<'a>> {
        let v5 = c.protocol_version == VERSION_5_0;
        let will5 = v5 && c.flags & FL_WILL != 0;
        match field {
            "flags" => Some(Value::Num(u32::from(c.flags))),
            "protocol_name" => bytes(c.protocol_name),
            "protocol_version" => Some(Value::Num(u32::from(c.protocol_version))),
            "client_identifier" => bytes(c.client_identifier),
            "will_topic" => bytes(c.will_topic),
            "will_payload" => bytes(c.will_payload),
            "username" => bytes(c.username),
            "password" => bytes(c.password),
            "keepalive" => Some(Value::Num(u32::from(c.keepalive))),
            "1" if will5 => Some(Value::Num(u32::from(c.will_props.payload_format_indicator))),
            "2" if will5 => Some(Value::Num(c.will_props.message_expiry_interval)),
            "3" if will5 => bytes(c.will_props.content_type),
            "8" if will5 => bytes(c.will_props.response_topic),
            "9" if will5 => bytes(c.will_props.correlation_data),
            "24" if will5 => Some(Value::Num(c.will_props.delay_interval)),
            "17" if v5 => Some(Value::Num(c.props.session_expiry_interval)),
            "21" if v5 => bytes(c.props.authentication_method),
            "22" if v5 => bytes(c.props.authentication_data),
            "23" if v5 => Some(Value::Num(u32::from(c.props.request_problem_information))),
            "25" if v5 => Some(Value::Num(u32::from(c.props.request_response_information))),
            "33" if v5 => Some(Value::Num(u32::from(c.props.receive_maximum))),
            "34" if v5 => Some(Value::Num(u32::from(c.props.topic_alias_maximum))),
            "39" if v5 => Some(Value::Num(c.props.maximum_packet_size)),
            _ => None,
        }
    }

    /// `mqtt_field_value` for a CONNACK.
    fn connack_field<'a>(c: &Connack<'a>, field: &str) -> Option<Value<'a>> {
        let v5 = c.protocol_version == VERSION_5_0;
        let p = &c.props;
        match field {
            "flags" => Some(Value::Num(u32::from(c.flags))),
            "reason_code" => Some(Value::Num(u32::from(c.reason_code))),
            "protocol_version" => Some(Value::Num(u32::from(c.protocol_version))),
            "17" if v5 => Some(Value::Num(p.session_expiry_interval)),
            "18" if v5 => bytes(p.assigned_client_identifier),
            "19" if v5 => Some(Value::Num(u32::from(p.server_keepalive))),
            "21" if v5 => bytes(p.authentication_method),
            "22" if v5 => bytes(p.authentication_data),
            "26" if v5 => bytes(p.response_information),
            "28" if v5 => bytes(p.server_reference),
            "31" if v5 => bytes(p.reason_string),
            "33" if v5 => Some(Value::Num(u32::from(p.receive_maximum))),
            "34" if v5 => Some(Value::Num(u32::from(p.topic_alias_maximum))),
            "36" if v5 => Some(Value::Num(u32::from(p.maximum_qos))),
            "37" if v5 => Some(Value::Num(u32::from(p.retain_available))),
            "39" if v5 => Some(Value::Num(p.maximum_packet_size)),
            "40" if v5 => Some(Value::Num(u32::from(p.wildcard_subscription_available))),
            "41" if v5 => Some(Value::Num(u32::from(p.subscription_identifiers_available))),
            "42" if v5 => Some(Value::Num(u32::from(p.shared_subscription_available))),
            _ => None,
        }
    }

    /// `mqtt_field_value`: `None` when the field is absent, the message invalid or still
    /// incomplete. `ty` and `field` come from [`type_id`] and [`field_id`].
    #[must_use]
    pub(super) fn field_value<'a>(msg: &'a [u8], ty: u8, field: &str) -> Option<Value<'a>> {
        match (validate(msg), ty) {
            (Parsed::Valid(Packet::Connect(c)), CPT_CONNECT) => connect_field(&c, field),
            (Parsed::Valid(Packet::Connack(c)), CPT_CONNACK) => connack_field(&c, field),
            _ => None,
        }
    }
}

/// T330: the converter `mqtt_is_valid`: 1 or 0, and no sample while the message is
/// incomplete (`SMP_F_MAY_CHANGE` in `HAProxy`).
fn mqtt_is_valid(msg: &[u8]) -> Option<Sample> {
    match mqtt::validate(msg) {
        mqtt::Parsed::Valid(_) => Some(Sample::Bool(true)),
        mqtt::Parsed::Invalid => Some(Sample::Bool(false)),
        mqtt::Parsed::NeedMoreData => None,
    }
}

/// T330: the converter `mqtt_field_value(<packettype>,<fieldname>)`.
fn mqtt_field_value(msg: &[u8], args: &[String]) -> Option<Sample> {
    let ty = mqtt::type_id(args.first()?)?;
    let field = mqtt::field_id(ty, args.get(1)?)?;
    // HAProxy declares a string but never sets the sample type, so the value stays binary (the
    // input type): it casts to a string, not to an integer.
    Some(Sample::Bin(match mqtt::field_value(msg, ty, field)? {
        mqtt::Value::Num(n) => n.to_string().into_bytes(),
        mqtt::Value::Bytes(b) => b.to_vec(),
    }))
}

/// T330: load-time check of `mqtt_field_value`'s arguments (`sample_conv_mqtt_field_value_check`).
fn mqtt_field_value_args_error(args: &[String]) -> Option<String> {
    let (Some(ty), Some(field)) = (args.first(), args.get(1)) else {
        return Some("invalid arg 2 in converter 'mqtt_field_value' : missing arguments (got 1/2), type 'string' expected.".to_string());
    };
    if args.len() > 2 {
        return Some(format!("invalid arg 2 in converter 'mqtt_field_value' : expected ')' before ',{})'.", args[2..].join(",")));
    }
    let Some(id) = mqtt::type_id(ty) else {
        return Some(format!("invalid args in converter 'mqtt_field_value' : Unknown MQTT type '{ty}'."));
    };
    mqtt::field_id(id, field).is_none().then(|| {
        format!("invalid args in converter 'mqtt_field_value' : Unknown MQTT field name '{field}' for packet type '{ty}'.")
    })
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

    /// T337: registers `names` as a fetch that gives one sample (`one`, used where a sample is
    /// evaluated) and, in an ACL, every value it can iterate on (`all`: `SMP_OPT_ITERATE`).
    fn register_iterating(&mut self, names: &[&'static str], out_type: SampleType, one: FetchFn, all: MultiFetchFn) {
        for &name in names {
            self.register_fetch(FetchDesc { name, out_type, func: one });
            self.register_multi_fetch(name, all);
        }
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

    /// T341: the arguments of each converter of a chain ([`check_converter_args`]). Whether
    /// each converter applies to what precedes it is checked with `HAProxy`'s declared types
    /// since T343 ([`crate::argspec::check_typed_expr`]), the fetch's included.
    #[must_use]
    pub fn check_converters(&self, converters: &[(String, Vec<String>)]) -> Option<String> {
        converters.iter().find_map(|(name, args)| check_converter_args(name, args))
    }

    /// T330: the total IP header length of `b` (v4 or v6, IPv6 extension headers included), the
    /// offset of the TCP or UDP header, or `None` when data are missing or unparsable
    /// (`ip_header_length()` in `src/net_helper.c` returning 0).
    fn ip_header_length(b: &[u8]) -> Option<usize> {
        let len = match b.first()? >> 4 {
            4 => usize::from(b[0] & 0xF) * 4,
            6 => {
                if b.len() < 40 {
                    return None;
                }
                let mut len = 40;
                let mut next = b[6];
                while next != 6 && next != 17 {
                    let h = b.get(len..len + 2)?;
                    next = h[0];
                    len += usize::from(h[1]) * 8 + 8;
                }
                len
            }
            _ => return None,
        };
        (len != 0 && b.len() >= len).then_some(len)
    }

    /// T330: the `ip.fp` fingerprint of the IP+TCP packet `b` (`sample_conv_ip_fp()` in
    /// `src/net_helper.c`): TOS, then flags, header length and wscale, window, MSS and the option
    /// mask, then by `<mode>` bit the TTL (1), the option kinds (2) and the source address (4).
    fn ip_fp(b: &[u8], args: &[String]) -> Option<Vec<u8>> {
        // ARG1(0,SINT): the argument is an integer; only its low bits matter.
        let mode = args.first().map_or(Some(0), |s| s.trim().parse::<i64>().ok())?;
        let ipver = b.first()? >> 4;
        let (iptos, pktlen, ipdf, ipttl, ipext, ipsrc) = match ipver {
            4 => {
                // The reference reads these fields whatever the header length says; a packet
                // too short for them cannot hold a TCP header either, so give no sample.
                let h = b.get(..20)?;
                if b.len() < usize::from(h[0] & 0xF) * 4 {
                    return None;
                }
                let pktlen = usize::from(u16::from_be_bytes([h[2], h[3]]));
                (h[1], pktlen, h[6] & 0x40 != 0, h[8], h[0] & 0xF != 5, &h[12..16])
            }
            6 => {
                let h = b.get(..40)?;
                let pktlen = 40 + usize::from(u16::from_be_bytes([h[4], h[5]]));
                // read_n16() >> 4 stored in a byte: the traffic class, across bytes 0 and 1
                let iptos = h[0] << 4 | h[1] >> 4;
                (iptos, pktlen, true, h[7], h[6] != 6 && h[6] != 17, &h[8..24])
            }
            _ => return None,
        };

        let mut out = vec![0u8; 8];
        out[0] = iptos;
        if mode & 1 != 0 {
            out.push(ipttl);
        }
        // two bits of TTL: <=32, <=64, <=128, <=255
        let ttl2: u8 = if ipttl > 64 { if ipttl > 128 { 3 } else { 2 } } else { u8::from(ipttl > 32) };

        let iplen = Self::ip_header_length(b)?;
        if iplen > pktlen {
            return None;
        }
        let tcp = &b[iplen..];
        let pktlen = pktlen - iplen;
        // the TCP header must be complete (tcp_fullhdr_length()) and fit the packet length
        if tcp.len() < 20 {
            return None;
        }
        let tcplen = usize::from(tcp[12] >> 4) * 4;
        if tcplen < 20 || tcp.len() < tcplen || tcplen > pktlen {
            return None;
        }
        let data_present = pktlen - tcplen > 0;
        let tcpflags = tcp[13];
        let tcpwin = u16::from_be_bytes([tcp[14], tcp[15]]);

        out[1] = u8::from(ipver == 6) << 7
            | u8::from(ipdf) << 6
            | ttl2 << 4
            | u8::from(ipext) << 3
            | u8::from(data_present) << 2
            | tcpflags >> 6;

        let (mut tcpmss, mut tcpws, mut opts) = (0u16, 0u8, 0u8);
        let mut ofs = 20;
        while ofs < tcplen {
            let opt = tcp[ofs];
            let next = match opt {
                0 => break,
                1 => ofs + 1,
                _ if ofs + 1 < tcplen && tcp[ofs + 1] > 1 => ofs + usize::from(tcp[ofs + 1]),
                _ => break,
            };
            if next > tcplen {
                break;
            }
            if mode & 2 != 0 {
                out.push(opt);
            }
            if opt == 2 && ofs + 3 < tcplen {
                tcpmss = u16::from_be_bytes([tcp[ofs + 2], tcp[ofs + 3]]);
            } else if opt == 3 && ofs + 2 < tcplen {
                // 1 to 15, 0 meaning absent
                let ws = tcp[ofs + 2];
                tcpws = if ws > 14 { 15 } else { ws + 1 };
            }
            if opt >= 2 {
                opts |= 1 << (if opt < 9 { opt - 2 } else { 7 });
            }
            ofs = next;
        }

        // tcplen << 2 in a byte: the data offset in words, in the high nibble
        out[2] = tcp[12] & 0xF0 | tcpws;
        out[3..5].copy_from_slice(&tcpwin.to_be_bytes());
        out[5..7].copy_from_slice(&tcpmss.to_be_bytes());
        out[7] = opts;
        if mode & 4 != 0 {
            out.extend_from_slice(ipsrc);
        }
        Some(out)
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
        // T331: `smp_fetch_fc_rcvd_proxy`: `CO_FL_RCVD_PROXY`, set once a PROXY header
        // (v1, v1 UNKNOWN, v2 PROXY or LOCAL) has been parsed. `proxy_tlvs` is `Some` exactly
        // then: `apply_proxy_header` stores every parsed header in `proxy_info`.
        let fc_rcvd_proxy_fetch: FetchFn = |ctx, _args| Some(Sample::Bool(ctx.proxy_tlvs.is_some()));
        self.register_fetch(FetchDesc {
            name: "fc_rcvd_proxy",
            out_type: SampleType::Bool,
            func: fc_rcvd_proxy_fetch,
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

        // T329: src_is_local, fc_src_is_local
        let src_is_local_fetch: FetchFn = |ctx, _args| {
            is_local_sample(ctx.client_addr)
        };
        let fc_src_is_local_fetch: FetchFn = |ctx, _args| {
            is_local_sample(ctx.fc_src.or(ctx.client_addr))
        };
        self.register_fetch(FetchDesc {
            name: "src_is_local",
            out_type: SampleType::Bool,
            func: src_is_local_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "fc_src_is_local",
            out_type: SampleType::Bool,
            func: fc_src_is_local_fetch,
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

        // T329: dst_is_local, fc_dst_is_local
        let dst_is_local_fetch: FetchFn = |ctx, _args| {
            is_local_sample(ctx.server_addr)
        };
        let fc_dst_is_local_fetch: FetchFn = |ctx, _args| {
            is_local_sample(ctx.fc_dst.or(ctx.server_addr))
        };
        self.register_fetch(FetchDesc {
            name: "dst_is_local",
            out_type: SampleType::Bool,
            func: dst_is_local_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "fc_dst_is_local",
            out_type: SampleType::Bool,
            func: fc_dst_is_local_fetch,
        });

        // T331: `fc_nb_streams`, `fc_settings_streams_limit` and `fc_glitches` are refused
        // instead ([`NOT_IMPLEMENTED`]): they were registered here as the constants 1, 1, 0.
        // T331: the backend connection (`SMP_USE_L4SRV`). Without one, none has a value;
        // `bc_reused` is 0 on any stream (`smp_fetch_reused`).
        self.register_fetch(FetchDesc {
            name: "bc_err",
            out_type: SampleType::Sint,
            func: |ctx, _args| ctx.bc_err.map(|e| Sample::Sint(e.code)),
        });
        self.register_fetch(FetchDesc {
            name: "bc_err_str",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.bc_err.map(|e| Sample::Str(e.text.to_string())),
        });
        self.register_fetch(FetchDesc {
            name: "bc_reused",
            out_type: SampleType::Bool,
            func: |ctx, _args| ctx.bc_reused.map(Sample::Bool),
        });
        self.register_fetch(FetchDesc {
            name: "bc_dst",
            // An address, IPv4 or IPv6 (`SMP_T_ADDR`), typed as `dst` is.
            out_type: SampleType::Ipv4,
            func: |ctx, _args| match ctx.bc_dst?.ip() {
                IpAddr::V4(v4) => Some(Sample::Ipv4(v4)),
                IpAddr::V6(v6) => Some(Sample::Ipv6(v6)),
            },
        });
        self.register_fetch(FetchDesc {
            name: "bc_dst_port",
            out_type: SampleType::Sint,
            func: |ctx, _args| ctx.bc_dst.map(|sa| Sample::Sint(i64::from(sa.port()))),
        });

        // --- 2. HTTP Request Line & URL Fetches ---
        self.register_fetch(FetchDesc {
            name: "path",
            out_type: SampleType::Str,
            func: |ctx, _args| {
                // `http_parse_path`: a target that is neither an absolute path nor an
                // absolute URI (`*`, `host:port`, what `replace-path a Y` leaves) has none.
                let path = http_parse_path(get_context_uri(ctx)?, get_context_method(ctx) == Some("OPTIONS"))?;
                Some(Sample::Str(path.split('?').next().unwrap_or_default().to_string()))
            },
        });

        self.register_fetch(FetchDesc {
            name: "pathq",
            out_type: SampleType::Str,
            func: |ctx, _args| {
                let path = http_parse_path(get_context_uri(ctx)?, get_context_method(ctx) == Some("OPTIONS"))?;
                Some(Sample::Str(path.to_string()))
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
            name: "url_ip",
            out_type: SampleType::Ipv4,
            func: |ctx, _args| {
                let (ip, _) = url_ipv4_authority(get_context_uri(ctx)?)?;
                Some(Sample::Ipv4(ip))
            },
        });
        self.register_fetch(FetchDesc {
            name: "url_port",
            out_type: SampleType::Sint,
            func: |ctx, _args| {
                let (_, port) = url_ipv4_authority(get_context_uri(ctx)?)?;
                Some(Sample::Sint(i64::from(port)))
            },
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

        // T337: `url_param`/`urlp` give the first parameter as a sample; an ACL tries each one.
        self.register_iterating(
            &["url_param", "urlp"],
            SampleType::Str,
            |ctx, args| url_param_fetch(ctx, args, false).pop().map(Sample::Str),
            |ctx, args| url_param_fetch(ctx, args, true).into_iter().map(Sample::Str).collect(),
        );
        // T327: `smp_fetch_url_param_val` is `strl2ic` over the raw value, not decoded.
        self.register_iterating(
            &["urlp_val"],
            SampleType::Sint,
            |ctx, args| url_param_fetch(ctx, args, false).pop().map(strl2ic_sample),
            |ctx, args| url_param_fetch(ctx, args, true).into_iter().map(strl2ic_sample).collect(),
        );

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

        // T326: `smp_fetch_fc_http_major` (`src/connection.c`), `fc_http_major` and
        // `bc_http_major`: the major version of the client's or the server's connection by its
        // mux (2 for H2, 1 for H1), and nothing where it has no HTTP mux (TCP mode, before the
        // mux is set up, no server connection yet). The runtime gives both in the context.
        self.register_fetch(FetchDesc {
            name: "fc_http_major",
            out_type: SampleType::Sint,
            func: |ctx, _args| ctx.fc_http_major.map(|m| Sample::Sint(i64::from(m))),
        });
        self.register_fetch(FetchDesc {
            name: "bc_http_major",
            out_type: SampleType::Sint,
            func: |ctx, _args| ctx.bc_http_major.map(|m| Sample::Sint(i64::from(m))),
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
        // T329e: `resp_ver`, the alias of `res.ver` (`src/http_fetch.c`).
        self.register_fetch(FetchDesc {
            name: "resp_ver",
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
        // `txn.conn_retries` and `txn.redispatched` (`smp_fetch_conn_retries`,
        // `smp_fetch_redispatched`): what the stream has spent on reaching a server.
        self.register_fetch(FetchDesc {
            name: "txn.conn_retries",
            out_type: SampleType::Sint,
            func: |ctx, _args| ctx.stream.map(|f| Sample::Sint(i64::from(f.retries))),
        });
        self.register_fetch(FetchDesc {
            name: "txn.redispatched",
            out_type: SampleType::Bool,
            func: |ctx, _args| ctx.stream.map(|f| Sample::Bool(f.redispatched)),
        });
        // `txn.status`: the status the log reports, `status` where a response is read.
        self.register_fetch(FetchDesc {
            name: "txn.status",
            out_type: SampleType::Sint,
            func: status_fetch,
        });

        // `smp_fetch_proto_http` (`src/http_fetch.c`), registered as `req.proto_http` and, T326,
        // as its alias `req_proto_http`.
        let proto_http_fetch: FetchFn = |ctx, _args| {
            Some(Sample::Bool(ctx.htx_slice.is_some() || ctx.htx.is_some() || ctx.req_uri.is_some()))
        };
        self.register_fetch(FetchDesc { name: "req.proto_http", out_type: SampleType::Bool, func: proto_http_fetch });
        self.register_fetch(FetchDesc { name: "req_proto_http", out_type: SampleType::Bool, func: proto_http_fetch });
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
            func: |ctx, _args| Some(Sample::Sint(i64::from(base32_hash(ctx)?))),
        });

        self.register_fetch(FetchDesc {
            name: "base32+src",
            out_type: SampleType::Bin,
            func: |ctx, _args| {
                let h = base32_hash(ctx)?;
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
            name: "url32",
            out_type: SampleType::Sint,
            // T326
            func: |ctx, _args| {
                let h = url32_hash(ctx);
                Some(Sample::Sint(i64::from(h)))
            },
        });

        self.register_fetch(FetchDesc {
            name: "url32+src",
            out_type: SampleType::Bin,
            // T326
            func: |ctx, _args| {
                let h = url32_hash(ctx);
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
            func: |ctx, _args| {
                fetch_base_path(ctx, true)
            },
        });

        // --- 4. HTTP Headers Fetches ---
        // T337: `smp_fetch_hdr` (comma values) and `smp_fetch_fhdr` (lines): the last one as a
        // sample, every one in an ACL, the `<occ>`th one (from the end when negative) either way.
        self.register_iterating(
            &["req.hdr", "hdr"],
            SampleType::Str,
            |ctx, args| header_one(ctx, args, false, false).map(Sample::Str),
            |ctx, args| header_all(ctx, args, false, false).into_iter().map(Sample::Str).collect(),
        );
        self.register_iterating(
            &["req.fhdr"],
            SampleType::Str,
            |ctx, args| header_one(ctx, args, false, true).map(Sample::Str),
            |ctx, args| header_all(ctx, args, false, true).into_iter().map(Sample::Str).collect(),
        );

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

        self.register_iterating(
            &["res.hdr", "shdr"],
            SampleType::Str,
            |ctx, args| header_one(ctx, args, true, false).map(Sample::Str),
            |ctx, args| header_all(ctx, args, true, false).into_iter().map(Sample::Str).collect(),
        );
        self.register_iterating(
            &["res.fhdr"],
            SampleType::Str,
            |ctx, args| header_one(ctx, args, true, true).map(Sample::Str),
            |ctx, args| header_all(ctx, args, true, true).into_iter().map(Sample::Str).collect(),
        );

        // T327: req.fhdr_cnt counts lines and req.hdr_cnt values, with or without a name, on
        // the headers as the oracle's H1 parser leaves them (`h1_cleaned_headers`).
        let req_hdr_cnt_fetch: FetchFn = |ctx, args| {
            let all = get_all_req_headers_all(ctx);
            let count = match args.first() {
                Some(name) => all.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name)).count(),
                None => all.len(),
            };
            Some(Sample::Sint(len_to_sint(count)))
        };
        let req_hdr_val_cnt_fetch: FetchFn = |ctx, args| {
            let all = get_all_req_headers_all(ctx);
            let total: usize = all
                .iter()
                .filter(|(n, _)| args.first().is_none_or(|name| n.eq_ignore_ascii_case(name)))
                .map(|(_, v)| hdr_values(v).len())
                .sum();
            Some(Sample::Sint(len_to_sint(total)))
        };
        self.register_fetch(FetchDesc {
            name: "req.hdr_cnt",
            out_type: SampleType::Sint,
            func: req_hdr_val_cnt_fetch,
        });
        // T302: req.hdrs fetch
        self.register_fetch(FetchDesc {
            name: "req.hdrs",
            out_type: SampleType::Str,
            func: |ctx, _args| req_header_block(ctx).map(Sample::Str),
        });

        // T329: req.hdrs_bin (`smp_fetch_hdrs_bin`, src/http_fetch.c). No request headers at
        // all, no sample, as HAProxy without an HTX message.
        let req_hdrs_bin_fetch: FetchFn = |ctx, _args| {
            if let Some(htx) = ctx.htx_slice {
                return Some(hdrs_bin(htx.headers(), true));
            }
            if let Some(htx) = ctx.htx {
                return Some(hdrs_bin(htx.headers().map(|hf| (hf.name.as_str(), hf.value.as_str())), true));
            }
            ctx.req_headers.map(|h| hdrs_bin(h.iter().map(|(k, v)| (k.as_str(), v.as_str())), true))
        };
        self.register_fetch(FetchDesc {
            name: "req.hdrs_bin",
            out_type: SampleType::Bin,
            func: req_hdrs_bin_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "hdr_cnt",
            out_type: SampleType::Sint,
            func: req_hdr_val_cnt_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "req.fhdr_cnt",
            out_type: SampleType::Sint,
            func: req_hdr_cnt_fetch,
        });
        let req_hdr_names_fetch: FetchFn = |ctx, args| {
            Some(Sample::Str(req_header_names(ctx).join(&names_delim(args))))
        };
        self.register_fetch(FetchDesc {
            name: "req.hdr_names",
            out_type: SampleType::Str,
            func: req_hdr_names_fetch,
        });

        // T327: res.hdr_cnt counts values and res.fhdr_cnt lines, with or without a name, on the
        // headers as the oracle's H1 parser leaves them (`h1_cleaned_headers`). shdr_cnt is the
        // same fetch as res.hdr_cnt on the oracle (`smp_fetch_hdr_cnt`): T326 registers it with
        // `res_hdr_cnt_f` too.
        let res_hdr_cnt_f: FetchFn = |ctx, args| {
            let all = get_all_res_headers_all(ctx);
            let total: usize = all
                .iter()
                .filter(|(n, _)| args.first().is_none_or(|name| n.eq_ignore_ascii_case(name)))
                .map(|(_, v)| hdr_values(v).len())
                .sum();
            Some(Sample::Sint(len_to_sint(total)))
        };
        self.register_fetch(FetchDesc {
            name: "res.hdr_cnt",
            out_type: SampleType::Sint,
            func: res_hdr_cnt_f,
        });
        self.register_fetch(FetchDesc {
            name: "shdr_cnt",
            out_type: SampleType::Sint,
            func: res_hdr_cnt_f,
        });
        self.register_fetch(FetchDesc {
            name: "res.fhdr_cnt",
            out_type: SampleType::Sint,
            func: |ctx, args| {
                let all = get_all_res_headers_all(ctx);
                let count = match args.first() {
                    Some(name) => all.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name)).count(),
                    None => all.len(),
                };
                Some(Sample::Sint(len_to_sint(count)))
            },
        });

        self.register_fetch(FetchDesc {
            name: "res.hdrs",
            out_type: SampleType::Str,
            func: |ctx, _| Some(Sample::Str(res_header_block(ctx))),
        });

        self.register_fetch(FetchDesc {
            name: "res.hdr_names",
            out_type: SampleType::Str,
            func: |ctx, args| {
                Some(Sample::Str(get_all_res_header_names(ctx).join(&names_delim(args))))
            },
        });

        self.register_fetch(FetchDesc {
            name: "res.hdrs_bin",
            out_type: SampleType::Bin,
            // T329: `smp_fetch_hdrs_bin` on the response, through the same H1 cleanup and
            // varint as req.hdrs_bin.
            func: |ctx, _args| {
                let pairs = |h: &[(String, String)]| hdrs_bin(h.iter().map(|(k, v)| (k.as_str(), v.as_str())), false);
                if let Some(headers) = ctx.res_headers {
                    return Some(pairs(headers));
                }
                Some(CURRENT_RES_HEADERS.with(|h| pairs(&h.borrow())))
            },
        });

        // T337: `smp_fetch_hdr_val`: `strl2ic` over the value `smp_fetch_hdr` gives.
        self.register_iterating(
            &["req.hdr_val", "hdr_val"],
            SampleType::Sint,
            |ctx, args| header_one(ctx, args, false, false).map(strl2ic_sample),
            |ctx, args| header_all(ctx, args, false, false).into_iter().map(strl2ic_sample).collect(),
        );
        // T326: shdr_val is the deprecated alias of res.hdr_val.
        self.register_iterating(
            &["res.hdr_val", "shdr_val"],
            SampleType::Sint,
            |ctx, args| header_one(ctx, args, true, false).map(strl2ic_sample),
            |ctx, args| header_all(ctx, args, true, false).into_iter().map(strl2ic_sample).collect(),
        );

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

        let res_hdr_ip_fetch: FetchFn = |ctx, args| {
            let name = args.first()?;
            let val = get_res_header(ctx, name)?;
            parse_ip_str(&val)
        };
        // T326: res.hdr_ip registered once with a named FetchFn so the deprecated alias shdr_ip below shares it
        self.register_fetch(FetchDesc {
            name: "res.hdr_ip",
            out_type: SampleType::Ipv4,
            func: res_hdr_ip_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "shdr_ip",
            out_type: SampleType::Ipv4,
            func: res_hdr_ip_fetch,
        });

        // T337: `smp_fetch_cookie`: the last cookie of that name (the first cookie when no name
        // is given) as a sample, every one in an ACL.
        self.register_iterating(
            &["req.cook", "cook", "cookie"],
            SampleType::Str,
            |ctx, args| cookie_fetch(ctx, args, false, false).pop().map(Sample::Str),
            |ctx, args| cookie_fetch(ctx, args, false, true).into_iter().map(Sample::Str).collect(),
        );
        self.register_iterating(
            &["res.cook", "scook"],
            SampleType::Str,
            |ctx, args| cookie_fetch(ctx, args, true, false).pop().map(Sample::Str),
            |ctx, args| cookie_fetch(ctx, args, true, true).into_iter().map(Sample::Str).collect(),
        );

        // T337: `smp_fetch_cookie_cnt` on a request: every cookie `smp_fetch_cookie` would try.
        let cook_cnt_fetch: FetchFn = |ctx, args| Some(Sample::Sint(len_to_sint(cookie_fetch(ctx, args, false, true).len())));
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

        let cook_names_fetch: FetchFn = |ctx, args| {
            // T326
            let delim = names_delim(args);
            let mut names = String::new();
            for hdr in get_all_req_headers(ctx, "cookie") {
                crate::cookie_names::append(&mut names, &hdr, true, &delim);
            }
            Some(Sample::Str(names))
        };
        self.register_fetch(FetchDesc {
            name: "req.cook_names",
            out_type: SampleType::Str,
            func: cook_names_fetch,
        });

        let res_cook_cnt_fetch: FetchFn = |ctx, args| {
            let name = args.first();
            // T327: as the oracle's smp_fetch_cookie_cnt: each Set-Cookie value (split at
            // commas outside quotes, the Expires date included) holds one cookie.
            let count = get_all_res_headers(ctx, "set-cookie")
                .iter()
                .flat_map(|hdr| hdr_values(hdr))
                .filter(|seg| set_cookie_is(seg.as_bytes(), name.map_or(&b""[..], |n| n.as_bytes())))
                .count();
            let count = len_to_sint(count);
            Some(Sample::Sint(count))
        };
        // T326: res.cook_cnt registered once with a named FetchFn so the deprecated alias scook_cnt below shares it
        self.register_fetch(FetchDesc {
            name: "res.cook_cnt",
            out_type: SampleType::Sint,
            func: res_cook_cnt_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "scook_cnt",
            out_type: SampleType::Sint,
            func: res_cook_cnt_fetch,
        });

        // T326: res.cook_names
        self.register_fetch(FetchDesc {
            name: "res.cook_names",
            out_type: SampleType::Str,
            func: |ctx, args| {
                let delim = names_delim(args);
                // A Set-Cookie holds one cookie: the first pair `cookie_names` accepts.
                let mut names = String::new();
                for hdr in get_all_res_headers(ctx, "set-cookie") {
                    crate::cookie_names::append(&mut names, &hdr, false, &delim);
                }
                Some(Sample::Str(names))
            },
        });

        // T337: `smp_fetch_cookie_val`: `strl2ic` over the value `smp_fetch_cookie` gives.
        self.register_iterating(
            &["req.cook_val", "cook_val"],
            SampleType::Sint,
            |ctx, args| cookie_fetch(ctx, args, false, false).pop().map(strl2ic_sample),
            |ctx, args| cookie_fetch(ctx, args, false, true).into_iter().map(strl2ic_sample).collect(),
        );
        self.register_iterating(
            &["res.cook_val", "scook_val"],
            SampleType::Sint,
            |ctx, args| cookie_fetch(ctx, args, true, false).pop().map(strl2ic_sample),
            |ctx, args| cookie_fetch(ctx, args, true, true).into_iter().map(strl2ic_sample).collect(),
        );

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

        // T326: req.body_param, `smp_fetch_body_param`: a raw (not URL-decoded) parameter of the
        // request body, binary like HAProxy's (SMP_T_BIN), so a non-UTF-8 value keeps its bytes.
        self.register_fetch(FetchDesc {
            name: "req.body_param",
            out_type: SampleType::Bin,
            func: |ctx, args| {
                let owned;
                let body: &[u8] = match (ctx.req_body, ctx.htx_slice) {
                    (Some(b), _) => b,
                    (_, Some(h)) => {
                        owned = h.body_bytes();
                        &owned
                    }
                    _ => return None,
                };
                let name = args.first().map_or(&b""[..], |s| s.as_bytes());
                // HAProxy looks only at the flag's first character (`*area == 'i'`).
                let insensitive = args.get(1).is_some_and(|s| s.starts_with('i'));
                // `smp_fetch_body_param` is `smp_fetch_param` with `&` as the delimiter (T337).
                url_param_values(body, name, b'&', insensitive).first().map(|v| Sample::Bin(v.to_vec()))
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
                // T331: what a `capture-req` converter wrote since, which the slots do not hold yet.
                if let Some(v) = crate::capture_write::pending(false, idx) {
                    return Some(capture_sample(v));
                }
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
                // T331: what a `capture-res` converter wrote since, which the slots do not hold yet.
                if let Some(v) = crate::capture_write::pending(true, idx) {
                    return Some(capture_sample(v));
                }
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

        // T327: capture.req.uri is the path of the request target with its query, as the
        // oracle's `http_parse_path` finds it: no sample for `*`, an authority or an absolute
        // URI without a path.
        self.register_fetch(FetchDesc {
            name: "capture.req.uri",
            out_type: SampleType::Str,
            func: |ctx, _args| {
                let path = http_parse_path(get_context_uri(ctx)?, get_context_method(ctx) == Some("OPTIONS"))?;
                Some(Sample::Str(path.to_string()))
            },
        });

        // T327: capture.req/res.ver return the version WITH the "HTTP/" prefix (unlike req/res.ver)
        self.register_fetch(FetchDesc {
            name: "capture.req.ver",
            out_type: SampleType::Str,
            func: |ctx, _args| {
                let v = get_context_req_version(ctx).map(str::to_string)
                    .or_else(|| ctx.htx.and_then(|h| h.req_line()).map(|l| l.version.as_str().to_string()))?;
                Some(Sample::Str(v))
            },
        });

        self.register_fetch(FetchDesc {
            name: "capture.res.ver",
            out_type: SampleType::Str,
            func: |ctx, _args| {
                let v = get_context_res_version(ctx).map(str::to_string)
                    .or_else(|| ctx.htx.and_then(|h| h.res_line()).map(|l| l.version.as_str().to_string()))?;
                Some(Sample::Str(v))
            },
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
        // T326: process-wide fetches
        self.register_fetch(FetchDesc {
            name: "pid",
            out_type: SampleType::Sint,
            func: |_ctx, _args| Some(Sample::Sint(i64::from(std::process::id()))),
        });
        self.register_fetch(FetchDesc {
            name: "hostname",
            out_type: SampleType::Str,
            func: |_ctx, _args| {
                HOSTNAME
                    .get_or_init(|| std::fs::read_to_string("/proc/sys/kernel/hostname").ok().map(|s| s.trim().to_string()))
                    .clone()
                    .map(Sample::Str)
            },
        });
        self.register_fetch(FetchDesc {
            name: "nbproc",
            out_type: SampleType::Sint,
            func: |_ctx, _args| Some(Sample::Sint(1)),
        });
        self.register_fetch(FetchDesc {
            name: "proc",
            out_type: SampleType::Sint,
            func: |_ctx, _args| Some(Sample::Sint(1)),
        });
        self.register_fetch(FetchDesc {
            name: "thread",
            out_type: SampleType::Sint,
            func: |_ctx, _args| Some(Sample::Sint(THREAD_ID.with(|t| i64::try_from(t.get()).unwrap_or(i64::MAX)))),
        });
        self.register_fetch(FetchDesc {
            name: "stopping",
            out_type: SampleType::Bool,
            // Set by `Engine::begin_soft_stop`, the flag `when stopping` reads.
            func: |_ctx, _args| Some(Sample::Bool(STOPPING.load(std::sync::atomic::Ordering::Relaxed))),
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
        // T331: `srv_weight`, `srv_iweight`, `srv_uweight` ([`ServerState`]'s weights).
        self.register_fetch(FetchDesc {
            name: "srv_weight",
            out_type: SampleType::Sint,
            func: |ctx, args| server_fetch(ctx, args, |s| Sample::Sint(i64::from(s.weight))),
        });
        self.register_fetch(FetchDesc {
            name: "srv_iweight",
            out_type: SampleType::Sint,
            func: |ctx, args| server_fetch(ctx, args, |s| Sample::Sint(i64::from(s.iweight))),
        });
        self.register_fetch(FetchDesc {
            name: "srv_uweight",
            out_type: SampleType::Sint,
            func: |ctx, args| server_fetch(ctx, args, |s| Sample::Sint(i64::from(s.uweight))),
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
        // The ClientHello capture (`tune.ssl.capture-buffer-size`, `smp_fetch_ssl_fc_*_bin` and
        // friends, src/ssl_sample.c): no sample without one. The `(1)` argument runs the list
        // through `exclude_tls_grease` into a trash chunk (`tune.bufsize`, 16384).
        self.register_fetch(FetchDesc {
            name: "ssl_fc_cipherlist_bin",
            out_type: SampleType::Bin,
            func: |ctx, args| capture_list(ctx, args, ibex_tls::SslCapture::ciphersuite),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_cipherlist_hex",
            out_type: SampleType::Bin,
            // `dump_binary`: upper-case hex (`hextab`), declared BIN, so `,hex` doubles it.
            func: |ctx, args| {
                let list = capture_bytes(ctx, args, ibex_tls::SslCapture::ciphersuite)?;
                Some(Sample::Bin(hex_encode(&list).into_bytes()))
            },
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_cipherlist_str",
            out_type: SampleType::Str,
            // `smp_fetch_ssl_fc_cl_str`: each 2-byte id through `SSL_CIPHER_find` and
            // `SSL_CIPHER_get_name`, `UNKNOWN(%04x)` for a miss, comma-joined; a trailing odd
            // byte (a list cut by the capture size) is not looked at.
            func: |ctx, args| {
                let list = capture_bytes(ctx, args, ibex_tls::SslCapture::ciphersuite)?;
                let names: Vec<String> = list
                    .chunks_exact(2)
                    .map(|p| {
                        let id = u16::from_be_bytes([p[0], p[1]]);
                        ibex_tls::cipher_names::openssl_cipher_name_by_id(id)
                            .map_or_else(|| format!("UNKNOWN({id:04x})"), str::to_string)
                    })
                    .collect();
                Some(Sample::Str(names.join(",")))
            },
        });
        // Ibex-only (no HAProxy fetch of this name; see docs/differences.md): the JA4 TLS client
        // fingerprint of the captured ClientHello. It needs the capture (`tune.ssl.capture-buffer-size`
        // > 0) to exist, though it does not depend on the size.
        self.register_fetch(FetchDesc {
            name: "ssl_fc_ja4",
            out_type: SampleType::Str,
            func: |ctx, _args| {
                let parts = ctx.ssl_fc.capture?.ja4.as_ref()?;
                Some(Sample::Str(crate::ja4::ja4(parts)))
            },
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_cipherlist_xxh",
            out_type: SampleType::Sint,
            // `smp->data.u.sint = capture->xxh64`: the unsigned 64-bit hash as a signed value.
            func: |ctx, _args| ctx.ssl_fc.capture.map(|c| Sample::Sint(c.xxh64.cast_signed())),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_protocol_hello_id",
            out_type: SampleType::Sint,
            func: |ctx, _args| ctx.ssl_fc.capture.map(|c| Sample::Sint(i64::from(c.protocol_version))),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_extlist_bin",
            out_type: SampleType::Bin,
            func: |ctx, args| capture_list(ctx, args, ibex_tls::SslCapture::extensions),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_eclist_bin",
            out_type: SampleType::Bin,
            func: |ctx, args| capture_list(ctx, args, ibex_tls::SslCapture::ec),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_ecformats_bin",
            out_type: SampleType::Bin,
            func: |ctx, _args| ctx.ssl_fc.capture.map(|c| Sample::Bin(c.ec_formats().to_vec())),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_supported_versions_bin",
            out_type: SampleType::Bin,
            func: |ctx, args| capture_list(ctx, args, ibex_tls::SslCapture::supver),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_sigalgs_bin",
            out_type: SampleType::Bin,
            func: |ctx, args| capture_list(ctx, args, ibex_tls::SslCapture::sigalgs),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_alpn",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.ssl_fc.alpn.map(|v| Sample::Str(String::from_utf8_lossy(v).into_owned())),
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
        // The error fetches the `option httpslog` line reads. `fc_err` is 0 here: Ibex does not
        // keep the error code of a connection that failed. The `ssl_*` ones have a value on a
        // TLS connection only, and no certificate error is recorded, so it is 0.
        self.register_fetch(FetchDesc {
            name: "fc_err",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(ctx.conn_err.map_or(0, |e| e.code))),
        });
        self.register_fetch(FetchDesc {
            name: "fc_err_str",
            out_type: SampleType::Str,
            func: |ctx, _args| Some(Sample::Str(ctx.conn_err.map_or("Success", |e| e.text).to_string())),
        });
        self.register_fetch(FetchDesc {
            name: "fc_err_name",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.conn_err.map(|e| Sample::Str(e.name.to_string())),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_err_str",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.conn_err.and_then(|e| e.ssl_text).map(|t| Sample::Str(t.to_string())),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_err",
            out_type: SampleType::Sint,
            func: |ctx, _args| match ctx.conn_err {
                Some(e) if e.tls => Some(Sample::Sint(e.ssl_code)),
                _ => ctx.ssl_fc.used.then_some(Sample::Sint(0)),
            },
        });
        for name in ["ssl_c_err", "ssl_c_ca_err"] {
            self.register_fetch(FetchDesc {
                name,
                out_type: SampleType::Sint,
                func: |ctx, _args| ctx.ssl_fc.used.then_some(Sample::Sint(0)),
            });
        }
        self.register_fetch(FetchDesc {
            name: "ssl_fc_is_resumed",
            out_type: SampleType::Bool,
            func: |ctx, _args| Some(Sample::Bool(ctx.ssl_fc.used && ctx.ssl_fc.resumed)),
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
                let decoded = ibex_regex::bytetext::bytes_to_text(&bytes);
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
                    Some(Sample::Bin(ibex_regex::bytetext::text_to_bytes(s).into_owned()))
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
            // `smp_fetch_var`: the stored sample, of the type it was set with (T364); the
            // default, when the variable is not set, is a string.
            out_type: SampleType::Str,
            func: |ctx, args| {
                let var_name = args.first()?;
                let stored = if var_name.starts_with("proc.") {
                    crate::vars::get(var_name)
                } else {
                    ctx.vars.and_then(|m| m.get(var_name).cloned()).or_else(|| crate::vars::get(var_name))
                };
                stored.or_else(|| args.get(1).cloned().map(Sample::Str))
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
                    "s" => Some(Sample::Sint(secs)),
                    "ms" => Some(Sample::Sint(secs * 1000 + i64::from(ms))),
                    "us" => Some(Sample::Sint((secs * 1000 + i64::from(ms)) * 1000)),
                    _ => None,
                }
            },
        });
        // T331: `request_date[(<unit>)]`: when the first byte of the HTTP request was received.
        // Millisecond resolution, as `accept_date`: `us` is the milliseconds times 1000.
        self.register_fetch(FetchDesc {
            name: "request_date",
            out_type: SampleType::Sint,
            func: |ctx, args| {
                let (secs, ms) = ctx.request_date?;
                match args.first().map_or("s", String::as_str) {
                    "s" => Some(Sample::Sint(secs)),
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
            // The microsecond part of the date (`date.tv_usec`), 0..999999.
            func: |_ctx, _args| {
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                Some(Sample::Sint(i64::from(now.subsec_micros())))
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
                // The low 32 bits of the clock: the truncation is the point.
                #[allow(clippy::cast_possible_truncation)]
                let seed_u32 = seed as u32;
                let r = i64::from(full_hash(seed_u32) % max.max(1));
                Some(Sample::Sint(r))
            },
        });
        // `dump_all_vars([<scope>][,<prefix>][,<delimiter>])`: the variables of <scope> as `name=value`
        // joined by <delimiter> (default ", "), only those whose name after the scope starts with <prefix>.
        // Without <scope> it visits sess, txn, req, res and proc in that order, as configuration.txt says;
        // HAProxy 3.5-dev8's binary dumps only the current context's scope (txn in a stream) instead, which
        // has been reported upstream: Ibex follows the documentation here. Each value prints by its stored
        // type, as HAProxy does (T364 S4). Within a scope the names are sorted; HAProxy's order is its hash tree's.
        // T329
        self.register_fetch(FetchDesc {
            name: "dump_all_vars",
            out_type: SampleType::Str,
            func: |ctx, args| {
                let scopes: &[&str] = match args.first().map(String::as_str).filter(|s| !s.is_empty()) {
                    None => &DUMP_VAR_SCOPES,
                    Some(s) => std::slice::from_ref(DUMP_VAR_SCOPES.iter().find(|&&k| k == s)?),
                };
                let prefix = args.get(1).map_or("", String::as_str);
                let delimiter = args.get(2).map_or(", ", String::as_str);
                let mut stream: Vec<(String, Sample)> = ctx.vars.map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default();
                crate::vars::with_current(|m| {
                    for (k, val) in m {
                        if !stream.iter().any(|(n, _)| n == k) {
                            stream.push((k.clone(), val.clone()));
                        }
                    }
                });
                let process: Vec<(String, Sample)> = crate::vars::proc_snapshot();
                let mut out = Vec::new();
                for scope in scopes {
                    let vars = if *scope == "proc" { &process } else { &stream };
                    let mut found: Vec<&(String, Sample)> = vars
                        .iter()
                        .filter(|(k, _)| k.strip_prefix(scope).and_then(|r| r.strip_prefix('.')).is_some_and(|r| r.starts_with(prefix)))
                        .collect();
                    found.sort_by(|a, b| a.0.cmp(&b.0));
                    out.extend(found.into_iter().map(|(k, v)| format!("{k}={}", dump_var_value(v))));
                }
                Some(Sample::Str(out.join(delimiter)))
            },
        });
        // T331: `tgroup`: the thread group, numbered from 0 (`tgid - 1`); always 0, Ibex
        // refuses `thread-groups` over 1.
        self.register_fetch(FetchDesc {
            name: "tgroup",
            out_type: SampleType::Sint,
            func: |_ctx, _args| Some(Sample::Sint(0)),
        });
        // T331: `master_id`: the master process's id in master-worker mode, none otherwise.
        // Ibex's `-W` does not assign one yet (`mworker_prepare_master`: `HAPROXY_MASTER_ID`
        // when it is a valid GUID, else a UUID v7), so it has no value: a known gap with
        // `HAProxy` under `-W`. The environment is not read, as `HAProxy` does not without a master.
        self.register_fetch(FetchDesc {
            name: "master_id",
            out_type: SampleType::Str,
            func: |_ctx, _args| None,
        });
        // T386: the per-stream scheduler counters and the CPU usage. `HAProxy` gives no value
        // without a stream (`smp->strm`). Ibex keeps no per-stream task counters: the time
        // counters are 0, as in `HAProxy` with `profiling.tasks` off (the default), and
        // `cpu_calls` is 1, the call that evaluates the fetch (known gap: `HAProxy` counts
        // every wakeup of the stream).
        self.register_fetch(FetchDesc {
            name: "cpu_calls",
            out_type: SampleType::Sint,
            func: |ctx, _args| has_stream(ctx).then_some(Sample::Sint(1)),
        });
        for name in ["cpu_ns_tot", "cpu_ns_avg", "lat_ns_tot", "lat_ns_avg"] {
            self.register_fetch(FetchDesc { name, out_type: SampleType::Sint, func: |ctx, _args| has_stream(ctx).then_some(Sample::Sint(0)) });
        }
        for name in ["cpu_usage_proc", "cpu_usage_thr", "cpu_usage_grp"] {
            self.register_fetch(FetchDesc { name, out_type: SampleType::Sint, func: |_ctx, _args| Some(Sample::Sint(cpu_usage_pct())) });
        }
        // T331: `quic_enabled`: always 0, Ibex has no QUIC.
        self.register_fetch(FetchDesc {
            name: "quic_enabled",
            out_type: SampleType::Bool,
            func: |_ctx, _args| Some(Sample::Bool(false)),
        });
    }

    /// T330: the TCP header length in bytes when `b` holds a complete TCP header (at least 20
    /// bytes, and as many as its data offset says), otherwise `None` (`tcp_fullhdr_length()`
    /// in `src/net_helper.c` returning 0, which makes every tcp.options converter give no sample).
    fn tcp_fullhdr_length(b: &[u8]) -> Option<usize> {
        if b.len() < 20 {
            return None;
        }
        let len = usize::from(b[12] >> 4) * 4;
        (len >= 20 && b.len() >= len).then_some(len)
    }

    /// T330: the offset in the TCP header `b` where option kind `opt` is first seen, if any
    /// (`tcp_fullhdr_find_opt()` in `src/net_helper.c`). The walk stops at END, at an option whose length
    /// byte is missing or under 2; an option counts only when its declared length fits the header.
    fn tcp_fullhdr_find_opt(b: &[u8], opt: u8) -> Option<usize> {
        let len = Self::tcp_fullhdr_length(b)?;
        let mut next = 20;
        while next < len {
            let curr = next;
            match b[curr] {
                0 => break,
                1 => next += 1,
                _ if next + 1 < len && b[next + 1] > 1 => next += usize::from(b[next + 1]),
                _ => break,
            }
            if b[curr] == opt && next <= len {
                return Some(curr);
            }
        }
        None
    }

    /// T330: the big-endian value of the `n` bytes at `ofs` in `b`. The reference reads them whatever the
    /// option's declared length; past the end of the input it would read out of bounds, here it
    /// gives 0.
    fn tcp_read_be(b: &[u8], ofs: usize, n: usize) -> i64 {
        b.get(ofs..ofs + n).map_or(0, |d| d.iter().fold(0i64, |v, &x| v << 8 | i64::from(x)))
    }

    #[allow(clippy::too_many_lines)]
    fn register_builtin_converters(&mut self) {
                
        // --- 1. String Transforms ---
        self.register_converter(ConvDesc {
            name: "lower",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Str(s) => Some(Sample::Str(s.to_ascii_lowercase())),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "upper",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                // sample_conv_str2upper: ASCII only; bytetext escapes pass unchanged.
                Sample::Str(s) => Some(Sample::Str(s.to_ascii_uppercase())),
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
                    Sample::Str(s) => ibex_regex::bytetext::text_len(s),
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

                    // `alloc_best_trash_chunk`: parts larger than the trash pool (bufsize
                    // plus the 32-byte buffer header) are no sample; the result is cut at
                    // bufsize - 1.
                    let trash = trash_size();
                    if s.len() + start.len() + var_val.len() + end.len() > trash + 32 {
                        return None;
                    }
                    s.push_str(start);
                    s.push_str(&var_val);
                    s.push_str(end);
                    truncate_to_trash(&mut s);
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
                // The argument is a variable (refused otherwise at load, T341); when it is not
                // set there is no sample (T327: an empty field in a log-format).
                let target_val = crate::vars::var_arg_str(args.first()?)?;
                let Sample::Str(s) = smp else { return None };
                // sample_conv_strcmp: strncmp() on the common length gives the difference of
                // the first differing (unsigned) bytes; equal prefixes give -1 / 0 / 1 by length.
                let a = ibex_regex::bytetext::text_to_bytes(&s);
                let b = ibex_regex::bytetext::text_to_bytes(&target_val);
                let res = match a.iter().zip(b.iter()).find(|(x, y)| x != y) {
                    Some((x, y)) => i64::from(*x) - i64::from(*y),
                    None => match a.len().cmp(&b.len()) {
                        std::cmp::Ordering::Less => -1,
                        std::cmp::Ordering::Equal => 0,
                        std::cmp::Ordering::Greater => 1,
                    },
                };
                Some(Sample::Sint(res))
            },
        });

        self.register_converter(ConvDesc {
            name: "field",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                // T359
                let idx_str = args.first()?;
                let seps_str = args.get(1).map_or(" ", |s| s.as_str());
                let idx: i64 = idx_str.parse().ok()?;
                if idx == 0 {
                    return None;
                }
                let count = args.get(2).map_or(1i32, |c| parse_count(c));
                let Sample::Str(s) = smp else { return None };
                let bytes = s.as_bytes();
                let len = bytes.len();
                let seps = seps_str.as_bytes();
                if idx < 0 {
                    let mut field = -1i64;
                    let mut start = len;
                    let mut end = len;
                    let mut cnt = count;
                    let mut found = false;
                    while start > 0 {
                        let pos = start - 1;
                        let Some(&b) = bytes.get(pos) else { break };
                        if seps.contains(&b) {
                            if field == idx {
                                if cnt == 1 {
                                    found = true;
                                    break;
                                } else if cnt > 1 {
                                    cnt -= 1;
                                }
                            } else {
                                end = pos;
                                field -= 1;
                            }
                        }
                        start -= 1;
                    }
                    if !found && field != idx {
                        return None;
                    }
                    let slice = s.get(start..end)?;
                    Some(Sample::Str(slice.to_string()))
                } else {
                    let mut field = 1i64;
                    let mut start = 0usize;
                    let mut end = 0usize;
                    let mut cnt = count;
                    let mut found = false;
                    while end < len {
                        let Some(&b) = bytes.get(end) else { break };
                        if seps.contains(&b) {
                            if field == idx {
                                if cnt == 1 {
                                    found = true;
                                    break;
                                } else if cnt > 1 {
                                    cnt -= 1;
                                }
                            } else {
                                start = end + 1;
                                field += 1;
                            }
                        }
                        end += 1;
                    }
                    if !found && field != idx {
                        return None;
                    }
                    let slice = s.get(start..end)?;
                    Some(Sample::Str(slice.to_string()))
                }
            },
        });

        self.register_converter(ConvDesc {
            name: "word",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                // T359
                let idx_str = args.first()?;
                let seps_str = args.get(1).map_or(" ", |s| s.as_str());
                let idx: i64 = idx_str.parse().ok()?;
                if idx == 0 {
                    return None;
                }
                let count = args.get(2).map_or(1i32, |c| parse_count(c));
                let Sample::Str(s) = smp else { return None };
                let bytes = s.as_bytes();
                let len = bytes.len();
                let seps = seps_str.as_bytes();
                if idx < 0 {
                    let mut word_num = 0i64;
                    let mut in_word = false;
                    let mut start = len;
                    let mut end = len;
                    let mut cnt = count;
                    let mut found = false;
                    while start > 0 {
                        let pos = start - 1;
                        let Some(&b) = bytes.get(pos) else { break };
                        let is_sep = seps.contains(&b);
                        if !in_word {
                            if !is_sep {
                                if word_num != idx {
                                    word_num -= 1;
                                    end = start;
                                }
                                in_word = true;
                            }
                        } else if is_sep {
                            if word_num == idx {
                                if cnt == 1 {
                                    found = true;
                                    break;
                                } else if cnt > 1 {
                                    cnt -= 1;
                                }
                            }
                            in_word = false;
                        }
                        start -= 1;
                    }
                    if !found && word_num != idx {
                        return None;
                    }
                    let slice = s.get(start..end)?;
                    Some(Sample::Str(slice.to_string()))
                } else {
                    let mut word_num = 0i64;
                    let mut in_word = false;
                    let mut start = 0usize;
                    let mut end = 0usize;
                    let mut cnt = count;
                    let mut found = false;
                    while end < len {
                        let Some(&b) = bytes.get(end) else { break };
                        let is_sep = seps.contains(&b);
                        if !in_word {
                            if !is_sep {
                                if word_num != idx {
                                    word_num += 1;
                                    start = end;
                                }
                                in_word = true;
                            }
                        } else if is_sep {
                            if word_num == idx {
                                if cnt == 1 {
                                    found = true;
                                    break;
                                } else if cnt > 1 {
                                    cnt -= 1;
                                }
                            }
                            in_word = false;
                        }
                        end += 1;
                    }
                    if !found && word_num != idx {
                        return None;
                    }
                    let slice = s.get(start..end)?;
                    Some(Sample::Str(slice.to_string()))
                }
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
                    // `%00` "cannot be represented in a string" (`url_decode`, `src/tools.c`).
                    if bad || s.contains("%00") {
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
                let n = resolve_int_arg(args.first().map_or("", String::as_str))?;
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
                let n = resolve_int_arg(args.first().map_or("", String::as_str))?;
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
                let factor = resolve_int_arg(args.first().map_or("", String::as_str))?;
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
                let divisor = resolve_int_arg(args.first().map_or("", String::as_str))?;
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
                let divisor = resolve_int_arg(args.first().map_or("", String::as_str))?;
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
                let mask = resolve_int_arg(args.first().map_or("", String::as_str))?;
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
                let mask = resolve_int_arg(args.first().map_or("", String::as_str))?;
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
                let mask = resolve_int_arg(args.first().map_or("", String::as_str))?;
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
            out_type: TypeSpec::Any, // SMP_T_ANY in HAProxy: what follows takes any type (T341)
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

        // T331: `capture-req(<id>)` and `capture-res(<id>)` store their input, as a string, in the
        // request's or response's capture slot <id> (cut at its length) and return it as it is.
        // A slot that does not exist captures nothing (`sample_conv_req_capture`). The write
        // is the engine's to put in the slot (`capture_write`).
        for (name, res) in [("capture-req", false), ("capture-res", true)] {
            self.register_ctx_converter(CtxConvDesc {
                name,
                in_type: TypeSpec::Exact(SampleType::Str),
                out_type: TypeSpec::Exact(SampleType::Str),
                func: if res { |_, smp, args| capture_conv(true, smp, args) } else { |_, smp, args| capture_conv(false, smp, args) },
            });
        }

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

        // T330: protobuf and ungrpc read a protocol buffers field of a binary sample.
        self.register_converter(ConvDesc {
            name: "protobuf",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Any,
            func: |smp, args| match smp {
                Sample::Bin(b) => pb_convert(&b, args, false),
                _ => None,
            },
        });
        self.register_converter(ConvDesc {
            name: "ungrpc",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Any,
            func: |smp, args| match smp {
                Sample::Bin(b) => pb_convert(&b, args, true),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "mqtt_is_valid",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bool),
            func: |smp, _args| match smp {
                Sample::Bin(b) => mqtt_is_valid(&b),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "mqtt_field_value",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Any,
            func: |smp, args| match smp {
                Sample::Bin(b) => mqtt_field_value(&b, args),
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
            // T343: `SMP_T_ADDR`, as `HAProxy` declares it; an ACL on it matches networks by
            // default (it took the string match of a string input when this was `Same`).
            out_type: TypeSpec::Addr,
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
                    if args.first().and_then(|s| crate::cast::parse_sint_arg(s)).unwrap_or(0) != 0 {
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
                    if args.first().and_then(|s| crate::cast::parse_sint_arg(s)).unwrap_or(0) != 0 {
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
                    if args.first().and_then(|s| crate::cast::parse_sint_arg(s)).unwrap_or(0) != 0 {
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
                    if args.first().and_then(|s| crate::cast::parse_sint_arg(s)).unwrap_or(0) != 0 {
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
                    if args.first().and_then(|s| crate::cast::parse_sint_arg(s)).unwrap_or(0) != 0 {
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
                // `unsigned int seed = arg_p->data.sint`: the low 32 bits.
                let [s0, s1, s2, s3, ..] = args.first().and_then(|s| crate::cast::parse_sint_arg(s)).unwrap_or(0).to_le_bytes();
                let seed = u32::from_le_bytes([s0, s1, s2, s3]);
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
                // `(unsigned long long int)arg_p->data.sint`.
                let seed = u64::from_ne_bytes(args.first().and_then(|s| crate::cast::parse_sint_arg(s)).unwrap_or(0).to_ne_bytes());
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
                // `(unsigned long long int)arg_p->data.sint`, then `XXH3_64bits_withSeed`.
                let seed = u64::from_ne_bytes(args.first().and_then(|s| crate::cast::parse_sint_arg(s)).unwrap_or(0).to_ne_bytes());
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
                // T343: the algorithm is checked at load (`check_crypto_digest`); a name
                // `OpenSSL` knows by an alias (`SHA-1`, `sha2-256`) is that digest, not sha256.
                let f = digest_by_name(args.first()?)?;
                let Sample::Bin(b) = smp else { return None };
                Some(Sample::Bin(f(&b)))
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
                    // A byte that is not UTF-8 is held as an escape character (T286), and
                    // U+FFFD is the replacement character itself.
                    let invalid = |c: char| c == '\u{FFFD}' || ibex_regex::bytetext::unescape_char(c).is_some();
                    if mode == "utf8" && s.chars().any(invalid) {
                        return Some(Sample::Str(String::new()));
                    }
                    if mode != "utf8" && mode != "utf8s" {
                        // IT_ASCII (default): every byte on its own; a byte that is not
                        // printable ASCII (control, 0x7f, >= 0x80) becomes \u00XX.
                        let mut out = String::new();
                        for b in ibex_regex::bytetext::text_to_bytes(&s).iter() {
                            match *b {
                                b'"' => out.push_str("\\\""),
                                b'\\' => out.push_str("\\\\"),
                                b'/' => out.push_str("\\/"),
                                8 => out.push_str("\\b"),
                                12 => out.push_str("\\f"),
                                b'\r' => out.push_str("\\r"),
                                b'\n' => out.push_str("\\n"),
                                b'\t' => out.push_str("\\t"),
                                0x20..=0x7e => out.push(char::from(*b)),
                                _ => {
                                    use std::fmt::Write;
                                    let _ = write!(out, "\\u{:04x}", *b);
                                }
                            }
                        }
                        return Some(Sample::Str(out));
                    }
                    let s = if mode == "utf8s" {
                        s.chars().filter(|c| !invalid(*c)).collect()
                    } else {
                        s
                    };
                    Some(Sample::Str(json_escape(&s)))
                }
                _ => None,
            },
        });
        
        /// C's `printf("%g")`: six significant digits, trailing zeros dropped, an exponent
        /// below -4 or from 6 up.
        fn format_g(v: f64) -> String {
            // serde_json numbers are finite, so there is no inf or nan to print.
            let e = format!("{v:.5e}");
            let (mant, exp) = e.split_once('e').unwrap_or((&e, "0"));
            let exp: i32 = exp.parse().unwrap_or(0);
            let trim = |t: String| if t.contains('.') { t.trim_end_matches('0').trim_end_matches('.').to_string() } else { t };
            if (-4..6).contains(&exp) {
                trim(format!("{v:.*}", usize::try_from(5 - exp).unwrap_or(0)))
            } else {
                format!("{}e{}{:02}", trim(mant.to_string()), if exp < 0 { '-' } else { '+' }, exp.abs())
            }
        }

        let json_query_conv: ConvFn = |smp, args| {
            let path = args.first()?;
            let int_mode = args.get(1).is_some_and(|s| s == "int");
            let Sample::Str(s) = smp else { return None };
            // T363: return HAProxy types for json_query
            let Ok(val) = serde_json::from_str::<serde_json::Value>(&s) else { return None };
            // mjson's JSONPath (src/mjson.c): `$`, then `.key` (a backslash takes the next
            // character literally, so `\.` is a dot in a key) and `[index]`; anything
            // else, including a path not starting with `$`, finds nothing.
            let mut current = &val;
            let mut chars = path.strip_prefix('$')?.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '[' {
                    let idx: String = chars.by_ref().take_while(|&c| c != ']').collect();
                    current = current.get(idx.parse::<usize>().ok()?)?;
                } else if c == '.' {
                    let mut key = String::new();
                    while let Some(&k) = chars.peek() {
                        if k == '.' || k == '[' {
                            break;
                        }
                        chars.next();
                        key.push(if k == '\\' { chars.next().unwrap_or(k) } else { k });
                    }
                    current = current.get(&key)?;
                } else {
                    return None;
                }
            }
            // Map value to Sample according to HAProxy semantics
            match current {
                serde_json::Value::String(s) => Some(Sample::Str(s.clone())),
                serde_json::Value::Bool(b) => Some(Sample::Bool(*b)),
                serde_json::Value::Number(n) => {
                    // mjson reads a double; `int` is strtoll of the text, kept to +-(2^53-1).
                    // A float is truncated here (HAProxy reads the integer prefix of its text).
                    const MAX: i64 = (1 << 53) - 1;
                    if int_mode {
                        let v = n.as_i64().or_else(|| n.as_f64().map(|f| f.trunc() as i64))?;
                        (-MAX..=MAX).contains(&v).then_some(Sample::Sint(v))
                    } else {
                        Some(Sample::Str(format_g(n.as_f64()?)))
                    }
                }
                serde_json::Value::Array(_) => {
                    serde_json::to_string(current).ok().map(Sample::Str)
                }
                serde_json::Value::Object(_) | serde_json::Value::Null => None,
            }
        };

        self.register_converter(ConvDesc {
            name: "json_query",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Any,
            func: json_query_conv,
        });

        // --- T328: JWT Query Converters ---
        // jwt_header_query([<json_path>[,<output_type>]])
        // Decodes the JWT header (first base64url part) and optionally applies json_query.
        self.register_converter(ConvDesc {
            name: "jwt_header_query",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Any,
            func: |smp, args| {
                let Sample::Str(s) = smp else { return None };
                let parts: Vec<&str> = s.splitn(3, '.').collect();
                let header_b64 = parts.first()?;
                let decoded = base64_decode(header_b64, true, false)?;
                let decoded_str = std::str::from_utf8(&decoded).ok()?;
                if let Some(path) = args.first() {
                    json_extract(decoded_str, path).map(Sample::Str)
                } else {
                    Some(Sample::Str(decoded_str.to_string()))
                }
            },
        });

        // jwt_payload_query([<json_path>[,<output_type>]])
        // Decodes the JWT payload (second base64url part) and optionally applies json_query.
        self.register_converter(ConvDesc {
            name: "jwt_payload_query",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Any,
            func: |smp, args| {
                let Sample::Str(s) = smp else { return None };
                let parts: Vec<&str> = s.splitn(3, '.').collect();
                let payload_b64 = parts.get(1)?;
                let decoded = base64_decode(payload_b64, true, false)?;
                let decoded_str = std::str::from_utf8(&decoded).ok()?;
                if let Some(path) = args.first() {
                    json_extract(decoded_str, path).map(Sample::Str)
                } else {
                    Some(Sample::Str(decoded_str.to_string()))
                }
            },
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
            out_type: TypeSpec::Any, // SMP_T_ANY in HAProxy: what follows takes any type (T341)
            func: |smp, args| {
                // `set-var` always has its variable name: the load refuses `set-var()`. The
                // variable keeps the sample's type (T364).
                crate::vars::set_cond(&args.join(","), smp.clone());
                Some(smp)
            },
        });

        self.register_converter(ConvDesc {
            name: "unset-var",
            in_type: TypeSpec::Any,
            out_type: TypeSpec::Any, // SMP_T_ANY in HAProxy: what follows takes any type (T341)
            func: |smp, args| {
                // A `proc.` variable is the process's, not the stream's (T156).
                if let Some(var_name) = args.first() {
                    crate::vars::unset(var_name);
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

        // T330: eth.* converters on a binary Ethernet frame (net_helper.c). Layout: dst MAC (6),
        // src MAC (6), any number of 802.1Q tags (0x8100 + TCI), EtherType (2), payload.

        self.register_converter(ConvDesc {
            name: "eth.data",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Bin(b.get(eth_hdr_len(&b)?..)?.to_vec())),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "eth.dst",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Bin(b.get(..6)?.to_vec())),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "eth.hdr",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Bin(b.get(..eth_hdr_len(&b)?)?.to_vec())),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "eth.proto",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    let o = eth_hdr_len(&b)?;
                    Some(Sample::Sint(i64::from(u16::from_be_bytes([*b.get(o - 2)?, *b.get(o - 1)?]))))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "eth.src",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Bin(b.get(6..12)?.to_vec())),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "eth.vlan",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                // The last VLAN id seen; id 0 is no VLAN (sample_conv_eth_vlan's `return !!vlan`).
                Sample::Bin(b) => {
                    let mut vlan = 0u16;
                    let mut idx = 12usize;
                    while idx + 2 < b.len() {
                        if b.get(idx..idx + 2)? != [0x81, 0x00] {
                            return (vlan != 0).then_some(Sample::Sint(i64::from(vlan)));
                        }
                        if idx + 4 > b.len() {
                            break;
                        }
                        vlan = u16::from_be_bytes([*b.get(idx + 2)?, *b.get(idx + 3)?]) & 0x0fff;
                        idx += 4;
                    }
                    None
                }
                _ => None,
            },
        });

        // T330: ip.src - source address from IP packet
        self.register_converter(ConvDesc {
            name: "ip.src",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Addr,
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    let ver = b.first()? >> 4;
                    match ver {
                        4 => {
                            if b.len() < 20 {
                                return None;
                            }
                            let octets: [u8; 4] = b[12..16].try_into().ok()?;
                            Some(Sample::Ipv4(Ipv4Addr::from(octets)))
                        }
                        6 => {
                            if b.len() < 40 {
                                return None;
                            }
                            let octets: [u8; 16] = b[8..24].try_into().ok()?;
                            Some(Sample::Ipv6(Ipv6Addr::from(octets)))
                        }
                        _ => None,
                    }
                }
                _ => None,
            },
        });

        // T330: ip.dst - destination address from IP packet
        self.register_converter(ConvDesc {
            name: "ip.dst",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Addr,
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    let ver = b.first()? >> 4;
                    match ver {
                        4 => {
                            if b.len() < 20 {
                                return None;
                            }
                            let octets: [u8; 4] = b[16..20].try_into().ok()?;
                            Some(Sample::Ipv4(Ipv4Addr::from(octets)))
                        }
                        6 => {
                            if b.len() < 40 {
                                return None;
                            }
                            let octets: [u8; 16] = b[24..40].try_into().ok()?;
                            Some(Sample::Ipv6(Ipv6Addr::from(octets)))
                        }
                        _ => None,
                    }
                }
                _ => None,
            },
        });

        // T330: ip.hdr - IP header bytes (IPv4: IHL*4; IPv6: 40 + extension headers)
        self.register_converter(ConvDesc {
            name: "ip.hdr",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Bin(b.get(..ip_header_length(&b)?)?.to_vec())),
                _ => None,
            },
        });

        // T330: ip.data - payload after IP header (empty for a header-only packet)
        self.register_converter(ConvDesc {
            name: "ip.data",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Bin(b.get(ip_header_length(&b)?..)?.to_vec())),
                _ => None,
            },
        });

        // T330: tcp.options.* (src/net_helper.c). An incomplete TCP header gives no sample.
        self.register_converter(ConvDesc {
            name: "tcp.options.mss",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    Self::tcp_fullhdr_length(&b)?;
                    let v = Self::tcp_fullhdr_find_opt(&b, 2).map_or(0, |ofs| Self::tcp_read_be(&b, ofs + 2, 2));
                    Some(Sample::Sint(v))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "tcp.options.sack",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    Self::tcp_fullhdr_length(&b)?;
                    Some(Sample::Sint(i64::from(Self::tcp_fullhdr_find_opt(&b, 4).is_some())))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "tcp.options.tsopt",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    Self::tcp_fullhdr_length(&b)?;
                    Some(Sample::Sint(i64::from(Self::tcp_fullhdr_find_opt(&b, 8).is_some())))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "tcp.options.tsval",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    Self::tcp_fullhdr_length(&b)?;
                    let v = Self::tcp_fullhdr_find_opt(&b, 8).map_or(0, |ofs| Self::tcp_read_be(&b, ofs + 2, 4));
                    Some(Sample::Sint(v))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "tcp.options.wscale",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    Self::tcp_fullhdr_length(&b)?;
                    let v = Self::tcp_fullhdr_find_opt(&b, 3).map_or(0, |ofs| Self::tcp_read_be(&b, ofs + 2, 1));
                    Some(Sample::Sint(v))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "tcp.options.wsopt",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    Self::tcp_fullhdr_length(&b)?;
                    Some(Sample::Sint(i64::from(Self::tcp_fullhdr_find_opt(&b, 3).is_some())))
                }
                _ => None,
            },
        });

        // One byte per option kind, a truncated or overrunning last option included
        // (sample_conv_tcp_options_list pushes the kind before it checks the length byte).
        self.register_converter(ConvDesc {
            name: "tcp.options_list",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    let len = Self::tcp_fullhdr_length(&b)?;
                    let mut out = Vec::new();
                    let mut ofs = 20;
                    while ofs < len {
                        let kind = b[ofs];
                        if kind == 0 {
                            break;
                        }
                        out.push(kind);
                        if kind == 1 {
                            ofs += 1;
                        } else if ofs + 1 < len && b[ofs + 1] > 1 {
                            ofs += usize::from(b[ofs + 1]);
                        } else {
                            break;
                        }
                    }
                    Some(Sample::Bin(out))
                }
                _ => None,
            },
        });
        // T330: ip.fp(<mode>), a port of sample_conv_ip_fp() in src/net_helper.c. Every field is
        // read through a bounds check: what is missing gives no sample, never an index panic.
        self.register_converter(ConvDesc {
            name: "ip.fp",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, args| match smp {
                Sample::Bin(b) => Self::ip_fp(&b, args).map(Sample::Bin),
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

        // `tcp.src`, `tcp.dst`, `tcp.seq`, `tcp.win`, `tcp.flags`: extract TCP header fields
        // from a binary sample. The input is a binary TCP segment: source port (2 bytes),
        // destination port (2), sequence number (4), ack number (4), data offset (high nibble)
        // + flags, window (2), ... all big-endian. Returns `None` when the input is shorter
        // than 20 bytes. Label T330.
        self.register_converter(ConvDesc {
            name: "tcp.src",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    if b.len() < 20 {
                        return None;
                    }
                    let src = i64::from(u16::from_be_bytes([b[0], b[1]]));
                    Some(Sample::Sint(src))
                }
                _ => None,
            },
        });
        self.register_converter(ConvDesc {
            name: "tcp.dst",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    if b.len() < 20 {
                        return None;
                    }
                    let dst = i64::from(u16::from_be_bytes([b[2], b[3]]));
                    Some(Sample::Sint(dst))
                }
                _ => None,
            },
        });
        self.register_converter(ConvDesc {
            name: "tcp.seq",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    if b.len() < 20 {
                        return None;
                    }
                    let seq = i64::from(u32::from_be_bytes([b[4], b[5], b[6], b[7]]));
                    Some(Sample::Sint(seq))
                }
                _ => None,
            },
        });
        self.register_converter(ConvDesc {
            name: "tcp.win",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    if b.len() < 20 {
                        return None;
                    }
                    let win = i64::from(u16::from_be_bytes([b[14], b[15]]));
                    Some(Sample::Sint(win))
                }
                _ => None,
            },
        });
        self.register_converter(ConvDesc {
            name: "tcp.flags",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    if b.len() < 20 {
                        return None;
                    }
                    // TCP flags are in byte 13 (lower 6 bits of the data offset+flags field)
                    let flags = i64::from(b[13]);
                    Some(Sample::Sint(flags))
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
                    // `sample_conv_var2smp_str`: cast to `str` from the variable's type.
                    crate::vars::var_arg_str(key_arg)?
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
        // `jwt_verify(<alg>,<key>)`: T331. Only the HMAC algorithms are verified. As in HAProxy the
        // <alg> argument alone selects the algorithm (the token's own "alg" is not compared), names
        // are case sensitive, and the result is 1, 0 or a negative code (-1 unknown algorithm,
        // -2 unmanaged algorithm, -3 invalid token).
        self.register_converter(ConvDesc {
            name: "jwt_verify",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| {
                let token = match smp {
                    Sample::Str(v) => v,
                    Sample::Bin(b) => String::from_utf8_lossy(&b).into_owned(),
                    _ => return None,
                };
                // As `chunk_printf("%.*s")` makes them in HAProxy: cut at the first NUL, and an
                // empty one is no sample. The argument is taken as written, spaces included.
                let resolve = |arg: &str| -> Option<String> {
                    let mut v = if hmac_key_is_var(arg) {
                        crate::vars::var_arg_str(arg)
                    } else {
                        Some(arg.to_string())
                    }?;
                    v.truncate(v.find('\0').unwrap_or(v.len()));
                    (!v.is_empty()).then_some(v)
                };
                let alg = resolve(args.first()?)?;
                let key = resolve(args.get(1)?)?;
                // jwt_verify(): the algorithm first (-1 unknown, -2 "none" without
                // jwt.allow_none_alg), then the token (-3), and only then the key (-5 for a public
                // key, which Ibex never loads).
                let digest_name = match alg.as_str() {
                    "HS256" => Some("sha256"),
                    "HS384" => Some("sha384"),
                    "HS512" => Some("sha512"),
                    "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512" | "PS256" | "PS384" | "PS512" => None,
                    "none" => return Some(Sample::Sint(-2)),
                    _ => return Some(Sample::Sint(-1)),
                };
                let mut parts = token.split('.');
                let (Some(jose), Some(claims), Some(sig), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
                    return Some(Sample::Sint(-3));
                };
                // HAProxy's base64url table maps '=' to the same value as '_', and nothing else is skipped.
                let sig = sig.replace('=', "_");
                let sig_ok = !sig.is_empty() && sig.len() % 4 != 1 && sig.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
                let Some(sig_bytes) = base64_decode(&sig, true, false).filter(|_| sig_ok) else {
                    return Some(Sample::Sint(-3));
                };
                let Some(digest_name) = digest_name else {
                    return Some(Sample::Sint(-5));
                };
                let (digest, block) = hmac_digest(digest_name)?;
                let mut key = key.into_bytes();
                if key.len() > block {
                    key = digest(&key);
                }
                key.resize(block, 0);
                let mut inner: Vec<u8> = key.iter().map(|b| b ^ 0x36).collect();
                inner.extend_from_slice(jose.as_bytes());
                inner.push(b'.');
                inner.extend_from_slice(claims.as_bytes());
                let mut outer: Vec<u8> = key.iter().map(|b| b ^ 0x5c).collect();
                outer.extend_from_slice(&digest(&inner));
                let expected = digest(&outer);
                // Constant-time comparison of the signature.
                let same = expected.len() == sig_bytes.len() && expected.iter().zip(&sig_bytes).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0;
                Some(Sample::Sint(i64::from(same)))
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
                    // The argument is a variable (refused otherwise at load, T341); when it is
                    // not set there is no sample (T327: an empty field in a log-format).
                    // T363a: the raw bytes of the variable, not the UTF-8 of its bytetext; T364:
                    // cast to `bin` from its type (`sample_conv_var2smp(.., SMP_T_BIN)`).
                    let target_bytes: Vec<u8> = crate::vars::var_arg_bin(args.first()?)?;

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

        // `x509_v_err_str`: an X.509 verification error code to its name (T328). The input is
        // cast to an integer first (SMP_T_SINT in HAProxy), and HAProxy's
        // `x509_v_err_int_to_str(int)` takes its low 32 bits; an unknown code prints as the
        // full 64-bit value, unsigned (`%llu`).
        self.register_converter(ConvDesc {
            name: "x509_v_err_str",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| {
                let Sample::Sint(code) = smp else { return None };
                let low = i32::from_le_bytes(code.to_le_bytes()[..4].try_into().ok()?);
                Some(Sample::Str(
                    x509_v_err_name(i64::from(low)).map_or_else(|| code.cast_unsigned().to_string(), str::to_string),
                ))
            },
        });
        // `ocsp_check_err_str` (T328): an OCSP check error code to its text. HAProxy's
        // `ssl_ocsp_check_err_to_str(int)` takes the low 32 bits; 0 and codes outside 1..=11
        // give an empty string.
        self.register_converter(ConvDesc {
            name: "ocsp_check_err_str",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Sint(n) => {
                    let code = i32::from_le_bytes(n.to_le_bytes()[..4].try_into().ok()?);
                    let s = match code {
                        1 => "OCSP verification failed",
                        2 => "OCSP unknown cert",
                        3 => "OCSP response(s) invalid",
                        4 => "OCSP response signature verification failure",
                        5 => "OCSP response not yet valid (contains a date in the future)",
                        6 => "OCSP response has expired",
                        7 => "no OCSP response available for certificate or responder unreachable",
                        8 => "unable to get issuer certificate",
                        9 => "CID mismatch",
                        10 => "Memory allocation failed",
                        11 => "Timeout",
                        _ => "",
                    };
                    Some(Sample::Str(s.to_string()))
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
        self.eval_all_opt(fetch_name, fetch_args, converters, ctx, false)
    }

    /// `eval_all` for an ACL (`acl_exec_cond`): a converter that gives no sample for an occurrence
    /// ends the expression there (`continue` to the next line of the ACL), the later occurrences
    /// of the fetch are not tried.
    #[must_use]
    pub fn eval_all_acl(
        &self,
        fetch_name: &str,
        fetch_args: &[String],
        converters: &[(&str, Vec<String>)],
        ctx: &SampleContext,
    ) -> Vec<Sample> {
        self.eval_all_opt(fetch_name, fetch_args, converters, ctx, true)
    }

    fn eval_all_opt(
        &self,
        fetch_name: &str,
        fetch_args: &[String],
        converters: &[(&str, Vec<String>)],
        ctx: &SampleContext,
        stop_at_failure: bool,
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
            match self.apply_converters_in(ctx, smp, converters) {
                Some(res) => out.push(res),
                None if stop_at_failure => break,
                None => {}
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
        // T337: a fetch that iterates in an ACL gives its own single sample here (the last
        // header value, the last cookie), not the first of the ACL's list.
        if let Some(f_desc) = self.get_fetch(fetch_name) {
            let smp = (f_desc.func)(ctx, fetch_args)?;
            return self.apply_converters_in(ctx, smp, converters);
        }
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
    // `req_version` first: the client's own version, which the HTX start line no longer has
    // for an h2 or h3 request (rewritten to HTTP/1.1 for the server leg).
    ctx.req_version
        .or_else(|| ctx.htx_slice.and_then(|h| h.req_line().map(|r| r.version)))
        .or_else(|| ctx.htx.and_then(|h| h.req_line().map(|r| r.version.as_str())))
}

fn get_context_res_version<'a>(ctx: &'a SampleContext) -> Option<&'a str> {
    ctx.htx_slice
        .and_then(|h| h.res_line().map(|r| r.version))
        .or(ctx.res_version)
        .or_else(|| ctx.htx.and_then(|h| h.res_line().map(|r| r.version.as_str())))
}

fn fetch_base(ctx: &SampleContext, _args: &[String]) -> Option<Sample> {
    fetch_base_path(ctx, false)
}

/// T327: `base` (`with_query` false) and `baseq`, as the oracle's `smp_fetch_base`: the Host
/// header, even for an absolute-form target, then the target's path (`http_parse_path`) up to
/// `?` (or with its query for `baseq`) when it starts with `/`. Without a Host header, or with
/// an empty one, it is what `path` (or `pathq`) gives.
fn fetch_base_path(ctx: &SampleContext, with_query: bool) -> Option<Sample> {
    let path = http_parse_path(get_context_uri(ctx)?, get_context_method(ctx) == Some("OPTIONS"));
    let cut = |p: &'_ str| -> usize {
        if with_query {
            p.len()
        } else {
            p.find('?').unwrap_or(p.len())
        }
    };
    let Some(mut out) = get_req_header(ctx, "host").filter(|h| !h.is_empty()) else {
        let p = path?;
        return Some(Sample::Str(p[..cut(p)].to_string()));
    };
    if let Some(p) = path.filter(|p| p.starts_with('/')) {
        out.push_str(&p[..cut(p)]);
    }
    Some(Sample::Str(out))
}

/// T327: the path of the request target `uri` as the oracle's `http_parse_path` finds it:
/// all of an absolute path; for an absolute URI (any scheme, any case) what follows the
/// authority, which may start with `?` or `#`; nothing for `*` or an authority (CONNECT).
/// An absolute URI that ends with its authority reads `/` (T326: the oracle's
/// `http_scheme_based_normalize`, `src/http_htx.c`, adds it on the way in), except for an
/// OPTIONS request (`options`), where it has no path.
fn http_parse_path(uri: &str, options: bool) -> Option<&str> {
    let b = uri.as_bytes();
    match b.first()? {
        b'*' => return None,
        b'/' => return Some(uri),
        c if !c.is_ascii_alphabetic() => return None,
        _ => {}
    }
    let scheme = 1 + b[1..].iter().take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.')).count();
    let rest = uri[scheme..].strip_prefix("://")?;
    match rest.find(['/', '?', '#']) {
        Some(i) => Some(&rest[i..]),
        None if options => None,
        None => Some("/"),
    }
}

/// `HAProxy`'s `smp_fetch_base32`: SDBM from 0 over the Host header's value, when there is
/// one (never an absolute URI's authority), then over the path up to `?` when it starts with
/// `/`, then `full_hash`.
fn base32_hash(ctx: &SampleContext) -> Option<u32> {
    let uri = get_context_uri(ctx)?;
    let (_, path, _) = split_uri(uri);
    let mut input = get_req_header(ctx, "host").map(String::into_bytes).unwrap_or_default();
    if path.starts_with('/') {
        input.extend_from_slice(path.as_bytes());
    }
    Some(full_hash(hash_sdbm(&input)))
}

/// `tune.bufsize`: the size of the trash chunks converters write into.
static TRASH_SIZE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(16_384);

/// Sets the size of the converters' trash chunks (`tune.bufsize`).
pub fn set_trash_size(n: usize) {
    TRASH_SIZE.store(n.max(2), std::sync::atomic::Ordering::Relaxed);
}

/// The size of the converters' trash chunks (`tune.bufsize`).
#[must_use]
pub fn trash_size() -> usize {
    TRASH_SIZE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Cuts `s` to what a trash chunk holds (`bufsize - 1` bytes and its NUL), at a character
/// boundary.
pub fn truncate_to_trash(s: &mut String) {
    let max = trash_size() - 1;
    if s.len() > max {
        let mut at = max;
        while !s.is_char_boundary(at) {
            at -= 1;
        }
        s.truncate(at);
    }
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

/// The pattern references of the map files the converters have read, by path: a lookup
/// takes this read lock, then the reference's.
static MAP_REFS: RwLock<Option<HashMap<String, Arc<crate::patref::PatRef>>>> = RwLock::new(None);

/// The reference of map file `path`, read from disk on first use (when the configuration
/// scan did not register it).
fn map_ref(path: &str) -> Option<Arc<crate::patref::PatRef>> {
    if let Ok(guard) = MAP_REFS.read() {
        if let Some(r) = guard.as_ref().and_then(|m| m.get(path)) {
            return Some(Arc::clone(r));
        }
    }
    let pat = crate::patref::map_file(path, crate::patref::MapKeys::Str, None)?;
    if let Ok(mut guard) = MAP_REFS.write() {
        guard.get_or_insert_with(HashMap::new).insert(path.to_string(), Arc::clone(&pat));
    }
    Some(pat)
}

/// The entry of map file `path` that `input` matches with `match_type`, as `(value, key)`.
#[must_use]
pub fn match_map(path: &str, input: &str, match_type: MapMatchType) -> Option<(String, String)> {
    let pat = map_ref(path)?;
    let t = pat.table();
    match match_type {
        MapMatchType::Str => t.match_str(input),
        MapMatchType::Int => t.match_int(input),
        MapMatchType::Beg => t.match_beg(input),
        MapMatchType::End => t.match_end(input),
        MapMatchType::Sub => t.match_sub(input),
        MapMatchType::Dir => t.match_dir(input),
        MapMatchType::Dom => t.match_dom(input),
        MapMatchType::Reg => t.match_reg(input),
        MapMatchType::Regm => t.match_regm(input),
        MapMatchType::Ip => t.match_ip(input),
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

/// The scopes `dump_all_vars` knows, in the order it visits them when given none. T329
const DUMP_VAR_SCOPES: [&str; 5] = ["sess", "txn", "req", "res", "proc"];

/// The configuration-time check of `dump_all_vars`'s arguments: an unknown <scope> is refused with
/// `HAProxy`'s message (an empty one means every scope). `None` for any other fetch or valid arguments. T329
#[must_use]
pub fn check_dump_all_vars_args(fetch: &str, args: &[String]) -> Option<String> {
    if fetch != "dump_all_vars" {
        return None;
    }
    let scope = args.first().map(String::as_str).filter(|s| !s.is_empty())?;
    if DUMP_VAR_SCOPES.contains(&scope) {
        return None;
    }
    Some(format!(
        "invalid args in fetch method 'dump_all_vars' : invalid scope '{scope}', must be one of: {}.",
        DUMP_VAR_SCOPES.join(", ")
    ))
}

/// A variable's value as `dump_all_vars` prints it, by its stored type (`smp_fetch_dump_all_vars`): a string
/// quoted with `"`, `\\`, CR, LF, backspace and NUL escaped (as `chunk_escape_string` does), a `bin` as
/// upper-case hex, an integer bare, a bool as `true`/`false`, an address as text, a method quoted. T329, T364 S4
fn dump_var_value(val: &Sample) -> String {
    use std::fmt::Write as _;
    let quote = |t: &str| {
        let mut out = String::with_capacity(t.len() + 2);
        out.push('"');
        for c in t.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\r' => out.push_str("\\r"),
                '\n' => out.push_str("\\n"),
                '\x08' => out.push_str("\\b"),
                '\0' => out.push_str("\\0"),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    };
    match val {
        Sample::Str(t) => quote(t),
        Sample::Bin(b) => b.iter().fold(String::with_capacity(b.len() * 2), |mut o, x| {
            let _ = write!(o, "{x:02X}");
            o
        }),
        Sample::Sint(n) => n.to_string(),
        Sample::Bool(b) => b.to_string(),
        Sample::Ipv4(a) => a.to_string(),
        Sample::Ipv6(a) => a.to_string(),
        Sample::Meth(m) => quote(m.as_str()),
    }
}

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
        // T363a: bytetext, not lossy UTF-8 (see engine.rs `sample_to_string`).
        Sample::Bin(b) => ibex_regex::bytetext::bytes_to_text(b),
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

/// T327: the end of the header value starting at `s` in `b`: the next comma outside a quoted
/// string, or the end. A port of `http_find_hdr_value_end` in the oracle (a backslash inside
/// quotes escapes the next byte).
fn hdr_value_end(b: &[u8], s: usize) -> usize {
    let (mut quoted, mut qdpair) = (false, false);
    for (i, &c) in b.iter().enumerate().skip(s) {
        if qdpair {
            qdpair = false;
        } else if quoted {
            match c {
                b'\\' => qdpair = true,
                b'"' => quoted = false,
                _ => {}
            }
        } else if c == b'"' {
            quoted = true;
        } else if c == b',' {
            return i;
        }
    }
    b.len()
}

/// T327: the comma-separated values of one header line as `http_find_header(full=0)` walks
/// them: split at commas outside quoted strings, each trimmed of blanks. An empty line or an
/// empty element is one (empty) value, so `"a,,b,"` gives four.
fn hdr_values(v: &str) -> Vec<&str> {
    let b = v.as_bytes();
    let mut out = Vec::new();
    let mut s = 0;
    loop {
        let n = hdr_value_end(b, s);
        out.push(v[s..n].trim_matches([' ', '\t']));
        if n >= b.len() {
            return out;
        }
        s = n + 1;
    }
}

/// T337: `MAX_HDR_HISTORY`, how far back from the last one a negative occurrence reaches.
const MAX_HDR_HISTORY: u64 = 10;

/// T337: calls `f` with each line of header `name`, in order, from the sources
/// [`get_all_req_headers`] / (with `res`) [`get_all_res_headers`] read, without copying them.
fn visit_header_lines(ctx: &SampleContext, name: &str, res: bool, f: &mut dyn FnMut(&str)) {
    let mut any = false;
    if res {
        for (k, v) in ctx.res_headers.into_iter().flatten() {
            if k.eq_ignore_ascii_case(name) {
                any = true;
                f(v);
            }
        }
        if !any {
            CURRENT_RES_HEADERS.with(|hdrs| {
                for (k, v) in hdrs.borrow().iter() {
                    if k.eq_ignore_ascii_case(name) {
                        f(v);
                    }
                }
            });
        }
        return;
    }
    if let Some(htx) = ctx.htx_slice {
        for (k, v) in htx.headers() {
            if k.eq_ignore_ascii_case(name) {
                any = true;
                f(v);
            }
        }
    }
    if any {
        return;
    }
    for hf in ctx.htx.into_iter().flat_map(Htx::headers) {
        if hf.name.eq_ignore_ascii_case(name) {
            f(&hf.value);
        }
    }
    for (k, v) in ctx.req_headers.into_iter().flatten() {
        if k.eq_ignore_ascii_case(name) {
            f(v);
        }
    }
}

/// T337: calls `f` with each value of header `name` as `smp_fetch_hdr` (comma values) or,
/// with `full`, `smp_fetch_fhdr` (lines) sees them.
fn visit_header_values(ctx: &SampleContext, name: &str, res: bool, full: bool, f: &mut dyn FnMut(&str)) {
    visit_header_lines(ctx, name, res, &mut |line| {
        if full {
            f(line);
            return;
        }
        let b = line.as_bytes();
        let mut s = 0;
        loop {
            let n = hdr_value_end(b, s);
            f(line[s..n].trim_matches([' ', '\t']));
            if n >= b.len() {
                return;
            }
            s = n + 1;
        }
    });
}

/// T337: the value of header `name` (`args[0]`) `smp_fetch_hdr` (comma values) or, with
/// `full`, `smp_fetch_fhdr` (lines) gives as a sample: the `<occ>`th one (`args[1]`), counted
/// from the end when negative, no further back than [`MAX_HDR_HISTORY`]
/// (`http_get_htx_hdr`), and the last one when `<occ>` is absent or 0. Only the value given
/// is copied: a negative occurrence counts the values first, then picks one.
fn header_one(ctx: &SampleContext, args: &[String], res: bool, full: bool) -> Option<String> {
    let name = args.first()?;
    let occ: i64 = args.get(1).and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    let target = if occ > 0 {
        u64::try_from(occ - 1).ok()?
    } else {
        let back = if occ == 0 { 1 } else { occ.unsigned_abs() };
        if back > MAX_HDR_HISTORY {
            return None;
        }
        let mut n: u64 = 0;
        visit_header_values(ctx, name, res, full, &mut |_| n += 1);
        n.checked_sub(back)?
    };
    let (mut i, mut out): (u64, Option<String>) = (0, None);
    visit_header_values(ctx, name, res, full, &mut |v| {
        if i == target {
            out = Some(v.to_string());
        }
        i += 1;
    });
    out
}

/// T337: the values of header `name` an ACL tries (`SMP_OPT_ITERATE`): every one, or only
/// [`header_one`]'s when an `<occ>` other than 0 is given.
fn header_all(ctx: &SampleContext, args: &[String], res: bool, full: bool) -> Vec<String> {
    let Some(name) = args.first() else { return Vec::new() };
    if args.get(1).and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(0) != 0 {
        return header_one(ctx, args, res, full).into_iter().collect();
    }
    let mut out = Vec::new();
    visit_header_values(ctx, name, res, full, &mut |v| out.push(v.to_string()));
    out
}

/// T337: the cookie values `smp_fetch_cookie` gives for `args[0]` (any cookie when absent or
/// empty), from `Cookie` or, with `res`, `Set-Cookie`. Each header is walked value by value
/// (`http_find_header(full=0)`), a value shorter than the name and `=` is skipped, and
/// [`crate::cookie_names::values`] reads the cookies of each. Every one when `iterate` (an
/// ACL), otherwise the last one, or the first one when no name is given.
fn cookie_fetch(ctx: &SampleContext, args: &[String], res: bool, iterate: bool) -> Vec<String> {
    let name = args.first().map_or("", String::as_str);
    let lines = if res { get_all_res_headers(ctx, "set-cookie") } else { get_all_req_headers(ctx, "cookie") };
    let mut vals: Vec<String> = Vec::new();
    for line in &lines {
        for elem in hdr_values(line).into_iter().filter(|e| e.len() > name.len()) {
            let found = crate::cookie_names::values(elem, name, !res);
            vals.extend(found.into_iter().map(str::to_string));
            if !iterate && name.is_empty() && !vals.is_empty() {
                vals.truncate(1);
                return vals;
            }
        }
    }
    if !iterate && vals.len() > 1 {
        vals.drain(..vals.len() - 1);
    }
    vals
}

/// T337: the parameters `smp_fetch_url_param` gives: `url_param([<name>[,<delim>[,i]]])`
/// reads the URI after its first `<delim>` (default `?`) with [`url_param_values`]. The first
/// one as a sample, every one when `iterate` (an ACL). Raw, not URL-decoded.
fn url_param_fetch(ctx: &SampleContext, args: &[String], iterate: bool) -> Vec<String> {
    let Some(uri) = get_context_uri(ctx) else { return Vec::new() };
    let name = args.first().map_or(&b""[..], |s| s.as_bytes());
    let delim = args.get(1).and_then(|s| s.bytes().next()).unwrap_or(b'?');
    // HAProxy looks only at the flag's first character (`*area == 'i'`).
    let insensitive = args.get(2).is_some_and(|s| s.starts_with('i'));
    let Some(start) = uri.bytes().position(|c| c == delim) else { return Vec::new() };
    let mut vals = url_param_values(&uri.as_bytes()[start + 1..], name, delim, insensitive);
    if !iterate {
        vals.truncate(1);
    }
    vals.into_iter().map(|v| String::from_utf8_lossy(v).into_owned()).collect()
}

/// T337: every value `http_find_next_url_param` (`src/http.c`) finds in the parameter list
/// `qs`, in order, each search starting where the last value ended. `&`, `;` and `delim` end a
/// parameter (`http_is_param_delimiter`); a name matches only at the start of a parameter and
/// only when `=` follows it (`http_find_url_param_pos`, case aside with `insensitive`); with
/// no name the value after the next `=` is taken, wherever it is.
fn url_param_values<'a>(qs: &'a [u8], name: &[u8], delim: u8, insensitive: bool) -> Vec<&'a [u8]> {
    let is_delim = |c: u8| c == b'&' || c == b';' || c == delim;
    let end = qs.len();
    let find_name = |mut pos: usize| -> Option<usize> {
        while pos < end {
            let equal = pos + name.len();
            if equal >= end {
                return None;
            }
            if qs[equal] == b'=' {
                let k = &qs[pos..equal];
                if if insensitive { k.eq_ignore_ascii_case(name) } else { k == name } {
                    return Some(equal + 1);
                }
                pos = equal + 1;
            }
            while pos < end && !is_delim(qs[pos]) {
                pos += 1;
            }
            if pos >= end {
                return None;
            }
            pos += 1;
        }
        None
    };
    let mut out = Vec::new();
    let mut from = 0;
    loop {
        let start = if name.is_empty() {
            match qs.get(from..).and_then(|r| r.iter().position(|&c| c == b'=')) {
                Some(p) => from + p + 1,
                None => break,
            }
        } else {
            match find_name(from) {
                Some(s) => s,
                None => break,
            }
        };
        let stop = qs[start..].iter().position(|&c| is_delim(c)).map_or(end, |p| start + p);
        out.push(&qs[start..stop]);
        // `smp_fetch_param` sets `SMP_F_NOT_LAST` only while the list goes on.
        if stop >= end {
            break;
        }
        from = stop;
    }
    out
}

/// T337: a `_val` fetch's sample: `strl2ic` over the value it read.
fn strl2ic_sample(v: String) -> Sample {
    Sample::Sint(i64::from(strl2ic(v.as_bytes())))
}

/// T327: `hdrs` as the oracle's H1 parser leaves them in HTX, for the header-count fetches:
/// [`crate::h1_clean::h1_clean_headers`] (the one implementation of that cleaning, shared
/// with `req.hdrs`/`res.hdrs` and the `*.hdr_names` fetches).
fn h1_cleaned_headers(hdrs: Vec<(String, String)>, is_req: bool) -> Vec<(String, String)> {
    crate::h1_clean::h1_clean_headers(hdrs.iter().map(|(n, v)| (n.as_str(), v.as_str())), is_req)
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
/// The delimiter of the `*.hdr_names` and `*.cook_names` fetches (T340): the first byte of the
/// argument (`args[0].data.str.area[0]` in HAProxy), `,` without an argument and NUL for an
/// empty one. A byte of 0x80 or more is a byte of text that is not UTF-8, so it goes in as
/// its bytetext character, as the names it separates carry theirs.
fn names_delim(args: &[String]) -> String {
    let Some(arg) = args.first() else { return ",".to_string() };
    match ibex_regex::bytetext::text_to_bytes(arg).first() {
        None => "\0".to_string(),
        Some(&b) if b >= 0x80 => ibex_regex::bytetext::escape_byte(b).to_string(),
        Some(&b) => char::from(b).to_string(),
    }
}

/// T326: the names of the request headers, lowercased, in order, from the first source that
/// has any, without those `HAProxy`'s H1 parser leaves out of HTX ([`crate::h1_clean`]).
fn req_header_names(ctx: &SampleContext) -> Vec<String> {
    let mut hdrs: Vec<(&str, &str)> = Vec::new();
    if let Some(htx) = ctx.htx_slice {
        hdrs.extend(htx.headers());
    }
    if let (true, Some(htx)) = (hdrs.is_empty(), ctx.htx) {
        hdrs.extend(htx.headers().map(|hf| (hf.name.as_str(), hf.value.as_str())));
    }
    if let (true, Some(headers)) = (hdrs.is_empty(), ctx.req_headers) {
        hdrs.extend(headers.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    }
    let kept = crate::h1_clean::kept_headers(&hdrs, true);
    hdrs.iter().zip(kept).filter(|(_, k)| *k).map(|((n, _), _)| n.to_ascii_lowercase()).collect()
}

/// T302: `req.hdrs` (`smp_fetch_hdrs`): the request's headers as the H1 parser stores them
/// ([`crate::h1_clean::h1_clean_headers`]), each `name: value\r\n`, then the `\r\n` that ends
/// them, there even when no header is. Read from the first request source present; `None`
/// when there is no request.
fn req_header_block(ctx: &SampleContext) -> Option<String> {
    use crate::h1_clean::{h1_clean_headers, header_block};
    let hdrs = if let Some(htx) = ctx.htx_slice {
        h1_clean_headers(htx.headers(), true)
    } else if let Some(htx) = ctx.htx {
        h1_clean_headers(htx.headers().map(|hf| (hf.name.as_str(), hf.value.as_str())), true)
    } else {
        h1_clean_headers(ctx.req_headers?.iter().map(|(k, v)| (k.as_str(), v.as_str())), true)
    };
    Some(header_block(&hdrs))
}

/// T327: all request header `(name, value)` pairs, in order, from the same sources as
/// `get_all_req_headers`, as the oracle's H1 parser leaves them (`h1_cleaned_headers`).
fn get_all_req_headers_all(ctx: &SampleContext) -> Vec<(String, String)> {
    let mut all = Vec::new();
    if let Some(htx) = ctx.htx_slice {
        all.extend(htx.headers().map(|(n, v)| (n.to_string(), v.to_string())));
    }
    if all.is_empty() {
        if let Some(htx) = ctx.htx {
            all.extend(htx.headers().map(|hf| (hf.name.clone(), hf.value.clone())));
        }
        if let Some(headers) = ctx.req_headers {
            all.extend(headers.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
    }
    h1_cleaned_headers(all, true)
}

/// The response's header `name`. Only the response is read: `ctx.htx_slice` holds the
/// *request* while a response rule runs, so a `shdr(x-n)` that fell back to it answered
/// with the request's `X-N` (T132).
fn get_res_header(ctx: &SampleContext, name: &str) -> Option<String> {
    get_all_res_headers(ctx, name).into_iter().next()
}

/// T329: `res.hdrs` (`smp_fetch_hdrs`): the response's headers as the H1 parser stores them
/// ([`crate::h1_clean::h1_clean_headers`]), each `name: value\r\n`, then the `\r\n` that ends
/// them. Raw: a header action that writes it has its own `%XX` encoding (`http_encode_map`).
/// Read from `ctx.res_headers`, else from the response being processed.
fn res_header_block(ctx: &SampleContext) -> String {
    use crate::h1_clean::{h1_clean_headers, header_block};
    let hdrs = match ctx.res_headers {
        Some(h) => h1_clean_headers(h.iter().map(|(k, v)| (k.as_str(), v.as_str())), false),
        None => CURRENT_RES_HEADERS.with(|h| h1_clean_headers(h.borrow().iter().map(|(k, v)| (k.as_str(), v.as_str())), false)),
    };
    header_block(&hdrs)
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

/// T326: the response header names, lowercased, in order (from where
/// [`get_all_res_headers`] reads them), without those `HAProxy`'s H1 parser leaves out of
/// HTX ([`crate::h1_clean`]).
fn get_all_res_header_names(ctx: &SampleContext) -> Vec<String> {
    let names = |hdrs: &[(&str, &str)]| -> Vec<String> {
        let kept = crate::h1_clean::kept_headers(hdrs, false);
        hdrs.iter().zip(kept).filter(|(_, k)| *k).map(|((n, _), _)| n.to_ascii_lowercase()).collect()
    };
    if let Some(headers) = ctx.res_headers.filter(|h| !h.is_empty()) {
        return names(&headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect::<Vec<_>>());
    }
    CURRENT_RES_HEADERS.with(|hdrs| names(&hdrs.borrow().iter().map(|(k, v)| (k.as_str(), v.as_str())).collect::<Vec<_>>()))
}


/// T327: all response header `(name, value)` pairs, in order, from the same sources as
/// `get_all_res_headers`, as the oracle's H1 parser leaves them (`h1_cleaned_headers`).
fn get_all_res_headers_all(ctx: &SampleContext) -> Vec<(String, String)> {
    let mut all: Vec<(String, String)> = ctx.res_headers.map(<[_]>::to_vec).unwrap_or_default();
    if all.is_empty() {
        CURRENT_RES_HEADERS.with(|hdrs| all.extend(hdrs.borrow().iter().cloned()));
    }
    h1_cleaned_headers(all, false)
}

/// T327: whether the Set-Cookie value `seg` holds a cookie named `name` (any cookie when
/// `name` is empty). A port of the oracle's `http_extract_cookie_value` with `list` = 0:
/// attributes starting with `$` or without `=` are skipped, and the first other one is the
/// cookie, whether or not it matches. Its bounds checks are kept, so `s=` (empty value) is not
/// a cookie named `s`.
fn set_cookie_is(seg: &[u8], name: &[u8]) -> bool {
    let spht = |c: u8| c == b' ' || c == b'\t';
    let end = seg.len();
    if end < name.len() + 1 {
        return false;
    }
    let mut att = 0;
    while att + name.len() + 1 < end {
        while att < end && spht(seg[att]) {
            att += 1;
        }
        let (mut equal, mut att_end) = (att, att);
        while equal < end && seg[equal] != b'=' && seg[equal] != b';' {
            equal += 1;
            if !spht(seg[equal - 1]) {
                att_end = equal;
            }
        }
        let next = if equal < end && seg[equal] == b'=' {
            let mut val = equal + 1;
            while val < end && spht(seg[val]) {
                val += 1;
            }
            cookie_value_end(seg, val)
        } else {
            equal
        };
        if seg.get(att) == Some(&b'$') || equal == next {
            att = next + 1;
            continue;
        }
        return name.is_empty() || &seg[att..att_end] == name;
    }
    false
}

/// T327: the end of the cookie value starting at `s`: the next `,` or `;` outside a quoted
/// string, or the end (the oracle's `http_find_cookie_value_end`).
fn cookie_value_end(b: &[u8], s: usize) -> usize {
    let (mut quoted, mut qdpair) = (false, false);
    for (i, &c) in b.iter().enumerate().skip(s) {
        if qdpair {
            qdpair = false;
        } else if quoted {
            match c {
                b'\\' => qdpair = true,
                b'"' => quoted = false,
                _ => {}
            }
        } else if c == b'"' {
            quoted = true;
        } else if c == b',' || c == b';' {
            return i;
        }
    }
    b.len()
}

/// `strl2ic` (`src/tools.c`): an optional '-', then the decimal digits up to the first other
/// byte, wrapping as a C `int` does; 0 where there are none ('+' is not a sign).
fn strl2ic(s: &[u8]) -> i32 {
    let (neg, digits) = match s.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, s),
    };
    digits.iter().take_while(|c| c.is_ascii_digit()).fold(0i32, |i, &c| {
        let j = i32::from(c - b'0');
        if neg { i.wrapping_mul(10).wrapping_sub(j) } else { i.wrapping_mul(10).wrapping_add(j) }
    })
}

/// The address and port `url_ip` and `url_port` read from an absolute-form target
/// (`url2sa`): a `http` or `https` scheme (any case; the port defaults to 80 or 443), no
/// userinfo, and a host that is four decimal numbers up to 255 -- a name, an IPv6 literal or
/// a short form is no address. The port is the digits after the colon, nothing if there are
/// none, and wraps at 65536 as the `u16` it is stored in does.
fn url_ipv4_authority(uri: &str) -> Option<(Ipv4Addr, u16)> {
    let (scheme, rest) = uri.split_once("://")?;
    let default = if scheme.eq_ignore_ascii_case("http") {
        80
    } else if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        return None;
    };
    let authority = &rest[..rest.find(['/', '?']).unwrap_or(rest.len())];
    if authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    let mut octets = [0u8; 4];
    let mut parts = host.split('.');
    for o in &mut octets {
        let part = parts.next().filter(|p| (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))?;
        *o = part.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    let port = match port {
        None | Some("") => default,
        Some(p) => {
            let digits = p.bytes().take_while(u8::is_ascii_digit).fold(0u32, |n, b| (n * 10 + u32::from(b - b'0')) & 0xFFFF_FFF);
            (digits & 0xFFFF) as u16
        }
    };
    Some((Ipv4Addr::from(octets), port))
}

/// T326: `smp_fetch_url32` (`src/http_fetch.c`): SDBM over the first Host value, then over the
/// request path (query included, as sent) when it starts with '/', then `full_hash`.
fn url32_hash(ctx: &SampleContext) -> u32 {
    let mut data = get_req_header(ctx, "host").unwrap_or_default().into_bytes();
    let uri = get_context_uri(ctx).unwrap_or("");
    let path = http_parse_path(uri, get_context_method(ctx) == Some("OPTIONS")).unwrap_or("");
    if path.starts_with('/') {
        data.extend_from_slice(path.as_bytes());
    }
    full_hash(hash_sdbm(&data))
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

/// The ISO 8601 week of a day: its year and number (`%G`, `%V`). `yday` counts from 0 in
/// year `y`, `wday` from Sunday = 0.
fn iso_week(y: i64, yday: i64, wday: i64) -> (i64, i64) {
    let iso_wday = if wday == 0 { 7 } else { wday };
    let week = (yday + 1 - iso_wday + 10) / 7;
    let weeks_in = |year: i64| {
        let jan1 = (days_from_civil(year, 1, 1) + 4).rem_euclid(7);
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        if jan1 == 4 || (leap && jan1 == 3) { 53 } else { 52 }
    };
    if week < 1 {
        (y - 1, weeks_in(y - 1))
    } else if week > weeks_in(y) {
        (y + 1, 1)
    } else {
        (y, week)
    }
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
    let (days, secs) = split_epoch(epoch.saturating_add(i64::from(offset)));

    let (y, m, d) = civil_from_days(days);
    let wday_idx = weekday_index(days);
    let month_idx = month_index(m);

    let hour = secs / 3600;
    let min = (secs % 3600) / 60;
    let sec = secs % 60;
    // Sunday is 0 (`%w`); the week counts of `%U`, `%W`, and the ISO ones of `%V %G %g`.
    let wday = (days + 4).rem_euclid(7);
    let yday = days - days_from_civil(y, 1, 1);
    let (iso_year, iso_week) = iso_week(y, yday, wday);
    let hour12 = if hour % 12 == 0 { 12 } else { hour % 12 };

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
                    'T' | 'X' => { let _ = write!(out, "{hour:02}:{min:02}:{sec:02}"); }
                    'R' => { let _ = write!(out, "{hour:02}:{min:02}"); }
                    'D' | 'x' => { let _ = write!(out, "{m:02}/{d:02}/{:02}", y % 100); }
                    'C' => { let _ = write!(out, "{:02}", y.div_euclid(100)); }
                    'e' => { let _ = write!(out, "{d:2}"); }
                    'j' => { let _ = write!(out, "{:03}", yday + 1); }
                    'k' => { let _ = write!(out, "{hour:2}"); }
                    'l' => { let _ = write!(out, "{hour12:2}"); }
                    'I' => { let _ = write!(out, "{hour12:02}"); }
                    'p' => out.push_str(if hour < 12 { "AM" } else { "PM" }),
                    'P' => out.push_str(if hour < 12 { "am" } else { "pm" }),
                    'r' => { let _ = write!(out, "{hour12:02}:{min:02}:{sec:02} {}", if hour < 12 { "AM" } else { "PM" }); }
                    'c' => { let _ = write!(out, "{} {} {d:2} {hour:02}:{min:02}:{sec:02} {y:04}", DAYS[wday_idx], MONTHS[month_idx]); }
                    'u' => { let _ = write!(out, "{}", if wday == 0 { 7 } else { wday }); }
                    'w' => { let _ = write!(out, "{wday}"); }
                    'U' => { let _ = write!(out, "{:02}", (yday + 7 - wday) / 7); }
                    'W' => { let _ = write!(out, "{:02}", (yday + 7 - (wday + 6) % 7) / 7); }
                    'V' => { let _ = write!(out, "{iso_week:02}"); }
                    'G' => { let _ = write!(out, "{iso_year:04}"); }
                    'g' => { let _ = write!(out, "{:02}", iso_year.rem_euclid(100)); }
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
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

/// One captured list for the `ssl_fc_*list_bin` fetches: the bytes as captured, or with
/// `GREASE` removed when the integer argument is not 0; no sample without a capture.
fn capture_bytes(ctx: &SampleContext, args: &[String], list: fn(&ibex_tls::SslCapture) -> &[u8]) -> Option<Vec<u8>> {
    let c = ctx.ssl_fc.capture?;
    let bytes = list(c);
    let filter = args.first().and_then(|a| a.parse::<i64>().ok()).unwrap_or(0) != 0;
    Some(if filter { ibex_tls::exclude_tls_grease(bytes, 16384) } else { bytes.to_vec() })
}

fn capture_list(ctx: &SampleContext, args: &[String], list: fn(&ibex_tls::SslCapture) -> &[u8]) -> Option<Sample> {
    capture_bytes(ctx, args, list).map(Sample::Bin)
}

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
    // Hex digits are ASCII: slicing text with another character in it would panic.
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
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

/// T343: the digest `digest(<alg>)` computes, by `OpenSSL` name (`EVP_get_digestbyname`), as
/// `hmac` takes it; `None` for a name it does not know.
pub(crate) fn digest_by_name(alg: &str) -> Option<fn(&[u8]) -> Vec<u8>> {
    hmac_digest(alg).map(|(f, _)| f)
}

/// T343: whether `alg` is an `OpenSSL` digest Ibex does not compute.
pub(crate) fn digest_unimplemented(alg: &str) -> bool {
    HMAC_UNIMPLEMENTED.contains(&alg.to_ascii_lowercase().as_str())
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

/// The variable named `name` cast to `str` (`sample_conv_var2smp_str`).
fn read_var(name: &str) -> Option<String> {
    crate::vars::var_arg_str(name)
}

/// Sets a variable to a string from a converter: in the stream's map, which the engine hands
/// back to the session when the step ends.
fn write_var(name: &str, value: String) {
    crate::vars::set(name, Sample::Str(value));
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

/// A variable `vars_check_arg` accepts: a scope, a dot and a name of letters, digits, `_`
/// and `.` (measured: `txn.a.b` yes, `txn.`, `txn.a-b`, `TXN.x` no).
fn is_var_ref(arg: &str) -> bool {
    ["proc.", "sess.", "txn.", "req.", "res.", "check."].iter().any(|p| {
        arg.strip_prefix(p).is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.')))
    })
}

fn hmac_key_is_var(key: &str) -> bool {
    ["txn.", "sess.", "req.", "res.", "proc."].iter().any(|p| key.starts_with(p))
}

/// T330: load-time check of the `protobuf`/`ungrpc` arguments: a dotted field number, then
/// optionally one of the types `HAProxy` knows.
fn check_protobuf_args(name: &str, args: &[String]) -> Option<String> {
    let first = args.first().map_or("", String::as_str);
    if first.is_empty() {
        return Some(format!(
            "invalid arg 1 in converter '{name}' : expected type 'Protocol buffers field number' at position 1, but got nothing."
        ));
    }
    if pb_field_path(first).is_none() {
        return Some(format!(
            "invalid arg 1 in converter '{name}' : failed to parse '{first}' as type 'Protocol buffers field number' at position 1."
        ));
    }
    if args.len() > 2 {
        return Some(format!("invalid arg 2 in converter '{name}' : expected ')' before ',{})'.", args[2..].join(",")));
    }
    args.get(1)
        .filter(|t| pb_type(t).is_none())
        .map(|t| format!("invalid args in converter '{name}' : Wrong protocol buffer type '{t}'."))
}

/// Load-time check of a converter's arguments, where `HAProxy` refuses some
/// (`invalid args in converter '<name>'`). `None` when they are acceptable.
#[must_use]
pub fn check_converter_args(name: &str, args: &[String]) -> Option<String> {
    match name {
        // `ARG1(0,SINT)`, and nothing after it.
        "ip.fp" if args.len() > 1 => Some(format!("invalid arg 2 in converter 'ip.fp' : expected ')' before ',{})'.", args[1..].join(","))),
        "ip.fp" => args
            .first()
            .filter(|a| crate::cast::parse_sint_arg(a).is_none())
            .map(|a| format!("invalid arg 1 in converter 'ip.fp' : failed to parse '{a}' as type 'integer' at position 1.")),
        // `ARG1(0,SINT)`: a seed (or avalanche flag) that is no integer is refused, not read as 0.
        "crc32" | "crc32c" | "djb2" | "sdbm" | "wt6" | "xxh32" | "xxh64" | "xxh3" => args
            .first()
            .filter(|a| crate::cast::parse_sint_arg(a).is_none())
            .map(|a| format!("invalid arg 1 in converter '{name}' : failed to parse '{a}' as type 'integer' at position 1.")),
        // T343: `map` itself too, not only the `map_*` forms.
        _ if (name == "map" || name.starts_with("map_")) && crate::patref::converter_map(name).is_some() => {
            let (keys, vals) = crate::patref::converter_map(name)?;
            let path = args.first()?.trim_matches(['"', '\'']);
            crate::patref::map_file_error(path, keys, vals).map(|e| format!("invalid args in converter '{name}' : {e}"))
        }
        "mqtt_field_value" => mqtt_field_value_args_error(args),
        "mqtt_is_valid" if !args.iter().all(String::is_empty) => Some(format!(
            "invalid arg 1 in converter 'mqtt_is_valid' : expected ')' before '{})'.",
            args.join(",")
        )),
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
        // T331: a literal <alg> is checked at load time as in HAProxy; the public-key algorithms need
        // a key file that Ibex does not load, so they are refused rather than silently answering.
        // T341: `smp_check_strcmp` / `smp_check_secure_memcmp`: the argument is a variable.
        "strcmp" | "secure_memcmp" => match args {
            [] => Some(format!("invalid args in converter '{name}' : missing variable name.")),
            [a] if a.is_empty() => Some(format!("invalid args in converter '{name}' : missing variable name.")),
            [a] if !is_var_ref(a) => Some(format!("invalid args in converter '{name}' : failed to register variable name '{a}'.")),
            [_] => None,
            [_, rest @ ..] => Some(format!("invalid arg 2 in converter '{name}' : expected ')' before ',{})'.", rest.join(","))),
        },
        "jwt_verify" => {
            let alg = args.first()?.as_str();
            if hmac_key_is_var(alg) || matches!(alg, "HS256" | "HS384" | "HS512") {
                return None;
            }
            Some(if matches!(alg, "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512" | "PS256" | "PS384" | "PS512" | "none") {
                format!("invalid args in converter 'jwt_verify' : algorithm {alg} is not implemented by Ibex (only HS256, HS384 and HS512)")
            } else {
                format!("invalid args in converter 'jwt_verify' : unknown JWT algorithm: {alg}.")
            })
        }
        "set-var" if args.first().is_none_or(String::is_empty) => {
            Some("invalid args in converter 'set-var' : Empty variable name cannot be accepted.".to_string())
        }
        "set-var" => args.iter().skip(1).filter(|c| !c.is_empty()).find_map(|c| match c.as_str() {
            "ifexists" | "ifnotexists" | "ifempty" | "ifnotempty" | "ifset" | "ifnotset" | "ifgt" | "iflt" => None,
            _ => Some(format!("invalid args in converter 'set-var' : unknown condition \"{c}\".")),
        }),
        "aes_cbc_enc" | "aes_cbc_dec" | "aes_gcm_enc" | "aes_gcm_dec" => check_aes_args(name, args),
        "protobuf" | "ungrpc" => check_protobuf_args(name, args),
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

/// T330: the length of an Ethernet header up to and including the `EtherType`, skipping every
/// 802.1Q tag, or None when the frame ends first (the loop in `net_helper.c`'s `sample_conv_eth_*`).
fn eth_hdr_len(b: &[u8]) -> Option<usize> {
    let mut idx = 12usize;
    while idx + 2 < b.len() {
        if b.get(idx..idx + 2)? != [0x81, 0x00] {
            return Some(idx + 2);
        }
        idx += 4;
    }
    None
}

/// T330: the length of an IPv4 or IPv6 header including every IPv6 extension header, or None
/// when the packet is shorter or the length is 0 (`ip_header_length` in `net_helper.c`).
fn ip_header_length(b: &[u8]) -> Option<usize> {
    let len = match b.first()? >> 4 {
        4 => usize::from(b[0] & 0x0f) * 4,
        6 => {
            if b.len() < 40 {
                return None;
            }
            let mut next = *b.get(6)?;
            let mut len = 40usize;
            while next != 6 && next != 17 {
                next = *b.get(len)?;
                len += usize::from(*b.get(len + 1)?) * 8 + 8;
            }
            len
        }
        _ => return None,
    };
    (len != 0 && len <= b.len()).then_some(len)
}

#[cfg(test)]
mod tests {
    /// `dump_var_value` escapes NUL as `\0` (as `chunk_escape_string` does). A NUL cannot be put in a
    /// string variable from a configuration: HAProxy 3.5-dev8 drops the `url_dec` of `%00` altogether, and
    /// dumps a `bin` variable as hex, so no oracle column exists; this pins the code's own rule. Also the
    /// integer-bare and the CR/LF/backspace/quote/backslash cases.
    #[test]
    fn dump_var_value_escapes_control_characters() {
        assert_eq!(dump_var_value(&Sample::Str("a\0b".into())), "\"a\\0b\"");
        assert_eq!(dump_var_value(&Sample::Str("a\r\n\x08\"\\".into())), "\"a\\r\\n\\b\\\"\\\\\"");
        // A string that reads as an integer is still a string: quoted (T364 S4).
        assert_eq!(dump_var_value(&Sample::Str("42".into())), "\"42\"");
        assert_eq!(dump_var_value(&Sample::Sint(42)), "42");
    }

    use super::*;

    /// `url_ip` reads a dotted quad of exactly four parts; a fifth is not an address.
    #[test]
    fn url_ip_wants_exactly_four_octets() {
        assert_eq!(url_ipv4_authority("http://1.2.3.4/"), Some((Ipv4Addr::new(1, 2, 3, 4), 80)));
        assert_eq!(url_ipv4_authority("http://1.2.3.4.5/"), None);
    }

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
        CURRENT_VARS.with(|v| v.borrow_mut().insert("txn.t156".to_string(), Sample::Str("v".to_string())));
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
        CURRENT_VARS.with(|v| {
            let mut v = v.borrow_mut();
            v.insert("txn.eq".to_string(), Sample::Str("my_secret_token".to_string()));
            v.insert("txn.ne".to_string(), Sample::Str("my_secret_tokeX".to_string()));
            v.insert("txn.short".to_string(), Sample::Str("short".to_string()));
        });
        let var = |n: &str| [n.to_string()];

        // Equal match
        assert_eq!((conv.func)(target.clone(), &var("txn.eq")), Some(Sample::Bool(true)));

        // Same length, differing byte
        assert_eq!((conv.func)(target.clone(), &var("txn.ne")), Some(Sample::Bool(false)));

        // Different length
        assert_eq!((conv.func)(target.clone(), &var("txn.short")), Some(Sample::Bool(false)));

        // A literal is no variable (refused at load, T341): no value
        assert_eq!((conv.func)(target, &var("my_secret_token")), None);
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
            &[("json_query", vec!["$.user.name".to_string()])],
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
        // Ibex-only by decision (user, 2026-10-18; T344): the JA4 TLS client fingerprint.
        "ssl_fc_ja4",
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
mod iso_week_tests {
    use super::format_time_ns;

    /// ISO weeks at the turn of a year (`%G-%V`): 2021-01-01 is in 2020's week 53, 2024-12-30
    /// in 2025's week 1, 2026-01-01 in 2026's week 1.
    #[test]
    fn the_iso_year_and_week_cross_the_new_year() {
        for (epoch, want) in [(1_609_459_200, "2020-53"), (1_735_516_800, "2025-01"), (1_767_225_600, "2026-01")] {
            assert_eq!(format_time_ns(epoch, 0, "%G-%V", false), want, "{epoch}");
        }
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

/// Returns the X.509 verification error name for a given error code (T328).
/// Returns `None` for unknown codes.
fn x509_v_err_name(code: i64) -> Option<&'static str> {
    Some(match code {
        0 => "X509_V_OK",
        1 => "X509_V_ERR_UNSPECIFIED",
        2 => "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT",
        3 => "X509_V_ERR_UNABLE_TO_GET_CRL",
        4 => "X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE",
        5 => "X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE",
        6 => "X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY",
        7 => "X509_V_ERR_CERT_SIGNATURE_FAILURE",
        8 => "X509_V_ERR_CRL_SIGNATURE_FAILURE",
        9 => "X509_V_ERR_CERT_NOT_YET_VALID",
        10 => "X509_V_ERR_CERT_HAS_EXPIRED",
        11 => "X509_V_ERR_CRL_NOT_YET_VALID",
        12 => "X509_V_ERR_CRL_HAS_EXPIRED",
        13 => "X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD",
        14 => "X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD",
        15 => "X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD",
        16 => "X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD",
        17 => "X509_V_ERR_OUT_OF_MEM",
        18 => "X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT",
        19 => "X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN",
        20 => "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
        21 => "X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE",
        22 => "X509_V_ERR_CERT_CHAIN_TOO_LONG",
        23 => "X509_V_ERR_CERT_REVOKED",
        24 => "X509_V_ERR_NO_ISSUER_PUBLIC_KEY",
        25 => "X509_V_ERR_PATH_LENGTH_EXCEEDED",
        26 => "X509_V_ERR_INVALID_PURPOSE",
        27 => "X509_V_ERR_CERT_UNTRUSTED",
        28 => "X509_V_ERR_CERT_REJECTED",
        29 => "X509_V_ERR_SUBJECT_ISSUER_MISMATCH",
        30 => "X509_V_ERR_AKID_SKID_MISMATCH",
        31 => "X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH",
        32 => "X509_V_ERR_KEYUSAGE_NO_CERTSIGN",
        33 => "X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER",
        34 => "X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION",
        35 => "X509_V_ERR_KEYUSAGE_NO_CRL_SIGN",
        36 => "X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION",
        37 => "X509_V_ERR_INVALID_NON_CA",
        38 => "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED",
        39 => "X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE",
        40 => "X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED",
        41 => "X509_V_ERR_INVALID_EXTENSION",
        42 => "X509_V_ERR_INVALID_POLICY_EXTENSION",
        43 => "X509_V_ERR_NO_EXPLICIT_POLICY",
        44 => "X509_V_ERR_DIFFERENT_CRL_SCOPE",
        45 => "X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE",
        46 => "X509_V_ERR_UNNESTED_RESOURCE",
        47 => "X509_V_ERR_PERMITTED_VIOLATION",
        48 => "X509_V_ERR_EXCLUDED_VIOLATION",
        49 => "X509_V_ERR_SUBTREE_MINMAX",
        50 => "X509_V_ERR_APPLICATION_VERIFICATION",
        51 => "X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE",
        52 => "X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX",
        53 => "X509_V_ERR_UNSUPPORTED_NAME_SYNTAX",
        54 => "X509_V_ERR_CRL_PATH_VALIDATION_ERROR",
        55 => "X509_V_ERR_PATH_LOOP",
        56 => "X509_V_ERR_SUITE_B_INVALID_VERSION",
        57 => "X509_V_ERR_SUITE_B_INVALID_ALGORITHM",
        58 => "X509_V_ERR_SUITE_B_INVALID_CURVE",
        59 => "X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM",
        60 => "X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED",
        61 => "X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256",
        62 => "X509_V_ERR_HOSTNAME_MISMATCH",
        63 => "X509_V_ERR_EMAIL_MISMATCH",
        64 => "X509_V_ERR_IP_ADDRESS_MISMATCH",
        65 => "X509_V_ERR_DANE_NO_MATCH",
        66 => "X509_V_ERR_EE_KEY_TOO_SMALL",
        67 => "X509_V_ERR_CA_KEY_TOO_SMALL",
        68 => "X509_V_ERR_CA_MD_TOO_WEAK",
        69 => "X509_V_ERR_INVALID_CALL",
        70 => "X509_V_ERR_STORE_LOOKUP",
        71 => "X509_V_ERR_NO_VALID_SCTS",
        72 => "X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION",
        73 => "X509_V_ERR_OCSP_VERIFY_NEEDED",
        74 => "X509_V_ERR_OCSP_VERIFY_FAILED",
        75 => "X509_V_ERR_OCSP_CERT_UNKNOWN",
        76 => "X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM",
        77 => "X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH",
        78 => "X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY",
        79 => "X509_V_ERR_INVALID_CA",
        80 => "X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA",
        81 => "X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN",
        82 => "X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA",
        83 => "X509_V_ERR_ISSUER_NAME_EMPTY",
        84 => "X509_V_ERR_SUBJECT_NAME_EMPTY",
        85 => "X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER",
        86 => "X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER",
        87 => "X509_V_ERR_EMPTY_SUBJECT_ALT_NAME",
        88 => "X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL",
        89 => "X509_V_ERR_CA_BCONS_NOT_CRITICAL",
        90 => "X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL",
        91 => "X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL",
        92 => "X509_V_ERR_CA_CERT_MISSING_KEY_USAGE",
        93 => "X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3",
        94 => "X509_V_ERR_EC_KEY_EXPLICIT_PARAMS",
        _ => return None,
    })
}

/// T330: the value types a `protobuf`/`ungrpc` field can be read as (`protobuf_type()` in `HAProxy`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum PbType {
    /// No type argument: the raw bytes of the field.
    Binary,
    /// `int32`, `uint32`, `int64`, `uint64`, `bool`, `enum`: the varint as an integer.
    Varint,
    /// `sint32`, `sint64`: the varint, zigzag decoded.
    Zigzag,
    /// `fixed32`: the four little-endian bytes, unsigned.
    Fixed32,
    /// `float`: the four bytes read as an IEEE float, then converted to an unsigned integer.
    Float,
    /// `sfixed32`: the four little-endian bytes, signed.
    Sfixed32,
    /// `fixed64`, `sfixed64`: the eight little-endian bytes.
    Fixed64,
    /// `double`: the eight bytes read as an IEEE double, then converted to an unsigned integer.
    Double,
}

/// T330: the type named by the second argument, `None` when it is not one `HAProxy` knows.
fn pb_type(name: &str) -> Option<PbType> {
    Some(match name {
        "int32" | "uint32" | "int64" | "uint64" | "bool" | "enum" => PbType::Varint,
        "sint32" | "sint64" => PbType::Zigzag,
        "fixed32" => PbType::Fixed32,
        "float" => PbType::Float,
        "sfixed32" => PbType::Sfixed32,
        "fixed64" | "sfixed64" => PbType::Fixed64,
        "double" => PbType::Double,
        _ => return None,
    })
}

/// T330: a dotted field path (`parse_dotted_uints()`): numbers separated by dots, the last one
/// not followed by a dot; an empty number reads as 0 and one too large wraps (`read_uint()`).
fn pb_field_path(s: &str) -> Option<Vec<u32>> {
    let b = s.as_bytes();
    let mut ids = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let mut n = 0u32;
        while let Some(d) = b.get(i).filter(|c| c.is_ascii_digit()) {
            n = n.wrapping_mul(10).wrapping_add(u32::from(d - b'0'));
            i += 1;
        }
        if i < b.len() {
            if b[i] != b'.' {
                return None;
            }
            i += 1;
            if i == b.len() {
                return None;
            }
        }
        ids.push(n);
    }
    Some(ids)
}

/// T330: reads a varint at `*pos` with `*len` bytes left, advancing both (`protobuf_decode_varint()`).
/// `None` when it is cut short or longer than ten bytes.
fn pb_varint(buf: &[u8], pos: &mut usize, len: &mut usize) -> Option<u64> {
    let mut val = 0u64;
    let mut shift = 0u32;
    while *len > 0 {
        let byte = *buf.get(*pos)?;
        val |= u64::from(byte & 0x7f) << shift;
        *pos += 1;
        *len -= 1;
        if byte & 0x80 == 0 {
            break;
        }
        if *len == 0 {
            return None;
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    Some(val)
}

/// T330: the integer part of an IEEE number (`neg` its sign, `m` the magnitude as an integer),
/// as the x86-64 truncating conversion makes it: `None` when it does not fit 64 bits signed,
/// where the processor answers `i64::MIN`.
fn pb_signed(neg: bool, m: u128) -> Option<i64> {
    let m = i64::try_from(m).ok().or_else(|| (neg && m == 1 << 63).then_some(i64::MIN))?;
    Some(if neg { m.wrapping_neg() } else { m })
}

/// T330: the magnitude of an IEEE number with `frac_bits` fraction bits, `exp` the biased
/// exponent and `frac` the fraction, as an integer (a value below one is 0): `None` from 2^64 up.
fn pb_magnitude(exp: u32, frac: u64, frac_bits: u32, bias: u32) -> Option<u128> {
    let Some(e) = exp.checked_sub(bias) else { return Some(0) };
    if e >= 64 {
        return None;
    }
    let mant = u128::from(frac | 1 << frac_bits);
    Some(if e >= frac_bits { mant << (e - frac_bits) } else { mant >> (frac_bits - e) })
}

/// T330: what `HAProxy` makes of a `double` field: the value of the double converted to a 64-bit
/// unsigned integer (as the C compiler does on x86-64), shown as a signed one.
fn pb_double(bits: u64) -> i64 {
    let neg = bits >> 63 != 0;
    let exp = u32::try_from((bits >> 52) & 0x7ff).unwrap_or(0);
    let frac = bits & ((1 << 52) - 1);
    if exp == 0x7ff {
        return if neg || frac != 0 { i64::MIN } else { 0 };
    }
    match pb_magnitude(exp, frac, 52, 1023) {
        None if neg => i64::MIN,
        None => 0,
        Some(m) if neg => pb_signed(true, m).unwrap_or(i64::MIN),
        Some(m) => u64::try_from(m).map_or(0, |u| i64::from_ne_bytes(u.to_ne_bytes())),
    }
}

/// T330: what `HAProxy` makes of a `float` field: the value of the float converted to a 32-bit
/// unsigned integer, that is the low 32 bits of the 64-bit conversion (as on x86-64).
fn pb_float(bits: u32) -> i64 {
    let neg = bits >> 31 != 0;
    let exp = (bits >> 23) & 0xff;
    let v = if exp == 0xff {
        i64::MIN
    } else {
        pb_magnitude(exp, u64::from(bits & 0x7f_ffff), 23, 127).and_then(|m| pb_signed(neg, m)).unwrap_or(i64::MIN)
    };
    let low = v.to_le_bytes();
    i64::from(u32::from_le_bytes([low[0], low[1], low[2], low[3]]))
}

/// T330: the sample for the field value at `pos` (`len` bytes left, `vlen` the length of a
/// length-delimited one), as the `protobuf_smp_store_*()` functions of `HAProxy` make it.
fn pb_store(buf: &[u8], wire: u64, ty: PbType, pos: usize, len: usize, vlen: usize) -> Option<Sample> {
    let fixed = |n: usize| -> Option<&[u8]> { if len < n { None } else { buf.get(pos..pos.checked_add(n)?) } };
    match wire {
        0 => {
            let (mut p, mut l) = (pos, len);
            let v = pb_varint(buf, &mut p, &mut l)?;
            match ty {
                PbType::Binary => Some(Sample::Bin(buf.get(pos..p)?.to_vec())),
                PbType::Varint => Some(Sample::Sint(i64::from_ne_bytes(v.to_ne_bytes()))),
                PbType::Zigzag => Some(Sample::Sint(i64::from_ne_bytes(((v >> 1) ^ (v & 1).wrapping_neg()).to_ne_bytes()))),
                _ => None,
            }
        }
        1 => {
            let b: [u8; 8] = fixed(8)?.try_into().ok()?;
            match ty {
                PbType::Binary => Some(Sample::Bin(b.to_vec())),
                PbType::Fixed64 => Some(Sample::Sint(i64::from_le_bytes(b))),
                PbType::Double => Some(Sample::Sint(pb_double(u64::from_le_bytes(b)))),
                _ => None,
            }
        }
        2 if len >= vlen && ty == PbType::Binary => Some(Sample::Bin(buf.get(pos..pos.checked_add(vlen)?)?.to_vec())),
        5 => {
            let b: [u8; 4] = fixed(4)?.try_into().ok()?;
            match ty {
                PbType::Binary => Some(Sample::Bin(b.to_vec())),
                PbType::Fixed32 => Some(Sample::Sint(i64::from(u32::from_le_bytes(b)))),
                PbType::Sfixed32 => Some(Sample::Sint(i64::from(i32::from_le_bytes(b)))),
                PbType::Float => Some(Sample::Sint(pb_float(u32::from_le_bytes(b)))),
                _ => None,
            }
        }
        _ => None,
    }
}

/// T330: looks the field `ids` up in the message at `*pos` (`*len` bytes), skipping the siblings
/// and entering the length-delimited parents, like `protobuf_field_lookup()` of `HAProxy`.
fn pb_lookup(buf: &[u8], pos: &mut usize, len: &mut usize, ids: &[u32], ty: PbType) -> Option<Sample> {
    let mut depth = 0;
    while *len > 0 && depth < ids.len() {
        let key = pb_varint(buf, pos, len)?;
        let wire = key & 7;
        // HAProxy keeps the field number in an `unsigned int`: the bits above 32 are dropped.
        let found = (key >> 3) & u64::from(u32::MAX) == u64::from(*ids.get(depth)?);
        if wire == 3 || wire == 4 || wire > 5 {
            return None;
        }
        let mut vlen = 0usize;
        if wire == 2 {
            vlen = usize::try_from(pb_varint(buf, pos, len)?).ok().filter(|v| v <= len)?;
        }
        if found {
            if depth + 1 == ids.len() {
                return pb_store(buf, wire, ty, *pos, *len, vlen);
            }
            if wire == 2 {
                *len = vlen;
                depth += 1;
                continue;
            }
            return None;
        }
        match wire {
            0 => {
                pb_varint(buf, pos, len)?;
            }
            1 | 5 => {
                let n = if wire == 1 { 8 } else { 4 };
                *len = len.checked_sub(n)?;
                *pos += n;
            }
            _ => {
                *len -= vlen;
                *pos += vlen;
            }
        }
    }
    None
}

/// T330: `protobuf(<field_number>[,<field_type>])` over the whole sample, or, with `grpc`,
/// `ungrpc(...)`: the same lookup in each gRPC message (5-byte header, then the message) in turn.
fn pb_convert(buf: &[u8], args: &[String], grpc: bool) -> Option<Sample> {
    let ids = pb_field_path(args.first()?)?;
    let ty = match args.get(1) {
        Some(t) => pb_type(t)?,
        None => PbType::Binary,
    };
    let (mut pos, mut left) = (0usize, buf.len());
    if !grpc {
        return pb_lookup(buf, &mut pos, &mut left, &ids, ty);
    }
    while left > 5 {
        let size = buf.get(pos.checked_add(1)?..pos.checked_add(5)?)?;
        let msg_len = usize::try_from(u32::from_be_bytes(size.try_into().ok()?)).ok()?;
        pos += 5;
        left -= 5;
        if left < msg_len {
            return None;
        }
        let mut msg_left = msg_len;
        if let Some(s) = pb_lookup(buf, &mut pos, &mut msg_left, &ids, ty) {
            return Some(s);
        }
        left -= msg_len;
    }
    None
}

/// T331: the body of `capture-req` and `capture-res`: the sample is stored in slot `args[0]`
/// and passed on. A negative or absent id is a slot that does not exist.
fn capture_conv(res: bool, smp: Sample, args: &[String]) -> Option<Sample> {
    if let Some(id) = args.first().and_then(|a| a.trim().parse::<usize>().ok()) {
        // The input was cast to a string before the converter ran.
        crate::capture_write::store(res, id, &ibex_regex::bytetext::text_to_bytes(&sample_to_string(&smp)));
    }
    Some(smp)
}

/// A header capture as a sample: a string, or the bytes when a capture length cut a
/// multi-byte character (captures are bytes, as in `HAProxy`).
fn capture_sample(bytes: Vec<u8>) -> Sample {
    String::from_utf8(bytes).map_or_else(|e| Sample::Bin(e.into_bytes()), Sample::Str)
}

/// T329: `HAProxy`'s varint (`encode_varint`, include/haproxy/intops.h), as `req.hdrs_bin`
/// and `res.hdrs_bin` write lengths: below 240 one byte; otherwise the low four bits of
/// `i` with `0xF0` set, then seven bits per byte with `0x80` set on all but the last.
fn encode_varint(out: &mut Vec<u8>, mut i: u64) {
    let low = |v: u64| v.to_le_bytes()[0];
    if i < 240 {
        out.push(low(i));
        return;
    }
    out.push(low(i) | 0xF0);
    i = (i - 240) >> 4;
    while i >= 128 {
        out.push(low(i) | 0x80);
        i = (i - 128) >> 7;
    }
    out.push(low(i));
}

#[cfg(test)]
mod varint_tests {
    use super::encode_varint;

    fn enc(i: u64) -> Vec<u8> {
        let mut v = Vec::new();
        encode_varint(&mut v, i);
        v
    }

    /// The decoder of include/haproxy/intops.h (`decode_varint`), to check round trips.
    fn dec(b: &[u8]) -> u64 {
        let mut i = u64::from(b[0]);
        if i < 240 {
            return i;
        }
        let mut r = 4;
        for &c in &b[1..] {
            i = i.wrapping_add(u64::from(c).wrapping_shl(r));
            r += 7;
        }
        i
    }

    #[test]
    fn boundaries() {
        // Values measured on HAProxy 3.5-dev8 through req.hdrs_bin (239, 240, 300, 2287,
        // 2288, 5000) and the C algorithm for the rest.
        assert_eq!(enc(0), [0x00]);
        assert_eq!(enc(239), [0xEF]);
        assert_eq!(enc(240), [0xF0, 0x00]);
        assert_eq!(enc(300), [0xFC, 0x03]);
        assert_eq!(enc(2287), [0xFF, 0x7F]);
        assert_eq!(enc(2288), [0xF0, 0x80, 0x00]);
        assert_eq!(enc(4095), [0xFF, 0xF0, 0x00]);
        assert_eq!(enc(4096), [0xF0, 0xF1, 0x00]);
        assert_eq!(enc(5000), [0xF8, 0xA9, 0x01]);
        assert_eq!(enc(1 << 20), [0xF0, 0xF1, 0xFE, 0x02]);
        assert_eq!(enc(u64::MAX), [0xFF, 0xF0, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0x0E]);
        for i in [0, 239, 240, 4095, 4096, 1 << 20, u64::MAX - 1, u64::MAX] {
            assert_eq!(dec(&enc(i)), i, "{i}");
        }
    }
}

/// T329: `req.hdrs_bin` / `res.hdrs_bin` of a message's headers (`smp_fetch_hdrs_bin`): each
/// header of [`h1_htx_headers`] as varint name length, lowercase name, varint value length,
/// value; then two zero bytes.
fn hdrs_bin<'a>(headers: impl Iterator<Item = (&'a str, &'a str)>, request: bool) -> Sample {
    let mut buf = Vec::new();
    for (name, value) in h1_htx_headers(headers, request) {
        encode_varint(&mut buf, name.len() as u64);
        buf.extend(name.bytes().map(|b| b.to_ascii_lowercase()));
        encode_varint(&mut buf, value.len() as u64);
        buf.extend_from_slice(value.as_bytes());
    }
    buf.extend_from_slice(&[0, 0]);
    Sample::Bin(buf)
}

/// T329: The headers of an HTTP/1 message as `HAProxy` puts them in its HTX, which Ibex keeps
/// as received. `Connection` loses its `close` and `keep-alive` tokens
/// (`h1_parse_connection_header` with `H1_MF_CLEAN_CONN_HDR`) and `Upgrade` its `h2c` and
/// `h2` ones (`h1_parse_upgrade_header`); a header left empty goes. For a request
/// (`h1_postparse_req_hdrs`), `Upgrade` goes without a `Connection: upgrade`, and the
/// `upgrade` token goes from `Connection` without an `Upgrade`. Names and order unchanged.
fn h1_htx_headers<'a>(headers: impl Iterator<Item = (&'a str, &'a str)>, request: bool) -> Vec<(&'a str, std::borrow::Cow<'a, str>)> {
    let is = |w: &str, t: &str| w.eq_ignore_ascii_case(t);
    let (mut conn_upg, mut upg_hdr) = (false, false);
    let mut out = Vec::new();
    for (name, value) in headers {
        let value = if is(name, "connection") {
            clean_header_list(value, |w| {
                conn_upg |= is(w, "upgrade");
                is(w, "close") || is(w, "keep-alive")
            })
        } else if is(name, "upgrade") {
            let v = clean_header_list(value, |w| is(w, "h2c") || is(w, "h2"));
            upg_hdr |= !v.is_empty();
            v
        } else {
            std::borrow::Cow::Borrowed(value)
        };
        if !value.is_empty() || (!is(name, "connection") && !is(name, "upgrade")) {
            out.push((name, value));
        }
    }
    if request && upg_hdr && !conn_upg {
        out.retain(|(n, _)| !is(n, "upgrade"));
    } else if request && conn_upg && !upg_hdr {
        out = out
            .into_iter()
            .filter_map(|(n, v)| {
                if !is(n, "connection") {
                    return Some((n, v));
                }
                let v = clean_header_list(&v, |w| is(w, "upgrade")).into_owned();
                (!v.is_empty()).then_some((n, std::borrow::Cow::Owned(v)))
            })
            .collect();
    }
    out
}

/// T329: `HAProxy`'s in-place cleanup of a comma-separated header value
/// (`h1_parse_connection_header`, `h1_parse_upgrade_header`, `http_remove_header_value`):
/// the words `drop` matches (each trimmed of blanks; commas inside quotes do not split) go.
/// Until one has gone the value is kept as written, up to the end of the last element
/// kept; after that each kept word is appended trimmed, after a `,`.
fn clean_header_list(value: &str, mut drop: impl FnMut(&str) -> bool) -> std::borrow::Cow<'_, str> {
    let bytes = value.as_bytes();
    let lws = |ch: u8| matches!(ch, b' ' | b'\t' | b'\r' | b'\n');
    // The end of the element starting at `at`: the next comma outside quotes (`http_find_hdr_value_end`).
    let elem_end = |mut at: usize| {
        let (mut quoted, mut qdpair) = (false, false);
        while at < bytes.len() {
            let ch = bytes[at];
            if qdpair {
                qdpair = false;
            } else if quoted {
                if ch == b'\\' {
                    qdpair = true;
                } else if ch == b'"' {
                    quoted = false;
                }
            } else if ch == b'"' {
                quoted = true;
            } else if ch == b',' {
                return at;
            }
            at += 1;
        }
        at
    };
    let (mut start, mut elem_start, mut kept) = (0, 0, 0);
    let mut rewritten: Option<String> = None;
    while start < bytes.len() {
        if lws(bytes[start]) {
            start += 1;
            continue;
        }
        let end = elem_end(start);
        let mut word_end = end;
        while word_end > start && lws(bytes[word_end - 1]) {
            word_end -= 1;
        }
        let word = &value[start..word_end];
        if !drop(word) {
            match &mut rewritten {
                None if kept == elem_start => kept = end,
                None => rewritten = Some(if kept == 0 { word.to_string() } else { format!("{},{word}", &value[..kept]) }),
                Some(r) => {
                    if !r.is_empty() {
                        r.push(',');
                    }
                    r.push_str(word);
                }
            }
        }
        elem_start = end;
        start = end + 1;
    }
    rewritten.map_or(std::borrow::Cow::Borrowed(&value[..kept]), std::borrow::Cow::Owned)
}

#[cfg(test)]
mod ip_header_length_tests {
    use super::Registry;

    /// `ip.fp` checks the packet is a whole IPv4 or IPv6 header before it asks for the length,
    /// so the arms of `Registry::ip_header_length` for a short IPv6 packet and for another IP
    /// version are never reached through a configuration (no oracle value exists for them); they
    /// are the same answers as the `ip.hdr` helper gives for the same bytes.
    #[test]
    fn short_ipv6_and_other_versions_have_no_length() {
        assert_eq!(Registry::ip_header_length(&[0x60, 0, 0, 0]), None);
        assert_eq!(Registry::ip_header_length(&[0x70; 40]), None);
        assert_eq!(Registry::ip_header_length(&[]), None);
        // a complete IPv4 header and an IPv6 one with TCP next
        let mut v4 = vec![0u8; 20];
        v4[0] = 0x45;
        assert_eq!(Registry::ip_header_length(&v4), Some(20));
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        v6[6] = 6;
        assert_eq!(Registry::ip_header_length(&v6), Some(40));
    }
}

/// The count argument of `field` and `word` (an integer; anything else is refused at load).
/// T359: parse as i64 and keep low 32 bits as C `int` does.
fn parse_count(arg: &str) -> i32 {
    let n = arg.parse::<i64>().unwrap_or_else(|_| if arg.starts_with('-') { i64::MIN } else { i64::MAX });
    // The low 32 bits, as C's `int` assignment keeps them: the truncation is the point.
    #[allow(clippy::cast_possible_truncation)]
    let v = n as i32;
    v
}
