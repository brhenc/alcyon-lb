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
use regex::RegexBuilder;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, LazyLock, RwLock};

thread_local! {
    pub static CURRENT_VARS: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
    pub static CURRENT_TIMEOUTS: RefCell<HashMap<&'static str, u32>> = RefCell::new(HashMap::new());
    pub static CURRENT_RES_HEADERS: RefCell<Vec<(String, String)>> = const { RefCell::new(Vec::new()) };
    pub static CURRENT_RES_STATUS: Cell<u16> = const { Cell::new(0) };
}

pub static GLOBAL_PROC_VARS: LazyLock<RwLock<HashMap<String, String>>> =
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

#[allow(clippy::implicit_hasher)]
pub fn set_current_timeouts(timeouts: HashMap<&'static str, u32>) {
    CURRENT_TIMEOUTS.with(|t| *t.borrow_mut() = timeouts);
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

/// Runtime context passed into sample fetch functions during evaluation.
#[derive(Debug, Clone, Default)]
pub struct SampleContext<'a> {
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
    pub captures_req_hdr: Option<&'a [String]>,
    pub captures_res_hdr: Option<&'a [String]>,
    pub vars: Option<&'a HashMap<String, String>>,
    pub timeouts: Option<&'a HashMap<String, u32>>,
    pub act_conn: u32,
    pub cum_conn: u64,
    pub conn_cnt: u64,
    pub conn_rate: u64,
    pub http_req_rate: u64,
    pub http_err_rate: u64,
    pub http_req_cnt: u64,
    pub bytes_in_cnt: u64,
    pub bytes_out_cnt: u64,
    pub gpc0: u64,
    pub gpc1: u64,
    pub gpt0: u64,
    pub sc_conn_rates: [u64; 3],
    pub sc_http_req_rates: [u64; 3],
    pub sc_http_err_rates: [u64; 3],
    pub sc_conn_cnts: [u64; 3],
    pub sc_http_req_cnts: [u64; 3],
    pub sc_bytes_in_cnts: [u64; 3],
    pub sc_bytes_out_cnts: [u64; 3],
    pub ssl_sni: Option<&'a str>,
    pub ssl_cipher: Option<&'a str>,
    pub ssl_version: Option<&'a str>,
    pub ssl_used: bool,
}

/// A sample fetch implementation.
pub type FetchFn = fn(&SampleContext, &[String]) -> Option<Sample>;

/// A sample converter implementation.
pub type ConvFn = fn(Sample, &[String]) -> Option<Sample>;

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

    #[must_use]
    pub fn get_fetch(&self, name: &str) -> Option<&FetchDesc> {
        self.fetches.get(name)
    }

    #[must_use]
    pub fn get_converter(&self, name: &str) -> Option<&ConvDesc> {
        self.converters.get(name)
    }

    #[must_use]
    pub fn fetch_count(&self) -> usize {
        self.fetches.len()
    }

    #[must_use]
    pub fn converter_count(&self) -> usize {
        self.converters.len()
    }

    #[must_use]
    pub fn fetch_names(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self.fetches.keys().copied().collect();
        names.sort_unstable();
        names
    }

    #[must_use]
    pub fn converter_names(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self.converters.keys().copied().collect();
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

        let dst_port_fetch: FetchFn =
            |ctx, _args| ctx.server_addr.map(|sa| Sample::Sint(i64::from(sa.port())));
        let fc_dst_port_fetch: FetchFn =
            |ctx, _args| ctx.fc_dst.or(ctx.server_addr).map(|sa| Sample::Sint(i64::from(sa.port())));
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

        self.register_fetch(FetchDesc {
            name: "method",
            out_type: SampleType::Meth,
            func: |ctx, _args| {
                if let Some(m_str) = get_context_method(ctx) {
                    return Some(Sample::Meth(ibex_proto::htx::HttpMethod::from_bytes(
                        m_str.as_bytes(),
                    )));
                }
                ctx.htx?
                    .req_line()
                    .map(|req| Sample::Meth(req.method.clone()))
            },
        });

        let request_version_fetch: FetchFn = |ctx, _args| {
            if let Some(v) = get_context_req_version(ctx) {
                return Some(Sample::Str(v.to_string()));
            }
            if let Some(htx) = ctx.htx {
                if let Some(req) = htx.req_line() {
                    return Some(Sample::Str(req.version.as_str().to_string()));
                }
            }
            Some(Sample::Str("HTTP/1.1".to_string()))
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

        let response_version_fetch: FetchFn = |ctx, _args| {
            if let Some(v) = get_context_res_version(ctx) {
                return Some(Sample::Str(v.to_string()));
            }
            if let Some(htx) = ctx.htx {
                if let Some(res) = htx.res_line() {
                    return Some(Sample::Str(res.version.as_str().to_string()));
                }
            }
            Some(Sample::Str("HTTP/1.1".to_string()))
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

        let request_payload_fetch: FetchFn = |ctx, args| {
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
        };
        self.register_fetch(FetchDesc {
            name: "req.payload",
            out_type: SampleType::Bin,
            func: request_payload_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "payload",
            out_type: SampleType::Bin,
            func: request_payload_fetch,
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

        // --- 7. Captures ---
        self.register_fetch(FetchDesc {
            name: "capture.req.hdr",
            out_type: SampleType::Str,
            func: |ctx, args| {
                let idx_str = args.first()?;
                let idx: usize = idx_str.parse().ok()?;
                let caps = ctx.captures_req_hdr?;
                caps.get(idx).cloned().map(Sample::Str)
            },
        });

        self.register_fetch(FetchDesc {
            name: "capture.res.hdr",
            out_type: SampleType::Str,
            func: |ctx, args| {
                let idx_str = args.first()?;
                let idx: usize = idx_str.parse().ok()?;
                let caps = ctx.captures_res_hdr?;
                caps.get(idx).cloned().map(Sample::Str)
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
            func: |ctx, _args| ctx.be_name.map(|n| Sample::Str(n.to_string())),
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
        self.register_fetch(FetchDesc {
            name: "srv_is_up",
            out_type: SampleType::Bool,
            func: |_ctx, _args| Some(Sample::Bool(true)),
        });
        self.register_fetch(FetchDesc {
            name: "nbsrv",
            out_type: SampleType::Sint,
            func: |_ctx, _args| Some(Sample::Sint(1)),
        });
        self.register_fetch(FetchDesc {
            name: "srv_queue",
            out_type: SampleType::Sint,
            func: |_ctx, _args| Some(Sample::Sint(0)),
        });
        self.register_fetch(FetchDesc {
            name: "avg_queue",
            out_type: SampleType::Sint,
            func: |_ctx, _args| Some(Sample::Sint(0)),
        });
        self.register_fetch(FetchDesc {
            name: "queue",
            out_type: SampleType::Sint,
            func: |_ctx, _args| Some(Sample::Sint(0)),
        });
        self.register_fetch(FetchDesc {
            name: "srv_conn",
            out_type: SampleType::Sint,
            func: |_ctx, _args| Some(Sample::Sint(0)),
        });
        self.register_fetch(FetchDesc {
            name: "srv_conn_free",
            out_type: SampleType::Sint,
            func: |_ctx, _args| Some(Sample::Sint(100)),
        });
        self.register_fetch(FetchDesc {
            name: "be_conn",
            out_type: SampleType::Sint,
            func: |_ctx, _args| Some(Sample::Sint(0)),
        });
        self.register_fetch(FetchDesc {
            name: "be_conn_free",
            out_type: SampleType::Sint,
            func: |_ctx, _args| Some(Sample::Sint(100)),
        });
        self.register_fetch(FetchDesc {
            name: "fe_conn",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(i64::from(ctx.act_conn))),
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
            func: |ctx, _args| Some(Sample::Sint(i64::from(ctx.act_conn))),
        });
        self.register_fetch(FetchDesc {
            name: "dst_conn",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(i64::from(ctx.act_conn))),
        });
        self.register_fetch(FetchDesc {
            name: "conn_cnt",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.conn_cnt))),
        });
        self.register_fetch(FetchDesc {
            name: "cum_conn",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.cum_conn))),
        });
        self.register_fetch(FetchDesc {
            name: "conn_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.conn_rate))),
        });
        self.register_fetch(FetchDesc {
            name: "sess_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.conn_rate))),
        });
        self.register_fetch(FetchDesc {
            name: "fe_sess_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.conn_rate))),
        });
        self.register_fetch(FetchDesc {
            name: "be_sess_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.conn_rate))),
        });
        self.register_fetch(FetchDesc {
            name: "srv_sess_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.conn_rate))),
        });
        self.register_fetch(FetchDesc {
            name: "sess_cnt",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.conn_cnt))),
        });
        self.register_fetch(FetchDesc {
            name: "req_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.http_req_rate))),
        });
        self.register_fetch(FetchDesc {
            name: "fe_req_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.http_req_rate))),
        });
        self.register_fetch(FetchDesc {
            name: "req_cnt",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.http_req_cnt))),
        });
        self.register_fetch(FetchDesc {
            name: "err_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.http_err_rate))),
        });
        self.register_fetch(FetchDesc {
            name: "err_cnt",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.http_err_rate))),
        });

        // --- 10. Stick Table Trackers Fetches ---
        macro_rules! reg_sc_fetches {
            ($name:literal, $field:ident, $arr:ident) => {
                self.register_fetch(FetchDesc {
                    name: $name,
                    out_type: SampleType::Sint,
                    func: |ctx, args| {
                        let slot = args
                            .first()
                            .and_then(|s| s.parse::<usize>().ok())
                            .unwrap_or(0);
                        if slot < 3 && ctx.$arr[slot] > 0 {
                            Some(Sample::Sint(u64_to_sint(ctx.$arr[slot])))
                        } else {
                            Some(Sample::Sint(u64_to_sint(ctx.$field)))
                        }
                    },
                });
            };
        }

        reg_sc_fetches!("sc_conn_cnt", conn_cnt, sc_conn_cnts);
        reg_sc_fetches!("sc_conn_rate", conn_rate, sc_conn_rates);
        reg_sc_fetches!("sc_http_req_rate", http_req_rate, sc_http_req_rates);
        reg_sc_fetches!("sc_http_err_rate", http_err_rate, sc_http_err_rates);
        reg_sc_fetches!("sc_http_req_cnt", http_req_cnt, sc_http_req_cnts);
        reg_sc_fetches!("sc_bytes_in_cnt", bytes_in_cnt, sc_bytes_in_cnts);
        reg_sc_fetches!("sc_bytes_out_cnt", bytes_out_cnt, sc_bytes_out_cnts);

        self.register_fetch(FetchDesc {
            name: "sc_conn_cur",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(i64::from(ctx.act_conn))),
        });
        self.register_fetch(FetchDesc {
            name: "sc_sess_cnt",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.conn_cnt))),
        });
        self.register_fetch(FetchDesc {
            name: "sc_sess_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.conn_rate))),
        });
        self.register_fetch(FetchDesc {
            name: "sc_http_err_cnt",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.http_err_rate))),
        });
        self.register_fetch(FetchDesc {
            name: "sc_bytes_in_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.bytes_in_cnt))),
        });
        self.register_fetch(FetchDesc {
            name: "sc_bytes_out_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.bytes_out_cnt))),
        });
        self.register_fetch(FetchDesc {
            name: "sc_kbytes_in",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.bytes_in_cnt / 1024))),
        });
        self.register_fetch(FetchDesc {
            name: "sc_kbytes_out",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.bytes_out_cnt / 1024))),
        });
        self.register_fetch(FetchDesc {
            name: "sc_trackers",
            out_type: SampleType::Sint,
            func: |_ctx, _args| Some(Sample::Sint(1)),
        });
        self.register_fetch(FetchDesc {
            name: "sc_gpc0",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.gpc0))),
        });
        self.register_fetch(FetchDesc {
            name: "sc_gpc1",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.gpc1))),
        });
        self.register_fetch(FetchDesc {
            name: "sc_gpc0_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.gpc0))),
        });
        self.register_fetch(FetchDesc {
            name: "sc_gpc1_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.gpc1))),
        });
        self.register_fetch(FetchDesc {
            name: "sc_gpt0",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.gpt0))),
        });

        // sc0_*, sc1_*, sc2_* aliases
        macro_rules! reg_sc_slot {
            ($slot:expr, $prefix:literal) => {
                self.register_fetch(FetchDesc {
                    name: concat!($prefix, "conn_cnt"),
                    out_type: SampleType::Sint,
                    func: |ctx, _args| {
                        if ctx.sc_conn_cnts[$slot] > 0 {
                            Some(Sample::Sint(u64_to_sint(ctx.sc_conn_cnts[$slot])))
                        } else {
                            Some(Sample::Sint(u64_to_sint(ctx.conn_cnt)))
                        }
                    },
                });
                self.register_fetch(FetchDesc {
                    name: concat!($prefix, "conn_rate"),
                    out_type: SampleType::Sint,
                    func: |ctx, _args| {
                        if ctx.sc_conn_rates[$slot] > 0 {
                            Some(Sample::Sint(u64_to_sint(ctx.sc_conn_rates[$slot])))
                        } else {
                            Some(Sample::Sint(u64_to_sint(ctx.conn_rate)))
                        }
                    },
                });
                self.register_fetch(FetchDesc {
                    name: concat!($prefix, "http_req_rate"),
                    out_type: SampleType::Sint,
                    func: |ctx, _args| {
                        if ctx.sc_http_req_rates[$slot] > 0 {
                            Some(Sample::Sint(u64_to_sint(ctx.sc_http_req_rates[$slot])))
                        } else {
                            Some(Sample::Sint(u64_to_sint(ctx.http_req_rate)))
                        }
                    },
                });
                self.register_fetch(FetchDesc {
                    name: concat!($prefix, "http_err_rate"),
                    out_type: SampleType::Sint,
                    func: |ctx, _args| {
                        if ctx.sc_http_err_rates[$slot] > 0 {
                            Some(Sample::Sint(u64_to_sint(ctx.sc_http_err_rates[$slot])))
                        } else {
                            Some(Sample::Sint(u64_to_sint(ctx.http_err_rate)))
                        }
                    },
                });
                self.register_fetch(FetchDesc {
                    name: concat!($prefix, "http_req_cnt"),
                    out_type: SampleType::Sint,
                    func: |ctx, _args| {
                        if ctx.sc_http_req_cnts[$slot] > 0 {
                            Some(Sample::Sint(u64_to_sint(ctx.sc_http_req_cnts[$slot])))
                        } else {
                            Some(Sample::Sint(u64_to_sint(ctx.http_req_cnt)))
                        }
                    },
                });
                self.register_fetch(FetchDesc {
                    name: concat!($prefix, "bytes_in_cnt"),
                    out_type: SampleType::Sint,
                    func: |ctx, _args| {
                        if ctx.sc_bytes_in_cnts[$slot] > 0 {
                            Some(Sample::Sint(u64_to_sint(ctx.sc_bytes_in_cnts[$slot])))
                        } else {
                            Some(Sample::Sint(u64_to_sint(ctx.bytes_in_cnt)))
                        }
                    },
                });
                self.register_fetch(FetchDesc {
                    name: concat!($prefix, "bytes_out_cnt"),
                    out_type: SampleType::Sint,
                    func: |ctx, _args| {
                        if ctx.sc_bytes_out_cnts[$slot] > 0 {
                            Some(Sample::Sint(u64_to_sint(ctx.sc_bytes_out_cnts[$slot])))
                        } else {
                            Some(Sample::Sint(u64_to_sint(ctx.bytes_out_cnt)))
                        }
                    },
                });
            };
        }

        reg_sc_slot!(0, "sc0_");
        reg_sc_slot!(1, "sc1_");
        reg_sc_slot!(2, "sc2_");

        // src_* stick table metrics
        self.register_fetch(FetchDesc {
            name: "src_conn_cnt",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.conn_cnt))),
        });
        self.register_fetch(FetchDesc {
            name: "src_conn_cur",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(i64::from(ctx.act_conn))),
        });
        self.register_fetch(FetchDesc {
            name: "src_conn_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.conn_rate))),
        });
        self.register_fetch(FetchDesc {
            name: "src_sess_cnt",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.conn_cnt))),
        });
        self.register_fetch(FetchDesc {
            name: "src_sess_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.conn_rate))),
        });
        self.register_fetch(FetchDesc {
            name: "src_http_req_cnt",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.http_req_cnt))),
        });
        self.register_fetch(FetchDesc {
            name: "src_http_req_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.http_req_rate))),
        });
        self.register_fetch(FetchDesc {
            name: "src_http_err_cnt",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.http_err_rate))),
        });
        self.register_fetch(FetchDesc {
            name: "src_http_err_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.http_err_rate))),
        });
        self.register_fetch(FetchDesc {
            name: "src_bytes_in_cnt",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.bytes_in_cnt))),
        });
        self.register_fetch(FetchDesc {
            name: "src_bytes_in_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.bytes_in_cnt))),
        });
        self.register_fetch(FetchDesc {
            name: "src_bytes_out_cnt",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.bytes_out_cnt))),
        });
        self.register_fetch(FetchDesc {
            name: "src_bytes_out_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.bytes_out_cnt))),
        });
        self.register_fetch(FetchDesc {
            name: "src_kbytes_in",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.bytes_in_cnt / 1024))),
        });
        self.register_fetch(FetchDesc {
            name: "src_kbytes_out",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.bytes_out_cnt / 1024))),
        });
        self.register_fetch(FetchDesc {
            name: "src_trackers",
            out_type: SampleType::Sint,
            func: |_ctx, _args| Some(Sample::Sint(1)),
        });
        self.register_fetch(FetchDesc {
            name: "src_gpc0",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.gpc0))),
        });
        self.register_fetch(FetchDesc {
            name: "src_gpc1",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.gpc1))),
        });
        self.register_fetch(FetchDesc {
            name: "src_gpc0_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.gpc0))),
        });
        self.register_fetch(FetchDesc {
            name: "src_gpc1_rate",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.gpc1))),
        });
        self.register_fetch(FetchDesc {
            name: "src_gpt0",
            out_type: SampleType::Sint,
            func: |ctx, _args| Some(Sample::Sint(u64_to_sint(ctx.gpt0))),
        });
        self.register_fetch(FetchDesc {
            name: "src_in_table",
            out_type: SampleType::Bool,
            func: |_ctx, _args| Some(Sample::Bool(true)),
        });

        // --- 11. Timeout Fetches ---
        macro_rules! reg_timeout_fetch {
            ($name:literal) => {
                self.register_fetch(FetchDesc {
                    name: $name,
                    out_type: SampleType::Sint,
                    func: |ctx, _args| {
                        if let Some(t_map) = ctx.timeouts {
                            if let Some(&v) = t_map.get($name) {
                                return Some(Sample::Sint(i64::from(v)));
                            }
                        }
                        CURRENT_TIMEOUTS.with(|t| {
                            t.borrow()
                                .get($name)
                                .copied()
                                .map(|v| Sample::Sint(i64::from(v)))
                        })
                    },
                });
            };
        }

        reg_timeout_fetch!("fe_client_timeout");
        reg_timeout_fetch!("cur_client_timeout");
        reg_timeout_fetch!("be_server_timeout");
        reg_timeout_fetch!("cur_server_timeout");
        reg_timeout_fetch!("be_connect_timeout");
        reg_timeout_fetch!("cur_connect_timeout");
        reg_timeout_fetch!("be_queue_timeout");
        reg_timeout_fetch!("cur_queue_timeout");
        reg_timeout_fetch!("be_tunnel_timeout");
        reg_timeout_fetch!("cur_tunnel_timeout");
        reg_timeout_fetch!("be_tarpit_timeout");
        reg_timeout_fetch!("cur_tarpit_timeout");
        reg_timeout_fetch!("fe_connect_timeout");
        reg_timeout_fetch!("fe_server_timeout");
        reg_timeout_fetch!("fe_queue_timeout");
        reg_timeout_fetch!("fe_tunnel_timeout");
        reg_timeout_fetch!("fe_tarpit_timeout");
        reg_timeout_fetch!("be_client_timeout");

        // --- 12. SSL Fetches ---
        self.register_fetch(FetchDesc {
            name: "ssl_fc_sni",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.ssl_sni.map(|sni| Sample::Str(sni.to_string())),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc",
            out_type: SampleType::Bool,
            func: |ctx, _args| Some(Sample::Bool(ctx.ssl_used || ctx.ssl_sni.is_some())),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_c_used",
            out_type: SampleType::Bool,
            func: |ctx, _args| Some(Sample::Bool(ctx.ssl_used || ctx.ssl_sni.is_some())),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_cipher",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.ssl_cipher.map(|c| Sample::Str(c.to_string())),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_protocol",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.ssl_version.map(|v| Sample::Str(v.to_string())),
        });
        self.register_fetch(FetchDesc {
            name: "ssl_fc_version",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.ssl_version.map(|v| Sample::Str(v.to_string())),
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
                Some(Sample::Str(s.to_string()))
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
        let date_fetch: FetchFn = |_ctx, _args| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            Some(Sample::Sint(u64_to_sint(now.as_secs())))
        };
        self.register_fetch(FetchDesc {
            name: "date",
            out_type: SampleType::Sint,
            func: date_fetch,
        });
        self.register_fetch(FetchDesc {
            name: "epoch",
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
        self.register_converter(ConvDesc {
            name: "length",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: len_conv,
        });

        self.register_converter(ConvDesc {
            name: "concat",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| match smp {
                Sample::Str(mut s) => {
                    for arg in args {
                        let piece = CURRENT_VARS
                            .with(|v| v.borrow().get(arg).cloned())
                            .unwrap_or_else(|| arg.clone());
                        s.push_str(&piece);
                    }
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
                if len == 0 {
                    return Some(Sample::Str(String::new()));
                }
                let start_idx = match idx.cmp(&0) {
                    std::cmp::Ordering::Greater => {
                        usize::try_from(idx).unwrap_or(usize::MAX).saturating_sub(1)
                    }
                    std::cmp::Ordering::Less => len.saturating_sub(
                        usize::try_from(idx.saturating_neg()).unwrap_or(usize::MAX),
                    ),
                    std::cmp::Ordering::Equal => return None,
                };
                if start_idx >= len {
                    return Some(Sample::Str(String::new()));
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
                let delim_char = args.get(1).and_then(|d| d.chars().next()).unwrap_or(' ');
                let count_str = args.get(2);

                let idx: i64 = idx_str.parse().ok()?;
                let count: usize = count_str.and_then(|c| c.parse().ok()).unwrap_or(1);

                let Sample::Str(s) = smp else { return None };
                let words: Vec<&str> = s.split(delim_char).filter(|w| !w.is_empty()).collect();
                let len = words.len();
                if len == 0 {
                    return Some(Sample::Str(String::new()));
                }
                let start_idx = match idx.cmp(&0) {
                    std::cmp::Ordering::Greater => {
                        usize::try_from(idx).unwrap_or(usize::MAX).saturating_sub(1)
                    }
                    std::cmp::Ordering::Less => len.saturating_sub(
                        usize::try_from(idx.saturating_neg()).unwrap_or(usize::MAX),
                    ),
                    std::cmp::Ordering::Equal => return None,
                };
                if start_idx >= len {
                    return Some(Sample::Str(String::new()));
                }
                let end_idx = if count == 0 {
                    len
                } else {
                    (start_idx + count).min(len)
                };
                let joined = words[start_idx..end_idx].join(&delim_char.to_string());
                Some(Sample::Str(joined))
            },
        });

        self.register_converter(ConvDesc {
            name: "param",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                let param_name = args.first()?;
                let delim = args.get(1).map_or("&", String::as_str);
                let Sample::Str(s) = smp else { return None };
                for pair in s.split(delim) {
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
                let item = args.first()?;
                let delim = args.get(1).map_or(",", String::as_str);
                let Sample::Str(s) = smp else { return None };
                if s.is_empty() {
                    Some(Sample::Str(item.clone()))
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
                Sample::Str(s) => Some(Sample::Str(s.trim_end_matches(['\r', '\n']).to_string())),
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
                Sample::Str(s) => {
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
                Sample::Str(s) => {
                    let host = if let Some(stripped) = s.strip_prefix('[') {
                        stripped.split(']').next().unwrap_or(&s)
                    } else if let Some((h, _)) = s.split_once(':') {
                        h
                    } else {
                        &s
                    };
                    Some(Sample::Str(host.to_string()))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "port_only",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Str(s) => {
                    let port_str = if s.starts_with('[') {
                        s.split("]:").nth(1)
                    } else {
                        s.split_once(':').map(|(_, p)| p)
                    }?;
                    port_str.parse::<i64>().ok().map(Sample::Sint)
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
            func: |smp, _args| match smp {
                Sample::Str(s) => Some(Sample::Str(url_decode(&s))),
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
                    return None;
                }
                match smp {
                    Sample::Sint(n) => Some(Sample::Sint(n / divisor)),
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
                    return None;
                }
                match smp {
                    Sample::Sint(n) => Some(Sample::Sint(n % divisor)),
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

        self.register_converter(ConvDesc {
            name: "when",
            in_type: TypeSpec::Any,
            out_type: TypeSpec::Same,
            func: |smp, args| {
                let op = args.first()?;
                let val = args.get(1)?;
                let matches = match op.as_str() {
                    "eq" => sample_to_string(&smp) == *val,
                    "ne" => sample_to_string(&smp) != *val,
                    "gt" => {
                        let a: i64 = sample_to_string(&smp).parse().ok()?;
                        let b: i64 = val.parse().ok()?;
                        a > b
                    }
                    "ge" => {
                        let a: i64 = sample_to_string(&smp).parse().ok()?;
                        let b: i64 = val.parse().ok()?;
                        a >= b
                    }
                    "lt" => {
                        let a: i64 = sample_to_string(&smp).parse().ok()?;
                        let b: i64 = val.parse().ok()?;
                        a < b
                    }
                    "le" => {
                        let a: i64 = sample_to_string(&smp).parse().ok()?;
                        let b: i64 = val.parse().ok()?;
                        a <= b
                    }
                    _ => false,
                };
                if matches {
                    if let Some(res) = args.get(2) {
                        Some(Sample::Str(res.clone()))
                    } else {
                        Some(smp)
                    }
                } else {
                    None
                }
            },
        });

        // --- 3. Encoding & Binary Converters ---
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
                    let clean = s.trim().trim_start_matches("0x").trim_start_matches("0X");
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
                Sample::Str(s) => base64_decode(&s).map(Sample::Bin),
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
                Sample::Str(s) => base64_decode(&s).map(Sample::Bin),
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
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    let mut n: u64 = 0;
                    for byte in b.iter().take(8) {
                        n = (n << 8) | u64::from(*byte);
                    }
                    Some(Sample::Str(n.to_string()))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "le2dec",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    let mut n: u64 = 0;
                    for (i, byte) in b.iter().take(8).enumerate() {
                        n |= u64::from(*byte) << (i * 8);
                    }
                    Some(Sample::Str(n.to_string()))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "be2hex",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Str(hex_encode(&b))),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "be_sort",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, _args| match smp {
                Sample::Bin(mut b) => {
                    b.sort_unstable();
                    Some(Sample::Bin(b))
                }
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "has_ctl",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Bool),
            func: |smp, _args| match smp {
                Sample::Bin(b) => {
                    let has = b
                        .iter()
                        .any(|&c| c < 32 && c != b'\t' && c != b'\r' && c != b'\n');
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
                    let offset = args.first()?.parse::<usize>().ok()?;
                    let len = args.get(1)?.parse::<usize>().ok()?;
                    if offset >= b.len() {
                        Some(Sample::Bin(Vec::new()))
                    } else {
                        let end = (offset + len).min(b.len());
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
                        let chosen_mask = mask2_str.unwrap_or(mask1_str);
                        let mask = if let Ok(prefix) = chosen_mask.parse::<u32>() {
                            if prefix == 0 {
                                0
                            } else if prefix >= 128 {
                                u128::MAX
                            } else {
                                !((1u128 << (128 - prefix)) - 1)
                            }
                        } else if let Ok(m_ip) = chosen_mask.parse::<Ipv6Addr>() {
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
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Sint(i64::from(hash_crc32(&b)))),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "crc32c",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Sint(i64::from(hash_crc32c(&b)))),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "djb2",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Sint(i64::from(hash_djb2(&b)))),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "sdbm",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Sint(i64::from(hash_sdbm(&b)))),
                _ => None,
            },
        });

        self.register_converter(ConvDesc {
            name: "wt6",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Sint(i64::from(hash_wt6(&b)))),
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
        let json_conv: ConvFn = |smp, args| {
            let path = args.first()?;
            let Sample::Str(s) = smp else { return None };
            json_extract(&s, path).map(Sample::Str)
        };
        self.register_converter(ConvDesc {
            name: "json",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: json_conv,
        });
        self.register_converter(ConvDesc {
            name: "json_query",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Any,
            func: json_conv,
        });

        // --- 7. Time & Date Converters ---
        self.register_converter(ConvDesc {
            name: "http_date",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                let offset = args.first().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
                match smp {
                    Sample::Sint(epoch) => Some(Sample::Str(format_http_date(epoch + offset))),
                    _ => None,
                }
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

        let ltime_conv: ConvFn = |smp, args| {
            let fmt = args.first().map_or("%d/%b/%Y:%H:%M:%S", String::as_str);
            let offset = args.get(1).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
            match smp {
                Sample::Sint(epoch) => Some(Sample::Str(format_time(epoch + offset, fmt))),
                _ => None,
            }
        };
        self.register_converter(ConvDesc {
            name: "ltime",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: ltime_conv,
        });
        self.register_converter(ConvDesc {
            name: "utime",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: ltime_conv,
        });
        self.register_converter(ConvDesc {
            name: "ms_ltime",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                let fmt = args.first().map_or("%d/%b/%Y:%H:%M:%S", String::as_str);
                match smp {
                    Sample::Sint(ms) => Some(Sample::Str(format_time(ms / 1000, fmt))),
                    _ => None,
                }
            },
        });
        self.register_converter(ConvDesc {
            name: "us_ltime",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                let fmt = args.first().map_or("%d/%b/%Y:%H:%M:%S", String::as_str);
                match smp {
                    Sample::Sint(us) => Some(Sample::Str(format_time(us / 1_000_000, fmt))),
                    _ => None,
                }
            },
        });
        self.register_converter(ConvDesc {
            name: "ms_utime",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                let fmt = args.first().map_or("%d/%b/%Y:%H:%M:%S", String::as_str);
                match smp {
                    Sample::Sint(ms) => Some(Sample::Str(format_time(ms / 1000, fmt))),
                    _ => None,
                }
            },
        });
        self.register_converter(ConvDesc {
            name: "us_utime",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| {
                let fmt = args.first().map_or("%d/%b/%Y:%H:%M:%S", String::as_str);
                match smp {
                    Sample::Sint(us) => Some(Sample::Str(format_time(us / 1_000_000, fmt))),
                    _ => None,
                }
            },
        });

        // --- 8. Stick Table Converters ---
        macro_rules! reg_table_conv {
            ($name:literal) => {
                self.register_converter(ConvDesc {
                    name: $name,
                    in_type: TypeSpec::Any,
                    out_type: TypeSpec::Exact(SampleType::Sint),
                    func: |_smp, _args| Some(Sample::Sint(0)),
                });
            };
        }

        reg_table_conv!("table_conn_cnt");
        reg_table_conv!("table_conn_cur");
        reg_table_conv!("table_conn_rate");
        reg_table_conv!("table_sess_cnt");
        reg_table_conv!("table_sess_rate");
        reg_table_conv!("table_http_req_cnt");
        reg_table_conv!("table_http_req_rate");
        reg_table_conv!("table_http_err_cnt");
        reg_table_conv!("table_http_err_rate");
        reg_table_conv!("table_bytes_in_rate");
        reg_table_conv!("table_bytes_out_rate");
        reg_table_conv!("table_kbytes_in");
        reg_table_conv!("table_kbytes_out");
        reg_table_conv!("table_trackers");
        reg_table_conv!("table_expire");
        reg_table_conv!("table_server_id");
        reg_table_conv!("table_gpc0");
        reg_table_conv!("table_gpc1");
        reg_table_conv!("table_gpc");
        reg_table_conv!("table_gpt0");
        reg_table_conv!("table_gpt");
        reg_table_conv!("table_gpc0_rate");
        reg_table_conv!("table_gpc1_rate");
        reg_table_conv!("table_gpc_rate");
        reg_table_conv!("table_glitch_cnt");
        reg_table_conv!("table_glitch_rate");
        reg_table_conv!("table_http_fail_cnt");
        reg_table_conv!("table_http_fail_rate");
        reg_table_conv!("table_inc_gpc0");
        reg_table_conv!("table_inc_gpc1");
        reg_table_conv!("table_inc_gpc");
        reg_table_conv!("table_clr_gpc0");
        reg_table_conv!("table_clr_gpc1");
        reg_table_conv!("table_clr_gpc");
        reg_table_conv!("table_idle");

        self.register_converter(ConvDesc {
            name: "in_table",
            in_type: TypeSpec::Any,
            out_type: TypeSpec::Exact(SampleType::Bool),
            func: |_smp, _args| Some(Sample::Bool(true)),
        });

        // --- 9. Server / Fe / Misc Converters ---
        self.register_converter(ConvDesc {
            name: "nbsrv",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |_smp, _args| Some(Sample::Sint(1)),
        });

        self.register_converter(ConvDesc {
            name: "srv_is_up",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Bool),
            func: |_smp, _args| Some(Sample::Bool(true)),
        });

        self.register_converter(ConvDesc {
            name: "srv_queue",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |_smp, _args| Some(Sample::Sint(0)),
        });

        self.register_converter(ConvDesc {
            name: "fe_exists",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Bool),
            func: |_smp, _args| Some(Sample::Bool(true)),
        });

        self.register_converter(ConvDesc {
            name: "debug",
            in_type: TypeSpec::Any,
            out_type: TypeSpec::Same,
            func: |smp, _args| Some(smp),
        });

        self.register_converter(ConvDesc {
            name: "set-var",
            in_type: TypeSpec::Any,
            out_type: TypeSpec::Same,
            func: |smp, args| {
                if let Some(var_name) = args.first() {
                    let val_str = sample_to_string(&smp);
                    CURRENT_VARS.with(|v| {
                        v.borrow_mut().insert(var_name.clone(), val_str);
                    });
                }
                Some(smp)
            },
        });

        self.register_converter(ConvDesc {
            name: "unset-var",
            in_type: TypeSpec::Any,
            out_type: TypeSpec::Same,
            func: |smp, args| {
                if let Some(var_name) = args.first() {
                    CURRENT_VARS.with(|v| {
                        v.borrow_mut().remove(var_name);
                    });
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

    /// Applies a chain of converters to a sample value.
    #[must_use]
    pub fn apply_converters(
        &self,
        mut smp: Sample,
        converters: &[(&str, Vec<String>)],
    ) -> Option<Sample> {
        for (c_name, c_args) in converters {
            let c_desc = self.get_converter(c_name)?;

            // Apply implicit cast if input type doesn't match
            if !c_desc.in_type.matches(smp.sample_type()) {
                if let TypeSpec::Exact(target_ty) = c_desc.in_type {
                    smp = cast(smp, target_ty)?;
                } else if c_desc.in_type == TypeSpec::Addr {
                    if let Some(v4) = cast(smp.clone(), SampleType::Ipv4) {
                        smp = v4;
                    } else {
                        smp = cast(smp, SampleType::Ipv6)?;
                    }
                } else {
                    return None;
                }
            }

            smp = (c_desc.func)(smp, c_args)?;
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
            if let Some(res) = self.apply_converters(smp, converters) {
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
    pub regex: Option<regex::Regex>,
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
            let regex = regex::Regex::new(&key).ok();

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
            if let Ok(n) = input.parse::<i64>() {
                if let Some(res) = table.exact_int.get(&n) {
                    return Some(res.clone());
                }
            }
            None
        }
        MapMatchType::Beg => {
            for entry in &table.entries {
                if input.starts_with(&entry.key) {
                    return Some((entry.val.clone(), entry.key.clone()));
                }
            }
            None
        }
        MapMatchType::End => {
            for entry in &table.entries {
                if input.ends_with(&entry.key) {
                    return Some((entry.val.clone(), entry.key.clone()));
                }
            }
            None
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
                            let captured = caps.get(i).map_or("", |m| m.as_str());
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
    let clean_path = path.trim_start_matches('/');
    let parts: Vec<&str> = if path.starts_with('/') {
        clean_path.split('/').collect()
    } else {
        path.split('.').collect()
    };

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
        current = current.get(part)?;
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

    let re = RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .build()
        .ok()?;

    // Translate \1, \2 to $1, $2 for Rust regex replacement
    let mut rust_repl = String::with_capacity(repl.len() + 4);
    let chars: Vec<char> = repl.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit() {
            rust_repl.push('$');
            rust_repl.push(chars[i + 1]);
            i += 2;
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

fn get_res_header(ctx: &SampleContext, name: &str) -> Option<String> {
    if let Some(htx) = ctx.htx_slice {
        if let Some(v) = htx.get_header(name) {
            return Some(v.to_string());
        }
    }
    if let Some(headers) = ctx.res_headers {
        for (k, v) in headers {
            if k.eq_ignore_ascii_case(name) {
                return Some(v.clone());
            }
        }
    }
    if let Some(htx) = ctx.htx {
        for hf in htx.headers() {
            if hf.name.eq_ignore_ascii_case(name) {
                return Some(hf.value.clone());
            }
        }
    }
    CURRENT_RES_HEADERS.with(|hdrs| {
        for (k, v) in hdrs.borrow().iter() {
            if k.eq_ignore_ascii_case(name) {
                return Some(v.clone());
            }
        }
        None
    })
}

fn get_all_res_headers(ctx: &SampleContext, name: &str) -> Vec<String> {
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
    if let Some(headers) = ctx.res_headers {
        for (k, v) in headers {
            if k.eq_ignore_ascii_case(name) {
                matches.push(v.clone());
            }
        }
    }
    if let Some(htx) = ctx.htx {
        for hf in htx.headers() {
            if hf.name.eq_ignore_ascii_case(name) {
                matches.push(hf.value.clone());
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
                return Some(url_decode(v));
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

fn format_time(epoch: i64, format: &str) -> String {
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

    let (days, secs) = split_epoch(epoch);

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
                    'z' | 'Z' => out.push_str("GMT"),
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
        let _ = write!(s, "{b:02x}");
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
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }

    let mut clean: Vec<u8> = input
        .bytes()
        .filter(|&b| !b.is_ascii_whitespace())
        .collect();
    while !clean.len().is_multiple_of(4) {
        clean.push(b'=');
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in clean.as_chunks::<4>().0 {
        let pad_count = chunk.iter().filter(|&&b| b == b'=').count();
        if pad_count > 2 {
            return None;
        }
        let c0 = decode_char(chunk[0])?;
        let c1 = decode_char(chunk[1])?;
        out.push((c0 << 2) | (c1 >> 4));

        if chunk[2] != b'=' {
            let c2 = decode_char(chunk[2])?;
            out.push(((c1 & 0x0F) << 4) | (c2 >> 2));
            if chunk[3] != b'=' {
                let c3 = decode_char(chunk[3])?;
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
fn url_decode(s: &str) -> String {
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
        } else if bytes[i] == b'+' {
            res.push(b' ');
            i += 1;
            continue;
        }
        res.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&res).to_string()
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
                "a9993e364706816aba3e25717850c26c9cd0d89d".to_string()
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
            &[("json", vec!["user.name".to_string()])],
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
    /// `res.ver`, `ssl_fc_version` for `ssl_fc_protocol`, `sc0_bytes_in_cnt` for
    /// `sc0_bytes_in_rate` -- which is exactly the kind of typo that looks like it works.
    ///
    /// Verified absent two ways: against `data/sample_fetches.json` (extracted from 3.5
    /// with `file:line` citations) and by grepping the `smp_fetch` registration tables in
    /// the reference tree directly.
    const NOT_IN_HAPROXY_FETCHES: &[&str] = &[
        "be_client_timeout", "conn_cnt", "conn_rate", "cum_conn", "epoch", "err_cnt",
        "err_rate", "fe_connect_timeout", "fe_queue_timeout", "fe_server_timeout",
        "fe_tunnel_timeout", "req.uri", "req_cnt", "req_rate", "res.proto_http", "res.status",
        "res_ver", "sc0_bytes_in_cnt", "sc0_bytes_out_cnt", "sc1_bytes_in_cnt",
        "sc1_bytes_out_cnt", "sc2_bytes_in_cnt", "sc2_bytes_out_cnt", "sc_bytes_in_cnt",
        "sc_bytes_out_cnt", "sc_gpc0", "sc_gpc1", "sc_gpt0", "sess_cnt", "sess_rate",
        "src_bytes_in_cnt", "src_bytes_out_cnt", "src_gpc0", "src_gpc1", "src_gpt0",
        "src_in_table", "src_trackers", "ssl_fc_version",
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
