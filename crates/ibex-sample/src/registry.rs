// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/sample.c and include/haproxy/sample.h.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Registries for Sample Fetches and Sample Converters.

use crate::cast::cast;
use crate::sample::{Sample, SampleType, TypeSpec};
use ibex_proto::htx::Htx;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// Runtime context passed into sample fetch functions during evaluation.
#[derive(Debug, Clone, Default)]
pub struct SampleContext<'a> {
    pub client_addr: Option<SocketAddr>,
    pub server_addr: Option<SocketAddr>,
    pub htx: Option<&'a Htx>,
    pub req_uri: Option<&'a str>,
    pub req_method: Option<&'a str>,
    pub req_headers: Option<&'a [(String, String)]>,
    pub act_conn: u32,
    pub cum_conn: u64,
    pub conn_cnt: u64,
    pub conn_rate: u64,
    pub http_req_rate: u64,
    pub http_err_rate: u64,
    pub http_req_cnt: u64,
    pub sc_conn_rates: [u64; 3],
    pub sc_http_req_rates: [u64; 3],
    pub sc_http_err_rates: [u64; 3],
    pub sc_conn_cnts: [u64; 3],
    pub sc_http_req_cnts: [u64; 3],
    pub ssl_sni: Option<&'a str>,
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

/// Central registry of sample fetches and converters.
pub struct Registry {
    fetches: HashMap<&'static str, FetchDesc>,
    converters: HashMap<&'static str, ConvDesc>,
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
        };
        r.register_builtin_fetches();
        r.register_builtin_converters();
        r
    }

    pub fn register_fetch(&mut self, desc: FetchDesc) {
        self.fetches.insert(desc.name, desc);
    }

    pub fn register_converter(&mut self, desc: ConvDesc) {
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

    #[allow(clippy::too_many_lines)]
    fn register_builtin_fetches(&mut self) {
        // src (client IP address)
        self.register_fetch(FetchDesc {
            name: "src",
            out_type: SampleType::Ipv4,
            func: |ctx, _args| match ctx.client_addr?.ip() {
                IpAddr::V4(v4) => Some(Sample::Ipv4(v4)),
                IpAddr::V6(v6) => Some(Sample::Ipv6(v6)),
            },
        });

        // src_port (client port)
        self.register_fetch(FetchDesc {
            name: "src_port",
            out_type: SampleType::Sint,
            func: |ctx, _args| ctx.client_addr.map(|sa| Sample::Sint(i64::from(sa.port()))),
        });

        // dst (destination listener IP)
        self.register_fetch(FetchDesc {
            name: "dst",
            out_type: SampleType::Ipv4,
            func: |ctx, _args| match ctx.server_addr?.ip() {
                IpAddr::V4(v4) => Some(Sample::Ipv4(v4)),
                IpAddr::V6(v6) => Some(Sample::Ipv6(v6)),
            },
        });

        // dst_port (destination listener port)
        self.register_fetch(FetchDesc {
            name: "dst_port",
            out_type: SampleType::Sint,
            func: |ctx, _args| ctx.server_addr.map(|sa| Sample::Sint(i64::from(sa.port()))),
        });

        // req.hdr(name) and hdr(name)
        let hdr_fetch: FetchFn = |ctx, args| {
            let hdr_name = args.first()?;
            if let Some(htx) = ctx.htx {
                if let Some(v) = htx.get_header(hdr_name) {
                    return Some(Sample::Str(v.to_string()));
                }
            }
            if let Some(headers) = ctx.req_headers {
                for (k, v) in headers {
                    if k.eq_ignore_ascii_case(hdr_name) {
                        return Some(Sample::Str(v.clone()));
                    }
                }
            }
            None
        };

        self.register_fetch(FetchDesc {
            name: "req.hdr",
            out_type: SampleType::Str,
            func: hdr_fetch,
        });

        self.register_fetch(FetchDesc {
            name: "hdr",
            out_type: SampleType::Str,
            func: hdr_fetch,
        });

        // path
        self.register_fetch(FetchDesc {
            name: "path",
            out_type: SampleType::Str,
            func: |ctx, _args| {
                if let Some(uri) = ctx.req_uri {
                    let path_only = uri.split('?').next().unwrap_or(uri);
                    return Some(Sample::Str(path_only.to_string()));
                }
                let req = ctx.htx?.req_line()?;
                let path_only = req.uri.split('?').next().unwrap_or(&req.uri);
                Some(Sample::Str(path_only.to_string()))
            },
        });

        // url (full URI)
        self.register_fetch(FetchDesc {
            name: "url",
            out_type: SampleType::Str,
            func: |ctx, _args| {
                if let Some(uri) = ctx.req_uri {
                    return Some(Sample::Str(uri.to_string()));
                }
                let req = ctx.htx?.req_line()?;
                Some(Sample::Str(req.uri.clone()))
            },
        });

        // query
        self.register_fetch(FetchDesc {
            name: "query",
            out_type: SampleType::Str,
            func: |ctx, _args| {
                let uri = ctx
                    .req_uri
                    .or_else(|| ctx.htx.and_then(|h| h.req_line().map(|r| r.uri.as_str())))?;
                uri.split_once('?').map(|(_, q)| Sample::Str(q.to_string()))
            },
        });

        // method
        self.register_fetch(FetchDesc {
            name: "method",
            out_type: SampleType::Meth,
            func: |ctx, _args| {
                if let Some(m_str) = ctx.req_method {
                    let m = match m_str.to_uppercase().as_str() {
                        "GET" => ibex_proto::htx::HttpMethod::Get,
                        "POST" => ibex_proto::htx::HttpMethod::Post,
                        "HEAD" => ibex_proto::htx::HttpMethod::Head,
                        "PUT" => ibex_proto::htx::HttpMethod::Put,
                        "DELETE" => ibex_proto::htx::HttpMethod::Delete,
                        _ => ibex_proto::htx::HttpMethod::Other(m_str.to_string()),
                    };
                    return Some(Sample::Meth(m));
                }
                ctx.htx?
                    .req_line()
                    .map(|req| Sample::Meth(req.method.clone()))
            },
        });

        // status
        self.register_fetch(FetchDesc {
            name: "status",
            out_type: SampleType::Sint,
            func: |ctx, _args| {
                ctx.htx?
                    .res_line()
                    .map(|res| Sample::Sint(i64::from(res.status)))
            },
        });

        // Stick table metrics
        self.register_fetch(FetchDesc {
            name: "sc_conn_cnt",
            out_type: SampleType::Sint,
            #[allow(clippy::cast_possible_wrap)]
            func: |ctx, _args| Some(Sample::Sint(ctx.conn_cnt as i64)),
        });

        self.register_fetch(FetchDesc {
            name: "sc_conn_rate",
            out_type: SampleType::Sint,
            #[allow(clippy::cast_possible_wrap)]
            func: |ctx, args| {
                let slot = args
                    .first()
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0);
                if slot < 3 && ctx.sc_conn_rates[slot] > 0 {
                    Some(Sample::Sint(ctx.sc_conn_rates[slot] as i64))
                } else {
                    Some(Sample::Sint(ctx.conn_rate as i64))
                }
            },
        });

        self.register_fetch(FetchDesc {
            name: "sc_http_req_rate",
            out_type: SampleType::Sint,
            #[allow(clippy::cast_possible_wrap)]
            func: |ctx, args| {
                let slot = args
                    .first()
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0);
                if slot < 3 && ctx.sc_http_req_rates[slot] > 0 {
                    Some(Sample::Sint(ctx.sc_http_req_rates[slot] as i64))
                } else {
                    Some(Sample::Sint(ctx.http_req_rate as i64))
                }
            },
        });

        self.register_fetch(FetchDesc {
            name: "sc_http_err_rate",
            out_type: SampleType::Sint,
            #[allow(clippy::cast_possible_wrap)]
            func: |ctx, args| {
                let slot = args
                    .first()
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0);
                if slot < 3 && ctx.sc_http_err_rates[slot] > 0 {
                    Some(Sample::Sint(ctx.sc_http_err_rates[slot] as i64))
                } else {
                    Some(Sample::Sint(ctx.http_err_rate as i64))
                }
            },
        });

        self.register_fetch(FetchDesc {
            name: "sc_conn_cnt",
            out_type: SampleType::Sint,
            #[allow(clippy::cast_possible_wrap)]
            func: |ctx, args| {
                let slot = args
                    .first()
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0);
                if slot < 3 && ctx.sc_conn_cnts[slot] > 0 {
                    Some(Sample::Sint(ctx.sc_conn_cnts[slot] as i64))
                } else {
                    Some(Sample::Sint(ctx.conn_cnt as i64))
                }
            },
        });

        self.register_fetch(FetchDesc {
            name: "sc_http_req_cnt",
            out_type: SampleType::Sint,
            #[allow(clippy::cast_possible_wrap)]
            func: |ctx, args| {
                let slot = args
                    .first()
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0);
                if slot < 3 && ctx.sc_http_req_cnts[slot] > 0 {
                    Some(Sample::Sint(ctx.sc_http_req_cnts[slot] as i64))
                } else {
                    Some(Sample::Sint(ctx.http_req_cnt as i64))
                }
            },
        });

        // SSL SNI
        self.register_fetch(FetchDesc {
            name: "ssl_fc_sni",
            out_type: SampleType::Str,
            func: |ctx, _args| ctx.ssl_sni.map(|sni| Sample::Str(sni.to_string())),
        });
    }

    #[allow(clippy::too_many_lines)]
    fn register_builtin_converters(&mut self) {
        // lower: string to lowercase
        self.register_converter(ConvDesc {
            name: "lower",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Str(s) => Some(Sample::Str(s.to_lowercase())),
                _ => None,
            },
        });

        // upper: string to uppercase
        self.register_converter(ConvDesc {
            name: "upper",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Str(s) => Some(Sample::Str(s.to_uppercase())),
                _ => None,
            },
        });

        // len: string length
        self.register_converter(ConvDesc {
            name: "len",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                #[allow(clippy::cast_possible_wrap)]
                Sample::Str(s) => Some(Sample::Sint(s.len() as i64)),
                _ => None,
            },
        });

        // add(n): integer addition
        self.register_converter(ConvDesc {
            name: "add",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| {
                let n = args.first()?.parse::<i64>().ok()?;
                match smp {
                    Sample::Sint(val) => Some(Sample::Sint(val.saturating_add(n))),
                    _ => None,
                }
            },
        });

        // sub(n): integer subtraction
        self.register_converter(ConvDesc {
            name: "sub",
            in_type: TypeSpec::Exact(SampleType::Sint),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, args| {
                let n = args.first()?.parse::<i64>().ok()?;
                match smp {
                    Sample::Sint(val) => Some(Sample::Sint(val.saturating_sub(n))),
                    _ => None,
                }
            },
        });

        // hex: binary to hexadecimal string
        self.register_converter(ConvDesc {
            name: "hex",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Str(hex_encode(&b))),
                _ => None,
            },
        });

        // hex2bin: hexadecimal string to binary
        self.register_converter(ConvDesc {
            name: "hex2bin",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, _args| match smp {
                Sample::Str(s) => hex_decode(&s).map(Sample::Bin),
                _ => None,
            },
        });

        // base64: binary to base64 string
        self.register_converter(ConvDesc {
            name: "base64",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Str(base64_encode(&b))),
                _ => None,
            },
        });

        // b64dec: base64 string to binary
        self.register_converter(ConvDesc {
            name: "b64dec",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Bin),
            func: |smp, _args| match smp {
                Sample::Str(s) => base64_decode(&s).map(Sample::Bin),
                _ => None,
            },
        });

        // concat(args...): string concatenation
        self.register_converter(ConvDesc {
            name: "concat",
            in_type: TypeSpec::Exact(SampleType::Str),
            out_type: TypeSpec::Exact(SampleType::Str),
            func: |smp, args| match smp {
                Sample::Str(mut s) => {
                    for arg in args {
                        s.push_str(arg);
                    }
                    Some(Sample::Str(s))
                }
                _ => None,
            },
        });

        // bytes(offset, len): binary slice
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

        // ipmask(mask_or_prefix): IP masking
        self.register_converter(ConvDesc {
            name: "ipmask",
            in_type: TypeSpec::Addr,
            out_type: TypeSpec::Same,
            func: |smp, args| {
                let mask_str = args.first()?;
                match smp {
                    Sample::Ipv4(ip) => {
                        let mask = if let Ok(prefix) = mask_str.parse::<u32>() {
                            if prefix > 32 {
                                return None;
                            }
                            u32::MAX.checked_shl(32 - prefix).unwrap_or(0)
                        } else if let Ok(m_ip) = mask_str.parse::<std::net::Ipv4Addr>() {
                            u32::from(m_ip)
                        } else {
                            return None;
                        };
                        Some(Sample::Ipv4(std::net::Ipv4Addr::from(u32::from(ip) & mask)))
                    }
                    Sample::Ipv6(ip) => {
                        let prefix = mask_str.parse::<u32>().ok()?;
                        if prefix > 128 {
                            return None;
                        }
                        let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
                        Some(Sample::Ipv6(std::net::Ipv6Addr::from(
                            u128::from(ip) & mask,
                        )))
                    }
                    _ => None,
                }
            },
        });

        // crc32: CRC32 checksum
        self.register_converter(ConvDesc {
            name: "crc32",
            in_type: TypeSpec::Exact(SampleType::Bin),
            out_type: TypeSpec::Exact(SampleType::Sint),
            func: |smp, _args| match smp {
                Sample::Bin(b) => Some(Sample::Sint(i64::from(crc32_compute(&b)))),
                _ => None,
            },
        });
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
        let f_desc = self.get_fetch(fetch_name)?;
        let mut smp = (f_desc.func)(ctx, fetch_args)?;

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
}

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

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        out.push(TABLE[usize::from(b0 >> 2)] as char);
        out.push(TABLE[usize::from(((b0 & 0x03) << 4) | (b1 >> 4))] as char);
        if chunk.len() > 1 {
            out.push(TABLE[usize::from(((b1 & 0x0F) << 2) | (b2 >> 6))] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[usize::from(b2 & 0x3F)] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[allow(clippy::chunks_exact_to_as_chunks, clippy::naive_bytecount)]
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let clean: Vec<u8> = input
        .bytes()
        .filter(|&b| !b.is_ascii_whitespace())
        .collect();
    if !clean.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in clean.chunks_exact(4) {
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

fn crc32_compute(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}
