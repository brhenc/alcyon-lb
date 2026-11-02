// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The fetches that read the raw buffer of a TCP stream before anything has terminated its
//! protocol: the TLS ClientHello parsers, the RDP cookie and `payload_lv`.
//!
//! This is `src/payload.c` (`smp_client_hello_parse` and the `smp_fetch_ssl_*`,
//! `fetch_rdp_cookie_name` and `smp_fetch_payload_lv`), including its bounds checks, which
//! are signed `int` arithmetic there and so are `i64` here. Each parser sees the whole
//! buffer and answers one of three things ([`Raw`]), the third being what makes a rule wait:
//! `SMP_F_MAY_CHANGE` is [`Raw::TooShort`].

/// What a parser makes of the bytes it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Raw<T> {
    /// A value.
    Found(T),
    /// No value yet, and more data could still give one (`SMP_F_MAY_CHANGE`).
    TooShort,
    /// Never a value, whatever follows.
    No,
}

impl<T> Raw<T> {
    /// The value, if there is one.
    pub fn found(self) -> Option<T> {
        match self {
            Raw::Found(v) => Some(v),
            _ => None,
        }
    }
}

/// The room the buffer leaves for incoming data (`channel_recv_limit` for the default
/// `tune.bufsize` of 16384 and `tune.maxrewrite` of 1024): `req.ssl_ver` does not wait for
/// a record longer than that.
const RECV_LIMIT: i64 = 16384 - 1024;

/// The size of a channel buffer (`c_size`), the bound `payload_lv` holds its offsets to.
pub const BUFSIZE: usize = 16384;

/// `d[i]` as C reads it; the checks of the callers keep `i` inside the buffer, and a
/// stray one reads 0 rather than panicking.
fn b(d: &[u8], i: i64) -> i64 {
    usize::try_from(i).ok().and_then(|i| d.get(i)).map_or(0, |&v| i64::from(v))
}

fn be16(d: &[u8], i: i64) -> i64 {
    (b(d, i) << 8) + b(d, i + 1)
}

fn len(d: &[u8]) -> i64 {
    i64::try_from(d.len()).unwrap_or(i64::MAX)
}

fn slice(d: &[u8], off: i64, n: i64) -> Vec<u8> {
    let (Ok(o), Ok(n)) = (usize::try_from(off), usize::try_from(n)) else { return Vec::new() };
    d.get(o..o.saturating_add(n)).map(<[u8]>::to_vec).unwrap_or_default()
}

/// `smp_fetch_ssl_hello_type`: the handshake type of the first record (1 for a ClientHello,
/// 2 for a ServerHello).
#[must_use]
pub fn hello_type(d: &[u8]) -> Raw<i64> {
    let bleft = len(d);
    if bleft == 0 {
        return Raw::TooShort;
    }
    let c = b(d, 0);
    if !((0x14..=0x17).contains(&c) || c == 0xFF) {
        return Raw::No;
    }
    if bleft < 9 {
        return Raw::TooShort;
    }
    if (b(d, 1) << 16) + b(d, 2) < 0x0003_0000 {
        return Raw::No;
    }
    if be16(d, 3) < 4 {
        return Raw::No;
    }
    let hs_type = b(d, 5);
    let hs_len = (b(d, 6) << 16) + (b(d, 7) << 8) + b(d, 8);
    if bleft < 9 + hs_len {
        return Raw::TooShort;
    }
    Raw::Found(hs_type)
}

/// `smp_fetch_req_ssl_ver`: the client version of an SSLv3/TLS ClientHello record, or of an
/// SSLv2 CLIENT-HELLO (`major << 16 | minor`).
#[must_use]
pub fn ssl_ver(d: &[u8]) -> Raw<i64> {
    let mut bleft = len(d);
    if bleft == 0 {
        return Raw::TooShort;
    }
    let mut p = 0i64;
    let c = b(d, 0);
    let (version, mut msg_len);
    if (0x14..=0x17).contains(&c) || c == 0xFF {
        if bleft < 11 {
            return Raw::TooShort;
        }
        let v = (b(d, 1) << 16) + b(d, 2);
        msg_len = be16(d, 3);
        if v < 0x0003_0000 {
            return Raw::No;
        }
        if msg_len < 6 || msg_len > (1 << 14) + 2048 {
            return Raw::No;
        }
        bleft -= 5;
        p += 5;
        version = (b(d, p + 4) << 16) + b(d, p + 5);
    } else {
        let (rlen, plen);
        if c & 0x80 != 0 {
            if bleft < 3 {
                return Raw::TooShort;
            }
            rlen = ((b(d, 0) & 0x7F) << 8) | b(d, 1);
            plen = 0;
            bleft -= 2;
            p += 2;
        } else {
            if bleft < 4 {
                return Raw::TooShort;
            }
            rlen = ((b(d, 0) & 0x3F) << 8) | b(d, 1);
            plen = b(d, 2);
            bleft -= 3;
            p += 3;
        }
        if b(d, p) != 0x01 {
            return Raw::No;
        }
        bleft -= 1;
        p += 1;
        if bleft < 8 {
            return Raw::TooShort;
        }
        version = (b(d, p) << 16) + b(d, p + 1);
        let cilen = be16(d, p + 2);
        let silen = be16(d, p + 4);
        let chlen = be16(d, p + 6);
        bleft -= 8;
        if cilen % 3 != 0 || (silen != 0 && silen != 16) || !(16..=32).contains(&chlen) || rlen != 9 + cilen + silen + chlen {
            return Raw::No;
        }
        msg_len = cilen + silen + chlen + plen;
    }
    // The message is waited for only as far as the buffer can hold it.
    msg_len = msg_len.min(RECV_LIMIT);
    if bleft < msg_len {
        return Raw::TooShort;
    }
    Raw::Found(version)
}

/// `smp_client_hello_parse`: `(offset, length)` of the cipher suites (`extensions` false) or
/// of the extension list (`extensions` true) of a ClientHello.
fn client_hello(d: &[u8], extensions: bool) -> Raw<(i64, i64)> {
    let mut bleft = len(d);
    let mut p = 0i64;
    if bleft == 0 {
        return Raw::TooShort;
    }
    if b(d, 0) != 0x16 {
        return Raw::No;
    }
    if bleft < 3 {
        return Raw::TooShort;
    }
    if b(d, 1) < 0x03 {
        return Raw::No;
    }
    if bleft < 5 {
        return Raw::TooShort;
    }
    let mut hs_len = be16(d, 3);
    if hs_len < 1 + 3 + 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + 2 {
        return Raw::No;
    }
    p += 5;
    bleft -= 5;
    if bleft < hs_len {
        return Raw::TooShort;
    }
    if b(d, p) != 0x01 {
        return Raw::No;
    }
    // (`HAProxy` tests `bleft < 4` here, which the record length check above rules out.)
    hs_len = (b(d, p + 1) << 16) + (b(d, p + 2) << 8) + b(d, p + 3);
    if hs_len < 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + 2 {
        return Raw::No;
    }
    p += 4;
    bleft -= 4;
    if bleft < hs_len {
        return Raw::TooShort;
    }
    if b(d, p) < 0x03 || b(d, p + 1) < 0x01 {
        return Raw::No;
    }
    let mut ext_len = b(d, p + 34);
    if ext_len > 32 || ext_len > hs_len - 35 {
        return Raw::No;
    }
    hs_len -= 35 + ext_len;
    p += 35 + ext_len;
    if hs_len < 4 {
        return Raw::No;
    }
    ext_len = be16(d, p);
    if ext_len < 2 || ext_len > hs_len - 2 {
        return Raw::No;
    }
    if !extensions {
        return Raw::Found((p, ext_len));
    }
    hs_len -= 2 + ext_len;
    p += 2 + ext_len;
    if hs_len < 2 || b(d, p) < 1 || b(d, p) > hs_len {
        return Raw::No;
    }
    hs_len -= 1 + b(d, p);
    p += 1 + b(d, p);
    if hs_len < 2 {
        return Raw::No;
    }
    ext_len = be16(d, p);
    if ext_len > hs_len - 2 {
        return Raw::No;
    }
    Raw::Found((p + 2, ext_len))
}

/// Walks the extensions as the fetches do, stopping at the first of type `ty`. An extension
/// running past the list makes the whole fetch fail, but only if reached before `ty`.
fn find_extension(d: &[u8], ty: i64) -> Raw<Option<(i64, i64)>> {
    let (mut p, mut hs_len) = match client_hello(d, true) {
        Raw::Found(v) => v,
        Raw::TooShort => return Raw::TooShort,
        Raw::No => return Raw::No,
    };
    while hs_len >= 4 {
        let (t, l) = (be16(d, p), be16(d, p + 2));
        if l > hs_len - 4 {
            return Raw::No;
        }
        if t == ty {
            return Raw::Found(Some((p + 4, l)));
        }
        hs_len -= 4 + l;
        p += 4 + l;
    }
    Raw::Found(None)
}

/// `req.ssl_st_ext`: 0 without a session ticket extension, 1 with an empty one, 2 with data.
#[must_use]
pub fn st_ext(d: &[u8]) -> Raw<i64> {
    match find_extension(d, 35) {
        Raw::Found(Some((_, l))) => Raw::Found(if l > 0 { 2 } else { 1 }),
        Raw::Found(None) => Raw::Found(0),
        Raw::TooShort => Raw::TooShort,
        Raw::No => Raw::No,
    }
}

/// `req.ssl_ec_ext`: whether a supported_groups (elliptic curves) extension is present.
#[must_use]
pub fn ec_ext(d: &[u8]) -> Raw<bool> {
    match find_extension(d, 10) {
        Raw::Found(f) => Raw::Found(f.is_some()),
        Raw::TooShort => Raw::TooShort,
        Raw::No => Raw::No,
    }
}

/// `req.ssl_cipherlist`: the cipher suites, as sent.
#[must_use]
pub fn cipherlist(d: &[u8]) -> Raw<Vec<u8>> {
    match client_hello(d, false) {
        Raw::Found((p, l)) => Raw::Found(slice(d, p + 2, l)),
        Raw::TooShort => Raw::TooShort,
        Raw::No => Raw::No,
    }
}

/// A list extension of type `ty` whose body is a 16-bit length then the list, `min` being
/// the least length of that list: the list, or `No`. The fetches of this shape all want the
/// extension to be there (`req.ssl_supported_groups`, `req.ssl_sigalgs`).
fn list_extension(d: &[u8], ty: i64, min: i64) -> Raw<(i64, i64)> {
    match find_extension(d, ty) {
        Raw::Found(Some((p, l))) => {
            if l < 2 {
                return Raw::No;
            }
            let n = be16(d, p);
            if n < min || n > l - 2 {
                return Raw::No;
            }
            Raw::Found((p + 2, n))
        }
        Raw::Found(None) | Raw::No => Raw::No,
        Raw::TooShort => Raw::TooShort,
    }
}

/// `req.ssl_supported_groups`: the group identifiers, as sent.
#[must_use]
pub fn supported_groups(d: &[u8]) -> Raw<Vec<u8>> {
    match list_extension(d, 10, 2) {
        Raw::Found((p, n)) => Raw::Found(slice(d, p, n)),
        Raw::TooShort => Raw::TooShort,
        Raw::No => Raw::No,
    }
}

/// `req.ssl_sigalgs`: the signature algorithms, as sent.
#[must_use]
pub fn sigalgs(d: &[u8]) -> Raw<Vec<u8>> {
    match list_extension(d, 13, 2) {
        Raw::Found((p, n)) => Raw::Found(slice(d, p, n)),
        Raw::TooShort => Raw::TooShort,
        Raw::No => Raw::No,
    }
}

/// `req.ssl_keyshare_groups`: the group of each key share, two bytes each.
#[must_use]
pub fn keyshare_groups(d: &[u8]) -> Raw<Vec<u8>> {
    match list_extension(d, 51, 4) {
        Raw::Found((p, n)) => {
            let mut out = Vec::new();
            let mut pos = 0i64;
            while pos + 4 <= n {
                out.extend_from_slice(&slice(d, p + pos, 2));
                pos += be16(d, p + pos + 2) + 4;
            }
            Raw::Found(out)
        }
        Raw::TooShort => Raw::TooShort,
        Raw::No => Raw::No,
    }
}

/// `req.ssl_sni`: the first host_name of the server_name extension.
///
/// Unlike the list fetches, an extension of another kind after a malformed server_name is
/// never reached: the first server_name extension decides. A name type other than 0 goes on
/// to the next extension.
#[must_use]
pub fn sni(d: &[u8]) -> Raw<Vec<u8>> {
    let (mut p, mut hs_len) = match client_hello(d, true) {
        Raw::Found(v) => v,
        Raw::TooShort => return Raw::TooShort,
        Raw::No => return Raw::No,
    };
    while hs_len >= 4 {
        let (ty, l) = (be16(d, p), be16(d, p + 2));
        if l > hs_len - 4 {
            return Raw::No;
        }
        if ty == 0 {
            if l < 2 {
                return Raw::No;
            }
            let srv_len = be16(d, p + 4);
            if srv_len < 4 || srv_len > l - 2 {
                return Raw::No;
            }
            let name_type = b(d, p + 6);
            let name_len = be16(d, p + 7);
            if name_len + 3 > srv_len {
                return Raw::No;
            }
            if name_type == 0 {
                return Raw::Found(slice(d, p + 9, name_len));
            }
        }
        hs_len -= 4 + l;
        p += 4 + l;
    }
    Raw::No
}

/// `req.ssl_alpn`: every protocol name of the first ALPN extension, in order (a sample
/// fetch sees the first, an ACL matches against all of them).
#[must_use]
pub fn alpn(d: &[u8]) -> Raw<Vec<Vec<u8>>> {
    match find_extension(d, 16) {
        Raw::Found(Some((p, l))) => {
            if l < 3 {
                return Raw::No;
            }
            // The cursor counts from the start of the extension header, as in `payload.c`.
            let ext = p - 4;
            let mut names = Vec::new();
            let mut off = 6i64;
            loop {
                let name_len = b(d, ext + off);
                if name_len + off - 3 > l {
                    break;
                }
                names.push(slice(d, ext + off + 1, name_len));
                if name_len + off - 3 < l {
                    off += name_len + 1;
                } else {
                    break;
                }
            }
            if names.is_empty() { Raw::No } else { Raw::Found(names) }
        }
        Raw::Found(None) | Raw::No => Raw::No,
        Raw::TooShort => Raw::TooShort,
    }
}

/// `fetch_rdp_cookie_name`: the value of the RDP cookie `name` (any cookie when `None`),
/// from the line `Cookie: name=value\r\n` that follows the 11 bytes of the connection
/// request header.
#[must_use]
pub fn rdp_cookie(d: &[u8], name: Option<&str>) -> Raw<Vec<u8>> {
    let mut bleft = len(d);
    if bleft <= 11 {
        return Raw::TooShort;
    }
    let mut p = 11i64;
    bleft -= 11;
    if bleft <= 7 {
        return Raw::TooShort;
    }
    if !slice(d, p, 7).eq_ignore_ascii_case(b"Cookie:") {
        return Raw::No;
    }
    p += 7;
    bleft -= 7;
    while bleft > 0 && b(d, p) == i64::from(b' ') {
        p += 1;
        bleft -= 1;
    }
    match name.filter(|n| !n.is_empty()) {
        Some(n) => {
            let clen = i64::try_from(n.len()).unwrap_or(i64::MAX);
            if bleft <= clen {
                return Raw::TooShort;
            }
            if b(d, p + clen) != i64::from(b'=') || !slice(d, p, clen).eq_ignore_ascii_case(n.as_bytes()) {
                return Raw::No;
            }
            p += clen + 1;
            bleft -= clen + 1;
        }
        None => {
            while bleft > 0 && b(d, p) != i64::from(b'=') {
                if b(d, p) == i64::from(b'\r') || b(d, p) == i64::from(b'\n') {
                    return Raw::No;
                }
                p += 1;
                bleft -= 1;
            }
            if bleft < 1 {
                return Raw::TooShort;
            }
            p += 1;
            bleft -= 1;
        }
    }
    let start = p;
    while bleft > 0 && b(d, p) != i64::from(b'\r') {
        p += 1;
        bleft -= 1;
    }
    if bleft < 2 {
        return Raw::TooShort;
    }
    if b(d, p + 1) != i64::from(b'\n') {
        return Raw::No;
    }
    Raw::Found(slice(d, start, p - start))
}

/// `req.rdp_cookie_cnt`: 1 if the cookie is there, 0 if it cannot be, nothing while unsure.
#[must_use]
pub fn rdp_cookie_cnt(d: &[u8], name: Option<&str>) -> Raw<i64> {
    match rdp_cookie(d, name) {
        Raw::Found(_) => Raw::Found(1),
        Raw::No => Raw::Found(0),
        Raw::TooShort => Raw::TooShort,
    }
}

/// The third argument of `payload_lv`: where the payload starts, `Implicit` (right after the
/// length), `Absolute`, or `Relative` to that implicit position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LvOffset {
    Implicit,
    Absolute(i64),
    Relative(i64),
}

/// `val_payload_lv`: the arguments of `payload_lv(<len offset>,<len size>[,<offset>])`, or
/// the error text `HAProxy` gives.
///
/// # Errors
/// `HAProxy`'s wording.
pub fn parse_payload_lv_args(args: &[String]) -> Result<(i64, i64, LvOffset), String> {
    let int = |s: &str| s.trim().parse::<i64>().map_err(|_| "invalid argument".to_string());
    let off1 = int(args.first().map_or("", String::as_str))?;
    let size = int(args.get(1).map_or("", String::as_str))?;
    if off1 < 0 {
        return Err("payload offset1 must be positive".into());
    }
    if size == 0 {
        return Err("payload length must be > 0".into());
    }
    let mut off2 = LvOffset::Implicit;
    if let Some(s) = args.get(2).filter(|s| !s.is_empty()) {
        let relative = s.starts_with(['+', '-']);
        let v: i64 = s.parse().map_err(|_| "payload offset2 is not a number".to_string())?;
        if off1.saturating_add(size).saturating_add(v) < 0 {
            return Err("payload offset2 too negative".into());
        }
        off2 = if relative { LvOffset::Relative(v) } else { LvOffset::Absolute(v) };
    }
    Ok((off1, size, off2))
}

/// `smp_fetch_payload_lv`: the bytes whose length is the big-endian number at
/// `(len offset, len size)` and which start right after it, or at the third argument.
#[must_use]
pub fn payload_lv(d: &[u8], args: &[String]) -> Raw<Vec<u8>> {
    let Ok((len_offset, len_size, off2)) = parse_payload_lv_args(args) else { return Raw::No };
    let data = len(d);
    let max = i64::try_from(BUFSIZE).unwrap_or(i64::MAX);
    if len_offset.saturating_add(len_size) > data {
        return Raw::TooShort;
    }
    // HAProxy accumulates into an `unsigned int`: a length wider than 4 bytes wraps.
    let mut buf_size = 0u32;
    for i in 0..len_size {
        buf_size = (buf_size << 8).wrapping_add(u32::try_from(b(d, i + len_offset)).unwrap_or(0));
    }
    let buf_size = i64::from(buf_size);
    // `val_payload_lv` stores a relative offset as `(v << 1) + 1` and an absolute one as is,
    // and the fetch then tests the low bit and shifts: an absolute offset therefore comes
    // out halved, and an odd one is taken as relative. Measured, and kept.
    let buf_offset = match off2 {
        LvOffset::Implicit => len_offset.saturating_add(len_size),
        LvOffset::Relative(v) => len_offset.saturating_add(len_size).saturating_add(v),
        LvOffset::Absolute(v) if v & 1 != 0 => len_offset.saturating_add(len_size).saturating_add(v >> 1),
        LvOffset::Absolute(v) => v >> 1,
    };
    if buf_size == 0 || buf_size > max || buf_offset.saturating_add(buf_size) > max {
        return Raw::No;
    }
    if buf_offset + buf_size > data {
        return Raw::TooShort;
    }
    Raw::Found(slice(d, buf_offset, buf_size))
}

use crate::registry::{FetchDesc, Registry, SampleContext};
use crate::sample::{Sample, SampleType};

/// The buffer a raw fetch reads: the request's (`Some(false)`), the response's
/// (`Some(true)`), or whichever the running rule set has (`None`: `payload_lv`). Only a
/// TCP stream has one; an HTTP one is HTX in `HAProxy`, where these have no value.
fn buffer<'a>(ctx: &SampleContext<'a>, res: Option<bool>) -> Option<&'a [u8]> {
    match res {
        Some(false) => ctx.raw_req,
        Some(true) => ctx.raw_res,
        None => ctx.raw_req.or(ctx.raw_res),
    }
}

fn lossy(v: Vec<u8>) -> Sample {
    Sample::Str(String::from_utf8_lossy(&v).into_owned())
}

macro_rules! raw_fetch {
    ($r:expr, $names:expr, $ty:expr, $dir:expr, |$d:ident, $a:ident| $parse:expr, $conv:expr) => {
        for name in $names {
            $r.register_fetch(FetchDesc {
                name,
                out_type: $ty,
                func: |ctx, $a| {
                    let $d = buffer(ctx, $dir)?;
                    ($parse).found().map($conv)
                },
            });
        }
    };
}

fn cookie_arg(args: &[String]) -> Option<&str> {
    args.first().map(String::as_str)
}

/// Registers the raw-buffer fetches (`src/payload.c`) and their deprecated spellings.
pub(crate) fn register(r: &mut Registry) {
    raw_fetch!(r, ["req.ssl_hello_type", "req_ssl_hello_type"], SampleType::Sint, Some(false), |d, _a| hello_type(d), Sample::Sint);
    raw_fetch!(r, ["res.ssl_hello_type", "rep_ssl_hello_type"], SampleType::Sint, Some(true), |d, _a| hello_type(d), Sample::Sint);
    raw_fetch!(r, ["req.ssl_ver", "req_ssl_ver"], SampleType::Sint, Some(false), |d, _a| ssl_ver(d), Sample::Sint);
    raw_fetch!(r, ["req.ssl_ec_ext"], SampleType::Bool, Some(false), |d, _a| ec_ext(d), Sample::Bool);
    raw_fetch!(r, ["req.ssl_st_ext"], SampleType::Sint, Some(false), |d, _a| st_ext(d), Sample::Sint);
    raw_fetch!(r, ["req.ssl_sni", "req_ssl_sni"], SampleType::Str, Some(false), |d, _a| sni(d), lossy);
    raw_fetch!(r, ["req.ssl_cipherlist"], SampleType::Bin, Some(false), |d, _a| cipherlist(d), Sample::Bin);
    raw_fetch!(r, ["req.ssl_supported_groups"], SampleType::Bin, Some(false), |d, _a| supported_groups(d), Sample::Bin);
    raw_fetch!(r, ["req.ssl_sigalgs"], SampleType::Bin, Some(false), |d, _a| sigalgs(d), Sample::Bin);
    raw_fetch!(r, ["req.ssl_keyshare_groups"], SampleType::Bin, Some(false), |d, _a| keyshare_groups(d), Sample::Bin);
    raw_fetch!(r, ["req.rdp_cookie", "rdp_cookie"], SampleType::Str, Some(false), |d, a| rdp_cookie(d, cookie_arg(a)), lossy);
    raw_fetch!(r, ["req.rdp_cookie_cnt", "rdp_cookie_cnt"], SampleType::Sint, Some(false), |d, a| rdp_cookie_cnt(d, cookie_arg(a)), Sample::Sint);
    raw_fetch!(r, ["req.payload_lv", "payload_lv"], SampleType::Bin, None, |d, a| payload_lv(d, a), Sample::Bin);
    raw_fetch!(r, ["res.payload_lv"], SampleType::Bin, Some(true), |d, a| payload_lv(d, a), Sample::Bin);
    // Every protocol name is a value for an ACL; a sample sees the first.
    r.register_multi_fetch("req.ssl_alpn", |ctx, _| {
        buffer(ctx, Some(false)).map(alpn).and_then(Raw::found).unwrap_or_default().into_iter().map(lossy).collect()
    });
    r.register_fetch(FetchDesc {
        name: "req.ssl_alpn",
        out_type: SampleType::Str,
        func: |ctx, _| alpn(buffer(ctx, Some(false))?).found()?.into_iter().next().map(lossy),
    });
}

/// The load-time check of the arguments of these fetches and of `accept_date` and
/// `request_date`, worded as `HAProxy` words it (`make_arg_list`, `val_payload_lv`,
/// `smp_check_date_unit`), or `None` when `fetch` is not one of them or its
/// arguments are fine.
#[must_use]
pub fn check_args(fetch: &str, args: &[String]) -> Option<String> {
    // `accept_date` and `request_date` take one optional unit (`smp_check_date_unit`); an
    // empty one, `()`, is refused like a wrong one.
    if matches!(fetch, "accept_date" | "request_date") {
        if let Some(extra) = args.get(1..).filter(|e| !e.is_empty()) {
            return Some(format!("fetch method '{fetch}' : expected ')' before ',{})'", extra.join(",")));
        }
        return args
            .first()
            .filter(|u| !matches!(u.as_str(), "s" | "ms" | "us"))
            .map(|u| format!("invalid args in fetch method '{fetch}' : expects 's', 'ms' or 'us', got '{u}'"));
    }
    let none = matches!(
        fetch,
        "req.ssl_hello_type" | "req_ssl_hello_type" | "res.ssl_hello_type" | "rep_ssl_hello_type" | "req.ssl_ver" | "req_ssl_ver"
            | "req.ssl_ec_ext" | "req.ssl_st_ext" | "req.ssl_sni" | "req_ssl_sni" | "req.ssl_cipherlist"
            | "req.ssl_supported_groups" | "req.ssl_sigalgs" | "req.ssl_keyshare_groups" | "req.ssl_alpn"
    );
    let cookie = matches!(fetch, "req.rdp_cookie" | "rdp_cookie" | "req.rdp_cookie_cnt" | "rdp_cookie_cnt");
    if none || cookie {
        let extra = args.get(usize::from(cookie)..).unwrap_or_default();
        if extra.is_empty() {
            return None;
        }
        let lead = if cookie { "," } else { "" };
        return Some(format!("fetch method '{fetch}' : expected ')' before '{lead}{})'", extra.join(",")));
    }
    if !matches!(fetch, "req.payload_lv" | "res.payload_lv" | "payload_lv") {
        return None;
    }
    if args.is_empty() {
        return Some(format!("fetch method '{fetch}' : expected type 'integer' at position 1, but got nothing"));
    }
    if args.len() == 1 && args[0].trim().parse::<i64>().is_ok() {
        return Some(format!("fetch method '{fetch}' : missing arguments (got 1/2), type 'integer' expected"));
    }
    for (i, a) in args.iter().take(2).enumerate() {
        if a.trim().parse::<i64>().is_err() {
            return Some(format!("fetch method '{fetch}' : failed to parse '{a}' as type 'integer' at position {}", i + 1));
        }
    }
    parse_payload_lv_args(args).err().map(|e| format!("invalid args in fetch method '{fetch}' : {e}"))
}

/// Whether `fetch` is one of these and has no value yet that more data could give
/// (`SMP_F_MAY_CHANGE`): the rule that reads it waits. `None` for any other fetch.
#[must_use]
pub fn raw_may_change(fetch: &str, args: &[String], d: &[u8]) -> Option<bool> {
    fn wait<T>(r: &Raw<T>) -> bool {
        matches!(r, Raw::TooShort)
    }
    Some(match fetch {
        "req.ssl_hello_type" | "req_ssl_hello_type" | "res.ssl_hello_type" | "rep_ssl_hello_type" => wait(&hello_type(d)),
        "req.ssl_ver" | "req_ssl_ver" => wait(&ssl_ver(d)),
        "req.ssl_ec_ext" => wait(&ec_ext(d)),
        "req.ssl_st_ext" => wait(&st_ext(d)),
        "req.ssl_sni" | "req_ssl_sni" => wait(&sni(d)),
        "req.ssl_cipherlist" => wait(&cipherlist(d)),
        "req.ssl_supported_groups" => wait(&supported_groups(d)),
        "req.ssl_sigalgs" => wait(&sigalgs(d)),
        "req.ssl_keyshare_groups" => wait(&keyshare_groups(d)),
        "req.ssl_alpn" => wait(&alpn(d)),
        "req.rdp_cookie" | "rdp_cookie" => wait(&rdp_cookie(d, cookie_arg(args))),
        "req.rdp_cookie_cnt" | "rdp_cookie_cnt" => wait(&rdp_cookie_cnt(d, cookie_arg(args))),
        "req.payload_lv" | "payload_lv" | "res.payload_lv" => wait(&payload_lv(d, args)),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(exts: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend(0..32u8);
        body.extend([0, 0, 2, 0x13, 2, 1, 0]);
        body.extend((exts.len() as u16).to_be_bytes());
        body.extend(exts);
        let mut hs = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend(body);
        let mut rec = vec![0x16, 3, 1, (hs.len() >> 8) as u8, hs.len() as u8];
        rec.extend(hs);
        rec
    }

    #[test]
    fn every_prefix_of_a_hello_is_waited_for_or_refused_never_a_panic() {
        let full = hello(&[0, 0, 0, 0x0c, 0, 0x0a, 0, 0, 7, b'a', b'.', b'b', b'.', b'c', b'.', b'd', 0, 16, 0, 5, 0, 3, 2, b'h', b'2']);
        for n in 0..=full.len() {
            let d = &full[..n];
            let _ = (hello_type(d), ssl_ver(d), st_ext(d), ec_ext(d), cipherlist(d), supported_groups(d));
            let _ = (sigalgs(d), keyshare_groups(d), sni(d), alpn(d), rdp_cookie(d, None), payload_lv(d, &["0".into(), "2".into()]));
            if n < full.len() {
                assert_ne!(sni(d), Raw::Found(b"a.b.c.d".to_vec()), "{n}");
            }
        }
        assert_eq!(sni(&full), Raw::Found(b"a.b.c.d".to_vec()));
        assert_eq!(alpn(&full), Raw::Found(vec![b"h2".to_vec()]));
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut x = 0x1234_5678u32;
        for _ in 0..20000 {
            let n = (x % 90) as usize;
            let mut d = Vec::new();
            for _ in 0..n {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                d.push(if x >> 28 < 6 { [0x16, 3, 1, 0, 0xff, 0x80][(x >> 28) as usize] } else { (x >> 16) as u8 });
            }
            let _ = (hello_type(&d), ssl_ver(&d), st_ext(&d), ec_ext(&d), cipherlist(&d), supported_groups(&d), sigalgs(&d));
            let _ = (keyshare_groups(&d), sni(&d), alpn(&d), rdp_cookie(&d, Some("x")), rdp_cookie_cnt(&d, None));
            let _ = payload_lv(&d, &["1".into(), "4".into(), "-2".into()]);
        }
    }

    #[test]
    fn payload_lv_arguments() {
        let a = |v: &[&str]| parse_payload_lv_args(&v.iter().map(ToString::to_string).collect::<Vec<_>>());
        assert_eq!(a(&["0", "4"]), Ok((0, 4, LvOffset::Implicit)));
        assert_eq!(a(&["0", "4", "+1"]), Ok((0, 4, LvOffset::Relative(1))));
        assert_eq!(a(&["0", "4", "7"]), Ok((0, 4, LvOffset::Absolute(7))));
        assert_eq!(a(&["-1", "4"]), Err("payload offset1 must be positive".into()));
        assert_eq!(a(&["0", "0"]), Err("payload length must be > 0".into()));
        assert_eq!(a(&["0", "1", "x"]), Err("payload offset2 is not a number".into()));
        assert_eq!(a(&["1", "1", "-3"]), Err("payload offset2 too negative".into()));
    }

    /// A hello with the given session id and a body whose length is exactly `n` bytes after
    /// the session id (padding or truncated lists), the record and handshake lengths matching.
    fn raw_hello(sid: usize, tail: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend(0..32u8);
        body.push(sid as u8);
        body.extend(vec![9u8; sid]);
        body.extend(tail);
        let mut hs = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend(body);
        let mut rec = vec![0x16, 3, 1, (hs.len() >> 8) as u8, hs.len() as u8];
        rec.extend(hs);
        rec
    }

    #[test]
    fn a_hello_cut_short_inside_is_refused_not_waited_for() {
        // Nothing after a 32-byte session id but 3 bytes: no room for a cipher list.
        assert_eq!(cipherlist(&raw_hello(32, &[0, 0, 0])), Raw::No);
        // Ciphers and one compression method fill the hello: no extension length follows.
        let d = raw_hello(0, &[0, 6, 0x13, 1, 0x13, 2, 0x13, 3, 2, 0, 1]);
        assert_eq!(sni(&d), Raw::No);
        assert_eq!(cipherlist(&d), Raw::Found(vec![0x13, 1, 0x13, 2, 0x13, 3]));
        // The same with an empty extension block: refused (HAProxy wants two bytes past the list).
        assert_eq!(sni(&raw_hello(0, &[0, 6, 0x13, 1, 0x13, 2, 0x13, 3, 1, 0, 0, 0])), Raw::No);
    }

    #[test]
    fn alpn_extension_shapes() {
        let hello_with = |e: &[u8]| {
            let mut tail = vec![0, 2, 0x13, 2, 1, 0];
            tail.extend((e.len() as u16).to_be_bytes());
            tail.extend(e);
            raw_hello(0, &tail)
        };
        // A server_name extension too small to hold a list length.
        assert_eq!(sni(&hello_with(&[0, 0, 0, 1, 0])), Raw::No);
        assert_eq!(supported_groups(&hello_with(&[0, 10, 0, 1, 0])), Raw::No, "a list extension too small for its length");
        // Too small to hold a list length and a name length.
        assert_eq!(alpn(&hello_with(&[0, 16, 0, 2, 0, 0])), Raw::No);
        // A name running past its extension.
        assert_eq!(alpn(&hello_with(&[0, 16, 0, 5, 0, 3, 0x20, b'a', b'b'])), Raw::No);
        assert_eq!(alpn(&hello_with(&[0, 16, 0, 5, 0, 3, 2, b'h', b'2'])), Raw::Found(vec![b"h2".to_vec()]));
    }

    #[test]
    fn rdp_cookie_shapes() {
        let c = |tail: &[u8], name: Option<&str>| rdp_cookie(&[&[3u8, 0, 0, 0x1a, 0x0e, 0xe0, 0, 0, 0, 0, 0][..], tail].concat(), name);
        assert_eq!(c(b"Cookie: m", Some("mstshash")), Raw::TooShort, "the name does not fit yet");
        assert_eq!(c(b"Cookie: ab\r\n", None), Raw::No, "a line end before any equal sign");
        assert_eq!(c(b"Cookie: abc", None), Raw::TooShort, "no equal sign yet");
        assert_eq!(c(b"Cookie: a=b\rX", None), Raw::No, "a CR not followed by LF");
        assert_eq!(c(b"Cookie: a=b\r\n", None), Raw::Found(b"b".to_vec()));
        assert_eq!(c(b"COOKIE:   MSTSHASH=u\r\n", Some("mstshash")), Raw::Found(b"u".to_vec()), "case and spaces");
        assert_eq!(c(b"Cookie: other=b\r\n", Some("mstshash")), Raw::No);
    }

    #[test]
    fn the_registered_fetches_read_the_buffer_of_their_direction() {
        use crate::registry::SampleContext;
        let reg = crate::registry::sample_registry();
        let hello = raw_hello(0, &[0, 2, 0x13, 2, 1, 0, 0, 0]);
        let ctx = SampleContext { phase: &crate::PhaseCtx { raw_res: Some(&hello), ..Default::default() }, live: None };
        let get = |name: &str| (reg.get_fetch(name).expect(name).func)(&ctx, &[]);
        assert_eq!(get("res.ssl_hello_type"), Some(crate::sample::Sample::Sint(1)));
        assert_eq!(get("rep_ssl_hello_type"), Some(crate::sample::Sample::Sint(1)));
        assert_eq!(get("req.ssl_hello_type"), None);
    }

    #[test]
    fn ssl_ver_of_an_sslv2_hello() {
        let v2 = [&[0x80u8, 0x1c, 1, 3, 0, 0, 3, 0, 0, 0, 0x10, 1, 0, 0x80][..], &(0x11..0x21u8).collect::<Vec<_>>()].concat();
        assert_eq!(ssl_ver(&v2), Raw::Found(0x0003_0000));
        assert_eq!(ssl_ver(&v2[..10]), Raw::TooShort, "the fixed fields are not all there");
        assert_eq!(ssl_ver(&v2[..v2.len() - 1]), Raw::TooShort, "the challenge is not all there");
        assert_eq!(ssl_ver(&[0x80, 0x1c, 2, 3, 0, 0, 3, 0, 0, 0, 0x10]), Raw::No, "not a CLIENT-HELLO");
    }
}
