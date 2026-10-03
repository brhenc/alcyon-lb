// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Persistence by cookie: the backend's `cookie <name> [options]` line.
//!
//! This is `http_manage_client_side_cookies`, `http_manage_server_side_cookies`, the
//! `Set-Cookie` insertion of `http_process_res_common` and
//! `http_check_response_for_cacheability` (`src/http_ana.c`), with `http_del_hdr_value`,
//! `http_find_cookie_value_end` (`src/http.c`) and `s30tob64`/`b64tos30` (`src/base64.c`),
//! ported pointer for pointer: the header values are byte vectors and the C pointers are
//! indices into them, so that spaces are stripped, values cut and `$` attributes dragged
//! along exactly where `HAProxy` does it. Nothing here touches a session; the engine hands
//! in the header values and applies what comes back.

use ibex_config::CookieConfig;

/// What one transaction learns from the request's cookies and the response needs
/// (`SF_DIRECT`, `txn->cookie_first_date`, `txn->cookie_last_date`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CookieTxn {
    /// The server was chosen by the client's cookie (`SF_DIRECT`).
    pub direct: bool,
    /// When the cookie was first set, seconds (a multiple of 4), or 0.
    pub first_date: i32,
    /// When the cookie was last seen, seconds (a multiple of 4), or 0.
    pub last_date: i32,
    /// What the client's cookie was (`TX_CK_*`), as an index into [`CK_STATES`].
    pub ck: u8,
    /// What became of the persistence cookie in the response (`TX_SCK_*`), as an index
    /// into [`SCK_STATES`].
    pub sck: u8,
}

/// The first of the two cookie characters of the termination state (`%tsc`), by
/// `TX_CK_*`: none, invalid, down server, valid, expired, old, unused.
pub const CK_STATES: &[u8; 8] = b"NIDVEOU7";
/// The second: none, passive (found and forwarded), deleted, inserted, replaced, updated.
pub const SCK_STATES: &[u8; 8] = b"NPDIRU67";

impl CookieTxn {
    /// The two `%tsc` characters.
    #[must_use]
    pub fn log_chars(&self) -> [u8; 2] {
        [CK_STATES[usize::from(self.ck & 7)], SCK_STATES[usize::from(self.sck & 7)]]
    }
}

/// What a server offers a cookie: its `cookie` value and whether a client may be sent to
/// it (`srv->cur_state != SRV_ST_STOPPED`).
#[derive(Debug, Clone, Copy)]
pub struct SrvCookie<'a> {
    pub value: Option<&'a [u8]>,
    pub usable: bool,
}

/// What to do with one `Cookie` header after its value went through [`client_side`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderEdit {
    Keep,
    Set(Vec<u8>),
    Remove,
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `s30tob64`: 30 bits as five base64 digits, no padding.
#[must_use]
pub fn s30tob64(mut v: i32) -> [u8; 5] {
    let mut out = [0u8; 5];
    for o in &mut out {
        *o = B64[((v >> 24) & 0x3f) as usize];
        v <<= 6;
    }
    out
}

/// `b64tos30`: the inverse, or -1 for a character that is not a base64 digit (padding
/// included). `s` must hold five bytes.
#[must_use]
pub fn b64tos30(s: &[u8]) -> i32 {
    let mut out = 0i32;
    for &c in &s[..5] {
        let Some(b) = B64.iter().position(|&d| d == c) else {
            return -1;
        };
        out = (out << 6) + b as i32;
    }
    out
}

/// `HTTP_IS_SPHT`.
const fn spht(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// `http_find_cookie_value_end`: the `,` or `;` that ends the value starting at `s`, outside
/// quotes, or the end.
fn cookie_value_end(h: &[u8], mut s: usize) -> usize {
    let (mut quoted, mut qdpair) = (false, false);
    while s < h.len() {
        let c = h[s];
        if qdpair {
            qdpair = false;
        } else if quoted {
            if c == b'\\' {
                qdpair = true;
            } else if c == b'"' {
                quoted = false;
            }
        } else if c == b'"' {
            quoted = true;
        } else if c == b',' || c == b';' {
            return s;
        }
        s += 1;
    }
    s
}

/// `http_del_hdr_value`: removes the value from `*from` up to the delimiter at `next`,
/// keeping the one delimiter-and-space that must stay. `*from` moves back over blanks.
/// Returns the (negative) change of the header's length.
fn del_hdr_value(h: &mut Vec<u8>, from: &mut usize, mut next: usize) -> isize {
    let end = h.len();
    let mut prev = *from;
    if prev == 0 {
        // The first value: eat the semicolon, if there is one.
        if next < end {
            next += 1;
        }
        while next < end && spht(h[next]) {
            next += 1;
        }
    } else {
        while spht(h[prev - 1]) {
            prev -= 1;
        }
        *from = prev;
        // Every caller passes the delimiter that follows the value, never the end.
        debug_assert!(next < end);
        h[prev] = h[next];
        prev += 1;
        next += 1;
        if prev + 1 < next {
            h[prev] = b' ';
            prev += 1;
        }
        while next < end && spht(h[next]) {
            next += 1;
        }
    }
    h.drain(prev..next);
    prev as isize - next as isize
}

/// `idx + delta`: the C code adds a negative `delta` to its pointers.
fn shift(idx: usize, delta: isize) -> usize {
    idx.saturating_add_signed(delta)
}

/// Removes the blanks around the `=` of the cookie at `att_end..equal..val_beg`, as both
/// parsers do before looking at the name. Returns how much shorter the header got.
fn strip_equal_blanks(h: &mut Vec<u8>, att_end: usize, equal: &mut usize, val_beg: &mut usize) -> isize {
    let mut stripped = 0isize;
    if att_end != *equal {
        h.drain(att_end..*equal);
        let d = att_end as isize - *equal as isize;
        stripped += d;
        *equal = att_end;
        *val_beg = shift(*val_beg, d);
    }
    if *val_beg > *equal + 1 {
        h.drain(*equal + 1..*val_beg);
        stripped += (*equal + 1) as isize - *val_beg as isize;
        *val_beg = *equal + 1;
    }
    stripped
}

/// One `Cookie` header value through `http_manage_client_side_cookies`. Returns whether any
/// of the header is left; `h` is edited in place. `st` carries what earlier headers of the
/// same request found, and `srv` the server chosen so far.
#[allow(clippy::too_many_lines)]
fn client_value(cfg: &CookieConfig, now: i64, servers: &[SrvCookie<'_>], h: &mut Vec<u8>, st: &mut CookieTxn, srv: &mut Option<usize>) {
    let name = cfg.name.as_bytes();
    let mut is_first = true;
    let mut del_from: Option<usize> = None;
    let mut preserve_hdr = false;
    let mut prev = 0usize;
    while prev < h.len() {
        let mut att_beg = prev;
        if !is_first {
            att_beg += 1;
        }
        is_first = false;
        while att_beg < h.len() && spht(h[att_beg]) {
            att_beg += 1;
        }
        // <att_end> is after the last non-blank before the equal sign.
        let mut equal = att_beg;
        let mut att_end = att_beg;
        while equal < h.len() {
            let c = h[equal];
            if c == b'=' || c == b',' || c == b';' {
                break;
            }
            equal += 1;
            if spht(c) {
                continue;
            }
            att_end = equal;
        }
        let (mut val_beg, mut val_end, mut next);
        if equal < h.len() && h[equal] == b'=' {
            val_beg = equal + 1;
            while val_beg < h.len() && spht(h[val_beg]) {
                val_beg += 1;
            }
            next = cookie_value_end(h, val_beg);
            val_end = next;
            while val_end > val_beg && spht(h[val_end - 1]) {
                val_end -= 1;
            }
        } else {
            val_beg = equal;
            val_end = equal;
            next = equal;
        }

        // An RFC 2109 attribute: it goes with the cookie before it.
        if att_beg < h.len() && h[att_beg] == b'$' {
            prev = next;
            continue;
        }

        // No equal sign: not ours, to be preserved.
        if equal == next {
            preserve_hdr = true;
            if let Some(mut d) = del_from.take() {
                let delta = del_hdr_value(h, &mut d, prev);
                next = shift(next, delta);
            }
            prev = next;
            continue;
        }

        if att_end != equal || val_beg > equal + 1 {
            let stripped = strip_equal_blanks(h, att_end, &mut equal, &mut val_beg);
            val_end = shift(val_end, stripped);
            next = shift(next, stripped);
        }

        if att_end - att_beg == name.len() && &h[att_beg..att_end] == name {
            // `NAME=SRV[|<lastseen>[|<firstseen>]]`, or in prefix mode `NAME=SRV~VALUE`.
            let mut delim;
            if cfg.prefix {
                delim = val_beg;
                while delim < val_end && h[delim] != b'~' {
                    delim += 1;
                }
            } else {
                delim = val_end;
                if let Some(bar) = h[val_beg..val_end].iter().position(|&c| c == b'|') {
                    let mut vbar = val_beg + bar;
                    delim = vbar;
                    vbar += 1;
                    if val_end - vbar >= 5 {
                        let v = b64tos30(&h[vbar..]);
                        if v > 0 {
                            st.last_date = v << 2;
                        }
                    }
                    if let Some(bar2) = h[vbar..val_end].iter().position(|&c| c == b'|') {
                        let v2 = vbar + bar2;
                        if val_end - v2 > 5 {
                            let v = b64tos30(&h[v2 + 1..]);
                            if v > 0 {
                                st.first_date = v << 2;
                            }
                        }
                    }
                }
            }

            // `maxlife`, then `maxidle`: a cookie too old is pretended not to be there. A
            // date more than a day ahead is the same.
            let first_gap = (now - i64::from(st.first_date)) as i32;
            let last_gap = (now - i64::from(st.last_date)) as i32;
            if st.first_date != 0
                && cfg.maxlife != 0
                && (first_gap > cfg.maxlife as i32 || first_gap.wrapping_neg() > 86400)
            {
                delim = val_beg;
                st.ck = 5;
                st.first_date = 0;
                st.last_date = 0;
            } else if st.last_date != 0 && cfg.maxidle != 0 && (last_gap > cfg.maxidle as i32 || last_gap.wrapping_neg() > 86400) {
                delim = val_beg;
                st.ck = 4;
                st.first_date = 0;
                st.last_date = 0;
            }

            // The first running server with this cookie value; an empty value is no value,
            // and once a server is assigned the later cookies are not looked up.
            let assigned = srv.is_some();
            let mut found = false;
            if delim != val_beg && !assigned {
                let wanted = &h[val_beg..delim];
                for (i, s) in servers.iter().enumerate() {
                    if s.value == Some(wanted) {
                        if s.usable {
                            *srv = Some(i);
                            st.direct = true;
                            st.ck = 3;
                            found = true;
                            break;
                        }
                        // A server with this cookie, but down: go on in case another is up.
                        st.ck = 2;
                    }
                }
            }
            // No server, and no reason given by a date or a down server: an invalid cookie,
            // or one set aside because a server was already chosen. (HAProxy tests the
            // bits of `TX_CK_*`, which is why every state past "invalid" counts as a reason.)
            if !found && st.ck & 6 == 0 {
                st.ck = if assigned { 6 } else { 1 };
            }

            // Prefix mode: the server id comes off, and the cookie is the application's.
            // Insert plus indirect: the whole cookie goes, the server never sees it.
            if cfg.prefix && delim != val_end {
                h.drain(val_beg..=delim);
                next = shift(next, val_beg as isize - (delim as isize + 1));
                del_from = None;
                preserve_hdr = true;
            } else if del_from.is_none() && cfg.insert && cfg.indirect {
                del_from = Some(prev);
            }
        } else {
            // Not ours. A cookie scheduled for removal before it goes now: the block
            // between, not the whole header.
            preserve_hdr = true;
            if let Some(mut d) = del_from.take() {
                let delta = del_hdr_value(h, &mut d, prev);
                next = shift(next, delta);
            }
        }
        prev = next;
    }

    // Cookies marked for deletion at the end of the line.
    if let Some(d) = del_from {
        h.truncate(if preserve_hdr { d } else { 0 });
    }
}

/// `http_manage_client_side_cookies` over every `Cookie` header value of a request, in
/// order. Returns the server the cookie chose (an index into `servers`), what the
/// transaction learnt, and one edit per input value.
#[must_use]
pub fn client_side(
    cfg: &CookieConfig,
    now: i64,
    servers: &[SrvCookie<'_>],
    values: &[Vec<u8>],
) -> (Option<usize>, CookieTxn, Vec<HeaderEdit>) {
    let mut st = CookieTxn::default();
    let mut srv = None;
    let mut edits = Vec::with_capacity(values.len());
    for v in values {
        let mut h = v.clone();
        client_value(cfg, now, servers, &mut h, &mut st, &mut srv);
        edits.push(if h == *v {
            HeaderEdit::Keep
        } else if h.is_empty() {
            HeaderEdit::Remove
        } else {
            HeaderEdit::Set(h)
        });
    }
    (srv, st, edits)
}

/// What a `Set-Cookie` header did to the persistence cookie (`TX_SCK_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// Not the persistence cookie.
    No,
    /// It is, and is forwarded as it is.
    Passive,
    /// It is, and the whole header is to be removed.
    Deleted,
    /// It is, and its value was rewritten.
    Replaced,
}

/// One `Set-Cookie` value through `http_manage_server_side_cookies`. Only the first cookie of
/// the header is looked at (a `Set-Cookie` cannot be folded). `target` is the server the
/// request went to: `None` when there is none, else its `cookie` value.
fn server_value(cfg: &CookieConfig, target: Option<Option<&[u8]>>, direct: bool, h: &mut Vec<u8>) -> Seen {
    let name = cfg.name.as_bytes();
    let mut att_beg = 0;
    while att_beg < h.len() && spht(h[att_beg]) {
        att_beg += 1;
    }
    let mut equal = att_beg;
    let mut att_end = att_beg;
    while equal < h.len() {
        let c = h[equal];
        if c == b'=' || c == b';' {
            break;
        }
        equal += 1;
        if spht(c) {
            continue;
        }
        att_end = equal;
    }
    let (mut val_beg, mut val_end);
    if equal < h.len() && h[equal] == b'=' {
        val_beg = equal + 1;
        while val_beg < h.len() && spht(h[val_beg]) {
            val_beg += 1;
        }
        val_end = cookie_value_end(h, val_beg);
        while val_end > val_beg && spht(h[val_end - 1]) {
            val_end -= 1;
        }
    } else {
        return Seen::No;
    }

    let stripped = if att_end != equal || val_beg > equal + 1 {
        strip_equal_blanks(h, att_end, &mut equal, &mut val_beg)
    } else {
        0
    };
    val_end = shift(val_end, stripped);

    if att_end - att_beg != name.len() || &h[att_beg..att_end] != name {
        return Seen::No;
    }
    if cfg.preserve {
        return Seen::Passive;
    }
    if (target.is_some() && cfg.insert) || (direct && cfg.indirect) {
        // Replaced by the one inserted later, or hidden from a direct access.
        return Seen::Deleted;
    }
    if let Some(Some(ck)) = target {
        if cfg.rewrite {
            h.splice(val_beg..val_end, ck.iter().copied());
            return Seen::Replaced;
        } else if cfg.prefix {
            let mut pre = ck.to_vec();
            pre.push(b'~');
            h.splice(val_beg..val_beg, pre);
            return Seen::Replaced;
        }
    }
    Seen::Passive
}

/// What the response is judged on for `nocache` (`TX_CACHEABLE`).
#[derive(Debug, Clone, Copy)]
pub struct ReqKind {
    /// GET, HEAD, OPTIONS or TRACE: a response may be cacheable.
    pub safe_method: bool,
    pub post: bool,
}

fn comma_values<'a>(hdrs: &'a [(String, String)], name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    hdrs.iter()
        .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
        .flat_map(|(_, v)| v.split(','))
        .map(|v| v.trim_matches(|c| c == ' ' || c == '\t'))
}

fn starts_with_ci(v: &str, prefix: &str) -> bool {
    v.len() >= prefix.len() && v.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

/// `TX_CACHEABLE` after the status check of `http_process_res_common` and
/// `http_check_response_for_cacheability`.
#[must_use]
pub fn response_cacheable(req: ReqKind, status: u16, hdrs: &[(String, String)]) -> bool {
    let mut cacheable = req.safe_method && matches!(status, 200 | 203 | 204 | 206 | 300 | 301 | 404 | 405 | 410 | 414 | 501);
    if status < 200 {
        return false;
    }
    if let Some((_, v)) = hdrs.iter().find(|(k, _)| k.eq_ignore_ascii_case("pragma")) {
        if v.trim().eq_ignore_ascii_case("no-cache") {
            return false;
        }
    }
    let (mut fresh, mut null_maxage) = (false, false);
    for v in comma_values(hdrs, "cache-control") {
        if v.eq_ignore_ascii_case("public") {
            cacheable = true;
        } else if v.eq_ignore_ascii_case("max-age=0") {
            null_maxage = true;
        } else if v.eq_ignore_ascii_case("no-cache=\"set-cookie\"") {
            // Only the cookie is not to be cached.
        } else if v.eq_ignore_ascii_case("private")
            || starts_with_ci(v, "private=")
            || v.eq_ignore_ascii_case("no-cache")
            || starts_with_ci(v, "no-cache=")
            || v.eq_ignore_ascii_case("no-store")
            || starts_with_ci(v, "no-store=")
            || v.eq_ignore_ascii_case("s-maxage=0")
        {
            cacheable = false;
        } else if starts_with_ci(v, "s-maxage") {
            fresh = true;
            null_maxage = false;
        } else if starts_with_ci(v, "max-age") {
            fresh = true;
        }
    }
    if null_maxage {
        cacheable = false;
    }
    let has_hdr = |n: &str| hdrs.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
    if !fresh {
        fresh = has_hdr("expires");
    }
    let validator = !fresh && (has_hdr("etag") || has_hdr("last-modified"));
    if !fresh && !validator {
        cacheable = false;
    }
    cacheable
}

/// The server the response came from, as far as the cookie is concerned.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    /// Its `cookie` value.
    pub value: Option<&'a [u8]>,
}

/// `Set-Cookie` and `Cache-control` handling of a final response: the server's own cookie
/// edited or removed, the persistence cookie inserted, and `nocache` applied. `hdrs` is the
/// response's header list, in order; headers added go at its end. Returns what became of
/// the persistence cookie (`CookieTxn::sck`).
pub fn process_response(
    cfg: &CookieConfig,
    target: Option<Target<'_>>,
    txn: &CookieTxn,
    req: ReqKind,
    status: u16,
    now: i64,
    hdrs: &mut Vec<(String, String)>,
) -> u8 {
    // `http_manage_server_side_cookies`.
    let tgt = target.map(|t| t.value);
    let mut found = false;
    let mut sck = txn.sck;
    let mut i = 0;
    while i < hdrs.len() {
        if hdrs[i].0.eq_ignore_ascii_case("set-cookie") {
            let mut v = hdrs[i].1.clone().into_bytes();
            let seen = server_value(cfg, tgt, txn.direct, &mut v);
            found |= seen != Seen::No;
            sck = match seen {
                Seen::No => sck,
                Seen::Passive => 1,
                Seen::Deleted => 2,
                Seen::Replaced => 4,
            };
            if seen == Seen::Deleted {
                hdrs.remove(i);
                continue;
            }
            hdrs[i].1 = String::from_utf8_lossy(&v).into_owned();
        }
        i += 1;
    }

    let cacheable = cfg.nocache && response_cacheable(req, status, hdrs);

    // Insert the cookie: the server is known and it is not the one the client asked for,
    // or the dates of the cookie need refreshing.
    let Some(Target { value }) = target else {
        return sck;
    };
    let last_in_past = i64::from(txn.last_date) < now;
    let insert = cfg.insert
        && !(found && cfg.preserve)
        && (!txn.direct
            || ((cfg.maxidle != 0 || txn.last_date != 0) && (txn.last_date == 0 || last_in_past))
            || (cfg.maxlife != 0 && txn.first_date == 0)
            || (cfg.maxlife == 0 && txn.first_date != 0))
        && (!cfg.postonly || req.post);
    if !insert {
        return sck;
    }
    let mut c = String::new();
    if let Some(value) = value {
        c.push_str(&cfg.name);
        c.push('=');
        c.push_str(&String::from_utf8_lossy(value));
        if cfg.maxidle != 0 || cfg.maxlife != 0 {
            // The last-seen date, mandatory; and the first date, the original one or now.
            c.push('|');
            c.push_str(&String::from_utf8_lossy(&s30tob64(((now + 3) >> 2) as i32)));
            if cfg.maxlife != 0 {
                c.push('|');
                let first = if txn.first_date != 0 { txn.first_date >> 2 } else { ((now + 3) >> 2) as i32 };
                c.push_str(&String::from_utf8_lossy(&s30tob64(first)));
            }
        }
        c.push_str("; path=/");
    } else {
        c.push_str(&cfg.name);
        c.push_str("=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/");
    }
    if let Some(d) = &cfg.domain {
        c.push_str("; domain=");
        c.push_str(d);
    }
    if cfg.httponly {
        c.push_str("; HttpOnly");
    }
    if cfg.secure {
        c.push_str("; Secure");
    }
    if let Some(a) = &cfg.attrs {
        c.push_str("; ");
        c.push_str(a);
    }
    hdrs.push(("Set-Cookie".to_string(), c));
    // Only the date was updated when the server did not change.
    sck = if value.is_some() && txn.direct { 5 } else { 3 };

    // HTTP/1.0 caches keep cookies: tell them not to.
    if cacheable {
        hdrs.push(("Cache-control".to_string(), "private".to_string()));
    }
    sck
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(opts: &str) -> CookieConfig {
        let text = format!("backend b\n  cookie SRV {}\n  server s 127.0.0.1:1\n", opts.replace("maxidle", "maxidle 1h").replace("maxlife", "maxlife 1h"));
        ibex_config::parse_str(&text).expect("parse").backends[0].cookie.clone().expect("a cookie")
    }

    const SRVS: [SrvCookie<'static>; 3] = [
        SrvCookie { value: Some(b"a"), usable: true },
        SrvCookie { value: Some(b"b"), usable: true },
        SrvCookie { value: None, usable: true },
    ];

    fn client(opts: &str, now: i64, hdrs: &[&str]) -> (Option<usize>, CookieTxn, Vec<String>) {
        let vals: Vec<Vec<u8>> = hdrs.iter().map(|h| h.as_bytes().to_vec()).collect();
        let (srv, txn, edits) = client_side(&cfg(opts), now, &SRVS, &vals);
        let out = vals
            .iter()
            .zip(edits)
            .filter_map(|(v, e)| match e {
                HeaderEdit::Keep => Some(String::from_utf8(v.clone()).unwrap()),
                HeaderEdit::Set(s) => Some(String::from_utf8(s).unwrap()),
                HeaderEdit::Remove => None,
            })
            .collect();
        (srv, txn, out)
    }

    #[test]
    fn dates_round_trip_as_haproxy_writes_them() {
        // Measured: HAProxy wrote `AAAAA` for 0 and the digits are the standard alphabet.
        assert_eq!(&s30tob64(0), b"AAAAA");
        assert_eq!(&s30tob64(1), b"AAAAB");
        assert_eq!(&s30tob64(63), b"AAAA/");
        assert_eq!(&s30tob64((1 << 30) - 1), b"/////");
        for v in [1, 63, 64, 123_456_789, (1 << 30) - 1] {
            assert_eq!(b64tos30(&s30tob64(v)), v);
        }
        assert_eq!(b64tos30(b"ab=cd"), -1);
        assert_eq!(b64tos30(b"AAA-A"), -1);
    }

    #[test]
    fn a_cookie_chooses_the_first_usable_server_with_its_value() {
        let (srv, st, out) = client("insert", 1000, &["SRV=b; o=1"]);
        assert_eq!((srv, st.direct, out), (Some(1), true, vec!["SRV=b; o=1".to_string()]));
        // An empty value, an unknown one and another case choose nothing.
        for h in ["SRV=", "SRV", "SRV=zz", "srv=b", "SRV=B"] {
            let (srv, st, _) = client("insert", 1000, &[h]);
            assert_eq!((srv, st.direct), (None, false), "{h}");
        }
        // Once chosen, a later cookie of the name is not looked up.
        let (srv, _, _) = client("insert", 1000, &["SRV=b", "SRV=a"]);
        assert_eq!(srv, Some(1));
        // A server that is not usable is passed over for the next one with the value.
        let mut down = SRVS;
        down[0].usable = false;
        let dup = [down[0], SrvCookie { value: Some(b"a"), usable: true }];
        let (srv, _, _) = client_side(&cfg("insert"), 0, &dup, &[b"SRV=a".to_vec()]);
        assert_eq!(srv, Some(1));
        let (srv, _, _) = client_side(&cfg("insert"), 0, &dup[..1], &[b"SRV=a".to_vec()]);
        assert_eq!(srv, None);
    }

    #[test]
    fn indirect_cuts_the_cookie_as_http_del_hdr_value_does() {
        let cases: [(&[&str], &str); 12] = [
            (&["SRV=b"], ""),
            (&["SRV=b; o=1"], "o=1"),
            (&["o=1; SRV=a"], "o=1"),
            (&["o=1; SRV=a; p=2"], "o=1; p=2"),
            (&["o = 1 ; SRV = b ; p=2"], "o=1; p=2"),
            (&["q=\"x;y\"; SRV=b"], "q=\"x;y\""),
            (&["$Version=1; SRV=b; $Path=/; o=1"], "$Version=1; o=1"),
            (&["SRV=b, o=1"], "o=1"),
            (&["o=1", "SRV=b"], "o=1"),
            (&["SRV=b", "p=2; SRV=a"], "p=2"),
            (&["x;  SRV=b;  y"], "x; y"),
            (&["SRV=b  ;  "], ""),
        ];
        for (hdrs, want) in cases {
            let (_, _, out) = client("insert indirect", 1000, hdrs);
            assert_eq!(out.join("|"), want, "{hdrs:?}");
        }
    }

    #[test]
    fn prefix_takes_the_server_id_off() {
        for (h, want) in [("SRV=b~xyz", "SRV=xyz"), ("o=1; SRV=b~xyz", "o=1; SRV=xyz"), ("SRV=b~", "SRV="), ("SRV=xyz", "SRV=xyz")] {
            let (srv, _, out) = client("prefix", 1000, &[h]);
            assert_eq!(out, vec![want.to_string()], "{h}");
            assert_eq!(srv, if h.contains('~') { Some(1) } else { None }, "{h}");
        }
    }

    #[test]
    fn dates_are_read_and_checked_only_when_asked() {
        let now = 1_700_000_000i64;
        let d = |t: i64| String::from_utf8(s30tob64((t >> 2) as i32).to_vec()).unwrap();
        // Read, and kept, with maxidle; not an error without it.
        let (srv, st, _) = client("insert maxidle", now, &[&format!("SRV=b|{}", d(now - 60))]);
        assert_eq!((srv, st.last_date), (Some(1), ((now - 60) >> 2 << 2) as i32));
        let (srv, st, _) = client("insert", now, &[&format!("SRV=b|{}", d(now - 7200))]);
        assert_eq!((srv, st.last_date != 0), (Some(1), true));
        // Idle two hours, or two days ahead: not followed, dates forgotten.
        for t in [now - 7200, now + 2 * 86400] {
            let (srv, st, _) = client("insert maxidle", now, &[&format!("SRV=b|{}", d(t))]);
            assert_eq!((srv, st.first_date, st.last_date, st.ck), (None, 0, 0, 4), "{t}");
        }
        // maxlife looks at the first date.
        let (srv, st, _) = client("insert maxlife", now, &[&format!("SRV=b|{}|{}", d(now), d(now - 60))]);
        assert_eq!((srv, st.first_date), (Some(1), ((now - 60) >> 2 << 2) as i32));
        let (srv, _, _) = client("insert maxlife", now, &[&format!("SRV=b|{}|{}", d(now), d(now - 7200))]);
        assert_eq!(srv, None);
        // Something that is not a date is no date.
        for v in ["b|ab=cd", "b|ab"] {
            let (srv, st, _) = client("insert maxidle", now, &[&format!("SRV={v}")]);
            assert_eq!((srv, st.last_date), (Some(1), 0), "{v}");
        }
    }

    fn respond(opts: &str, target: Option<Option<&[u8]>>, txn: CookieTxn, req: ReqKind, hdrs: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut h: Vec<(String, String)> = hdrs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect();
        let _ = process_response(&cfg(opts), target.map(|value| Target { value }), &txn, req, 200, 1_700_000_000, &mut h);
        h
    }

    const GET: ReqKind = ReqKind { safe_method: true, post: false };

    fn pairs(h: &[(String, String)]) -> Vec<String> {
        h.iter().map(|(k, v)| format!("{k}: {v}")).collect()
    }

    #[test]
    fn insert_adds_the_cookie_and_replaces_the_servers() {
        let a: Option<&[u8]> = Some(b"a");
        let h = respond("insert", Some(a), CookieTxn::default(), GET, &[("Set-Cookie", "other=1"), ("set-cookie", "SRV=zzz; path=/x")]);
        assert_eq!(pairs(&h), ["Set-Cookie: other=1", "Set-Cookie: SRV=a; path=/"]);
        // A direct access gets nothing, and the server's own cookie stays with plain insert.
        let direct = CookieTxn { direct: true, ..CookieTxn::default() };
        assert!(respond("insert", Some(a), direct, GET, &[]).is_empty());
        // No server: nothing to insert.
        assert!(respond("insert", None, CookieTxn::default(), GET, &[]).is_empty());
        // A server without a value: told to forget it.
        let h = respond("insert", Some(None), CookieTxn::default(), GET, &[]);
        assert_eq!(pairs(&h), ["Set-Cookie: SRV=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/"]);
        // Preserve keeps the server's cookie and inserts nothing; without one it inserts.
        let h = respond("insert preserve", Some(a), CookieTxn::default(), GET, &[("Set-Cookie", "SRV=zzz")]);
        assert_eq!(pairs(&h), ["Set-Cookie: SRV=zzz"]);
        let h = respond("insert preserve", Some(a), CookieTxn::default(), GET, &[]);
        assert_eq!(pairs(&h), ["Set-Cookie: SRV=a; path=/"]);
        // postonly
        assert!(respond("insert postonly", Some(a), CookieTxn::default(), GET, &[]).is_empty());
        let post = ReqKind { safe_method: false, post: true };
        assert_eq!(respond("insert postonly", Some(a), CookieTxn::default(), post, &[]).len(), 1);
    }

    #[test]
    fn attributes_follow_in_haproxys_order() {
        let mut c = cfg("insert");
        c.httponly = true;
        c.secure = true;
        c.domain = Some(".a.com; domain=.b.org".into());
        c.attrs = Some("SameSite=Lax; Foo".into());
        let mut h = Vec::new();
        let _ = process_response(&c, Some(Target { value: Some(b"a") }), &CookieTxn::default(), GET, 200, 0, &mut h);
        assert_eq!(h[0].1, "SRV=a; path=/; domain=.a.com; domain=.b.org; HttpOnly; Secure; SameSite=Lax; Foo");
    }

    #[test]
    fn rewrite_prefix_and_indirect_edit_the_servers_cookie() {
        let b: Option<&[u8]> = Some(b"b");
        let h = respond("rewrite", Some(b), CookieTxn::default(), GET, &[("Set-Cookie", "SRV = zzz ; path=/x")]);
        assert_eq!(pairs(&h), ["Set-Cookie: SRV=b ; path=/x"]);
        let h = respond("prefix", Some(b), CookieTxn::default(), GET, &[("Set-Cookie", "SRV=abc; path=/")]);
        assert_eq!(pairs(&h), ["Set-Cookie: SRV=b~abc; path=/"]);
        // A server without a value leaves it alone.
        let h = respond("rewrite", Some(None), CookieTxn::default(), GET, &[("Set-Cookie", "SRV=abc")]);
        assert_eq!(pairs(&h), ["Set-Cookie: SRV=abc"]);
        let direct = CookieTxn { direct: true, ..CookieTxn::default() };
        assert!(respond("indirect", Some(b), direct, GET, &[("Set-Cookie", "SRV=b")]).is_empty());
        let h = respond("indirect", Some(b), CookieTxn::default(), GET, &[("Set-Cookie", "SRV=a")]);
        assert_eq!(pairs(&h), ["Set-Cookie: SRV=a"]);
        // Another cookie has its blanks around the equal sign stripped all the same.
        let h = respond("indirect", Some(b), direct, GET, &[("Set-Cookie", "x = y; path=/")]);
        assert_eq!(pairs(&h), ["Set-Cookie: x=y; path=/"]);
    }

    #[test]
    fn dates_are_written_for_maxidle_and_maxlife() {
        let a: Option<&[u8]> = Some(b"a");
        let now = 1_700_000_000i64;
        let d = String::from_utf8(s30tob64(((now + 3) >> 2) as i32).to_vec()).unwrap();
        let h = respond("insert maxidle", Some(a), CookieTxn::default(), GET, &[]);
        assert_eq!(h[0].1, format!("SRV=a|{d}; path=/"));
        let h = respond("insert maxlife", Some(a), CookieTxn::default(), GET, &[]);
        assert_eq!(h[0].1, format!("SRV=a|{d}|{d}; path=/"));
        // A direct access refreshes a past date, keeps the first, and leaves a future one.
        let first = (now - 100) as i32 >> 2 << 2;
        let old = CookieTxn { direct: true, first_date: first, last_date: (now - 60) as i32, ..CookieTxn::default() };
        let h = respond("insert maxlife", Some(a), old, GET, &[]);
        let f = String::from_utf8(s30tob64(first >> 2).to_vec()).unwrap();
        assert_eq!(h[0].1, format!("SRV=a|{d}|{f}; path=/"));
        let fresh = CookieTxn { last_date: (now + 100) as i32, ..old };
        assert!(respond("insert maxlife", Some(a), fresh, GET, &[]).is_empty());
        // A first date nothing asks for is dropped; none asked for and none seen: nothing.
        let h = respond("insert", Some(a), CookieTxn { direct: true, first_date: first, last_date: 0, ..CookieTxn::default() }, GET, &[]);
        assert_eq!(h[0].1, "SRV=a; path=/");
        // Dates are not asked for, but one was seen and is in the past: refreshed.
        let h = respond("insert maxidle", Some(a), CookieTxn { direct: true, first_date: 0, last_date: (now - 8) as i32, ..CookieTxn::default() }, GET, &[]);
        assert_eq!(h[0].1, format!("SRV=a|{d}; path=/"));
    }

    #[test]
    fn nocache_marks_only_a_cacheable_response_private() {
        let a: Option<&[u8]> = Some(b"a");
        let t = CookieTxn::default();
        let cases: [(&[(&str, &str)], bool); 9] = [
            (&[], false),
            (&[("ETag", "\"x\"")], true),
            (&[("Last-Modified", "x")], true),
            (&[("Expires", "x")], true),
            (&[("Cache-Control", "max-age=60")], true),
            (&[("Cache-Control", "public")], false),
            (&[("Cache-Control", "max-age=60, private")], false),
            (&[("Cache-Control", "max-age=0")], false),
            (&[("Pragma", "no-cache"), ("ETag", "x")], false),
        ];
        for (hdrs, private) in cases {
            let h = respond("insert nocache", Some(a), t, GET, hdrs);
            assert_eq!(h.last().map(|(k, v)| (k.as_str(), v.as_str())) == Some(("Cache-control", "private")), private, "{hdrs:?}");
        }
        let post = ReqKind { safe_method: false, post: true };
        let h = respond("insert nocache", Some(a), t, post, &[("ETag", "x")]);
        assert_eq!(h.len(), 2, "{h:?}");
        let mut h = vec![("ETag".to_string(), "x".to_string())];
        let _ = process_response(&cfg("insert nocache"), Some(Target { value: Some(b"a") }), &t, GET, 500, 0, &mut h);
        assert_eq!(h.len(), 2, "a 500 is not cacheable: {h:?}");
        assert!(!response_cacheable(GET, 199, &[]));
        assert!(response_cacheable(GET, 200, &[("Cache-Control".to_string(), "max-age=0, s-maxage=5".to_string())]));
    }

    #[test]
    fn quoted_values_hold_delimiters_and_the_last_value_goes_cleanly() {
        let (_, _, out) = client("insert indirect", 1000, &["q=\"a\\\"b;c\"; SRV=b"]);
        assert_eq!(out, ["q=\"a\\\"b;c\""]);
        let (_, _, out) = client("insert indirect", 1000, &["x; SRV=b"]);
        assert_eq!(out, ["x"]);
        // A second date that is not one, or too short, is no date.
        for v in ["SRV=b|asFbe|ab=cd", "SRV=b|asFbe|ab"] {
            let (srv, st, _) = client("insert maxlife", 1_700_000_000, &[v]);
            assert_eq!((srv, st.first_date), (Some(1), 0), "{v}");
        }
    }

    #[test]
    fn a_set_cookie_without_a_value_or_with_blanks_is_read_as_it_is() {
        let a: Option<&[u8]> = Some(b"a");
        let h = respond("insert", Some(a), CookieTxn::default(), GET, &[("Set-Cookie", "novalue")]);
        assert_eq!(pairs(&h), ["Set-Cookie: novalue", "Set-Cookie: SRV=a; path=/"]);
        let h = respond("rewrite", Some(a), CookieTxn::default(), GET, &[("Set-Cookie", "  SRV=zzz")]);
        assert_eq!(pairs(&h), ["Set-Cookie:   SRV=a"]);
    }

    #[test]
    fn cache_control_directives_are_read_as_haproxy_reads_them() {
        // A pragma that is not `no-cache` is nothing.
        assert!(response_cacheable(GET, 200, &[("Pragma".into(), "cache".into()), ("ETag".into(), "x".into())]));
        // Only the cookie is not to be cached: the response still is.
        let h = [("Cache-Control".to_string(), "no-cache=\"set-cookie\", max-age=60".to_string())];
        assert!(response_cacheable(GET, 200, &h));
        let h = [("Cache-Control".to_string(), "no-cache".to_string()), ("Expires".to_string(), "x".to_string())];
        assert!(!response_cacheable(GET, 200, &h));
    }
}
