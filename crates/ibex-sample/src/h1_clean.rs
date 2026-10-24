// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The headers of an HTTP/1 message as `HAProxy`'s parser leaves them in HTX. It takes `close`
//! and `keep-alive` out of a `Connection` value and `h2c`/`h2` out of an `Upgrade` value, and
//! drops the header when nothing is left (`h1_parse_connection_header` with
//! `H1_MF_CLEAN_CONN_HDR` and `h1_parse_upgrade_header`, `src/h1.c`). In a request it then
//! drops an `Upgrade` header that no `Connection: upgrade` refers to, and an `upgrade` token
//! that no `Upgrade` header backs (`h1_postparse_req_hdrs`, `src/h1_htx.c`).
//!
//! Ibex keeps the headers as received, so the fetches that read HTX apply the rewrite
//! themselves: those that dump the whole header block (`req.hdrs`, `res.hdrs`) through
//! [`h1_clean_headers`], those that list header names (`req.hdr_names`, `res.hdr_names`)
//! through [`kept_headers`].

fn is_lws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// The end of the element that starts at `s` (`http_find_hdr_value_end`, `src/http.c`): the
/// next comma outside a quoted string, or the end of the value.
fn value_end(v: &[u8], mut s: usize) -> usize {
    let (mut quoted, mut qdpair) = (false, false);
    while s < v.len() {
        let c = v[s];
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
        } else if c == b',' {
            return s;
        }
        s += 1;
    }
    s
}

/// `value` without the elements `drop` selects, rewritten the way `HAProxy` rewrites it in
/// place (`http_remove_header_value`, `include/haproxy/http.h`, and the same loop in
/// `h1_parse_connection_header`/`h1_parse_upgrade_header`): until the first dropped element
/// the value stays as it came (up to the end of the last element kept, blanks included);
/// after it, each kept element is appended trimmed, behind a bare `,`. Elements end at a
/// comma outside a quoted string. `drop` sees every element, kept or not.
#[must_use]
pub fn drop_items(value: &str, mut drop: impl FnMut(&str) -> bool) -> String {
    let v = value.as_bytes();
    let mut out = String::new();
    // `p`: the end of the last element seen. `out.len() == p` is the C's
    // `hv->ptr + hv->len == p`: no rewrite done till now.
    let (mut p, mut w) = (0, 0);
    while w < v.len() {
        if is_lws(v[w]) {
            w += 1;
            continue;
        }
        let n = value_end(v, w);
        let mut len = n - w;
        while len > 0 && is_lws(v[w + len - 1]) {
            len -= 1;
        }
        // `w`, `n` and `w + len` sit next to ASCII bytes, so they are char boundaries.
        let word = &value[w..w + len];
        if !drop(word) {
            if out.len() == p {
                out = value[..n].to_string();
            } else {
                if !out.is_empty() {
                    out.push(',');
                }
                out.push_str(word);
            }
        }
        p = n;
        w = n + 1;
    }
    out
}

/// For each of `headers` (name, value), in order, the value the H1 parser leaves in HTX
/// (trimmed, rewritten), or `None` when it takes the header out. `request` adds the
/// request-only `Upgrade`/`Connection: upgrade` pairing.
fn clean_values<'a>(headers: impl Iterator<Item = (&'a str, &'a str)>, request: bool) -> Vec<(&'a str, Option<String>)> {
    clean_values_with(headers, request, true)
}

/// [`clean_values`]; without `conn_tokens`, `close` and `keep-alive` stay in `Connection`.
fn clean_values_with<'a>(headers: impl Iterator<Item = (&'a str, &'a str)>, request: bool, conn_tokens: bool) -> Vec<(&'a str, Option<String>)> {
    let is = |w: &str, t: &str| w.eq_ignore_ascii_case(t);
    let (mut conn_upg, mut upg_hdr) = (false, false);
    let mut out: Vec<(&'a str, Option<String>)> = Vec::new();
    for (n, v) in headers {
        let v = v.trim_matches([' ', '\t']);
        let left = if n.eq_ignore_ascii_case("connection") {
            drop_items(v, |w| {
                conn_upg |= is(w, "upgrade");
                conn_tokens && (is(w, "close") || is(w, "keep-alive"))
            })
        } else if n.eq_ignore_ascii_case("upgrade") {
            let left = drop_items(v, |w| is(w, "h2c") || is(w, "h2"));
            upg_hdr |= !left.is_empty();
            left
        } else {
            out.push((n, Some(v.to_string())));
            continue;
        };
        out.push((n, (!left.is_empty()).then_some(left)));
    }
    if request && upg_hdr && !conn_upg {
        for (n, left) in &mut out {
            if n.eq_ignore_ascii_case("upgrade") {
                *left = None;
            }
        }
    } else if request && conn_upg && !upg_hdr {
        for (n, left) in &mut out {
            if n.eq_ignore_ascii_case("connection") {
                if let Some(l) = left {
                    let l = drop_items(l, |w| is(w, "upgrade"));
                    *left = (!l.is_empty()).then_some(l);
                }
            }
        }
    }
    out
}

/// For each of `headers` (name, value), in order, whether `HAProxy`'s H1 parser keeps it in
/// HTX. `request` adds the request-only `Upgrade`/`Connection: upgrade` pairing.
#[must_use]
pub fn kept_headers(headers: &[(&str, &str)], request: bool) -> Vec<bool> {
    clean_values(headers.iter().copied(), request).into_iter().map(|(_, v)| v.is_some()).collect()
}

/// The headers `hdrs` (name, value) as the H1 parser stores them in HTX ([`kept_headers`]
/// says which stay): names lowercased, values trimmed and rewritten.
pub(crate) fn h1_clean_headers<'a>(hdrs: impl Iterator<Item = (&'a str, &'a str)>, request: bool) -> Vec<(String, String)> {
    clean_values(hdrs, request).into_iter().filter_map(|(n, v)| Some((n.to_ascii_lowercase(), v?))).collect()
}

/// [`h1_clean_headers`] for a message whose own `close` and `keep-alive` the runtime has
/// already taken out of `Connection` (before its rules run, T439): one left there is a
/// rule's, and stays, as it does in `HAProxy`'s HTX (`req.hdr_cnt(connection)` counts the
/// `close` that `set-header connection close` wrote, T442).
pub(crate) fn h1_clean_headers_kept_conn<'a>(hdrs: impl Iterator<Item = (&'a str, &'a str)>, request: bool) -> Vec<(String, String)> {
    clean_values_with(hdrs, request, false).into_iter().filter_map(|(n, v)| Some((n.to_ascii_lowercase(), v?))).collect()
}

/// The block `smp_fetch_hdrs` builds: each header `name: value\r\n`, then `\r\n` (the end of
/// headers, always there).
pub(crate) fn header_block(hdrs: &[(String, String)]) -> String {
    let mut out = String::with_capacity(hdrs.iter().map(|(n, v)| n.len() + v.len() + 4).sum::<usize>() + 2);
    for (n, v) in hdrs {
        out.push_str(n);
        out.push_str(": ");
        out.push_str(v);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ka(w: &str) -> bool {
        w.eq_ignore_ascii_case("close") || w.eq_ignore_ascii_case("keep-alive")
    }

    #[test]
    fn drop_items_like_http_remove_header_value() {
        // Measured through req.hdrs on 3.5-dev8-885761-29.
        assert_eq!(drop_items("close", ka), "");
        assert_eq!(drop_items("close, X-Hop", ka), "X-Hop");
        assert_eq!(drop_items("X-Hop, close", ka), "X-Hop");
        assert_eq!(drop_items("A,  B", ka), "A,  B");
        assert_eq!(drop_items("keep-alive, A,  B", ka), "A,B");
        assert_eq!(drop_items("foo, Upgrade, bar", |t| t.eq_ignore_ascii_case("upgrade")), "foo,bar");
    }

    #[test]
    fn quoted_backslash_pairs_do_not_end_quotes() {
        // Measured through req.hdrs on 3.5-dev8 (Connection: `"a\",close", close, x` and
        // `"a\\",close, x`): an escaped quote keeps the string open, an escaped backslash does not.
        assert_eq!(drop_items(r#""a\",close", close, x"#, ka), r#""a\",close",x"#);
        assert_eq!(drop_items(r#""a\\",close, x"#, ka), r#""a\\",x"#);
    }

    #[test]
    fn rewrite_follows_haproxy() {
        assert_eq!(drop_items("Keep-Alive, Close", ka), "");
        assert_eq!(drop_items("close, x-y", ka), "x-y");
        assert_eq!(drop_items("x-y ,  close , z", ka), "x-y ,z"); // in place: the blank before the first comma stays
        assert_eq!(drop_items("x-y ,  z", ka), "x-y ,  z");
        assert_eq!(drop_items(",  , close", ka), ",  ");
        assert_eq!(drop_items("\"a,close\", close", ka), "\"a,close\"");
    }

    #[test]
    fn request_upgrade_pairing() {
        let c = |h: &[(&'static str, &'static str)]| h1_clean_headers(h.iter().copied(), true);
        assert!(c(&[("Upgrade", "websocket")]).is_empty());
        assert!(c(&[("Connection", "keep-alive, Upgrade")]).is_empty());
        assert_eq!(c(&[("Connection", "Upgrade, foo"), ("Upgrade", "h2c")]), [("connection".to_string(), "foo".to_string())]);
        // A response keeps both: the pairing is the request parser's.
        assert_eq!(h1_clean_headers([("Upgrade", "websocket")].into_iter(), false).len(), 1);
    }

    #[test]
    fn commas_inside_quotes_do_not_split() {
        // Measured through req.hdrs and req.hdr_names on 3.5-dev8-885761-29 (batch/1011
        // integration of t329a and t326a): a quoted comma is not an element boundary, so
        // neither a quoted `close` nor a quoted `upgrade` is an element.
        let c = |h: &[(&'static str, &'static str)]| h1_clean_headers(h.iter().copied(), true);
        assert_eq!(
            c(&[("Host", "a"), ("Connection", "x=\"a,close,b\", keep-alive")]),
            [("host".to_string(), "a".to_string()), ("connection".to_string(), "x=\"a,close,b\"".to_string())]
        );
        assert_eq!(
            c(&[("Host", "a"), ("Connection", "x=\"y,upgrade\""), ("Upgrade", "websocket")]),
            [("host".to_string(), "a".to_string()), ("connection".to_string(), "x=\"y,upgrade\"".to_string())]
        );
        assert_eq!(c(&[("Connection", "\"a,close\", close")]), [("connection".to_string(), "\"a,close\"".to_string())]);
    }

    #[test]
    fn kept_headers_measured() {
        // (headers, request?, kept) as HAProxy 3.5-dev8 lists them with req/res.hdr_names.
        let h = |s: &'static str| -> Vec<(&'static str, &'static str)> { s.split('|').map(|l| l.split_once(": ").unwrap()).collect() };
        assert_eq!(kept_headers(&h("Host: a|Connection: upgrade|Upgrade: foo"), true), [true, true, true]);
        assert_eq!(kept_headers(&h("Connection: upgrade|Upgrade: h2c"), true), [false, false]);
        assert_eq!(kept_headers(&h("Upgrade: websocket"), true), [false]);
        assert_eq!(kept_headers(&h("Upgrade: websocket"), false), [true]);
        assert_eq!(kept_headers(&h("Connection: x-y, upgrade|X-Y: 1"), true), [true, true]);
        assert_eq!(kept_headers(&h("Connection: upgrade|Connection: close"), true), [false, false]);
        assert_eq!(kept_headers(&h("Connection: close|Keep-Alive: timeout=5"), false), [false, true]);
        assert_eq!(kept_headers(&h("Connection: keep-alive, x-z"), false), [true]);
    }
}
