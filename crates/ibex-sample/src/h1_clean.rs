// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Which headers of an HTTP/1 message `HAProxy`'s parser leaves in HTX. It takes `close` and
//! `keep-alive` out of a `Connection` value and `h2c`/`h2` out of an `Upgrade` value, and drops
//! the header when nothing is left (`h1_parse_connection_header` with `H1_MF_CLEAN_CONN_HDR`
//! and `h1_parse_upgrade_header`, `src/h1.c`). In a request it then drops an `Upgrade` header
//! that no `Connection: upgrade` refers to, and an `upgrade` token that no `Upgrade` header
//! backs (`h1_postparse_req_hdrs`, `src/h1_htx.c`). The fetches that list header names
//! (`req.hdr_names`, `res.hdr_names`) read HTX, so they do not see what the parser took out.

fn is_lws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// The end of the element that starts at `s` (`http_find_hdr_value_end`): the next comma
/// outside a quoted string, or the end of the value.
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

/// `value` without the elements `skip` matches, rewritten the way `HAProxy` rewrites it in
/// place: until the first skipped element the value stays as it came (up to the end of the
/// last element kept); after it, each kept element is appended behind a `,`.
fn rewrite(value: &str, mut skip: impl FnMut(&str) -> bool) -> String {
    let v = value.as_bytes();
    let mut out = String::new();
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
        if !skip(word) {
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

/// For each of `headers` (name, value), in order, whether `HAProxy`'s H1 parser keeps it in
/// HTX. `request` adds the request-only `Upgrade`/`Connection: upgrade` pairing.
#[must_use]
pub fn kept_headers(headers: &[(&str, &str)], request: bool) -> Vec<bool> {
    let is = |w: &str, t: &str| w.eq_ignore_ascii_case(t);
    let (mut conn_upg, mut upg_hdr) = (false, false);
    // The value left of each `Connection` header, `None` for the others.
    let mut conn: Vec<Option<String>> = Vec::with_capacity(headers.len());
    let mut kept: Vec<bool> = Vec::with_capacity(headers.len());
    for (n, v) in headers {
        let v = v.trim_matches([' ', '\t']);
        if n.eq_ignore_ascii_case("connection") {
            let left = rewrite(v, |w| {
                conn_upg |= is(w, "upgrade");
                is(w, "close") || is(w, "keep-alive")
            });
            kept.push(!left.is_empty());
            conn.push(Some(left));
        } else if n.eq_ignore_ascii_case("upgrade") {
            let left = rewrite(v, |w| is(w, "h2c") || is(w, "h2"));
            upg_hdr |= !left.is_empty();
            kept.push(!left.is_empty());
            conn.push(None);
        } else {
            kept.push(true);
            conn.push(None);
        }
    }
    if request && upg_hdr && !conn_upg {
        for (k, (n, _)) in kept.iter_mut().zip(headers) {
            if n.eq_ignore_ascii_case("upgrade") {
                *k = false;
            }
        }
    }
    if request && conn_upg && !upg_hdr {
        for (k, left) in kept.iter_mut().zip(&conn) {
            if let (true, Some(left)) = (*k, left) {
                *k = !rewrite(left, |w| is(w, "upgrade")).is_empty();
            }
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_follows_haproxy() {
        let ka = |w: &str| w.eq_ignore_ascii_case("close") || w.eq_ignore_ascii_case("keep-alive");
        assert_eq!(rewrite("close", ka), "");
        assert_eq!(rewrite("Keep-Alive, Close", ka), "");
        assert_eq!(rewrite("close, x-y", ka), "x-y");
        assert_eq!(rewrite("x-y ,  close , z", ka), "x-y ,z"); // in place: the blank before the first comma stays
        assert_eq!(rewrite("x-y ,  z", ka), "x-y ,  z");
        assert_eq!(rewrite(",  , close", ka), ",  ");
        assert_eq!(rewrite("\"a,close\", close", ka), "\"a,close\"");
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
