// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `Connection` and `Upgrade` headers as `HAProxy`'s H1 parser leaves them in the HTX
//! message (`h1_parse_connection_header` and `h1_parse_upgrade_header` with
//! `H1_MF_CLEAN_CONN_HDR`, `src/h1.c`; `h1_postparse_req_hdrs`, `src/h1_htx.c`), for the
//! fetches that dump the whole header block (`req.hdrs`, `res.hdrs`).
//!
//! Ibex keeps the headers as received, so these fetches apply the rewrite themselves.

/// `http_remove_header_value` (`include/haproxy/http.h`): the comma-separated `value` without
/// the items `drop` selects. Until one is dropped the value is kept verbatim (blanks
/// included); after that, each kept item is appended trimmed, after a bare `,`.
pub(crate) fn drop_items(value: &str, drop: impl Fn(&str) -> bool) -> String {
    let lws = |b: u8| b == b' ' || b == b'\t';
    let b = value.as_bytes();
    let mut out = String::new();
    // `hv->ptr + hv->len == p`: nothing has been dropped yet, `out` is `value[..out.len()]`.
    let mut verbatim = true;
    let mut w = 0;
    while w < b.len() {
        if lws(b[w]) {
            w += 1;
            continue;
        }
        let n = b[w..].iter().position(|&c| c == b',').map_or(b.len(), |i| w + i);
        let mut end = n;
        while end > w && lws(b[end - 1]) {
            end -= 1;
        }
        let word = &value[w..end];
        if drop(word) {
            verbatim = false;
        } else if verbatim {
            out = value[..n].to_string();
        } else {
            if !out.is_empty() {
                out.push(',');
            }
            out.push_str(word);
        }
        // The next item starts after the comma.
        w = n + 1;
    }
    out
}

fn has_item(value: &str, item: &str) -> bool {
    value.split(',').any(|t| t.trim_matches([' ', '\t']).eq_ignore_ascii_case(item))
}

/// The headers `hdrs` (name, value) as the H1 parser stores them: `close` and `keep-alive`
/// out of every `Connection`, `h2c` and `h2` out of every `Upgrade`, a header that ends up
/// empty gone. For a request also (`h1_postparse_req_hdrs`): an `Upgrade` with no `upgrade`
/// item in a `Connection` goes, and with no `Upgrade` the `upgrade` item goes. Names are
/// lowercased and values trimmed, as in HTX.
pub(crate) fn h1_clean_headers<'a>(hdrs: impl Iterator<Item = (&'a str, &'a str)>, request: bool) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let (mut conn_upg, mut upg_hdr) = (false, false);
    for (name, value) in hdrs {
        let name = name.to_ascii_lowercase();
        let value = value.trim_matches([' ', '\t']);
        let value = match name.as_str() {
            "connection" => {
                conn_upg |= has_item(value, "upgrade");
                drop_items(value, |t| t.eq_ignore_ascii_case("close") || t.eq_ignore_ascii_case("keep-alive"))
            }
            "upgrade" => {
                let v = drop_items(value, |t| t.eq_ignore_ascii_case("h2c") || t.eq_ignore_ascii_case("h2"));
                upg_hdr |= !v.is_empty();
                v
            }
            _ => {
                out.push((name, value.to_string()));
                continue;
            }
        };
        if !value.is_empty() {
            out.push((name, value));
        }
    }
    if request && upg_hdr && !conn_upg {
        out.retain(|(n, _)| n != "upgrade");
    } else if request && conn_upg && !upg_hdr {
        out.retain_mut(|(n, v)| {
            if n == "connection" {
                *v = drop_items(v, |t| t.eq_ignore_ascii_case("upgrade"));
                !v.is_empty()
            } else {
                true
            }
        });
    }
    out
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

    fn conn(v: &str) -> String {
        drop_items(v, |t| t.eq_ignore_ascii_case("close") || t.eq_ignore_ascii_case("keep-alive"))
    }

    #[test]
    fn drop_items_like_http_remove_header_value() {
        // Measured through req.hdrs on 3.5-dev8-885761-29.
        assert_eq!(conn("close"), "");
        assert_eq!(conn("close, X-Hop"), "X-Hop");
        assert_eq!(conn("X-Hop, close"), "X-Hop");
        assert_eq!(conn("A,  B"), "A,  B");
        assert_eq!(conn("keep-alive, A,  B"), "A,B");
        assert_eq!(drop_items("foo, Upgrade, bar", |t| t.eq_ignore_ascii_case("upgrade")), "foo,bar");
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
}
