// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Health-check replies a hostile server controls (T242): the first byte picks the
//! parser and whether the server has closed; the rest is what it sent. LDAP and MySQL
//! are in `check_ldap_mysql`, apart, so that their known panics (T238) do not stop this one.
#![no_main]
use ibex_config::ast::ResolvedTcpExpectPattern as P;
use ibex_rt::check_reply as cr;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else { return };
    let eof = sel & 0x80 != 0;
    match sel % 6 {
        0 => {
            let _ = cr::redis(rest, eof);
        }
        1 => {
            let _ = cr::smtp_status_line(rest);
            let _ = cr::smtp_reply(rest, eof);
        }
        2 => {
            let _ = cr::pgsql(rest, eof);
        }
        3 => {
            let _ = cr::ssl_hello(rest, eof);
        }
        4 => {
            let _ = cr::http_response(rest);
        }
        _ => {
            // tcp-check expect: [kind][min-recv][len] pattern, then the reply.
            if rest.len() < 3 {
                return;
            }
            let (kind, min, plen) = (rest[0] % 3, i64::from(rest[1] as i8), usize::from(rest[2] % 16));
            let rest = &rest[3..];
            let plen = plen.min(rest.len());
            let (pat, reply) = rest.split_at(plen);
            let pattern = match kind {
                0 => P::String(String::from_utf8_lossy(pat).into_owned()),
                1 => P::Binary(pat.to_vec()),
                _ => P::RString(String::from_utf8_lossy(pat).into_owned()),
            };
            let _ = cr::tcp_expect(&pattern, min, reply, eof);
        }
    }
});
