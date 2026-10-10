// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `cookie` persistence over hostile header values (T242; production review #14 was a
//! panic here): the client's `Cookie` headers through `client_side`, the server's
//! `Set-Cookie` headers through `process_response`. Two flag bytes set the cookie
//! options; the rest is split at 0xFF into: name, three server cookie values, the Cookie
//! values and the Set-Cookie values (each a list split at LF).
#![no_main]
use ibex_config::CookieConfig;
use ibex_rt::cookie::{self, ReqKind, SrvCookie, Target};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let (f, g) = (data[0], data[1]);
    let bit = |b: u8, n: u8| b & (1 << n) != 0;
    let mut seg = data[2..].split(|&b| b == 0xFF);
    let mut next = || seg.next().unwrap_or(&[]);
    let name = String::from_utf8_lossy(next()).into_owned();
    let cfg = CookieConfig {
        name: if name.is_empty() { "SRV".into() } else { name },
        rewrite: bit(f, 0),
        indirect: bit(f, 1),
        insert: bit(f, 2),
        prefix: bit(f, 3),
        nocache: bit(f, 4),
        postonly: bit(f, 5),
        preserve: bit(f, 6),
        httponly: bit(f, 7),
        secure: bit(g, 0),
        domain: bit(g, 1).then(|| "example.com".into()),
        attrs: bit(g, 2).then(|| "SameSite=Lax".into()),
        maxidle: if bit(g, 3) { 60 } else { 0 },
        maxlife: if bit(g, 4) { 3600 } else { 0 },
    };
    let vals: Vec<&[u8]> = (0..3).map(|_| next()).collect();
    let servers: Vec<SrvCookie<'_>> = vals
        .iter()
        .enumerate()
        .map(|(i, v)| SrvCookie { value: Some(v), usable: i != 1, persistent: bit(g, 5) })
        .collect();
    let cookies: Vec<Vec<u8>> = next().split(|&b| b == b'\n').map(<[u8]>::to_vec).collect();
    let now = 1_700_000_000;
    let (srv, txn, _edits) = cookie::client_side(&cfg, now, &servers, &cookies);
    let mut hdrs: Vec<(String, String)> = next()
        .split(|&b| b == b'\n')
        .map(|v| ("Set-Cookie".to_string(), String::from_utf8_lossy(v).into_owned()))
        .collect();
    let target = srv.map(|i| Target { value: servers[i].value }).or(bit(g, 6).then_some(Target { value: None }));
    let req = ReqKind { safe_method: bit(g, 7), post: !bit(g, 7) };
    let _ = cookie::process_response(&cfg, target, &txn, req, 200, now, &mut hdrs);
});
