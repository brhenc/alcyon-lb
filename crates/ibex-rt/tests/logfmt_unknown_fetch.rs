// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A `%[<expr>]` in any log-format string names a fetch and converters that must exist, as
//! `sample_parse_expr` demands ("failed to parse sample expression <nosuch]> : unknown
//! fetch method 'nosuch'"). Before this, only a few places (`log-format`, `unique-id-format`)
//! refused; an unknown one in `http-request set-header`, `redirect`, `deny ... hdr`, ... loaded
//! and yielded an empty value on every request (T147 item 1).
//!
//! Measured against `HAProxy` 3.5-dev8-885761-29, 2026-10-04, `haproxy -c -f`: every `REFUSED`
//! line exits 1 with the quoted text; every `ACCEPTED` line exits 0.

use std::process::Command;

fn check(cfg: &str) -> (Option<i32>, String) {
    let path = std::env::temp_dir().join(format!("ibex_lfunknown_{}_{:x}.cfg", std::process::id(), cfg.len()));
    std::fs::write(&path, cfg).expect("write config");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("run ibex -c");
    let _ = std::fs::remove_file(&path);
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

fn config(fe_rule: &str, be_rule: &str) -> String {
    format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind 127.0.0.1:18080\n  {fe_rule}\n  default_backend be\n\
         backend be\n  {be_rule}\n  server s1 127.0.0.1:1\n"
    )
}

const REFUSED: &[(&str, &str, &str)] = &[
    ("http-request set-header x %[nosuch]", "", "unknown fetch method 'nosuch'"),
    ("http-request set-header x %[src,nosuchc]", "", "unknown converter 'nosuchc'"),
    ("http-request add-header x a%[nosuch]b", "", "unknown fetch method 'nosuch'"),
    ("http-request redirect location /%[nosuch]", "", "unknown fetch method 'nosuch'"),
    ("http-request deny deny_status 403 hdr x %[nosuch]", "", "unknown fetch method 'nosuch'"),
    ("http-request set-var-fmt(txn.a) %[nosuch]", "", "unknown fetch method 'nosuch'"),
    ("http-request set-path %[nosuch]", "", "unknown fetch method 'nosuch'"),
    ("http-response set-header x %[nosuch]", "", "unknown fetch method 'nosuch'"),
    ("http-after-response set-header x %[nosuch]", "", "unknown fetch method 'nosuch'"),
    ("http-response redirect location /%[nosuch]", "", "unknown fetch method 'nosuch'"),
    ("tcp-request content set-var-fmt(txn.a) %[nosuch]", "", "unknown fetch method 'nosuch'"),
    ("", "http-request set-header x %[nosuch]", "unknown fetch method 'nosuch'"),
    ("", "http-response set-header x %[nosuch]", "unknown fetch method 'nosuch'"),
    ("", "http-error status 503 content-type text/plain lf-string %[nosuch]", "unknown fetch method 'nosuch'"),
];

const ACCEPTED: &[(&str, &str)] = &[
    ("http-request set-header x %[src]", ""),
    ("http-request set-header x %[src,lower]", ""),
    ("http-request set-header x %{+Q}[req.hdr(host),lower]", ""),
    ("http-request redirect location /%[path]", ""),
    ("http-request set-header x %[date(0,ms),div(1000)]-%[accept_date(us)]", ""),
    ("http-response set-header x %%[nosuch]", ""),
    ("", "http-response set-header x %[res.hdr(server)]"),
];

#[test]
fn unknown_fetch_or_converter_in_a_log_format_is_refused() {
    for (fe, be, text) in REFUSED {
        let (code, out) = check(&config(fe, be));
        assert_eq!(code, Some(1), "`{fe}` / `{be}` must be refused: {out}");
        assert!(out.contains(text), "`{fe}` / `{be}`: expected {text:?} in: {out}");
    }
}

#[test]
fn known_fetches_in_a_log_format_load() {
    for (fe, be) in ACCEPTED {
        let (code, out) = check(&config(fe, be));
        assert_eq!(code, Some(0), "`{fe}` / `{be}` must load: {out}");
    }
}
