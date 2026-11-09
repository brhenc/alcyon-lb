// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T430 row 8: `monitor` and `monitor-uri` in a backend. `HAProxy` 3.5-dev8 warns
//! "'<kw>' ignored because backend 'b' has no frontend capability." (before it reads the
//! arguments) and carries on; measured with `haproxy -c` on 2026-10-19.

use alcyon_config::parse_config;

fn cfg(line: &str) -> String {
    format!(
        "defaults\n    mode http\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\n\n\
         backend b\n    {line}\n    server s 127.0.0.1:9\n"
    )
}

#[test]
fn the_line_is_ignored_with_a_warning() {
    for (line, kw) in [("monitor fail if TRUE", "monitor"), ("monitor-uri /m", "monitor-uri")] {
        let c = parse_config(&cfg(line)).unwrap_or_else(|e| panic!("{line}: {e}"));
        let w: Vec<_> = c.proxy_warnings.iter().filter(|w| w.text.contains("no frontend capability")).collect();
        assert_eq!(w.len(), 1, "{line}: {:?}", c.proxy_warnings.iter().map(|w| &w.text).collect::<Vec<_>>());
        assert_eq!(w[0].text, format!("'{kw}' ignored because backend 'b' has no frontend capability."));
        assert!(!w[0].alert);
        assert_eq!(w[0].line, 8, "{line}");
    }
}

#[test]
fn a_bad_line_is_still_refused_after_the_warning() {
    for (line, msg) in [
        ("monitor foo", "'monitor' only supports 'fail'."),
        ("monitor-uri", "'monitor-uri' expects an URI."),
    ] {
        let err = parse_config(&cfg(line)).expect_err(line).to_string();
        assert!(err.contains(msg), "{line}: {err}");
    }
}
