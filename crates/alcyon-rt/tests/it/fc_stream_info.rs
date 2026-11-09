// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T331: `fc_nb_streams`, `fc_settings_streams_limit` and `fc_glitches` are refused at load
//! until Alcyon can answer them. `HAProxy` asks the front mux (`MUX_CTL_GET_NBSTRM`,
//! `MUX_CTL_GET_MAXSTRM`, `MUX_CTL_GET_GLITCHES`): on HTTP/1 that is 1, 1 and the
//! connection's `h1c->glitches`; on HTTP/2 the live `h2c->nb_streams`, the advertised
//! `SETTINGS_MAX_CONCURRENT_STREAMS` and `h2c->glitches`. `HAProxy` 3.5-dev8, three HEADERS
//! frames in one write on a `proto h2` bind: `3|100|0`, `2|100|0`, `1|100|0`, and `3|7|0`, ...
//! with `tune.h2.fe.max-concurrent-streams 7`. Alcyon's h2 streams are served by entries that
//! do not see their connection's mux, and Alcyon counts no HTTP/1 glitches, so the fetches
//! used to load as the constants 1, 1 and 0: right on HTTP/1 only, and an ACL on them
//! compared the constant as if it were the state.

use std::process::Command;

/// `{X}` is the place of the expression under test.
const CFG: &str = "global
  nbthread 1
defaults
  mode http
  timeout connect 1s
  timeout client 5s
  timeout server 5s
frontend fe
  bind 127.0.0.1:0
  {X}
";

/// `alcyon -c` on `CFG` with `line` in the frontend: the exit code and what it printed.
fn check(tag: &str, line: &str) -> (Option<i32>, String) {
    let dir = std::env::temp_dir().join(format!("fc-stream-info-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(&path, CFG.replace("{X}", line)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&path).output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

#[test]
fn fc_stream_fetches_are_refused_with_a_reason() {
    for (i, f) in ["fc_nb_streams", "fc_settings_streams_limit", "fc_glitches"].into_iter().enumerate() {
        for (j, line) in [
            format!("http-request return status 200 content-type text/plain lf-string \"%[{f}]\""),
            format!("http-request deny if {{ {f} gt 0 }}"),
        ]
        .iter()
        .enumerate()
        {
            let (code, out) = check(&format!("{i}-{j}"), line);
            assert_ne!(code, Some(0), "{line:?} loaded: {out}");
            assert!(out.contains(&format!("'{f}' : not implemented in Alcyon")), "{line:?}: {out}");
        }
    }
}
