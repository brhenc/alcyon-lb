// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `stats <word>` in `global`. `HAProxy` (`cli_parse_global`, `src/cli.c`) accepts `socket`,
//! `timeout`, `maxconn`, `calculate-max-counters`, and refuses `bind-process` and anything
//! else. Ibex accepted every other word and dropped it. The texts are those of `haproxy -c`
//! 3.5-dev8 on the same lines; a word Ibex does not act on is refused, not dropped.

use std::process::Command;

fn check(line: &str) -> (bool, String) {
    let cfg = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(cfg.path(), format!("global\n  {line}\n")).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(cfg.path()).output().expect("run ibex -c");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn a_stats_word_haproxy_refuses_is_refused() {
    for (line, expected) in [
        ("stats", "'stats' only supports 'socket', 'maxconn', 'bind-process', 'calculate-max-counters'  and 'timeout' (got '')"),
        ("stats bogus", "'stats' only supports 'socket', 'maxconn', 'bind-process', 'calculate-max-counters'  and 'timeout' (got 'bogus')"),
        ("stats socket", "'stats socket' in global section expects an address or a path to a UNIX socket"),
        ("stats bind-process 1", "'stats bind-process' is not supported anymore."),
        ("stats maxconn", "'stats maxconn' expects a positive value"),
        ("stats maxconn 0", "'stats maxconn' expects a positive value"),
        ("stats maxconn abc", "'stats maxconn' expects a positive value"),
        ("stats calculate-max-counters", "'calculate-max-counters' only supports 'on' and 'off', received ''"),
        ("stats calculate-max-counters maybe", "'calculate-max-counters' only supports 'on' and 'off', received 'maybe'"),
    ] {
        let (ok, err) = check(line);
        assert!(!ok, "`{line}` was accepted");
        assert!(err.contains(expected), "`{line}`: {err}");
    }
}

/// `HAProxy` accepts these; Ibex does not act on them and says so, rather than dropping them.
#[test]
fn a_stats_word_ibex_does_not_act_on_is_refused_as_such() {
    for line in ["stats maxconn 5", "stats calculate-max-counters off"] {
        let (ok, err) = check(line);
        assert!(!ok, "`{line}` was accepted and dropped");
        assert!(err.contains("is not supported by Ibex"), "`{line}`: {err}");
    }
}

/// `on` is what `HAProxy` does without the line.
#[test]
fn calculate_max_counters_on_is_accepted() {
    for line in ["stats calculate-max-counters on", "stats calculate-max-counters ON"] {
        let (ok, err) = check(line);
        assert!(ok, "`{line}`: {err}");
    }
}
