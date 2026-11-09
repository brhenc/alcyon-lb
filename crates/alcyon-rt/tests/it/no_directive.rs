// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T351: `no <keyword>` in a proxy or `defaults` section. `HAProxy` (3.5-dev8, `haproxy -c`)
//! accepts `no` only before `option` and `log`; anything else, or nothing, is refused with
//! one message. Alcyon accepted any `no <keyword>` with a warning and dropped it.

use std::process::Command;

fn check(section: &str, line: &str) -> (bool, String) {
    let cfg = tempfile::NamedTempFile::new().expect("tmp");
    let body = match section {
        "backend" => format!("defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\nfrontend f\n  bind 127.0.0.1:0\n  default_backend b\nbackend b\n  {line}\n"),
        "defaults" => format!("defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n  {line}\nlisten s\n  bind 127.0.0.1:0\n"),
        "frontend" => format!("defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\nfrontend f\n  bind 127.0.0.1:0\n  {line}\n"),
        _ => format!("defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\nlisten s\n  bind 127.0.0.1:0\n  {line}\n"),
    };
    std::fs::write(cfg.path(), body).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(cfg.path()).output().expect("run alcyon -c");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

const ONLY: &str = "negation/default currently supported only for options, log, busy-polling, set-dumpable, strict-limits, insecure-fork-wanted and numa-cpu-mapping.";

#[test]
fn a_no_that_haproxy_refuses_is_refused() {
    for section in ["defaults", "listen", "frontend", "backend"] {
        for line in ["no", "no foo", "no timeout client", "no cookie", "no mode", "no retries", "no balance", "no stats enable", "no log-format"] {
            let (ok, err) = check(section, line);
            assert!(!ok, "{section}: `{line}` was accepted");
            assert!(err.contains(ONLY), "{section}: `{line}`: {err}");
        }
    }
}

#[test]
fn a_no_that_haproxy_accepts_is_accepted() {
    for section in ["defaults", "listen", "backend"] {
        for line in ["no log", "no option httpclose", "no option abortonclose"] {
            let (ok, err) = check(section, line);
            assert!(ok, "{section}: `{line}`: {err}");
        }
    }
}
