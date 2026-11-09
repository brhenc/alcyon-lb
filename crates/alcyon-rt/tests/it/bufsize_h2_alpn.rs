// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `tune.bufsize` below 16384 with HTTP/2 offered by ALPN (T223).
//!
//! `HAProxy` refuses an HTTP frontend (or `listen`) whose `bind` offers `h2` by ALPN while
//! `tune.bufsize` (rounded up to a multiple of 16) is below 16384 (`src/proxy.c`), one alert
//! per such `bind`:
//! `HTTP frontend 'f' enables HTTP/2 via ALPN at [cfg:9], so global.tune.bufsize must be at
//! least 16384 bytes (2048 now).` Measured on `HAProxy 3.5-dev8-885761-29`: refused with
//! `alpn h2` and `alpn h2,http/1.1` in a frontend and in a listen; accepted with `alpn
//! http/1.1`, with `ssl` and no `alpn`, in `mode tcp`, and from `tune.bufsize 16369` (16384
//! once rounded). Alcyon refused only frontends, with its own text, and accepted the listen.
//!
//! A deliberate difference: `bind ... proto h2` (cleartext) with a small buffer. `HAProxy`
//! accepts it and then fails every HTTP/2 request on it (curl: `nghttp2 recv error -902`;
//! with the default buffer the same request is answered 200). Alcyon refuses it at load, with
//! its own text, rather than start a listener that cannot serve.

use crate::common;

use std::process::Command;

fn cert() -> String {
    // Any certificate and key the TLS loader accepts: the configuration is only checked.
    format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"))
}

/// `alcyon -c` on a configuration with `tune.bufsize <bufsize>` and the proxy `section`
/// holding `bind_line`: the exit status and what it printed.
fn check(bufsize: u32, section: &str, mode: &str, bind_line: &str) -> (bool, String) {
    let fe = common::reserve_addr();
    let bind_line = bind_line.replace("{fe}", &fe.to_string()).replace("{crt}", &cert());
    let proxy = match section {
        "frontend" => format!("frontend f\n  {bind_line}\n  default_backend b\nbackend b\n  server s 127.0.0.1:1\n"),
        _ => format!("listen f\n  {bind_line}\n  server s 127.0.0.1:1\n"),
    };
    let cfg = format!(
        "global\n  tune.bufsize {bufsize}\ndefaults\n  mode {mode}\n  timeout client 1s\n  timeout server 1s\n  timeout connect 1s\n{proxy}"
    );
    let path = std::env::temp_dir().join(format!("alcyon-bsh2-{}-{}.cfg", std::process::id(), fe.port()));
    std::fs::write(&path, cfg).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&path).output().expect("alcyon -c");
    let _ = std::fs::remove_file(&path);
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn http_frontends_and_listens_offering_h2_by_alpn_need_a_16k_buffer() {
    for section in ["frontend", "listen"] {
        for alpn in ["h2", "h2,http/1.1"] {
            let (ok, err) = check(2048, section, "http", &format!("bind {{fe}} ssl crt {{crt}} alpn {alpn}"));
            assert!(!ok, "{section} with alpn {alpn} accepted");
            // The bind is the proxy's line, line 9 of the file.
            let want = "HTTP frontend 'f' enables HTTP/2 via ALPN at [";
            let tail = ":9], so global.tune.bufsize must be at least 16384 bytes (2048 now).";
            assert!(err.contains(want) && err.contains(tail), "{section} alpn {alpn}: {err}");
            assert!(!err.contains("parsing ["), "{section} alpn {alpn}: HAProxy's alert names the bind itself: {err}");
        }
    }
}

#[test]
fn without_h2_by_alpn_or_with_a_large_enough_buffer_it_loads() {
    for (bufsize, section, mode, bind) in [
        (2048, "frontend", "http", "bind {fe} ssl crt {crt} alpn http/1.1"),
        (2048, "listen", "http", "bind {fe} ssl crt {crt}"),
        (2048, "listen", "tcp", "bind {fe} ssl crt {crt} alpn h2"),
        (2048, "frontend", "tcp", "bind {fe} ssl crt {crt} alpn h2"),
        (16369, "listen", "http", "bind {fe} ssl crt {crt} alpn h2"),
        (16384, "frontend", "http", "bind {fe} ssl crt {crt} alpn h2,http/1.1"),
    ] {
        let (ok, err) = check(bufsize, section, mode, bind);
        assert!(ok, "bufsize {bufsize}, {section}, mode {mode}, {bind}: {err}");
    }
}

/// The deliberate difference (see the module): cleartext `proto h2` with a small buffer is
/// refused rather than started broken.
#[test]
fn cleartext_h2_with_a_small_buffer_is_refused() {
    let (ok, err) = check(2048, "frontend", "http", "bind {fe} proto h2");
    assert!(!ok, "accepted: {err}");
    assert!(err.contains("tune.bufsize"), "{err}");
}
