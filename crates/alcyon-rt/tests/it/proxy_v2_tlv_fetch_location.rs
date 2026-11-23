// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `set-proxy-v2-tlv-fmt(<id>) <fmt>` is rendered when the server connection opens
//! (`make_proxy_line_v2`, src/connection.c), before any response exists: `HAProxy`
//! compiles the format against that location (`parse_logformat_string(...,
//! SMP_VAL_BE_SRV_CON, ...)`, src/server.c) and refuses at load a sample fetch whose
//! sources are not in the location's capabilities (src/sample.c's `fetch_cap`): the
//! response's (`SMP_USE_HRSHV`/`HRSHP`/`L6RES`/`HRSBO`) and the server's own address
//! and connection (`SMP_USE_L4SRV`/`L5SRV`) are not in; the request's, the server's
//! name and the final statistics are. The refusal is the line
//! `sample fetch <name> may not be reliably used here because it needs '<sources>'
//! which is not available here` under the `'server <backend>/<srv>' :` prefix.
//!
//! Every expected value was measured on the oracle (3.5-dev11).
//!
//! Set `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`: it passes
//! all.

use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;

/// The binary under test: the oracle's when `T281_ORACLE` names one, alcyon otherwise.
fn bin() -> String {
    std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

/// Runs `-c` on a `mode http` backend whose server line is
/// `server s1 127.0.0.1:1 send-proxy-v2 set-proxy-v2-tlv-fmt(0xE1) %[fetch]`; the exit
/// status and the stderr.
fn run_check(fetch: &str) -> (bool, String) {
    let mut cfg = NamedTempFile::new().expect("tmp file");
    let text = format!(
        "global\n\
         defaults\n\
             mode http\n\
             timeout connect 5s\n\
             timeout client 5s\n\
             timeout server 5s\n\
         backend be\n\
             server s1 127.0.0.1:1 send-proxy-v2 set-proxy-v2-tlv-fmt(0xE1) %[{fetch}]\n"
    );
    cfg.write_all(text.as_bytes()).expect("write config");
    let out = Command::new(bin())
        .arg("-c")
        .arg("-f")
        .arg(cfg.path())
        .output()
        .expect("run the check");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// The oracle's refusal for a fetch the server-connect location cannot read, under the
/// `'server be/s1' :` prefix: the fetch is named as the fetch method's keyword
/// (`res.hdr(y)` is `<res.hdr>`), and the need is the name of its sources.
fn expected_refusal(fetch_name: &str, part: &str) -> String {
    format!(
        "'server be/s1' : sample fetch <{fetch_name}> may not be reliably used here because it needs '{part}' which is not available here"
    )
}

/// The fetches the server-connect location cannot read: `%[fetch]` must be refused at
/// load, with the oracle's line. The first four are the task's table; the rest were
/// measured on the oracle the same way.
// Only fetches both binaries know: `ssl_bc_sni` and `bs.id` refuse on the oracle for this
// same reason but Alcyon does not register them yet, so it refuses them as "unknown fetch
// method" before the location check; they stay out of the table.
const REFUSED: &[(&str, &str, &str)] = &[
    ("res.hdr(y)", "res.hdr", "HTTP response headers"),
    ("status", "status", "HTTP response"),
    ("res.len", "res.len", "response buffer"),
    ("capture.res.hdr(0)", "capture.res.hdr", "HTTP response"),
    ("res.body", "res.body", "HTTP response headers"),
    ("res.body_len", "res.body_len", "HTTP response headers"),
    ("res.cook", "res.cook", "HTTP response headers"),
    ("bc.timer.connect", "bc.timer.connect", "server address"),
    ("bc_err", "bc_err", "server address"),
    ("bc_http_major", "bc_http_major", "server address"),
    ("req.timer.queue", "req.timer.queue", "server address"),
    ("txn.conn_retries", "txn.conn_retries", "server address"),
    ("txn.redispatched", "txn.redispatched", "server address"),
    ("bc_reused", "bc_reused", "server address"),
    ("bc_dst", "bc_dst", "server address"),
    ("bc_nb_streams", "bc_nb_streams", "server-side connection"),
    ("ssl_bc", "ssl_bc", "server-side connection"),
    ("ssl_bc_cipher", "ssl_bc_cipher", "server-side connection"),
    ("ssl_bc_protocol", "ssl_bc_protocol", "server-side connection"),
];

/// The fetches the server-connect location can read: `%[fetch]` must load.
const ACCEPTED: &[&str] = &[
    "req.hdr(host)",
    "path",
    "src",
    "ssl_fc",
    "req.body",
    "str(x)",
    "srv_name",
    "txn.timer.total",
    "res.timer.data",
];

/// Every refused row: `-c` fails and the stderr carries the oracle's line verbatim.
#[test]
fn tlv_format_refuses_response_and_server_connection_fetches() {
    for (fetch, name, part) in REFUSED {
        let (ok, stderr) = run_check(fetch);
        let want = expected_refusal(name, part);
        assert!(
            !ok && stderr.contains(&want),
            "the check did not refuse %[{fetch}] with the oracle's line\nwant: {want}\ngot ok={ok}:\n{stderr}"
        );
    }
}

/// Every accepted row: `-c` passes; the location has the request, the server's name and
/// the final statistics, not only the response and the server connection.
#[test]
fn tlv_format_accepts_the_rest() {
    for fetch in ACCEPTED {
        let (ok, stderr) = run_check(fetch);
        assert!(ok, "the check refused %[{fetch}]\n{stderr}");
    }
}
