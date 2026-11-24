// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `unix@` and absolute-path `bind` parsing and refusals (T655 slice U1).
//!
//! Measured against `HAProxy` 3.5-dev11-ce79f339c (`haproxy -c`):
//! * `bind unix@<path>`, `bind /<path>`, `bind stream+unix@<path>`, `bind stream+/<path>`
//!   are accepted in `frontend` and `listen` sections (including relative paths after `unix@`
//!   and `${VAR}` expansion).
//! * Socket path limit is 97 bytes after any `unix@` prefix: 97 bytes is accepted, 98 bytes
//!   fails with `'bind' : socket path '<arg>' too long (max 97)`.
//! * `uxdg@<path>` fails with `'bind' : dgram-type address not acceptable in '<arg>'`.
//! * `quic+unix@<path>` and `quic+/<path>` fail with
//!   `'bind' : unsupported stream protocol for datagram family 1 address '<arg>'`.
//! * `quic4@/<path>` and `quic6@/<path>` fail with a missing-port error (IPv4/IPv6 only).
//! * Still refused in U1: `abns@`, `abnsz@`, `unix@@`, empty `unix@`,
//!   `mode`/`uid`/`gid`/`user`/`group` on a unix bind, and unix addresses on `server` (U2).

use alcyon_config::{parse_str, Config, ConfigError};

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n";

fn in_frontend(bind: &str) -> Result<Config, ConfigError> {
    parse_str(&format!("{DEFAULTS}frontend x\n  {bind}\n"))
}

fn in_listen(bind: &str) -> Result<Config, ConfigError> {
    parse_str(&format!("{DEFAULTS}listen x\n  {bind}\n"))
}

#[test]
fn unix_bind_forms_are_accepted_in_frontend_and_listen() {
    let valid = [
        "bind unix@/tmp/alcyon-u1-a.sock",
        "bind /tmp/alcyon-u1-b.sock",
        "bind unix@relative.sock",
        "bind stream+unix@/tmp/alcyon-u1-c.sock",
        "bind stream+/tmp/alcyon-u1-d.sock",
        "bind /tmp/alcyon-u1-e.sock ssl crt /tmp/c.pem",
        "bind unix@/tmp/alcyon-u1-f.sock name ubind id 42",
        "bind /tmp/alcyon-u1-g.sock accept-proxy",
    ];
    for line in valid {
        for f in [in_frontend, in_listen] {
            f(line).unwrap_or_else(|e| panic!("expected valid `{line}`, got: {e}"));
        }
    }

    // `${VAR}` expansion producing a bare absolute unix path (as HAProxy reg-tests write).
    std::env::set_var("ALCYON_U1_TEST_TMPDIR", "/tmp/u1-env-dir");
    let cfg = in_frontend("bind \"${ALCYON_U1_TEST_TMPDIR}/fe1.sock\" ssl crt /tmp/c.pem")
        .expect("expanded unix path must parse");
    assert_eq!(cfg.frontends[0].binds.len(), 1);
    assert!(cfg.frontends[0].binds[0].ssl);
}

#[test]
fn unix_bind_path_length_boundary_at_97_bytes() {
    let ok97 = format!("/{}", "a".repeat(96));
    let bad98 = format!("/{}", "a".repeat(97));
    assert_eq!(ok97.len(), 97);
    assert_eq!(bad98.len(), 98);

    for f in [in_frontend, in_listen] {
        f(&format!("bind {ok97}")).expect("97-byte bare path must load");
        f(&format!("bind unix@{ok97}")).expect("97-byte unix@ path must load");

        let e1 = f(&format!("bind {bad98}")).expect_err("98-byte bare path must fail").to_string();
        assert!(
            e1.contains(&format!("'bind' : socket path '{bad98}' too long (max 97)")),
            "bare 98: {e1}"
        );

        let e2 = f(&format!("bind unix@{bad98}")).expect_err("98-byte unix@ path must fail").to_string();
        assert!(
            e2.contains(&format!("'bind' : socket path 'unix@{bad98}' too long (max 97)")),
            "unix@ 98: {e2}"
        );
    }
}

#[test]
fn refused_unix_variants_and_quic_on_unix_report_expected_errors() {
    for f in [in_frontend, in_listen] {
        // Refused prefixes kept out of U1.
        for (addr, prefix) in [
            ("abns@foo", "abns@"),
            ("abnsz@foo", "abnsz@"),
            ("unix@@foo", "unix@@"),
        ] {
            let err = f(&format!("bind {addr}")).expect_err(addr).to_string();
            assert!(
                err.contains(&format!("address prefix '{prefix}' is not implemented")),
                "{addr}: {err}"
            );
        }

        // Empty path after `unix@`: fail closed (do not bind abstract autobind).
        let empty = f("bind unix@").expect_err("empty unix@").to_string();
        assert!(empty.contains("unix@"), "empty unix@: {empty}");

        // `uxdg@`: measured HAProxy message.
        let uxdg = f("bind uxdg@/tmp/x.sock").expect_err("uxdg@").to_string();
        assert!(
            uxdg.contains("'bind' : dgram-type address not acceptable in 'uxdg@/tmp/x.sock'"),
            "uxdg@: {uxdg}"
        );

        // QUIC on a unix path: measured HAProxy messages.
        for qaddr in ["quic+unix@/tmp/q.sock", "quic+/tmp/q.sock"] {
            let err = f(&format!("bind {qaddr} ssl crt /tmp/c.pem")).expect_err(qaddr).to_string();
            assert!(
                err.contains(&format!("'bind' : unsupported stream protocol for datagram family 1 address '{qaddr}'")),
                "{qaddr}: {err}"
            );
        }
        for qaddr in ["quic4@/tmp/q.sock", "quic6@/tmp/q.sock"] {
            let err = f(&format!("bind {qaddr} ssl crt /tmp/c.pem")).expect_err(qaddr).to_string();
            assert!(err.contains("missing port"), "{qaddr}: {err}");
        }

        // Bare relative path without `unix@` still requires a port (as on HAProxy).
        let rel = f("bind ./rel.sock").expect_err("bare ./rel.sock").to_string();
        assert!(rel.contains("missing port"), "./rel.sock: {rel}");

        // Unix bind permissions/ownership keywords stay refused in U1.
        for kw_arg in ["mode 600", "uid 0", "gid 0", "user nobody", "group nobody"] {
            let kw = kw_arg.split(' ').next().unwrap();
            let err = f(&format!("bind /tmp/m.sock {kw_arg}")).expect_err(kw_arg).to_string();
            assert!(
                err.contains(&format!("'{kw}'")) && err.contains("not supported"),
                "{kw_arg}: {err}"
            );
        }
    }
}

#[test]
fn unix_bind_validation_errors_name_the_unix_path_and_servers_stay_refused() {
    // Duplicate listener id names the unix paths, not `0.0.0.0:0`.
    let dup = parse_str(&format!(
        "{DEFAULTS}frontend x\n  bind /tmp/a.sock id 7\n  bind /tmp/b.sock id 7\n"
    ))
    .expect_err("duplicate id")
    .to_string();
    assert!(dup.contains("/tmp/a.sock") && dup.contains("/tmp/b.sock"), "dup id: {dup}");
    assert!(!dup.contains("0.0.0.0:0"), "dup id leaked sentinel addr: {dup}");

    // `verify required` without `ca-file` names the unix path.
    let vfy = in_frontend("bind /tmp/v.sock ssl crt /tmp/c.pem verify required")
        .expect_err("verify without ca-file")
        .to_string();
    assert!(
        vfy.contains("Proxy 'x': verify is enabled but no CA file specified for bind '/tmp/v.sock' at "),
        "verify without ca-file: {vfy}"
    );

    // U2 stays out of scope: `server` with unix addresses stays refused.
    for saddr in ["unix@/tmp/srv.sock", "/tmp/srv.sock"] {
        let err = parse_str(&format!("{DEFAULTS}backend be\n  server s1 {saddr}\n"))
            .expect_err(saddr)
            .to_string();
        assert!(
            err.contains("address prefix 'unix@' is not implemented"),
            "server {saddr}: {err}"
        );
    }

    // An unset `${VAR}` in an unquoted bind address fails closed.
    let missing_env = in_frontend("bind ${ALCYON_U1_DEFINITELY_UNSET_VAR}")
        .expect_err("unset env var")
        .to_string();
    assert!(missing_env.contains("resolves to an empty address"), "missing env: {missing_env}");

    // Interior NUL byte in a unix bind path fails closed.
    let nul_path = in_frontend("bind /tmp/bad\0.sock")
        .expect_err("nul in unix path")
        .to_string();
    assert!(nul_path.contains("invalid NUL byte"), "nul path: {nul_path}");
}
