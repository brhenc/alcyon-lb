// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Global `crt-base` and `ca-base` (T125). Before this `crt-base` was accepted and
//! dropped and `ca-base` was an unknown keyword. Measured with `haproxy -c` 3.5-dev8-885761-29:
//!
//! * a relative `bind ... crt` / `server ... crt` path is read under `crt-base`, a relative
//!   `server ... ca-file` / `crl-file` path under `ca-base`; absolute paths are left alone;
//! * `crt-base` with no argument: "global statement 'crt-base' expects a directory path as an
//!   argument."; with two: "'crt-base' cannot handle unexpected argument '/b'."; twice:
//!   "'crt-base' already specified." (same for `ca-base`).

use std::io::Write;
use std::process::Command;

fn check(cfg: &str) -> (Option<i32>, String) {
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("ibex -c");
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

const DEFAULTS: &str = "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n";

fn certs() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("dir");
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    std::fs::write(dir.path().join("both.pem"), format!("{}{}", cert.cert.pem(), cert.key_pair.serialize_pem())).expect("both");
    std::fs::write(dir.path().join("ca.pem"), cert.cert.pem()).expect("ca");
    dir
}

#[test]
fn crt_base_prefixes_relative_crt() {
    let dir = certs();
    let d = dir.path().display();
    let fe = "frontend fe\n  bind 127.0.0.1:18090 ssl crt both.pem\n  http-request return status 200\n";
    let (c, o) = check(&format!("global\n  crt-base {d}\n{DEFAULTS}{fe}"));
    assert_eq!(c, Some(0), "{o}");
    // The keyword may come after the sections that use it: it is resolved at the end.
    let (c, o) = check(&format!("{DEFAULTS}{fe}global\n  crt-base {d}\n"));
    assert_eq!(c, Some(0), "{o}");
    let (c, o) = check(&format!("{DEFAULTS}{fe}"));
    assert_ne!(c, Some(0), "no crt-base: the relative path is not found: {o}");
    // An absolute path ignores the base.
    let abs = format!("frontend fe\n  bind 127.0.0.1:18090 ssl crt {d}/both.pem\n  http-request return status 200\n");
    let (c, o) = check(&format!("global\n  crt-base /nonexistent\n{DEFAULTS}{abs}"));
    assert_eq!(c, Some(0), "{o}");
    // The base is not applied to the CA files.
    let be = "backend be\n  server s1 127.0.0.1:1 ssl verify required ca-file ca.pem\n";
    let (c, o) = check(&format!("global\n  crt-base {d}\n{DEFAULTS}{be}"));
    assert_ne!(c, Some(0), "crt-base is not the CA base: {o}");
}

#[test]
fn ca_base_prefixes_relative_ca_file() {
    let dir = certs();
    let d = dir.path().display();
    let be = "backend be\n  server s1 127.0.0.1:1 ssl verify required ca-file ca.pem\n";
    let (c, o) = check(&format!("global\n  ca-base {d}\n{DEFAULTS}{be}"));
    assert_eq!(c, Some(0), "{o}");
    let (c, o) = check(&format!("{DEFAULTS}{be}"));
    assert_ne!(c, Some(0), "{o}");
    // default-server inherits it too.
    let ds = "backend be\n  default-server ssl verify required ca-file ca.pem\n  server s1 127.0.0.1:1\n";
    let (c, o) = check(&format!("global\n  ca-base {d}\n{DEFAULTS}{ds}"));
    assert_eq!(c, Some(0), "{o}");
}

#[test]
fn base_arguments_are_checked() {
    for kw in ["ca-base", "crt-base"] {
        let (c, o) = check(&format!("global\n  {kw}\n"));
        assert_ne!(c, Some(0), "{o}");
        assert!(o.contains(&format!("global statement '{kw}' expects a directory path as an argument.")), "{o}");
        let (c, o) = check(&format!("global\n  {kw} /a /b\n"));
        assert_ne!(c, Some(0), "{o}");
        assert!(o.contains(&format!("'{kw}' cannot handle unexpected argument '/b'.")), "{o}");
        let (c, o) = check(&format!("global\n  {kw} /a\n  {kw} /b\n"));
        assert_ne!(c, Some(0), "{o}");
        assert!(o.contains(&format!("'{kw}' already specified.")), "{o}");
    }
}
