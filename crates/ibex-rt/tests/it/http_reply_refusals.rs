// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T341: an HTTP reply (`http-request return`, `deny`, `tarpit`, `http-error`) with a body and
//! no `content-type`. `HAProxy` refuses it at load (`http_parse_http_reply`): "a content type
//! must be defined with a log-format payload" for `lf-string`/`lf-file`, even an empty one,
//! and "a content type must be defined when non-empty payload is configured" for a
//! non-empty `string`/`file`. Measured with `haproxy -c` on 3.5-dev8-885761-29, 2026-10-17;
//! Ibex loaded them all and sent the body without a `content-type`.

use std::process::Command;

const LF: &str = "a content type must be defined with a log-format payload";
const RAW: &str = "a content type must be defined when non-empty payload is configured";

fn check(i: usize, rule: &str) -> (Option<i32>, String) {
    let p = std::env::temp_dir().join(format!("ibex_reply_ct_{}_{i}.cfg", std::process::id()));
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind 127.0.0.1:1\n  {rule}\n  default_backend be\n\
         backend be\n  server s1 127.0.0.1:1\n"
    );
    std::fs::write(&p, cfg).expect("write config");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&p).output().expect("run ibex -c");
    let _ = std::fs::remove_file(&p);
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

#[test]
fn a_reply_with_a_body_needs_a_content_type() {
    let dir = std::env::temp_dir().join(format!("ibex_reply_ct_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let (empty, full) = (dir.join("empty"), dir.join("full"));
    std::fs::write(&empty, "").expect("write");
    std::fs::write(&full, "hello\n").expect("write");
    let (empty, full) = (empty.display(), full.display());
    let refused = [
        ("http-request return status 200 lf-string %[str(a)]".to_string(), LF),
        ("http-request return lf-string x".to_string(), LF),
        ("http-request return status 200 hdr x y lf-string x".to_string(), LF),
        (format!("http-request return status 200 lf-file {empty}"), LF),
        (format!("http-request return status 200 lf-file {full}"), LF),
        ("http-request return status 200 string abc".to_string(), RAW),
        (format!("http-request return status 200 file {full}"), RAW),
        ("http-request deny status 403 lf-string x".to_string(), LF),
        ("http-request deny status 403 string x".to_string(), RAW),
        ("http-error status 503 lf-string x".to_string(), LF),
        ("http-error status 503 string x".to_string(), RAW),
    ];
    let accepted = [
        "http-request return status 200 content-type t lf-string x".to_string(),
        "http-request return status 200 content-type t string x".to_string(),
        "http-request deny status 403 content-type t string x".to_string(),
        "http-error status 503 content-type t lf-string x".to_string(),
        format!("http-request return status 200 file {empty}"),
        "http-request return status 200".to_string(),
    ];
    let mut wrong = Vec::new();
    for (i, (rule, text)) in refused.iter().enumerate() {
        let (code, out) = check(i, rule);
        if code != Some(1) || !out.contains(text) {
            wrong.push(format!("`{rule}`: exit {code:?}, expected {text:?}: {}", out.trim()));
        }
    }
    for (i, rule) in accepted.iter().enumerate() {
        let (code, out) = check(100 + i, rule);
        if code != Some(0) {
            wrong.push(format!("`{rule}` must load: {}", out.trim()));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(wrong.is_empty(), "{} cases differ from HAProxy:\n{}", wrong.len(), wrong.join("\n"));
}
