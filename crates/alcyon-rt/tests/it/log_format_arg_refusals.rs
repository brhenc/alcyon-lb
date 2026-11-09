// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T341: a converter's arguments are checked in a log-format as in a rule. `log-format`,
//! `unique-id-format`, `error-log-format` and `log-format-sd` are compiled apart from the rule
//! expressions, and before this they loaded a bad `hmac` key, an `xxh32` seed that is no
//! integer or `url_enc(path)`, and then logged nothing for them on every request (§5).
//!
//! Measured against HAProxy 3.5-dev8-885761-29, 2026-10-17, `haproxy -c -f` with the
//! directive in a frontend:
//!
//! * `log-format "%[str(a),hmac(sha256,Zm9v!)]"`: "failed to parse log-format : failed to
//!   parse sample expression <...> : invalid args in converter 'hmac' : failed to parse key :
//!   argument needs to be base64 encoded, and can either be a string or a variable."
//! * `unique-id-format "%[str(a),xxh32(q)]"`: "failed to parse unique-id : ... : invalid arg 1
//!   in converter 'xxh32' : failed to parse 'q' as type 'integer' at position 1."
//! * `error-log-format "%[str(a),url_enc(path)]"`: "failed to parse error-log-format : ... :
//!   invalid args in converter 'url_enc' : Unexpected encode type. Allowed value is 'query'."
//! * `log-format-sd` as `log-format`, "failed to parse log-format-sd".
//! * `log-format "%[str(a),add(abc)]"` and `http-request set-header x "%[str(a),add(abc)]"`:
//!   "invalid args in converter 'add' : expects an integer or a variable name."

use std::process::Command;

fn check(line: &str) -> (Option<i32>, String) {
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind 127.0.0.1:18080\n  {line}\n  default_backend be\n\
         backend be\n  server s1 127.0.0.1:1\n"
    );
    let path = std::env::temp_dir().join(format!("alcyon_lfargs_{}_{:x}.cfg", std::process::id(), line.bytes().map(usize::from).sum::<usize>() * 31 + line.len()));
    std::fs::write(&path, cfg).expect("write config");
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&path).output().expect("run alcyon -c");
    let _ = std::fs::remove_file(&path);
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

const HMAC: &str = "invalid args in converter 'hmac' : failed to parse key : argument needs to be base64 encoded, and can either be a string or a variable.";
const XXH: &str = "invalid arg 1 in converter 'xxh32' : failed to parse 'q' as type 'integer' at position 1.";
const ENC: &str = "invalid args in converter 'url_enc' : Unexpected encode type. Allowed value is 'query'.";
const ADD: &str = "invalid args in converter 'add' : expects an integer or a variable name.";

#[test]
fn bad_converter_arguments_in_a_log_format_are_refused() {
    let refused: &[(&str, &str, &str)] = &[
        ("log-format \"%[str(a),hmac(sha256,Zm9v!)]\"", "failed to parse log-format : ", HMAC),
        ("unique-id-format \"%[str(a),xxh32(q)]\"", "failed to parse unique-id", XXH),
        ("error-log-format \"%[str(a),url_enc(path)]\"", "failed to parse error-log-format : ", ENC),
        ("log-format-sd \"%[str(a),hmac(sha256,Zm9v!)]\"", "failed to parse log-format-sd : ", HMAC),
        ("log-format \"%[str(a),add(abc)]\"", "failed to parse log-format : ", ADD),
        ("http-request set-header x \"%[str(a),add(abc)]\"", "failed to parse sample expression", ADD),
    ];
    for (line, ctx, text) in refused {
        let (code, out) = check(line);
        assert_eq!(code, Some(1), "`{line}` must be refused: {out}");
        assert!(out.contains(ctx) && out.contains(text), "`{line}`: expected {ctx:?} and {text:?} in: {out}");
    }
}

#[test]
fn good_converter_arguments_in_a_log_format_load() {
    for line in [
        "log-format \"%[str(a),hmac(sha256,Zm9v)]\"",
        "unique-id-format \"%[str(a),xxh32(1)]\"",
        "error-log-format \"%[str(a),url_enc(query)]\"",
        "log-format \"%[str(a),add(1)] %[str(1),add(txn.x)]\"",
    ] {
        let (code, out) = check(line);
        assert_eq!(code, Some(0), "`{line}` must load: {out}");
    }
}
