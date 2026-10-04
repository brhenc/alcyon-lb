// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-request replace-path`, `replace-pathq` and `replace-uri` (T146 item 9, and the
//! "Left by T154" finding of `tasks/T154-pcre-syntax-with-fancy-regex.md`).
//!
//! Every expected value was measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-04, and
//! `http_action_replace_uri` (`src/http_act.c`) read for the rest. What it does: the regex
//! is run on the path (`replace-path`), the path and query (`replace-pathq`) or the whole
//! target (`replace-uri`); when it matches, the *whole* of that part -- not just the
//! matched text -- is replaced by the replacement, which is a log-format string whose
//! `\0`..`\9` and `\xHH` `exp_replace` then expands; when it does not match, or the part is
//! empty, nothing changes. A bad regex stops the load.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

/// `(tag, action, regex, replacement, request target, "path|query|url|pathq|method")`.
const CASES: &[(&str, &str, &str, &str, &str, &str)] = &[
    ("A", "replace-path", "^/a", "/Z", "/ab?q=1", "/Z|q=1|/Z?q=1|/Z?q=1|GET"),
    ("B", "replace-path", "a", "Y", "/ab?q=1", "|q=1|Y?q=1||GET"),
    ("C", "replace-path", "^/(.*)", r"/pre/\1", "/x/y?q=1", "/pre/x/y|q=1|/pre/x/y?q=1|/pre/x/y?q=1|GET"),
    ("D", "replace-path", "/(b)", r"X\1", "/abc?q=1", "/abc|q=1|/abc?q=1|/abc?q=1|GET"),
    ("E", "replace-path", "nomatch", "Z", "/abc?q=1", "/abc|q=1|/abc?q=1|/abc?q=1|GET"),
    ("F", "replace-pathq", "^/a", "/Z", "/ab?q=1", "/Z||/Z|/Z|GET"),
    ("G", "replace-pathq", r"^/(.*)\?(.*)", r"/\2/\1", "/ab?q=1", "/q=1/ab||/q=1/ab|/q=1/ab|GET"),
    ("H", "replace-uri", "^http://h/(.*)", r"/new/\1", "http://h/ab?q=1", "/new/ab|q=1|/new/ab?q=1|/new/ab?q=1|GET"),
    ("I", "replace-uri", "^/a", "/Z", "/ab?q=1", "/Z||/Z|/Z|GET"),
    ("J", "replace-uri", "(.*)", r"/z\1", "/ab?q=1", "/z/ab|q=1|/z/ab?q=1|/z/ab?q=1|GET"),
    ("K", "replace-path", "^/a", "%[str(Q)]", "/ab?q=1", "|q=1|Q?q=1||GET"),
    ("L", "replace-path", "(.)", r"\0\0", "/ab?q=1", "//|q=1|//?q=1|//?q=1|GET"),
    ("M", "replace-path", "^/a", r"\x41", "/ab?q=1", "|q=1|A?q=1||GET"),
    ("N", "replace-pathq", "b", "Y", "/ab?q=1b", "||Y||GET"),
    ("O", "replace-path", "^/a", "/Z", "/a", "/Z||/Z|/Z|GET"),
    ("P", "replace-path", "^", "/Z", "/ab", "/Z||/Z|/Z|GET"),
    ("R", "replace-uri", "^/a", "/Z", "http://h/ab?q=1", "/ab|q=1|http://h/ab?q=1|/ab?q=1|GET"),
    ("S", "replace-uri", "a", "Z", "/aab?q=1", "||Z||GET"),
    ("T", "replace-path", "(?i)^/A", "/Z", "/ab?q=1", "/Z|q=1|/Z?q=1|/Z?q=1|GET"),
    ("U", "replace-path", r"^/a(b)?", r"/[\1]", "/a?q=1", "/[]|q=1|/[]?q=1|/[]?q=1|GET"),
    ("V", "replace-path", "b$", "Y", "/ab", "||Y||GET"),
];

fn config(fe: std::net::SocketAddr) -> String {
    let mut cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\nfrontend f\n  bind {fe}\n"
    );
    for (tag, act, re, rp, _, _) in CASES {
        cfg.push_str(&format!("  http-request {act} {re} {rp} if {{ hdr(x-t) -m str {tag} }}\n"));
    }
    cfg.push_str("  http-request return status 200 content-type text/plain lf-string \"%[path]|%[query]|%[url]|%[pathq]|%[method]\\n\"\n");
    cfg
}

#[test]
fn the_whole_part_is_replaced_by_the_expanded_log_format() {
    let fe = common::reserve_addr();
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(config(fe).as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened");
    let mut wrong = Vec::new();
    for (tag, act, re, rp, target, want) in CASES {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(3))).ok();
        c.write_all(format!("GET {target} HTTP/1.1\r\nHost: h\r\nX-T: {tag}\r\nConnection: close\r\n\r\n").as_bytes()).expect("send");
        let mut got = String::new();
        let _ = c.read_to_string(&mut got);
        let body = got.split_once("\r\n\r\n").map_or("", |(_, b)| b).trim_end();
        if body != *want {
            wrong.push(format!("{tag}: {act} {re} {rp} on {target}: want {want:?}, got {body:?}"));
        }
    }
    common::stop(&mut child);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

fn check(rule: &str) -> (bool, String) {
    let mut f = NamedTempFile::new().expect("tmp");
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n\
         frontend f\n  bind 127.0.0.1:1\n  {rule}\n  default_backend b\nbackend b\n  http-request return status 200\n"
    );
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn the_load_refuses_a_bad_regex_and_a_wrong_argument_count() {
    for act in ["replace-path", "replace-pathq", "replace-uri"] {
        let (ok, err) = check(&format!("http-request {act} (a /x"));
        assert!(!ok && err.contains("failed to parse the regex"), "{act} (a: {err}");
        for rule in [format!("http-request {act} a"), format!("http-request {act} a b c")] {
            let (ok, err) = check(&rule);
            assert!(!ok && err.contains("expects exactly 2 arguments <match-regex> and <replace-format>"), "{rule}: {err}");
        }
        assert!(check(&format!("http-request {act} a b if TRUE")).0, "{act} with a condition must load");
    }
}
