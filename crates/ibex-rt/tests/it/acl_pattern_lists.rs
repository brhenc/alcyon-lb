// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! An ACL matches if ANY of its patterns matches (T99): `acl bad path /a /b` denies `/a`
//! and `/b`, with the flags (`-i`, `-m`) and the default method applying to every pattern,
//! `-f <file>` patterns joining the inline ones, and several `acl` lines of one name ORed.
//!
//! Every status below was measured on the reference binary, `HAProxy 3.5-dev8-885761-29`,
//! on 2026-10-03: each case is a frontend with the given `acl` lines, the given rule, and
//! `http-request return status 200`, and a `GET <path>` with `Host: <host>` (and `X-N: <n>`
//! when given) from 127.0.0.1. A deny rule answers 403. `{F}` is a pattern file holding
//! `/f1`, a comment, a blank line and `  /f2  `.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;

/// (path, Host, X-N, status HAProxy answered).
type Probe = (&'static str, &'static str, Option<&'static str>, u16);

struct Case {
    name: &'static str,
    acls: &'static [&'static str],
    rule: &'static str,
    probes: &'static [Probe],
}

const PATTERNS: &str = "/f1\n# a comment\n\n  /f2  \n";

fn status_of(addr: std::net::SocketAddr, path: &str, host: &str, xn: Option<&str>) -> u16 {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("timeout");
    let n = xn.map_or(String::new(), |n| format!("X-N: {n}\r\n"));
    write!(s, "GET {path} HTTP/1.1\r\nHost: {host}\r\n{n}Connection: close\r\n\r\n").expect("send");
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    text.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0)
}

fn run_case(c: &Case, files: &str) {
    let fe = common::reserve_addr();
    let mut cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\nfrontend f\n  bind {fe}\n"
    );
    for a in c.acls {
        cfg.push_str(&format!("  {}\n", a.replace("{F}", files)));
    }
    cfg.push_str(&format!("  {}\n  http-request return status 200\n", c.rule.replace("{F}", files)));
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Ibex)
        .expect("spawn ibex");
    let up = common::wait_listening(fe);
    let mut bad = Vec::new();
    if up {
        for &(path, host, xn, want) in c.probes {
            let got = status_of(fe, path, host, xn);
            if got != want {
                bad.push(format!("{path} host={host} x-n={xn:?}: HAProxy {want}, Ibex {got}"));
            }
        }
    }
    common::stop(&mut child);
    assert!(up, "{}: ibex never listened with:\n{cfg}", c.name);
    assert!(bad.is_empty(), "{}: differs from HAProxy with:\n{cfg}\n{}", c.name, bad.join("\n"));
}

#[test]
fn every_pattern_of_an_acl_is_matched_like_haproxy() {
    let mut pf = NamedTempFile::new().expect("tmp");
    pf.write_all(PATTERNS.as_bytes()).expect("write patterns");
    let files = pf.path().to_str().expect("utf8 path").to_string();
    let mut failures = Vec::new();
    for c in CASES {
        if let Err(e) = std::panic::catch_unwind(|| run_case(c, &files)) {
            let msg = e.downcast_ref::<String>().cloned().unwrap_or_default();
            failures.push(msg);
        }
    }
    assert!(failures.is_empty(), "{} case(s) differ:\n{}", failures.len(), failures.join("\n---\n"));
}

/// An `acl` line that does not compile is refused at load, as HAProxy does: left out
/// quietly, the rule naming it would never match and the deny list would allow everything.
#[test]
fn an_acl_line_that_does_not_compile_is_refused() {
    for acl in [
        "acl bad path -z /a",
        "acl bad path -f /nonexistent/t99/patterns",
        "acl bad path -m nosuch /a",
        "acl bad path -m str -m beg /a",
        "acl bad req.hdr_val(x-n) -m int 5:1",
    ] {
        let cfg = format!(
            "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\nfrontend f\n  bind 127.0.0.1:1\n  {acl}\n  http-request deny if bad\n"
        );
        let mut f = NamedTempFile::new().expect("tmp");
        f.write_all(cfg.as_bytes()).expect("write cfg");
        let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run ibex -c");
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(!out.status.success(), "{acl} should be refused, ibex said: {text}");
        assert!(text.contains("while parsing ACL 'bad'"), "{acl}: {text}");
    }
}

const CASES: &[Case] = &[
    Case {
        name: "path_default",
        acls: &["acl bad path /a /b"],
        rule: "http-request deny if bad",
        probes: &[("/a", "x", None, 403), ("/b", "x", None, 403), ("/c", "x", None, 200)],
    },
    Case {
        name: "path_str_m",
        acls: &["acl bad path -m str /a /b /c"],
        rule: "http-request deny if bad",
        probes: &[("/a", "x", None, 403), ("/b", "x", None, 403), ("/c", "x", None, 403), ("/d", "x", None, 200)],
    },
    Case {
        name: "path_beg",
        acls: &["acl bad path_beg /a /b"],
        rule: "http-request deny if bad",
        probes: &[("/a1", "x", None, 403), ("/b1", "x", None, 403), ("/c1", "x", None, 200)],
    },
    Case {
        name: "path_beg_m",
        acls: &["acl bad path -m beg /a /b"],
        rule: "http-request deny if bad",
        probes: &[("/a1", "x", None, 403), ("/b1", "x", None, 403), ("/c1", "x", None, 200)],
    },
    Case {
        name: "path_end",
        acls: &["acl bad path_end .x .y"],
        rule: "http-request deny if bad",
        probes: &[("/f.x", "x", None, 403), ("/f.y", "x", None, 403), ("/f.z", "x", None, 200)],
    },
    Case {
        name: "path_sub",
        acls: &["acl bad path_sub aa bb"],
        rule: "http-request deny if bad",
        probes: &[("/1aa", "x", None, 403), ("/1bb", "x", None, 403), ("/1cc", "x", None, 200)],
    },
    Case {
        name: "path_dir",
        acls: &["acl bad path_dir a b"],
        rule: "http-request deny if bad",
        probes: &[("/q/a/z", "x", None, 403), ("/q/b/z", "x", None, 403), ("/q/c/z", "x", None, 200)],
    },
    Case {
        name: "path_dir_m",
        acls: &["acl bad path -m dir a b"],
        rule: "http-request deny if bad",
        probes: &[("/q/a/z", "x", None, 403), ("/q/b/z", "x", None, 403), ("/q/c/z", "x", None, 200)],
    },
    Case {
        name: "hdr_dom",
        acls: &["acl bad hdr_dom(host) a.com b.org"],
        rule: "http-request deny if bad",
        probes: &[("/", "x.a.com", None, 403), ("/", "y.b.org", None, 403), ("/", "c.net", None, 200)],
    },
    Case {
        name: "hdr_dom_m",
        acls: &["acl bad hdr(host) -m dom a.com b.org"],
        rule: "http-request deny if bad",
        probes: &[("/", "x.a.com", None, 403), ("/", "y.b.org", None, 403), ("/", "c.net", None, 200)],
    },
    Case {
        name: "path_reg",
        acls: &["acl bad path_reg ^/a ^/b$"],
        rule: "http-request deny if bad",
        probes: &[("/a1", "x", None, 403), ("/b", "x", None, 403), ("/b1", "x", None, 200), ("/c", "x", None, 200)],
    },
    Case {
        name: "path_reg_m",
        acls: &["acl bad path -m reg ^/a ^/b$"],
        rule: "http-request deny if bad",
        probes: &[("/a1", "x", None, 403), ("/b", "x", None, 403), ("/b1", "x", None, 200), ("/c", "x", None, 200)],
    },
    Case {
        name: "src_all_match",
        acls: &["acl bad src 10.0.0.0/8 127.0.0.0/8"],
        rule: "http-request deny if bad",
        probes: &[("/a", "x", None, 403)],
    },
    Case {
        name: "src_first_only",
        acls: &["acl bad src 127.0.0.0/8 10.0.0.0/8"],
        rule: "http-request deny if bad",
        probes: &[("/a", "x", None, 403)],
    },
    Case {
        name: "src_none",
        acls: &["acl bad src 10.0.0.0/8 192.168.0.0/16"],
        rule: "http-request deny if bad",
        probes: &[("/a", "x", None, 200)],
    },
    Case {
        name: "src_host",
        acls: &["acl bad src 192.168.0.1 127.0.0.1"],
        rule: "http-request deny if bad",
        probes: &[("/a", "x", None, 403)],
    },
    Case {
        name: "src_mixed",
        acls: &["acl bad src 10.0.0.1 127.0.0.0/24"],
        rule: "http-request deny if bad",
        probes: &[("/a", "x", None, 403)],
    },
    Case {
        name: "int_ranges",
        acls: &["acl bad req.hdr_val(x-n) 1:5 10 20:30"],
        rule: "http-request deny if bad",
        probes: &[("/", "x", Some("3"), 403), ("/", "x", Some("10"), 403), ("/", "x", Some("25"), 403), ("/", "x", Some("7"), 200), ("/", "x", Some("31"), 200), ("/", "x", Some("1"), 403), ("/", "x", Some("5"), 403), ("/", "x", Some("20"), 403), ("/", "x", Some("30"), 403)],
    },
    Case {
        name: "int_open",
        acls: &["acl bad req.hdr_val(x-n) :2 100:"],
        rule: "http-request deny if bad",
        probes: &[("/", "x", Some("1"), 403), ("/", "x", Some("2"), 403), ("/", "x", Some("3"), 200), ("/", "x", Some("99"), 200), ("/", "x", Some("100"), 403), ("/", "x", Some("500"), 403)],
    },
    Case {
        name: "int_ops",
        acls: &["acl bad req.hdr_val(x-n) gt 100 200"],
        rule: "http-request deny if bad",
        probes: &[("/", "x", Some("50"), 200), ("/", "x", Some("101"), 403), ("/", "x", Some("150"), 403)],
    },
    Case {
        name: "int_ops2",
        acls: &["acl bad req.hdr_val(x-n) lt 5 eq 7"],
        rule: "http-request deny if bad",
        probes: &[("/", "x", Some("3"), 403), ("/", "x", Some("7"), 403), ("/", "x", Some("8"), 200), ("/", "x", Some("50"), 200)],
    },
    Case {
        name: "int_m",
        acls: &["acl bad req.hdr_val(x-n) -m int 1:5 10"],
        rule: "http-request deny if bad",
        probes: &[("/", "x", Some("3"), 403), ("/", "x", Some("10"), 403), ("/", "x", Some("7"), 200)],
    },
    Case {
        name: "len",
        acls: &["acl bad path -m len 2 4:5"],
        rule: "http-request deny if bad",
        probes: &[("/a", "x", None, 403), ("/abc", "x", None, 403), ("/ab", "x", None, 200), ("/abcd", "x", None, 403), ("/abcde", "x", None, 200), ("/abcdef", "x", None, 200)],
    },
    Case {
        name: "icase",
        acls: &["acl bad path -i /a /b"],
        rule: "http-request deny if bad",
        probes: &[("/A", "x", None, 403), ("/B", "x", None, 403), ("/c", "x", None, 200), ("/a", "x", None, 403)],
    },
    Case {
        name: "icase_beg",
        acls: &["acl bad path_beg -i /a /b"],
        rule: "http-request deny if bad",
        probes: &[("/Aa", "x", None, 403), ("/Bb", "x", None, 403), ("/c", "x", None, 200)],
    },
    Case {
        name: "icase_m",
        acls: &["acl bad path -m str -i /a /b"],
        rule: "http-request deny if bad",
        probes: &[("/A", "x", None, 403), ("/B", "x", None, 403), ("/c", "x", None, 200)],
    },
    Case {
        name: "icase_reg",
        acls: &["acl bad path_reg -i ^/a ^/b"],
        rule: "http-request deny if bad",
        probes: &[("/Aa", "x", None, 403), ("/Bb", "x", None, 403), ("/c", "x", None, 200)],
    },
    Case {
        name: "anon",
        acls: &[],
        rule: "http-request deny if { path /a /b }",
        probes: &[("/a", "x", None, 403), ("/b", "x", None, 403), ("/c", "x", None, 200)],
    },
    Case {
        name: "anon_unless",
        acls: &[],
        rule: "http-request deny unless { path /a /b }",
        probes: &[("/a", "x", None, 200), ("/b", "x", None, 200), ("/c", "x", None, 403)],
    },
    Case {
        name: "anon_neg",
        acls: &[],
        rule: "http-request deny if !{ path /a /b }",
        probes: &[("/a", "x", None, 200), ("/b", "x", None, 200), ("/c", "x", None, 403)],
    },
    Case {
        name: "neg_named",
        acls: &["acl good path /a /b"],
        rule: "http-request deny if !good",
        probes: &[("/a", "x", None, 200), ("/b", "x", None, 200), ("/c", "x", None, 403)],
    },
    Case {
        name: "unless_named",
        acls: &["acl good path /a /b"],
        rule: "http-request deny unless good",
        probes: &[("/a", "x", None, 200), ("/b", "x", None, 200), ("/c", "x", None, 403)],
    },
    Case {
        name: "multiline",
        acls: &["acl bad path /a", "acl bad path /b", "acl bad path_beg /c"],
        rule: "http-request deny if bad",
        probes: &[("/a", "x", None, 403), ("/b", "x", None, 403), ("/c1", "x", None, 403), ("/d", "x", None, 200)],
    },
    Case {
        name: "multiline_fetch",
        acls: &["acl bad path /a", "acl bad hdr(host) evil other"],
        rule: "http-request deny if bad",
        probes: &[("/a", "x", None, 403), ("/z", "evil", None, 403), ("/z", "other", None, 403), ("/z", "x", None, 200)],
    },
    Case {
        name: "and_two",
        acls: &["acl p path /a /b", "acl h hdr(host) x y"],
        rule: "http-request deny if p h",
        probes: &[("/a", "x", None, 403), ("/b", "y", None, 403), ("/b", "z", None, 200), ("/c", "x", None, 200)],
    },
    Case {
        name: "file_only",
        acls: &["acl bad path -f {F}"],
        rule: "http-request deny if bad",
        probes: &[("/f1", "x", None, 403), ("/f2", "x", None, 403), ("/f3", "x", None, 200)],
    },
    Case {
        name: "file_inline",
        acls: &["acl bad path -f {F} /x /y"],
        rule: "http-request deny if bad",
        probes: &[("/f1", "x", None, 403), ("/f2", "x", None, 403), ("/x", "x", None, 403), ("/y", "x", None, 403), ("/z", "x", None, 200)],
    },
    Case {
        name: "file_beg",
        acls: &["acl bad path -m beg -f {F} /x"],
        rule: "http-request deny if bad",
        probes: &[("/f11", "x", None, 403), ("/f2z", "x", None, 403), ("/xa", "x", None, 403), ("/z", "x", None, 200)],
    },
    Case {
        name: "file_icase",
        acls: &["acl bad path -i -f {F} /x"],
        rule: "http-request deny if bad",
        probes: &[("/F1", "x", None, 403), ("/F2", "x", None, 403), ("/X", "x", None, 403), ("/z", "x", None, 200)],
    },
    Case {
        name: "anon_file",
        acls: &[],
        rule: "http-request deny if { path -f {F} /x }",
        probes: &[("/f1", "x", None, 403), ("/f2", "x", None, 403), ("/x", "x", None, 403), ("/z", "x", None, 200)],
    },
    Case {
        name: "dash_dash",
        acls: &["acl bad path -- /a /b"],
        rule: "http-request deny if bad",
        probes: &[("/a", "x", None, 403), ("/b", "x", None, 403), ("/c", "x", None, 200)],
    },
    Case {
        name: "found_flag",
        acls: &["acl bad path -m found"],
        rule: "http-request deny if bad",
        probes: &[("/a", "x", None, 403)],
    },
];
