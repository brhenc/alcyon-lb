// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A pattern is one config word however it was written: `"a b\r\n\$4"` is the five bytes
//! `a b<CR><LF>$4` after `parse_line`, and the ACL matches exactly those, in an `acl`
//! line and in an inline `{ }` condition (checks/redis-check.vtc relies on the second:
//! `{ req.payload(0,14) -m str "*1\r\n\$4\r\nPING\r\n" }`).

use ibex_sample::{sample_registry, Expr, SampleContext};

#[test]
fn a_pattern_keeps_its_spaces_and_escaped_bytes() {
    let cfg = ibex_config::parse_str(
        "frontend f\n  mode tcp\n  bind 127.0.0.1:1\n  \
         acl named req.payload(0,0) -m str \"a b\\r\\n\\$4\"\n  \
         acl slash req.payload(0,0) -m str \\x41\\\\\n  \
         tcp-request content accept if { req.payload(0,0) -m str \"a b\\r\\n\\$4\" }\n  \
         default_backend b\nbackend b\n  mode tcp\n  server s 127.0.0.1:2\n",
    )
    .expect("parse");
    let fe = &cfg.frontends[0];
    let inline = fe.tcp_req_content_rules[0].cond.as_ref().expect("cond").terms[0].name.clone();
    let inline = inline.trim_start_matches('{').trim_end_matches('}').trim().to_string();
    let reg = sample_registry();
    for (expr, payloads) in [
        (fe.acls[0].expr.clone(), [&b"a b\r\n$4"[..], b"a b\r\n$4"]),
        (fe.acls[1].expr.clone(), [&b"A\\"[..], b"A\\"]),
        (inline, [&b"a b\r\n$4"[..], b"a b\r\n$4"]),
    ] {
        let e = Expr::parse(&expr).unwrap_or_else(|err| panic!("{expr:?}: {err:?}"));
        for p in payloads {
            let ctx = SampleContext { phase: &ibex_sample::PhaseCtx { req_body: Some(p), ..Default::default() }, live: None };
            assert!(e.eval(reg, &ctx), "{expr:?} should match {p:?}");
        }
        for p in [&b"a b"[..], b"a b\\r\\n$4", b"a", b"A\\\\"] {
            let ctx = SampleContext { phase: &ibex_sample::PhaseCtx { req_body: Some(p), ..Default::default() }, live: None };
            assert!(!e.eval(reg, &ctx), "{expr:?} should not match {p:?}");
        }
    }
}
