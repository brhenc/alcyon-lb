// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The patterns of a `bin` ACL (T144b 11). `HAProxy 3.5-dev8-885761-29` refuses, at load
//! (`haproxy -c`, exit 1), in a named ACL and in an anonymous `{ }` one, in every rule
//! that takes a condition:
//!
//! ```text
//! payload(0,2) 1            an even number of hex digit is expected.
//! payload(0,2) -m bin 123   an even number of hex digit is expected.
//! payload(0,2) -m bin 12 3  an even number of hex digit is expected.   (one word per pattern)
//! payload(0,2) -m bin 1x1   an even number of hex digit is expected.   (the length first)
//! payload(0,2) -m bin 0x12  an hex digit is expected (found 'x').
//! payload(0,2) -m bin 1g    an hex digit is expected (found 'g').
//! req.hdr(x) -m bin 1       an even number of hex digit is expected.
//! req.payload(0,2) 1        matching method must be specified first (using '-m') when using
//!                           a sample fetch of this type ('req.payload').
//! payload(0,2) 12 / -m bin 123456 / -m beg 1 / req.payload(0,2) -m beg 1    accepted
//! ```
//!
//! Ibex refused the named ACLs and loaded the anonymous ones: a rule on one never matched.

mod common;

use std::process::Command;

/// What `ibex -c` says about a frontend whose configuration lines are `body`.
fn check(body: &str) -> (Option<i32>, String) {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n mode http\n timeout client 5s\n timeout server 5s\n timeout connect 5s\n\
         frontend fe\n bind {fe}\n{body}\n default_backend be\n\
         backend be\n server s 127.0.0.1:1\n"
    );
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("ibex_aclbin_{}_{n}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("ibex -c");
    let _ = std::fs::remove_file(&path);
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

const EVEN: &str = "an even number of hex digit is expected";
const HEX_X: &str = "an hex digit is expected (found 'x')";
const HEX_G: &str = "an hex digit is expected (found 'g')";
const NEED_M: &str = "matching method must be specified first (using '-m') when using a sample fetch of this type ('req.payload')";

#[test]
fn a_bin_pattern_that_is_not_whole_bytes_of_hex_is_refused_in_a_named_acl() {
    let cases = [
        ("payload(0,2) 1", EVEN),
        ("payload(0,2) 123", EVEN),
        ("payload(0,2) -m bin 123", EVEN),
        ("payload(0,2) -m bin 12 3", EVEN),
        ("payload(0,2) -m bin 1x1", EVEN),
        ("payload(0,2) -m bin g", EVEN),
        ("payload(0,2) -m bin 0x12", HEX_X),
        ("payload(0,2) -m bin 1g", HEX_G),
        ("payload(0,2) -m bin 123g", HEX_G),
        ("req.hdr(x) -m bin 1", EVEN),
        ("req.payload(0,2) -m bin ab cd 1", EVEN),
        ("req.payload(0,2) 1", NEED_M),
    ];
    for (acl, want) in cases {
        let (code, text) = check(&format!(" acl a {acl}\n http-request deny if a"));
        assert_eq!(code, Some(1), "acl a {acl}: {text}");
        assert!(text.contains(want), "acl a {acl}: wanted {want:?} in {text}");
    }
}

#[test]
fn a_bin_pattern_that_is_not_whole_bytes_of_hex_is_refused_in_an_anonymous_acl() {
    let cases = [
        (" http-request deny if { payload(0,2) 1 }", EVEN),
        (" http-request deny if { req.payload(0,2) -m bin 1 }", EVEN),
        (" http-request deny if { req.hdr(x) -m bin 1 }", EVEN),
        (" http-request deny if { payload(0,2) -m bin 0x12 }", HEX_X),
        (" http-request deny if { payload(0,2) -m bin 1g }", HEX_G),
        (" http-request deny if { req.payload(0,2) 1 }", NEED_M),
        (" tcp-request content accept if { payload(0,2) 1 }", EVEN),
        (" tcp-request connection accept if { payload(0,2) -m bin 1 }", EVEN),
        (" use_backend be if { payload(0,2) 1 }", EVEN),
        (" http-request redirect location / if { payload(0,2) 1 }", EVEN),
        (" http-response deny if { res.payload(0,2) -m bin 1 }", EVEN),
        (" http-after-response set-header a b if { res.payload(0,2) -m bin 1 }", EVEN),
        (" http-request deny unless { payload(0,2) -m bin ab 1 }", EVEN),
    ];
    for (rule, want) in cases {
        let (code, text) = check(rule);
        assert_eq!(code, Some(1), "{rule}: {text}");
        assert!(text.contains(want), "{rule}: wanted {want:?} in {text}");
    }
}

#[test]
fn whole_bytes_of_hex_and_other_methods_are_accepted() {
    for rule in [
        " http-request deny if { payload(0,2) 12 }",
        " http-request deny if { payload(0,2) -m bin 123456 }",
        " http-request deny if { payload(0,2) -m bin ab CD 00ff }",
        " http-request deny if { payload(0,2) -m beg 1 }",
        " http-request deny if { req.payload(0,2) -m beg 1 }",
        " http-request deny if { req.payload(0,2) -m bin 12 }",
        " acl a payload(0,2) 12\n http-request deny if a",
    ] {
        let (code, text) = check(rule);
        assert_eq!(code, Some(0), "{rule}: {text}");
    }
}
