// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A matching method the fetch's output type cannot take is refused when the configuration
//! is read (T376, finding D8 of the T364 design). `parse_acl_expr` (`src/acl.c`) refuses
//! `-m <method>` unless `method == found || sample_casts[output type][pat_match_types[method]]`:
//! "matching method 'ip' cannot be used with fetch keyword 'always_true'." Ibex loaded these
//! and the ACL never matched: a deny rule that typo'd its method allowed everything.
//!
//! The table is measured on HAProxy 3.5-dev8-885761-29, 2026-10-18, `haproxy -c -f` with
//! `acl a <fetch> -m <method> <pattern>`: 14 methods (found, bool, int, ip, bin, len, str, sub,
//! reg, beg, end, dir, dom, regm) x 15 fetches (one per output type, a converter that
//! changes the type, and the `any` typed `var()`), 210 cells; 19 refused. The `keyword` in the
//! text is the first word of the expression as written (`str` for `str(a),b64dec`).
//! `-m bool` and `-m regm` are not implemented by Ibex (T364 D2), so only their refusals are here.
//!
//! * refused: `always_true -m ip`; `ipv6`, `src`, `bin`, `method`, the `bin`/`ipv4`/`ipv6`
//!   results of converters, `-m bool` and `-m int` on them (`bin` and `method` also `-m ip`).
//! * accepted: everything else, in particular every method on `var(txn.x)` (type any) and
//!   `-m bin` on a bool.

use std::process::Command;

const REFUSED: &[(&str, &str)] = &[
    ("src", "bool"),
    ("src", "int"),
    ("bin(01)", "bool"),
    ("bin(01)", "int"),
    ("bin(01)", "ip"),
    ("always_true", "ip"),
    ("str(a),b64dec", "bool"),
    ("str(a),b64dec", "int"),
    ("str(a),b64dec", "ip"),
    ("str(a),not", "ip"),
    ("str(1.2.3.4),ipmask(24)", "bool"),
    ("str(1.2.3.4),ipmask(24)", "int"),
    ("str(::1),ipmask(8,64)", "bool"),
    ("str(::1),ipmask(8,64)", "int"),
    ("ipv6(::1)", "bool"),
    ("ipv6(::1)", "int"),
    ("method", "bool"),
    ("method", "int"),
    ("method", "ip"),
];

const ACCEPTED: &[(&str, &str)] = &[
    ("src", "beg"),
    ("src", "bin"),
    ("src", "dir"),
    ("src", "dom"),
    ("src", "end"),
    ("src", "found"),
    ("src", "ip"),
    ("src", "len"),
    ("src", "reg"),
    ("src", "str"),
    ("src", "sub"),
    ("var(txn.x)", "beg"),
    ("var(txn.x)", "bin"),
    ("var(txn.x)", "dir"),
    ("var(txn.x)", "dom"),
    ("var(txn.x)", "end"),
    ("var(txn.x)", "found"),
    ("var(txn.x)", "int"),
    ("var(txn.x)", "ip"),
    ("var(txn.x)", "len"),
    ("var(txn.x)", "reg"),
    ("var(txn.x)", "str"),
    ("var(txn.x)", "sub"),
    ("bin(01)", "beg"),
    ("bin(01)", "bin"),
    ("bin(01)", "dir"),
    ("bin(01)", "dom"),
    ("bin(01)", "end"),
    ("bin(01)", "found"),
    ("bin(01)", "len"),
    ("bin(01)", "reg"),
    ("bin(01)", "str"),
    ("bin(01)", "sub"),
    ("always_true", "beg"),
    ("always_true", "bin"),
    ("always_true", "dir"),
    ("always_true", "dom"),
    ("always_true", "end"),
    ("always_true", "found"),
    ("always_true", "int"),
    ("always_true", "len"),
    ("always_true", "reg"),
    ("always_true", "str"),
    ("always_true", "sub"),
    ("str(a),b64dec", "beg"),
    ("str(a),b64dec", "bin"),
    ("str(a),b64dec", "dir"),
    ("str(a),b64dec", "dom"),
    ("str(a),b64dec", "end"),
    ("str(a),b64dec", "found"),
    ("str(a),b64dec", "len"),
    ("str(a),b64dec", "reg"),
    ("str(a),b64dec", "str"),
    ("str(a),b64dec", "sub"),
    ("str(a),not", "beg"),
    ("str(a),not", "bin"),
    ("str(a),not", "dir"),
    ("str(a),not", "dom"),
    ("str(a),not", "end"),
    ("str(a),not", "found"),
    ("str(a),not", "int"),
    ("str(a),not", "len"),
    ("str(a),not", "reg"),
    ("str(a),not", "str"),
    ("str(a),not", "sub"),
    ("str(1.2.3.4),ipmask(24)", "beg"),
    ("str(1.2.3.4),ipmask(24)", "bin"),
    ("str(1.2.3.4),ipmask(24)", "dir"),
    ("str(1.2.3.4),ipmask(24)", "dom"),
    ("str(1.2.3.4),ipmask(24)", "end"),
    ("str(1.2.3.4),ipmask(24)", "found"),
    ("str(1.2.3.4),ipmask(24)", "ip"),
    ("str(1.2.3.4),ipmask(24)", "len"),
    ("str(1.2.3.4),ipmask(24)", "reg"),
    ("str(1.2.3.4),ipmask(24)", "str"),
    ("str(1.2.3.4),ipmask(24)", "sub"),
    ("str(::1),ipmask(8,64)", "beg"),
    ("str(::1),ipmask(8,64)", "bin"),
    ("str(::1),ipmask(8,64)", "dir"),
    ("str(::1),ipmask(8,64)", "dom"),
    ("str(::1),ipmask(8,64)", "end"),
    ("str(::1),ipmask(8,64)", "found"),
    ("str(::1),ipmask(8,64)", "ip"),
    ("str(::1),ipmask(8,64)", "len"),
    ("str(::1),ipmask(8,64)", "reg"),
    ("str(::1),ipmask(8,64)", "str"),
    ("str(::1),ipmask(8,64)", "sub"),
    ("str(5),length", "beg"),
    ("str(5),length", "bin"),
    ("str(5),length", "dir"),
    ("str(5),length", "dom"),
    ("str(5),length", "end"),
    ("str(5),length", "found"),
    ("str(5),length", "int"),
    ("str(5),length", "ip"),
    ("str(5),length", "len"),
    ("str(5),length", "reg"),
    ("str(5),length", "str"),
    ("str(5),length", "sub"),
    ("int(5),hex", "beg"),
    ("int(5),hex", "bin"),
    ("int(5),hex", "dir"),
    ("int(5),hex", "dom"),
    ("int(5),hex", "end"),
    ("int(5),hex", "found"),
    ("int(5),hex", "int"),
    ("int(5),hex", "ip"),
    ("int(5),hex", "len"),
    ("int(5),hex", "reg"),
    ("int(5),hex", "str"),
    ("int(5),hex", "sub"),
    ("ipv4(1.2.3.4)", "beg"),
    ("ipv4(1.2.3.4)", "bin"),
    ("ipv4(1.2.3.4)", "dir"),
    ("ipv4(1.2.3.4)", "dom"),
    ("ipv4(1.2.3.4)", "end"),
    ("ipv4(1.2.3.4)", "found"),
    ("ipv4(1.2.3.4)", "int"),
    ("ipv4(1.2.3.4)", "ip"),
    ("ipv4(1.2.3.4)", "len"),
    ("ipv4(1.2.3.4)", "reg"),
    ("ipv4(1.2.3.4)", "str"),
    ("ipv4(1.2.3.4)", "sub"),
    ("ipv6(::1)", "beg"),
    ("ipv6(::1)", "bin"),
    ("ipv6(::1)", "dir"),
    ("ipv6(::1)", "dom"),
    ("ipv6(::1)", "end"),
    ("ipv6(::1)", "found"),
    ("ipv6(::1)", "ip"),
    ("ipv6(::1)", "len"),
    ("ipv6(::1)", "reg"),
    ("ipv6(::1)", "str"),
    ("ipv6(::1)", "sub"),
    ("method", "beg"),
    ("method", "bin"),
    ("method", "dir"),
    ("method", "dom"),
    ("method", "end"),
    ("method", "found"),
    ("method", "len"),
    ("method", "reg"),
    ("method", "str"),
    ("method", "sub"),
    ("int(5)", "beg"),
    ("int(5)", "bin"),
    ("int(5)", "dir"),
    ("int(5)", "dom"),
    ("int(5)", "end"),
    ("int(5)", "found"),
    ("int(5)", "int"),
    ("int(5)", "ip"),
    ("int(5)", "len"),
    ("int(5)", "reg"),
    ("int(5)", "str"),
    ("int(5)", "sub"),
    ("str(a)", "beg"),
    ("str(a)", "bin"),
    ("str(a)", "dir"),
    ("str(a)", "dom"),
    ("str(a)", "end"),
    ("str(a)", "found"),
    ("str(a)", "int"),
    ("str(a)", "ip"),
    ("str(a)", "len"),
    ("str(a)", "reg"),
    ("str(a)", "str"),
    ("str(a)", "sub"),
];

fn load(body: &str) -> (bool, String) {
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind 127.0.0.1:18080\n{body}  default_backend be\n\
         backend be\n  server s1 127.0.0.1:1\n"
    );
    let n = cfg.bytes().fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(u64::from(b)));
    let path = std::env::temp_dir().join(format!("ibex_matchtype_{}_{n:x}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("run ibex -c");
    let _ = std::fs::remove_file(&path);
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

fn pattern(method: &str) -> &'static str {
    match method {
        "found" | "bool" => "",
        "int" | "len" => "1",
        "ip" => "1.2.3.4",
        "bin" => "01",
        _ => "a",
    }
}

fn message(fetch: &str, method: &str) -> String {
    let kw = fetch.split(['(', ',']).next().unwrap_or(fetch);
    format!("matching method '{method}' cannot be used with fetch keyword '{kw}'")
}

#[test]
fn a_method_the_output_type_cannot_take_is_refused_in_a_named_acl() {
    for (fetch, method) in REFUSED {
        let (ok, out) = load(&format!("  acl a {fetch} -m {method} {}\n  http-request deny if a\n", pattern(method)));
        assert!(!ok, "HAProxy refuses `acl a {fetch} -m {method}`, Ibex loaded it: {out}");
        assert!(out.contains(&message(fetch, method)), "`{fetch} -m {method}`: wrong text: {out}");
    }
}

#[test]
fn a_method_the_output_type_can_take_still_loads() {
    for (fetch, method) in ACCEPTED {
        let (ok, out) = load(&format!("  acl a {fetch} -m {method} {}\n  http-request deny if a\n", pattern(method)));
        assert!(ok, "HAProxy loads `acl a {fetch} -m {method}`: {out}");
    }
}

/// Every place a condition is read refuses it, an anonymous `{ }` ACL included.
#[test]
fn the_check_applies_wherever_a_condition_is_read() {
    let e = "src -m int 1";
    let want = message("src", "int");
    for body in [
        format!("  http-request deny if {{ {e} }}\n"),
        format!("  http-request deny unless {{ {e} }}\n"),
        format!("  http-response deny if {{ {e} }}\n"),
        format!("  tcp-request content reject if {{ {e} }}\n"),
        format!("  tcp-request connection reject if {{ {e} }}\n"),
        format!("  use_backend be if {{ {e} }}\n"),
        format!("  acl a {e}\n  use_backend be if a\n"),
        format!("  acl a {e}\n  http-request deny if a\n"),
        format!("  acl a {e}\n"),
    ] {
        let (ok, out) = load(&body);
        assert!(!ok, "Ibex loaded `{body}`");
        assert!(out.contains(&want), "`{body}`: wrong text: {out}");
    }
    // The converter's output type decides, not the fetch's: `src,map_ip` etc. are str/int.
    let (ok, out) = load("  http-request deny if { src,ipmask(24) -m int 1 }\n");
    assert!(!ok, "{out}");
    assert!(out.contains(&message("src", "int")), "{out}");
    let (ok, out) = load("  http-request deny if { src,hex -m ip 1.2.3.4 }\n");
    assert!(ok, "str converts to addr: {out}");
}

/// The line that used to load and never match: a source-address ACL written with the integer
/// method. With the check, the typo is a load error instead of a deny list that allows
/// everything.
#[test]
fn an_address_acl_with_the_int_method_does_not_load() {
    let (ok, out) = load("  acl bad src -m int 127.0.0.1\n  http-request deny if bad\n");
    assert!(!ok, "loaded: {out}");
    assert!(out.contains("matching method 'int' cannot be used with fetch keyword 'src'"), "{out}");
}
