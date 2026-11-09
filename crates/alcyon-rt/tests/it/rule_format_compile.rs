// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T455: a rule's format is compiled when the configuration loads, as `HAProxy`'s
//! `parse_logformat_string` does: an alias that does not exist, a truncated `%` and a fetch
//! the rule cannot use are refused with `HAProxy`'s message, not printed as text per request.
//! Every message was measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-25.

use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

fn check(rule: &str) -> (bool, String) {
    let mut f = NamedTempFile::new().expect("tmp");
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\nfrontend f\n  bind 127.0.0.1:1\n  {rule}\n  default_backend b\nbackend b\n  server s 127.0.0.1:1\n"
    );
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(f.path()).output().expect("run");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

const NO_ALIAS: &str = "no such format alias 'zz'. If you wanted to emit the '%' character verbatim, you need to use '%%'.";

/// Every action that takes a format refuses an unknown alias, with its own name in the message.
#[test]
fn an_unknown_alias_is_refused_in_every_rule_format() {
    let rules = [
        ("http-request", "set-header", "set-header x-a \"%zz\""),
        ("http-request", "add-header", "add-header x-a \"%zz\""),
        ("http-response", "set-header", "set-header x-a \"%zz\""),
        ("http-after-response", "set-header", "set-header x-a \"%zz\""),
        ("http-request", "set-var-fmt(txn.a)", "set-var-fmt(txn.a) \"%zz\""),
        ("http-response", "set-var-fmt(txn.a)", "set-var-fmt(txn.a) \"%zz\""),
        ("http-request", "set-path", "set-path \"/%zz\""),
        ("http-request", "set-pathq", "set-pathq \"/%zz\""),
        ("http-request", "set-query", "set-query \"%zz\""),
        ("http-request", "set-uri", "set-uri \"/%zz\""),
        ("http-request", "set-method", "set-method \"%zz\""),
        ("http-request", "replace-header", "replace-header x ^(.*)$ \"%zz\""),
        ("http-response", "replace-header", "replace-header x ^(.*)$ \"%zz\""),
        ("http-request", "replace-path", "replace-path ^(.*)$ \"%zz\""),
        ("http-request", "redirect", "redirect location \"/%zz\""),
        ("http-request", "redirect", "redirect prefix \"/%zz\""),
        ("http-request", "redirect", "redirect scheme \"%zz\""),
        ("http-response", "redirect", "redirect location \"/%zz\""),
        ("http-request", "return", "return status 200 content-type text/plain lf-string \"%zz\""),
        ("http-response", "return", "return status 200 content-type text/plain lf-string \"%zz\""),
        ("http-request", "deny", "deny deny_status 403 content-type text/plain lf-string \"%zz\""),
        ("http-request", "tarpit", "tarpit content-type text/plain lf-string \"%zz\""),
    ];
    let mut wrong = Vec::new();
    for (dir, action, tail) in rules {
        let (ok, err) = check(&format!("{dir} {tail}"));
        let want = format!("error detected in frontend 'f' while parsing '{dir} {action}' rule : {NO_ALIAS}");
        if ok || !err.contains(&want) {
            wrong.push(format!("{dir} {tail}: ok={ok} {err}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_tcp_rule_format_is_refused_without_the_rule_prefix() {
    let (ok, err) = check("tcp-request content set-var-fmt(txn.a) \"%zz\"");
    assert!(!ok && err.contains(&format!("{}\n", &NO_ALIAS[..NO_ALIAS.len() - 1])), "{err}");
}

#[test]
fn a_malformed_percent_is_refused() {
    for (fmt, msg) in [
        ("%", "truncated line after '%'."),
        ("%1", "unexpected alias name near '1' at position 1 line : '%1'. Maybe you want to write a single '%', use the syntax '%%'."),
        ("%{+Q}", "parse argument modifier without alias name near '%{+Q}'."),
        ("%Zq", "no such format alias 'Zq'. If you wanted to emit the '%' character verbatim, you need to use '%%'."),
        ("%cix", "no such format alias 'cix'. If you wanted to emit the '%' character verbatim, you need to use '%%'."),
    ] {
        let (ok, err) = check(&format!("http-request set-header x-a \"{fmt}\""));
        let want = format!("error detected in frontend 'f' while parsing 'http-request set-header' rule : {msg}");
        assert!(!ok && err.contains(&want), "{fmt}: {err}");
    }
}

/// What `HAProxy` loads, Alcyon loads: the aliases and options a rule format may use.
#[test]
fn the_aliases_haproxy_accepts_load() {
    for fmt in ["%ci:%cp", "%ft %ST %B %{+Q}r %Tr %s %Ta %hr %CC %b %f %fi %fp %si %sp", "%(n)ci", "%{+X}ci", "%o", "100%%", "%[str(a)]", "%{+Q}[str(a)]"] {
        let (ok, err) = check(&format!("http-request set-header x-a \"{fmt}\""));
        assert!(ok, "{fmt}: {err}");
    }
}

/// `be_name` needs a backend, which a frontend's rules do not have yet (row 7).
#[test]
fn be_name_in_a_frontend_rule_format_is_refused() {
    let (ok, err) = check("http-request set-header x-a \"%[be_name]\"");
    let want = "error detected in frontend 'f' while parsing 'http-request set-header' rule : sample fetch <be_name> may not be reliably used here because it needs 'backend' which is not available here.";
    assert!(!ok && err.contains(want), "{err}");
}

fn check_cfg(cfg: &str) -> (bool, String) {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(f.path()).output().expect("run");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// The message names the section the rule is in, as `HAProxy`'s does (measured on 3.5-dev8 on
/// 2026-10-25): `backend 'b'`, `proxy 'l'` for a listen, `defaults 'd'`.
#[test]
fn the_refusal_names_the_section_kind() {
    const D: &str = "  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n";
    let rule = "  http-request set-header x-a \"%zz\"\n";
    for (cfg, place) in [
        (format!("defaults\n{D}backend b\n{rule}  server s 127.0.0.1:1\n"), "backend 'b'"),
        (format!("defaults\n{D}listen l\n  bind 127.0.0.1:1\n{rule}  server s 127.0.0.1:1\n"), "proxy 'l'"),
        (format!("defaults d\n{D}{rule}frontend f from d\n  bind 127.0.0.1:1\n"), "defaults 'd'"),
    ] {
        let (ok, err) = check_cfg(&cfg);
        let want = format!("error detected in {place} while parsing 'http-request set-header' rule : {NO_ALIAS}");
        assert!(!ok && err.contains(&want), "{place}: {err}");
    }
}

/// A format whose sample does not parse is refused once, by the sample's own check, not again
/// as a format (measured on 3.5-dev8: `failed to parse sample expression <nosuchfetch]> :
/// unknown fetch method 'nosuchfetch'.`).
#[test]
fn a_format_with_a_bad_sample_is_refused_by_the_sample_check() {
    let (ok, err) = check("http-request set-header x-a \"%[nosuchfetch]\"");
    assert!(!ok && err.contains("unknown fetch method 'nosuchfetch'"), "{err}");
    assert_eq!(err.lines().filter(|l| l.contains("nosuchfetch")).count(), 1, "refused once: {err}");
}
