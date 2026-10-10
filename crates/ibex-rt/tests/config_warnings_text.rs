// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The warnings `-c` prints at configuration load, word for word as HAProxy prints them (T273 D).
//!
//! Every expectation was measured on HAProxy 3.5-dev8-885761-29 with `haproxy -c -f <file>`:
//! the `[WARNING]` lines of stderr (pid replaced by `PID`, the file name by `F`; the two
//! `[NOTICE]` version lines are dropped), `Warnings were found.` on stdout and the exit code.
//! Set `T273D_ORACLE=/path/to/haproxy` to run the cases against HAProxy: it passes them all.

use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

const TIMEOUTS: &str = "    timeout client 1s\n    timeout server 1s\n    timeout connect 1s\n";
const MISSING: &str = "\n   | While not properly invalid, you will certainly encounter various problems\n   | with such a configuration. To fix this, please ensure that all following\n   | timeouts are set to a non-zero value: 'client', 'connect', 'server'.";

/// Runs `-c` on `cfg`; returns (normalised warning lines, `Warnings were found.` seen, exit code).
fn check(cfg: &str) -> (String, bool, i32) {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write");
    let bin = std::env::var("T273D_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let out = Command::new(bin).arg("-c").arg("-f").arg(f.path()).output().expect("run");
    let path = f.path().display().to_string();
    let err = String::from_utf8_lossy(&out.stderr).replace(&path, "F");
    let mut text = String::new();
    for line in err.lines() {
        if line.starts_with("[NOTICE]") {
            continue;
        }
        // "(1234)" -> "(PID)"
        let line = match (line.find('('), line.find(')')) {
            (Some(a), Some(b)) if b > a && line[a + 1..b].bytes().all(|c| c.is_ascii_digit()) => format!("{}(PID){}", &line[..a], &line[b + 1..]),
            _ => line.to_string(),
        };
        text.push_str(&line);
        text.push('\n');
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    (text.strip_suffix('\n').unwrap_or(&text).to_string(), stdout.contains("Warnings were found."), out.status.code().unwrap_or(-1))
}

fn expect(cfg: &str, warnings: &str) {
    let (text, flag, rc) = check(cfg);
    assert_eq!(text, warnings, "stderr for:\n{cfg}");
    assert_eq!(flag, !warnings.is_empty(), "'Warnings were found.' on stdout for:\n{cfg}");
    assert_eq!(rc, 0, "exit code for:\n{cfg}");
}

#[test]
fn missing_timeouts_on_http_frontend_and_backend() {
    let cfg = "global\n    maxconn 100\nfrontend f\n    bind 127.0.0.1:18080\n    mode http\n    default_backend b\nbackend b\n    mode http\n    server s 127.0.0.1:1\n";
    expect(
        cfg,
        &format!("[WARNING]  (PID) : missing timeouts for frontend 'f'.{MISSING}\n[WARNING]  (PID) : missing timeouts for backend 'b'.{MISSING}"),
    );
}

#[test]
fn missing_timeouts_on_listen_and_the_rule_per_proxy() {
    // l1: no bind and no server timeout; l2 (tcp): `timeout tunnel` stands for `server`; l3
    // (http): it does not; l4: `timeout client 0` is unset; b1: no server, no warning; l5, f1:
    // disabled.
    let cfg = "listen l1\n    timeout client 1s\n    server s 127.0.0.1:1\n\
listen l2\n    bind 127.0.0.1:18081\n    timeout client 1s\n    timeout connect 1s\n    timeout tunnel 1s\n    server s 127.0.0.1:1\n\
listen l3\n    bind 127.0.0.1:18082\n    mode http\n    timeout client 1s\n    timeout connect 1s\n    timeout tunnel 1s\n    server s 127.0.0.1:1\n\
listen l4\n    bind 127.0.0.1:18083\n    mode http\n    timeout client 0\n    timeout connect 1s\n    timeout server 1s\n\
backend b1\n    mode http\n    timeout connect 1s\n\
frontend f1\n    mode http\n    bind 127.0.0.1:18084\n    disabled\n\
listen l5\n    disabled\n\
frontend f2\n    bind 127.0.0.1:18085\n    mode http\n    timeout client 1s\n";
    expect(
        cfg,
        &format!(
            "[WARNING]  (PID) : proxy 'l1' has no 'bind' directive. Please declare it as a backend if this was intended.\n\
[WARNING]  (PID) : missing timeouts for proxy 'l1'.{MISSING}\n\
[WARNING]  (PID) : missing timeouts for proxy 'l3'.{MISSING}\n\
[WARNING]  (PID) : missing timeouts for proxy 'l4'.{MISSING}"
        ),
    );
}

#[test]
fn frontend_without_bind() {
    let cfg = "frontend f\n    mode http\nbackend b\n    server s 127.0.0.1:1\n";
    expect(
        cfg,
        &format!(
            "[WARNING]  (PID) : frontend 'f' has no 'bind' directive. Please declare it as a backend if this was intended.\n\
[WARNING]  (PID) : missing timeouts for frontend 'f'.{MISSING}\n\
[WARNING]  (PID) : missing timeouts for backend 'b'.{MISSING}"
        ),
    );
}

#[test]
fn chroot_twice_has_the_blank_line_haproxy_prints() {
    let cfg = format!("global\n    chroot /tmp\n    chroot /tmp\ndefaults\n{TIMEOUTS}listen l\n    bind 127.0.0.1:18080\n");
    expect(&cfg, "[WARNING]  (PID) : config : parsing [F:3] : 'chroot' is already specified. Continuing.\n");
}

#[test]
fn cookie_domain_without_a_dot() {
    let cfg = format!("defaults\n{TIMEOUTS}backend b\n    mode http\n    cookie SRV insert domain foo\n    server s 127.0.0.1:1\n");
    expect(&cfg, "[WARNING]  (PID) : config : parsing [F:7]: domain 'foo' contains no embedded dot, this configuration may not work properly (see RFC6265#5.2.3).");
}

#[test]
fn cookie_and_stick_in_a_frontend() {
    let cfg = format!("defaults\n{TIMEOUTS}frontend f\n    bind 127.0.0.1:18080\n    mode http\n    cookie SRV insert\n    stick on src\n");
    expect(
        &cfg,
        "[WARNING]  (PID) : config : parsing [F:8] : 'cookie' ignored because frontend 'f' has no backend capability.\n\
[WARNING]  (PID) : config : parsing [F:9] : 'stick' ignored because frontend 'f' has no backend capability.",
    );
}

#[test]
fn httpchk_in_a_frontend() {
    let cfg = format!("defaults\n{TIMEOUTS}frontend f\n    bind 127.0.0.1:18080\n    mode http\n    option httpchk\n    default_backend b\nbackend b\n    mode http\n    server s 127.0.0.1:1\n");
    expect(&cfg, "[WARNING]  (PID) : config : parsing [F:8] : 'httpchk' ignored because frontend 'f' has no backend capability.");
}

#[test]
fn tcp_check_rules_without_option() {
    let cfg = format!("defaults\n{TIMEOUTS}listen l\n    bind 127.0.0.1:18080\n    tcp-check connect\n    server s 127.0.0.1:1\n");
    expect(&cfg, "[WARNING]  (PID) : proxy 'l' uses tcp-check rules without 'option tcp-check', so the rules are ignored.");
}

#[test]
fn a_configuration_with_nothing_to_say_says_nothing() {
    let cfg = format!("defaults\n{TIMEOUTS}listen l\n    bind 127.0.0.1:18080\n    server s 127.0.0.1:1\n");
    expect(&cfg, "");
}

#[test]
fn warning_directive_and_uid_count_as_warnings() {
    let cfg = format!("global\n.warning \"hello\"\n    uid abc\ndefaults\n{TIMEOUTS}listen l\n    bind 127.0.0.1:18080\n");
    expect(
        &cfg,
        "[WARNING]  (PID) : config : parsing [F:2]: 'hello'.\n\
[WARNING]  (PID) : config : parsing [F:3] :  uid: string 'abc' is not a number.\n   | You might want to use the 'user' parameter to use a system user name.",
    );
}

#[test]
fn default_server_ssl_version_is_an_alert_that_does_not_fail() {
    // HAProxy prints it as an ALERT, carries on and exits 0, with no "Warnings were found.".
    let cfg = format!("defaults\n{TIMEOUTS}    default-server no-sslv3\nlisten l\n    bind 127.0.0.1:18080\n    server s 127.0.0.1:1\n");
    let (text, flag, rc) = check(&cfg);
    assert_eq!(text, "[ALERT]    (PID) : config : [F:5] : 'no-sslv3' option is not accepted in default-server sections");
    assert!(!flag);
    assert_eq!(rc, 0);
}
