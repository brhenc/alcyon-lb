// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The warnings `-c` prints at configuration load, word for word as HAProxy prints them (T273 D).
//!
//! Every expectation was measured on HAProxy 3.5-dev8-885761-29 with `haproxy -c -f <file>`:
//! the `[WARNING]` lines of stderr (pid replaced by `PID`, the file name by `F`; the two
//! `[NOTICE]` version lines are dropped), `Warnings were found.` on stdout and the exit code.
//! Set `T273D_ORACLE=/path/to/haproxy` to run the cases against HAProxy: it passes them all.

use crate::common;

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

// ---------------------------------------------------------------------------------------------
// T274 A: references HAProxy resolves when the configuration loads (`check_config_validity`).
// Measured the same way; the ALERT lines of stderr, pid replaced, and exit code 1.

fn alerts(cfg: &str) -> (Vec<String>, i32) {
    let (text, _, rc) = check_any(cfg);
    (text.lines().filter(|l| l.starts_with("[ALERT]")).map(String::from).collect(), rc)
}

/// [`check`] without asserting on the exit code.
fn check_any(cfg: &str) -> (String, bool, i32) {
    check(cfg)
}

fn refuses(cfg: &str, lines: &[&str]) {
    let (got, rc) = alerts(cfg);
    let want: Vec<String> = lines.iter().map(|l| format!("[ALERT]    (PID) : {l}")).collect();
    assert_eq!(got, want, "ALERT lines for:\n{cfg}");
    assert_eq!(rc, 1, "exit code for:\n{cfg}");
}

fn accepts(cfg: &str) {
    let (got, rc) = alerts(cfg);
    assert!(got.is_empty() && rc == 0, "expected to load, got {got:?} rc={rc} for:\n{cfg}");
}

/// A configuration whose only fault is `extra`, put in frontend `f` (HTTP, `bind`, timeouts).
fn fe(extra: &str) -> String {
    format!("frontend f\n    bind 127.0.0.1:18090\n    mode http\n    timeout client 1s\n{extra}backend b\n    mode http\n    timeout server 1s\n    timeout connect 1s\n    server s 127.0.0.1:1\n")
}

#[test]
fn use_backend_of_a_backend_that_does_not_exist() {
    refuses(&fe("    use_backend nosuch if { path /x }\n    default_backend b\n"), &["Proxy 'f': unable to find required use_backend: 'nosuch'."]);
}

#[test]
fn default_backend_of_a_backend_that_does_not_exist() {
    refuses(&fe("    default_backend nosuch\n"), &["Proxy 'f': unable to find required default_backend: 'nosuch'."]);
}

#[test]
fn default_backend_comes_first_then_the_use_backend_rules_in_order() {
    refuses(
        &fe("    use_backend nosuch1 if { path /a }\n    use_backend nosuch2 if { path /b }\n    default_backend nosuch3\n"),
        &[
            "Proxy 'f': unable to find required default_backend: 'nosuch3'.",
            "Proxy 'f': unable to find required use_backend: 'nosuch1'.",
            "Proxy 'f': unable to find required use_backend: 'nosuch2'.",
        ],
    );
}

#[test]
fn a_frontend_is_not_a_backend_and_a_listen_is() {
    refuses(&fe("    use_backend f\n"), &["Proxy 'f': unable to find required use_backend: 'f'."]);
    accepts(&format!(
        "listen l\n    bind 127.0.0.1:18091\n    mode http\n{TIMEOUTS}    server s 127.0.0.1:1\n{}",
        fe("    use_backend l\n    default_backend b\n")
    ));
}

#[test]
fn a_disabled_backend_is_still_a_target_and_a_disabled_frontend_is_not_checked() {
    accepts(&format!("backend d\n    disabled\n    mode http\n{TIMEOUTS}    server s 127.0.0.1:1\n{}", fe("    use_backend d\n    default_backend b\n")));
    accepts(&format!(
        "frontend g\n    disabled\n    bind 127.0.0.1:18092\n    mode http\n{TIMEOUTS}    use_backend zz\n    http-request track-sc0 src table zz\n{}",
        fe("    default_backend b\n")
    ));
}

#[test]
fn only_the_first_proxy_in_error_is_reported() {
    let cfg = format!(
        "frontend f1\n    bind 127.0.0.1:18093\n    mode http\n{TIMEOUTS}    use_backend u1\nfrontend f2\n    bind 127.0.0.1:18094\n    mode http\n{TIMEOUTS}    use_backend u2\n"
    );
    refuses(&cfg, &["Proxy 'f1': unable to find required use_backend: 'u1'."]);
}

#[test]
fn track_sc_names_a_table_that_exists() {
    for (rule, n) in [
        ("http-request track-sc0 src table nosuch", 0),
        ("tcp-request connection track-sc1 src table nosuch", 1),
        ("tcp-request session track-sc2 src table nosuch", 2),
        ("tcp-request content track-sc0 src table nosuch", 0),
    ] {
        refuses(&fe(&format!("    {rule}\n    default_backend b\n")), &[&format!("Proxy 'f': unable to find table 'nosuch' referenced by track-sc{n}.")]);
    }
    // In a backend, and with no `table`: the proxy's own, which has none.
    let cfg = format!("{}    http-request track-sc1 src table nosuch\n", fe("    default_backend b\n"));
    refuses(&cfg, &["Proxy 'b': unable to find table 'nosuch' referenced by track-sc1."]);
    refuses(&fe("    http-request track-sc0 src\n    default_backend b\n"), &["Proxy 'f': unable to find table 'f' referenced by track-sc0."]);
}

#[test]
fn track_sc_finds_the_own_table_and_one_in_another_proxy() {
    accepts(&fe("    stick-table type ip size 1k\n    http-request track-sc0 src\n    default_backend b\n"));
    // (A table in a disabled backend crashes HAProxy 3.5-dev8 with SIGSEGV at `-c`; not tested.)
    accepts(&format!(
        "backend t\n    mode http\n    stick-table type ip size 1k\n{}",
        fe("    http-request track-sc0 src table t\n    default_backend b\n")
    ));
}

/// Ibex only: HAProxy builds the backend name of a `use_backend` from a log-format string;
/// Ibex looks the written text up as a name, never finds it and sends the request to the
/// default backend, so it refuses.
#[test]
fn a_log_format_use_backend_is_refused_by_ibex() {
    if std::env::var("T273D_ORACLE").is_ok() {
        return;
    }
    let (got, rc) = alerts(&fe("    use_backend %[req.hdr(x)]\n    default_backend b\n"));
    assert_eq!(rc, 1, "{got:?}");
}

#[test]
fn accept_invalid_http_request_is_the_deprecated_name_of_the_unsafe_option() {
    let dep = |name: &str, new: &str, line: usize| {
        format!("[WARNING]  (PID) : config : parsing [F:{line}]: option '{name}' is deprecated. please use 'option {new}' if absolutely needed.")
    };
    let line = fe("").lines().position(|l| l.starts_with("backend")).unwrap() + 1; // the line after the frontend
    let mut cfg = fe("");
    cfg = cfg.replacen("backend b\n", "    option accept-invalid-http-request\nbackend b\n", 1);
    expect(&cfg, &dep("accept-invalid-http-request", "accept-unsafe-violations-in-http-request", line));
    // The response side, in a backend.
    let cfg = format!("{}    option accept-invalid-http-response\n", fe(""));
    let n = cfg.lines().count();
    // (Ibex also prints its own notice that the response option is not implemented.)
    let (text, flag, rc) = check(&cfg);
    let got: Vec<&str> = text.lines().filter(|l| l.starts_with("[WARNING]")).collect();
    assert_eq!(got, [dep("accept-invalid-http-response", "accept-unsafe-violations-in-http-response", n)], "{text}");
    assert!(flag);
    assert_eq!(rc, 0);
}

#[test]
fn accept_invalid_http_request_has_no_negation() {
    let cfg = fe("    no option accept-invalid-http-request\n");
    // (Ibex words the frame of this alert `parsing [F:5] :`, HAProxy `parsing [F:5]:`: T274 B.)
    let (text, _, rc) = check(&cfg);
    let alert = text.lines().find(|l| l.starts_with("[ALERT]")).unwrap_or("");
    assert!(alert.ends_with("negation/default is not supported for option 'accept-invalid-http-request'."), "{text}");
    assert_eq!(rc, 1);
}

/// The option acts: a `#` in the request target is a 400 without it and is served with it,
/// under either name (`accept-invalid-http-request` sets what the new name sets).
#[test]
fn accept_invalid_http_request_acts_on_the_request_parser() {
    use std::io::Read;
    if std::env::var("T273D_ORACLE").is_ok() {
        return;
    }
    let status = |option: &str| -> String {
        let addr = common::reserve_addr();
        let cfg = format!(
            "frontend f\n    bind {addr}\n    mode http\n{TIMEOUTS}{option}    http-request return status 200\n"
        );
        let mut f = NamedTempFile::new().expect("tmp");
        f.write_all(cfg.as_bytes()).expect("write");
        let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
            .arg("-f")
            .arg(f.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn");
        let _ibex = common::Ibex(child);
        assert!(common::wait_listening(addr), "ibex did not listen");
        let mut s = std::net::TcpStream::connect(addr).expect("connect");
        s.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        s.write_all(b"GET /a#b HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n").unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).lines().next().unwrap_or("").to_string()
    };
    assert_eq!(status(""), "HTTP/1.1 400 Bad request");
    assert_eq!(status("    option accept-unsafe-violations-in-http-request\n"), "HTTP/1.1 200 OK");
    assert_eq!(status("    option accept-invalid-http-request\n"), "HTTP/1.1 200 OK");
}

// ---------------------------------------------------------------------------------------------
// T274 G1: `default_backend` in a `defaults` section.

const DEF_BODY: &str = "    mode http\n    timeout client 1s\n    timeout server 1s\n    timeout connect 1s\n";
const BE_B: &str = "backend b\n    mode http\n    server s 127.0.0.1:1\n";

#[test]
fn defaults_default_backend_is_inherited_by_frontend_and_listen() {
    accepts(&format!("defaults\n{DEF_BODY}    default_backend b\nfrontend f\n    bind 127.0.0.1:18091\nfrontend f2\n    bind 127.0.0.1:18092\n{BE_B}"));
}

#[test]
fn defaults_default_backend_that_does_not_exist_fails_the_proxy_that_inherits_it() {
    refuses(
        &format!("defaults\n{DEF_BODY}    default_backend nosuch\nfrontend f\n    bind 127.0.0.1:18091\n{BE_B}"),
        &["Proxy 'f': unable to find required default_backend: 'nosuch'."],
    );
    // Overridden by the frontend's own: the inherited name is never looked up.
    accepts(&format!("defaults\n{DEF_BODY}    default_backend nosuch\nfrontend f\n    bind 127.0.0.1:18091\n    default_backend b\n{BE_B}"));
}

#[test]
fn defaults_default_backend_follows_named_defaults() {
    let cfg = format!(
        "defaults d1\n{DEF_BODY}    default_backend nosuch\ndefaults d2\n{DEF_BODY}frontend f from d1\n    bind 127.0.0.1:18091\nfrontend g from d2\n    bind 127.0.0.1:18092\n{BE_B}"
    );
    let (got, rc) = alerts(&cfg);
    assert_eq!(got, vec!["[ALERT]    (PID) : Proxy 'f': unable to find required default_backend: 'nosuch'.".to_string()]);
    assert_eq!(rc, 1);
    // `defaults d1 from d0` inherits it too.
    accepts(&format!("defaults d0\n{DEF_BODY}    default_backend b\ndefaults d1 from d0\nfrontend f from d1\n    bind 127.0.0.1:18091\n{BE_B}"));
    let cfg = format!("defaults d0\n{DEF_BODY}    default_backend nosuch\ndefaults d1 from d0\nfrontend f from d1\n    bind 127.0.0.1:18091\n{BE_B}");
    refuses(&cfg, &["Proxy 'f': unable to find required default_backend: 'nosuch'."]);
}

#[test]
fn defaults_default_backend_with_no_user_is_not_looked_up() {
    accepts(&format!("defaults\n{DEF_BODY}    default_backend nosuch\n{BE_B}"));
}

#[test]
fn defaults_default_backend_routes_requests() {
    if std::env::var("T273D_ORACLE").is_ok() {
        return;
    }
    let addr = common::reserve_addr();
    let cfg = format!(
        "defaults\n{DEF_BODY}    default_backend b\nfrontend f\n    bind {addr}\nbackend b\n    mode http\n    http-request return status 218\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn");
    let _ibex = common::Ibex(child);
    assert!(common::wait_listening(addr), "ibex did not listen");
    let mut s = std::net::TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = std::io::Read::read_to_end(&mut s, &mut out);
    assert_eq!(String::from_utf8_lossy(&out).lines().next().unwrap_or(""), "HTTP/1.1 218 Success");
}

// ---------------------------------------------------------------------------------------------
// T274 G3: references checked after the parse print as HAProxy prints them: no `config :
// parsing` frame; a tracking alert names its `server` line.

fn defaults_then(rest: &str) -> String {
    format!("defaults\n{DEF_BODY}{rest}")
}

#[test]
fn tracking_alerts_name_the_server_line_and_have_no_frame() {
    refuses(
        &defaults_then("backend b\n    server s 127.0.0.1:1 track nosuch/x\n"),
        &["[F:7] : 'server b/s' : unable to find required proxy 'nosuch' for tracking."],
    );
    refuses(
        &defaults_then("backend b\n    server s 127.0.0.1:1\n    server t 127.0.0.1:1 track s2\n"),
        &["[F:8] : 'server b/t' : unable to find required server 's2' for tracking."],
    );
    refuses(
        &defaults_then("backend b\n    server s 127.0.0.1:1\n    server t 127.0.0.1:1 track s\n"),
        &["[F:8] : 'server b/t' : unable to use b/s for tracking as it does not have any check nor agent enabled."],
    );
    refuses(
        &defaults_then("backend b\n    server s 127.0.0.1:1 track t\n    server t 127.0.0.1:1 track s\n"),
        &["[F:8] : 'server b/t' : unable to track b/s as it belongs to a tracking chain looping back to b/t."],
    );
}

#[test]
fn use_server_and_stick_table_alerts_have_no_frame() {
    refuses(
        &defaults_then("backend b\n    server s 127.0.0.1:1\n    use-server nosuch if TRUE\n"),
        &["backend 'b' : unable to find server 'nosuch' referenced in a 'use-server' rule."],
    );
    refuses(
        &defaults_then("listen l\n    bind 127.0.0.1:18091\n    server s 127.0.0.1:1\n    use-server nosuch if TRUE\n"),
        &["proxy 'l' : unable to find server 'nosuch' referenced in a 'use-server' rule."],
    );
    refuses(
        &defaults_then("backend b\n    stick-table type ip size 1k\n    stick on src table nosuch\n    server s 127.0.0.1:1\n"),
        &["Proxy 'b': unable to find stick-table 'nosuch'."],
    );
}

// T274 G2: Ibex does not validate response heads, so the option has nothing to relax and
// says so instead of "not implemented and is ignored" (docs/differences.md).
#[test]
fn accept_unsafe_violations_in_http_response_says_it_has_nothing_to_relax() {
    if std::env::var("T273D_ORACLE").is_ok() {
        return;
    }
    let (text, _, rc) = check_any(&defaults_then("backend b\n    option accept-unsafe-violations-in-http-response\n    server s 127.0.0.1:1\n"));
    assert_eq!(rc, 0);
    assert!(text.contains("nothing to relax") && !text.contains("not implemented"), "{text}");
}
