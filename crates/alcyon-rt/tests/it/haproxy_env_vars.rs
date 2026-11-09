// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `HAPROXY_*` variables a configuration can read (T431). Measured on HAProxy 3.5-dev8
//! with `.notice "${HAPROXY_X-UNSET}"` under `-c`, and `show env` on a running process:
//! BRANCH `3.5`; STARTUP_VERSION what `-v` prints; CFGFILES the files as given, joined by `;`
//! (the whole list, from the first file on); the log format variables hold the default
//! formats while the configuration is parsed, and the five HTTP/TCP ones are unset after it,
//! so children do not inherit them (BRANCH, CFGFILES and the two KEYLOG ones stay set).
//! Alcyon runs as a child process: the variables are set in its own process.

use crate::common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::Duration;

const HTTP: &str = "%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r";
const HTTP_CLF: &str = "%{+Q}o %{-Q}ci - - [%trg] %r %ST %B \"\" \"\" %cp %ms %ft %b %s %TR %Tw %Tc %Tr %Ta %tsc %ac %fc %bc %sc %rc %sq %bq %CC %CS %hrl %hsl";
const HTTPS: &str = "%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r %[fc_err]/%[ssl_fc_err,hex]/%[ssl_c_err]/%[ssl_c_ca_err]/%[ssl_fc_is_resumed] %[ssl_fc_sni]/%sslv/%sslc";
const TCP: &str = "%ci:%cp [%t] %ft %b/%s %Tw/%Tc/%Tt %B %ts %ac/%fc/%bc/%sc/%rc %sq/%bq";
const TCP_CLF: &str = "%{+Q}o %{-Q}ci - - [%T] \"TCP \" 000 %B \"\" \"\" %cp %ms %ft %b %s %Th %Tw %Tc %Tt %U %ts-- %ac %fc %bc %sc %rc %sq %bq \"\" \"\" ";

fn keylog(side: &str) -> String {
    // HAProxy's backend format has two spaces after the first %[..,hex] (log.c keylog_format_bc).
    let sep = if side == "bc" { "  " } else { " " };
    format!(
        "CLIENT_RANDOM %[ssl_{side}_client_random,hex]{sep}%[ssl_{side}_session_key,hex]\n\
         CLIENT_EARLY_TRAFFIC_SECRET %[ssl_{side}_client_random,hex] %[ssl_{side}_client_early_traffic_secret]\n\
         CLIENT_HANDSHAKE_TRAFFIC_SECRET %[ssl_{side}_client_random,hex] %[ssl_{side}_client_handshake_traffic_secret]\n\
         SERVER_HANDSHAKE_TRAFFIC_SECRET %[ssl_{side}_client_random,hex] %[ssl_{side}_server_handshake_traffic_secret]\n\
         CLIENT_TRAFFIC_SECRET_0 %[ssl_{side}_client_random,hex] %[ssl_{side}_client_traffic_secret_0]\n\
         SERVER_TRAFFIC_SECRET_0 %[ssl_{side}_client_random,hex] %[ssl_{side}_server_traffic_secret_0]\n\
         EXPORTER_SECRET %[ssl_{side}_client_random,hex] %[ssl_{side}_exporter_secret]\n\
         EARLY_EXPORTER_SECRET %[ssl_{side}_client_random,hex] %[ssl_{side}_early_exporter_secret]"
    )
}

#[test]
fn the_variables_hold_the_oracles_values_while_the_configuration_is_parsed() {
    let dir = tempfile::tempdir().expect("tmp dir");
    let a = dir.path().join("a.cfg");
    let b = dir.path().join("b.cfg");
    let vars = [
        "HAPROXY_BRANCH",
        "HAPROXY_STARTUP_VERSION",
        "HAPROXY_CFGFILES",
        "HAPROXY_HTTP_LOG_FMT",
        "HAPROXY_HTTP_CLF_LOG_FMT",
        "HAPROXY_HTTPS_LOG_FMT",
        "HAPROXY_TCP_LOG_FMT",
        "HAPROXY_TCP_CLF_LOG_FMT",
        "HAPROXY_KEYLOG_FC_LOG_FMT",
        "HAPROXY_KEYLOG_BC_LOG_FMT",
    ];
    let mut text = String::from("global\n");
    for v in vars {
        text.push_str(&format!("  .notice \"{v}=${{{v}-UNSET}}\"\n"));
    }
    std::fs::write(&a, &text).expect("write a");
    std::fs::write(&b, "global\n  .notice \"B2=${HAPROXY_CFGFILES-UNSET}\"\n").expect("write b");
    // Inherited values must be replaced, as HAProxy's setenv(.., 1) does.
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .env("HAPROXY_BRANCH", "inherited")
        .env("HAPROXY_HTTP_LOG_FMT", "inherited")
        .args(["-c", "-f"])
        .arg(&a)
        .arg("-f")
        .arg(&b)
        .output()
        .expect("run alcyon -c");
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    let files = format!("{};{}", a.display(), b.display());
    let want = [
        ("HAPROXY_BRANCH", "3.5".to_string()),
        ("HAPROXY_STARTUP_VERSION", alcyon_rt::version::VERSION.to_string()),
        ("HAPROXY_CFGFILES", files.clone()),
        ("HAPROXY_HTTP_LOG_FMT", HTTP.to_string()),
        ("HAPROXY_HTTP_CLF_LOG_FMT", HTTP_CLF.to_string()),
        ("HAPROXY_HTTPS_LOG_FMT", HTTPS.to_string()),
        ("HAPROXY_TCP_LOG_FMT", TCP.to_string()),
        ("HAPROXY_TCP_CLF_LOG_FMT", TCP_CLF.to_string()),
        ("HAPROXY_KEYLOG_FC_LOG_FMT", keylog("fc")),
        ("HAPROXY_KEYLOG_BC_LOG_FMT", keylog("bc")),
        ("B2", files),
    ];
    for (name, value) in want {
        let line = format!("'{name}={value}'.");
        assert!(err.contains(&line), "{name}: expected `{line}` in\n{err}");
    }
}

fn ask(sock: &std::path::Path, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect cli");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// HAProxy unsets the five HTTP/TCP log format variables after the parse (`show env` on the
/// running process lacks them); BRANCH, CFGFILES, STARTUP_VERSION and the KEYLOG ones stay.
#[test]
fn the_log_format_variables_are_unset_after_the_parse() {
    let dir = tempfile::tempdir().expect("tmp dir");
    let sock = dir.path().join("cli.sock");
    let fe = common::reserve_addr();
    let cfg = dir.path().join("alcyon.cfg");
    std::fs::write(&cfg, format!("global\n  stats socket {} level admin\nfrontend f\n  mode tcp\n  bind {fe}\n", sock.display())).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Alcyon)
        .expect("spawn alcyon");
    assert!(common::wait_listening(fe), "alcyon never listened on {fe}");
    let env = ask(&sock, "show env");
    let names: Vec<&str> = env.lines().filter_map(|l| l.split_once('=')).map(|(k, _)| k).filter(|k| k.starts_with("HAPROXY_")).collect();
    for gone in ["HAPROXY_HTTP_LOG_FMT", "HAPROXY_HTTP_CLF_LOG_FMT", "HAPROXY_HTTPS_LOG_FMT", "HAPROXY_TCP_LOG_FMT", "HAPROXY_TCP_CLF_LOG_FMT"] {
        assert!(!names.contains(&gone), "{gone} is still set: {names:?}");
    }
    for kept in ["HAPROXY_BRANCH", "HAPROXY_CFGFILES", "HAPROXY_STARTUP_VERSION", "HAPROXY_KEYLOG_FC_LOG_FMT", "HAPROXY_KEYLOG_BC_LOG_FMT"] {
        assert!(names.contains(&kept), "{kept} is not set: {names:?}");
    }
    common::stop(&mut child);
}
