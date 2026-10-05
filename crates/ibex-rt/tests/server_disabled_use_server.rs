// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `server ... disabled`, `use-server` and `force-be-switch`.
//!
//! Every expectation was measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-04:
//!
//! * a server declared `disabled` starts in maintenance: `show stat` says `MAINT`, it takes
//!   no traffic under `roundrobin`, and `enable server` brings it back (`default-server
//!   disabled` is inherited, a server's own `enabled` undoes it);
//! * `disable server` shows `MAINT` as well;
//! * `use-server <srv> if|unless <cond>` picks the server whatever the algorithm says. The
//!   rules run in order and the first whose condition holds *and whose server is not
//!   stopped* (down or in maintenance) wins; a stopped server's rule is skipped for the
//!   next one, then for the algorithm. A draining server is still picked (`cur_state !=
//!   SRV_ST_STOPPED`);
//! * `force-be-switch if <cond>` lets `use_backend` pick a backend that is disabled, which
//!   then has no server: 503. Without it the rule is skipped and the next one applies.
//! * the parser: `use-server` and `force-be-switch` both require `if` or `unless`; a
//!   `use-server` naming no server of the backend fails the load; a frontend refuses
//!   `use-server` (it warns that it has no backend capability, keeps the rule, then fails
//!   the load on the missing server); `force-be-switch` is for frontends and listens only.
//!
//! Not implemented, so refused at load: a `use-server` whose name is a log-format
//! expression.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
    sock: PathBuf,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
    }
}

/// A server answering every request with `X-Server: <name>`.
fn server(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        buf.drain(..end + 4);
                        let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Server: {name}\r\n\r\nok");
                        if c.write_all(resp.as_bytes()).is_err() {
                            return;
                        }
                    }
                    match c.read(&mut chunk) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
            });
        }
    });
    addr
}

fn start(cfg: &str) -> (Ibex, SocketAddr) {
    let (ibex, fe, _) = start2(cfg);
    (ibex, fe)
}

/// `start`, with a second frontend address for `{fe2}`.
fn start2(cfg: &str) -> (Ibex, SocketAddr, SocketAddr) {
    let fe = common::reserve_addr();
    let fe2 = common::reserve_addr();
    let sock = std::env::temp_dir().join(format!("ibex_t121_{}_{}.sock", std::process::id(), fe.port()));
    let mut text = cfg
        .replace("{fe}", &fe.to_string())
        .replace("{fe2}", &fe2.to_string())
        .replace("{sock}", &sock.display().to_string());
    for name in ["s1", "s2", "s3"] {
        text = text.replace(&format!("{{{name}}}"), &server(name).to_string());
    }
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, _cfg: f, sock };
    assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}");
    if text.contains(&fe2.to_string()) {
        assert!(common::wait_listening(fe2), "ibex never listened on {fe2} with:\n{text}");
    }
    (ibex, fe, fe2)
}

fn cli(ibex: &Ibex, cmd: &str) -> String {
    let mut s = UnixStream::connect(&ibex.sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// The `status` column of `show stat` for `<px>,<sv>`.
fn status_of(ibex: &Ibex, px: &str, sv: &str) -> String {
    let stat = cli(ibex, "show stat");
    let mut lines = stat.lines();
    let header = lines.next().expect("a header").trim_start_matches("# ");
    let col = header.split(',').position(|c| c == "status").expect("a status column");
    lines
        .find(|l| l.starts_with(&format!("{px},{sv},")))
        .map_or_else(|| format!("<no {px}/{sv} in {stat:?}>"), |l| l.split(',').nth(col).unwrap_or("").to_string())
}

/// The answer to `GET /` with `headers`: the `X-Server` it carries, or its status line.
fn get(fe: SocketAddr, headers: &[&str]) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let extra: String = headers.iter().map(|h| format!("{h}\r\n")).collect();
    c.write_all(format!("GET / HTTP/1.1\r\nHost: x\r\n{extra}Connection: close\r\n\r\n").as_bytes()).expect("send");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    let text = String::from_utf8_lossy(&got).into_owned();
    text.split("\r\n")
        .find_map(|l| l.strip_prefix("X-Server: "))
        .map_or_else(|| text.lines().next().unwrap_or("<nothing>").to_string(), str::to_string)
}

fn gets(fe: SocketAddr, headers: &[&str], n: usize) -> Vec<String> {
    (0..n).map(|_| get(fe, headers)).collect()
}

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n";
const ADMIN: &str = "global\n  stats socket {sock} mode 600 level admin\n";

fn backend(rules: &str, servers: &str) -> String {
    format!(
        "{ADMIN}{DEFAULTS}frontend f\n  bind {{fe}}\n  default_backend b\nbackend b\n  balance roundrobin\n{rules}{servers}"
    )
}

#[test]
fn a_disabled_server_takes_no_traffic_until_enabled() {
    let (ibex, fe) = start(&backend("", "  server s1 {s1} disabled\n  server s2 {s2}\n"));
    assert_eq!(status_of(&ibex, "b", "s1"), "MAINT");
    assert!(gets(fe, &[], 6).iter().all(|s| s == "s2"), "a disabled server was used");

    cli(&ibex, "enable server b/s1");
    assert_ne!(status_of(&ibex, "b", "s1"), "MAINT");
    let got = gets(fe, &[], 6);
    assert!(got.contains(&"s1".to_string()) && got.contains(&"s2".to_string()), "{got:?}");
}

#[test]
fn without_disabled_the_server_takes_traffic() {
    let (ibex, fe) = start(&backend("", "  server s1 {s1}\n  server s2 {s2}\n"));
    assert_ne!(status_of(&ibex, "b", "s1"), "MAINT");
    let got = gets(fe, &[], 6);
    assert!(got.contains(&"s1".to_string()) && got.contains(&"s2".to_string()), "{got:?}");
}

#[test]
fn a_disabled_server_with_a_check_stays_in_maintenance() {
    // The check goes to a live listener: it passes, and must not bring the server back.
    let (ibex, fe) = start(&backend("", "  server s1 {s1} disabled check inter 100ms\n  server s2 {s2}\n"));
    thread::sleep(Duration::from_millis(600));
    assert_eq!(status_of(&ibex, "b", "s1"), "MAINT");
    assert!(gets(fe, &[], 4).iter().all(|s| s == "s2"));
}

#[test]
fn default_server_disabled_is_inherited_and_enabled_undoes_it() {
    let (ibex, fe) = start(&backend("", "  default-server disabled\n  server s1 {s1}\n  server s2 {s2} enabled\n"));
    assert_eq!(status_of(&ibex, "b", "s1"), "MAINT");
    assert_ne!(status_of(&ibex, "b", "s2"), "MAINT");
    assert!(gets(fe, &[], 4).iter().all(|s| s == "s2"));
}

#[test]
fn disable_server_puts_the_server_in_maintenance() {
    let (ibex, fe) = start(&backend("", "  server s1 {s1}\n  server s2 {s2}\n"));
    cli(&ibex, "disable server b/s1");
    assert_eq!(status_of(&ibex, "b", "s1"), "MAINT");
    assert!(gets(fe, &[], 4).iter().all(|s| s == "s2"));
}

#[test]
fn use_server_picks_the_server_whatever_the_algorithm_says() {
    let (_ibex, fe) = start(&backend(
        "  use-server s2 if { req.hdr(x-u) 2 }\n  use-server s1 if { req.hdr(x-u) 1 }\n",
        "  server s1 {s1}\n  server s2 {s2}\n",
    ));
    assert!(gets(fe, &["x-u: 2"], 6).iter().all(|s| s == "s2"));
    assert!(gets(fe, &["x-u: 1"], 6).iter().all(|s| s == "s1"));
    // The control: no rule matches, the algorithm spreads the requests.
    let got = gets(fe, &["x-u: 3"], 6);
    assert!(got.contains(&"s1".to_string()) && got.contains(&"s2".to_string()), "{got:?}");
}

#[test]
fn use_server_unless_and_rule_order() {
    let (_ibex, fe) = start(&backend(
        "  use-server s2 if { req.hdr(x-u) 2 }\n  use-server s1 if { req.hdr(x-u) 2 }\n  \
         use-server s1 unless { req.hdr(x-u) -m found }\n",
        "  server s1 {s1}\n  server s2 {s2}\n",
    ));
    assert!(gets(fe, &["x-u: 2"], 4).iter().all(|s| s == "s2"), "the first matching rule wins");
    assert!(gets(fe, &[], 4).iter().all(|s| s == "s1"), "unless");
}

#[test]
fn use_server_skips_a_stopped_server_for_the_next_rule_then_the_algorithm() {
    let (ibex, fe) = start(&backend(
        "  use-server s3 if { req.hdr(x-u) 3 }\n  use-server s2 if { req.hdr(x-u) 3 }\n  \
         use-server s1 if { req.hdr(x-u) 1 }\n",
        "  server s1 {s1}\n  server s2 {s2}\n  server s3 {s3} disabled\n",
    ));
    // s3 is in maintenance: the second rule applies.
    assert!(gets(fe, &["x-u: 3"], 4).iter().all(|s| s == "s2"));
    // s1 in maintenance: its rule is skipped and the algorithm finds the only server left.
    cli(&ibex, "disable server b/s1");
    assert!(gets(fe, &["x-u: 1"], 4).iter().all(|s| s == "s2"));
    cli(&ibex, "enable server b/s1");
    assert!(gets(fe, &["x-u: 1"], 4).iter().all(|s| s == "s1"));
    // Enabled, s3 takes its rule's requests.
    cli(&ibex, "enable server b/s3");
    assert!(gets(fe, &["x-u: 3"], 4).iter().all(|s| s == "s3"));
}

#[test]
fn use_server_still_picks_a_draining_server() {
    let (ibex, fe) = start(&backend(
        "  use-server s1 if { req.hdr(x-u) 1 }\n",
        "  server s1 {s1}\n  server s2 {s2}\n",
    ));
    cli(&ibex, "set server b/s1 state drain");
    assert!(gets(fe, &["x-u: 1"], 4).iter().all(|s| s == "s1"), "drain keeps use-server");
    // The control: the algorithm leaves a draining server alone.
    assert!(gets(fe, &["x-u: 9"], 4).iter().all(|s| s == "s2"));
}

#[test]
fn disabling_a_checked_server_keeps_it_in_maintenance() {
    let (ibex, fe) = start(&backend("", "  server s1 {s1} check inter 100ms\n  server s2 {s2}\n"));
    thread::sleep(Duration::from_millis(400));
    assert_ne!(status_of(&ibex, "b", "s1"), "MAINT");
    cli(&ibex, "disable server b/s1");
    thread::sleep(Duration::from_millis(400)); // several checks, all passing
    assert_eq!(status_of(&ibex, "b", "s1"), "MAINT");
    assert!(gets(fe, &[], 4).iter().all(|s| s == "s2"));
}

#[test]
fn set_server_state_maint_and_drain_are_not_down() {
    let (ibex, _fe) = start(&backend("", "  server s1 {s1}\n  server s2 {s2}\n"));
    cli(&ibex, "set server b/s1 state maint");
    assert_eq!(status_of(&ibex, "b", "s1"), "MAINT");
    cli(&ibex, "set server b/s1 state drain");
    assert_eq!(status_of(&ibex, "b", "s1"), "DRAIN");
    cli(&ibex, "set server b/s1 state ready");
    assert_ne!(status_of(&ibex, "b", "s1"), "DRAIN");
}

#[test]
fn use_server_in_tcp_mode_listen_and_backend() {
    let (_ibex, l, g) = start2(&format!(
        "{DEFAULTS}listen l\n  bind {{fe}}\n  mode tcp\n  balance roundrobin\n  use-server s2 if TRUE\n  \
         server s1 {{s1}}\n  server s2 {{s2}}\n\
         frontend g\n  bind {{fe2}}\n  mode tcp\n  default_backend tb\n\
         backend tb\n  mode tcp\n  balance roundrobin\n  use-server s2 if TRUE\n  \
         server s1 {{s1}}\n  server s2 {{s2}}\n"
    ));
    assert!(gets(l, &[], 4).iter().all(|s| s == "s2"), "listen");
    assert!(gets(g, &[], 4).iter().all(|s| s == "s2"), "frontend and backend");
}

#[test]
fn force_be_switch_in_tcp_mode_and_on_a_default_backend() {
    let (_ibex, g, l) = start2(&format!(
        "{DEFAULTS}frontend g\n  bind {{fe}}\n  mode tcp\n  force-be-switch if TRUE\n  use_backend offt if TRUE\n\
         listen l\n  bind {{fe2}}\n  force-be-switch if {{ req.hdr(x-force) 1 }}\n  default_backend off\n  \
         server s1 {{s1}}\n\
         backend off\n  disabled\n  server s2 {{s2}}\n\
         backend offt\n  mode tcp\n  disabled\n  server s2 {{s2}}\n"
    ));
    // The backend is disabled: nothing is answered.
    assert_eq!(get(g, &[]), "<nothing>");
    // A default backend that is disabled is skipped, the listen serves from its own server;
    // forced, the request goes to the disabled one, which has no server.
    assert_eq!(get(l, &[]), "s1");
    assert_eq!(get(l, &["x-force: 1"]), "HTTP/1.1 503 Service Unavailable");
}

#[test]
fn use_server_in_a_listen_section() {
    let (_ibex, fe) = start(&format!(
        "{DEFAULTS}listen l\n  bind {{fe}}\n  balance roundrobin\n  use-server s2 if {{ req.hdr(x-u) 2 }}\n  \
         server s1 {{s1}}\n  server s2 {{s2}}\n"
    ));
    assert!(gets(fe, &["x-u: 2"], 6).iter().all(|s| s == "s2"));
}

#[test]
fn force_be_switch_lets_use_backend_pick_a_disabled_backend() {
    let (_ibex, fe) = start(&format!(
        "{DEFAULTS}frontend f\n  bind {{fe}}\n  force-be-switch if {{ req.hdr(x-force) 1 }}\n  \
         use_backend off if {{ req.hdr(x-t) off }}\n  use_backend on if {{ req.hdr(x-t) on }}\n  default_backend dflt\n\
         backend off\n  disabled\n  server s2 {{s2}}\n\
         backend on\n  server s1 {{s1}}\n\
         backend dflt\n  server s3 {{s3}}\n"
    ));
    // A disabled backend is skipped, the next rule and the default backend apply.
    assert_eq!(get(fe, &["x-t: off"]), "s3");
    // Forced, the rule picks it, and it has no server to give.
    assert_eq!(get(fe, &["x-t: off", "x-force: 1"]), "HTTP/1.1 503 Service Unavailable");
    // The control: forcing changes nothing for a backend that is enabled.
    assert_eq!(get(fe, &["x-t: on", "x-force: 1"]), "s1");
    assert_eq!(get(fe, &["x-t: on"]), "s1");
}

/// `ibex -c -f`: (exit code, stdout + stderr).
fn check(i: usize, cfg: &str) -> (Option<i32>, String) {
    let p = std::env::temp_dir().join(format!("ibex_t121_{}_{i}.cfg", std::process::id()));
    std::fs::write(&p, cfg).expect("write config");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&p).output().expect("run ibex -c");
    let _ = std::fs::remove_file(&p);
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

#[test]
fn the_parser_checks_use_server_and_force_be_switch_as_haproxy_does() {
    // (frontend lines, backend lines, text the refusal must contain; "" = accepted)
    let cases: &[(&str, &str, &str)] = &[
        ("", "use-server s1", "'use-server' requires either 'if' or 'unless' followed by a condition."),
        ("", "use-server", "'use-server' expects a server name."),
        ("", "use-server s9 if TRUE", "backend 'b' : unable to find server 's9' referenced in a 'use-server' rule."),
        ("", "use-server s%[req.hdr(x)] if TRUE", "log-format server name is not implemented"),
        ("use-server s1 if TRUE", "", "frontend 'f' : unable to find server 's1' referenced in a 'use-server' rule."),
        ("force-be-switch", "", "'force-be-switch' requires either 'if' or 'unless' followed by a condition."),
        ("", "force-be-switch if TRUE", "force-be-switch"),
        ("force-be-switch if TRUE", "use-server s1 if TRUE", ""),
        ("", "use-server s1 unless FALSE", ""),
    ];
    for (i, (fe, be, want)) in cases.iter().enumerate() {
        let cfg = format!(
            "{DEFAULTS}frontend f\n  bind 127.0.0.1:1\n  {fe}\n  default_backend b\nbackend b\n  {be}\n  server s1 127.0.0.1:1\n"
        );
        let (code, out) = check(i, &cfg);
        if want.is_empty() {
            assert_eq!(code, Some(0), "case {i} {fe:?} {be:?} must load: {out}");
        } else {
            assert_ne!(code, Some(0), "case {i} {fe:?} {be:?} must be refused");
            assert!(out.contains(want), "case {i}: {out:?} must contain {want:?}");
        }
    }
}

#[test]
fn use_server_resolves_servers_declared_after_it_and_in_listens() {
    let ok = format!("{DEFAULTS}listen l\n  bind 127.0.0.1:1\n  use-server s2 if TRUE\n  server s1 127.0.0.1:1\n  server s2 127.0.0.1:2\n");
    assert_eq!(check(100, &ok).0, Some(0));
    let bad = ok.replace("use-server s2", "use-server s9");
    let (code, out) = check(101, &bad);
    assert_ne!(code, Some(0));
    assert!(out.contains("listen 'l' : unable to find server 's9' referenced in a 'use-server' rule."), "{out}");
}

/// `<op_state> <admin_state>` of a server in `show servers state b`.
fn state_of(ibex: &Ibex, sv: &str) -> String {
    let out = cli(ibex, "show servers state b");
    out.lines()
        .map(|l| l.split(' ').collect::<Vec<_>>())
        .find(|f| f.get(3) == Some(&sv))
        .map_or_else(|| format!("<no {sv} in {out:?}>"), |f| format!("{} {}", f[5], f[6]))
}

/// T146b item 6, measured on HAProxy 3.5-dev8-885761-29: a server the configuration
/// disables carries `SRV_ADMF_CMAINT` (4) as well as `FMAINT` (1), and the CLI never clears
/// the 4: `enable server` leaves 4, `disable server` goes back to 5. A server disabled over
/// the CLI has only 1.
#[test]
fn show_servers_state_admin_flags_of_a_config_disabled_server() {
    let (ibex, _fe) = start(&backend("", "  server s1 {s1} disabled\n  server s2 {s2}\n"));
    assert_eq!(state_of(&ibex, "s1"), "0 5");
    assert_eq!(state_of(&ibex, "s2"), "2 0");
    cli(&ibex, "enable server b/s1");
    assert_eq!(state_of(&ibex, "s1"), "2 4");
    cli(&ibex, "disable server b/s1");
    assert_eq!(state_of(&ibex, "s1"), "0 5");
    cli(&ibex, "disable server b/s2");
    assert_eq!(state_of(&ibex, "s2"), "0 1");
    cli(&ibex, "enable server b/s2");
    assert_eq!(state_of(&ibex, "s2"), "2 0");
}
