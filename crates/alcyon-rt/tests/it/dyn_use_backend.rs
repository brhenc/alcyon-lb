// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `use_backend` with a log-format name and `be-unpublished` (T637 slice DYNUSEBE).
//!
//! The specification is the reg-test `reg-tests/stream/test_content_switching.vtc`, which
//! passes on the oracle. Every expectation below was measured on it (3.5-dev11):
//!
//! * a `use_backend <log-format>` rule builds its name per request and looks the backend up
//!   by name (`process_switching_rules`, `src/stream.c`): a name that is no backend, a
//!   frontend, or nothing, ends the rules' loop and the fallback runs on the default
//!   backend -- the remaining rules are not tried, as `HAProxy` breaks the loop on a
//!   failed dynamic resolution;
//! * a name that is a disabled or an unpublished backend skips the rule for the next one,
//!   then for the `default_backend`, as a rule naming a backend the configuration
//!   disables; `force-be-switch` overrides the unpublished flag and runs the request in
//!   that backend, which has a server to give; it overrides the disabled flag too, into a
//!   backend with no server: 503;
//! * `be-unpublished` (a `backend` or a `listen`) starts the proxy with its `unpublished`
//!   flag set; `publish backend` and `unpublish backend` on the stats socket change it at
//!   run time ("Backend published." / "Backend unpublished."; "No such backend." for a
//!   name that is no backend, including a frontend's; "No effect on a disabled
//!   backend.");
//! * the parser refuses `be-unpublished` where `HAProxy` refuses it: "'be-unpublished'
//!   only available in backend or listen section." in a `frontend`, "'be-unpublished' not
//!   allowed in 'defaults' section." in a `defaults`.
//!
//! Set `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`: it passes all.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

struct Alcyon {
    child: Child,
    _cfg: NamedTempFile,
    sock: PathBuf,
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
    }
}

/// The proxy under test, with the four frontends, the `listen` and the stats socket the
/// rows below need. `{fe_dyn}`..`{li}` and `{sock}` are replaced.
const CFG: &str = "global\n  stats socket {sock} mode 600 level admin\n\
defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
frontend fe_dyn\n  bind {fe_dyn}\n  use_backend %[req.hdr(\"x-target\")]\n\
frontend fe_dyn_def\n  bind {fe_dyn_def}\n  use_backend %[req.hdr(\"x-target\")]\n  default_backend be_ok\n\
frontend fe_force\n  bind {fe_force}\n\
  force-be-switch if { req.hdr(\"x-force\") \"1\" }\n\
  use_backend %[req.hdr(\"x-target\")]\n  default_backend be_ok\n\
listen li\n  bind {li}\n  be-unpublished\n\
  use_backend %[req.hdr(\"x-target\")] if { req.hdr(\"x-dyn\") \"1\" }\n\
  server srv {li_srv}\n\
frontend fe2\n  bind {fe2}\n\
  force-be-switch if { req.hdr(\"x-force\") \"1\" }\n\
  use_backend %[req.hdr(\"x-target\")] if { req.hdr(\"x-dyn\") \"1\" }\n\
  use_backend be_unpublished if { req.hdr(\"x-target\") \"be_unpublished\" }\n\
  use_backend be_disabled if { req.hdr(\"x-target\") \"be_disabled\" }\n\
  use_backend be\n  use_backend be2\n  default_backend be_default\n\
backend be\n  http-request return status 200 hdr \"x-be\" %[be_name]\n\
backend be2\n  http-request return status 200 hdr \"x-be\" %[be_name]\n\
backend be_unpublished\n  be-unpublished\n  http-request return status 200 hdr \"x-be\" %[be_name]\n\
backend be_disabled\n  disabled\n  http-request return status 200 hdr \"x-be\" %[be_name]\n\
backend be_default\n  http-request return status 200 hdr \"x-be\" %[be_name]\n\
backend be_ok\n  http-request return status 200 hdr \"x-be\" %[be_name]\n";

fn start() -> (Alcyon, SocketAddr, SocketAddr, SocketAddr, SocketAddr, SocketAddr, SocketAddr) {
    let (fe_dyn, fe_dyn_def, fe_force, li, fe2, li_srv, sock_addr) = (
        common::reserve_addr(),
        common::reserve_addr(),
        common::reserve_addr(),
        common::reserve_addr(),
        common::reserve_addr(),
        common::reserve_addr(),
        common::reserve_addr(),
    );
    let sock = std::env::temp_dir().join(format!("alcyon_dynusebe_{}_{}.sock", std::process::id(), fe_dyn.port()));
    let mut text = CFG
        .replace("{fe_dyn}", &fe_dyn.to_string())
        .replace("{fe_dyn_def}", &fe_dyn_def.to_string())
        .replace("{fe_force}", &fe_force.to_string())
        .replace("{li}", &li.to_string())
        .replace("{fe2}", &fe2.to_string())
        .replace("{li_srv}", &li_srv.to_string())
        .replace("{sock}", &sock.display().to_string());
    let _ = sock_addr;
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let srv = li_server(li_srv);
    let child = common::alcyon_command(&bin)
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the proxy");
    let alcyon = Alcyon { child, _cfg: f, sock };
    for (i, a) in [fe_dyn, fe_dyn_def, fe_force, li, fe2, li_srv].into_iter().enumerate() {
        assert!(common::wait_listening(a), "no listener {i} of six, config:\n{text}");
    }
    drop(srv);
    (alcyon, fe_dyn, fe_dyn_def, fe_force, li, fe2, sock_addr)
}

/// The server the `listen` proxy keeps for itself: every request it answers with
/// `x-be: li`, so a request that stayed on the listen proxy is told where it ran.
fn li_server(addr: SocketAddr) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let l = std::net::TcpListener::bind(addr).expect("bind the listen proxy's server");
        for _ in 0..200 {
            let Ok((mut s, _)) = l.accept() else {
                continue;
            };
            let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
            let _ = s.set_write_timeout(Some(Duration::from_millis(500)));
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf);
            let body = "ok";
            let _ = s.write_all(format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nx-be: li\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes());
            let _ = s.shutdown(std::net::Shutdown::Write);
            let _ = s.read(&mut buf);
        }
    })
}

/// The stats-socket answer to `cmd`, read to the close of the command's reply.
fn cli(alcyon: &Alcyon, cmd: &str) -> String {
    let mut s = UnixStream::connect(&alcyon.sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// The answer to `GET /` with `headers`: its status line and the `x-be` header it carries.
fn get(fe: SocketAddr, headers: &[&str]) -> (String, Option<String>) {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let extra: String = headers.iter().map(|h| format!("{h}\r\n")).collect();
    c.write_all(format!("GET / HTTP/1.1\r\nHost: x\r\n{extra}Connection: close\r\n\r\n").as_bytes()).expect("send");
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") else {
            match c.read(&mut buf) {
                Ok(n) if n > 0 => got.extend_from_slice(&buf[..n]),
                _ => break,
            }
            continue;
        };
        let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
        let len = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        if got.len() >= end + 4 + len {
            break;
        }
        match c.read(&mut buf) {
            Ok(n) if n > 0 => got.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    let text = String::from_utf8_lossy(&got).into_owned();
    let status = text.lines().next().unwrap_or("<nothing>").to_string();
    let xbe = text
        .split("\r\n")
        .find_map(|l| l.split_once(": ").filter(|(n, _)| n.eq_ignore_ascii_case("x-be")))
        .map(|(_, v)| v.to_string());
    (status, xbe)
}

/// The assertion the rows share: a 200 carrying `x-be: <want>`.
fn expect_be(got: (String, Option<String>), want: &str, what: &str) {
    assert_eq!(got.0.split_whitespace().nth(1).unwrap_or(""), "200", "{what}: {got:?}");
    assert_eq!(got.1.as_deref(), Some(want), "{what}: {got:?}");
}

fn expect_503(got: (String, Option<String>), what: &str) {
    assert_eq!(got.0.split_whitespace().nth(1).unwrap_or(""), "503", "{what}: {got:?}");
}

#[test]
fn a_dynamic_rule_routes_by_the_built_name() {
    let (alcyon, fe_dyn, _fe_dyn_def, _fe_force, _li, _fe2, _sock) = start();
    expect_be(get(fe_dyn, &["x-target: be_ok"]), "be_ok", "the name a rule builds");
    expect_503(get(fe_dyn, &["x-target: no_such"]), "an unknown name, no default");
    // A name that is a frontend is no backend, on either proxy it is written in.
    expect_503(get(fe_dyn, &["x-target: fe_dyn"]), "the frontend's own name");
    expect_503(get(fe_dyn, &["x-target: fe_dyn_def"]), "the other frontend's name");
    drop(alcyon);
}

#[test]
fn a_dynamic_name_of_a_frontend_falls_to_the_default_backend() {
    let (alcyon, _fe_dyn, fe_dyn_def, _fe_force, _li, _fe2, _sock) = start();
    // A frontend is never a target: the rule failed to resolve, the default takes over.
    expect_be(get(fe_dyn_def, &["x-target: fe2"]), "be_ok", "a frontend's name");
    expect_be(get(fe_dyn_def, &["x-target: no_such"]), "be_ok", "an unknown name");
    drop(alcyon);
}

#[test]
fn a_conditional_dynamic_rule_falls_to_the_next_rule_then_the_default() {
    let (alcyon, _fe_dyn, _fe_dyn_def, _fe_force, _li, fe2, _sock) = start();
    expect_be(get(fe2, &["x-dyn: 1", "x-target: be"]), "be", "the dynamic rule matching");
    // The built name is no backend: the remaining rules are not tried (the unconditional
    // `use_backend be` would have matched), the default takes over.
    expect_be(get(fe2, &["x-dyn: 1", "x-target: no_such"]), "be_default", "an unknown dynamic name");
    // The rule does not match at all: the static rules run, as before this slice.
    expect_be(get(fe2, &["x-target: be"]), "be", "the static rule, no dynamic");
    drop(alcyon);
}

#[test]
fn a_dynamic_rule_skips_a_disabled_or_unpublished_backend() {
    let (alcyon, _fe_dyn, _fe_dyn_def, _fe_force, _li, fe2, _sock) = start();
    // The built name is a backend the configuration disabled: the rule is skipped for the
    // next one, `use_backend be`.
    expect_be(get(fe2, &["x-dyn: 1", "x-target: be_disabled"]), "be", "the disabled backend");
    // The same for one that `be-unpublished` started unpublished: the dynamic rule and the
    // static one naming it are both skipped, `use_backend be` applies.
    expect_be(get(fe2, &["x-dyn: 1", "x-target: be_unpublished"]), "be", "the unpublished backend, dynamic");
    expect_be(get(fe2, &["x-target: be_unpublished"]), "be", "the unpublished backend, static rule");
    drop(alcyon);
}

#[test]
fn force_be_switch_overrides_the_unpublished_flag() {
    let (alcyon, _fe_dyn, _fe_dyn_def, fe_force, _li, fe2, _sock) = start();
    // Unpublished, forced: the request runs in the backend, which has a server to give.
    expect_be(get(fe2, &["x-force: 1", "x-target: be_unpublished"]), "be_unpublished", "a forced static rule");
    expect_be(get(fe2, &["x-force: 1", "x-dyn: 1", "x-target: be_unpublished"]), "be_unpublished", "a forced dynamic rule");
    // Disabled, forced: the backend has no server: 503.
    expect_503(get(fe2, &["x-force: 1", "x-dyn: 1", "x-target: be_disabled"]), "a forced dynamic rule to the disabled backend");
    expect_503(get(fe_force, &["x-force: 1", "x-target: be_disabled"]), "a forced dynamic rule, dedicated frontend");
    expect_be(get(fe_force, &["x-force: 1", "x-target: be_unpublished"]), "be_unpublished", "a forced dynamic rule, dedicated frontend");
    drop(alcyon);
}

#[test]
fn an_unknown_dynamic_name_with_force_falls_to_the_default() {
    let (alcyon, _fe_dyn, _fe_dyn_def, fe_force, _li, _fe2, _sock) = start();
    // The dynamic rule failed to resolve; `force-be-switch` cannot make a name that is no
    // backend: the eligible default takes over.
    expect_be(get(fe_force, &["x-force: 1", "x-target: no_such"]), "be_ok", "the eligible default");
    drop(alcyon);
}

#[test]
fn unpublish_and_publish_backend_move_the_flag_at_run_time() {
    let (alcyon, _fe_dyn, _fe_dyn_def, _fe_force, _li, fe2, _sock) = start();
    // The names `HAProxy` refuses, with its texts.
    assert!(cli(&alcyon, "unpublish backend no_such").contains("No such backend."), "unknown name");
    assert!(cli(&alcyon, "unpublish backend fe_dyn").contains("No such backend."), "a frontend's name");
    assert!(cli(&alcyon, "unpublish backend be_disabled").contains("No effect on a disabled backend."), "a disabled backend");
    // No name at all: the same refusal, on both commands.
    assert!(cli(&alcyon, "unpublish backend").contains("No such backend."), "no name at all");
    assert!(cli(&alcyon, "publish backend").contains("No such backend."), "no name at all, publish");
    // A listen names, like a backend.
    assert!(cli(&alcyon, "unpublish backend li").contains("Backend unpublished."), "a listen names too");
    assert!(cli(&alcyon, "publish backend li").contains("Backend published."), "a listen names too, back");

    assert!(cli(&alcyon, "unpublish backend be").contains("Backend unpublished."), "unpublish be");
    expect_be(get(fe2, &[]), "be2", "a static rule on the unpublished backend skips to the next");
    expect_be(get(fe2, &["x-dyn: 1", "x-target: be"]), "be2", "the dynamic rule on it skips to the next");
    expect_be(get(fe2, &["x-force: 1"]), "be", "force-be-switch overrides it, static");
    expect_be(get(fe2, &["x-force: 1", "x-dyn: 1", "x-target: be"]), "be", "force-be-switch overrides it, dynamic");

    assert!(cli(&alcyon, "publish backend be").contains("Backend published."), "publish be");
    expect_be(get(fe2, &["x-target: be"]), "be", "the static rule matches again");
    expect_be(get(fe2, &["x-dyn: 1", "x-target: be"]), "be", "the dynamic rule matches again");
    drop(alcyon);
}

#[test]
// The `be-unpublished` the listen holds at load: a dynamic name that builds it is
// skipped like a backend's, the default runs; `force-be-switch` runs the request in
// the listen anyway, in its own server.
fn a_listen_be_unpublished_starts_unpublished_and_forces_in() {
    let (alcyon, _fe_dyn, fe_dyn_def, fe_force, _li, _fe2, _sock) = start();
    expect_be(get(fe_dyn_def, &["x-target: li"]), "be_ok", "a dynamic name that builds the unpublished listen");
    expect_be(
        get(fe_force, &["x-force: 1", "x-target: li"]),
        "li",
        "the same with force-be-switch: it runs in the listen",
    );
    drop(alcyon);
}

#[test]
fn a_listen_proxy_switches_by_dynamic_name_and_stays_put() {
    let (alcyon, _fe_dyn, _fe_dyn_def, _fe_force, li, _fe2, _sock) = start();
    expect_be(get(li, &["x-dyn: 1", "x-target: be"]), "be", "the dynamic rule of the listen");
    // No default of its own: the request stays on the listen proxy.
    expect_be(get(li, &["x-dyn: 1", "x-target: no_such"]), "li", "the listen keeps the request");
    drop(alcyon);
}

/// A configuration that starts, then the assertion that the proxy refused the load.
fn refused_load(cfg: &str, needle: &str) {
    let fe = common::reserve_addr();
    let sock = std::env::temp_dir().join(format!("alcyon_dynusebe_ref_{}_{}.sock", std::process::id(), fe.port()));
    let text = cfg
        .replace("{fe}", &fe.to_string())
        .replace("{sock}", &sock.display().to_string());
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let mut child = common::alcyon_command(&bin)
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the proxy");
    let status = child.wait().expect("wait");
    let _ = common::stop(&mut child);
    assert!(!status.success(), "the load succeeded where {needle:?} was expected:\n{text}");
    let out = Command::new(&bin)
        .args(["-c", "-f", f.path().to_str().unwrap()])
        .output()
        .expect("re-run with -c");
    let all = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(all.contains(needle), "no {needle:?} in:\n{all}\nconfig:\n{text}");
    let _ = std::fs::remove_file(&sock);
}

#[test]
fn be_unpublished_is_refused_where_haproxy_refuses_it() {
    let base = "global\n  stats socket {sock} mode 600 level admin\n\
defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n";
    refused_load(
        &format!("{base}frontend fe\n  bind {{fe}}\n  be-unpublished\n  server s 127.0.0.1:1\n"),
        "only available in backend or listen section",
    );
    refused_load(
        &format!("{base}defaults\n  be-unpublished\nbackend b\n  server s 127.0.0.1:1\n"),
        "not allowed in 'defaults' section",
    );
}
