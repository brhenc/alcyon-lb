// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `set server <b>/<s> weight|addr|port|state` and `set weight`, `get weight` (T133).
//!
//! Every expectation was measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-04, with a
//! `stats socket` in the configuration:
//!
//! * `set server weight <n>` / `set weight <n>` change the weight (`uweight`), never the
//!   initial one: `get weight` answers `<n> (initial <i>)`. `<n>%` is a share of the
//!   initial weight, truncated; an absolute weight is 0..=256;
//! * `set server addr <ip> [port <p>]` moves the server and answers what changed
//!   (`IP changed from 'a' to 'b', port changed from 'x' to 'y' by 'stats socket command'`,
//!   `nothing changed`); there is no `set server ... port`;
//! * `show servers state` carries the admin state (maint 1, drain 8), the operational state
//!   (maint 0, drain 2) and the weights.
//! * a successful command with nothing to say answers one empty line.

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
    // A counter, not the port: `reserve_addr` can hand the same port to two concurrent tests.
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let sock = std::env::temp_dir().join(format!("ibex_t133_{}_{n}.sock", std::process::id()));
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
    // The stats socket is bound after the frontends are listening.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !ibex.sock.exists() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
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


const ADMIN: &str = "global\n  stats socket {sock} mode 600 level admin\n";
const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n";

fn conf(servers: &str) -> String {
    format!("{ADMIN}{DEFAULTS}frontend f\n  bind {{fe}}\n  default_backend b\nbackend b\n  balance roundrobin\n{servers}")
}

/// The `show servers state b` line of server `sv`, split into fields.
fn state_of(ibex: &Ibex, sv: &str) -> Vec<String> {
    let out = cli(ibex, "show servers state b");
    out.lines()
        .find(|l| l.split(' ').nth(3) == Some(sv))
        .map_or_else(|| panic!("no {sv} in {out:?}"), |l| l.split(' ').map(str::to_string).collect())
}

// Fields of `show servers state`: 4 addr, 5 op_state, 6 admin_state, 7 uweight, 8 iweight, 18 port.

#[test]
fn set_server_weight_changes_the_weight_and_the_balancing() {
    let (ibex, fe) = start(&conf("  server s1 {s1} weight 5\n  server s2 {s2}\n"));
    let st = state_of(&ibex, "s1");
    assert_eq!((st[7].as_str(), st[8].as_str()), ("5", "5"));

    assert_eq!(cli(&ibex, "set server b/s1 weight 10"), "\n");
    let st = state_of(&ibex, "s1");
    assert_eq!((st[7].as_str(), st[8].as_str()), ("10", "5"), "{st:?}");
    assert_eq!(cli(&ibex, "get weight b/s1"), "10 (initial 5)\n\n");

    assert_eq!(cli(&ibex, "set server b/s1 weight 0"), "\n");
    assert_eq!(cli(&ibex, "get weight b/s1"), "0 (initial 5)\n\n");
    assert!(gets(fe, &[], 6).iter().all(|s| s == "s2"), "a server of weight 0 was used");

    assert_eq!(cli(&ibex, "set server b/s1 weight 50%"), "\n");
    assert_eq!(cli(&ibex, "get weight b/s1"), "2 (initial 5)\n\n");
    assert_eq!(cli(&ibex, "set server b/s1 weight 150%"), "\n");
    assert_eq!(cli(&ibex, "get weight b/s1"), "7 (initial 5)\n\n");
    let got = gets(fe, &[], 8);
    assert!(got.contains(&"s1".to_string()) && got.contains(&"s2".to_string()), "{got:?}");
}

#[test]
fn set_weight_keeps_the_initial_weight() {
    let (ibex, _fe) = start(&conf("  server s1 {s1}\n"));
    assert_eq!(cli(&ibex, "set weight b/s1 7"), "\n");
    assert_eq!(cli(&ibex, "get weight b/s1"), "7 (initial 1)\n\n");
    assert_eq!(cli(&ibex, "set weight b/s1 300%"), "\n");
    assert_eq!(cli(&ibex, "get weight b/s1"), "3 (initial 1)\n\n");
}

#[test]
fn weight_errors_are_answered() {
    let (ibex, _fe) = start(&conf("  server s1 {s1}\n"));
    for (cmd, want) in [
        ("set server b/s1 weight 300", "Absolute weight can only be between 0 and 256 inclusive.\n\n"),
        ("set server b/s1 weight abc", "Empty weight string empty or preceded by garbage\n\n"),
        ("set server b/s1 weight 5abc", "Trailing garbage in weight string\n\n"),
        ("set server b/s1 weight", "Require <weight> or <weight%>.\n\n"),
        ("set weight b/s1", "Require <weight> or <weight%>.\n\n"),
        ("set weight b/s1 300", "Absolute weight can only be between 0 and 256 inclusive.\n\n"),
        ("set weight", "Require 'backend/server'.\n\n"),
        ("set weight s1 3", "Require 'backend/server'.\n\n"),
        ("set weight nobe/s1 3", "No such backend.\n\n"),
        ("set weight b/zz 3", "No such server.\n\n"),
        ("set server nobe/s1 state maint", "No such backend.\n\n"),
        ("set server b/zz state maint", "No such server.\n\n"),
        ("set server b", "Require 'backend/server'.\n\n"),
        ("set server b/s1 state bogus", "'set server <srv> state' expects 'ready', 'drain' and 'maint'.\n\n"),
        ("set server b/s1 foo", "usage: set server <backend>/<server> addr | agent | agent-addr | agent-port | agent-send | check-addr | check-port | fqdn | health | name | ssl | state | weight\n\n"),
        ("get weight b/zz", "No such server.\n\n"),
    ] {
        assert_eq!(cli(&ibex, cmd), want, "{cmd}");
    }
    assert_eq!(cli(&ibex, "get weight b/s1"), "1 (initial 1)\n\n");
}

#[test]
fn set_server_addr_moves_the_server() {
    let s2 = server("s2");
    let (ibex, fe) = start(&conf("  server s1 {s1}\n"));
    assert_eq!(get(fe, &[]), "s1");
    let old = state_of(&ibex, "s1")[18].clone();
    let port = s2.port();
    assert_eq!(
        cli(&ibex, &format!("set server b/s1 addr 127.0.0.1 port {port}")),
        format!("port changed from '{old}' to '{port}' by 'stats socket command'\n\n")
    );
    assert_eq!(state_of(&ibex, "s1")[18], port.to_string());
    assert_eq!(get(fe, &[]), "s2", "the server did not move");
    assert_eq!(cli(&ibex, &format!("set server b/s1 addr 127.0.0.1 port {port}")), "nothing changed\n\n");
    assert_eq!(
        cli(&ibex, &format!("set server b/s1 addr 127.0.0.2 port {port}")),
        "IP changed from '127.0.0.1' to '127.0.0.2' by 'stats socket command'\n\n"
    );
    assert_eq!(state_of(&ibex, "s1")[4], "127.0.0.2");
    assert_eq!(
        cli(&ibex, "set server b/s1 addr 127.0.0.1 port 7"),
        format!("IP changed from '127.0.0.2' to '127.0.0.1', port changed from '{port}' to '7' by 'stats socket command'\n\n")
    );
}

#[test]
fn set_server_addr_errors_are_answered() {
    let (ibex, _fe) = start(&conf("  server s1 {s1}\n"));
    for (cmd, want) in [
        ("set server b/s1 addr nohost.invalid", "Invalid addr 'nohost.invalid'\n\n"),
        ("set server b/s1 addr 127.0.0.2:8000", "Invalid addr '127.0.0.2:8000'\n\n"),
        ("set server b/s1 addr", "set server <b>/<s> addr requires an address and optionally a port.\n\n"),
        ("set server b/s1 addr 127.0.0.1 port abc", "problem converting port 'abc' to an int\n\n"),
        ("set server b/s1 port 8000", "usage: set server <backend>/<server> addr | agent | agent-addr | agent-port | agent-send | check-addr | check-port | fqdn | health | name | ssl | state | weight\n\n"),
    ] {
        assert_eq!(cli(&ibex, cmd), want, "{cmd}");
    }
}

#[test]
fn set_server_state_shows_in_show_servers_state_and_show_stat() {
    let (ibex, fe) = start(&conf("  server s1 {s1}\n  server s2 {s2}\n"));
    let st = state_of(&ibex, "s1");
    assert_eq!((st[5].as_str(), st[6].as_str()), ("2", "0"));

    assert_eq!(cli(&ibex, "set server b/s1 state maint"), "\n");
    let st = state_of(&ibex, "s1");
    assert_eq!((st[5].as_str(), st[6].as_str()), ("0", "1"), "{st:?}");
    assert_eq!(status_of(&ibex, "b", "s1"), "MAINT");
    assert!(gets(fe, &[], 4).iter().all(|s| s == "s2"));

    assert_eq!(cli(&ibex, "set server b/s1 state drain"), "\n");
    let st = state_of(&ibex, "s1");
    assert_eq!((st[5].as_str(), st[6].as_str()), ("2", "8"), "{st:?}");
    assert_eq!(status_of(&ibex, "b", "s1"), "DRAIN");

    assert_eq!(cli(&ibex, "set server b/s1 state ready"), "\n");
    let st = state_of(&ibex, "s1");
    assert_eq!((st[5].as_str(), st[6].as_str()), ("2", "0"), "{st:?}");
}

#[test]
fn unknown_commands_still_say_so() {
    let (ibex, _fe) = start(&conf("  server s1 {s1}\n"));
    assert_eq!(
        cli(&ibex, "frobnicate"),
        "Unknown command. Please enter 'help' for a list of valid commands.\n\n".replace("\n\n", "\n")
    );
}

fn conf_level(level: &str) -> String {
    conf("  server s1 {s1}\n").replace("level admin", &format!("level {level}"))
}

#[test]
fn show_cli_level_and_dropping_it() {
    let (ibex, _fe) = start(&conf("  server s1 {s1}\n"));
    assert_eq!(cli(&ibex, "show cli level"), "admin\n\n");
    assert_eq!(cli(&ibex, "operator; show cli level"), "\noperator\n\n");
    assert_eq!(cli(&ibex, "user; show cli level"), "\nuser\n\n");
    // The levels only go down.
    assert_eq!(cli(&ibex, "operator; user; show cli level"), "\n\nuser\n\n");
    assert_eq!(cli(&ibex, "user; operator; show cli level"), "\nPermission denied\n\nuser\n\n");
}

#[test]
fn a_lower_level_is_refused_what_needs_more() {
    let (ibex, _fe) = start(&conf("  server s1 {s1}\n"));
    for (cmd, want) in [
        ("operator; set weight b/s1 3", "\nPermission denied\n\n"),
        ("user; set weight b/s1 3", "\nPermission denied\n\n"),
        ("operator; disable server b/s1", "\nPermission denied\n\n"),
        ("user; get weight b/s1", "\nPermission denied\n\n"),
        ("user; show env HOME", "\nPermission denied\n\n"),
        ("user; clear counters", "\nPermission denied\n\n"),
        ("operator; clear counters all", "\nPermission denied\n\n"),
    ] {
        assert_eq!(cli(&ibex, cmd), want, "{cmd}");
    }
    assert_eq!(cli(&ibex, "get weight b/s1"), "1 (initial 1)\n\n", "a refused command changed something");
    assert_eq!(cli(&ibex, "operator; get weight b/s1"), "\n1 (initial 1)\n\n");
    assert!(cli(&ibex, "user; show info").contains("Name: "));
}

#[test]
fn the_socket_level_is_where_connections_start() {
    let (ibex, _fe) = start(&conf_level("operator"));
    assert_eq!(cli(&ibex, "show cli level"), "operator\n\n");
    assert_eq!(cli(&ibex, "set weight b/s1 3"), "Permission denied\n\n");
    assert_eq!(cli(&ibex, "operator; show cli level"), "\noperator\n\n");
    let (ibex, _fe) = start(&conf_level("user"));
    assert_eq!(cli(&ibex, "show cli level"), "user\n\n");
}

#[test]
fn an_unknown_socket_level_is_refused() {
    let cfg = "global\n  stats socket /tmp/x.sock level foo\nbackend b\n  server s 127.0.0.1:1\n";
    let err = ibex_config::parse_str(cfg).expect_err("a socket level of foo must not load");
    assert!(err.message.contains("'level' only supports 'user', 'operator', and 'admin' (got 'foo')"), "{}", err.message);
}

#[test]
fn show_version_and_show_cli_sockets() {
    let (ibex, _fe) = start(&conf("  server s1 {s1}\n"));
    let v = cli(&ibex, "show version");
    assert!(v.chars().next().is_some_and(|c| c.is_ascii_digit()) && v.ends_with("\n\n"), "{v:?}");
    let s = cli(&ibex, "show cli sockets");
    assert!(s.starts_with("# socket lvl processes\nunix@") && s.contains(" admin all\n"), "{s:?}");
}

#[test]
fn the_rest_of_the_set_server_surface() {
    let (ibex, _fe) = start(&conf("  server s1 {s1}\n"));
    assert_eq!(cli(&ibex, "set server"), "Require 'backend/server'.\n\n");
    assert_eq!(cli(&ibex, "set server b/s1 weight -5%"), "Relative weight must be positive.\n\n");
    assert_eq!(cli(&ibex, "set server b/s1 weight -"), "Empty weight string empty or preceded by garbage\n\n");
    assert_eq!(cli(&ibex, "set server b/s1 weight 1000000%"), "\n");
    assert_eq!(cli(&ibex, "get weight b/s1"), "256 (initial 1)\n\n");
    assert!(cli(&ibex, "set server b/s1 maxconn 7").starts_with("usage: set server "));
    assert_eq!(cli(&ibex, "set maxconn server b/s1 7"), "\n");
    assert_eq!(cli(&ibex, "set maxconn server b/zz 7"), "No such server.\n\n");
    assert_eq!(cli(&ibex, "set maxconn server nob/s1 7"), "No such backend.\n\n");
    assert_eq!(cli(&ibex, "set maxconn server b/s1 x"), "maxconn string empty or preceded by garbage\n\n");
    assert_eq!(cli(&ibex, "set maxconn server b/s1"), "Require <maxconn>.\n\n");
    assert_eq!(cli(&ibex, "set maxconn server b"), "Require 'backend/server'.\n\n");
    assert_eq!(cli(&ibex, "set maxconn frontend f 12"), "\n");
    assert_eq!(cli(&ibex, "set maxconn frontend nof 12"), "No such frontend.\n\n");
    let stat = cli(&ibex, "show stat");
    let header = stat.lines().next().expect("header").trim_start_matches("# ");
    let col = header.split(',').position(|c| c == "slim").expect("slim");
    let row = stat.lines().find(|l| l.starts_with("b,s1,")).expect("row");
    assert_eq!(row.split(',').nth(col), Some("7"), "{row}");
    // A port is its low 16 bits.
    let old = state_of(&ibex, "s1")[18].clone();
    assert_eq!(
        cli(&ibex, "set server b/s1 addr 127.0.0.1 port 70000"),
        format!("port changed from '{old}' to '4464' by 'stats socket command'\n\n")
    );
}

#[test]
fn a_level_name_is_parsed_to_a_level() {
    use ibex_rt::applet::CliLevel;
    assert_eq!(CliLevel::parse("user"), Some(CliLevel::User));
    assert_eq!(CliLevel::parse("operator"), Some(CliLevel::Operator));
    assert_eq!(CliLevel::parse("admin"), Some(CliLevel::Admin));
    assert_eq!(CliLevel::parse("root"), None);
}

#[test]
fn a_checked_server_follows_state_and_address_changes() {
    let s2 = server("s2");
    let (ibex, _fe) = start(&conf("  server s1 {s1} check inter 10s\n"));
    assert_eq!(cli(&ibex, "set server b/s1 state maint"), "\n");
    assert_eq!(status_of(&ibex, "b", "s1"), "MAINT");
    let port = s2.port();
    let old = state_of(&ibex, "s1")[18].clone();
    assert_eq!(
        cli(&ibex, &format!("set server b/s1 addr 127.0.0.1 port {port}")),
        format!("port changed from '{old}' to '{port}' by 'stats socket command'\n\n")
    );
    assert_eq!(status_of(&ibex, "b", "s1"), "MAINT");
    assert_eq!(cli(&ibex, "set server b/s1 state ready"), "\n");
}

#[test]
fn set_maxconn_global_is_applied_not_dropped() {
    // T146 item 3 enforces the global limit, so the command no longer has to be refused
    // (`cli/levels.vtc` expects `Maxconn: 1234` after it).
    let (ibex, _fe) = start(&conf("  server s1 {s1}\n"));
    assert_eq!(cli(&ibex, "set maxconn global 1234"), "\n");
    assert!(cli(&ibex, "show info").contains("\nMaxconn: 1234\n"));
}
