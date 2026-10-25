// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The server-state file at start (T490): `server-state-file`, `server-state-base`,
//! `load-server-state-from-file global|local|none`, `server-state-file-name`, and the
//! `show servers state` columns the file is written from.
//!
//! Every row and message was measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-25 with
//! the same sections and the same file (`apply_server_state`, `src/server_state.c`):
//!
//! * the file is read before the servers take traffic; a server takes from its line the
//!   operational state (stopped: DOWN until its checks bring it up, also with no check), the
//!   admin state (maintenance, drain), the weight when the file's initial weight is the
//!   configuration's, the health counter, `disable health`, the last check status, the
//!   seconds since the last change and the port. The address is not restored for a server
//!   written as an address (`srv->lastaddr` is read only by `init-addr last`, for a name);
//! * the configuration wins where it changed: a server the file had `disabled` and the
//!   configuration no longer has leaves maintenance, a new `disabled` enters it, a new
//!   initial weight keeps the configuration's weight, and a drain that came from a weight
//!   of 0 is dropped once the weight is no longer 0;
//! * a line whose version, length or field count is wrong voids the whole file; a line with
//!   a bad value voids that server's line only; lines for servers or backends the
//!   configuration lacks are skipped (a local file warns about each);
//! * a local file is `<server-state-base>/<server-state-file-name or backend name>`, and its
//!   lines must name the backend (name, or id with a warning).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

const HEADER: &str = "# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord srv_use_ssl srv_check_port srv_check_addr srv_agent_addr srv_agent_port";

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

/// A port nothing listens on.
fn dead_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().expect("addr").port()
}

struct Run {
    ibex: common::Ibex,
    sock: PathBuf,
    fe: SocketAddr,
    dir: tempfile::TempDir,
}

impl Run {
    /// Starts ibex on `cfg` with the files `files` (name, text) in a fresh directory.
    /// `{dir}` is that directory, `{fe}` the frontend, `{sock}` the stats socket, `{live}`
    /// the port of a server answering `X-Server: live`, `{dead}` a port nothing listens on.
    fn start(cfg: &str, files: &[(&str, &str)]) -> Self {
        let dir = tempfile::tempdir().expect("tmpdir");
        let fe = common::reserve_addr();
        let sock = dir.path().join("s.sock");
        let live = server("live").port().to_string();
        let dead = dead_port().to_string();
        let subst = |t: &str| {
            t.replace("{dir}", &dir.path().display().to_string())
                .replace("{fe}", &fe.to_string())
                .replace("{sock}", &sock.display().to_string())
                .replace("{live}", &live)
                .replace("{dead}", &dead)
        };
        for (name, text) in files {
            let p = dir.path().join(name);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).expect("mkdir");
            }
            std::fs::write(&p, subst(text)).expect("write state file");
        }
        let text = subst(cfg);
        let cfg_path = dir.path().join("ibex.cfg");
        std::fs::write(&cfg_path, &text).expect("write cfg");
        let err = std::fs::File::create(dir.path().join("stderr")).expect("stderr file");
        let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
            .arg("-f")
            .arg(&cfg_path)
            .current_dir(dir.path())
            .stdout(Stdio::null())
            .stderr(err)
            .spawn()
            .expect("spawn ibex");
        let ibex = common::Ibex(child);
        assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}\n{}", std::fs::read_to_string(dir.path().join("stderr")).unwrap_or_default());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !sock.exists() && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        Run { ibex, sock, fe, dir }
    }

    fn cli(&self, cmd: &str) -> String {
        let mut s = UnixStream::connect(&self.sock).expect("connect to the stats socket");
        s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    /// `show servers state` fields 3 (name), 5..=8 (op, admin, uweight, iweight), 12..=13
    /// (health, `check_state` without `CHK_ST_INPROGRESS`, which depends on the moment), one
    /// string per server.
    fn rows(&self) -> Vec<String> {
        self.cli("show servers state")
            .lines()
            .skip(2)
            .filter(|l| !l.is_empty())
            .map(|l| {
                let f: Vec<&str> = l.split(' ').collect();
                let state = f[13].parse::<u32>().expect("srv_check_state") & !1;
                format!("{}/{} {} {} {} {} {} {state}", f[1], f[3], f[5], f[6], f[7], f[8], f[12])
            })
            .collect()
    }

    /// One `show servers state` field of `<px>/<sv>`.
    fn field(&self, px: &str, sv: &str, n: usize) -> String {
        let out = self.cli("show servers state");
        out.lines()
            .find(|l| l.split(' ').nth(1) == Some(px) && l.split(' ').nth(3) == Some(sv))
            .and_then(|l| l.split(' ').nth(n))
            .map_or_else(|| panic!("no {px}/{sv} in {out:?}"), str::to_string)
    }

    /// `<px>/<sv> <status>` of `show stat`, per server.
    fn statuses(&self) -> Vec<String> {
        let stat = self.cli("show stat");
        let mut lines = stat.lines();
        let header = lines.next().expect("a header").trim_start_matches("# ");
        let col = |n: &str| header.split(',').position(|c| c == n).expect("column");
        let (st, w) = (col("status"), col("weight"));
        lines
            .filter(|l| !l.is_empty() && !l.contains(",FRONTEND,") && !l.contains(",BACKEND,"))
            .map(|l| {
                let f: Vec<&str> = l.split(',').collect();
                format!("{}/{} {} {}", f[0], f[1], f[st], f[w])
            })
            .collect()
    }

    /// What ibex printed while it started, ` : ` and what follows on each line.
    fn messages(&self) -> Vec<String> {
        let path = self.dir.path().join("stderr");
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.contains("FD limit"))
            .filter_map(|l| l.split_once(") : ").map(|(level, m)| format!("{} {m}", level.split(']').next().unwrap_or("").trim_start_matches('['))))
            .collect()
    }

    fn get(&self) -> String {
        let mut c = TcpStream::connect(self.fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
        let mut got = Vec::new();
        let _ = c.read_to_end(&mut got);
        let text = String::from_utf8_lossy(&got).into_owned();
        text.split("\r\n")
            .find_map(|l| l.split_once(": ").filter(|(n, _)| n.eq_ignore_ascii_case("X-Server")).map(|(_, v)| v.to_string()))
            .unwrap_or_else(|| text.lines().next().unwrap_or("<nothing>").to_string())
    }

    fn path(&self, name: &str) -> String {
        Path::new(self.dir.path()).join(name).display().to_string()
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        common::stop(&mut self.ibex);
    }
}

fn state(lines: &[&str]) -> String {
    let mut s = format!("1\n{HEADER}\n");
    for l in lines {
        s.push_str(l);
        s.push('\n');
    }
    s
}

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n";

/// `base.cfg` of the measurement: backend `b` (s1 weight 5, s2) and backend `c` (x1).
fn base(global: &str, defaults: &str, b: &str, c: &str) -> String {
    format!(
        "global\n  stats socket {{sock}} mode 600 level admin\n{global}{DEFAULTS}{defaults}frontend f\n  bind {{fe}}\n  default_backend b\n\
         backend b\n{b}  server s1 127.0.0.1:{{live}} weight 5\n  server s2 127.0.0.1:{{live}}\nbackend c\n{c}  server x1 127.0.0.1:{{live}}\n"
    )
}

fn global_file(name: &str) -> String {
    format!("  server-state-file {{dir}}/{name}\n")
}

const LOAD_GLOBAL: &str = "  load-server-state-from-file global\n";

#[test]
fn the_file_restores_weight_admin_state_health_and_disabled_checks() {
    let cfg = format!(
        "global\n  stats socket {{sock}} mode 600 level admin\n  server-state-file {{dir}}/st\n{DEFAULTS}{LOAD_GLOBAL}\
         frontend f\n  bind {{fe}}\n  default_backend b\nbackend b\n\
         \x20 server s1 127.0.0.1:{{live}} weight 5\n  server s2 127.0.0.1:{{live}}\n  server s3 127.0.0.1:{{live}}\n\
         \x20 server s4 127.0.0.1:{{live}}\n  server s5 127.0.0.1:{{live}} check inter 30s\n\
         \x20 server s6 127.0.0.1:{{dead}} check inter 30s\n  server s7 127.0.0.1:{{live}} check inter 30s\n\
         \x20 server s8 127.0.0.1:{{live}} disabled\nbackend c\n  server x1 127.0.0.1:{{live}}\n"
    );
    let file = state(&[
        "3 b 1 s1 127.0.0.1 2 0 9 5 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
        "3 b 2 s2 127.0.0.9 0 1 3 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
        "3 b 3 s3 127.0.0.1 2 8 1 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
        "3 b 4 s4 127.0.0.1 2 0 4 3 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
        "3 b 5 s5 127.0.0.1 2 0 1 1 100 6 3 4 2 0 0 0 - {live} - 0 0 - - 0",
        "3 b 6 s6 127.0.0.1 0 0 1 1 100 8 2 0 6 0 0 0 - {dead} - 0 0 - - 0",
        "3 b 7 s7 127.0.0.1 2 1 1 1 100 6 3 4 6 0 0 0 - {live} - 0 0 - - 0",
        "3 b 8 s8 127.0.0.1 2 4 1 1 100 1 0 0 8 0 0 0 - {live} - 0 0 - - 0",
        "4 c 1 x1 127.0.0.1 2 0 1 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
        "4 c 2 gone 127.0.0.1 2 0 1 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
    ]);
    let run = Run::start(&cfg, &[("st", &file)]);
    assert_eq!(
        run.rows(),
        [
            "b/s1 2 0 9 5 4 0",
            "b/s2 0 1 3 1 0 0",
            "b/s3 2 8 1 1 4 0",
            "b/s4 2 0 1 1 4 0",
            "b/s5 2 0 1 1 4 2",
            "b/s6 0 0 1 1 0 6",
            "b/s7 0 1 1 1 0 14",
            "b/s8 2 4 1 1 4 8",
            "c/x1 2 0 1 1 4 0",
        ]
    );
    assert_eq!(
        run.statuses(),
        [
            "b/s1 no check 9",
            "b/s2 MAINT 3",
            "b/s3 DRAIN 1",
            "b/s4 no check 1",
            "b/s5 no check 1",
            "b/s6 DOWN 1",
            "b/s7 MAINT 1",
            "b/s8 no check 1",
            "c/x1 no check 1",
        ]
    );
    // The address of a server written as an address is the configuration's.
    assert_eq!(run.field("b", "s2", 4), "127.0.0.1");
    // The seconds since the last change carry on from the file's, and so does `lastchg`;
    // the check status of s6 is the file's until its next check (inter 30s).
    let since: u64 = run.field("b", "s1", 9).parse().expect("seconds");
    assert!((100..110).contains(&since), "srv_time_since_last_change {since}");
    assert_eq!((run.field("b", "s6", 10).as_str(), run.field("b", "s6", 11).as_str()), ("8", "2"));
    // Nothing is said about a line the configuration has no server for (global file); the
    // stopped servers and the one the file takes out of maintenance are (measured on HAProxy).
    assert_eq!(
        run.messages(),
        [
            "WARNING Server b/s2 is DOWN, changed from server-state after a reload. 6 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.",
            "WARNING Server b/s6 is DOWN, changed from server-state after a reload. 4 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.",
            "WARNING Server b/s8 is UP/READY (leaving forced maintenance)."
        ]
    );
}

#[test]
fn the_port_in_the_file_takes_the_traffic() {
    // Configured on a port nothing listens on; the file has the live one.
    let cfg = format!(
        "global\n  stats socket {{sock}} mode 600 level admin\n  server-state-file {{dir}}/st\n{DEFAULTS}{LOAD_GLOBAL}\
         frontend f\n  bind {{fe}}\n  default_backend b\nbackend b\n  server s1 127.0.0.1:{{dead}}\n"
    );
    let run = Run::start(&cfg, &[("st", &state(&["3 b 1 s1 127.0.0.7 2 0 1 1 0 1 0 0 0 0 0 0 - {live} - 0 0 - - 0"]))]);
    assert_eq!(run.get(), "live");
    assert_eq!(run.field("b", "s1", 4), "127.0.0.1");
}

#[test]
fn a_server_stopped_in_the_file_starts_down_even_without_a_check() {
    let cfg = base(&global_file("st"), LOAD_GLOBAL, "", "");
    let file = state(&[
        "3 b 1 s1 127.0.0.1 0 0 9 5 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
        "3 b 2 s2 127.0.0.1 2 0 3 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
        "9 zz 1 q1 127.0.0.1 2 0 3 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
        "3 b 7 nosuch 127.0.0.1 2 0 3 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
    ]);
    let run = Run::start(&cfg, &[("st", &file)]);
    assert_eq!(run.rows(), ["b/s1 0 0 9 5 0 0", "b/s2 2 0 3 1 4 0", "c/x1 2 0 1 1 0 0"]);
    assert_eq!(run.statuses(), ["b/s1 DOWN 9", "b/s2 no check 3", "c/x1 no check 1"]);
    assert_eq!(run.messages(), ["WARNING Server b/s1 is DOWN, changed from server-state after a reload. 1 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue."]);
}

#[test]
fn a_changed_configuration_wins_over_the_file() {
    // e1: the initial weight went from 4 to 5; s2 and x1 were `disabled` and are no longer.
    let run = Run::start(
        &base(&global_file("st"), LOAD_GLOBAL, "", ""),
        &[(
            "st",
            &state(&[
                "3 b 1 s1 127.0.0.1 2 0 2 4 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
                "3 b 2 s2 127.0.0.1 0 5 1 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
                "4 c 1 x1 127.0.0.1 0 4 1 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
            ]),
        )],
    );
    assert_eq!(run.rows(), ["b/s1 2 0 5 5 4 0", "b/s2 0 0 1 1 0 0", "c/x1 0 0 1 1 0 0"]);
    assert_eq!(run.statuses(), ["b/s1 no check 5", "b/s2 DOWN 1", "c/x1 DOWN 1"]);
    drop(run);

    // e2: the configuration now disables s1 (ready in the file) and s2 (in maintenance).
    let cfg = base(&global_file("st"), LOAD_GLOBAL, "", "")
        .replace("weight 5\n", "weight 5 disabled\n")
        .replace("  server s2 127.0.0.1:{live}\n", "  server s2 127.0.0.1:{live} disabled\n");
    let run = Run::start(
        &cfg,
        &[(
            "st",
            &state(&[
                "3 b 1 s1 127.0.0.1 2 0 2 5 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
                "3 b 2 s2 127.0.0.1 2 1 1 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
            ]),
        )],
    );
    assert_eq!(run.rows(), ["b/s1 0 5 2 5 4 8", "b/s2 0 5 1 1 4 8", "c/x1 2 0 1 1 0 0"]);
    assert_eq!(run.statuses(), ["b/s1 MAINT 2", "b/s2 MAINT 1", "c/x1 no check 1"]);
    drop(run);

    // e3: a drain from an initial weight of 0 is dropped now that it is 5; a forced drain is
    // kept; an inherited maintenance (2) is not restored.
    let run = Run::start(
        &base(&global_file("st"), LOAD_GLOBAL, "", ""),
        &[(
            "st",
            &state(&[
                "3 b 1 s1 127.0.0.1 2 8 0 0 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
                "3 b 2 s2 127.0.0.1 2 8 1 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
                "4 c 1 x1 127.0.0.1 2 2 1 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
            ]),
        )],
    );
    assert_eq!(run.rows(), ["b/s1 2 0 5 5 4 0", "b/s2 2 8 1 1 4 0", "c/x1 2 0 1 1 4 0"]);
    assert_eq!(run.statuses(), ["b/s1 no check 5", "b/s2 DRAIN 1", "c/x1 no check 1"]);
}

/// The rows of a start that applied nothing from the file.
const UNTOUCHED: [&str; 3] = ["b/s1 2 0 5 5 0 0", "b/s2 2 0 1 1 0 0", "c/x1 2 0 1 1 0 0"];

#[test]
fn a_broken_file_is_not_applied_and_says_why() {
    let good = "3 b 1 s1 127.0.0.1 2 1 9 5 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0";
    let cases: [(&str, String, &str); 6] = [
        // A short line voids the lines before it too.
        ("short", state(&[good, "3 b 2 s2 127.0.0.1 2 0"]), "WARNING config: corrupted global server state file '{f}' at line 3."),
        ("v2", format!("2\n{good}\n"), "WARNING config: Can't get version of the global server state file '{f}'."),
        ("vsp", format!("1 \n{good}\n"), "WARNING config: Can't get version of the global server state file '{f}'."),
        ("empty", String::new(), "NOTICE config: Empty global server state file '{f}'."),
        ("nonl", format!("1\n{good}"), "WARNING config: corrupted global server state file '{f}' at line 1."),
        ("long", format!("1\n{}\n", "x".repeat(2000)), "WARNING config: corrupted global server state file '{f}' at line 1."),
    ];
    for (name, text, msg) in &cases {
        let run = Run::start(&base(&global_file(name), LOAD_GLOBAL, "", ""), &[(name, text)]);
        assert_eq!(run.rows(), UNTOUCHED, "{name}");
        assert_eq!(run.messages(), [msg.replace("{f}", &run.path(name))], "{name}");
    }
    let run = Run::start(&base(&global_file("missing"), LOAD_GLOBAL, "", ""), &[]);
    assert_eq!(run.rows(), UNTOUCHED);
    assert_eq!(
        run.messages(),
        [format!("NOTICE config: Can't open global server state file '{}': No such file or directory", run.path("missing"))]
    );
}

#[test]
fn a_bad_value_voids_that_line_only_and_extra_fields_are_ignored() {
    let file = state(&[
        "3 b 1 s1 127.0.0.1 2 1 9 5 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0 x x x x x x",
        "3 b 2 s2 127.0.0.1 9 0 3 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
        "4 c 1 x1 127.0.0.1 2 0 300 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
    ]);
    let run = Run::start(&base(&global_file("st"), LOAD_GLOBAL, "", ""), &[("st", &file)]);
    assert_eq!(run.rows(), ["b/s1 0 1 9 5 0 0", "b/s2 2 0 1 1 0 0", "c/x1 2 0 1 1 0 0"]);
    assert_eq!(
        run.messages(),
        [
            "WARNING server-state application failed for server 'b/s2', invalid srv_op_state value '9'",
            "WARNING server-state application failed for server 'c/x1', invalid srv_uweight value '300'",
        ]
    );
}

#[test]
fn local_files_live_under_server_state_base() {
    let b = state(&[
        "3 b 1 s1 127.0.0.1 2 1 2 5 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
        "3 b 9 gone 127.0.0.1 2 1 2 5 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
        "4 c 1 x1 127.0.0.1 2 1 1 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
    ]);
    // f1: `b` reads `<base>/b` and warns about `gone`; `c` reads `cfile`, whose line has the
    // name but another id.
    let cfile = state(&["9 c 1 x1 127.0.0.1 2 1 1 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0"]);
    let run = Run::start(
        &base("  server-state-base {dir}/sb\n", "  load-server-state-from-file local\n", "", "  server-state-file-name cfile\n"),
        &[("sb/b", &b), ("sb/cfile", &cfile)],
    );
    assert_eq!(run.rows(), ["b/s1 0 1 2 5 0 0", "b/s2 2 0 1 1 0 0", "c/x1 0 1 1 1 0 0"]);
    assert_eq!(
        run.messages(),
        [
            "WARNING Proxy 'b': can't find server 'gone' in backend 'b'",
            "WARNING Proxy 'c': backend ID mismatch: from server state file: '9', from running config '4'",
        ]
    );
    drop(run);

    // f2: an absolute `server-state-file-name`, a base with its own `/`; a line with the id
    // and another name is skipped, whatever its `bk_f_forced_id` (HAProxy tests that flag
    // against `PR_O_FORCED_ID`, 0x80, so it never holds). The backend `d` has no file.
    let zz = state(&["4 zz 1 x1 127.0.0.1 2 1 1 1 100 1 0 0 0 0 1 0 - {live} - 0 0 - - 0"]);
    let cfg = base(
        "  server-state-base {dir}/sb/\n",
        "  load-server-state-from-file local\n",
        "",
        "  server-state-file-name {dir}/zz\n",
    ) + "backend d\n  server d1 127.0.0.1:{live}\n";
    let run = Run::start(&cfg, &[("sb/b", &b), ("zz", &zz)]);
    assert_eq!(run.rows(), ["b/s1 0 1 2 5 0 0", "b/s2 2 0 1 1 0 0", "c/x1 2 0 1 1 0 0", "d/d1 2 0 1 1 0 0"]);
    assert_eq!(
        run.messages(),
        [
            "WARNING Proxy 'b': can't find server 'gone' in backend 'b'".to_string(),
            "WARNING Proxy 'c': backend name mismatch: from server state file: 'zz', from running config 'c'".to_string(),
            format!("NOTICE Proxy 'd': Can't open server state file '{}': No such file or directory.", run.path("sb/d")),
        ]
    );
}

#[test]
fn none_reads_nothing_and_global_without_a_file_warns() {
    let file = state(&["3 b 1 s1 127.0.0.1 2 1 9 5 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0"]);
    // `none` in the backend wins over `global` in `defaults`; a relative `server-state-file`
    // is under the working directory when there is no base.
    let run = Run::start(&base("  server-state-file st\n", LOAD_GLOBAL, "  load-server-state-from-file none\n", ""), &[("st", &file)]);
    assert_eq!(run.rows(), UNTOUCHED);
    drop(run);
    let run = Run::start(&base("  server-state-file st\n", LOAD_GLOBAL, "", ""), &[("st", &file)]);
    assert_eq!(run.rows()[0], "b/s1 0 1 9 5 0 0");
    drop(run);
    // A global file no backend reads is not opened (it does not exist: no notice).
    let run = Run::start(&base(&global_file("missing"), "  load-server-state-from-file local\n", "", ""), &[("b", &file)]);
    assert_eq!(run.rows()[0], "b/s1 0 1 9 5 0 0");
    // Without a base, a local file is under the working directory, and named as written.
    assert_eq!(run.messages(), ["NOTICE Proxy 'c': Can't open server state file 'c': No such file or directory."]);
    drop(run);
    let run = Run::start(&base("", LOAD_GLOBAL, "", ""), &[]);
    assert_eq!(run.rows(), UNTOUCHED);
    assert_eq!(
        run.messages(),
        [
            "WARNING backend 'b' configured to load server state file from global section 'server-state-file' directive. Unfortunately, 'server-state-file' is not set!",
            "WARNING backend 'c' configured to load server state file from global section 'server-state-file' directive. Unfortunately, 'server-state-file' is not set!",
        ]
    );
}

/// `srv_op_state` 1 (starting) and 3 (stopping, `NOLB`): `HAProxy` keeps a starting server
/// running with its counter below `rise`, and a stopping one `NOLB` unless `fall` is 1 (then
/// it is stopped). Ibex has no `NOLB` state (no `http-check disable-on-404`), so it runs the
/// server and says so; the text is Ibex's own.
#[test]
fn starting_and_stopping_servers() {
    let cfg = format!(
        "global\n  stats socket {{sock}} mode 600 level admin\n  server-state-file {{dir}}/st\n{DEFAULTS}{LOAD_GLOBAL}\
         frontend f\n  bind {{fe}}\n  default_backend b\nbackend b\n\
         \x20 server s3 127.0.0.1:{{live}}\n  server s4 127.0.0.1:{{live}}\n\
         \x20 server s7 127.0.0.1:{{live}} check inter 30s rise 1 fall 1\n  server s8 127.0.0.1:{{dead}} check inter 30s rise 1 fall 1\n"
    );
    let file = state(&[
        "2 b 1 s3 127.0.0.1 1 0 1 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
        "2 b 2 s4 127.0.0.1 3 0 1 1 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
        "2 b 3 s7 127.0.0.1 1 0 1 1 100 6 3 1 6 0 0 0 - {live} - 0 0 - - 0",
        "2 b 4 s8 127.0.0.1 3 0 1 1 100 6 3 1 6 0 0 0 - {dead} - 0 0 - - 0",
    ]);
    let run = Run::start(&cfg, &[("st", &file)]);
    // HAProxy: s3 `2 0 1 1 1 0`, s4 `3 0 1 1 2 0` (NOLB), s7 `2 0 1 1 1 6`, s8 `0 0 1 1 0 6`.
    assert_eq!(run.rows(), ["b/s3 2 0 1 1 1 0", "b/s4 2 0 1 1 2 0", "b/s7 2 0 1 1 1 6", "b/s8 0 0 1 1 0 6"]);
    assert_eq!(
        run.messages(),
        [
            "WARNING server-state partially applied for server 'b/s4', srv_op_state 3 (stopping, NOLB) is not implemented in Ibex: the server runs",
            "WARNING Server b/s8 is DOWN, changed from server-state after a reload. 3 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue."
        ]
    );
}

/// The `show servers state` columns that differed from `HAProxy`'s before T490.
#[test]
fn show_servers_state_columns_match_haproxy() {
    let cfg = format!(
        "global\n  stats socket {{sock}} mode 600 level admin\n{DEFAULTS}frontend f\n  bind {{fe}}\n  default_backend b\nbackend b\n\
         \x20 server s1 127.0.0.1:{{live}} check inter 200ms disabled\n  server s2 127.0.0.1:{{live}} disabled\n\
         \x20 server s3 127.0.0.1:{{live}} check inter 200ms\n  server s4 127.0.0.1:{{live}} ssl verify none\n"
    );
    let run = Run::start(&cfg, &[]);
    // CHK_ST_PAUSED (8) while a checked server is in maintenance, and for good on a server
    // with no check that the configuration disabled; `srv_use_ssl`.
    let rows = |run: &Run| run.cli("show servers state").lines().skip(2).filter(|l| !l.is_empty()).map(|l| {
        let f: Vec<&str> = l.split(' ').collect();
        format!("{} {} {} {}", f[3], f[5], f[13].parse::<u32>().expect("srv_check_state") & !1, f[20])
    }).collect::<Vec<_>>();
    assert_eq!(rows(&run), ["s1 0 14 0", "s2 0 8 0", "s3 2 6 0", "s4 2 0 1"]);
    run.cli("disable server b/s3");
    run.cli("enable server b/s1");
    run.cli("enable server b/s2");
    assert_eq!(rows(&run), ["s1 2 6 0", "s2 2 8 0", "s3 0 14 0", "s4 2 0 1"]);
    // The seconds since the last change: 0 right after one, the uptime otherwise.
    assert_eq!(run.field("b", "s3", 9), "0");
    thread::sleep(Duration::from_millis(2100));
    let up: u64 = run.field("b", "s4", 9).parse().expect("seconds");
    assert!(up >= 2, "srv_time_since_last_change of an unchanged server {up}");
}

/// A drain on a stopped server, a `disabled` server with a check that the file had enabled,
/// and the columns Ibex cannot apply. `HAProxy` (same file): s1 `0 8 1 1 0 0` DOWN, s2 `2 4`
/// UP, s3 "partially applied ..., health checks are not enabled on this server" (no check),
/// s4 the check port 19805 applied. Ibex has no `set server check-port`, no agent checks and
/// no `set server ssl`, so it keeps the configuration's and says so (texts in Ibex's words
/// but the two `HAProxy` has).
#[test]
fn columns_ibex_cannot_apply_are_named() {
    let cfg = format!(
        "global\n  stats socket {{sock}} mode 600 level admin\n  server-state-file {{dir}}/st\n{DEFAULTS}{LOAD_GLOBAL}\
         frontend f\n  bind {{fe}}\n  default_backend b\nbackend b\n  server-state-file-name x\n\
         \x20 server s1 127.0.0.1:{{live}}\n  server s2 127.0.0.1:{{live}} check inter 30s disabled\n\
         \x20 server s3 127.0.0.1:{{live}}\n  server s4 127.0.0.1:{{live}} check inter 30s\n\
         \x20 server s5 127.0.0.1:{{live}} ssl verify none\n  server s6 127.0.0.1:{{live}}\n"
    );
    let file = state(&[
        "3 b 1 s1 127.0.0.1 0 8 1 1 0 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
        "3 b 2 s2 127.0.0.1 2 4 1 1 0 1 0 0 14 0 0 0 - {live} - 0 0 - - 0",
        "3 b 3 s3 127.0.0.1 2 0 1 1 0 1 0 0 0 0 0 0 - {live} - 1 19805 127.0.0.3 127.0.0.4 19806",
        "3 b 4 s4 127.0.0.1 2 0 1 1 0 1 0 0 6 0 0 0 - {live} - 0 19805 - - 0",
        "3 b 5 s5 127.0.0.1 2 0 1 1 0 1 0 0 0 0 0 0 - {live} - 0 0 - - 0",
        "3 b 6 s6 127.0.0.1 2 0 1 1 0 1 0 0 0 0 0 0 - {live} - 0 0 - 127.0.0.4 0",
    ]);
    let run = Run::start(&cfg, &[("st", &file)]);
    let rows = run.rows();
    assert_eq!(rows[0], "b/s1 0 8 1 1 0 0");
    assert_eq!(&rows[1..], ["b/s2 2 4 1 1 4 6", "b/s3 2 0 1 1 4 0", "b/s4 2 0 1 1 4 6", "b/s5 2 0 1 1 4 0", "b/s6 2 0 1 1 4 0"]);
    let st = run.statuses();
    assert_eq!((st[0].as_str(), st[1].as_str()), ("b/s1 DOWN 1", "b/s2 UP 1"));
    assert_eq!(
        run.messages(),
        [
            "WARNING Proxy 'b': 'server-state-file-name' is ignored without 'load-server-state-from-file local'.",
            "WARNING Server b/s1 is DOWN, changed from server-state after a reload. 4 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.",
            "WARNING Server b/s2 is UP/READY (leaving forced maintenance).",
            "WARNING server-state partially applied for server 'b/s3', health checks are not enabled on this server",
            "WARNING server-state partially applied for server 'b/s4', srv_check_port/srv_check_addr are not applied: Ibex has no 'set server check-port/check-addr'",
            "WARNING server-state partially applied for server 'b/s5', srv_use_ssl 0 is not applied: Ibex has no 'set server ssl'",
            "WARNING server-state partially applied for server 'b/s6', agent checks are not enabled on this server",
        ]
    );
}

/// `HAProxy`: `config: Can't open global server state file '<f>': Permission denied`, a
/// warning (a missing file is a notice).
#[test]
fn an_unreadable_file_is_a_warning() {
    use std::os::unix::fs::PermissionsExt;
    if rustix::process::geteuid().is_root() {
        return; // root reads it anyway
    }
    let file = state(&["3 b 1 s1 127.0.0.1 2 1 9 5 100 1 0 0 0 0 0 0 - {live} - 0 0 - - 0"]);
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("locked");
    std::fs::write(&path, &file).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    let run = Run::start(&base(&format!("  server-state-file {}\n", path.display()), LOAD_GLOBAL, "", ""), &[]);
    assert_eq!(run.rows(), UNTOUCHED);
    assert_eq!(
        run.messages(),
        [format!("WARNING config: Can't open global server state file '{}': Permission denied", path.display())]
    );
}
