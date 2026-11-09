// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `global node` / `global description` in `show info` (plain, typed, json) and on the stats
//! page, and a proxy's `description` on the stats page (T264).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` with `node mynode` and `description "global desc"`:
//!
//! * `show info`: `node: mynode` and `description: global desc`; typed: `50.node.1:COSV:str:mynode`
//!   and `51.description.1:COSV:str:global desc`; json: field pos 50 `node` and pos 51
//!   `description`, tags `Config`/`Output`/`Service`, type `str`;
//! * without `description` the field is absent in all three; without `node` it is the host name;
//! * `show stat` (plain, typed, json) has no node or description column at all;
//! * the stats page, with `stats show-node` and `stats show-desc` given no argument, says
//!   `Statistics Report for pid N on gnode: gdesc one` (the global ones) and puts the
//!   proxy's `description` unescaped in a `<th class="desc">` of its table (Alcyon's page has its own layout: a `class="desc"` element beside the proxy name); `<title>` has the node.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

struct Alcyon {
    child: Child,
    sock: PathBuf,
    dir: PathBuf,
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn backend() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 || c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// `global_extra` goes in `global`, `fe_extra` in the frontend (which has `stats uri /st`).
fn start(global_extra: &str, fe_extra: &str) -> (Alcyon, SocketAddr) {
    let fe = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("alcyon_t264_{}_{}", std::process::id(), fe.port()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sock = dir.join("s.sock");
    let cfg = format!(
        "global\n  nbthread 1\n{global_extra}  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout client 5s\n  timeout connect 1s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n  stats enable\n  stats uri /st\n{fe_extra}  default_backend be\n\
         backend be\n  description back desc\n  server s {}\n",
        sock.display(),
        backend()
    );
    std::fs::write(dir.join("cfg"), cfg).expect("cfg");
    let child =
        Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(dir.join("cfg")).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let alcyon = Alcyon { child, sock, dir };
    assert!(common::wait_listening(fe));
    let end = std::time::Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(&alcyon.sock).is_err() {
        assert!(std::time::Instant::now() < end, "the stats socket never came up");
        thread::sleep(Duration::from_millis(25));
    }
    (alcyon, fe)
}

fn cli(sock: &Path, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn page(fe: SocketAddr) -> String {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(b"GET /st HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn lines_with(text: &str, what: &[&str]) -> Vec<String> {
    text.lines().filter(|l| what.iter().any(|w| l.contains(w))).map(str::to_string).collect()
}

#[test]
fn show_info_has_the_configured_node_and_description() {
    let (alcyon, _) = start("  node mynode\n  description global desc\n", "");
    assert_eq!(lines_with(&cli(&alcyon.sock, "show info"), &["node:", "description:"]), ["node: mynode", "description: global desc"]);
    assert_eq!(
        lines_with(&cli(&alcyon.sock, "show info typed"), &[".node.", ".description."]),
        ["50.node.1:COSV:str:mynode", "51.description.1:COSV:str:global desc"]
    );
    let json = cli(&alcyon.sock, "show info json");
    assert!(
        json.contains(r#"{"field":{"pos":50,"name":"node"},"processNum":1,"tags":{"origin":"Config","nature":"Output","scope":"Service"},"value":{"type":"str","value":"mynode"}}"#),
        "{json}"
    );
    assert!(
        json.contains(r#"{"field":{"pos":51,"name":"description"},"processNum":1,"tags":{"origin":"Config","nature":"Output","scope":"Service"},"value":{"type":"str","value":"global desc"}}"#),
        "{json}"
    );
}

#[test]
fn without_them_the_node_is_the_host_name_and_there_is_no_description() {
    let (alcyon, _) = start("", "");
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").expect("hostname").trim().to_string();
    assert_eq!(lines_with(&cli(&alcyon.sock, "show info"), &["node:", "description:"]), [format!("node: {host}")]);
    assert!(lines_with(&cli(&alcyon.sock, "show info typed"), &[".description."]).is_empty());
    assert!(!cli(&alcyon.sock, "show info json").contains(r#""name":"description""#));
}

#[test]
fn show_stat_has_no_node_or_description() {
    let (alcyon, _) = start("  node mynode\n  description global desc\n", "  description front desc\n");
    for cmd in ["show stat", "show stat typed", "show stat json"] {
        let out = cli(&alcyon.sock, cmd);
        assert!(!out.contains("mynode") && !out.contains("global desc") && !out.contains("front desc"), "{cmd}: {out}");
    }
}

#[test]
fn the_stats_page_shows_the_global_and_the_proxy_descriptions() {
    let (_alcyon, fe) =
        start("  node gnode\n  description gdesc one\n", "  description front <b>desc</b>\n  stats show-node\n  stats show-desc\n");
    let p = page(fe);
    assert!(p.contains("Statistics Report for pid "), "{p}");
    assert!(p.contains(" on gnode: gdesc one</h2>"), "{p}");
    assert!(p.contains("on gnode</title>"), "{p}");
    assert!(p.contains(r#"class="desc">front <b>desc</b></div>"#), "{p}");
    assert!(p.contains(r#"class="desc">back desc</div>"#), "{p}");
}

// T272 C: a reload is a fresh process that reads the configuration again (`-sf`; the master
// in `-W` mode starts a new worker the same way), so the identity cannot go stale.
#[test]
fn a_reload_with_sf_shows_the_node_and_description_of_the_new_configuration() {
    let (mut old, _) = start("  node first\n  description one\n", "");
    let dir = old.dir.clone();
    let cfg = std::fs::read_to_string(dir.join("cfg")).expect("cfg");
    std::fs::write(dir.join("cfg"), cfg.replace("node first", "node second").replace("description one", "description two")).expect("rewrite");
    assert_eq!(lines_with(&cli(&old.sock, "show info"), &["node:", "description:"]), ["node: first", "description: one"]);
    let mut new = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(dir.join("cfg"))
        .arg("-sf")
        .arg(old.child.id().to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let _ = old.child.wait();
    let end = std::time::Instant::now() + Duration::from_secs(10);
    let info = loop {
        let info = cli(&old.sock, "show info");
        if info.contains("node: second") || std::time::Instant::now() > end {
            break info;
        }
        thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(lines_with(&info, &["node:", "description:"]), ["node: second", "description: two"]);
    common::stop(&mut new);
}

#[test]
fn check_mode_prints_the_show_desc_warning_as_haproxy_does() {
    let dir = std::env::temp_dir().join(format!("alcyon_t272c_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("cfg");
    std::fs::write(&cfg, "defaults\n  mode http\n  timeout client 5s\n  timeout connect 1s\n  timeout server 5s\nfrontend fe\n  bind 127.0.0.1:0\n  stats enable\n  stats show-desc\n").expect("cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&cfg).output().expect("run");
    let err = String::from_utf8_lossy(&out.stderr);
    let want = format!("config : parsing [{}:9]: 'show-desc' requires a parameter or 'desc' to be set in the global section.", cfg.display());
    assert!(out.status.success(), "{err}");
    assert!(err.lines().any(|l| l.starts_with("[WARNING]") && l.ends_with(&want)), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
