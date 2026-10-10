// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The numeric ids of proxies, servers and listeners (T86).
//!
//! Every expectation was measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-04 with a
//! `stats socket` in the configuration (`src/cfgparse.c`, `check_config_validity`):
//!
//! * proxies are numbered in the order they are written, frontends and backends together,
//!   from 2: id 1 is skipped unless a proxy asks for it with `id`;
//! * `id <n>` is kept, and the others take the first number not in use, so a proxy written
//!   before another that asked for 3 gets 4 when 3 is the next one it would have had;
//! * servers are numbered from 1 in each backend, around the `id`s the others asked for;
//! * `show stat` lists the proxies in the order they were written, not in id order;
//! * `show servers state` carries the proxy id (`be_id`), the server id (`srv_id`) and
//!   whether each was forced (`bk_f_forced_id`, `srv_f_forced_id`);
//! * `fe_id`, `be_id` and `so_id` read them; with one thread, `so_id` numbers the listeners
//!   of a proxy from 1 (from the one after the previous bind's when that bind had an `id`).
//!   With several threads each bind has one listener per thread and the ids spread out.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
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
    }
}

fn start(body: &str, wait_for: SocketAddr) -> Ibex {
    let dir = std::env::temp_dir().join(format!("ibex-t86-{}-{}", std::process::id(), wait_for.port()));
    std::fs::create_dir_all(&dir).expect("dir");
    let sock = dir.join("stats.sock");
    let text = format!(
        "global\n  nbthread 1\n  stats socket {}\n\
         defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n{body}",
        sock.display()
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, _cfg: f, sock };
    assert!(common::wait_listening(wait_for), "ibex never listened on {wait_for} with:\n{text}");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !ibex.sock.exists() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    ibex
}

fn cli(ibex: &Ibex, cmd: &str) -> String {
    let mut s = UnixStream::connect(&ibex.sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// `pxname,svname,iid,sid` of every row of `show stat`.
fn stat_ids(ibex: &Ibex, cmd: &str) -> Vec<String> {
    let stat = cli(ibex, cmd);
    let mut lines = stat.lines();
    let header = lines.next().expect("a header").trim_start_matches("# ");
    let col = |name: &str| header.split(',').position(|c| c == name).expect(name);
    let (px, sv, iid, sid) = (col("pxname"), col("svname"), col("iid"), col("sid"));
    lines
        .filter(|l| !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split(',').collect();
            format!("{},{},{},{}", f[px], f[sv], f[iid], f[sid])
        })
        .collect()
}

/// `be_id be_name srv_id srv_name bk_f_forced_id srv_f_forced_id` of every server.
fn servers_state(ibex: &Ibex) -> Vec<String> {
    cli(ibex, "show servers state")
        .lines()
        .skip(2)
        .filter(|l| !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            format!("{} {} {} {} {} {}", f[0], f[1], f[2], f[3], f[15], f[16])
        })
        .collect()
}

fn get(addr: SocketAddr) -> String {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out.to_ascii_lowercase()
}

#[test]
fn proxies_are_numbered_from_2_in_declaration_order() {
    let fe = common::reserve_addr();
    let ibex = start(
        &format!(
            "frontend fe\n  bind {fe}\n  default_backend be\n\
             backend be\n  server s1 127.0.0.1:1\n\
             backend be2\n  server s1 127.0.0.1:1\n  server s2 127.0.0.1:1\n"
        ),
        fe,
    );
    assert_eq!(
        stat_ids(&ibex, "show stat"),
        ["fe,FRONTEND,2,0", "be,s1,3,1", "be,BACKEND,3,0", "be2,s1,4,1", "be2,s2,4,2", "be2,BACKEND,4,0"]
    );
    assert_eq!(
        servers_state(&ibex),
        ["3 be 1 s1 0 0", "4 be2 1 s1 0 0", "4 be2 2 s2 0 0"]
    );
    // `show stat <iid>` selects by that id.
    assert_eq!(stat_ids(&ibex, "show stat 4 -1 -1"), ["be2,s1,4,1", "be2,s2,4,2", "be2,BACKEND,4,0"]);
    // So does the name of the proxy, and `show servers state` takes either.
    assert_eq!(stat_ids(&ibex, "show stat be2"), ["be2,s1,4,1", "be2,s2,4,2", "be2,BACKEND,4,0"]);
    for who in ["be2", "4"] {
        let state = cli(&ibex, &format!("show servers state {who}"));
        let rows: Vec<&str> = state.lines().skip(2).filter(|l| !l.is_empty()).collect();
        assert_eq!(rows.len(), 2, "{who}: {state}");
        assert!(rows.iter().all(|r| r.starts_with("4 be2 ")), "{who}: {state}");
    }
    assert!(cli(&ibex, "show servers state nope").starts_with("Can't find backend."));
}

#[test]
fn a_backend_written_first_is_2() {
    let fe = common::reserve_addr();
    let ibex = start(
        &format!(
            "backend be\n  server s1 127.0.0.1:1\n\
             frontend fe\n  bind {fe}\n  default_backend be\n"
        ),
        fe,
    );
    assert_eq!(servers_state(&ibex), ["2 be 1 s1 0 0"]);
    assert_eq!(
        stat_ids(&ibex, "show stat"),
        ["be,s1,2,1", "be,BACKEND,2,0", "fe,FRONTEND,3,0"]
    );
}

#[test]
fn explicit_ids_are_kept_and_the_others_go_round_them() {
    let (fe, fe2, li) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let ibex = start(
        &format!(
            "backend be\n  server s1 127.0.0.1:1\n  server s2 127.0.0.1:1 id 7\n  server s3 127.0.0.1:1\n  server s4 127.0.0.1:1 id 2\n\
             frontend fe\n  bind {fe}\n  default_backend be\n\
             backend be2\n  id 10\n  server s1 127.0.0.1:1\n\
             frontend fe2\n  id 3\n  bind {fe2}\n\
             listen li\n  bind {li}\n  server a 127.0.0.1:1\n\
             backend be3\n  server s1 127.0.0.1:1\n"
        ),
        fe,
    );
    assert_eq!(
        stat_ids(&ibex, "show stat"),
        [
            "be,s1,2,1", "be,s2,2,7", "be,s3,2,3", "be,s4,2,2", "be,BACKEND,2,0",
            "fe,FRONTEND,4,0",
            "be2,s1,10,1", "be2,BACKEND,10,0",
            "fe2,FRONTEND,3,0",
            "li,FRONTEND,5,0", "li,a,5,1", "li,BACKEND,5,0",
            "be3,s1,6,1", "be3,BACKEND,6,0",
        ]
    );
    assert_eq!(
        servers_state(&ibex),
        [
            "2 be 1 s1 0 0",
            "2 be 7 s2 0 1",
            "2 be 3 s3 0 0",
            "2 be 2 s4 0 1",
            "10 be2 1 s1 1 0",
            "5 li 1 a 0 0",
            "6 be3 1 s1 0 0",
        ]
    );
}

#[test]
fn fe_id_be_id_and_so_id_read_the_ids() {
    let (a, b, c, d, e) = (
        common::reserve_addr(),
        common::reserve_addr(),
        common::reserve_addr(),
        common::reserve_addr(),
        common::reserve_addr(),
    );
    let (x, y) = (common::reserve_addr(), common::reserve_addr());
    let ibex = start(
        &format!(
            "frontend fe\n  bind {a} id 5\n  bind {b}\n  bind {c} id 2\n  bind {d}\n  bind {e}\n\
             \x20 http-request return status 200 hdr x-so %[so_id] hdr x-fe %[fe_id]\n\
             frontend fe2\n  bind {x}\n  bind {y}\n  default_backend be\n\
             backend be\n  http-request return status 200 hdr x-be %[be_id] hdr x-fe %[fe_id]\n"
        ),
        a,
    );
    for (addr, so) in [(a, 5), (b, 6), (c, 2), (d, 3), (e, 4)] {
        let r = get(addr);
        assert!(r.contains(&format!("x-so: {so}\r\n")), "{addr}: {r}");
        assert!(r.contains("x-fe: 2\r\n"), "{addr}: {r}");
    }
    for addr in [x, y] {
        let r = get(addr);
        assert!(r.contains("x-be: 4\r\n"), "{addr}: {r}");
        assert!(r.contains("x-fe: 3\r\n"), "{addr}: {r}");
    }
    drop(ibex);
}

/// `srv_check_health` of a server nothing checks is the `rise` of the `default-server` line
/// it was copied from, or of its own line, 0 without one; measured on the same
/// configurations.
#[test]
fn a_server_nothing_checks_reports_the_rise_of_default_server() {
    let fe = common::reserve_addr();
    let ibex = start(
        &format!(
            "defaults\n  default-server no-check rise 1 fall 1\n\
             frontend fe\n  bind {fe}\n  default_backend be1\n\
             backend be1\n  server s1 127.0.0.1:1\n  server s2 127.0.0.1:1 rise 3\n  server s3 127.0.0.1:1 disabled\n\
             backend be2\n  default-server rise 4\n  server s4 127.0.0.1:1\n"
        ),
        fe,
    );
    let state = cli(&ibex, "show servers state");
    let health: Vec<String> = state
        .lines()
        .skip(2)
        .filter(|l| !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            format!("{} {}", f[3], f[12])
        })
        .collect();
    assert_eq!(health, ["s1 1", "s2 3", "s3 0", "s4 4"]);
}

/// A frontend with no `bind` has no listener, so no listener id; one built in code with the
/// `bind` shorthand has one.
#[test]
fn listener_ids_follow_the_binds_a_frontend_has() {
    let addr = common::reserve_addr();
    let config = ibex_config::parse_str("frontend nobind\n  mode http\n").expect("parse");
    let engine = ibex_rt::engine::Engine::new(&config, 64).expect("engine");
    assert!(engine.proxies[0].ids.listener_ids.is_empty());

    let config = ibex_config::Config {
        frontends: vec![ibex_config::FrontendSection { name: "fe".into(), bind: Some(addr), ..Default::default() }],
        ..Default::default()
    };
    let engine = ibex_rt::engine::Engine::new(&config, 64).expect("engine");
    assert_eq!(engine.proxies[0].ids.listener_ids, [1]);
}
