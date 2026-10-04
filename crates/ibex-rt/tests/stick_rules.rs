// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `stick on`, `stick match`, `stick store-request` and `stick store-response` against the
//! real binary (T149).
//!
//! Every expected sequence was measured on HAProxy 3.5-dev8-885761-29 (`nbthread 1`,
//! `balance roundrobin` over three servers `s1 s2 s3`, one request per connection, the
//! server that answered named in `x-srv`). Without a rule the sequence is s1 s2 s3 s1 s2
//! s3. In what the numbers say:
//! - a `stick match` that finds its key sends the request to the server stored with it,
//!   and does not use up a turn of the round robin;
//! - `stick on` stores the key with the server that answered (`store-request`), at the
//!   response, so a request a `use-server` sent elsewhere stores that server;
//! - `store-response` stores a key read from the response;
//! - a rule's condition decides whether the rule runs at all;
//! - after a `stick on` or `store-request` rule has a key for a table, the next such rule
//!   for that table is skipped whole, its match included.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// Three HTTP servers: each answers with `x-srv` (its name) and `x-id: id-<name>`.
fn http_servers() -> [SocketAddr; 3] {
    ["s1", "s2", "s3"].map(|name| {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = l.local_addr().expect("addr");
        thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = s.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        let rsp = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Srv: {name}\r\nX-Id: id-{name}\r\n\r\n");
                        if s.write_all(rsp.as_bytes()).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        addr
    })
}

/// Three TCP servers that say their name when a client connects.
fn tcp_servers() -> [SocketAddr; 3] {
    ["s1", "s2", "s3"].map(|name| {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = l.local_addr().expect("addr");
        thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let _ = s.write_all(name.as_bytes());
            }
        });
        addr
    })
}

struct Ibex(Child, NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(cfg: &str, fe: SocketAddr) -> Ibex {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
        thread::sleep(Duration::from_millis(20));
    }
    Ibex(child, f)
}

const HEAD: &str = "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n";
const TABLE: &str = "  stick-table type string len 16 size 1k expire 1m\n";

fn servers(s: &[SocketAddr; 3]) -> String {
    format!("  server s1 {}\n  server s2 {}\n  server s3 {}\n", s[0], s[1], s[2])
}

/// A `listen` with `rules` and the three servers; the server each request reached.
fn run_listen(rules: &str, reqs: &[&str]) -> Vec<String> {
    run_listen_named("l", rules, reqs)
}

fn run_listen_named(name: &str, rules: &str, reqs: &[&str]) -> Vec<String> {
    let s = http_servers();
    let fe = common::reserve_addr();
    run_cfg(&format!("{HEAD}listen {name}\n  bind {fe}\n  balance roundrobin\n{rules}{}", servers(&s)), fe, reqs)
}

fn run_cfg(cfg: &str, fe: SocketAddr, reqs: &[&str]) -> Vec<String> {
    let _ibex = start(cfg, fe);
    reqs.iter()
        .map(|extra| {
            let mut c = TcpStream::connect(fe).expect("connect");
            c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            c.write_all(format!("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{extra}\r\n").as_bytes()).unwrap();
            let mut resp = Vec::new();
            let mut buf = [0u8; 4096];
            while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => resp.extend_from_slice(&buf[..n]),
                }
            }
            let resp = String::from_utf8_lossy(&resp).to_ascii_lowercase();
            thread::sleep(Duration::from_millis(50));
            resp.split("x-srv: ").nth(1).map_or_else(|| format!("no answer: {resp:?}"), |r| r[..2].to_string())
        })
        .collect()
}

const A: &str = "X-User: a\r\n";
const B: &str = "X-User: b\r\n";

#[test]
fn without_a_rule_the_servers_take_turns() {
    assert_eq!(run_listen("", &[A, A, A, B, B, A]), ["s1", "s2", "s3", "s1", "s2", "s3"]);
}

#[test]
fn stick_on_sends_a_key_back_to_the_server_that_answered_it() {
    let rules = format!("{TABLE}  stick on hdr(x-user)\n");
    assert_eq!(run_listen(&rules, &[A, A, A, B, B, A]), ["s1", "s1", "s1", "s2", "s2", "s1"]);
}

#[test]
fn stick_match_alone_stores_nothing() {
    let rules = format!("{TABLE}  stick match hdr(x-user)\n");
    assert_eq!(run_listen(&rules, &[A, A, A, B, B, A]), ["s1", "s2", "s3", "s1", "s2", "s3"]);
}

#[test]
fn a_table_is_shared_with_table_and_a_match_takes_no_turn() {
    let s = http_servers();
    let fe = common::reserve_addr();
    let cfg = format!(
        "{HEAD}frontend f\n  bind {fe}\n  use_backend b2 if {{ hdr(x-be) b2 }}\n  default_backend b1\n\
         backend b1\n  balance roundrobin\n{TABLE}  stick store-request hdr(x-user)\n{}\
         backend b2\n  balance roundrobin\n  stick match hdr(x-user) table b1\n{}",
        servers(&s),
        servers(&s)
    );
    let c = "X-User: c\r\nX-Be: b2\r\n";
    let got = run_cfg(&cfg, fe, &[A, B, "X-User: a\r\nX-Be: b2\r\n", "X-User: b\r\nX-Be: b2\r\n", c, c]);
    assert_eq!(got, ["s1", "s2", "s1", "s2", "s1", "s2"]);
}

#[test]
fn store_response_keys_a_response_header_to_the_server_that_sent_it() {
    let rules = format!("{TABLE}  stick match hdr(x-sess)\n  stick store-response res.hdr(x-id)\n");
    let got = run_listen(
        &rules,
        &["", "", "X-Sess: id-s2\r\n", "X-Sess: id-s1\r\n", "X-Sess: id-s2\r\n", "X-Sess: id-s1\r\n"],
    );
    assert_eq!(got, ["s1", "s2", "s2", "s1", "s2", "s1"]);
}

#[test]
fn a_condition_decides_whether_the_rule_runs() {
    let on = "X-User: a\r\nX-Sticky: 1\r\n";
    let rules = format!("{TABLE}  stick on hdr(x-user) if {{ hdr(x-sticky) -m found }}\n");
    assert_eq!(run_listen(&rules, &[on, A, on, A, on]), ["s1", "s2", "s1", "s3", "s1"]);
    let off = "X-User: a\r\nX-Nosticky: 1\r\n";
    let rules = format!("{TABLE}  stick on hdr(x-user) unless {{ hdr(x-nosticky) -m found }}\n");
    assert_eq!(run_listen(&rules, &[A, off, A, off, A]), ["s1", "s2", "s1", "s3", "s1"]);
}

/// The second `stick on` is skipped whole once the first has a key for the table, even
/// when only the second would find its key: `s3` at the third request.
#[test]
fn a_second_stick_on_for_a_table_is_skipped_once_the_first_has_a_key() {
    let rules = format!("{TABLE}  stick on hdr(x-user)\n  stick on hdr(x-alt)\n");
    let alt = "X-Alt: k\r\n";
    let both = "X-User: zz\r\nX-Alt: k\r\n";
    let fresh = "X-User: new\r\nX-Alt: k\r\n";
    assert_eq!(run_listen(&rules, &[alt, A, both, A, fresh, alt]), ["s1", "s2", "s3", "s2", "s1", "s1"]);
}

#[test]
fn use_server_decides_and_the_key_is_stored_with_the_server_that_answered() {
    let rules = format!("{TABLE}  stick on hdr(x-user)\n  use-server s2 if {{ hdr(x-force) -m found }}\n");
    let force_a = "X-User: a\r\nX-Force: 1\r\n";
    let force_q = "X-User: q\r\nX-Force: 1\r\n";
    let q = "X-User: q\r\n";
    assert_eq!(run_listen(&rules, &[A, force_a, A, force_q, q]), ["s1", "s2", "s2", "s2", "s2"]);
}

/// The key is the address the client connected to (two `bind` addresses stand for two
/// clients); the server says its name when the connection opens.
#[test]
fn stick_on_in_tcp_mode_sticks_a_key() {
    let s = tcp_servers();
    let fe = common::reserve_addr();
    let fe2 = SocketAddr::new("127.0.0.2".parse().unwrap(), fe.port());
    let cfg = format!(
        "global\n  nbthread 1\ndefaults\n  mode tcp\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         listen l\n  bind {fe}\n  bind {fe2}\n  balance roundrobin\n  stick-table type ip size 1k expire 1m\n  stick on dst\n{}",
        servers(&s)
    );
    let _ibex = start(&cfg, fe);
    let mut got = Vec::new();
    for addr in [fe, fe2, fe, fe2, fe] {
        let mut c = TcpStream::connect(addr).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut buf = [0u8; 8];
        let n = c.read(&mut buf).unwrap_or(0);
        got.push(String::from_utf8_lossy(&buf[..n]).to_string());
        thread::sleep(Duration::from_millis(50));
    }
    // The readiness probe of `start` took s1 and closed at once: HAProxy stores nothing for
    // it either (measured with the same probe).
    assert_eq!(got, ["s2", "s3", "s2", "s3", "s2"]);
}

/// `ibex -c` on a configuration with `rules` in a backend: the refusal, if any.
fn check(mode: &str, rules: &str) -> Result<(), String> {
    let mut f = NamedTempFile::new().expect("tmp");
    let cfg = format!(
        "defaults\n  mode {mode}\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind 127.0.0.1:0\n  default_backend b\nbackend b\n{rules}  server s1 127.0.0.1:1\n"
    );
    f.write_all(cfg.as_bytes()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run ibex");
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
    }
}

#[test]
fn what_cannot_work_is_refused_at_load() {
    let t = "  stick-table type ip size 1k\n";
    let refused = |mode: &str, rules: &str, why: &str| {
        let e = check(mode, rules).expect_err(&format!("{rules:?} loaded"));
        assert!(e.contains(why), "{rules:?}: wanted {why:?} in {e:?}");
    };
    refused("http", &format!("{t}  stick on nosuch\n"), "unknown fetch method 'nosuch'");
    refused("http", &format!("{t}  stick match src,nosuchconv\n"), "unknown converter 'nosuchconv'");
    refused("http", &format!("{t}  stick store-request nosuch\n"), "unknown fetch method 'nosuch'");
    refused("http", &format!("{t}  stick store-response nosuch\n"), "unknown fetch method 'nosuch'");
    refused("http", "  stick on src\n", "unable to find stick-table 'b'");
    refused("http", &format!("{t}  stick on src table nosuch\n"), "unable to find stick-table 'nosuch'");
    refused("http", &format!("{t}  stick on src foo\n"), "unknown keyword 'foo'");
    refused("http", &format!("{t}  stick on\n"), "expects a fetch method");
    refused("http", &format!("{t}  stick foo src\n"), "expects 'on', 'match', or 'store'");
    // The response is not inspected in TCP mode, so a key from it could not be stored.
    refused("tcp", &format!("{t}  stick store-response src\n"), "stick store-response");
    refused("http", &format!("{t}  stick\n"), "expects 'on', 'match', or 'store'");
    check("http", &format!("{t}  stick on src\n  stick store-response res.hdr(x)\n")).expect("valid rules refused");
    check("http", &format!("{t}  track-sc0 src\n  stick on src\n")).expect("track-sc0 beside stick refused");
}

/// `store-response` with a named table, a false condition and a second rule for the same
/// table (skipped), then the same table by name from a match (measured: s1 s2 s2 s1).
#[test]
fn store_response_rules_with_a_table_a_condition_and_a_second_rule() {
    let rules = format!(
        "{TABLE}  stick match hdr(x-sess)\n  stick store-response res.hdr(x-id) table b if {{ res.hdr(x-never) -m found }}\n\
         stick store-response res.hdr(x-id) table b\n  stick store-response res.hdr(nosuch)\n"
    );
    let got = run_listen_named("b", &rules, &["", "", "X-Sess: id-s2\r\n", "X-Sess: id-s1\r\n"]);
    assert_eq!(got, ["s1", "s2", "s2", "s1"]);
}

/// A `table` naming a disabled backend: Ibex builds no table for it, so the rules that use
/// it do nothing and the servers keep taking turns. (Not measured on HAProxy: the same
/// configuration does not even listen there.)
#[test]
fn a_table_of_a_disabled_backend_is_no_table() {
    let s = http_servers();
    let fe = common::reserve_addr();
    let cfg = format!(
        "{HEAD}frontend f\n  bind {fe}\n  default_backend b\n\
         backend t\n  disabled\n{TABLE}  server s1 {}\n\
         backend b\n  balance roundrobin\n  stick on hdr(x-user) table t\n  stick store-response res.hdr(x-id) table t\n{}",
        s[0],
        servers(&s)
    );
    assert_eq!(run_cfg(&cfg, fe, &[A, A, A, A]), ["s1", "s2", "s3", "s1"]);
}
