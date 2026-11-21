// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `tcp-md5sig` on `bind` and `server` (RFC 2385), the oracle's
//! `reg-tests/connection/tcp_md5_signature.vtc`, plus the `-c` and `-cc` behaviour
//! around the key.
//!
//! The reg-test runs a proxy whose `internal` listener is bound twice, once with
//! `tcp-md5sig mypass` and once without, and a frontend that routes to four
//! servers: with the right key (200), with a wrong key (503: the connection
//! fails), to the unkeyed bind (200), and to the unkeyed bind with a key set on
//! the server (503: the keyed connect to the unkeyed listener fails).
//!
//! Every expected value was measured on `HAProxy` 3.5-dev11 (the oracle). Set
//! `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`.

use crate::common;

use std::io::{BufRead, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Output, Stdio};
use tempfile::NamedTempFile;

/// The binary under test: `alcyon`, or `HAProxy` when `T281_ORACLE` names it.
fn bin() -> String {
    std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

struct Proxy {
    child: common::Alcyon,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// Starts the binary on `conf`, its output discarded; the caller waits on a
/// plain (unkeyed) listener before using it.
fn start(conf: &str) -> Proxy {
    let mut cfg = NamedTempFile::new().unwrap();
    cfg.write_all(conf.as_bytes()).unwrap();
    let child = common::alcyon_command(&bin())
        .arg("-f")
        .arg(cfg.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    Proxy { child: common::Alcyon(child), _cfg: cfg }
}

/// The first line of the reply to `GET <path>` on `addr`, or `None` when the
/// connection does not produce a status within ten seconds.
fn status_of(addr: SocketAddr, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10)).ok()?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok()?;
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes())
        .ok()?;
    let mut line = String::new();
    std::io::BufReader::new(&stream)
        .read_line(&mut line)
        .ok()?;
    Some(line)
}

/// The reg-test, as two proxies on loopback.
#[test]
fn reg_test_topology() {
    let fe = common::reserve_addr();
    let md5_be = common::reserve_addr();
    let plain_be = common::reserve_addr();
    let conf_be = format!(
        "defaults\n mode http\n timeout client 5s\n timeout server 5s\n listen internal\n  bind {be} tcp-md5sig mypass\n  bind {plain}\n  http-request return status 200\n",
        be = md5_be,
        plain = plain_be
    );
    let conf_fe = format!(
        "defaults\n mode http\n timeout client 5s\n timeout server 5s\n timeout connect 100ms\n retries 0\n listen front\n  bind {fe}\n  use-server s1 if {{ path /s1 }}\n  use-server s2 if {{ path /s2 }}\n  use-server s3 if {{ path /s3 }}\n  use-server s4 if {{ path /s4 }}\n  server s1 {be} tcp-md5sig mypass\n  server s2 {be} tcp-md5sig badpass\n  server s3 {plain}\n  server s4 {plain} tcp-md5sig mypass\n",
        fe = fe,
        be = md5_be,
        plain = plain_be
    );
    let _be = start(&conf_be);
    let _fe = start(&conf_fe);
    // Both proxies listen on `plain_be`... the frontend waits on its own bind; the
    // backend's keyed bind cannot be probed (an unkeyed probe is dropped by the
    // kernel), so wait on its plain one.
    assert!(common::wait_listening(plain_be), "the backend proxy did not come up");
    assert!(common::wait_listening(fe), "the frontend proxy did not come up");

    let get = |path: &str| status_of(fe, path).unwrap_or_else(|| "no response".into());
    assert_eq!(get("/s1"), "HTTP/1.1 200 OK\r\n", "right key on both ends");
    assert!(get("/s2").starts_with("HTTP/1.1 5"), "wrong server key: {}", get("/s2"));
    assert_eq!(get("/s3"), "HTTP/1.1 200 OK\r\n", "no key on either end");
    assert!(get("/s4").starts_with("HTTP/1.1 5"), "keyed connect to an unkeyed bind: {}", get("/s4"));
}

/// `default-server` has no address, so `HAProxy`'s `srv_parse_tcp_md5sig`
/// stores no key in it: a server that does not set one of its own connects
/// unkeyed, and the keyed listener drops the connection (measured on the
/// oracle: 503, not 200).
#[test]
fn default_server_key_is_ignored() {
    let fe = common::reserve_addr();
    let md5_be = common::reserve_addr();
    let conf_be = format!(
        "defaults\n mode http\n timeout client 5s\n timeout server 5s\n listen internal\n  bind {be} tcp-md5sig mypass\n  http-request return status 200\n",
        be = md5_be
    );
    let conf_fe = format!(
        "defaults\n mode http\n timeout client 5s\n timeout server 5s\n timeout connect 100ms\n retries 0\n listen front\n  bind {fe}\n  default-server tcp-md5sig mypass\n  server s1 {be}\n",
        fe = fe,
        be = md5_be
    );
    let _be = start(&conf_be);
    let _fe = start(&conf_fe);
    assert!(common::wait_listening(fe), "the frontend proxy did not come up");
    let status = status_of(fe, "/").unwrap_or_else(|| "no response".into());
    assert!(
        status.starts_with("HTTP/1.1 5"),
        "the default-server key must not reach the server: {status}"
    );
}

/// `-c` with a key longer than `TCP_MD5SIG_MAXKEYLEN` (80): `HAProxy` prints the
/// alert and still exits 0 (the bind is served without the key), on a `bind` and
/// on a `server` alike. 80 characters itself is accepted.
#[test]
fn key_too_long_is_an_alert_not_an_error() {
    let fe = common::reserve_addr();
    let long = "a".repeat(81);
    let conf_bind = format!(
        "defaults\n mode http\n timeout client 5s\n listen x\n  bind {fe} tcp-md5sig {long}\n"
    );
    let out = run_check(&conf_bind);
    let err = err_of(&out);
    assert_eq!(out.status.code(), Some(0), "bind: {err}");
    assert!(
        err.contains("'tcp-md5sig' : password too long (at most 80 characters expected)"),
        "bind: {err}"
    );

    let conf_srv = format!(
        "defaults\n mode http\n timeout client 5s\n timeout server 5s\n listen x\n  bind {fe}\n  server s1 127.0.0.1:39901 tcp-md5sig {long}\n"
    );
    let out = run_check(&conf_srv);
    let err = err_of(&out);
    assert_eq!(out.status.code(), Some(0), "server: {err}");
    assert!(
        err.contains("'tcp-md5sig' : password too long (at most 80 characters expected)"),
        "server: {err}"
    );

    let ok80 = "a".repeat(80);
    let conf_ok = format!("defaults\n mode http\n timeout client 5s\n listen x\n  bind {fe} tcp-md5sig {ok80}\n");
    let out = run_check(&conf_ok);
    let err = err_of(&out);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(!err.contains("password too long"), "{err}");

    // `default-server` has no address, so the key is ignored with no length
    // check at all (measured: no alert on the oracle).
    let conf_dsr = format!(
        "defaults\n mode http\n timeout client 5s\n timeout server 5s\n listen x\n  bind {fe}\n  default-server tcp-md5sig {long}\n  server s1 127.0.0.1:39901\n"
    );
    let out = run_check(&conf_dsr);
    let err = err_of(&out);
    assert_eq!(out.status.code(), Some(0), "default-server: {err}");
    assert!(!err.contains("password too long"), "default-server: {err}");
}

/// A key with no argument is refused, and the refusal fails the load (exit 1),
/// as `HAProxy`'s `ERR_FATAL`.
#[test]
fn missing_key_fails_the_load() {
    let fe = common::reserve_addr();
    let conf_bind = format!("defaults\n mode http\n timeout client 5s\n listen x\n  bind {fe} tcp-md5sig\n");
    let out = run_check(&conf_bind);
    let err = err_of(&out);
    assert_ne!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("missing TCP MD5 signature password"), "{err}");

    let conf_srv = format!(
        "defaults\n mode http\n timeout client 5s\n timeout server 5s\n listen x\n  bind {fe}\n  server s1 127.0.0.1:39901 tcp-md5sig\n"
    );
    let out = run_check(&conf_srv);
    let err = err_of(&out);
    assert_ne!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("missing TCP MD5 signature password"), "{err}");

    let conf_dsr = format!(
        "defaults\n mode http\n timeout client 5s\n timeout server 5s\n listen x\n  bind {fe}\n  default-server tcp-md5sig\n"
    );
    let out = run_check(&conf_dsr);
    let err = err_of(&out);
    assert_ne!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("missing TCP MD5 signature password"), "{err}");
}

/// A name-based server has no address at parse time, so `HAProxy`'s
/// `srv_parse_tcp_md5sig` keeps no key for it (measured on the oracle: accepted
/// and silently ignored, with no length check even for an 81-character key).
#[test]
fn name_based_server_key_is_ignored() {
    let long = "a".repeat(81);
    let conf = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\nresolvers r1\n  nameserver ns 127.0.0.1:53\nbackend b\n  server s1 name1.example:8080 resolvers r1 init-addr none tcp-md5sig {long}\n"
    );
    let out = run_check(&conf);
    let err = err_of(&out);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(!err.contains("tcp-md5sig"), "a name-based server's key is silently ignored: {err}");
}

/// The reg-test's gate: `-cc 'feature(HAVE_WORKING_TCP_MD5SIG)'` exits 0 on
/// Linux, as `HAProxy`'s registered feature does when its probe worked; so does
/// `feature(HAVE_TCP_MD5SIG)`.
#[test]
fn feature_queries_answer_like_haproxy() {
    for expr in ["feature(HAVE_WORKING_TCP_MD5SIG)", "feature(HAVE_TCP_MD5SIG)"] {
        let status = Command::new(&bin()).arg("-cc").arg(expr).output().unwrap().status;
        assert!(status.success(), "{expr}: exit {:?}", status.code());
    }
}

/// `haproxy -c -f <conf>`, captured.
fn run_check(conf: &str) -> Output {
    let mut cfg = NamedTempFile::new().unwrap();
    cfg.write_all(conf.as_bytes()).unwrap();
    Command::new(&bin())
        .arg("-c")
        .arg("-f")
        .arg(cfg.path())
        .output()
        .unwrap()
}

/// `out.stderr` as text, for the assertions and the failure messages.
fn err_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}
