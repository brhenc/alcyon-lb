// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `server` keywords and proxy `option`s that used to parse and then do nothing (T94),
//! against the real daemon.
//!
//! Each case was run against the reference `HAProxy` 3.5-dev8-885761-29 on 2026-10-03 with
//! the same configuration, the same requests and recording backends; what it did is in the
//! doc comment of each test. The configuration-level table of every keyword is in
//! `crates/ibex-config/tests/server_keywords.rs` and `crates/ibex-config/tests/proxy_options.rs`.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn ibex_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_ibex"))
}

fn write_cfg(name: &str, body: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("ibex_t94_{}_{}", std::process::id(), name));
    std::fs::write(&p, body).expect("write config");
    p
}

/// `ibex -c -f <cfg>`: (exit code, stdout + stderr).
fn check(name: &str, cfg: &str) -> (Option<i32>, String) {
    let path = write_cfg(name, cfg);
    let out = Command::new(ibex_bin()).arg("-c").arg("-f").arg(&path).output().expect("run ibex -c");
    let _ = std::fs::remove_file(&path);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.code(), text)
}

struct Daemon(Child, std::path::PathBuf);

impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_file(&self.1);
    }
}

fn start(name: &str, cfg: &str, port: u16) -> Daemon {
    let path = write_cfg(name, cfg);
    let child = Command::new(ibex_bin())
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let d = Daemon(child, path);
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the daemon never listened on {port}");
        thread::sleep(Duration::from_millis(25));
    }
    d
}

/// A backend that records the head of every request it is handed and answers 200.
struct Backend {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Backend {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
        let port = listener.local_addr().expect("addr").port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        thread::spawn(move || {
            for c in listener.incoming() {
                let Ok(mut c) = c else { return };
                c.set_read_timeout(Some(Duration::from_millis(500))).ok();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut tmp) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
                        _ => break,
                    }
                }
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                sink.lock().expect("lock").push(String::from_utf8_lossy(&buf).into_owned());
            }
        });
        Self { port, seen }
    }

    fn requests(&self) -> Vec<String> {
        self.seen.lock().expect("lock").clone()
    }
}

/// Sends one request on its own connection; returns the status line.
fn get(port: u16, path: &str, extra: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 6.6.6.6\r\n{extra}Connection: close\r\n\r\n").expect("write");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).lines().next().unwrap_or("").to_string()
}

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 3s\n  timeout server 3s\n";

/// The task's configuration. `HAProxy` connects to the server with TLS and verifies its
/// certificate; Ibex has no TLS towards servers, loaded this, said it was valid, and
/// connected in plaintext.
#[test]
fn ibex_c_refuses_a_server_it_would_reach_in_plaintext() {
    let (code, text) = check(
        "tls.cfg",
        &format!("{DEFAULTS}backend b\n  server s1 10.0.0.1:443 ssl verify required ca-file ca.pem alpn h2\n"),
    );
    assert_ne!(code, Some(0), "`ibex -c` accepted a TLS server line; Ibex would connect in plaintext:\n{text}");
    assert!(text.contains("'ssl'"), "the error must name the keyword:\n{text}");
}

/// A tuning keyword is accepted, and the operator is told it does nothing.
/// `HAProxy` 3.5-dev8: `server s1 ... slowstart 10s` is valid.
#[test]
fn ibex_c_warns_about_a_tuning_keyword_it_ignores() {
    let (code, text) = check("slowstart.cfg", &format!("{DEFAULTS}backend b\n  server s1 127.0.0.1:8080 slowstart 10s\n"));
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("warning") && text.contains("slowstart"),
        "`slowstart` is ignored, and nothing said so:\n{text}"
    );
}

/// `default-server send-proxy` and `server a ... no-send-proxy`. `HAProxy`: the request
/// reaches `a` with no PROXY line (`GET /0 HTTP/1.1` first). Ibex sent `PROXY TCP4 ...`.
#[test]
fn no_send_proxy_overrides_default_server_send_proxy() {
    let a = Backend::spawn();
    let port = common::reserve_port();
    let _d = start(
        "nosendproxy.cfg",
        &format!(
            "{DEFAULTS}frontend f\n  bind 127.0.0.1:{port}\n  default_backend be\n\
             backend be\n  default-server send-proxy\n  server a 127.0.0.1:{} no-send-proxy\n",
            a.port
        ),
        port,
    );
    assert!(get(port, "/", "").contains("200"));
    let reqs = a.requests();
    assert_eq!(reqs.len(), 1, "{reqs:?}");
    assert!(reqs[0].starts_with("GET / "), "`no-send-proxy` was ignored; the server received {:?}", reqs[0]);
}

/// Control for the test above: without `no-send-proxy`, the PROXY line is sent.
#[test]
fn default_server_send_proxy_is_inherited() {
    let a = Backend::spawn();
    let port = common::reserve_port();
    let _d = start(
        "sendproxy.cfg",
        &format!(
            "{DEFAULTS}frontend f\n  bind 127.0.0.1:{port}\n  default_backend be\n\
             backend be\n  default-server send-proxy\n  server a 127.0.0.1:{}\n",
            a.port
        ),
        port,
    );
    assert!(get(port, "/", "").contains("200"));
    let reqs = a.requests();
    assert!(reqs.first().is_some_and(|r| r.starts_with("PROXY TCP4 ")), "{reqs:?}");
}

/// `server a ... cookie backup` and `server b ...`, `balance roundrobin`. `HAProxy` reads
/// "backup" as the cookie value: `a` is an active server and takes requests (4 of 4, and 3
/// of 4 with no `cookie` at all, under its multi-threaded round robin). Ibex dropped
/// `cookie`, read `backup` as a keyword, and sent every request to `b`.
#[test]
fn a_keyword_argument_is_not_read_as_a_keyword() {
    let (a, b) = (Backend::spawn(), Backend::spawn());
    let port = common::reserve_port();
    let _d = start(
        "cookiebackup.cfg",
        &format!(
            "{DEFAULTS}frontend f\n  bind 127.0.0.1:{port}\n  default_backend be\n\
             backend be\n  balance roundrobin\n  server a 127.0.0.1:{} cookie backup\n  server b 127.0.0.1:{}\n",
            a.port, b.port
        ),
        port,
    );
    for i in 0..4 {
        assert!(get(port, &format!("/{i}"), "").contains("200"));
    }
    assert!(
        !a.requests().is_empty(),
        "server `a` took no request: `cookie backup` made it a backup server. b got {}",
        b.requests().len()
    );
}

/// `cookie SRV` and `server a ... cookie A`, `server b ... cookie B`, in a listen section.
/// `HAProxy`: `Cookie: SRV=B` sends 4 of 4 requests to `b`; `Cookie: SRV=b` (the server's
/// name, not its cookie) matches nothing and is load-balanced (3 to `a`, 1 to `b`). Ibex
/// ignored the server's `cookie` and matched the cookie against server names.
#[test]
fn a_server_cookie_value_is_what_persistence_matches() {
    for (cookie, all_to_b) in [("SRV=B", true), ("SRV=b", false)] {
        let (a, b) = (Backend::spawn(), Backend::spawn());
        let port = common::reserve_port();
        let _d = start(
            "cookievalue.cfg",
            &format!(
                "{DEFAULTS}listen l\n  bind 127.0.0.1:{port}\n  balance roundrobin\n  cookie SRV\n\
                 server a 127.0.0.1:{} cookie A\n  server b 127.0.0.1:{} cookie B\n",
                a.port, b.port
            ),
            port,
        );
        for i in 0..4 {
            assert!(get(port, &format!("/{i}"), &format!("Cookie: {cookie}\r\n")).contains("200"));
        }
        let (na, nb) = (a.requests().len(), b.requests().len());
        if all_to_b {
            assert_eq!((na, nb), (0, 4), "`Cookie: {cookie}` must stick to the server whose cookie is B");
        } else {
            assert!(na > 0, "`Cookie: {cookie}` names a server, not a cookie value, and must not stick: a={na} b={nb}");
        }
    }
}

fn xff_values(req: &str) -> Vec<String> {
    req.lines()
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| k.trim().eq_ignore_ascii_case("x-forwarded-for"))
        .map(|(_, v)| v.trim().to_string())
        .collect()
}

/// `option forwardfor` in `defaults`, and in a frontend whose backend has none. `HAProxy`
/// adds `x-forwarded-for: 127.0.0.1` after the client's own `6.6.6.6` in both cases. Ibex
/// ignored the option in `defaults` (with a warning) and dropped it in a frontend (in
/// silence), so the server saw only the address the client claimed. Control: with the
/// option nowhere, the server sees only `6.6.6.6`, in `HAProxy` and in Ibex.
#[test]
fn option_forwardfor_in_defaults_and_in_a_frontend_reaches_the_server() {
    let cases = [
        ("defaults", format!("{DEFAULTS}  option forwardfor\n"), "", true),
        ("frontend", DEFAULTS.to_string(), "  option forwardfor\n", true),
        ("nowhere", DEFAULTS.to_string(), "", false),
    ];
    for (place, defaults, fe_opt, expect) in cases {
        let a = Backend::spawn();
        let port = common::reserve_port();
        let _d = start(
            "forwardfor.cfg",
            &format!(
                "{defaults}frontend f\n  bind 127.0.0.1:{port}\n{fe_opt}  default_backend be\n\
                 backend be\n  server a 127.0.0.1:{}\n",
                a.port
            ),
            port,
        );
        assert!(get(port, "/", "").contains("200"));
        let reqs = a.requests();
        let xff = xff_values(&reqs[0]);
        if expect {
            assert!(
                xff.iter().any(|v| v == "127.0.0.1"),
                "`option forwardfor` in {place}: the server must learn the client's address; it saw {xff:?}"
            );
        } else {
            assert_eq!(xff, ["6.6.6.6"], "no forwardfor anywhere: the header passes through untouched");
        }
    }
}

/// `option originalto` in a frontend whose backend has none. `HAProxy` 3.5-dev8
/// (2026-10-03) adds `x-original-to: 127.0.0.1`, the address the client connected to.
/// Ibex read the option from the backend only, and sent nothing.
#[test]
fn option_originalto_in_a_frontend_reaches_the_server() {
    let a = Backend::spawn();
    let port = common::reserve_port();
    let _d = start(
        "originalto.cfg",
        &format!(
            "{DEFAULTS}frontend f\n  bind 127.0.0.1:{port}\n  option originalto\n  default_backend be\n\
             backend be\n  server a 127.0.0.1:{}\n",
            a.port
        ),
        port,
    );
    assert!(get(port, "/", "").contains("200"));
    let reqs = a.requests();
    assert!(
        reqs[0].to_ascii_lowercase().contains("x-original-to: 127.0.0.1"),
        "`option originalto` in the frontend did not reach the server: {:?}",
        reqs[0]
    );
}

/// `option redispatch` in `defaults`, `retries 1`, a dead first server. `HAProxy`: 4 of 4
/// requests answered 200 by the live server. Ibex ignored the option in `defaults` and
/// answered 503 to every request that was first sent to the dead server.
#[test]
fn option_redispatch_in_defaults_is_inherited() {
    let a = Backend::spawn();
    let dead = common::reserve_port();
    let port = common::reserve_port();
    let _d = start(
        "redispatch.cfg",
        &format!(
            "{DEFAULTS}  option redispatch\nfrontend f\n  bind 127.0.0.1:{port}\n  default_backend be\n\
             backend be\n  balance roundrobin\n  retries 1\n  server dead 127.0.0.1:{dead}\n  server a 127.0.0.1:{}\n",
            a.port
        ),
        port,
    );
    let statuses: Vec<String> = (0..4).map(|i| get(port, &format!("/{i}"), "")).collect();
    assert!(
        statuses.iter().all(|s| s.contains("200")),
        "`option redispatch` from defaults did not move the retry off the dead server: {statuses:?}"
    );
}

/// An option that changes what reaches the server is refused rather than ignored.
/// `HAProxy` 3.5-dev8 accepts `option forwarded` in a backend and adds a `forwarded`
/// header; Ibex has no RFC 7239 support, and the server would see only what the client
/// sent. A tuning option is accepted with a warning.
#[test]
fn ibex_c_refuses_an_option_it_cannot_honour_and_warns_about_tuning() {
    let (code, text) = check("forwarded.cfg", &format!("{DEFAULTS}backend b\n  option forwarded\n  server s1 127.0.0.1:8080\n"));
    assert_ne!(code, Some(0), "`option forwarded` was accepted and would do nothing:\n{text}");
    assert!(text.contains("'forwarded'") || text.contains("option forwarded"), "{text}");

    let (code, text) = check("tcpka.cfg", &format!("{DEFAULTS}backend b\n  option srvtcpka\n  server s1 127.0.0.1:8080\n"));
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("warning") && text.contains("srvtcpka"), "{text}");
}
