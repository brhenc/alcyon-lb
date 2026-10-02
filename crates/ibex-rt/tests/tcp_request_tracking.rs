// SPDX-License-Identifier: GPL-2.0-or-later

//! Who decides that a client is tracked in a stick table.
//!
//! In `HAProxy` the answer is: a `track-sc` rule, and nothing else. A table with no rule
//! pointing at it stays empty, and the rules are the only thing that writes to it.
//!
//! Ibex used to answer differently. The engine counted into any table it found on the
//! proxy -- unconditionally in `connect_http_backend`, and behind
//! `if tcp_req_conn_rules.is_empty()` and `if http_req_rules.is_empty()` in two more
//! places, the second under a comment calling itself "fallback default tracking".
//! Meanwhile `Proxy::stick_rules` was populated from three config sections and never read.
//! Every `track-sc` form was decorative: the counters in `show table` were the engine
//! counting by itself.
//!
//! Three consequences followed, and the tests below are one apiece:
//!
//! 1. A table was populated for clients nobody asked to track -- an attacker-driven
//!    allocation on any frontend that declared a table for any reason.
//! 2. Adding an unrelated `http-request` rule switched the counting off, so a rate limit
//!    stopped working because somebody added a header.
//! 3. A test asserting `conn_cnt=3` after configuring `track-sc0` passed whether or not
//!    tracking was implemented, so the coverage did not hold the feature down.
//!
//! All three are fixed. These tests exist to keep them fixed: each one distinguishes
//! "the rule tracked" from "something tracked", which is the distinction that was missing.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ibex_config::ast::{
    BackendSection, Config, FrontendSection, HttpReqAction, HttpReqRule, Mode, Server,
    StickRule, StickRuleType, StickTableConfigAst, TcpReqContentAction, TcpReqContentRule,
};
use ibex_rt::engine::Engine;


fn start_dummy_backend(
    addr: SocketAddr,
    running: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let listener = TcpListener::bind(addr).expect("bind dummy srv");
        listener.set_nonblocking(true).expect("nonblocking");
        while running.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if req.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                let _ = stream.flush();
            }
            thread::sleep(Duration::from_millis(2));
        }
    })
}

fn table_config() -> StickTableConfigAst {
    StickTableConfigAst {
        key_type: "ip".into(),
        size: 1000,
        expire: Duration::from_secs(60),
        store_fields: vec![
            "conn_cnt".into(),
            "conn_cur".into(),
            "conn_rate(10s)".into(),
            "http_req_cnt".into(),
            "http_req_rate(10s)".into(),
        ],
    }
}

/// Drives `requests` requests through `frontend` and returns what `show table` reports.
fn run_and_show_table(frontend: FrontendSection, fe_addr: SocketAddr, requests: usize) -> String {
    let srv_addr = common::reserve_addr();
    let running = Arc::new(AtomicBool::new(true));
    let backend = start_dummy_backend(srv_addr, Arc::clone(&running));

    let config = Config {
        frontends: vec![frontend],
        backends: vec![BackendSection {
            name: "be_track".into(),
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(3)),
            srvtimeout: Some(Duration::from_secs(3)),
            servers: vec![Server::new("s1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 64).expect("Engine::new");
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let cli_sock_path = temp_dir.path().join("ibex.sock");
    engine
        .bind_cli_socket(&cli_sock_path)
        .expect("bind_cli_socket");

    for _ in 0..requests {
        let mut client = TcpStream::connect(fe_addr).expect("connect to frontend");
        client.set_nonblocking(true).expect("set_nonblocking");
        client
            .write_all(b"GET /api/test HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("write req");

        let start = Instant::now();
        let mut response = Vec::new();
        let mut buf = [0u8; 1024];
        while start.elapsed() < Duration::from_secs(2) {
            let _ = engine.run_once().expect("engine step");
            if let Ok(n) = client.read(&mut buf) {
                if n > 0 {
                    response.extend_from_slice(&buf[..n]);
                    if response.windows(4).any(|w| w == b"\r\n\r\n") && response.len() > 20 {
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    for _ in 0..10 {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(2));
    }

    let mut cli = UnixStream::connect(&cli_sock_path).expect("connect to cli socket");
    cli.set_nonblocking(true).expect("set_nonblocking cli");
    cli.write_all(b"show table\n").expect("write show table");

    let start = Instant::now();
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    while start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once().expect("engine step");
        if let Ok(n) = cli.read(&mut buf) {
            if n > 0 {
                out.extend_from_slice(&buf[..n]);
                break;
            }
        }
        thread::sleep(Duration::from_millis(2));
    }

    running.store(false, Ordering::Relaxed);
    let _ = backend.join();
    String::from_utf8_lossy(&out).into_owned()
}

/// Returns the entry lines of a `show table` dump, excluding the `# table:` header.
fn entries(dump: &str) -> Vec<&str> {
    dump.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with("# table:"))
        .collect()
}

/// Reads a counter out of a `show table` entry, e.g. `http_req_rate(10000)=3` -> 3.
///
/// Matched by prefix because the rate fields carry their window in the name, and the
/// window is not what is under test here.
fn counter(dump: &str, name: &str) -> Option<u64> {
    let at = dump.find(name)?;
    let eq = dump[at..].find('=')? + at + 1;
    let digits: String = dump[eq..].chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// A stick table with no `track-sc` rule pointing at it must stay empty.
///
/// A table is often declared for one purpose -- a `stick-table` shared by a peers section,
/// or one a single backend consults -- and `HAProxy` writes to it only where a rule says
/// to. Ibex creates an entry per client regardless, so declaring a table anywhere turns
/// every frontend using that proxy into a per-source-IP allocator driven by whoever
/// connects. At the connection rates this project is built for, who is allowed to make
/// the daemon allocate is the whole question.
#[test]
fn a_stick_table_is_not_populated_without_a_tracking_rule() {
    let fe_addr = common::reserve_addr();
    let dump = run_and_show_table(
        FrontendSection {
            name: "fe_untracked".into(),
            bind: Some(fe_addr),
            mode: Mode::Http,
            clitimeout: Some(Duration::from_secs(3)),
            default_backend: Some("be_track".into()),
            stick_table: Some(table_config()),
            // Deliberately no stick_rules and no tcp-request rules of any kind.
            ..Default::default()
        },
        fe_addr,
        3,
    );

    assert!(
        dump.contains("# table: fe_untracked"),
        "the table was not declared at all:\n{dump}"
    );
    assert!(
        entries(&dump).is_empty(),
        "a stick table with no tracking rule was populated anyway. The engine counts into \
         any table it finds on the proxy, so a declared table becomes an attacker-driven \
         allocation whether or not the configuration asked to track anything. \
         `show table` said:\n{dump}"
    );
}

/// Tracking must not be switched off by an unrelated rule.
///
/// `http_req_cnt` is only incremented under `if proxies[proxy_idx].http_req_rules
/// .is_empty()`, so this configuration -- a `track-sc0` rule and one `set-header` that has
/// nothing to do with it -- stops counting requests. An operator adding a header to a
/// frontend silently disables the counter their rate limit is built on, and nothing in
/// the configuration, the logs or `show table` says why.
///
/// This is the test that shows the counters are not coming from the tracking rule. The
/// rule is present and unchanged in both cases; only the unrelated rule differs.
#[test]
fn an_unrelated_http_request_rule_does_not_switch_off_tracking() {
    let fe_addr = common::reserve_addr();
    let tracked = || FrontendSection {
        name: "fe_track".into(),
        bind: Some(fe_addr),
        mode: Mode::Http,
        clitimeout: Some(Duration::from_secs(3)),
        default_backend: Some("be_track".into()),
        stick_table: Some(table_config()),
        stick_rules: vec![StickRule {
            rule_type: StickRuleType::TrackSc0,
            expr: "src".into(),
        }],
        ..Default::default()
    };

    // Baseline: the tracking rule alone. This is what the existing coverage asserts.
    let without = run_and_show_table(tracked(), fe_addr, 3);
    assert_eq!(
        counter(&without, "http_req_rate"),
        Some(3),
        "the baseline did not count three requests, so this test cannot say anything \
         about what the extra rule changes:\n{without}"
    );

    // The same tracking rule, plus one rule that has nothing to do with tracking.
    let fe_addr2 = common::reserve_addr();
    let mut with_header = tracked();
    with_header.bind = Some(fe_addr2);
    with_header.http_req_rules = vec![HttpReqRule {
        action: HttpReqAction::SetHeader {
            name: "X-Unrelated".into(),
            fmt: "1".into(),
        },
        cond: None,
    }];
    let with = run_and_show_table(with_header, fe_addr2, 3);

    assert_eq!(
        counter(&with, "http_req_rate"),
        Some(3),
        "adding an unrelated `http-request set-header` rule stopped the stick table \
         counting requests. The HTTP counters are incremented only when `http_req_rules` \
         is empty, so the counter a rate limit depends on is switched off by any rule \
         added to the frontend for any reason. `show table` said:\n{with}"
    );
}

/// `track-sc0` at content scope must track, like `track-sc0` everywhere else.
///
/// The connection-scope evaluator and the legacy `stick_rules` path both track now. The
/// content-scope evaluator still ends its match with `_ => {}`, which swallows
/// `track-sc0`, `track-sc1`, `track-sc2`, `sc-inc-gpc0`, `do-log`, `use-service`,
/// `attach-srv` and `lua.*`.
///
/// This test is deliberately configured with no `stick_rules` at all, so the only thing
/// that could populate the table is the content rule. While the implicit tracking existed
/// this could not be written -- the table filled either way. Now that it is gone, the
/// question is answerable.
///
/// Either implement these actions or refuse them in `parse_tcp_req_content`. A rate limit
/// that parses cleanly and enforces nothing is the one outcome worse than not having the
/// keyword at all.
#[test]
fn track_sc0_at_content_scope_populates_the_stick_table() {
    let fe_addr = common::reserve_addr();
    let dump = run_and_show_table(
        FrontendSection {
            name: "fe_content_track".into(),
            bind: Some(fe_addr),
            mode: Mode::Http,
            clitimeout: Some(Duration::from_secs(3)),
            default_backend: Some("be_track".into()),
            stick_table: Some(table_config()),
            // No stick_rules: the content rule is the only thing that could track.
            tcp_req_content_rules: vec![TcpReqContentRule {
                action: TcpReqContentAction::TrackSc0 {
                    expr: "src".into(),
                    table: None,
                },
                cond: None,
            }],
            ..Default::default()
        },
        fe_addr,
        3,
    );

    assert!(
        dump.contains("# table: fe_content_track"),
        "the table was not declared at all:\n{dump}"
    );
    assert!(
        !entries(&dump).is_empty(),
        "`tcp-request content track-sc0 src` created no stick-table entry after three \
         requests. The action is parsed, validated against the table it names, stored on \
         the proxy -- and then dropped by the `_ => {{}}` arm of the content evaluator. \
         `show table` said:\n{dump}"
    );
}
