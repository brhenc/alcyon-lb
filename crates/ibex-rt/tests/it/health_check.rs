// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use crate::common;

use ibex_config::{Config, ListenSection, Mode, Server, LogTarget};
use ibex_rt::{Engine, ServerStatus};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn health_check_detects_down_server_and_routes_to_live_server() {
    // 1. Start live backend server on a random port
    let live_listener = TcpListener::bind("127.0.0.1:0").expect("bind live backend");
    let live_addr = live_listener.local_addr().expect("local_addr");

    let live_running = Arc::new(AtomicBool::new(true));
    let live_running_clone = Arc::clone(&live_running);

    let server_thread = thread::spawn(move || {
        live_listener
            .set_nonblocking(false)
            .expect("set_nonblocking");
        while live_running_clone.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = live_listener.accept() {
                let mut buf = [0u8; 128];
                let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                if let Ok(n) = stream.read(&mut buf) {
                    if n > 0 {
                        let _ = stream.write_all(&buf[..n]);
                    }
                }
            }
        }
    });

    // 2. Pick a dead backend port where nothing listens
    let dead_addr = common::reserve_addr();

    // 3. Bind proxy listener
    let proxy_addr = common::reserve_addr();

    let config = Config {
        listens: vec![ListenSection {
            name: "lb_test".into(),
            addr: proxy_addr,
            mode: Mode::Tcp,
            contimeout: Some(Duration::from_millis(500)),
            clitimeout: Some(Duration::from_millis(2000)),
            srvtimeout: Some(Duration::from_millis(2000)),
            maxconn: 1000,
            retries: 2,
            servers: vec![
                Server {
                    check: true,
                    ..Server::new("dead_srv", dead_addr)
                },
                Server {
                    check: true,
                    ..Server::new("live_srv", live_addr)
                },
            ],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 1024).expect("Engine::new");

    // Configure faster check intervals for test speed
    for check in &mut engine.checks {
        Arc::make_mut(&mut check.config).inter = Duration::from_millis(50);
        Arc::make_mut(&mut check.config).timeout = Duration::from_millis(100);
        Arc::make_mut(&mut check.config).fall = 2;
        Arc::make_mut(&mut check.config).rise = 1;
    }

    // Run engine passes to execute health checks
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_millis(400) {
        let _ = engine.run_once().expect("engine run_once");
        thread::sleep(Duration::from_millis(10));
    }

    // Verify server statuses
    assert_eq!(
        engine.proxies[0].server_statuses[0].load(std::sync::atomic::Ordering::Relaxed), ServerStatus::Down as u8,
        "dead server should be DOWN"
    );
    assert_eq!(
        engine.proxies[0].server_statuses[1].load(std::sync::atomic::Ordering::Relaxed), ServerStatus::Up as u8,
        "live server should be UP"
    );

    // Verify select_server returns live_srv (index 1) and skips dead_srv
    let selected = engine.proxies[0].select_server();
    assert_eq!(selected, Some(live_addr));

    // Send traffic through proxy to verify proxying to live server works
    let mut client = TcpStream::connect(proxy_addr).expect("connect to proxy");
    client.write_all(b"ping").expect("send ping");

    let client_start = std::time::Instant::now();
    while client_start.elapsed() < Duration::from_millis(300) {
        let _ = engine.run_once().expect("engine run_once");
        thread::sleep(Duration::from_millis(5));
    }

    let mut reply = [0u8; 4];
    client
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set_read_timeout");
    let n = client.read(&mut reply).expect("read reply");
    assert_eq!(&reply[..n], b"ping");

    // Verify stats
    let stats_csv = engine.stats_csv(1234);
    assert!(stats_csv.contains("lb_test,live_srv"));
    assert!(stats_csv.contains("lb_test,dead_srv"));

    live_running.store(false, Ordering::Relaxed);
    let _ = TcpStream::connect(live_addr); // wake accept loop
    let _ = server_thread.join();
}

/// A server going down must reach a syslog collector.
///
/// `check::step_check` called `on_success`/`on_failure` and dropped the `CheckEvent` they
/// return, so nothing downstream ever learned a server had changed state and no datagram
/// was sent. `SyslogTarget` and `LogFormat` were both complete and unit-tested at the
/// time; neither was reachable from the engine. This drives the real path end to end --
/// config, check, event, target, socket -- because that is the only part that was missing.
#[test]
fn a_server_going_down_emits_a_syslog_datagram() {
    use ibex_config::{GlobalSection, LogConfig, LogFacility};
    use std::net::UdpSocket;

    // A collector on a random port, and a backend address nothing is listening on.
    let collector = UdpSocket::bind("127.0.0.1:0").expect("bind collector");
    // Short, so the poll loop below keeps driving the engine between reads. A timeout as
    // long as the overall budget would block the first recv for the whole test and give
    // the engine exactly one pass to work with.
    collector
        .set_read_timeout(Some(Duration::from_millis(20)))
        .expect("read timeout");
    let collector_addr = collector.local_addr().expect("collector addr");

    let dead_addr = common::reserve_addr();

    let config = Config {
        global: Some(GlobalSection {
            logs: vec![LogConfig {
                target: LogTarget::Udp(collector_addr),
                max_len: 1024,
                format: None,
                sample: None,
                facility: LogFacility::Local0,
                level: None,
            }],
            ..Default::default()
        }),
        listens: vec![ListenSection {
            name: "be_log".into(),
            addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            mode: Mode::Tcp,
            // `log global` is the form every real config uses. It was rejected outright
            // before this change: "expects <address> and <facility> as arguments".
            log_global: true,
            servers: vec![Server {
                check: true,
                ..Server::new("dead_srv", dead_addr)
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 1024).expect("Engine::new");
    for check in &mut engine.checks {
        Arc::make_mut(&mut check.config).inter = Duration::from_millis(20);
        Arc::make_mut(&mut check.config).timeout = Duration::from_millis(50);
        Arc::make_mut(&mut check.config).fall = 1;
        Arc::make_mut(&mut check.config).rise = 1;
    }

    let start = std::time::Instant::now();
    let mut buf = [0u8; 1024];
    let mut got: Option<String> = None;
    while start.elapsed() < Duration::from_millis(1500) && got.is_none() {
        let _ = engine.run_once().expect("engine run_once");
        if let Ok(n) = collector.recv(&mut buf) {
            got = Some(String::from_utf8_lossy(&buf[..n]).into_owned());
        }
        thread::sleep(Duration::from_millis(5));
    }

    let line = got.expect("no syslog datagram arrived for the server going DOWN");

    // PRI = facility 16 (local0) * 8 + severity 1 (alert) = 129. A server going DOWN is
    // logged at LOG_ALERT (src/server.c); the "Health check for server" line is written only
    // under `option log-health-checks`, which this configuration does not have (T404).
    assert!(
        line.starts_with("<129>"),
        "wrong facility/severity in {line:?}"
    );
    assert!(
        line.contains("Server be_log/dead_srv is DOWN, reason: "),
        "unexpected message body: {line:?}"
    );
    assert!(
        line.contains(". 0 active and 0 backup servers left."),
        "missing or malformed counts: {line:?}"
    );
}

/// Without a `log` directive nothing is sent, however many checks run.
///
/// The gate matters: a proxy with no target must not be paying to format a message, and
/// an operator who configured no logging must not receive any.
#[test]
fn no_log_directive_means_no_datagrams() {
    use std::net::UdpSocket;

    let collector = UdpSocket::bind("127.0.0.1:0").expect("bind collector");
    collector
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("read timeout");

    let dead_addr = common::reserve_addr();

    let config = Config {
        listens: vec![ListenSection {
            name: "be_quiet".into(),
            addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            mode: Mode::Tcp,
            servers: vec![Server {
                check: true,
                ..Server::new("dead_srv", dead_addr)
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut engine = Engine::new(&config, 1024).expect("Engine::new");
    for check in &mut engine.checks {
        Arc::make_mut(&mut check.config).inter = Duration::from_millis(20);
        Arc::make_mut(&mut check.config).timeout = Duration::from_millis(50);
        Arc::make_mut(&mut check.config).fall = 1;
    }

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_millis(300) {
        let _ = engine.run_once().expect("engine run_once");
        thread::sleep(Duration::from_millis(5));
    }

    let mut buf = [0u8; 1024];
    assert!(
        collector.recv(&mut buf).is_err(),
        "a proxy with no log directive sent a datagram"
    );
}

/// HAProxy reports a check result when the status *code* changes, independently of the
/// health counter: `set_server_check_status()` opens with
///
///     int report = (status != prev_status) ? 1 : 0;
///
/// (`src/check.c`, HAProxy 3.5-dev7) and the health-counter branches below it can only
/// raise `report`, never clear it.
///
/// That first term is what makes the very first check after boot loggable. A server with
/// `check` starts at `health == rise`, which is already full health for `rise 1 fall 1`,
/// so the counter does not move on the first success — but the status code goes from the
/// initial value to `L7OK`, and HAProxy logs it. Verified against the reference binary:
///
///     backend be1
///       option log-health-checks
///       option redis-check
///       server srv 127.0.0.1:$PORT check inter 1s rise 1 fall 1
///
///     <29>... haproxy[...]: Health check for server be1/srv succeeded, reason: Layer7
///     check passed, code: 0, info: "Redis server is ok", check duration: 0ms, status: 1/1 UP.
///
/// Without the status-code term Ibex returns `None` here and the line is never emitted,
/// which is why every reg-test in tasks/T54 asserts on a datagram that never arrives.
#[test]
fn first_check_result_is_reported_even_when_the_health_counter_does_not_move() {
    use ibex_rt::{CheckEvent, ServerCheckConfig, ServerCheckState};
    use ibex_sched::Tick;

    let config = ServerCheckConfig {
        inter: Duration::from_millis(1000),
        rise: 1,
        fall: 1,
        timeout: Duration::from_millis(2000),
        ..Default::default()
    };
    let addr: SocketAddr = "127.0.0.1:1".parse().expect("addr");
    let mut check = ServerCheckState::new(0, 0, addr, config, Tick(0));

    // `rise 1 fall 1` puts a fresh server at full health already, so the counter cannot
    // move. HAProxy still logs this one, because the status code changed.
    let event = check.on_success_full(
        "L7OK",
        "Layer7 check passed",
        0,
        None,
        Some("Redis server is ok".to_string()),
    );
    assert!(
        matches!(event, Some(CheckEvent::Succeeded | CheckEvent::WentUp)),
        "the first successful check must be reported; HAProxy logs it because the status \
         code changed, not because the health counter moved (got {event:?})"
    );
    assert_eq!(
        check.log_line("be1", "srv", event.expect("event")),
        "Health check for server be1/srv succeeded, reason: Layer7 check passed, \
         code: 0, info: \"Redis server is ok\", check duration: 0ms, status: 1/1 UP."
    );

    // A second identical result moves nothing and repeats the same status code, so
    // HAProxy stays silent: one datagram per steady state, not one per interval.
    let repeat = check.on_success_full(
        "L7OK",
        "Layer7 check passed",
        0,
        None,
        Some("Redis server is ok".to_string()),
    );
    assert!(
        repeat.is_none(),
        "an unchanged status code with an unchanged health counter must not be reported \
         (got {repeat:?})"
    );
}

/// T304: the servers of a backend share one copy of their check parameters; a server whose
/// parameters differ has its own. 60,000 checked servers used to hold 60,000 copies
/// (`request_allocations::sixty_thousand_backends_with_checks_memory_bounded`). Built in
/// code, not parsed: a parse registers resolved checks for every test in this process.
#[test]
fn the_servers_of_a_backend_share_their_check_parameters() {
    let server = |name: &str, port: u16, inter: u64| {
        let mut s = Server::new(name.to_string(), SocketAddr::from(([127, 0, 0, 1], port)));
        s.check = true;
        s.inter = Some(Duration::from_secs(inter));
        s
    };
    let config = Config {
        backends: vec![ibex_config::BackendSection {
            name: "be_share".into(),
            mode: Mode::Tcp,
            servers: vec![server("s1", 19961, 60), server("s2", 19962, 60), server("s3", 19963, 60), server("s4", 19964, 30)],
            ..Default::default()
        }],
        ..Default::default()
    };
    let engine = Engine::new(&config, 64).expect("Engine::new");
    let [a, b, c, d] = &engine.checks[..] else { panic!("four checks, got {}", engine.checks.len()) };
    assert!(Arc::ptr_eq(&a.config, &b.config) && Arc::ptr_eq(&a.config, &c.config));
    assert!(!Arc::ptr_eq(&a.config, &d.config), "s4 has its own inter");
    assert_eq!(d.config.inter, Duration::from_secs(30));
    assert_eq!((d.proxy(), d.server()), (0, 3));
    // Between checks no server holds the state of a running one.
    assert!(engine.checks.iter().all(|c| !c.run.is_held()));
}

/// The servers that share a resolved HTTP check share its compiled `http-check send`
/// log-formats too. Registered under proxy indexes no configuration in this process has.
#[test]
fn the_servers_that_share_a_resolved_check_share_its_send_formats() {
    use ibex_config::ast::{register_resolved_check, ResolvedCheckConfig, ResolvedHttpCheck};
    use ibex_rt::{ServerCheckConfig, ServerCheckState};
    let http = |uri: &str| {
        Arc::new(ResolvedCheckConfig::Http(Box::new(ResolvedHttpCheck {
            method: "GET".into(),
            uri: uri.into(),
            uri_lf: false,
            version: "HTTP/1.0".into(),
            host: None,
            headers: vec![("x-lf".into(), "%[str(a)]".into())],
            body: None,
            body_lf: false,
            has_send: true,
            send_state: false,
            pre_rules: Vec::new(),
            rules: Vec::new(),
            check_port: None,
            send_proxy: false,
            connect_addr: None,
        })))
    };
    let (shared, other) = (http("/a"), http("/b"));
    let addr = SocketAddr::from(([127, 0, 0, 1], 19965));
    // A parse elsewhere in this process clears the table; try again until none came between.
    for _ in 0..100 {
        register_resolved_check(9_001, 0, Arc::clone(&shared));
        register_resolved_check(9_001, 1, Arc::clone(&shared));
        register_resolved_check(9_001, 2, Arc::clone(&other));
        let checks: Vec<ServerCheckState> =
            (0..3).map(|i| ServerCheckState::new(9_001, i, addr, ServerCheckConfig::default(), ibex_sched::Tick(0))).collect();
        let (Some(f0), Some(f1), Some(f2)) = (&checks[0].http_send, &checks[1].http_send, &checks[2].http_send) else { continue };
        if !checks[0].resolved_config.as_ref().is_some_and(|r| Arc::ptr_eq(r, &shared)) {
            continue;
        }
        assert!(Arc::ptr_eq(f0, f1), "one compiled copy for the servers that share a check");
        assert!(!Arc::ptr_eq(f0, f2), "another check has its own");
        return;
    }
    panic!("the resolved checks were cleared on every attempt");
}
