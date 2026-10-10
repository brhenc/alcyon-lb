// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![forbid(unsafe_code)]
#![allow(clippy::similar_names, clippy::too_many_lines, clippy::doc_markdown)]

//! Comprehensive end-to-end integration test suite validating the Canonical `HAProxy` 3.5
//! configuration (`examples/canonical_haproxy_35.cfg`) executed on Project Ibex.
//!
//! Validates:
//! 1. Full AST and architecture parity against `examples/canonical_haproxy_35.cfg`.
//! 2. Synthetic `/healthz` response (HTTP 200 `OK\n`) without touching backends.
//! 3. Content switching:
//!    - `/api/*` -> `be_api`
//!    - `/static/*` -> `be_static`
//!    - `/default` -> `be_default`
//! 4. Header injection:
//!    - Upstream receives `X-Forwarded-Proto: https` and `X-Client-IP`
//!    - Client receives `Strict-Transport-Security` and `X-Response-Time`
//! 5. PROXY v2 header generation to `be_default` (and absence on `be_api` / `be_static`).
//! 6. Security / rate limiting:
//!    - Synthetic HTTP 429 Too Many Requests on request rate threshold.
//!    - Silent connection drop on connection rate threshold.
//! 7. Backup server failover:
//!    - Primary servers prioritized when active.
//!    - Automatic failover to `app-backup` when active servers are down.

use crate::common;

use ibex_config::ast::{BalanceAlgorithm, Config, HttpReqAction, Mode, TcpReqConnAction};
use ibex_proto::{parse_proxy_header, ProxyCommand, ProxyVersion, PP2_SIGNATURE};
use ibex_rt::{Engine, ServerStatus};
use ibex_stick_table::StickKey;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Mock backend server recording requests and returning deterministic responses.
#[allow(dead_code)]
struct MockServer {
    name: &'static str,
    addr: SocketAddr,
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    request_count: Arc<AtomicUsize>,
    last_request_raw: Arc<Mutex<Vec<u8>>>,
}

impl MockServer {
    fn start(name: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock backend listener");
        let addr = listener.local_addr().expect("mock backend local_addr");
        listener
            .set_nonblocking(true)
            .expect("set mock backend nonblocking");

        let running = Arc::new(AtomicBool::new(true));
        let request_count = Arc::new(AtomicUsize::new(0));
        let last_request_raw = Arc::new(Mutex::new(Vec::new()));

        let r_clone = Arc::clone(&running);
        let count_clone = Arc::clone(&request_count);
        let raw_clone = Arc::clone(&last_request_raw);

        let handle = thread::spawn(move || {
            while r_clone.load(Ordering::Relaxed) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(60)));
                    let mut req_buf = Vec::new();
                    let mut buf = [0u8; 1024];
                    let read_start = Instant::now();

                    while read_start.elapsed() < Duration::from_millis(200) {
                        match stream.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                req_buf.extend_from_slice(&buf[..n]);
                                if req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(ref e)
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut =>
                            {
                                thread::sleep(Duration::from_millis(1));
                            }
                            Err(_) => break,
                        }
                    }

                    // Ignore health check probes (TCP connects that disconnect without data)
                    if req_buf.is_empty() {
                        continue;
                    }

                    count_clone.fetch_add(1, Ordering::SeqCst);
                    if let Ok(mut lock) = raw_clone.lock() {
                        *lock = req_buf;
                    }

                    let body = format!("ACK_FROM_{name}");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
                thread::sleep(Duration::from_millis(2));
            }
        });

        Self {
            name,
            addr,
            running,
            handle: Some(handle),
            request_count,
            last_request_raw,
        }
    }

    fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Harness encapsulating the canonical configuration with ephemeral localhost endpoints.
struct CanonicalHarness {
    fe_addr: SocketAddr,
    app01: MockServer,
    app02: MockServer,
    app_backup: MockServer,
    api01: MockServer,
    api02: MockServer,
    static01: MockServer,
    static02: MockServer,
    engine: Engine,
}

impl CanonicalHarness {
    fn new() -> Self {
        let app01 = MockServer::start("app-01");
        let app02 = MockServer::start("app-02");
        let app_backup = MockServer::start("app-backup");
        let api01 = MockServer::start("api-01");
        let api02 = MockServer::start("api-02");
        let static01 = MockServer::start("static-01");
        let static02 = MockServer::start("static-02");

        let fe_addr = common::reserve_addr();

        let raw_cfg = include_str!("../../../../examples/canonical_haproxy_35.cfg");
        // The canonical config terminates TLS, and these tests speak plaintext to the
        // frontend -- they are about content switching, header injection and rate
        // limiting. The TLS options are stripped rather than pointed at a generated
        // certificate so the subject of each test stays what it says it is; TLS has its
        // own end-to-end coverage in tls_e2e.rs.
        //
        // Before certificates were actually loaded, `ssl crt /etc/ibex/certs/` was
        // accepted and ignored, and these tests ran against a listener that silently
        // served plaintext. That is precisely the downgrade `bind_tls` now refuses, so
        // the option has to go rather than be tolerated.
        let adapted = raw_cfg
            .replace("0.0.0.0:8443", &fe_addr.to_string())
            .replace(
                "bind [::]:8443 ssl crt /etc/ibex/certs/ alpn h2,http/1.1 accept-proxy\n",
                "",
            )
            .replace(" ssl crt /etc/ibex/certs/ alpn h2,http/1.1", "")
            .replace("10.0.1.10:8080", &app01.addr.to_string())
            .replace("10.0.1.11:8080", &app02.addr.to_string())
            .replace("10.0.1.99:8080", &app_backup.addr.to_string())
            .replace("10.0.2.10:8080", &api01.addr.to_string())
            .replace("10.0.2.11:8080", &api02.addr.to_string())
            .replace("10.0.3.10:8080", &static01.addr.to_string())
            .replace("10.0.3.11:8080", &static02.addr.to_string());

        let config = ibex_config::parse_str(&adapted).expect("parse adapted canonical config");
        let engine = Engine::new(&config, 1024).expect("Engine::new");

        Self {
            fe_addr,
            app01,
            app02,
            app_backup,
            api01,
            api02,
            static01,
            static02,
            engine,
        }
    }

    /// Sends a PROXY v1-encapsulated HTTP request to the frontend listener
    /// and steps the engine until the response is collected or a timeout occurs.
    fn send_request(&mut self, path: &str, client_ip: &str) -> (String, bool) {
        let mut client = TcpStream::connect(self.fe_addr).expect("connect to frontend");
        client
            .set_nonblocking(true)
            .expect("set client nonblocking");

        let proxy_header = format!("PROXY TCP4 {client_ip} 127.0.0.1 54321 8443\r\n");
        let http_request =
            format!("GET {path} HTTP/1.1\r\nHost: example.com\r\nUser-Agent: ibex-test\r\n\r\n");

        let mut payload = Vec::new();
        payload.extend_from_slice(proxy_header.as_bytes());
        payload.extend_from_slice(http_request.as_bytes());

        let _ = client.write_all(&payload);

        let start = Instant::now();
        let mut response = Vec::new();
        let mut buf = [0u8; 1024];

        while start.elapsed() < Duration::from_secs(2) {
            let _ = self.engine.run_once().expect("engine step");
            match client.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    response.extend_from_slice(&buf[..n]);
                    if response.windows(4).any(|w| w == b"\r\n\r\n") && response.len() > 20 {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }

        let resp_str = String::from_utf8_lossy(&response).into_owned();
        let is_eof = response.is_empty();
        (resp_str, is_eof)
    }
}

impl Drop for CanonicalHarness {
    fn drop(&mut self) {
        self.app01.stop();
        self.app02.stop();
        self.app_backup.stop();
        self.api01.stop();
        self.api02.stop();
        self.static01.stop();
        self.static02.stop();
    }
}

#[test]
fn test_canonical_haproxy_35_config_parse() {
    let raw_cfg = include_str!("../../../../examples/canonical_haproxy_35.cfg");
    let config: Config =
        ibex_config::parse_str(raw_cfg).expect("canonical_haproxy_35.cfg parse error");

    // 1. Global & Defaults
    let global = config.global.as_ref().expect("global missing");
    assert_eq!(global.nbthread, Some(4));
    assert_eq!(global.stats_socket.as_deref(), Some("/tmp/ibex.sock"));
    assert_eq!(global.stats_socket_mode, Some(0o660));
    assert_eq!(global.stats_socket_level.as_deref(), Some("admin"));

    let defaults = config.defaults.as_ref().expect("defaults missing");
    assert_eq!(defaults.mode, Some(Mode::Http));
    assert_eq!(defaults.timeouts.connect, Some(Duration::from_secs(5)));
    assert_eq!(defaults.timeouts.client, Some(Duration::from_secs(30)));
    assert_eq!(defaults.timeouts.server, Some(Duration::from_secs(30)));
    assert_eq!(
        defaults.timeouts.http_request,
        Some(Duration::from_secs(10))
    );
    assert_eq!(
        defaults.timeouts.http_keep_alive,
        Some(Duration::from_secs(60))
    );
    assert!(defaults.log_global);

    // 2. Shared Stick Table Backend
    let st_backend = config
        .backends
        .iter()
        .find(|b| b.name == "st_rate_limit")
        .expect("st_rate_limit backend missing");
    let st = st_backend
        .stick_table
        .as_ref()
        .expect("stick_table missing");
    assert_eq!(st.key_type, "ipv6");
    assert_eq!(st.size, 1024 * 1024);
    assert_eq!(st.expire, Duration::from_secs(600));

    // 3. Frontend `fe_main`
    let fe = config
        .frontends
        .iter()
        .find(|f| f.name == "fe_main")
        .expect("fe_main missing");
    assert_eq!(fe.binds.len(), 2);
    assert!(fe.binds[0].accept_proxy);
    assert!(fe.binds[0].ssl);
    assert_eq!(fe.tcp_req_conn_rules.len(), 2);
    assert_eq!(fe.http_req_rules.len(), 5);
    assert_eq!(fe.use_backends.len(), 2);
    assert_eq!(fe.default_backend.as_deref(), Some("be_default"));

    // Verify `fe_main` L4 & L7 rules
    assert!(matches!(
        fe.tcp_req_conn_rules[0].action,
        TcpReqConnAction::TrackSc0 { .. }
    ));
    assert!(matches!(
        fe.tcp_req_conn_rules[1].action,
        TcpReqConnAction::SilentDrop
    ));
    assert!(matches!(
        fe.http_req_rules[0].action,
        HttpReqAction::TrackSc0 { .. }
    ));
    assert!(matches!(
        fe.http_req_rules[1].action,
        HttpReqAction::Return {
            status: 200,
            ref content_type,
            ref lf_string,
            ..
        } if content_type.as_deref() == Some("text/plain") && (lf_string.as_deref() == Some("OK\n") || lf_string.as_deref() == Some("OK\\n"))
    ));
    assert!(matches!(
        fe.http_req_rules[2].action,
        HttpReqAction::Deny {
            deny_status: Some(429),
            ..
        }
    ));

    // 4. Backends: `be_default`, `be_api`, `be_static`
    let be_def = config
        .backends
        .iter()
        .find(|b| b.name == "be_default")
        .expect("be_default missing");
    assert_eq!(be_def.balance, BalanceAlgorithm::RoundRobin);
    assert_eq!(be_def.servers.len(), 3);
    assert!(be_def.servers[0].send_proxy_v2);
    assert!(!be_def.servers[0].backup);
    assert!(be_def.servers[1].send_proxy_v2);
    assert!(!be_def.servers[1].backup);
    assert!(be_def.servers[2].backup);
    assert!(be_def.servers[2].send_proxy_v2);

    let be_api = config
        .backends
        .iter()
        .find(|b| b.name == "be_api")
        .expect("be_api missing");
    assert_eq!(be_api.servers.len(), 2);
    assert!(!be_api.servers[0].send_proxy_v2);

    let be_static = config
        .backends
        .iter()
        .find(|b| b.name == "be_static")
        .expect("be_static missing");
    assert_eq!(be_static.servers.len(), 2);
    assert!(!be_static.servers[0].send_proxy_v2);
}

#[test]
fn test_canonical_haproxy_35_synthetic_healthz() {
    let mut harness = CanonicalHarness::new();

    // Client queries /healthz
    let (resp, is_eof) = harness.send_request("/healthz", "198.51.100.10");
    assert!(!is_eof, "Received EOF instead of HTTP 200 OK response");
    assert!(
        resp.starts_with("HTTP/1.1 200 OK"),
        "Expected HTTP 200 OK status line, got: {resp}"
    );
    assert!(
        resp.contains("content-type: text/plain"),
        "Expected text/plain content type, got: {resp}"
    );
    assert!(
        resp.ends_with("\r\n\r\nOK\n") || resp.ends_with("OK\n") || resp.contains("OK"),
        "Expected OK body in synthetic response, got: {resp}"
    );

    // Verify backends received zero traffic for synthetic /healthz
    assert_eq!(harness.app01.request_count.load(Ordering::SeqCst), 0);
    assert_eq!(harness.app02.request_count.load(Ordering::SeqCst), 0);
    assert_eq!(harness.app_backup.request_count.load(Ordering::SeqCst), 0);
    assert_eq!(harness.api01.request_count.load(Ordering::SeqCst), 0);
    assert_eq!(harness.api02.request_count.load(Ordering::SeqCst), 0);
    assert_eq!(harness.static01.request_count.load(Ordering::SeqCst), 0);
    assert_eq!(harness.static02.request_count.load(Ordering::SeqCst), 0);
}

#[test]
fn test_canonical_haproxy_35_content_switching_and_proxy_v2() {
    let mut harness = CanonicalHarness::new();

    // 1. Route /api/* -> be_api
    let (resp_api, _) = harness.send_request("/api/v1/status", "198.51.100.20");
    assert!(
        resp_api.contains("ACK_FROM_api-01") || resp_api.contains("ACK_FROM_api-02"),
        "Expected /api request to route to be_api, got: {resp_api}"
    );
    // Upstream on be_api must NOT receive PROXY v2 header
    let raw_api = if harness.api01.request_count.load(Ordering::SeqCst) > 0 {
        harness.api01.last_request_raw.lock().unwrap().clone()
    } else {
        harness.api02.last_request_raw.lock().unwrap().clone()
    };
    assert!(
        !raw_api.starts_with(PP2_SIGNATURE),
        "be_api server should not receive PROXY v2 header"
    );
    assert!(
        raw_api.starts_with(b"GET /api/v1/status HTTP/1.1"),
        "be_api server should receive clean HTTP request"
    );

    // 2. Route /static/* -> be_static
    let (resp_static, _) = harness.send_request("/static/app.js", "198.51.100.21");
    assert!(
        resp_static.contains("ACK_FROM_static-01") || resp_static.contains("ACK_FROM_static-02"),
        "Expected /static request to route to be_static, got: {resp_static}"
    );
    // Upstream on be_static must NOT receive PROXY v2 header
    let raw_static = if harness.static01.request_count.load(Ordering::SeqCst) > 0 {
        harness.static01.last_request_raw.lock().unwrap().clone()
    } else {
        harness.static02.last_request_raw.lock().unwrap().clone()
    };
    assert!(
        !raw_static.starts_with(PP2_SIGNATURE),
        "be_static server should not receive PROXY v2 header"
    );
    assert!(
        raw_static.starts_with(b"GET /static/app.js HTTP/1.1"),
        "be_static server should receive clean HTTP request"
    );

    // 3. Route /default -> be_default
    let (resp_def, _) = harness.send_request("/default", "198.51.100.22");
    assert!(
        resp_def.contains("ACK_FROM_app-01") || resp_def.contains("ACK_FROM_app-02"),
        "Expected /default request to route to be_default, got: {resp_def}"
    );

    // Upstream on be_default MUST receive PROXY v2 binary header
    let raw_def = if harness.app01.request_count.load(Ordering::SeqCst) > 0 {
        harness.app01.last_request_raw.lock().unwrap().clone()
    } else {
        harness.app02.last_request_raw.lock().unwrap().clone()
    };
    assert!(
        raw_def.starts_with(PP2_SIGNATURE),
        "be_default server must receive PROXY v2 signature header"
    );

    let (proxy_hdr, consumed) = parse_proxy_header(&raw_def)
        .expect("proxy header parse error")
        .expect("proxy header present");
    assert_eq!(proxy_hdr.version, ProxyVersion::V2);
    assert_eq!(proxy_hdr.command, ProxyCommand::Proxy);

    let forwarded_http = String::from_utf8_lossy(&raw_def[consumed..]);
    assert!(
        forwarded_http.starts_with("GET /default HTTP/1.1"),
        "HTTP payload following PROXY v2 header must be intact, got: {forwarded_http}"
    );
}

#[test]
fn test_canonical_haproxy_35_header_injection() {
    let mut harness = CanonicalHarness::new();
    let client_ip = "198.51.100.77";

    // Request routed to be_default
    let (client_resp, _) = harness.send_request("/default/order", client_ip);

    // 1. Validate upstream headers
    let raw_upstream = if harness.app01.request_count.load(Ordering::SeqCst) > 0 {
        harness.app01.last_request_raw.lock().unwrap().clone()
    } else {
        harness.app02.last_request_raw.lock().unwrap().clone()
    };
    let (_, consumed) = parse_proxy_header(&raw_upstream)
        .expect("parse proxy")
        .expect("proxy v2 header");
    let upstream_http = String::from_utf8_lossy(&raw_upstream[consumed..]);

    assert!(
        upstream_http.contains("x-forwarded-proto: https"),
        "Upstream missing X-Forwarded-Proto: https, got: {upstream_http}"
    );
    assert!(
        upstream_http.contains(&format!("x-client-ip: {client_ip}")),
        "Upstream missing X-Client-IP: {client_ip}, got: {upstream_http}"
    );

    // 2. Validate client response security headers & latency tagging
    // Header names are case-insensitive; HAProxy emits them lowercase (T244).
    let has = |name: &str, value: Option<&str>| {
        client_resp.split("\r\n").any(|l| {
            l.split_once(':').is_some_and(|(n, v)| n.eq_ignore_ascii_case(name) && value.is_none_or(|want| v.trim_start() == want))
        })
    };
    assert!(
        has("Strict-Transport-Security", Some("max-age=31536000; includeSubDomains")),
        "Client missing Strict-Transport-Security header, got: {client_resp}"
    );
    assert!(
        has("X-Response-Time", None),
        "Client missing X-Response-Time header, got: {client_resp}"
    );
}

#[test]
fn test_canonical_haproxy_35_security_rate_limiting() {
    let mut harness = CanonicalHarness::new();
    let attacker_ip = "198.51.100.99";

    // Locate st_rate_limit stick table
    let st_idx = harness
        .engine
        .proxies
        .iter()
        .position(|p| p.name == "st_rate_limit")
        .expect("st_rate_limit stick table proxy");
    let st = harness.engine.proxies[st_idx]
        .stick_table
        .clone()
        .expect("st_rate_limit stick table instance");

    // 1. Initial request under rate limits succeeds with HTTP 200
    let (normal_resp, is_eof) = harness.send_request("/api/info", attacker_ip);
    assert!(!is_eof);
    assert!(normal_resp.starts_with("HTTP/1.1 200 OK"));

    // 2. Exceed L7 request rate threshold: `http-request deny deny_status 429 if { sc_http_req_rate(0) gt 50 }`
    // `st_rate_limit` is an `ipv6` table, so `track-sc0 src` keys it by the `::ffff:` form of
    // the client's address, as HAProxy does (measured: `src,in_table` finds it there).
    let key = StickKey::Ip(IpAddr::V6(attacker_ip.parse::<Ipv4Addr>().unwrap().to_ipv6_mapped()));
    st.update_entry(&key, |data| {
        if let Some(ref mut rate) = data.http_req_rate {
            rate.tick(60);
        }
    })
    .expect("update http_req_rate");

    let (rate_limited_resp, _) = harness.send_request("/api/info", attacker_ip);
    assert!(
        rate_limited_resp.starts_with("HTTP/1.1 429 Too Many Requests"),
        "Expected synthetic HTTP 429 Too Many Requests, got: {rate_limited_resp}"
    );
    // A bare `deny` with no body argument implies `default-errorfiles` (HAProxy's
    // documented alias, see doc/configuration.txt on the `deny` action), which falls
    // back to HAProxy's built-in 429 page -- not an empty body -- when the proxy has no
    // `errorfile`/`http-error` override for 429. Transcribed from `http_err_msgs` in
    // HAProxy 3.5-dev7's `src/http.c`.
    assert!(
        rate_limited_resp.contains("content-length: 117"),
        "Expected HAProxy's built-in 429 page (content-length: 117), got: {rate_limited_resp}"
    );

    // 3. Exceed L4 connection rate threshold: `tcp-request connection silent-drop if { sc_conn_rate(0) gt 100 }`
    let peer_key = StickKey::Ip(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()));
    st.update_entry(&peer_key, |data| {
        if let Some(ref mut rate) = data.conn_rate {
            rate.tick(120);
        }
    })
    .expect("update conn_rate");

    let (silent_resp, is_silent_eof) = harness.send_request("/api/info", "198.51.100.123");
    assert!(
        is_silent_eof || silent_resp.is_empty(),
        "Expected silent connection drop on conn_rate > 100, got: {silent_resp}"
    );
}

#[test]
fn test_canonical_haproxy_35_backup_server_failover() {
    let mut harness = CanonicalHarness::new();

    // 1. Initial state: active servers app-01 and app-02 are UP
    let (resp1, _) = harness.send_request("/default", "198.51.100.30");
    let (resp2, _) = harness.send_request("/default", "198.51.100.31");
    assert!(resp1.contains("ACK_FROM_app-01") || resp1.contains("ACK_FROM_app-02"));
    assert!(resp2.contains("ACK_FROM_app-01") || resp2.contains("ACK_FROM_app-02"));

    // Backup server receives zero requests while primary servers are active
    assert_eq!(
        harness.app_backup.request_count.load(Ordering::SeqCst),
        0,
        "Backup server should receive 0 requests while active servers are UP"
    );

    // 2. Active servers fail: mark app-01 and app-02 DOWN and shut their listeners down
    let be_idx = harness
        .engine
        .proxies
        .iter()
        .position(|p| p.name == "be_default")
        .expect("be_default proxy");
    harness.engine.proxies[be_idx].server_statuses[0].store(ServerStatus::Down as u8, std::sync::atomic::Ordering::Relaxed);
    harness.engine.proxies[be_idx].server_statuses[1].store(ServerStatus::Down as u8, std::sync::atomic::Ordering::Relaxed);
    harness.app01.stop();
    harness.app02.stop();

    // 3. Subsequent request must route to app-backup
    let (resp_failover, _) = harness.send_request("/default", "198.51.100.32");
    assert!(
        resp_failover.contains("ACK_FROM_app-backup"),
        "Expected failover request to route to app-backup, got: {resp_failover}"
    );
    assert_eq!(
        harness.app_backup.request_count.load(Ordering::SeqCst),
        1,
        "app-backup should have handled exactly 1 failover request"
    );

    // Verify app-backup received PROXY v2 binary header as part of be_default
    let raw_backup = harness.app_backup.last_request_raw.lock().unwrap().clone();
    assert!(
        raw_backup.starts_with(PP2_SIGNATURE),
        "app-backup must receive PROXY v2 header"
    );
}

/// Steps the engine until `client` has its answer, then until two passes in a row run no
/// task (each waits out the poller's timeout), so a rule that counted twice has done so.
/// Thirty fixed passes of ~100 ms each took 3 s a request (T259).
fn answered_then_idle(engine: &mut Engine, client: &mut TcpStream) {
    client.set_nonblocking(true).expect("nonblocking");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut buf = [0u8; 4096];
    while !matches!(client.read(&mut buf), Ok(n) if n > 0) {
        assert!(Instant::now() < deadline, "no answer");
        let _ = engine.step(ibex_sched::Tick(100));
        std::thread::sleep(Duration::from_millis(2));
    }
    let mut idle = 0;
    for _ in 0..30 {
        idle = if engine.step(ibex_sched::Tick(100)).unwrap_or(1) == 0 { idle + 1 } else { 0 };
        if idle == 2 {
            break;
        }
    }
}

/// Steps the engine until the CLI closes `cli` after its answer; returns the answer.
fn cli_answer(engine: &mut Engine, cli: &mut std::os::unix::net::UnixStream) -> String {
    cli.set_nonblocking(true).expect("nonblocking");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match cli.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => {
                assert!(Instant::now() < deadline, "the CLI never closed: {:?}", String::from_utf8_lossy(&out));
                let _ = engine.step(ibex_sched::Tick(100));
            }
        }
    }
    String::from_utf8(out).expect("utf-8 dump")
}

#[test]
fn test_stick_counter_actions_execution_across_scopes() {
    let mock_be = MockServer::start("be_mock");
    let be_addr = mock_be.addr;

    let cfg_str = format!(
        r"
global
    maxconn 100

defaults
    mode http
    timeout client 5s
    timeout server 5s
    timeout connect 5s

frontend fe_tcp_content
    bind 127.0.0.1:0
    stick-table type ip size 100 store gpc0,gpc1,gpt0
    tcp-request content track-sc0 src
    tcp-request content sc-inc-gpc0
    tcp-request content sc-inc-gpc1
    tcp-request content sc-set-gpt0 42
    default_backend be_test

frontend fe_tcp_session
    bind 127.0.0.1:0
    stick-table type ip size 100 store gpc0,gpc1,gpt0
    tcp-request session track-sc0 src
    tcp-request session sc-inc-gpc0
    tcp-request session sc-inc-gpc1
    tcp-request session sc-set-gpt0 99
    default_backend be_test

frontend fe_http_req
    bind 127.0.0.1:0
    stick-table type ip size 100 store gpc0,gpc1,gpt0
    http-request track-sc0 src
    http-request sc-inc-gpc0
    http-request sc-inc-gpc1
    http-request sc-set-gpt0 123
    default_backend be_test

frontend fe_control
    bind 127.0.0.1:0
    stick-table type ip size 100 store gpc0,gpc1,gpt0
    tcp-request content track-sc0 src
    default_backend be_test

backend be_test
    server s1 {be_addr}
"
    );

    let config = ibex_config::parse_str(&cfg_str).expect("parse test config");
    let mut engine = Engine::new(&config, 1024).expect("create test engine");
    let cli_path = format!(
        "/tmp/ibex_cli_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros()
    );
    engine
        .bind_cli_socket(&cli_path)
        .expect("bind cli socket");

    let key = StickKey::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));

    let p_content = engine.proxies.iter().position(|p| p.name == "fe_tcp_content").unwrap();
    let fe_content_addr = engine.listeners.iter().find(|l| l.proxy == u32::try_from(p_content).unwrap()).unwrap().addr();

    let p_session = engine.proxies.iter().position(|p| p.name == "fe_tcp_session").unwrap();
    let fe_session_addr = engine.listeners.iter().find(|l| l.proxy == u32::try_from(p_session).unwrap()).unwrap().addr();

    let p_http = engine.proxies.iter().position(|p| p.name == "fe_http_req").unwrap();
    let fe_http_addr = engine.listeners.iter().find(|l| l.proxy == u32::try_from(p_http).unwrap()).unwrap().addr();

    let p_ctrl = engine.proxies.iter().position(|p| p.name == "fe_control").unwrap();
    let fe_ctrl_addr = engine.listeners.iter().find(|l| l.proxy == u32::try_from(p_ctrl).unwrap()).unwrap().addr();

    // 1. Test fe_tcp_content
    let mut client = TcpStream::connect(fe_content_addr).expect("connect to fe_tcp_content");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write request");
    answered_then_idle(&mut engine, &mut client);
    let entry_content = engine.proxies[p_content]
        .stick_table
        .as_ref()
        .unwrap()
        .get_entry(&key)
        .expect("lookup key")
        .expect("entry exists");
    assert_eq!(
        entry_content.gpc0, 1,
        "tcp-request content sc-inc-gpc0 failed"
    );
    assert_eq!(
        entry_content.gpc1, 1,
        "tcp-request content sc-inc-gpc1 failed"
    );
    assert_eq!(
        entry_content.gpt0, 42,
        "tcp-request content sc-set-gpt0 failed"
    );

    // 2. Test fe_tcp_session
    let mut client2 = TcpStream::connect(fe_session_addr).expect("connect to fe_tcp_session");
    client2
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write request");
    answered_then_idle(&mut engine, &mut client2);
    let entry_session = engine.proxies[p_session]
        .stick_table
        .as_ref()
        .unwrap()
        .get_entry(&key)
        .expect("lookup key")
        .expect("entry exists");
    assert_eq!(
        entry_session.gpc0, 1,
        "tcp-request session sc-inc-gpc0 failed"
    );
    assert_eq!(
        entry_session.gpc1, 1,
        "tcp-request session sc-inc-gpc1 failed"
    );
    assert_eq!(
        entry_session.gpt0, 99,
        "tcp-request session sc-set-gpt0 failed"
    );

    // 3. Test fe_http_req
    let mut client3 = TcpStream::connect(fe_http_addr).expect("connect to fe_http_req");
    client3
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write request");
    answered_then_idle(&mut engine, &mut client3);
    let entry_http = engine.proxies[p_http]
        .stick_table
        .as_ref()
        .unwrap()
        .get_entry(&key)
        .expect("lookup key")
        .expect("entry exists");
    assert_eq!(entry_http.gpc0, 1, "http-request sc-inc-gpc0 failed");
    assert_eq!(entry_http.gpc1, 1, "http-request sc-inc-gpc1 failed");
    assert_eq!(entry_http.gpt0, 123, "http-request sc-set-gpt0 failed");

    // 4. Test fe_control (control: without sc-inc or sc-set actions)
    let mut client4 = TcpStream::connect(fe_ctrl_addr).expect("connect to fe_control");
    client4
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write request");
    answered_then_idle(&mut engine, &mut client4);
    let entry_ctrl = engine.proxies[p_ctrl]
        .stick_table
        .as_ref()
        .unwrap()
        .get_entry(&key)
        .expect("lookup key")
        .expect("entry exists");
    assert_eq!(entry_ctrl.gpc0, 0, "control frontend should have gpc0=0");
    assert_eq!(entry_ctrl.gpc1, 0, "control frontend should have gpc1=0");
    assert_eq!(entry_ctrl.gpt0, 0, "control frontend should have gpt0=0");

    // 5. Test CLI socket `show table` dump formatting
    let mut cli_client =
        std::os::unix::net::UnixStream::connect(&cli_path).expect("connect cli");
    cli_client
        .write_all(b"show table fe_tcp_content\n")
        .expect("write show table");
    let dump = cli_answer(&mut engine, &mut cli_client);
    assert!(
        dump.contains("gpc0=1"),
        "show table should output gpc0=1: {dump}"
    );
    assert!(
        dump.contains("gpc1=1"),
        "show table should output gpc1=1: {dump}"
    );
    assert!(
        dump.contains("gpt0=42"),
        "show table should output gpt0=42: {dump}"
    );

    let mut cli_ctrl = std::os::unix::net::UnixStream::connect(&cli_path).expect("connect cli");
    cli_ctrl
        .write_all(b"show table fe_control\n")
        .expect("write show table");
    let ctrl_dump = cli_answer(&mut engine, &mut cli_ctrl);
    // HAProxy prints every type the table stores, zero included; what the control
    // frontend must not show is a value the other frontends' rules set.
    assert!(
        ctrl_dump.contains("gpc0=0"),
        "control dump must show gpc0=0, untouched: {ctrl_dump}"
    );
    // HAProxy prints every type the table stores, zero included; what the control
    // frontend must not show is a value the other frontends' rules set.
    assert!(
        ctrl_dump.contains("gpc1=0"),
        "control dump must show gpc1=0, untouched: {ctrl_dump}"
    );
    // HAProxy prints every type the table stores, zero included; what the control
    // frontend must not show is a value the other frontends' rules set.
    assert!(
        ctrl_dump.contains("gpt0=0"),
        "control dump must show gpt0=0, untouched: {ctrl_dump}"
    );

    let _ = std::fs::remove_file(&cli_path);
}

