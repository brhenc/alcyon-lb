// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T260): sets the process-global tune.bufsize through in-process engines and asserts on it
// Integration tests for CLI Applet and Unix Domain Socket (hatop compatibility).

mod common;

use ibex_config::parse_str;
use ibex_rt::Engine;
use ibex_sched::Tick;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

fn create_test_engine(socket_path: &PathBuf) -> Engine {
    let _g = BUFSIZE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    build_test_engine(socket_path)
}

/// [`create_test_engine`] for a test that already holds `BUFSIZE` (it is not re-entrant).
fn build_test_engine(socket_path: &PathBuf) -> Engine {
    // The servers are never connected to. The frontend port is reserved: every test here
    // builds an engine, and with SO_REUSEPORT a shared fixed port does not fail to bind,
    // it silently joins the other engines.
    let cfg_str = format!(
        "listen test_proxy\n    bind {}\n    mode tcp\n    server srv1 127.0.0.1:29091\n    \
         server srv2 127.0.0.1:29092\n",
        common::reserve_addr()
    );
    let config = parse_str(&cfg_str).expect("failed to parse test config");
    let mut engine = Engine::new(&config, 1024).expect("failed to create engine");
    engine
        .bind_cli_socket(socket_path)
        .expect("failed to bind stats socket");
    engine
}

fn step_engine_until<F>(engine: &mut Engine, mut condition: F, max_steps: usize)
where
    F: FnMut(&mut Engine) -> bool,
{
    let mut tick = Tick(100);
    for _ in 0..max_steps {
        let _ = engine.step(tick);
        if condition(engine) {
            return;
        }
        tick = tick.add(10);
    }
    panic!("step_engine_until: condition was not met within {max_steps} steps");
}

#[test]
fn cli_applet_interactive_handshake_and_show_info_hatop_parity() {
    let socket_path = PathBuf::from(format!("/tmp/ibex_test_cli_{}.sock", std::process::id()));
    let mut engine = create_test_engine(&socket_path);

    // 1. Connect client UnixStream
    let mut client = UnixStream::connect(&socket_path).expect("failed to connect to cli socket");
    client
        .set_nonblocking(true)
        .expect("failed to set nonblocking");

    // Step engine to accept client
    engine.step(Tick(100)).expect("engine step failed");
    assert_eq!(engine.applets.live(), 1, "applet session should be live");

    // 2. Send prompt\n
    client.write_all(b"prompt\n").expect("write failed");
    step_engine_until(
        &mut engine,
        |_eng| {
            let mut buf = [0u8; 64];
            if let Ok(n) = client.read(&mut buf) {
                n > 0 && buf[..n].ends_with(b"> ")
            } else {
                false
            }
        },
        20,
    );

    // 3. Send show info\n
    client.write_all(b"show info\n").expect("write failed");
    let mut info_response = Vec::new();
    step_engine_until(
        &mut engine,
        |_eng| {
            let mut buf = [0u8; 1024];
            if let Ok(n) = client.read(&mut buf) {
                if n > 0 {
                    info_response.extend_from_slice(&buf[..n]);
                }
            }
            info_response.ends_with(b"\n> ")
        },
        20,
    );

    let info_text = String::from_utf8_lossy(&info_response);
    let mandatory_keys = [
        "Name:",
        "Version:",
        "Release_date:",
        "Nbproc:",
        "Process_num:",
        "Pid:",
        "Uptime:",
        "Maxconn:",
        "CurrConns:",
        "Maxpipes:",
        "PipesUsed:",
        "Tasks:",
        "Run_queue:",
        "node:",
    ];
    for key in mandatory_keys {
        assert!(
            info_text.lines().any(|l| l.starts_with(key)),
            "missing mandatory hatop key '{key}' in show info response:\n{info_text}"
        );
    }

    // 4. Send quit\n
    client.write_all(b"quit\n").expect("write failed");
    let mut tick = Tick(300);
    for _ in 0..10 {
        let _ = engine.step(tick);
        if engine.applets.live() == 0 {
            break;
        }
        tick = tick.add(10);
    }
    assert_eq!(
        engine.applets.live(),
        0,
        "applet session should be closed after quit"
    );
}

#[test]
fn cli_applet_show_stat_and_admin_server_state_mutations() {
    let socket_path = PathBuf::from(format!("/tmp/ibex_test_stat_{}.sock", std::process::id()));
    let mut engine = create_test_engine(&socket_path);

    let mut client = UnixStream::connect(&socket_path).expect("failed to connect to cli socket");
    client
        .set_nonblocking(true)
        .expect("failed to set nonblocking");
    engine.step(Tick(100)).expect("engine step failed");

    // Enable prompt mode
    client.write_all(b"prompt\n").expect("write failed");
    step_engine_until(
        &mut engine,
        |_eng| {
            let mut buf = [0u8; 32];
            client.read(&mut buf).is_ok_and(|n| n > 0)
        },
        20,
    );

    // Fetch initial stats
    client.write_all(b"show stat\n").expect("write failed");
    let mut stat_response = Vec::new();
    step_engine_until(
        &mut engine,
        |_eng| {
            let mut buf = [0u8; 2048];
            if let Ok(n) = client.read(&mut buf) {
                if n > 0 {
                    stat_response.extend_from_slice(&buf[..n]);
                }
            }
            stat_response.ends_with(b"\n> ")
        },
        20,
    );

    let stat_text = String::from_utf8_lossy(&stat_response);
    assert!(stat_text.contains("# pxname,svname,"));
    assert!(stat_text.contains("test_proxy,FRONTEND,"));
    assert!(stat_text.contains("test_proxy,srv1,"));
    assert!(stat_text.contains("test_proxy,srv2,"));
    assert!(stat_text.contains("test_proxy,BACKEND,"));

    // Verify each line has at least 51 commas
    for line in stat_text.lines() {
        if line.starts_with('#') || line.starts_with('>') || line.is_empty() {
            continue;
        }
        assert!(
            line.matches(',').count() >= 51,
            "stat line has fewer than 51 commas: {line}"
        );
    }

    // Disable srv1
    client
        .write_all(b"disable server test_proxy/srv1\n")
        .expect("write failed");
    step_engine_until(
        &mut engine,
        |_eng| {
            let mut buf = [0u8; 64];
            client.read(&mut buf).is_ok_and(|n| n > 0)
        },
        20,
    );

    assert_eq!(
        engine.proxies[0].server_statuses[0].load(std::sync::atomic::Ordering::Relaxed), ibex_rt::ServerStatus::Maint as u8,
        "srv1 should be in maintenance after disable server (HAProxy: MAINT)"
    );

    // Re-enable srv1
    client
        .write_all(b"enable server test_proxy/srv1\n")
        .expect("write failed");
    step_engine_until(
        &mut engine,
        |_eng| {
            let mut buf = [0u8; 64];
            client.read(&mut buf).is_ok_and(|n| n > 0)
        },
        20,
    );

    assert_eq!(
        engine.proxies[0].server_statuses[0].load(std::sync::atomic::Ordering::Relaxed), ibex_rt::ServerStatus::Up as u8,
        "srv1 should be marked Up after enable server"
    );

    // Set server srv2 state drain
    client
        .write_all(b"set server test_proxy/srv2 state drain\n")
        .expect("write failed");
    step_engine_until(
        &mut engine,
        |_eng| {
            let mut buf = [0u8; 64];
            client.read(&mut buf).is_ok_and(|n| n > 0)
        },
        20,
    );

    assert_eq!(
        engine.proxies[0].server_statuses[1].load(std::sync::atomic::Ordering::Relaxed), ibex_rt::ServerStatus::Drain as u8,
        "srv2 should be draining (HAProxy: DRAIN) after set server state drain"
    );
}

#[test]
fn cli_applet_one_shot_non_interactive_command() {
    let socket_path = PathBuf::from(format!(
        "/tmp/ibex_test_oneshot_{}.sock",
        std::process::id()
    ));
    let mut engine = create_test_engine(&socket_path);

    let mut client = UnixStream::connect(&socket_path).expect("failed to connect to cli socket");
    client
        .set_nonblocking(true)
        .expect("failed to set nonblocking");
    engine.step(Tick(100)).expect("engine step failed");

    // In one-shot mode, client sends command directly without 'prompt'
    client.write_all(b"show info\n").expect("write failed");

    let mut resp = Vec::new();
    let mut tick = Tick(110);
    for _ in 0..20 {
        let _ = engine.step(tick);
        let mut buf = [0u8; 1024];
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                resp.extend_from_slice(&buf[..n]);
            }
        }
        if engine.applets.live() == 0 && !resp.is_empty() {
            break;
        }
        tick = tick.add(10);
    }

    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.contains("Name: Ibex"),
        "expected show info output in one-shot mode"
    );
    assert!(
        !text.contains("> "),
        "one-shot mode should not include prompt delimiter"
    );
}

/// `tune.bufsize` is process-global. `cli_applet_show_pools_configured_sizes` sets it while
/// `cli_applet_show_pools` reads it to warm a buffer and again to check the answer; run in
/// parallel, the size could change between the two and the check failed.
static BUFSIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `Engine::new` sets the process-global `tune.bufsize` (16384 when the config says
/// nothing), so every engine is built under `BUFSIZE`: built in parallel with
/// `cli_applet_show_pools_configured_sizes`, another test's engine put the size back to
/// 16384 between its `Engine::new` and its `show pools`, about one run in three. A test
/// that holds `BUFSIZE` itself builds with `build_test_engine`.
fn new_engine(config: &ibex_config::Config) -> Engine {
    let _g = BUFSIZE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    Engine::new(config, 1024).expect("failed to create engine")
}

#[test]
fn cli_applet_show_pools() {
    let _g = BUFSIZE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let socket_path = PathBuf::from(format!(
        "/tmp/ibex_test_pools_{}.sock",
        std::process::id()
    ));
    let mut engine = build_test_engine(&socket_path);

    // Warm-up a buffer so Pool buffer has non-zero stats. Take the size from the
    // configured standard rather than the BUFSIZE constant: the two are separate (a
    // const and an AtomicUsize) and only the configured one selects a pool class.
    let _buf = ibex_rt::buf::Buf::with_capacity(ibex_rt::buf::get_bufsize());

    let mut client = UnixStream::connect(&socket_path).expect("failed to connect to cli socket");
    client
        .set_nonblocking(true)
        .expect("failed to set nonblocking");
    engine.step(Tick(100)).expect("engine step failed");

    client.write_all(b"show pools\n").expect("write failed");

    let mut resp = Vec::new();
    let mut tick = Tick(110);
    for _ in 0..20 {
        let _ = engine.step(tick);
        let mut buf = [0u8; 1024];
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                resp.extend_from_slice(&buf[..n]);
            }
        }
        if engine.applets.live() == 0 && !resp.is_empty() {
            break;
        }
        tick = tick.add(10);
    }

    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.contains("Dumping pools usage. Use SIGQUIT to flush them.\n"),
        "expected HAProxy header in show pools: {text}"
    );
    // Assert the *configured* size, not a literal. `tune.bufsize` is process-global
    // mutable state, so a sibling test that configures 32768 changes what this one sees
    // when the two run in the same binary. Asserting what is configured is both
    // order-independent and the contract that actually matters here; the sibling test
    // below covers the specific values.
    let expected = format!("- Pool buffer ({} bytes/64)", ibex_rt::buf::get_bufsize());
    assert!(
        text.contains(&expected),
        "expected buffer pool entry for the configured size in show pools: {text}"
    );
    assert!(
        text.contains("Total:"),
        "expected total summary in show pools: {text}"
    );
}

#[test]
fn cli_applet_show_pools_configured_sizes() {
    let socket_path = PathBuf::from(format!(
        "/tmp/ibex_test_pools_cfg_{}.sock",
        std::process::id()
    ));
    let _g = BUFSIZE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let cfg_str = format!(
        "global\n    tune.bufsize 32768\n    tune.bufsize.small 2048\n    tune.bufsize.large 65536\n\n\
         listen test_proxy\n    bind {}\n    mode tcp\n    server srv1 127.0.0.1:29093\n",
        common::reserve_addr()
    );
    let config = parse_str(&cfg_str).expect("failed to parse test config");
    let mut engine = Engine::new(&config, 1024).expect("failed to create engine");
    engine
        .bind_cli_socket(&socket_path)
        .expect("failed to bind stats socket");

    let mut client = UnixStream::connect(&socket_path).expect("failed to connect to cli socket");
    client
        .set_nonblocking(true)
        .expect("failed to set nonblocking");
    engine.step(Tick(100)).expect("engine step failed");

    client.write_all(b"show pools\n").expect("write failed");

    let mut resp = Vec::new();
    let mut tick = Tick(110);
    for _ in 0..20 {
        let _ = engine.step(tick);
        let mut buf = [0u8; 1024];
        if let Ok(n) = client.read(&mut buf) {
            if n > 0 {
                resp.extend_from_slice(&buf[..n]);
            }
        }
        if engine.applets.live() == 0 && !resp.is_empty() {
            break;
        }
        tick = tick.add(10);
    }

    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.contains("- Pool buffer (32768 bytes/64)"),
        "show pools must report configured tune.bufsize 32768: {text}"
    );
    assert!(
        text.contains("- Pool small_buffer (2048 bytes/64)"),
        "show pools must report configured tune.bufsize.small 2048: {text}"
    );
    assert!(
        text.contains("- Pool large_buffer (65536 bytes/64)"),
        "show pools must report configured tune.bufsize.large 65536: {text}"
    );
}


#[test]
fn cli_applet_error_messages_and_tables_parity() {
    let socket_path = PathBuf::from(format!("/tmp/ibex_test_cli_err_{}.sock", std::process::id()));
    let cfg_str = r"
backend be
    stick-table type ip size 1m expire 10m store gpc0,conn_rate(10s)
";
    let config = ibex_config::parse_str(cfg_str).expect("config");
    let mut engine = new_engine(&config);
    engine.bind_cli_socket(&socket_path).expect("bind");
    engine.step(Tick(10)).unwrap();

    let mut execute_cmd = |cmd: &str| -> String {
        let mut client = UnixStream::connect(&socket_path).expect("connect");
        client.set_nonblocking(true).unwrap();
        client.write_all(cmd.as_bytes()).unwrap();
        
        let mut resp = Vec::new();
        let mut tick = Tick(20);
        for _ in 0..20 {
            let _ = engine.step(tick);
            let mut buf = [0u8; 1024];
            if let Ok(n) = client.read(&mut buf) {
                if n > 0 { resp.extend_from_slice(&buf[..n]); }
            }
            if engine.applets.live() == 0 && !resp.is_empty() { break; }
            tick = tick.add(10);
        }
        String::from_utf8_lossy(&resp).into_owned()
    };

    assert_eq!(execute_cmd("clear counters server nosuch/s1\n"), "No such backend.\n\n");
    assert_eq!(execute_cmd("clear counters server be/nosuch\n"), "No such server.\n\n");
    
    let info = execute_cmd("show info nonexistent\n");
    assert!(info.starts_with("Name: Ibex"), "show info nonexistent should return info dump");

    assert_eq!(execute_cmd("show servers state nonexistent\n"), "Can't find backend.\n");
    
    assert_eq!(execute_cmd("set server nosuch/s1 state maint\n"), "No such backend.\n\n");
    assert_eq!(execute_cmd("set server be/nosuch state maint\n"), "No such server.\n\n");
    assert_eq!(execute_cmd("set server be/nosuch maxconn 10\n"), "No such server.\n\n");

    let table = execute_cmd("show table be\n");
    assert!(table.contains("# table: be, type: ip, size:1048576, used:0"));
}

// ---------------------------------------------------------------------------------------
// `show pools` against the oracle (slice M1). Shape, not values: the pools differ (HAProxy
// has 69, Ibex keeps the objects it really has) and so do their counts. Ports 47450-47452.
// ---------------------------------------------------------------------------------------

mod pools {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const ORACLE: &str = "/home/bhenc/reference/haproxy/haproxy";
    const ORACLE_PORT: u16 = 47450;
    const IBEX_PORT: u16 = 47451;
    const BACKEND_PORT: u16 = 47452;
    const ERR: &str = "Expects either 'byname', 'bysize', 'byusage', 'match <pfx>', 'detailed', or a max number of output lines.\n\n";

    /// The ports are fixed: one test at a time.
    static SERIAL: Mutex<()> = Mutex::new(());

    struct Proxy {
        child: Option<std::process::Child>,
        ibex: bool,
        sock: String,
        port: u16,
    }

    impl Proxy {
        fn start(ibex: bool, dir: &str) -> Proxy {
            let port = if ibex { IBEX_PORT } else { ORACLE_PORT };
            let name = if ibex { "ibex" } else { "oracle" };
            std::fs::create_dir_all(dir).unwrap();
            let sock = format!("{dir}/{name}.sock");
            let _ = std::fs::remove_file(&sock);
            let cfg = format!(
                "global\n    nbthread 1\n    stats socket {sock} level admin\n\
                 defaults\n    mode http\n    timeout connect 5s\n    timeout client 10s\n    timeout server 10s\n\
                 frontend f\n    bind 127.0.0.1:{port}\n    default_backend b\n\
                 backend b\n    server s 127.0.0.1:{BACKEND_PORT}\n"
            );
            let path = format!("{dir}/{name}.cfg");
            std::fs::write(&path, cfg).unwrap();
            let bin = if ibex { env!("CARGO_BIN_EXE_ibex") } else { ORACLE };
            let child = std::process::Command::new(bin)
                .args(["-f", &path])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn proxy");
            let p = Proxy { child: Some(child), ibex, sock, port };
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            assert!(crate::common::wait_listening(addr), "{name} did not listen");
            for _ in 0..100 {
                if UnixStream::connect(&p.sock).is_ok() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            p
        }

        fn cli(&self, cmd: &str) -> String {
            let mut s = UnixStream::connect(&self.sock).expect("cli connect");
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
            let mut out = Vec::new();
            s.read_to_end(&mut out).expect("cli read");
            String::from_utf8(out).unwrap()
        }

        fn pools(&self, args: &str) -> Pools {
            Pools::parse(&self.cli(&format!("show pools {args}")))
        }

        /// One completed keep-alive request on a fresh connection, left open.
        fn keepalive(&self) -> TcpStream {
            let mut c = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
            let mut got = Vec::new();
            let mut b = [0u8; 256];
            while !got.ends_with(b"ok") {
                let n = c.read(&mut b).expect("response");
                assert!(n > 0, "closed before the response");
                got.extend_from_slice(&b[..n]);
            }
            c
        }
    }

    impl Drop for Proxy {
        fn drop(&mut self) {
            if let Some(mut c) = self.child.take() {
                if self.ibex {
                    crate::common::stop(&mut c);
                } else {
                    let _ = c.kill();
                    let _ = c.wait();
                }
            }
        }
    }

    struct Backend(Arc<AtomicBool>, Option<std::thread::JoinHandle<()>>);

    impl Backend {
        fn start() -> Backend {
            let l = TcpListener::bind(("127.0.0.1", BACKEND_PORT)).expect("backend port");
            l.set_nonblocking(true).unwrap();
            let run = Arc::new(AtomicBool::new(true));
            let r = run.clone();
            let h = std::thread::spawn(move || {
                while r.load(Ordering::Relaxed) {
                    match l.accept() {
                        Ok((mut s, _)) => {
                            let r = r.clone();
                            std::thread::spawn(move || {
                                s.set_nonblocking(false).unwrap();
                                s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
                                let mut acc = Vec::new();
                                let mut b = [0u8; 1024];
                                while r.load(Ordering::Relaxed) {
                                    match s.read(&mut b) {
                                        Ok(0) => return,
                                        Ok(n) => acc.extend_from_slice(&b[..n]),
                                        Err(_) => continue,
                                    }
                                    while let Some(p) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
                                        acc.drain(..p + 4);
                                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                                    }
                                }
                            });
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(5)),
                    }
                }
            });
            Backend(run, Some(h))
        }
    }

    impl Drop for Backend {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Relaxed);
            if let Some(h) = self.1.take() {
                let _ = h.join();
            }
        }
    }

    #[derive(Debug, Clone)]
    struct Line {
        name: String,
        size: u64,
        align: u64,
        allocated: u64,
        bytes: u64,
        used: u64,
        cached: u64,
        failures: u64,
        users: u64,
        shared: bool,
        regs: Vec<String>,
    }

    impl Line {
        /// Blocks handed out: `used` counts those sitting in the thread caches as well.
        fn in_use(&self) -> u64 {
            self.used - self.cached
        }
    }

    #[derive(Debug)]
    struct Pools {
        header: String,
        lines: Vec<Line>,
        total: (u64, u64, u64, u64),
        raw: String,
    }

    /// Takes `<digits>` off the front of `s`.
    fn num<'a>(s: &'a str, what: &str) -> (u64, &'a str) {
        let n = s.bytes().take_while(u8::is_ascii_digit).count();
        assert!(n > 0, "expected a number for {what} at {s:?}");
        (s[..n].parse().unwrap(), &s[n..])
    }

    fn lit<'a>(s: &'a str, p: &str) -> &'a str {
        s.strip_prefix(p).unwrap_or_else(|| panic!("expected {p:?} at {s:?}"))
    }

    fn parse_line(l: &str) -> Line {
        let r = lit(l, "  - Pool ");
        let (name, r) = r.split_once(" (").unwrap_or_else(|| panic!("no size in {l:?}"));
        assert!(!name.is_empty() && !name.contains(' '), "{l:?}");
        let (size, r) = num(r, "size");
        let r = lit(r, " bytes/");
        let (align, r) = num(r, "align");
        let r = lit(r, ") : ");
        let (allocated, r) = num(r, "allocated");
        let r = lit(r, " allocated (");
        let (bytes, r) = num(r, "bytes");
        let r = lit(r, " bytes), ");
        let (used, r) = num(r, "used");
        let r = lit(r, " used (~");
        let (cached, r) = num(r, "cached");
        let r = lit(r, " by thread caches), needed_avg ");
        let (_needed, r) = num(r, "needed_avg");
        let r = lit(r, ", ");
        let (failures, r) = num(r, "failures");
        let r = lit(r, " failures, ");
        let (users, r) = num(r, "users");
        let r = lit(r, " users, @0x");
        let n = r.bytes().take_while(u8::is_ascii_hexdigit).count();
        assert!(n > 0, "{l:?}");
        let r = &r[n..];
        let shared = r == " [SHARED]";
        assert!(shared || r.is_empty(), "trailing {r:?} in {l:?}");
        Line { name: name.into(), size, align, allocated, bytes, used, cached, failures, users, shared, regs: vec![] }
    }

    impl Pools {
        fn parse(raw: &str) -> Pools {
            assert!(raw.ends_with(".\n\n"), "the Total: line and an empty line must end the output: {raw:?}");
            let mut it = raw.lines();
            let header = it.next().unwrap().to_string();
            let mut lines: Vec<Line> = vec![];
            let mut total = None;
            for l in it {
                if l.starts_with("  - Pool ") {
                    lines.push(parse_line(l));
                } else if l.starts_with("      >  ") {
                    lines.last_mut().expect("registration before any pool").regs.push(l.to_string());
                } else if let Some(r) = l.strip_prefix("Total: ") {
                    let (n, r) = num(r, "pools");
                    let r = lit(r, " pools, ");
                    let (a, r) = num(r, "alloc");
                    let r = lit(r, " bytes allocated, ");
                    let (u, r) = num(r, "used");
                    let r = lit(r, " used (~");
                    let (c, r) = num(r, "cached");
                    assert_eq!(r, " by thread caches).", "{l:?}");
                    total = Some((n, a, u, c));
                } else {
                    assert!(l.is_empty() && total.is_some(), "unexpected line {l:?}");
                }
            }
            Pools { header, lines, total: total.expect("no Total: line"), raw: raw.into() }
        }

        fn get(&self, name: &str) -> &Line {
            self.lines.iter().find(|l| l.name == name).unwrap_or_else(|| panic!("no pool {name} in {}", self.raw))
        }
    }

    /// Both proxies and a backend, one test at a time.
    fn pair(test: &str) -> (std::sync::MutexGuard<'static, ()>, Backend, Proxy, Proxy) {
        let g = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = format!("/tmp/mem-show-pools/{test}");
        let be = Backend::start();
        let o = Proxy::start(false, &dir);
        let i = Proxy::start(true, &dir);
        (g, be, o, i)
    }

    /// In the interactive mode (`prompt`) the dump and the error end with the empty line and
    /// then the prompt, no more: HAProxy's `Total:` line is followed by `\n\n> `.
    #[test]
    fn show_pools_in_prompt_mode_ends_with_the_prompt() {
        let (_g, _be, o, i) = pair("prompt");
        for p in [&o, &i] {
            let mut s = UnixStream::connect(&p.sock).expect("cli connect");
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut read_to_prompt = |s: &mut UnixStream| {
                let mut got = Vec::new();
                let mut b = [0u8; 4096];
                while !got.ends_with(b"> ") {
                    let n = s.read(&mut b).expect("cli read");
                    assert!(n > 0, "closed: {}", String::from_utf8_lossy(&got));
                    got.extend_from_slice(&b[..n]);
                }
                String::from_utf8(got).unwrap()
            };
            s.write_all(b"prompt\n").unwrap();
            assert_eq!(read_to_prompt(&mut s), "\n> ");
            s.write_all(b"show pools 1\n").unwrap();
            let dump = read_to_prompt(&mut s);
            assert!(dump.starts_with("Dumping pools usage (limited to the first 1 entries)."), "{dump}");
            assert!(dump.ends_with(" by thread caches).\n\n> "), "{dump}");
            s.write_all(b"show pools bogus\n").unwrap();
            assert_eq!(read_to_prompt(&mut s), format!("{ERR}> "));
        }
    }

    #[test]
    fn show_pools_rejects_what_it_does_not_know() {
        let (_g, _be, o, i) = pair("bogus");
        for bad in ["bogus", "byname bogus", "match", "-1"] {
            let cmd = format!("show pools {bad}");
            assert_eq!(o.cli(&cmd), ERR, "oracle {bad}");
            assert_eq!(i.cli(&cmd), ERR, "ibex {bad}");
        }
    }

    #[test]
    fn show_pools_limit_and_sort_orders() {
        let (_g, _be, o, i) = pair("sorts");
        for p in [&o, &i] {
            let r = p.pools("byname 2");
            assert_eq!(r.header, "Dumping pools usage (limited to the first 2 entries). Use SIGQUIT to flush them.");
            assert_eq!(r.lines.len(), 2, "{}", r.raw);
            assert!(r.lines[0].name.as_bytes() <= r.lines[1].name.as_bytes(), "{}", r.raw);
            let all = p.pools("byname");
            assert_eq!(all.header, "Dumping pools usage. Use SIGQUIT to flush them.");
            assert!(all.lines.len() > 2);
            assert!(all.lines.windows(2).all(|w| w[0].name.as_bytes() <= w[1].name.as_bytes()), "{}", all.raw);
            // The limit cuts the lines, not the Total: that counts every pool that matched.
            assert_eq!(r.total.0 as usize, all.lines.len(), "{}", r.raw);
            let s = p.pools("bysize");
            assert!(s.lines.windows(2).all(|w| w[0].size >= w[1].size), "{}", s.raw);
            let u = p.pools("byusage");
            assert!(!u.lines.is_empty());
            assert!(u.lines.iter().all(|l| l.allocated > 0), "byusage hides empty pools: {}", u.raw);
            assert!(u.lines.windows(2).all(|w| w[0].bytes >= w[1].bytes), "{}", u.raw);
        }
    }

    #[test]
    fn show_pools_match_prefix_and_totals() {
        let (_g, _be, o, i) = pair("match");
        for p in [&o, &i] {
            let r = p.pools("match buf");
            assert!(!r.lines.is_empty(), "{}", r.raw);
            assert!(r.lines.iter().all(|l| l.name.starts_with("buf")), "{}", r.raw);
            assert!(r.lines.iter().any(|l| l.name == "buffer"), "{}", r.raw);
            assert_eq!(r.total.0 as usize, r.lines.len(), "{}", r.raw);
            assert_eq!(r.total.1, r.lines.iter().map(|l| l.bytes).sum::<u64>(), "{}", r.raw);
            // `match` and a number in any order.
            let m = p.pools("1 match buf");
            assert_eq!(m.lines.len(), 1);
            let none = p.pools("match nosuchpool");
            assert!(none.lines.is_empty() && none.total.0 == 0, "{}", none.raw);
        }
    }

    #[test]
    fn show_pools_line_shape_and_totals() {
        let (_g, _be, o, i) = pair("shape");
        let _c = i.keepalive();
        let _d = o.keepalive();
        for p in [&o, &i] {
            let r = p.pools("");
            assert!(r.lines.len() >= 4, "{}", r.raw);
            for l in &r.lines {
                assert!(l.used >= l.cached, "used includes the thread caches: {l:?}");
                assert_eq!(l.allocated * l.size, l.bytes, "{l:?}");
                assert!(l.align > 0 && l.users > 0, "{l:?}");
            }
            // Nothing moves between two reads of a quiet process only for the pools that
            // do not follow the CLI connection itself: compare the sums to the lines.
            assert_eq!(r.total.0 as usize, r.lines.len(), "{}", r.raw);
            assert_eq!(r.total.1, r.lines.iter().map(|l| l.bytes).sum::<u64>(), "{}", r.raw);
            assert_eq!(r.total.2, r.lines.iter().map(|l| l.used * l.size).sum::<u64>(), "{}", r.raw);
            assert_eq!(r.total.3, r.lines.iter().map(|l| l.cached * l.size).sum::<u64>(), "{}", r.raw);
            // `detailed`: one registration line per pool, with the provider's file and line.
            let d = p.pools("detailed");
            for l in &d.lines {
                assert!(!l.regs.is_empty(), "{} has no registration: {}", l.name, d.raw);
                for g in &l.regs {
                    let ok = g.starts_with("      >  ") && g.contains(": size=") && g.contains(" flags=")
                        && g.contains(" align=") && g.ends_with(']') && g.contains(" [");
                    assert!(ok, "{g:?}");
                }
            }
        }
        for l in &i.pools("").lines {
            assert!(!l.shared, "Ibex merges no pool: {l:?}");
            assert_eq!(l.failures, 0, "{l:?}");
        }
        let d = i.pools("detailed match session");
        assert!(d.lines[0].regs[0].contains(".rs:"), "{}", d.raw);
    }

    #[test]
    fn show_pools_counters_follow_traffic() {
        let (_g, _be, _o, i) = pair("counters");
        // The probes that waited for the listeners are closed but may not be reaped yet.
        let mut rest = i.pools("");
        for _ in 0..100 {
            if rest.get("session").in_use() == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
            rest = i.pools("");
        }
        assert_eq!(rest.get("session").in_use(), 0, "{}", rest.raw);
        let buf0 = rest.get("buffer").allocated;
        let conns: Vec<TcpStream> = (0..5).map(|_| i.keepalive()).collect();
        let busy = i.pools("");
        assert_eq!(busy.get("session").in_use(), 5, "{}", busy.raw);
        assert!(busy.get("session").allocated >= 5);
        assert!(busy.get("buffer").allocated > buf0, "{}", busy.raw);
        let held = busy.get("buffer").allocated;
        // `show info` sums the same providers, the two arenas included.
        let mut checked = false;
        for _ in 0..20 {
            let a = i.pools("");
            let info = i.cli("show info");
            let b = i.pools("");
            if a.total.1 == b.total.1 {
                let v: u64 = info
                    .lines()
                    .find_map(|l| l.strip_prefix("PoolAlloc_bytes: "))
                    .expect("PoolAlloc_bytes")
                    .parse()
                    .unwrap();
                assert_eq!(v, a.total.1, "PoolAlloc_bytes is the pools' Total:\n{}\n{info}", a.raw);
                assert!(v >= a.get("session").bytes + a.get("appctx").bytes, "{info}");
                checked = true;
                break;
            }
        }
        assert!(checked, "the pools never held still");
        drop(conns);
        let mut after = i.pools("");
        for _ in 0..100 {
            if after.get("session").in_use() == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
            after = i.pools("");
        }
        assert_eq!(after.get("session").in_use(), 0, "{}", after.raw);
        assert!(after.get("buffer").allocated >= held, "buffers are kept, not freed: {}", after.raw);
        assert!(after.get("appctx").allocated >= 1, "{}", after.raw);
    }
}
