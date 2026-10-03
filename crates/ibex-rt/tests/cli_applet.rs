// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Integration tests for CLI Applet and Unix Domain Socket (hatop compatibility).

mod common;

use ibex_config::parse_str;
use ibex_rt::Engine;
use ibex_sched::Tick;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

fn create_test_engine(socket_path: &PathBuf) -> Engine {
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
        engine.proxies[0].server_statuses[0].load(std::sync::atomic::Ordering::Relaxed), ibex_rt::ServerStatus::Down as u8,
        "srv1 should be marked Down after disable server"
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
        engine.proxies[0].server_statuses[1].load(std::sync::atomic::Ordering::Relaxed), ibex_rt::ServerStatus::Down as u8,
        "srv2 should be marked Down after set server state drain"
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

#[test]
fn cli_applet_show_pools() {
    let _g = BUFSIZE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let socket_path = PathBuf::from(format!(
        "/tmp/ibex_test_pools_{}.sock",
        std::process::id()
    ));
    let mut engine = create_test_engine(&socket_path);

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
    let expected = format!("- Pool buffer ({} bytes)", ibex_rt::buf::get_bufsize());
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
        text.contains("- Pool buffer (32768 bytes)"),
        "show pools must report configured tune.bufsize 32768: {text}"
    );
    assert!(
        text.contains("- Pool small_buffer (2048 bytes)"),
        "show pools must report configured tune.bufsize.small 2048: {text}"
    );
    assert!(
        text.contains("- Pool large_buffer (65536 bytes)"),
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
    let mut engine = Engine::new(&config, 1024).expect("engine");
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

    assert_eq!(execute_cmd("clear counters server nosuch/s1\n"), "No such backend.\n");
    assert_eq!(execute_cmd("clear counters server be/nosuch\n"), "No such server.\n");
    
    let info = execute_cmd("show info nonexistent\n");
    assert!(info.starts_with("Name: Ibex"), "show info nonexistent should return info dump");

    assert_eq!(execute_cmd("show servers state nonexistent\n"), "Can't find backend.\n");
    
    assert_eq!(execute_cmd("set server nosuch/s1 state maint\n"), "No such backend.\n");
    assert_eq!(execute_cmd("set server be/nosuch state maint\n"), "No such server.\n");
    assert_eq!(execute_cmd("set server be/nosuch maxconn 10\n"), "");

    let table = execute_cmd("show table be\n");
    assert!(table.contains("# table: be, type: ip, size:1048576, used:0"));
}
