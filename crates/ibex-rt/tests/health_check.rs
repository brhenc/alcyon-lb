// SPDX-License-Identifier: GPL-2.0-or-later

use ibex_config::{Config, ListenSection, Mode, Server};
use ibex_rt::{Engine, ServerStatus};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
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
    let dead_listener = TcpListener::bind("127.0.0.1:0").expect("bind temp");
    let dead_addr = dead_listener.local_addr().expect("dead addr");
    drop(dead_listener); // Now closed

    // 3. Bind proxy listener
    let proxy_bind = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_addr = proxy_bind.local_addr().expect("proxy addr");
    drop(proxy_bind);

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
        check.config.inter = Duration::from_millis(50);
        check.config.timeout = Duration::from_millis(100);
        check.config.fall = 2;
        check.config.rise = 1;
    }

    // Run engine passes to execute health checks
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_millis(400) {
        let _ = engine.run_once().expect("engine run_once");
        thread::sleep(Duration::from_millis(10));
    }

    // Verify server statuses
    assert_eq!(
        engine.proxies[0].server_statuses[0],
        ServerStatus::Down,
        "dead server should be DOWN"
    );
    assert_eq!(
        engine.proxies[0].server_statuses[1],
        ServerStatus::Up,
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
