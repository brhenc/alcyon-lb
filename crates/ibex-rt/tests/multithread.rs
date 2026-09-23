use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

#[test]
fn test_multithread_config_initialization() {
    // Write a config with nbthread 4 and custom maxrewrite.
    let config_path = "/tmp/multithread_test.cfg";
    let mut f = std::fs::File::create(config_path).unwrap();
    f.write_all(b"
global
    nbthread 4
    tune.maxrewrite 2048

defaults
    mode http
    timeout connect 5s
    timeout client  5s
    timeout server  5s

frontend fe
    bind 127.0.0.1:48192
    http-request add-header X-Padding ").unwrap();

    let padding = "A".repeat(1500);
    f.write_all(padding.as_bytes()).unwrap();

    f.write_all(b"
    default_backend be

backend be
    server s1 127.0.0.1:48193
").unwrap();
    f.flush().unwrap();

    // Start a dummy backend
    let dummy_be = std::net::TcpListener::bind("127.0.0.1:48193").unwrap();

    let exe = env::var("CARGO_BIN_EXE_ibex").unwrap_or_else(|_| "target/debug/ibex".to_string());
    
    let mut child = Command::new(exe)
        .arg("-D")
        .arg("-p")
        .arg("/tmp/ibex_test.pid")
        .arg("-f")
        .arg(config_path)
        .spawn()
        .expect("failed to spawn ibex");

    // Wait for it to daemonize
    let status = child.wait().expect("failed to wait on ibex");
    assert!(status.success(), "ibex failed to start: {:?}", status);

    // Give it a moment to fully initialize
    std::thread::sleep(Duration::from_millis(500));

    // Send 100 requests. If any thread did not initialize its thread_locals,
    // the request will fail because the padding is 1500 > default maxrewrite 1024.
    let mut success_count = 0;
    for _ in 0..100 {
        if let Ok(mut stream) = TcpStream::connect("127.0.0.1:48192") {
            stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            
            // Accept on dummy backend
            if let Ok((mut be_stream, _)) = dummy_be.accept() {
                let mut buf = [0u8; 4096];
                let n = be_stream.read(&mut buf).unwrap_or(0);
                if n > 0 {
                    be_stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").unwrap();
                    success_count += 1;
                }
            }
        }
    }

    assert_eq!(success_count, 100, "Not all requests succeeded. Some threads might have failed to initialize maxrewrite.");

    // Clean up
    if let Ok(pid_str) = std::fs::read_to_string("/tmp/ibex_test.pid") {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            let _ = std::process::Command::new("kill").arg(pid_str.trim()).output();
        }
    }
}
