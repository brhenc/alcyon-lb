// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use std::env;
use std::fs;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::io::{Read, Write};

fn find_free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("bind udp")
        .local_addr()
        .expect("local_addr")
        .port()
}

fn find_free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind tcp")
        .local_addr()
        .expect("local_addr")
        .port()
}

fn curl_has_http3() -> bool {
    let out = Command::new("curl").arg("--version").output().expect("curl version");
    String::from_utf8_lossy(&out.stdout).contains("HTTP3")
}

fn spawn_echo_backend(stop: Arc<AtomicBool>, port: u16) {
    let l = TcpListener::bind(format!("127.0.0.1:{port}")).expect("bind backend");
    l.set_nonblocking(true).expect("nonblocking");
    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match l.accept() {
                Ok((mut c, _)) => {
                    let mut buf = [0u8; 4096];
                    let _ = c.set_read_timeout(Some(Duration::from_millis(500)));
                    if let Ok(n) = c.read(&mut buf) {
                        if n > 0 {
                            let body = b"hello-from-ibex-h3";
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                                body.len(),
                                String::from_utf8_lossy(body)
                            );
                            let _ = c.write_all(resp.as_bytes());
                        }
                    }
                }
                Err(_) => thread::sleep(Duration::from_millis(5)),
            }
        }
    });
}

fn create_cert(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("test.pem");
    let out = Command::new("openssl")
        .args([
            "req", "-newkey", "rsa:2048", "-new", "-nodes", "-x509",
            "-days", "3650",
            "-keyout", path.to_str().unwrap(),
            "-out", path.to_str().unwrap(),
            "-subj", "/CN=localhost"
        ])
        .output()
        .expect("openssl req");
    assert!(out.status.success(), "openssl failed");
    path
}

#[test]
fn quic4_bind_parses_and_serves_http3() {
    if !curl_has_http3() {
        eprintln!("curl on this host has no HTTP3 support; skipping");
        return;
    }

    let temp_dir = std::env::temp_dir();
    let cert = create_cert(&temp_dir);
    let quic_port = find_free_port();
    let backend_port = find_free_tcp_port();

    let cfg_path = temp_dir.join(format!("ibex_{}_{}.cfg", std::process::id(), std::sync::atomic::AtomicUsize::new(0).fetch_add(1, std::sync::atomic::Ordering::SeqCst) + std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos() as usize));
    let cfg = format!(
        "
global
    log stdout format raw local0

defaults
    mode http
    timeout client 5s
    timeout connect 5s
    timeout server 5s

frontend test_quic
    bind quic4@127.0.0.1:{quic_port} ssl crt {cert}
    default_backend default

backend default
    server s1 127.0.0.1:{backend_port}
",
        quic_port = quic_port,
        cert = cert.display(),
        backend_port = backend_port
    );
    fs::write(&cfg_path, cfg).expect("write config");

    let stop = Arc::new(AtomicBool::new(false));
    spawn_echo_backend(Arc::clone(&stop), backend_port);

    let bin = std::env::var("CARGO_BIN_EXE_ibex").unwrap_or_else(|_| std::env::current_dir().unwrap().parent().unwrap().parent().unwrap().join("target/debug/ibex").to_string_lossy().to_string());
    let mut ibex = Command::new(bin)
        .arg("-f")
        .arg(&cfg_path)
        .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().expect("spawn ibex");

    thread::sleep(Duration::from_millis(1500)); // wait for ibex to start

    let out = Command::new("curl")
        .args([
            "-sS", "--http3-only", "-k", "--max-time", "15",
            "--resolve", &format!("localhost:{quic_port}:127.0.0.1"),
            &format!("https://localhost:{quic_port}/probe"),
            "-o", "-", "-w", "\n__STATUS__%{http_code} __VER__%{http_version}",
        ])
        .output()
        .expect("run curl");

    stop.store(true, Ordering::Relaxed);
    let _ = ibex.kill();
    let out_ibex = ibex.wait_with_output().expect("wait ibex");
    let ibex_stdout = String::from_utf8_lossy(&out_ibex.stdout);
    let ibex_stderr = String::from_utf8_lossy(&out_ibex.stderr);
    println!("IBEX STDOUT:\n{}\nIBEX STDERR:\n{}", ibex_stdout, ibex_stderr);
    

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        stdout.contains("__STATUS__200"),
        "curl --http3 must get 200 from Ibex over a quic4@ bind.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("__VER__3"),
        "the response must arrive over HTTP/3, not a fallback.\nstdout: {stdout}"
    );
    assert!(
        stdout.contains("hello-from-ibex-h3"),
        "the response body must reach the client.\nstdout: {stdout}"
    );
}

#[test]
fn quic_bind_requires_ssl() {
    let temp_dir = std::env::temp_dir();
    let cfg_path = temp_dir.join(format!("ibex_{}_{}.cfg", std::process::id(), std::sync::atomic::AtomicUsize::new(0).fetch_add(1, std::sync::atomic::Ordering::SeqCst) + std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos() as usize));
    let cfg = "
frontend test_quic
    bind quic4@127.0.0.1:8443
";
    fs::write(&cfg_path, cfg).expect("write config");

    let bin = std::env::var("CARGO_BIN_EXE_ibex").unwrap_or_else(|_| std::env::current_dir().unwrap().parent().unwrap().parent().unwrap().join("target/debug/ibex").to_string_lossy().to_string());
    let out = Command::new(bin)
        .arg("-c")
        .arg("-f")
        .arg(&cfg_path)
        .output()
        .expect("run ibex");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "ibex -c should fail for quic without ssl");
    assert!(stderr.contains("QUIC protocol detected, enabling ssl. Use 'ssl' to shut this warning."), "expected warning: {}", stderr);
    assert!(stderr.contains("no SSL certificate specified for bind (use 'crt')"), "expected error message: {}", stderr);
}

#[test]
fn quic_unsupported_prefixes_rejected() {
    let temp_dir = std::env::temp_dir();
    let cfg_path = temp_dir.join(format!("ibex_{}_{}.cfg", std::process::id(), std::sync::atomic::AtomicUsize::new(0).fetch_add(1, std::sync::atomic::Ordering::SeqCst) + std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos() as usize));
    let cfg = "
frontend test_quic
    bind dgram+127.0.0.1:8443 ssl crt dummy.pem
";
    fs::write(&cfg_path, cfg).expect("write config");

    let bin = std::env::var("CARGO_BIN_EXE_ibex").unwrap_or_else(|_| std::env::current_dir().unwrap().parent().unwrap().parent().unwrap().join("target/debug/ibex").to_string_lossy().to_string());
    let out = Command::new(bin)
        .arg("-c")
        .arg("-f")
        .arg(&cfg_path)
        .output()
        .expect("run ibex");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "ibex -c should fail for dgram+");
    assert!(stderr.contains("address prefix 'dgram+' is not implemented"), "expected error message: {}", stderr);
}
