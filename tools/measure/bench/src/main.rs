// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn run_backend(port: &str) {
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).expect("bind backend");
    println!("READY");
    for stream in listener.incoming() {
        if let Ok(mut s) = stream {
            s.set_nodelay(true).ok();
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let mut pending = Vec::new();
                let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    pending.extend_from_slice(&buf[..n]);
                    for _ in 0..complete_requests(&mut pending) {
                        if s.write_all(resp).is_err() {
                            return;
                        }
                    }
                }
            });
        }
    }
}

/// Takes the complete requests (head and `content-length` body) off the front of `pending` and
/// returns how many there were; a partial one stays for the next read (T555: a body in a read
/// of its own was answered as a request).
fn complete_requests(pending: &mut Vec<u8>) -> usize {
    let mut n = 0;
    while let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
        let head = &pending[..end];
        let len = head
            .split(|&b| b == b'\n')
            .find_map(|l| {
                let l = std::str::from_utf8(l).ok()?.trim();
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().ok()).flatten()
            })
            .unwrap_or(0);
        if pending.len() < end + 4 + len {
            break;
        }
        pending.drain(..end + 4 + len);
        n += 1;
    }
    n
}

fn run_client(addr: &str, conns: usize, duration_secs: u64) {
    let run = Arc::new(AtomicBool::new(true));
    let count = Arc::new(AtomicUsize::new(0));

    let mut threads = Vec::new();
    for _ in 0..conns {
        let r = run.clone();
        let c = count.clone();
        let a = addr.to_string();
        threads.push(thread::spawn(move || {
            let mut stream = match TcpStream::connect(&a) {
                Ok(s) => s,
                Err(_) => return,
            };
            stream.set_nodelay(true).unwrap();
            let mut buf = [0u8; 4096];
            let req = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
            while r.load(Ordering::Relaxed) {
                if stream.write_all(req).is_err() {
                    break;
                }
                match stream.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        c.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => break,
                }
            }
        }));
    }

    // Warmup 1s
    thread::sleep(Duration::from_secs(1));
    count.store(0, Ordering::Relaxed);
    let start = Instant::now();
    thread::sleep(Duration::from_secs(duration_secs));
    let elapsed = start.elapsed();
    run.store(false, Ordering::Relaxed);
    for t in threads {
        let _ = t.join();
    }
    let total = count.load(Ordering::Relaxed);
    let rps = total as f64 / elapsed.as_secs_f64();
    println!("total: {total}, rps: {rps:.2}");
}

fn run_fixed(addr: &str, conns: usize, num_requests: usize) {
    let count = Arc::new(AtomicUsize::new(0));
    let target = num_requests;
    let mut threads = Vec::new();

    for _ in 0..conns {
        let c = count.clone();
        let a = addr.to_string();
        threads.push(thread::spawn(move || {
            let mut stream = match TcpStream::connect(&a) {
                Ok(s) => s,
                Err(_) => return,
            };
            stream.set_nodelay(true).unwrap();
            let mut buf = [0u8; 4096];
            let req = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
            while c.load(Ordering::Relaxed) < target {
                if stream.write_all(req).is_err() {
                    break;
                }
                match stream.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        let prev = c.fetch_add(1, Ordering::Relaxed);
                        if prev + 1 >= target {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        }));
    }

    for t in threads {
        let _ = t.join();
    }
    println!("completed: {}", count.load(Ordering::Relaxed));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: measure-bench <backend|client|fixed> [args...]");
        std::process::exit(1);
    }
    match args[1].as_str() {
        "backend" => {
            if args.len() < 3 {
                eprintln!("Usage: measure-bench backend <port>");
                std::process::exit(1);
            }
            run_backend(&args[2]);
        }
        "client" => {
            if args.len() < 5 {
                eprintln!("Usage: measure-bench client <addr> <conns> <duration_secs>");
                std::process::exit(1);
            }
            let addr = &args[2];
            let conns: usize = args[3].parse().expect("conns");
            let duration: u64 = args[4].parse().expect("duration");
            run_client(addr, conns, duration);
        }
        "fixed" => {
            if args.len() < 5 {
                eprintln!("Usage: measure-bench fixed <addr> <conns> <num_requests>");
                std::process::exit(1);
            }
            let addr = &args[2];
            let conns: usize = args[3].parse().expect("conns");
            let reqs: usize = args[4].parse().expect("reqs");
            run_fixed(addr, conns, reqs);
        }
        other => {
            eprintln!("Unknown command: {other}");
            std::process::exit(1);
        }
    }
}
