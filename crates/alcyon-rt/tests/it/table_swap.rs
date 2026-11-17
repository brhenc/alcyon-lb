// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T637 S2: a table of backends is swapped under workers that are serving (design section 3.1).
//!
//! Two workers run their loops on their own threads, the way `alcyon` runs them. A client asks
//! the frontend for a page the whole time. The backend `b` of the table they hold sends to
//! server A; the table posted with [`alcyon_rt::table::publish`] has a `b` that sends to server B.
//! Every answer must be a complete 200 from A or from B (nothing is lost on the swap), and once
//! every worker has replied with the new epoch no answer comes from A.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use alcyon_rt::engine::Engine;
use alcyon_rt::mailbox::Mailboxes;
use alcyon_sched::task::TaskRef;

/// A server whose every answer is a 200 with `body` as its one-byte payload.
fn server(body: &'static str) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind server");
    let addr = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 2048];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut buf) {
                        Ok(n) if n > 0 => got.extend_from_slice(&buf[..n]),
                        _ => return,
                    }
                }
                let _ = c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n{body}").as_bytes());
            });
        }
    });
    addr
}

fn config(fe: SocketAddr, srv: SocketAddr) -> alcyon_config::Config {
    let text = format!(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  default_backend b\nbackend b\n  server s1 {srv}\n"
    );
    alcyon_config::parse_str(&text).expect("parse")
}

/// One request; the byte of the body of a complete 200, or why there is none.
fn get(fe: SocketAddr) -> Result<u8, String> {
    let mut c = TcpStream::connect(fe).map_err(|e| format!("connect: {e}"))?;
    c.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").map_err(|e| format!("write: {e}"))?;
    let mut out = Vec::new();
    c.read_to_end(&mut out).map_err(|e| format!("read: {e}"))?;
    if out.starts_with(b"HTTP/1.1 200 ") && (out.ends_with(b"\r\n\r\nA") || out.ends_with(b"\r\n\r\nB")) {
        Ok(out[out.len() - 1])
    } else {
        Err(format!("{:?}", String::from_utf8_lossy(&out)))
    }
}

#[test]
fn a_table_swapped_under_serving_workers_is_the_one_every_later_request_reads() {
    let (a, b) = (server("A"), server("B"));
    let fe = common::reserve_addr();
    let (cfg_a, cfg_b) = (config(fe, a), config(fe, b));
    let table_a = Engine::build_shared_state(&cfg_a).expect("shared state A");
    let table_b = Engine::build_shared_state(&cfg_b).expect("shared state B");
    let slot = table_a.slot_by_name("b").expect("backend b");
    let new = Arc::new(table_a.table().replace(slot, table_b[slot].clone()));
    assert_eq!(new.epoch(), 2);

    let boxes = Mailboxes::new(2).expect("mailboxes");
    let stop = Arc::new(AtomicBool::new(false));
    let workers: Vec<_> = (0..2)
        .map(|wid| {
            let (cfg, proxies, boxes, stop) = (cfg_a.clone(), table_a.clone(), Arc::clone(&boxes), Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut e = Engine::new_worker(&cfg, 64, wid, proxies).expect("worker");
                e.share_mailboxes(&boxes, wid).expect("mailboxes");
                while !stop.load(Ordering::Relaxed) {
                    let _ = e.run_once();
                }
            })
        })
        .collect();
    assert!(common::wait_listening(fe), "the frontend never listened");
    assert_eq!(get(fe), Ok(b'A'), "before the swap the backend sends to A");

    let traffic_stop = Arc::new(AtomicBool::new(false));
    let traffic = {
        let ts = Arc::clone(&traffic_stop);
        std::thread::spawn(move || {
            let mut seen = Vec::new();
            while !ts.load(Ordering::Relaxed) {
                seen.push(get(fe));
            }
            seen
        })
    };
    std::thread::sleep(Duration::from_millis(100));
    let g = alcyon_rt::table::publish(&boxes, &new, 0, TaskRef::NONE);
    let deadline = Instant::now() + Duration::from_secs(10);
    let epochs = loop {
        if let Some(e) = g.take() {
            break e;
        }
        assert!(Instant::now() < deadline, "no reply from every worker to the table");
        std::thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(epochs, vec![2, 2], "each worker replies with the epoch it now reads");
    for i in 0..20 {
        assert_eq!(get(fe), Ok(b'B'), "request {i} after the epoch reply");
    }
    traffic_stop.store(true, Ordering::Relaxed);
    let seen = traffic.join().expect("traffic");
    stop.store(true, Ordering::Relaxed);
    boxes.broadcast(|| alcyon_rt::mailbox::Msg::Wake(TaskRef::NONE));
    for w in workers {
        w.join().expect("worker");
    }
    assert!(seen.len() > 5, "the traffic ran during the swap: {} requests", seen.len());
    let bad: Vec<_> = seen.iter().filter(|r| r.is_err()).collect();
    assert!(bad.is_empty(), "requests lost across the swap: {bad:?}");
}
