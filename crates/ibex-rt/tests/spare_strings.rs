// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (AGENTS.md rule 6): sets the process-wide `tune.memory.hot-size` and
// `tune.ibex.zero-spares`, and installs a #[global_allocator] to see what a freed spare left
// in memory; any other test in a shared binary would change both under it.

//! S1 (design/memory-2026-10-24.md, ported from fix/t444's test): the spare strings and lists
//! each thread keeps (`ibex_sample::spare`, `ibex_alloc::Pool`s) are bounded by
//! `tune.memory.hot-size` as `HAProxy`'s per-thread hot cache is, listed in `show pools`,
//! freed by the thread's pool walk (`pool_gc`), and wiped when `tune.ibex.zero-spares` is on
//! (whatever `tune.ibex.zero-buffers` says: that one is the I/O buffers').

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ibex_alloc::CountingAllocator;
use ibex_rt::engine::Engine;
use ibex_sample::spare;

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator::new();

/// The settings are process-wide: the tests take turns.
static TURN: Mutex<()> = Mutex::new(());

const SECRET: &str = "Authorization: Bearer hunter2-0123456789abcdef";

/// The first bytes of the block of `cap` bytes `act` frees, given a string of that capacity
/// holding [`SECRET`]; `None` when `act` frees no such block.
fn freed_after(cap: usize, act: impl FnOnce(String)) -> Option<Vec<u8>> {
    let mut s = String::with_capacity(cap);
    s.push_str(SECRET);
    assert_eq!(s.capacity(), cap);
    ibex_alloc::watch_freed(cap);
    act(s);
    ibex_alloc::freed_bytes()
}

fn zeros(b: Option<&Vec<u8>>) -> bool {
    b.is_some_and(|b| !b.is_empty() && b.iter().all(|&x| x == 0))
}

fn secret(b: Option<&Vec<u8>>) -> bool {
    b.is_some_and(|b| b.starts_with(SECRET.as_bytes()))
}

/// A string given back is wiped before it is kept, and before it is freed for being over a
/// limit; a scratch string is wiped when it goes back to its pool. With the setting off the
/// old bytes stay. `tune.ibex.zero-buffers` is set the other way each time: it does not decide.
#[test]
fn a_spare_string_is_wiped_when_zero_spares_is_on() {
    let _turn = TURN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    ibex_alloc::set_hot_size(ibex_alloc::HOT_SIZE_DEFAULT);
    for on in [true, false] {
        ibex_alloc::set_zero_spares(on);
        ibex_alloc::set_zero_buffers(!on);
        let check = |what: &str, b: Option<Vec<u8>>| {
            if on {
                assert!(zeros(b.as_ref()), "setting on, {what}: freed bytes {b:?}");
            } else {
                assert!(secret(b.as_ref()), "setting off, {what}: freed bytes {b:?}");
            }
        };
        let _ = ibex_alloc::drain_local_pools();
        // Kept, then handed out again (LIFO) and dropped.
        check("kept", freed_after(4000, |s| {
            spare::give(s);
            drop(spare::string());
        }));
        // Larger than a string is kept.
        check("over KEEP_MAX", freed_after(spare::KEEP_MAX + 4000, spare::give));
        // Over what the thread may keep.
        ibex_alloc::set_hot_size(1000);
        check("over hot-size", freed_after(4000, spare::give));
        ibex_alloc::set_hot_size(ibex_alloc::HOT_SIZE_DEFAULT);
        // A scratch string: the nested call's goes back to the pool, and is freed when the
        // thread's pools are drained.
        check("scratch", freed_after(3000, |s| {
            let mut s = Some(s);
            ibex_rt::reuse::with_string(|_| ibex_rt::reuse::with_string(|b| *b = s.take().unwrap_or_default()));
            let _ = ibex_alloc::drain_local_pools();
        }));
    }
    ibex_alloc::set_zero_spares(false);
    ibex_alloc::set_zero_buffers(false);
}

/// AGENTS.md 5: `tune.ibex.zero-spares` reaches the give. `Engine::new` applies the global
/// setting (`ibex_alloc::set_zero_spares`), the pools' thread copy follows, and the give wipes
/// from it. Unset is off.
#[test]
fn the_configured_zero_spares_reaches_the_give() {
    let _turn = TURN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    ibex_alloc::set_hot_size(ibex_alloc::HOT_SIZE_DEFAULT);
    for (text, wiped) in [("on", true), ("", false), ("off", false)] {
        // The opposite of what zero-spares asks: the buffer setting must not decide.
        let mut global = format!("global\n    tune.ibex.zero-buffers {}\n", if wiped { "off" } else { "on" });
        if !text.is_empty() {
            global.push_str(&format!("    tune.ibex.zero-spares {text}\n"));
        }
        let _engine = Engine::new(&ibex_config::parse_str(&global).expect("parse"), 64).expect("Engine::new");
        let _ = ibex_alloc::drain_local_pools();
        let b = freed_after(4000, |s| {
            spare::give(s);
            drop(spare::string());
        });
        if wiped {
            assert!(zeros(b.as_ref()), "zero-spares {text:?}: freed bytes {b:?}");
        } else {
            assert!(secret(b.as_ref()), "zero-spares {text:?}: freed bytes {b:?}");
        }
    }
    ibex_alloc::set_zero_spares(false);
    ibex_alloc::set_zero_buffers(false);
}

/// A server that answers no request before it has `n` of them (or 10 s went by), so that the
/// `n` requests are in the proxy at once.
fn held_backend(l: TcpListener, n: usize, run: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        l.set_nonblocking(true).expect("nonblocking");
        let mut conns: Vec<(TcpStream, bool)> = Vec::new();
        let mut buf = vec![0u8; 65536];
        let start = Instant::now();
        let mut answered = false;
        while run.load(Ordering::Relaxed) {
            while let Ok((s, _)) = l.accept() {
                s.set_nonblocking(true).expect("nonblocking");
                conns.push((s, false));
            }
            for (s, head) in &mut conns {
                if let Ok(k) = s.read(&mut buf) {
                    if k > 0 && buf[..k].windows(4).any(|w| w == b"\r\n\r\n") {
                        *head = true;
                    }
                }
            }
            let heads = conns.iter().filter(|c| c.1).count();
            if !answered && (heads >= n || start.elapsed() > Duration::from_secs(10)) {
                for (s, _) in &mut conns {
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                }
                conns.clear();
                answered = true;
            }
            thread::sleep(Duration::from_millis(1));
        }
    })
}

/// `n` requests, each with a 15 KiB URI and a 15 KiB header copied into a variable, in the
/// proxy at once; the engine runs on this thread, so its spares are this thread's. Returns
/// how many got their answer.
fn burst(global: &str, n: usize) -> usize {
    let (sl, sa) = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let a = l.local_addr().expect("addr");
        (l, a)
    };
    let fa: SocketAddr = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr")
    };
    let run = Arc::new(AtomicBool::new(true));
    let be = held_backend(sl, n, Arc::clone(&run));
    let cfg = format!(
        "global\n  maxconn 4000\n  tune.bufsize 65536\n{global}defaults\n  mode http\n  timeout client 20s\n  timeout server 20s\n  timeout connect 5s\n\
         frontend f\n  bind {fa}\n  http-request set-var(txn.big) req.hdr(x-big)\n  default_backend b\nbackend b\n  server s1 {sa}\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let req = format!(
        "GET /{} HTTP/1.1\r\nHost: localhost\r\nX-Big: {}\r\nConnection: close\r\n\r\n",
        "u".repeat(15 * 1024),
        "h".repeat(15 * 1024)
    );
    let mut clients: Vec<(TcpStream, usize, Vec<u8>, bool)> = Vec::with_capacity(n);
    for _ in 0..n {
        let c = TcpStream::connect(fa).expect("connect");
        c.set_nonblocking(true).expect("nonblocking");
        clients.push((c, 0, Vec::new(), false));
        let _ = engine.run_once();
    }
    let start = Instant::now();
    let mut buf = [0u8; 4096];
    while start.elapsed() < Duration::from_secs(30) && clients.iter().any(|c| !c.3) {
        let _ = engine.run_once();
        for (c, sent, got, done) in &mut clients {
            if *sent < req.len() {
                match c.write(&req.as_bytes()[*sent..]) {
                    Ok(k) => *sent += k,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                    Err(_) => *done = true,
                }
            }
            if !*done {
                match c.read(&mut buf) {
                    Ok(0) => *done = true,
                    Ok(k) => got.extend_from_slice(&buf[..k]),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                    Err(_) => *done = true,
                }
            }
        }
    }
    let ok = clients.iter().filter(|c| c.2.starts_with(b"HTTP/1.1 200")).count();
    drop(clients);
    for _ in 0..20 {
        let _ = engine.run_once();
    }
    run.store(false, Ordering::Relaxed);
    let _ = be.join();
    ok
}

/// After 600 requests with 15 KiB values at once, this thread keeps at most
/// `tune.memory.hot-size` bytes of spares: 524288 when unset, 65536 when set so. The thread's
/// pool walk (what `pool_gc` runs) frees them.
#[test]
fn a_burst_keeps_no_more_spare_bytes_than_hot_size() {
    let _turn = TURN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    // Given back directly, 600 strings of 15 KiB: what the thread keeps is the bound.
    ibex_alloc::set_hot_size(ibex_alloc::HOT_SIZE_DEFAULT);
    let _ = ibex_alloc::drain_local_pools();
    for _ in 0..600 {
        spare::give(String::with_capacity(15 * 1024));
    }
    let kept = spare::thread_bytes();
    assert!(kept > ibex_alloc::HOT_SIZE_DEFAULT / 2 && kept <= ibex_alloc::HOT_SIZE_DEFAULT, "{kept} bytes kept of 600 strings given back, bound {}", ibex_alloc::HOT_SIZE_DEFAULT);
    // Through the proxy: the method and URI of each connection (`ReqText`) are spares.
    for (global, limit) in [("", ibex_alloc::HOT_SIZE_DEFAULT), ("  tune.memory.hot-size 65536\n", 65536)] {
        let _ = ibex_alloc::drain_local_pools();
        let ok = burst(global, 600);
        assert_eq!(ok, 600, "{global:?}: not every request was answered");
        let kept = spare::thread_bytes();
        println!("[MEASUREMENT S1] {global:?}: {kept} bytes of spares kept after 600 requests at once");
        assert!(kept > limit / 2, "{global:?}: {kept} bytes kept: the burst left the spares nearly empty, so it tests nothing");
        assert!(kept <= limit, "{global:?}: {kept} bytes kept, over the limit of {limit}");
        let _ = ibex_alloc::drain_local_pools();
        assert_eq!(spare::thread_bytes(), 0, "{global:?}: the pool walk left spares");
    }
}

/// `show pools` lists the spare strings and lists, with HAProxy's line format, and counts
/// their bytes in the totals `show info` reads.
#[test]
fn show_pools_lists_the_spares() {
    let _turn = TURN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    ibex_alloc::set_hot_size(ibex_alloc::HOT_SIZE_DEFAULT);
    let _ = ibex_alloc::drain_local_pools();
    assert_eq!(burst("", 50), 50);
    let kept = spare::thread_bytes();
    assert!(kept > 0, "the requests left no spare");
    let pools = ibex_alloc::global_pool_registry().show_pools(&[]);
    let line = pools.lines().find(|l| l.starts_with("  - Pool spare_str (")).unwrap_or_else(|| panic!("no spare_str pool in:\n{pools}"));
    assert!(line.contains(" by thread caches), needed_avg 0, 0 failures, 1 users, @0x"), "{line}");
    assert!(pools.lines().any(|l| l.starts_with("  - Pool spare_list (")), "no spare_list pool in:\n{pools}");
    let (alloc, _) = ibex_alloc::global_pool_registry().totals();
    assert!(alloc >= kept as u64, "show info's pool bytes ({alloc}) leave out the {kept} spare bytes");
}
