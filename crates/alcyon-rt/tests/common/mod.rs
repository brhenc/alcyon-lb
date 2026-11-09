// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Shared helpers for the alcyon-rt integration tests.
//!
//! Each test file that uses this says `mod common;`; not every file uses every helper.
#![allow(dead_code)]

use std::fs::File;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Mutex;

/// Ports handed out by [`reserve_addr`]: below the kernel's ephemeral range
/// (`/proc/sys/net/ipv4/ip_local_port_range`, 32768-60999 by default).
const FIRST: u16 = 20000;
const COUNT: u16 = 12768;

/// Lock files held until the process exits.
static HELD: Mutex<Vec<File>> = Mutex::new(Vec::new());

/// A loopback address on which the test can start a listener, for example the frontend
/// of an alcyon it is about to spawn.
///
/// Picking a port by binding `:0`, dropping the listener and binding again later loses a
/// race. Between the drop and the rebind, the kernel can hand the same port to any
/// `connect()` or `bind(:0)` in the test run, and the proxy then fails to start. And
/// because alcyon binds with `SO_REUSEPORT`, two proxies given the same port can both
/// start, so one test's requests reach another test's proxy. Both happened in the suite.
///
/// So a port here:
/// * comes from below the ephemeral range, so the kernel never assigns it to anyone;
/// * is exclusively `flock`ed under the temp directory, so no other test in this
///   process or in a concurrently running test process (another worktree, an oracle run)
///   is given it. The lock is held until the process exits, and the kernel drops it then,
///   even after a crash;
/// * was bindable at the moment it was handed out, which skips ports that something
///   outside the tests is using.
///
/// The caller binds later, so a short window remains in which a process outside the tests
/// could take the port; the lock only excludes other users of this helper.
pub fn reserve_addr() -> SocketAddr {
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let dir = std::env::temp_dir().join("alcyon-test-ports");
    std::fs::create_dir_all(&dir).expect("create the port lock directory");
    // Start each process somewhere different so concurrent runs rarely contend for a lock.
    let start = u16::try_from(std::process::id().wrapping_mul(97) % u32::from(COUNT)).unwrap_or(0);
    for _ in 0..COUNT {
        let i = NEXT.fetch_add(1, Ordering::Relaxed) % COUNT;
        let port = FIRST + (start + i) % COUNT;
        let Ok(file) = File::create(dir.join(port.to_string())) else { continue };
        if rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_err() {
            continue;
        }
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
        if !bindable(addr) {
            continue; // in use by something outside the tests
        }
        HELD.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(file);
        return addr;
    }
    panic!("no free test port in {FIRST}..{}", FIRST + COUNT);
}

/// Whether `addr` can be bound: for TCP the way alcyon binds (`SO_REUSEADDR`) and without
/// listening, and for UDP by anyone.
///
/// `TcpListener::bind` listens. A test that spawns a process at that moment forks a child
/// holding a copy of every open descriptor until it execs, so the probe could outlive its
/// drop by a few hundred microseconds, still listening, and alcyon's bind then failed with
/// `EADDRINUSE` (traced in `tcp_proxy` under concurrent runs). A socket that is only bound
/// does not conflict with a later `SO_REUSEADDR` bind, wherever copies of it live.
pub fn bindable(addr: SocketAddr) -> bool {
    use rustix::net::{AddressFamily, SocketFlags, SocketType};
    let Ok(fd) = rustix::net::socket_with(AddressFamily::INET, SocketType::STREAM, SocketFlags::CLOEXEC, None)
    else {
        return false;
    };
    if !(rustix::net::sockopt::set_socket_reuseaddr(&fd, true).is_ok() && rustix::net::bind(&fd, &addr).is_ok()) {
        return false;
    }
    // The same port for UDP, with no reuse option, so the bind fails if anything holds it. A
    // QUIC listener holds only UDP, with `SO_REUSEPORT`: an alcyon a failed test left running
    // kept its port, the TCP probe alone handed it out again, and the next QUIC test's alcyon
    // joined the orphan's reuseport group and lost datagrams to it (2026-11-09,
    // tests/it/common_helpers.rs).
    let Ok(udp) = rustix::net::socket_with(AddressFamily::INET, SocketType::DGRAM, SocketFlags::CLOEXEC, None)
    else {
        return false;
    };
    rustix::net::bind(&udp, &addr).is_ok()
}

/// The port of [`reserve_addr`].
pub fn reserve_port() -> u16 {
    reserve_addr().port()
}

/// Steps an in-process engine until `done` holds, for up to two seconds.
///
/// A fixed number of steps is a guess at how long the kernel takes to deliver a connection
/// to the listener, and on a loaded machine (the whole suite runs in parallel) the guess is
/// short. Returns whether `done` held; the caller asserts on the value it wanted, so a real
/// failure still reports what it saw.
pub fn drive_until(engine: &mut alcyon_rt::engine::Engine, mut done: impl FnMut(&alcyon_rt::engine::Engine) -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        let _ = engine.run_once();
        if done(engine) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    false
}

/// Waits up to five seconds for something to accept connections on `addr`. The probe
/// connection is closed without sending anything.
pub fn wait_listening(addr: SocketAddr) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(200)).is_ok() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    false
}

/// Stops a spawned `alcyon` the way it exits cleanly -- `SIGUSR1`, the soft stop -- and waits
/// for it; `SIGKILL` only if it is still there after five seconds.
///
/// Under `cargo llvm-cov` the spawned binary is instrumented, but it writes its coverage
/// profile only on a normal exit. A test that ends the daemon with `SIGKILL` therefore runs
/// its code and counts for nothing: `harness/covercheck.py` reported the HTTP/2 client read
/// path (`proxy.rs`) as executed by no test while `h2_multiplexing` drove it on every run.
/// Every test that spawns the binary ends it through here.
pub fn stop(child: &mut std::process::Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    if let Some(pid) = i32::try_from(child.id()).ok().and_then(rustix::process::Pid::from_raw) {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::Usr1);
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// A spawned `alcyon` that is stopped when it goes out of scope, also when the test panics
/// before it reaches its own `stop` call. Derefs to `Child`, so `common::stop(&mut alcyon)`,
/// `alcyon.id()` and `alcyon.stdout.take()` keep working. `stop` is a no-op on a child that has
/// already exited, so an explicit `common::stop` followed by the drop is harmless.
pub struct Alcyon(pub std::process::Child);

impl std::ops::Deref for Alcyon {
    type Target = std::process::Child;
    fn deref(&self) -> &std::process::Child {
        &self.0
    }
}

impl std::ops::DerefMut for Alcyon {
    fn deref_mut(&mut self) -> &mut std::process::Child {
        &mut self.0
    }
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        stop(&mut self.0);
    }
}

thread_local! {
    /// The HTTP/3 path (`relay` or `mux`) of the alcyon the test on this thread starts, set by
    /// [`h3_both_paths!`]; empty, the environment's `ALCYON_H3_PATH` decides as in alcyon.
    static H3_PATH: std::cell::Cell<&'static str> = const { std::cell::Cell::new("") };
}

/// Runs `test` with every alcyon this thread starts through [`alcyon_command`] on the HTTP/3
/// path `path` (T511: `tune.alcyon.h3-path`, through `ALCYON_H3_PATH` in the child's
/// environment).
pub fn on_h3_path(path: &'static str, test: impl FnOnce()) {
    H3_PATH.with(|p| p.set(path));
    test();
}

/// The test on this thread runs its alcyon with HTTP/3 streams through the mux.
pub fn h3_mux() -> bool {
    match H3_PATH.with(std::cell::Cell::get) {
        "" => std::env::var("ALCYON_H3_PATH").map_or(true, |v| v != "relay"),
        p => p == "mux",
    }
}

/// `mux` or `relay`: the HTTP/3 path of the alcyon the test on this thread starts, for names
/// (directories, sockets) that must not collide between the two copies of a [`h3_both_paths!`]
/// test running in parallel.
pub fn h3_path_name() -> &'static str {
    if h3_mux() { "mux" } else { "relay" }
}

/// `Command::new` for the alcyon under test, on this thread's HTTP/3 path.
pub fn alcyon_command(bin: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    let mut c = std::process::Command::new(bin);
    let path = H3_PATH.with(std::cell::Cell::get);
    if !path.is_empty() {
        c.env("ALCYON_H3_PATH", path);
    }
    c
}

/// Each test fn twice, `<name>::relay` and `<name>::mux` (T511): the HTTP/3 tests run on
/// both paths of `tune.alcyon.h3-path`, in parallel as any two tests, so the gate's coverage
/// sees the mux's lines and the relay keeps its tests until it is removed (slice H5).
#[macro_export]
macro_rules! h3_both_paths {
    ($(#[$m:meta])* fn $name:ident() $body:block) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            fn both_paths_body() $body
            $(#[$m])*
            #[test]
            fn relay() {
                $crate::common::on_h3_path("relay", both_paths_body);
            }
            $(#[$m])*
            #[test]
            fn mux() {
                $crate::common::on_h3_path("mux", both_paths_body);
            }
        }
    };
}

/// `$ALCYON_REFERENCE/<rel>`: a file of the reference `HAProxy` builds (T630; README, "Running the
/// oracle tests"), for example `haproxy/haproxy`, `haproxy-quic/haproxy` or
/// `haproxy-1.0.2/haproxy102`. `None`, after a line saying why the caller skips, when the
/// variable is unset or empty or the file is not there. There is no default under anyone's
/// home; the gate checks the files exist before its suite runs (`harness/reference.py
/// --require`), so a skip cannot pass a gate.
pub fn reference(rel: &str) -> Option<std::path::PathBuf> {
    let Some(root) = std::env::var_os("ALCYON_REFERENCE").filter(|v| !v.is_empty()) else {
        println!("skipped: ALCYON_REFERENCE is not set (this test needs $ALCYON_REFERENCE/{rel})");
        return None;
    };
    let p = std::path::Path::new(&root).join(rel);
    if p.exists() {
        Some(p)
    } else {
        println!("skipped: {} does not exist (ALCYON_REFERENCE)", p.display());
        None
    }
}
