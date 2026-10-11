// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `global maxconn` (T146 item 3): the number of client connections the process holds at
//! once, across every frontend and worker (`actconn`/`global.maxconn` in `HAProxy`).
//!
//! Past it the listeners stop accepting, and the connections wait in the kernel backlog
//! until one closes (`limit_listener(.., &global_listener_queue)`), as with a frontend's
//! own `maxconn`. The stats socket is not counted. State is process-wide, set when an
//! engine is built from a configuration that has a `maxconn`.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static CURR: AtomicU32 = AtomicU32::new(0);
/// The limit in force (`set maxconn global`); 0 is no limit.
static MAX: AtomicU32 = AtomicU32::new(0);
/// What the configuration said (`global.hardmaxconn`): `set maxconn global` stays below it.
static HARD: AtomicU32 = AtomicU32::new(0);
/// `global.maxsock` and `global.rlimit_nofile` as [`apply_nofile_limit`] settled them
/// (`show info` `Maxsock` and `Ulimit-n`); 0 before it ran.
static MAXSOCK: AtomicU64 = AtomicU64::new(0);
static ULIMIT_N: AtomicU64 = AtomicU64::new(0);

/// Raises the soft limit on open files to `maxsock` when it is lower, as `HAProxy` does at
/// startup (`apply_nofile_limit`, src/limits.c): the hard limit is raised along with it when
/// it is lower too (which only a privileged process may do); a higher soft limit is left
/// alone. When that fails, `strict` (the default `strict-limits`) makes it an error, the
/// alert `HAProxy` exits with; otherwise the soft limit goes to the hard one and the
/// returned warning says so. Records `Maxsock` and `Ulimit-n` for `show info`.
///
/// Without it the process kept the soft limit it was started with -- 1024 under systemd --
/// while `maxconn` came from the hard one: `EMFILE` at ~500 sessions (T237).
///
/// # Errors
/// The alert, when the limit cannot be raised and `strict` is set.
pub fn apply_nofile_limit(maxsock: u64, strict: bool) -> Result<Option<String>, String> {
    use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
    MAXSOCK.store(maxsock, Ordering::Relaxed);
    ULIMIT_N.store(maxsock, Ordering::Relaxed);
    let cur = getrlimit(Resource::Nofile);
    if cur.current.is_none_or(|c| c >= maxsock) {
        return Ok(None);
    }
    let maximum = cur.maximum.map(|m| m.max(maxsock));
    if setrlimit(Resource::Nofile, Rlimit { current: Some(maxsock), maximum }).is_ok() {
        return Ok(None);
    }
    let soft = cur.current.unwrap_or(0);
    let hard = cur.maximum.map_or_else(|| "unlimited".to_string(), |m| m.to_string());
    let msg = format!(
        "Cannot raise FD limit to {maxsock}, current limit is {soft} and hard limit is {hard}. You may prefer to let \
         Ibex adjust the limit by itself; for this, please just drop any 'maxconn' from the global section. You may \
         also force a new 'maxconn' value that is a bit lower than half of the hard limit minus listeners and checks."
    );
    if strict {
        return Err(msg);
    }
    // `no strict-limits`: as much as the hard limit allows.
    let _ = setrlimit(Resource::Nofile, Rlimit { current: cur.maximum, maximum: cur.maximum });
    let now = getrlimit(Resource::Nofile).current.unwrap_or(soft);
    ULIMIT_N.store(now, Ordering::Relaxed);
    Ok(Some(format!("{msg} Running with a limit of {now}.")))
}

/// `show info` `Maxsock`: what [`apply_nofile_limit`] was given, `None` before it ran.
#[must_use]
pub fn maxsock_value() -> Option<u64> {
    Some(MAXSOCK.load(Ordering::Relaxed)).filter(|&v| v != 0)
}

/// Whether `fd` is at or past `maxsock`. `HAProxy` closes such a socket whatever the soft
/// limit on open files allows: an accepted one pauses the listener (`sock_accept_conn`), a
/// server one fails its connect as a configuration limit (`sock_create_server_socket`), so
/// the descriptors stay within what `maxconn` sized (MY-7). Never true before
/// [`apply_nofile_limit`] ran (tests driving an engine in-process).
#[must_use]
pub fn past_maxsock(fd: std::os::fd::RawFd) -> bool {
    maxsock_value().is_some_and(|m| u64::try_from(fd).is_ok_and(|fd| fd >= m))
}

/// `show info` `Ulimit-n`: the limit [`apply_nofile_limit`] settled, `None` before it ran.
#[must_use]
pub fn ulimit_n() -> Option<u64> {
    Some(ULIMIT_N.load(Ordering::Relaxed)).filter(|&v| v != 0)
}

/// The `global.maxconn` `HAProxy` computes for a configuration without one
/// (`compute_ideal_maxconn`): half of what is left of the file descriptors after its own
/// -- 12, one per listener, and 10 for a `stats socket` -- measured on 3.5-dev8-885761-29
/// (it raises the soft limit to the hard one first, and one descriptor is not counted).
///
/// Each thread past the first takes three more (its poller and wake-up pipe, as in
/// [`maxsock`]): 2031 for `nbthread 4` under a hard limit of 4096 where `nbthread 1` gets
/// 2035, measured. Without them `maxsock` overran the hard limit the soft one is raised to
/// (T237).
#[must_use]
pub fn ideal_maxconn(nofile_hard: Option<u64>, listeners: usize, stats_socket: bool, nbthread: usize) -> u32 {
    // Unlimited is what the kernel allows a process: `fs.nr_open`'s default.
    let nofile = nofile_hard.unwrap_or(1_048_576);
    let threads = 3 * (nbthread.max(1) as u64 - 1);
    let overhead = 12 + listeners as u64 + if stats_socket { 10 } else { 0 } + threads;
    u32::try_from((nofile.saturating_sub(1).saturating_sub(overhead)) / 2).unwrap_or(u32::MAX).max(1)
}

/// Called once per engine built from `config`: the limit is the configured `maxconn`, or the
/// one `HAProxy` computes from the file descriptor limit; counting starts from zero when it
/// is configured.
pub fn configure(maxconn: Option<u32>, listeners: usize, stats_socket: bool) {
    let hard_nofile = {
        let l = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        l.maximum
    };
    let v = maxconn.unwrap_or_else(|| ideal_maxconn(hard_nofile, listeners, stats_socket, crate::stats::NBTHREAD.load(Ordering::Relaxed) as usize));
    MAX.store(v, Ordering::Relaxed);
    HARD.store(v, Ordering::Relaxed);
    if maxconn.is_some() {
        CURR.store(0, Ordering::Relaxed);
    }
}

/// `global.maxsock` as `HAProxy` computes it (`compute_ideal_maxsock` and the socket
/// eaters before it): 10, one per listener, 10 for the CLI's connections when there is a
/// stats socket, one per server with `check`, two per connection of `maxconn`, and three per
/// thread (a poller and a wake-up pipe). Measured on 3.5-dev8-885761-29 (`show info`
/// `Maxsock`): 225 for `maxconn 100`, `nbthread 1`, one `bind` and a stats socket; 234 with
/// `nbthread 4`; 227 with two checked servers; 4025 for `maxconn 2000`. Pipes (splicing)
/// are not counted: Ibex does not splice.
#[must_use]
pub fn maxsock(maxconn: u32, listeners: usize, stats_socket: bool, checks: usize, nbthread: usize) -> usize {
    let maxconn = usize::try_from(maxconn).unwrap_or(usize::MAX);
    10usize
        .saturating_add(listeners)
        .saturating_add(if stats_socket { 10 } else { 0 })
        .saturating_add(checks)
        .saturating_add(maxconn.saturating_mul(2))
        .saturating_add(nbthread.saturating_mul(3))
}

/// `tune.pool_low_count` and `tune.pool_high_count`: `ratio` percent of `maxsock`, rounded up.
#[must_use]
pub fn pool_count(maxsock: usize, ratio: u8) -> usize {
    maxsock.saturating_mul(usize::from(ratio)).saturating_add(99) / 100
}

/// A client connection was admitted.
pub fn acquire() {
    CURR.fetch_add(1, Ordering::Relaxed);
}

/// Takes a slot if there is one, atomically: false when `global maxconn` is reached.
pub fn try_acquire() -> bool {
    let max = MAX.load(Ordering::Relaxed);
    CURR.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| (max == 0 || c < max).then_some(c + 1)).is_ok()
}

/// A client connection closed.
pub fn release() {
    let _ = CURR.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| Some(c.saturating_sub(1)));
}

/// The client connections open in the process (`actconn`, `%ac`).
#[must_use]
pub fn current() -> u32 {
    CURR.load(Ordering::Relaxed)
}

/// True when no further connection may be accepted.
#[must_use]
pub fn full() -> bool {
    let max = MAX.load(Ordering::Relaxed);
    max != 0 && CURR.load(Ordering::Relaxed) >= max
}

/// The limit in force, 0 for none.
#[must_use]
pub fn max() -> u32 {
    MAX.load(Ordering::Relaxed)
}

/// The configured limit, 0 for none.
#[must_use]
pub fn hard() -> u32 {
    HARD.load(Ordering::Relaxed)
}

/// `set maxconn global <v>`: above the configured limit is out of range, 0 or less means
/// that limit again (`cli_parse_set_maxconn_global`).
///
/// # Errors
/// `Value out of range.` when `v` is above the configured limit.
pub fn set(v: i64) -> Result<(), &'static str> {
    let hard = hard();
    if hard != 0 && v > i64::from(hard) {
        return Err("Value out of range.");
    }
    let v = if v <= 0 { hard } else { u32::try_from(v).unwrap_or(u32::MAX) };
    MAX.store(v, Ordering::Relaxed);
    Ok(())
}
