// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `global maxconn` (T146 item 3): the number of client connections the process holds at
//! once, across every frontend and worker (`actconn`/`global.maxconn` in `HAProxy`).
//!
//! Past it the listeners stop accepting, and the connections wait in the kernel backlog
//! until one closes (`limit_listener(.., &global_listener_queue)`), as with a frontend's
//! own `maxconn`. The stats socket is not counted. State is process-wide, set when an
//! engine is built from a configuration that has a `maxconn`.

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

static CURR: AtomicU32 = AtomicU32::new(0);
/// The limit in force (`set maxconn global`); 0 is no limit.
static MAX: AtomicU32 = AtomicU32::new(0);
/// What the configuration said (`global.hardmaxconn`): `set maxconn global` stays below it.
static HARD: AtomicU32 = AtomicU32::new(0);
/// `global.maxsock` and `global.rlimit_nofile` as [`apply_nofile_limit`] settled them
/// (`show info` `Maxsock` and `Ulimit-n`); 0 before it ran.
static MAXSOCK: AtomicU64 = AtomicU64::new(0);
static ULIMIT_N: AtomicU64 = AtomicU64::new(0);
/// Number of listening sockets (T320): one per `bind` address plus one per `stats socket`.
static LISTENERS: AtomicUsize = AtomicUsize::new(0);
/// Accepts made while `actconn + 1 >= global maxconn` (T320), the last two slots: client
/// connections refused afterwards and stats-socket accepts included, as in listener.c.
static REACHED: AtomicU64 = AtomicU64::new(0);

/// `-m <megs>`: `RLIMIT_DATA`, soft and hard, to `megs` MiB, as `HAProxy` sets it (T465). Past
/// it an allocation fails: Ibex's buffers, sessions, timers and idle lists fail one stream or
/// connection then (tradeoff.md 6.23), other allocations abort the process.
///
/// # Errors
/// `HAProxy`'s alert, which it exits 1 with, when the limit cannot be set (a hard limit below
/// it, without the privilege to raise it).
pub fn apply_memmax_rlimit(megs: u64) -> Result<(), String> {
    use rustix::process::{setrlimit, Resource, Rlimit};
    let bytes = megs.saturating_mul(1_048_576);
    setrlimit(Resource::Data, Rlimit { current: Some(bytes), maximum: Some(bytes) }).map_err(|_| format!("[haproxy.main()] Cannot fix MEM limit to {megs} megs."))
}

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

/// The descriptor number no client or server socket may reach; 0 (no ceiling) until
/// [`settle_fd_ceiling`] ran.
static FD_CEILING: AtomicU64 = AtomicU64::new(0);

/// Whether `fd` is past the descriptors `maxsock` sized. `HAProxy` closes any socket whose
/// descriptor is `>= global.maxsock`, whatever the soft limit on open files allows: an
/// accepted one pauses the listener (`sock_accept_conn`), a server one fails its connect as
/// a configuration limit (`sock_create_server_socket`), so the descriptors stay within what
/// `maxconn` sized (MY-7). Never true before [`settle_fd_ceiling`] ran (tests driving an
/// engine in-process).
#[must_use]
pub fn past_maxsock(fd: std::os::fd::RawFd) -> bool {
    let ceiling = FD_CEILING.load(Ordering::Relaxed);
    ceiling != 0 && u64::try_from(fd).is_ok_and(|fd| fd >= ceiling)
}

/// The descriptors open when the process started: whatever launched it left them.
static INHERITED_FDS: std::sync::OnceLock<Vec<u64>> = std::sync::OnceLock::new();

fn open_fds() -> Vec<u64> {
    std::fs::read_dir("/proc/self/fd")
        .map(|d| d.flatten().filter_map(|e| e.file_name().to_str()?.parse::<u64>().ok()).collect())
        .unwrap_or_default()
}

/// Records the descriptors inherited from the launcher; call first thing in `main`.
/// `settle_fd_ceiling` leaves them out: `HAProxy` ignores them too (its `maxsock` comes from
/// the configuration; a descriptor inherited at 2000 stays open and changes neither `Maxsock`
/// nor the sockets it accepts, T438).
pub fn record_inherited_fds() {
    let _ = INHERITED_FDS.set(open_fds());
}

/// Sets the ceiling [`past_maxsock`] enforces, once every worker is up and before any is
/// released to accept: `maxsock` (`global.maxsock`, which `HAProxy` compares an accepted
/// descriptor with, src/sock.c:110), or, when Ibex's own descriptors already take more of it
/// than `HAProxy`'s estimate allows for (its workers hold four each where `HAProxy` counts
/// three: 260 open at start against a `maxsock` of 216 with `maxconn 1` and 64 threads), the
/// highest one of its own open plus two per `maxconn` and `HAProxy`'s reserve of ten.
/// Otherwise every connection would be refused. Descriptors inherited at start are not
/// Ibex's own and do not count.
pub fn settle_fd_ceiling() {
    let inherited = INHERITED_FDS.get().map_or(&[][..], Vec::as_slice);
    let highest = open_fds().into_iter().filter(|fd| !inherited.contains(fd) || *fd <= 2).max().unwrap_or(0);
    let own = highest + 1 + 2 * u64::from(hard()) + 10;
    FD_CEILING.store(MAXSOCK.load(Ordering::Relaxed).max(own), Ordering::Relaxed);
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

static MEMMAX_MB: AtomicU32 = AtomicU32::new(0);

/// `show info` `Memmax_MB`: the `-m` value (`global.rlimit_memmax`), 0 without `-m`.
#[must_use]
pub fn memmax_mb() -> u32 {
    MEMMAX_MB.load(Ordering::Relaxed)
}

/// Records the `-m <megs>` budget for `show info` and `/metrics`.
pub fn set_memmax_mb(megs: u32) {
    MEMMAX_MB.store(megs, Ordering::Relaxed);
}

/// `STREAM_MAX_COST` of include/haproxy/defaults.h:538, `sizeof(struct stream) + 2 *
/// sizeof(struct channel) + 2 * sizeof(struct connection) + requri_len + 2 * cookie_len`.
/// Ibex has no such structs; the value is the one that reproduces the `maxconn` and the
/// "absolute maximum possible value without SSL" HAProxy 3.5-dev8-885761-29 prints for
/// `-m` 5, 10, 64, 100 and 1000 (35719 or 35720 per connection at the default bufsize;
/// 2952 is the upper of the two).
const STREAM_MAX_COST: u64 = 2952;
/// `SSL_SESSION_MAX_COST` and `SSL_HANDSHAKE_MAX_COST` (defaults.h:525, 530).
const SSL_SESSION_MAX_COST: u64 = 16 * 1024;
const SSL_HANDSHAKE_MAX_COST: u64 = 76 * 1024;
/// `MEM_USABLE_RATIO` (defaults.h:548).
const MEM_USABLE_RATIO: f64 = 0.97;

/// `round_2dig` (src/tools.c:670): the first two digits, then zeros.
fn round_2dig(mut i: u64) -> u64 {
    let mut mul = 1;
    while i >= 100 {
        i /= 10;
        mul *= 10;
    }
    i * mul
}

/// What `-m` does to `global.maxconn` (`compute_ideal_maxconn`, src/limits.c:285-365):
/// `-m` is a budget, not an rlimit. `maxconn` is the configured one. `sides` counts the
/// sides that use TLS (a `bind ... ssl`: 1, `server ... ssl`: 1, both: 2).
///
/// Returns the `maxconn` to run with: the computed one when none was configured, the
/// configured one otherwise. `ssl_cache` is `tune.ssl.cachesize` (200 bytes an entry,
/// only counted when TLS is used), `bufsize` is `tune.bufsize`.
///
/// # Errors
/// The alert `HAProxy` exits 1 with when the configured `maxconn` leaves no room for the
/// TLS connections (it has no equivalent for a cleartext-only configuration).
#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss, clippy::cast_sign_loss, clippy::cast_possible_wrap)]
pub fn memmax_maxconn(megs: u32, maxconn: Option<u32>, sides: u64, bufsize: u64, ssl_cache: u64) -> Result<u32, String> {
    let per_conn = STREAM_MAX_COST + 2 * bufsize;
    let ssl_cost = SSL_SESSION_MAX_COST + SSL_HANDSHAKE_MAX_COST;
    let mut mem = (u64::from(megs) * 1_048_576) as i64;
    if sides > 0 {
        mem -= (ssl_cache * 200) as i64;
    }
    let mem = (mem as f64 * MEM_USABLE_RATIO) as i64;
    let avail = mem.max(0) as u64;
    let cap = |v: u64| u32::try_from(round_2dig(v)).unwrap_or(u32::MAX);
    match (maxconn, sides) {
        (None, 0) => {
            let n = cap(avail / per_conn);
            if n == 0 {
                return Err(format!("Cannot compute the automatic maxconn because global.maxsslconn is already too high for the global.memmax value ({megs} MB). The absolute maximum possible value is {}, but 0 was found.", avail / ssl_cost));
            }
            Ok(n)
        }
        (None, sides) => Ok(cap(avail / (per_conn + sides * SSL_SESSION_MAX_COST + SSL_HANDSHAKE_MAX_COST))),
        (Some(mc), 0) => Ok(mc),
        (Some(mc), sides) => {
            let sslmem = mem - i64::from(mc) * per_conn as i64;
            let maxsslconn = if sslmem > 0 { round_2dig(sslmem as u64 / ssl_cost) } else { 0 };
            if sslmem <= 0 || maxsslconn < sides {
                return Err(format!(
                    "Cannot compute the automatic maxsslconn because global.maxconn is already too high for the global.memmax value ({megs} MB). The absolute maximum possible value without SSL is {}, but {mc} was found and SSL is in use.",
                    avail / per_conn
                ));
            }
            Ok(mc)
        }
    }
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
    LISTENERS.store(listeners, Ordering::Relaxed);
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

/// An accepted connection, limited or not (T320): `HAProxy` counts `MaxconnReached` when
/// `actconn + 1 >= maxconn` after the accept (listener.c), outside its `BC_O_UNLIMITED` guard,
/// so the stats socket counts too. Called right after `accept()`, before any rule can refuse
/// the connection; a client connection's own slot is already in `CURR` there.
pub fn note_accept() {
    let max = MAX.load(Ordering::Relaxed);
    if max != 0 && CURR.load(Ordering::Relaxed).saturating_add(1) >= max {
        REACHED.fetch_add(1, Ordering::Relaxed);
    }
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

/// The number of listening sockets (`show info` `Listeners`).
#[must_use]
pub fn listeners() -> usize {
    LISTENERS.load(Ordering::Relaxed)
}

/// Accepts made while `actconn + 1 >= global maxconn` ([`note_accept`]; `show info`
/// `MaxconnReached`). Never reset by `clear counters`.
#[must_use]
pub fn reached() -> u64 {
    REACHED.load(Ordering::Relaxed)
}
