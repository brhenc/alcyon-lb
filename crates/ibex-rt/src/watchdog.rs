// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The thread watchdog (T361): `HAProxy`'s src/wdt.c.
//!
//! A worker owns its connections and nothing steals them, so a worker that spins (an
//! O(n^2) on attacker input, a loop bug) stalls every one of them while the process looks
//! alive. As `HAProxy` does, a worker found stuck is reported every tick
//! (`WARNING! thread N has stopped processing traffic ...`) and, once it has been stuck for
//! a second of its own CPU time and one tick more, the process is aborted
//! (`PANIC! Thread N is about to kill the process`, exit status 134) so that the master or
//! the service manager restarts it. Measured on `HAProxy` 3.5-dev8: tasks/T361-watchdog.md.
//!
//! **The data path pays one store.** A worker [`progress`]es at the top of every loop
//! pass, after every task it runs and after every CLI command: a relaxed store of its own
//! counter, no syscall, no lock, no allocation. Each descriptor event it handles clears its
//! stuck mark ([`under_control`]). Around `epoll_wait` it says it is
//! [`sleeping`]. Everything else happens on one monitor thread ([`start`]) that wakes
//! every tick (100 ms, `warn-blocked-traffic-after`):
//!
//! * a worker whose counter moved, or that sleeps in the poller, is fine;
//! * a worker whose counter did not move is accused: the monitor notes its CPU time;
//! * accused again, its CPU time since the accusation is the time it has been stuck.
//!   `HAProxy`'s challenge (`is_sched_alive`, src/task.c:935) and thresholds
//!   (src/wdt.c:166-199): from one tick it is reported; past one second it is marked
//!   stuck, and a worker still marked stuck at the next report aborts the process.
//!
//! **CPU time, not wall time**, as `HAProxy`'s per-thread CPU-clock timers: a worker that
//! the host did not schedule, or that is blocked off-CPU, is never killed for it (and a
//! deadlock is not caught: T361 decision 2). Each worker opens its own
//! `/proc/thread-self/schedstat` when it registers -- before the chroot -- and the
//! monitor reads it, only for an accused worker, with `pread`. Without it (no `/proc`)
//! the worker is watched on the monotonic clock, and a warning says so.

use std::cell::Cell;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::OnceLock;
use std::time::Duration;

/// `HAProxy`'s default `warn-blocked-traffic-after` (src/wdt.c:48).
pub const DEFAULT_WARN_AFTER: Duration = Duration::from_millis(100);

/// Stuck this long (CPU time), a worker is marked stuck; still stuck at the next tick, the
/// process is aborted (src/wdt.c:196).
const STUCK_NS: u64 = 1_000_000_000;

/// One worker's state, written by the worker and read by the monitor.
struct Slot {
    /// Moved by every [`progress`].
    beat: AtomicU64,
    /// In the poller.
    sleeping: AtomicBool,
    /// `TH_FL_STUCK`: set by the monitor past [`STUCK_NS`], cleared by the worker.
    stuck: AtomicBool,
    /// The worker's live sessions (`stream_cnt` in the warning).
    streams: AtomicU32,
    /// How the monitor reads this worker's CPU time; set when it registers.
    /// `/proc/thread-self/schedstat` of the worker, opened by it.
    clock: OnceLock<File>,
}

struct Watchdog {
    slots: Box<[Slot]>,
}

static WATCHDOG: OnceLock<Watchdog> = OnceLock::new();

/// `BlockedTrafficWarnings` in `show info` (`warn_blocked_issued`, src/debug.c:913).
static WARNINGS: AtomicU32 = AtomicU32::new(0);

thread_local! {
    /// This thread's slot: `None` on every thread that is not a registered worker (the
    /// monitor, in-process test engines), for which every call here does nothing.
    static MINE: Cell<Option<&'static Slot>> = const { Cell::new(None) };
}

/// The number of warnings printed since the start.
#[must_use]
pub fn blocked_traffic_warnings() -> u32 {
    WARNINGS.load(Relaxed)
}

/// Sets up the table for `nbthread` workers. Once per process, before the workers start.
pub fn init(nbthread: usize) {
    let slots = (0..nbthread)
        .map(|_| Slot {
            beat: AtomicU64::new(0),
            sleeping: AtomicBool::new(false),
            stuck: AtomicBool::new(false),
            streams: AtomicU32::new(0),
            clock: OnceLock::new(),
        })
        .collect();
    let _ = WATCHDOG.set(Watchdog { slots });
}

/// Opens the CPU clock of the calling thread. Without one the thread is not watched
/// (wall-clock detection is T361 slice 4); `HAProxy` says the same when its timer cannot be
/// set up (src/wdt.c:260).
fn open_clock(path: &str, id: usize) -> Option<File> {
    File::open(path).ok().filter(|f| read_sched(f).is_some()).or_else(|| {
        crate::stderr_line!(
            "[WARNING]  ({}) : Failed to setup watchdog timer for thread {}, disabling lockup detection.",
            std::process::id(),
            id + 1
        );
        None
    })
}

/// Makes the calling thread worker `id`. Called by the worker itself, before the chroot.
pub fn register(id: usize) {
    let Some(slot) = WATCHDOG.get().and_then(|w| w.slots.get(id)) else { return };
    let _ = open_clock("/proc/thread-self/schedstat", id).map(|f| slot.clock.set(f));
    MINE.with(|m| m.set(Some(slot)));
}

/// The worker made progress: it ran a task, a command, or went round its loop
/// (`sched_stuck = 0`, src/task.c:681; `TH_FL_STUCK` cleared, src/task.c:737).
#[inline]
pub fn progress() {
    MINE.with(|m| {
        if let Some(s) = m.get() {
            s.beat.store(s.beat.load(Relaxed).wrapping_add(1), Relaxed);
            s.stuck.store(false, Relaxed);
        }
    });
}

/// The worker enters (`true`) or leaves the poller (`TH_FL_SLEEPING`).
#[inline]
pub fn sleeping(yes: bool) {
    MINE.with(|m| {
        if let Some(s) = m.get() {
            s.sleeping.store(yes, Relaxed);
        }
    });
}

/// The worker's live sessions, reported in the warning.
#[inline]
pub fn set_streams(n: usize) {
    MINE.with(|m| {
        if let Some(s) = m.get() {
            s.streams.store(u32::try_from(n).unwrap_or(u32::MAX), Relaxed);
        }
    });
}

/// Not stuck, though not done either: still reported, not killed for it. Clears
/// `TH_FL_STUCK`, as each descriptor event does (src/fd.c:685) and as long work that knows
/// it is under control does (`debug dev loop <ms> warn`, src/debug.c:1303).
#[inline]
pub fn under_control() {
    MINE.with(|m| {
        if let Some(s) = m.get() {
            s.stuck.store(false, Relaxed);
        }
    });
}

/// Starts the monitor thread, ticking every `warn_after`. Once, after [`init`]. With
/// `warn_only` (`ibex.watchdog-warn-only`) a thread stuck for good is warned about, never
/// aborted on.
///
/// # Errors
/// The thread could not be spawned.
pub fn start(warn_after: Duration, warn_only: bool) -> std::io::Result<()> {
    let Some(wd) = WATCHDOG.get() else { return Ok(()) };
    std::thread::Builder::new().name("ibex-wdt".into()).spawn(move || monitor(wd, warn_after, warn_only)).map(|_| ())
}

fn monitor(wd: &'static Watchdog, tick: Duration, warn_only: bool) -> ! {
    let tick_ns = u64::try_from(tick.as_nanos()).unwrap_or(u64::MAX);
    // HAProxy's timer runs on the thread's CPU clock: it fires after exactly one tick of
    // CPU. This one sleeps a tick of wall time, in which the thread gets at most a tick of
    // CPU, a little less as a rule; without slack the second look would fall just short
    // and every report come one tick late (measured: first warning at 298 ms, panic at
    // ~1.3 s, against HAProxy's 201 ms and ~1.2 s).
    let slack = tick_ns / 2;
    let n = wd.slots.len();
    let mut seen = vec![0u64; n];
    let mut accused: Vec<Option<u64>> = vec![None; n];
    loop {
        std::thread::sleep(tick);
        for (i, s) in wd.slots.iter().enumerate() {
            let beat = s.beat.load(Relaxed);
            if beat != seen[i] || s.sleeping.load(Relaxed) {
                seen[i] = beat;
                accused[i] = None;
                continue;
            }
            // A thread without a clock reads as no CPU used, so it is never accused.
            let now = s.clock.get().and_then(read_sched).unwrap_or(0);
            let Some(since) = accused[i] else {
                accused[i] = Some(now);
                continue;
            };
            let stuck_for = now.saturating_sub(since);
            if stuck_for.saturating_add(slack) < tick_ns {
                continue;
            }
            if s.stuck.load(Relaxed) && !warn_only {
                panic_now(i);
            }
            if stuck_for.saturating_add(slack) >= STUCK_NS {
                s.stuck.store(true, Relaxed);
            }
            warn(i, stuck_for.saturating_add(tick_ns), s.streams.load(Relaxed));
        }
    }
}

/// The first field of a `schedstat`: nanoseconds on a CPU.
fn read_sched(f: &File) -> Option<u64> {
    let mut buf = [0u8; 64];
    let len = f.read_at(&mut buf, 0).ok()?;
    let digits = buf[..len].iter().take_while(|b| b.is_ascii_digit()).count();
    std::str::from_utf8(&buf[..digits]).ok()?.parse().ok()
}

/// `ha_stuck_warning` (src/debug.c:898), without the thread dump.
fn warn(worker: usize, stuck_ns: u64, streams: u32) {
    WARNINGS.fetch_add(1, Relaxed);
    crate::stderr_line!(
        "\nWARNING! thread {} has stopped processing traffic for {} milliseconds\n    \
         with {} streams currently blocked, prevented from making any progress.\n    \
         While this may occasionally happen with inefficient configurations\n    \
         involving excess of regular expressions, map_reg, or heavy Lua processing,\n    \
         this must remain exceptional because the system's stability is now at risk.\n    \
         Timers in logs may be reported incorrectly, spurious timeouts may happen,\n    \
         some incoming connections may silently be dropped, health checks may\n    \
         randomly fail, and accesses to the CLI may block the whole process. The\n    \
         blocking delay before emitting this warning may be adjusted via the global\n    \
         'warn-blocked-traffic-after' directive.\n => Trying to gracefully recover now (pid {}).",
        worker + 1,
        stuck_ns / 1_000_000,
        streams,
        std::process::id()
    );
}

/// `ha_panic` (src/debug.c:801), without the thread dumps: the core file has them.
fn panic_now(worker: usize) -> ! {
    crate::stderr_line!(
        "\nPANIC! Thread {} is about to kill the process (pid {}).\n\nIbex info:\n  version: {}\n\n\
         Hint: when reporting this bug to developers, please check if a core file was\n      \
         produced, open it with 'gdb', issue 't a a bt full', check that the\n      \
         output does not contain sensitive data, then join it with the bug report.",
        worker + 1,
        std::process::id(),
        env!("CARGO_PKG_VERSION")
    );
    crate::crash::die()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn a_missing_clock_is_no_clock() {
        assert!(open_clock("/proc/thread-self/no-such-file", 0).is_none());
        assert!(open_clock("/proc/thread-self/schedstat", 0).is_some());
    }

    #[test]
    fn schedstat_first_field_is_read() {
        let f = File::open("/proc/thread-self/schedstat").expect("schedstat");
        let before = read_sched(&f).expect("a number");
        // The kernel folds the running time in at its scheduler tick: spin past a few.
        let end = Instant::now() + Duration::from_millis(30);
        while Instant::now() < end {}
        let after = read_sched(&f).expect("a number");
        assert!(after > before, "{before} -> {after}");
    }
}
