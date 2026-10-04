// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The per-transaction counters `show stat` reports for a frontend, a backend and each
//! server: the response classes, request and byte totals, error counts and the averaged
//! timings (T165).
//!
//! They are made on first use ([`Proxy::tc`]): a configuration of sixty thousand backends
//! that never saw a request pays one empty cell each. One set is shared by every worker;
//! each counter is a relaxed atomic that a stream touches once, when it ends.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

/// Samples a running average spans (`TIME_STATS_SAMPLES`).
const SAMPLES: u64 = 512;

/// A running sum of durations in milliseconds as `HAProxy` keeps one (`swrate_add_dynamic`),
/// and the greatest value seen. The average divides by the requests counted so far, up to
/// [`SAMPLES`] (`stats_fill_sv_stats`).
#[derive(Default, Debug)]
pub struct TimeStat {
    sum: AtomicU64,
    max: AtomicU32,
}

impl TimeStat {
    /// Adds a sample, `counted` being the requests (or connections) the object has served.
    pub fn add(&self, ms: u64, counted: u64) {
        let window = if counted > SAMPLES { SAMPLES } else { 0 };
        let s = self.sum.load(Ordering::Relaxed);
        let decay = if window > 0 { (s + window - 1) / window } else { 0 };
        self.sum.store(s - decay + ms, Ordering::Relaxed);
        self.max.fetch_max(u32::try_from(ms).unwrap_or(u32::MAX), Ordering::Relaxed);
    }

    /// The average, rounded up as `swrate_avg` does.
    #[must_use]
    pub fn avg(&self, counted: u64) -> u64 {
        let n = if counted > 0 && counted < SAMPLES { counted } else { SAMPLES };
        self.sum.load(Ordering::Relaxed).div_ceil(n)
    }

    #[must_use]
    pub fn max(&self) -> u32 {
        self.max.load(Ordering::Relaxed)
    }
}

/// The counters of one frontend, one backend or one server.
#[derive(Default, Debug)]
// One cache line boundary per set, so a frontend's counters and a backend's do not share lines.
#[repr(align(64))]
pub struct TxnCounters {
    /// Responses by class: 1xx to 5xx, then anything else (`hrsp_*`).
    pub hrsp: [AtomicU64; 6],
    /// Requests (`req_tot`).
    pub req_tot: AtomicU64,
    /// Streams, or for a server the connections tried, retries included (`stot`).
    pub stot: AtomicU64,
    /// Times the load balancer chose it (`lbtot`).
    pub lbtot: AtomicU64,
    /// Request bytes as parsed, response bytes as the server sent them (`bin`, `bout`).
    pub bin: AtomicU64,
    pub bout: AtomicU64,
    pub cli_abrt: AtomicU64,
    pub srv_abrt: AtomicU64,
    /// Connection failures (`econ`) and response failures (`eresp`).
    pub econ: AtomicU64,
    pub eresp: AtomicU64,
    /// Requests the frontend could not parse (`ereq`).
    pub ereq: AtomicU64,
    /// When a stream last ended on it, in [`now_ms`] (0: never).
    pub last_sess: AtomicU64,
    pub qtime: TimeStat,
    pub ctime: TimeStat,
    pub rtime: TimeStat,
    pub ttime: TimeStat,
    /// The greatest sessions per second seen (`rate_max`), requests (`req_rate_max`).
    pub rate_max: AtomicU32,
    pub req_rate_max: AtomicU32,
    /// Streams ending per second on it (`rate`), for a backend or a server.
    pub sess_rate: crate::engine::RateCtr,
    /// The most streams it served at once, as seen when one ended (`smax`).
    pub smax: AtomicU32,
    /// Times a check took it down (`chkdown`), for a server.
    pub chkdown: AtomicU64,
    /// A server's last state change in [`now_ms`] (0: none since the start), when it went
    /// down (0: it is not) and the time it has been down before that, in milliseconds.
    pub last_chg: AtomicU64,
    pub down_since: AtomicU64,
    pub downtime_ms: AtomicU64,
}

impl TxnCounters {
    /// Counts a response status in its class.
    pub fn count_status(&self, status: i64) {
        let class = match status {
            100..=199 => 0,
            200..=299 => 1,
            300..=399 => 2,
            400..=499 => 3,
            500..=599 => 4,
            _ => 5,
        };
        self.hrsp[class].fetch_add(1, Ordering::Relaxed);
    }

    /// Notes a stream that ended now.
    pub fn touch(&self) {
        self.last_sess.store(now_ms(), Ordering::Relaxed);
    }

    /// Seconds since `stamp` (a [`now_ms`] value), or `None` when it was never set.
    #[must_use]
    pub fn since_secs(stamp: u64) -> Option<u64> {
        (stamp != 0).then(|| now_ms().saturating_sub(stamp) / 1000)
    }

    /// A state change of a server: from `was_down` to `down` (`lastchg`, `downtime`).
    pub fn state_changed(&self, was_down: bool, down: bool) {
        let now = now_ms();
        self.last_chg.store(now, Ordering::Relaxed);
        if down && !was_down {
            self.chkdown.fetch_add(1, Ordering::Relaxed);
            self.down_since.store(now, Ordering::Relaxed);
        } else if was_down && !down {
            let since = self.down_since.swap(0, Ordering::Relaxed);
            if since != 0 {
                self.downtime_ms.fetch_add(now.saturating_sub(since), Ordering::Relaxed);
            }
        }
    }

    /// The seconds spent down, the present spell included (`downtime`).
    #[must_use]
    pub fn downtime_secs(&self) -> u64 {
        let since = self.down_since.load(Ordering::Relaxed);
        let open = if since == 0 { 0 } else { now_ms().saturating_sub(since) };
        (self.downtime_ms.load(Ordering::Relaxed) + open) / 1000
    }

    /// Zeroes everything (`clear counters`).
    pub fn clear(&self) {
        for h in &self.hrsp {
            h.store(0, Ordering::Relaxed);
        }
        for c in [&self.req_tot, &self.stot, &self.lbtot, &self.bin, &self.bout, &self.cli_abrt, &self.srv_abrt, &self.econ, &self.eresp, &self.ereq] {
            c.store(0, Ordering::Relaxed);
        }
        for t in [&self.qtime, &self.ctime, &self.rtime, &self.ttime] {
            t.sum.store(0, Ordering::Relaxed);
            t.max.store(0, Ordering::Relaxed);
        }
        self.rate_max.store(0, Ordering::Relaxed);
        self.smax.store(0, Ordering::Relaxed);
        self.req_rate_max.store(0, Ordering::Relaxed);
    }
}

/// Milliseconds since the first call, never 0.
#[must_use]
pub fn now_ms() -> u64 {
    static EPOCH: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
    EPOCH.elapsed().as_millis() as u64 + 1
}

/// A proxy's counters: as a frontend, as a backend, and one set per server.
#[derive(Debug)]
pub struct ProxyCounters {
    pub fe: TxnCounters,
    pub be: TxnCounters,
    pub srv: Box<[TxnCounters]>,
}

impl ProxyCounters {
    #[must_use]
    pub fn new(servers: usize) -> Self {
        ProxyCounters { fe: TxnCounters::default(), be: TxnCounters::default(), srv: (0..servers).map(|_| TxnCounters::default()).collect() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn average_rounds_up_like_swrate() {
        let t = TimeStat::default();
        t.add(200, 1);
        for _ in 0..6 {
            t.add(0, 1);
        }
        // 200 over seven requests is 28.6: `HAProxy` printed 29 (3.5-dev8-885761-29), and
        // 25 over the eight a backend counted.
        assert_eq!(t.avg(7), 29);
        assert_eq!(t.avg(8), 25);
        assert_eq!(t.max(), 200);
    }

    #[test]
    fn statuses_fall_in_their_class() {
        let c = TxnCounters::default();
        for s in [101, 200, 204, 301, 404, 503, 600, -1] {
            c.count_status(s);
        }
        let got: Vec<u64> = c.hrsp.iter().map(|h| h.load(Ordering::Relaxed)).collect();
        assert_eq!(got, [1, 2, 1, 1, 1, 2]);
    }
}
