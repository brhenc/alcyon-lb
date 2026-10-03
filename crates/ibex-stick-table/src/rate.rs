// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Sliding window frequency & rate calculation for stick tables.

use std::time::Instant;

/// Sliding window frequency rate tracker
#[derive(Debug, Clone)]
pub struct SlidingRate {
    period_millis: u64,
    current_count: u64,
    previous_count: u64,
    window_start: Instant,
}

impl SlidingRate {
    /// Creates a sliding rate calculator for the given period in milliseconds.
    #[must_use]
    pub fn new(period_millis: u64) -> Self {
        Self {
            period_millis: period_millis.max(1),
            current_count: 0,
            previous_count: 0,
            window_start: Instant::now(),
        }
    }

    /// Creates a sliding rate calculator with explicit initial counts (for testing and simulation).
    #[must_use]
    pub fn with_counts(period_millis: u64, current_count: u64, previous_count: u64) -> Self {
        Self {
            period_millis: period_millis.max(1),
            current_count,
            previous_count,
            window_start: Instant::now(),
        }
    }

    /// Records `n` events (e.g. requests, connections, errors).
    pub fn tick(&mut self, n: u64) {
        self.advance_window();
        self.current_count = self.current_count.saturating_add(n);
    }

    /// Records `n` events at an explicit elapsed time offset from window start (useful for deterministic tests).
    pub fn tick_at_elapsed(&mut self, n: u64, elapsed_ms: u64) {
        self.advance_by_millis(elapsed_ms);
        self.current_count = self.current_count.saturating_add(n);
    }

    /// Computes the current rate (events per period) using weighted sliding window.
    #[must_use]
    pub fn rate(&self) -> u64 {
        let elapsed_ms = u64::try_from(self.window_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.rate_at_elapsed(elapsed_ms)
    }

    /// Computes the sliding window rate at a specific elapsed duration (in milliseconds).
    ///
    /// Uses 128-bit intermediate arithmetic to guarantee zero overflow even under extreme
    /// counter magnitudes and wrap-around test conditions.
    #[must_use]
    pub fn rate_at_elapsed(&self, elapsed_ms: u64) -> u64 {
        if self.period_millis == 0 {
            return 0;
        }
        let two_periods = self.period_millis.saturating_mul(2);
        if elapsed_ms >= two_periods {
            0
        } else if elapsed_ms >= self.period_millis {
            let remaining = two_periods.saturating_sub(elapsed_ms);
            let num = u128::from(self.current_count) * u128::from(remaining);
            u64::try_from(num / u128::from(self.period_millis)).unwrap_or(u64::MAX)
        } else {
            let remaining = self.period_millis.saturating_sub(elapsed_ms);
            let num = u128::from(self.previous_count) * u128::from(remaining);
            let prev_weighted =
                u64::try_from(num / u128::from(self.period_millis)).unwrap_or(u64::MAX);
            self.current_count.saturating_add(prev_weighted)
        }
    }

    /// Advances the window given elapsed milliseconds since `window_start`.
    pub fn advance_by_millis(&mut self, elapsed_ms: u64) {
        let two_periods = self.period_millis.saturating_mul(2);
        if elapsed_ms >= two_periods {
            self.previous_count = 0;
            self.current_count = 0;
            self.window_start = Instant::now();
        } else if elapsed_ms >= self.period_millis {
            self.previous_count = self.current_count;
            self.current_count = 0;
            self.window_start = Instant::now();
        }
    }

    fn advance_window(&mut self) {
        let elapsed_ms = u64::try_from(self.window_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.advance_by_millis(elapsed_ms);
    }

    /// Returns the period in milliseconds.
    #[must_use]
    pub const fn period_millis(&self) -> u64 {
        self.period_millis
    }

    /// Returns the current count.
    #[must_use]
    pub const fn current_count(&self) -> u64 {
        self.current_count
    }

    /// Returns the previous count.
    #[must_use]
    pub const fn previous_count(&self) -> u64 {
        self.previous_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sliding_rate() {
        let mut rate = SlidingRate::new(1000);
        rate.tick(10);
        assert!(rate.rate() >= 10);
    }
}
