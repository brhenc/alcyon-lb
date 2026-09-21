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
    pub fn new(period_millis: u64) -> Self {
        Self {
            period_millis: period_millis.max(1000),
            current_count: 0,
            previous_count: 0,
            window_start: Instant::now(),
        }
    }

    /// Records `n` events (e.g. requests, connections, errors).
    pub fn tick(&mut self, n: u64) {
        self.advance_window();
        self.current_count = self.current_count.saturating_add(n);
    }

    /// Computes the current rate (events per period) using weighted sliding window.
    pub fn rate(&self) -> u64 {
        let elapsed_ms = self.window_start.elapsed().as_millis() as u64;
        if elapsed_ms >= self.period_millis * 2 {
            0
        } else if elapsed_ms >= self.period_millis {
            let weight = (self.period_millis * 2 - elapsed_ms) as f64 / self.period_millis as f64;
            (self.current_count as f64 * weight) as u64
        } else {
            let weight = (self.period_millis - elapsed_ms) as f64 / self.period_millis as f64;
            let prev_weighted = (self.previous_count as f64 * weight) as u64;
            self.current_count.saturating_add(prev_weighted)
        }
    }

    fn advance_window(&mut self) {
        let elapsed_ms = self.window_start.elapsed().as_millis() as u64;
        if elapsed_ms >= self.period_millis * 2 {
            self.previous_count = 0;
            self.current_count = 0;
            self.window_start = Instant::now();
        } else if elapsed_ms >= self.period_millis {
            self.previous_count = self.current_count;
            self.current_count = 0;
            self.window_start = Instant::now();
        }
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
