// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Property-based tests for `SlidingRate` sliding window calculations and wrap-around conditions.

use ibex_stick_table::SlidingRate;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Invariant: For any configuration and counts, rate is always bounded between 0 and
    /// `current_count.saturating_add(previous_count)`.
    #[test]
    fn prop_sliding_rate_bounds(
        period in 1u64..100_000,
        curr in any::<u64>(),
        prev in any::<u64>(),
        elapsed in 0u64..300_000
    ) {
        let rate_calc = SlidingRate::with_counts(period, curr, prev);
        let calculated_rate = rate_calc.rate_at_elapsed(elapsed);
        let max_possible = curr.saturating_add(prev);
        prop_assert!(
            calculated_rate <= max_possible,
            "Rate {} exceeded max possible {}",
            calculated_rate,
            max_possible
        );
    }

    /// Invariant: At elapsed == 0, rate is exactly current_count + previous_count (modulo saturation).
    #[test]
    fn prop_sliding_rate_zero_elapsed(
        period in 1u64..100_000,
        curr in any::<u64>(),
        prev in any::<u64>()
    ) {
        let rate_calc = SlidingRate::with_counts(period, curr, prev);
        let calculated = rate_calc.rate_at_elapsed(0);
        let expected = curr.saturating_add(prev);
        prop_assert_eq!(calculated, expected);
    }

    /// Invariant: For any elapsed >= 2 * period, rate is identically 0.
    #[test]
    fn prop_sliding_rate_zero_after_two_periods(
        period in 1u64..100_000,
        curr in any::<u64>(),
        prev in any::<u64>(),
        extra_elapsed in 0u64..100_000
    ) {
        let rate_calc = SlidingRate::with_counts(period, curr, prev);
        let elapsed = (period * 2).saturating_add(extra_elapsed);
        let calculated = rate_calc.rate_at_elapsed(elapsed);
        prop_assert_eq!(calculated, 0);
    }

    /// Invariant: Monotonic decay when current_count == 0.
    /// As elapsed increases within the window (0 <= t1 <= t2 <= period), rate(t1) >= rate(t2).
    #[test]
    fn prop_sliding_rate_decay_monotonicity(
        period in 10u64..100_000,
        prev in any::<u64>(),
        t1 in 0u64..50_000,
        t2 in 0u64..50_000
    ) {
        let t_a = t1 % period;
        let t_b = t2 % period;
        let t_lo = t_a.min(t_b);
        let t_hi = t_a.max(t_b);

        let rate_calc = SlidingRate::with_counts(period, 0, prev);
        let r_lo = rate_calc.rate_at_elapsed(t_lo);
        let r_hi = rate_calc.rate_at_elapsed(t_hi);

        prop_assert!(
            r_lo >= r_hi,
            "Rate did not monotonically decay: r({}) = {}, r({}) = {}",
            t_lo, r_lo, t_hi, r_hi
        );
    }

    /// Invariant: Window transition continuity.
    /// At elapsed == period, the previous window has fully decayed and rate == current_count.
    #[test]
    fn prop_sliding_rate_window_boundary(
        period in 1u64..100_000,
        curr in any::<u64>(),
        prev in any::<u64>()
    ) {
        let rate_calc = SlidingRate::with_counts(period, curr, prev);
        let calculated = rate_calc.rate_at_elapsed(period);
        prop_assert_eq!(calculated, curr);
    }

    /// Invariant: Extreme counter values (u64::MAX) and wrap-around arithmetic safety.
    /// Under extreme counter values, intermediate multiplication must never overflow or panic.
    #[test]
    fn prop_sliding_rate_wraparound_extremes(
        period in prop_oneof![Just(1u64), Just(1000u64), Just(u64::MAX / 4), Just(u64::MAX / 2), Just(u64::MAX)],
        curr in prop_oneof![Just(0u64), Just(1u64), Just(u64::MAX / 2), Just(u64::MAX - 1), Just(u64::MAX)],
        prev in prop_oneof![Just(0u64), Just(1u64), Just(u64::MAX / 2), Just(u64::MAX - 1), Just(u64::MAX)],
        elapsed_mode in 0u8..=6
    ) {
        let elapsed = match elapsed_mode {
            0 => 0,
            1 => 1,
            2 => period / 2,
            3 => period,
            4 => period.saturating_add(1),
            5 => period.saturating_mul(2),
            _ => u64::MAX,
        };
        let mut rate_calc = SlidingRate::with_counts(period, curr, prev);
        let rate = rate_calc.rate_at_elapsed(elapsed);
        prop_assert!(rate <= curr.saturating_add(prev));

        // Advance and tick under extreme values
        rate_calc.tick_at_elapsed(u64::MAX, elapsed);
        let rate_after = rate_calc.rate_at_elapsed(0);
        prop_assert!(rate_after >= curr);
    }

    /// Simulation test: Sequence of random ticks and elapsed intervals preserves all invariants.
    #[test]
    fn prop_sliding_rate_simulation(
        period in 1000u64..10_000,
        steps in prop::collection::vec((0u64..1000, 0u64..5000), 1..50)
    ) {
        let mut rate_calc = SlidingRate::new(period);
        for (events, elapsed_step) in steps {
            rate_calc.tick_at_elapsed(events, elapsed_step);
            let r = rate_calc.rate_at_elapsed(0);
            prop_assert!(r <= rate_calc.current_count().saturating_add(rate_calc.previous_count()));
        }
    }
}
