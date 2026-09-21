// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/ticks.h.
// Copyright (C) 2000-2026 Willy Tarreau <w@1wt.eu> and HAProxy contributors.
// See LICENSE in the repository root.

//! Wrapping millisecond ticks.
//!
//! Port of `include/haproxy/ticks.h`. Time is a 32-bit millisecond counter that wraps
//! roughly every 49.7 days, and comparisons are done on the *signed difference* rather
//! than on the values, so wrapping is invisible to callers.
//!
//! Zero is reserved as [`Tick::ETERNITY`], meaning "never expires". Arithmetic that
//! would land on zero is nudged to one, exactly as `tick_add()` does in C.
//!
//! The reason this is a newtype rather than a bare `u32`: the ordering is *not* the
//! integer ordering, so `<` on the raw value is wrong in a way that is invisible until
//! the counter wraps — a bug that appears once every 49.7 days of uptime. Making the
//! type distinct removes the possibility of writing it.

/// A point in time, in milliseconds, modulo 2^32.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Tick(pub u32);

impl Tick {
    /// "Never." Reserved sentinel, matching C's `TICK_ETERNITY == 0`.
    pub const ETERNITY: Tick = Tick(0);

    /// How far back [`crate::Scheduler`] looks when scanning the timer tree: half the
    /// tick space, so the ordered tree is searched as a circle. Matches
    /// `TIMER_LOOK_BACK`.
    pub const LOOK_BACK: u32 = 1 << 31;

    #[must_use]
    #[inline]
    pub const fn is_set(self) -> bool {
        self.0 != 0
    }

    /// `true` if this tick has been reached, by signed difference. Never true for
    /// [`Tick::ETERNITY`].
    #[must_use]
    #[inline]
    pub const fn is_expired(self, now: Tick) -> bool {
        if !self.is_set() {
            return false;
        }
        #[allow(clippy::cast_possible_wrap)]
        {
            (self.0.wrapping_sub(now.0) as i32) <= 0
        }
    }

    /// `true` if `self` is strictly earlier than `other`, accounting for wrap.
    /// [`Tick::ETERNITY`] is later than everything.
    #[must_use]
    #[inline]
    pub const fn is_before(self, other: Tick) -> bool {
        if !self.is_set() {
            return false;
        }
        if !other.is_set() {
            return true;
        }
        #[allow(clippy::cast_possible_wrap)]
        {
            (self.0.wrapping_sub(other.0) as i32) < 0
        }
    }

    /// Adds a millisecond delay, skipping the reserved zero value.
    #[must_use]
    #[inline]
    pub const fn add(self, ms: u32) -> Tick {
        let t = self.0.wrapping_add(ms);
        Tick(if t == 0 { 1 } else { t })
    }

    /// The earlier of two ticks, treating [`Tick::ETERNITY`] as infinitely far away.
    #[must_use]
    #[inline]
    pub const fn earliest(self, other: Tick) -> Tick {
        if self.is_before(other) {
            self
        } else if other.is_set() {
            other
        } else {
            self
        }
    }

    /// Milliseconds remaining until this tick, or `None` for eternity / already past.
    #[must_use]
    #[inline]
    pub const fn remaining(self, now: Tick) -> Option<u32> {
        if !self.is_set() || self.is_expired(now) {
            return None;
        }
        Some(self.0.wrapping_sub(now.0))
    }
}

#[cfg(test)]
mod tests {
    use super::Tick;

    #[test]
    fn eternity_never_expires() {
        assert!(!Tick::ETERNITY.is_expired(Tick(0)));
        assert!(!Tick::ETERNITY.is_expired(Tick(u32::MAX)));
        assert!(!Tick::ETERNITY.is_set());
    }

    #[test]
    fn expiry_is_by_signed_difference() {
        assert!(Tick(100).is_expired(Tick(100)));
        assert!(Tick(100).is_expired(Tick(101)));
        assert!(!Tick(100).is_expired(Tick(99)));
    }

    #[test]
    fn comparison_survives_wrap() {
        // The case a bare u32 gets wrong: a timer just past the wrap point is *later*
        // than one just before it, even though its integer value is smaller.
        let before = Tick(u32::MAX - 10);
        let after = before.add(20); // wraps through zero
        assert!(
            before.is_before(after),
            "{before:?} should precede {after:?}"
        );
        assert!(!after.is_before(before));
        assert!(after.is_expired(after));
        assert!(!after.is_expired(before));
    }

    #[test]
    fn add_skips_the_reserved_zero() {
        let t = Tick(u32::MAX).add(1); // would land exactly on 0
        assert_eq!(t, Tick(1));
        assert!(t.is_set());
    }

    #[test]
    fn earliest_treats_eternity_as_infinite() {
        assert_eq!(Tick(50).earliest(Tick::ETERNITY), Tick(50));
        assert_eq!(Tick::ETERNITY.earliest(Tick(50)), Tick(50));
        assert_eq!(Tick(50).earliest(Tick(70)), Tick(50));
        assert_eq!(Tick::ETERNITY.earliest(Tick::ETERNITY), Tick::ETERNITY);
    }

    #[test]
    fn remaining_is_none_when_past_or_eternal() {
        assert_eq!(Tick(200).remaining(Tick(150)), Some(50));
        assert_eq!(Tick(100).remaining(Tick(150)), None);
        assert_eq!(Tick::ETERNITY.remaining(Tick(150)), None);
    }
}
