// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Debug-build counters of what a request does to shared state and to the clock, so that
//! `tests/it/engine_pass.rs` can pin them (T579). Per thread, so parallel tests do not see
//! each other. Nothing in a release build: every function is empty and inlined away.

#[cfg(debug_assertions)]
mod on {
    use std::cell::Cell;
    thread_local! {
        static RMWS: Cell<u64> = const { Cell::new(0) };
        static WALL_READS: Cell<u64> = const { Cell::new(0) };
        static SRV_ROWS: Cell<u64> = const { Cell::new(0) };
        static CLOCK_READS: Cell<u64> = const { Cell::new(0) };
    }
    pub fn rmw() {
        RMWS.with(|c| c.set(c.get() + 1));
    }
    pub fn wall_read() {
        WALL_READS.with(|c| c.set(c.get() + 1));
    }
    pub fn clock_read() {
        CLOCK_READS.with(|c| c.set(c.get() + 1));
    }
    pub fn srv_rows(n: usize) {
        SRV_ROWS.with(|c| c.set(c.get() + n as u64));
    }
    #[must_use]
    pub fn srv_rows_read() -> u64 {
        SRV_ROWS.with(Cell::get)
    }
    #[must_use]
    pub fn rmws() -> u64 {
        RMWS.with(Cell::get)
    }
    #[must_use]
    pub fn wall_reads() -> u64 {
        WALL_READS.with(Cell::get)
    }
    #[must_use]
    pub fn clock_reads() -> u64 {
        CLOCK_READS.with(Cell::get)
    }
}
#[cfg(debug_assertions)]
pub use on::*;

#[cfg(not(debug_assertions))]
mod off {
    #[inline(always)]
    pub fn rmw() {}
    #[inline(always)]
    pub fn wall_read() {}
    #[inline(always)]
    pub fn clock_read() {}
    #[inline(always)]
    pub fn srv_rows(_n: usize) {}
}
#[cfg(not(debug_assertions))]
pub use off::*;
