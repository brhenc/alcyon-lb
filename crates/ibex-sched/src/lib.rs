// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/task.c and include/haproxy/task.h.
// Copyright (C) 2000-2026 Willy Tarreau <w@1wt.eu> and HAProxy contributors.
// See LICENSE in the repository root.

//! A HAProxy-style task scheduler.
//!
//! This is not a general-purpose async runtime, and the difference is the point. It
//! implements four mechanisms that exist specifically to keep a proxy responsive under
//! adversarial load, none of which a throughput-optimised runtime provides:
//!
//! 1. **Class budgets.** Work is split into five classes with separate per-pass budgets.
//!    `Heavy` has a budget of one, so a thread never runs two TLS handshakes back to
//!    back without servicing I/O in between — a handshake flood degrades handshake
//!    throughput without touching the latency of established connections.
//! 2. **Bounded work per pass.** Both the run loop and the timer scan stop after a fixed
//!    number of items, so a million simultaneously-expiring timers cannot stall a thread.
//! 3. **Lazy timer requeue.** Pushing a timeout *later* costs zero tree operations. A
//!    slowloris client dribbling one byte per second across 100k connections generates
//!    essentially no timer churn.
//! 4. **Bounded tree depth.** The run and wait queues are ebtrees, whose depth is a
//!    function of key width rather than element count or key distribution, so no choice
//!    of input degrades them.
//!
//! See `design/003-scheduler.md` for the evidence behind each, and
//! `design/006-data-layout.md` for why a [`task::Task`] is 32 bytes.

#![forbid(unsafe_code)]

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod sched;
pub mod task;
pub mod tick;

pub use sched::{Class, Dispatch, Outcome, Scheduler, RUNQUEUE_DEPTH};
pub use task::{task_pool_stats, CallSite, Kind, NodeRef, Task, TaskArena, TaskRef, WorkKind, TASK_POOL};
pub use tick::Tick;
