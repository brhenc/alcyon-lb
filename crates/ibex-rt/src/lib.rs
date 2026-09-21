// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/fd.c, src/ev_epoll.c, src/listener.c and src/haproxy.c
// (run_poll_loop). Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors.
// See LICENSE in the repository root.

//! The runtime: one thread per core, each with its own poller, listener and scheduler.
//!
//! Connections are assigned to a thread at accept and never move, so everything
//! reachable from a connection is touched by exactly one thread and the data path needs
//! no locks. See `design/002-threading-and-affinity.md`.

#![forbid(unsafe_code)]

pub mod fdtab;
pub mod listener;
pub mod poller;

pub use fdtab::{FdTab, FdState, Interest};
pub use listener::Listener;
pub use poller::{Event, Poller};
