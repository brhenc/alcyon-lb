// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/fd-t.h and src/fd.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The file-descriptor table: what each fd belongs to, and what it is waiting for.
//!
//! `HAProxy` keeps a flat `fdtab[]` indexed directly by fd number rather than a hash map,
//! because the kernel already guarantees fds are small dense integers. Indexing an
//! array by fd is one load; hashing is not. Ibex keeps that.

use ibex_sched::TaskRef;
use std::os::fd::RawFd;

/// What an fd is currently waiting for.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Interest {
    pub readable: bool,
    pub writable: bool,
}

impl Interest {
    pub const NONE: Interest = Interest { readable: false, writable: false };
    pub const READ: Interest = Interest { readable: true, writable: false };
    pub const WRITE: Interest = Interest { readable: false, writable: true };
    pub const BOTH: Interest = Interest { readable: true, writable: true };

    #[must_use]
    pub const fn is_none(self) -> bool {
        !self.readable && !self.writable
    }
}

/// What kind of thing an fd is, and who to wake when it becomes ready.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FdState {
    /// Not in use.
    Closed,
    /// A listening socket. Readiness means a connection is waiting to be accepted.
    Listener { listener: u32 },
    /// A connection. Readiness wakes the owning task.
    Conn { task: TaskRef, conn: u32 },
}

#[derive(Copy, Clone, Debug)]
struct Entry {
    state: FdState,
    interest: Interest,
    /// Readiness observed but not yet consumed. `HAProxy` keeps this so a task that stops
    /// early — because it hit a budget — does not lose the knowledge that more data is
    /// waiting.
    ready: Interest,
}

impl Entry {
    const EMPTY: Entry = Entry {
        state: FdState::Closed,
        interest: Interest::NONE,
        ready: Interest::NONE,
    };
}

/// Per-thread fd table, indexed by fd number.
pub struct FdTab {
    entries: Vec<Entry>,
    live: usize,
}

impl FdTab {
    #[must_use]
    pub fn with_capacity(max_fd: usize) -> Self {
        FdTab {
            entries: vec![Entry::EMPTY; max_fd],
            live: 0,
        }
    }

    #[must_use]
    pub const fn live(&self) -> usize {
        self.live
    }

    fn slot(&mut self, fd: RawFd) -> &mut Entry {
        let i = usize::try_from(fd).unwrap_or(0);
        if i >= self.entries.len() {
            // Growing here is a boot-time event in practice: the table is sized from
            // the fd rlimit, so a resize means the limit was raised under us.
            self.entries.resize(i + 1, Entry::EMPTY);
        }
        &mut self.entries[i]
    }

    /// Claims an fd.
    pub fn insert(&mut self, fd: RawFd, state: FdState, interest: Interest) {
        let e = self.slot(fd);
        if e.state == FdState::Closed {
            self.live += 1;
        }
        let e = self.slot(fd);
        e.state = state;
        e.interest = interest;
        e.ready = Interest::NONE;
    }

    /// Releases an fd.
    pub fn remove(&mut self, fd: RawFd) {
        let e = self.slot(fd);
        if e.state != FdState::Closed {
            self.live -= 1;
        }
        *self.slot(fd) = Entry::EMPTY;
    }

    #[must_use]
    pub fn state(&self, fd: RawFd) -> FdState {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.entries.get(i))
            .map_or(FdState::Closed, |e| e.state)
    }

    #[must_use]
    pub fn interest(&self, fd: RawFd) -> Interest {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.entries.get(i))
            .map_or(Interest::NONE, |e| e.interest)
    }

    pub fn set_interest(&mut self, fd: RawFd, interest: Interest) {
        self.slot(fd).interest = interest;
    }

    /// Records observed readiness.
    pub fn set_ready(&mut self, fd: RawFd, readable: bool, writable: bool) {
        let e = self.slot(fd);
        e.ready.readable |= readable;
        e.ready.writable |= writable;
    }

    #[must_use]
    pub fn ready(&self, fd: RawFd) -> Interest {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.entries.get(i))
            .map_or(Interest::NONE, |e| e.ready)
    }

    /// Consumes recorded readiness, typically after a read returned `EAGAIN`.
    pub fn clear_ready(&mut self, fd: RawFd, readable: bool, writable: bool) {
        let e = self.slot(fd);
        if readable {
            e.ready.readable = false;
        }
        if writable {
            e.ready.writable = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_remove_track_liveness() {
        let mut t = FdTab::with_capacity(64);
        assert_eq!(t.live(), 0);
        t.insert(5, FdState::Listener { listener: 0 }, Interest::READ);
        assert_eq!(t.live(), 1);
        assert_eq!(t.state(5), FdState::Listener { listener: 0 });
        t.remove(5);
        assert_eq!(t.live(), 0);
        assert_eq!(t.state(5), FdState::Closed);
    }

    #[test]
    fn readiness_persists_until_consumed() {
        // A task that stops early because it hit a budget must not lose the knowledge
        // that more data is waiting, or the connection stalls until the next event.
        let mut t = FdTab::with_capacity(16);
        t.insert(3, FdState::Closed, Interest::READ);
        t.set_ready(3, true, false);
        assert!(t.ready(3).readable);
        assert!(t.ready(3).readable, "still set after being observed");
        t.clear_ready(3, true, false);
        assert!(!t.ready(3).readable, "cleared only on explicit consume");
    }

    #[test]
    fn table_grows_past_initial_capacity() {
        let mut t = FdTab::with_capacity(4);
        t.insert(1000, FdState::Conn { task: ibex_sched::TaskRef(7), conn: 2 },
                 Interest::BOTH);
        assert_eq!(t.state(1000), FdState::Conn { task: ibex_sched::TaskRef(7), conn: 2 });
        assert_eq!(t.live(), 1);
    }

    #[test]
    fn unknown_fds_read_as_closed() {
        let t = FdTab::with_capacity(8);
        assert_eq!(t.state(99_999), FdState::Closed);
        assert_eq!(t.state(-1), FdState::Closed);
    }
}
