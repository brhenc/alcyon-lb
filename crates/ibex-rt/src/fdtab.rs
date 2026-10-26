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
    pub const NONE: Interest = Interest {
        readable: false,
        writable: false,
    };
    pub const READ: Interest = Interest {
        readable: true,
        writable: false,
    };
    pub const WRITE: Interest = Interest {
        readable: false,
        writable: true,
    };
    pub const BOTH: Interest = Interest {
        readable: true,
        writable: true,
    };

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
    /// A listening socket for CLI / stats. Readiness means a CLI client is waiting.
    CliListener,
    /// A further CLI socket (`stats socket` lines after the first), by index.
    CliExtra(u32),
    /// A connection. Readiness wakes the owning task.
    Conn { task: TaskRef, conn: u32 },
    /// A QUIC listening socket. Readiness means datagrams are waiting.
    ///
    /// A QUIC connection is not a file descriptor -- thousands share this one socket and are
    /// told apart by connection ID -- so unlike `Listener` there is nothing to accept. The
    /// engine drives the listener, which demultiplexes internally.
    QuicListener { listener: u32 },
    /// A backend socket opened by a QUIC request. Readiness advances that listener's legs.
    QuicBackend { listener: u32 },
    /// This worker's mailbox (`crate::mailbox`): another worker asked something.
    Mailbox,
    /// A nameserver's socket of a `resolvers` section (`crate::resolvers`), by section:
    /// readiness wakes the section's task.
    Resolver { section: u32 },
    /// An idle server connection in this worker's lists (`crate::engine::IdlePool`),
    /// still registered for reads: an event on it is its server closing it, or sending
    /// what nobody asked for (T434). Not counted in [`used`]: the lists count their own.
    Idle,
}

impl FdState {
    /// Whether an fd in this state counts as in use in the table (`live`, [`used`]).
    const fn counted(self) -> bool {
        !matches!(self, FdState::Closed | FdState::Idle)
    }
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

/// The fds every worker's table holds (`ha_used_fds`, which `fd_insert` and `fd_delete`
/// count): what the idle server connections are weighed against (T230).
static USED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The fds in every worker's table.
#[must_use]
pub fn used() -> usize {
    USED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Per-thread fd table, indexed by fd number.
pub struct FdTab {
    entries: Vec<Entry>,
    live: usize,
}

impl Drop for FdTab {
    /// A table that goes (an engine rebuilt or dropped) takes its fds out of the count.
    fn drop(&mut self) {
        USED.fetch_sub(self.live, std::sync::atomic::Ordering::Relaxed);
    }
}

impl FdTab {
    #[must_use]
    pub fn with_capacity(max_fd: usize) -> Self {
        // Reserved, not filled: the table is indexed by fd number, which is per process,
        // so every worker's covers the highest fd any of them holds. Filling it wrote
        // `max_fd` entries (2 MB at the default 65,536 connections) into every worker
        // whether or not it ever saw that fd (T160); `slot` fills it as fds arrive,
        // within the reservation, so it still does not reallocate on the data path.
        FdTab {
            entries: Vec::with_capacity(max_fd),
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
            // Within the reserved capacity this writes the new entries and does not
            // allocate; beyond it (the fd rlimit was raised under us) it reallocates.
            self.entries.resize(i + 1, Entry::EMPTY);
        }
        &mut self.entries[i]
    }

    /// Claims an fd.
    pub fn insert(&mut self, fd: RawFd, state: FdState, interest: Interest) {
        let e = self.slot(fd);
        if !e.state.counted() {
            self.live += 1;
            USED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let e = self.slot(fd);
        e.state = state;
        e.interest = interest;
        e.ready = Interest::NONE;
    }

    /// Hands a connection's fd to another task, its readiness and interest kept: a server
    /// connection that goes from one stream of an HTTP/2 connection to its owner, or back
    /// (T280).
    pub fn set_task(&mut self, fd: RawFd, task: TaskRef) {
        let e = self.slot(fd);
        if let FdState::Conn { conn, .. } = e.state {
            e.state = FdState::Conn { task, conn };
        }
    }

    /// Releases an fd.
    pub fn remove(&mut self, fd: RawFd) {
        let e = self.slot(fd);
        if e.state.counted() {
            self.live -= 1;
            USED.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
        *self.slot(fd) = Entry::EMPTY;
    }

    /// A server connection goes idle into this worker's lists, still registered for reads
    /// ([`FdState::Idle`]): out of the count, which the lists keep for their own (T434).
    pub fn set_idle(&mut self, fd: RawFd) {
        let e = self.slot(fd);
        if e.state.counted() {
            self.live -= 1;
            USED.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
        *self.slot(fd) = Entry { state: FdState::Idle, interest: Interest::READ, ready: Interest::NONE };
    }

    #[must_use]
    pub fn state(&self, fd: RawFd) -> FdState {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.entries.get(i))
            .map_or(FdState::Closed, |e| e.state)
    }

    /// Whether no socket of this worker's holds `fd`'s slot: `Closed`, or `Idle` (an idle
    /// server connection that left the lists without an event -- taken by another worker,
    /// purged -- leaves its `Idle` entry behind, and a socket given that number next is not
    /// in the epoll set; T434). What [`FdState::counted`] does not count.
    #[must_use]
    pub fn is_free(&self, fd: RawFd) -> bool {
        !self.state(fd).counted()
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

    /// An idle server connection leaves the count and comes back into it when a request
    /// takes it; an idle entry removed or overwritten counts nothing (T434).
    #[test]
    fn an_idle_entry_is_not_counted() {
        let mut t = FdTab::with_capacity(64);
        let conn = FdState::Conn { task: ibex_sched::TaskRef(1), conn: 1 };
        t.insert(9, conn, Interest::BOTH);
        assert_eq!(t.live(), 1);
        t.set_idle(9);
        assert_eq!((t.live(), t.state(9), t.interest(9)), (0, FdState::Idle, Interest::READ));
        assert!(t.is_free(9), "an idle entry holds no socket of the worker's");
        t.insert(9, conn, Interest::READ);
        assert_eq!(t.live(), 1);
        assert!(!t.is_free(9));
        t.set_idle(9);
        t.remove(9);
        assert_eq!((t.live(), t.state(9)), (0, FdState::Closed));
        t.set_idle(9);
        t.set_idle(9);
        assert_eq!(t.live(), 0);
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
        t.insert(
            1000,
            FdState::Conn {
                task: ibex_sched::TaskRef(7),
                conn: 2,
            },
            Interest::BOTH,
        );
        assert_eq!(
            t.state(1000),
            FdState::Conn {
                task: ibex_sched::TaskRef(7),
                conn: 2
            }
        );
        assert_eq!(t.live(), 1);
    }

    #[test]
    fn unknown_fds_read_as_closed() {
        let t = FdTab::with_capacity(8);
        assert_eq!(t.state(99_999), FdState::Closed);
        assert_eq!(t.state(-1), FdState::Closed);
    }
}
